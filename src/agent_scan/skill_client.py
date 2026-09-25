import hashlib
import logging
import os
import stat
from collections.abc import Iterator

import yaml
from yaml.error import YAMLError

from agent_scan.models.skill import DiscoveredSkill, SkillFile, SkillFrontmatter
from agent_scan.redact import redact_text
from agent_scan.utils import get_relative_path, is_path_within_boundary

logger = logging.getLogger(__name__)

# Synthetic description emitted when binary skill content is allowed.
BINARY_FILE_DESCRIPTION_PREFIX = "Binary file. Hash: "
_MAX_SKILL_FILE_BYTES = 20 * 1024 * 1024
_MAX_SKILL_WALK_DEPTH = 10

_SKILL_LINK_CREDENTIAL_PATHS = {
    "ssh-credentials": (".ssh",),
    "cloud-credentials": (".aws", ".config/gcloud", ".azure", ".kube"),
    "netrc-credentials": (".netrc", ".git-credentials", ".npmrc", ".pypirc"),
}
_SKILL_LINK_SYSTEM_PATHS = (
    (
        os.environ.get("SYSTEMROOT", os.environ.get("WINDIR", r"C:\Windows")),
        os.environ.get("PROGRAMFILES", r"C:\Program Files"),
        os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
        os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
    )
    if os.name == "nt"
    else ("/etc", "/var", "/usr")
)

# Cap traversal depth when walking a commands dir, mirroring the value used by
# the discoverer plugin/extension walks (``agents.base._MAX_PLUGIN_RGLOB_DEPTH``).
# Kept as a separate constant here to avoid a circular import (agents.base
# imports this module).
_MAX_COMMANDS_WALK_DEPTH = 10


class SkillInspectionError(Exception):
    """A collected skill could not be interpreted as a valid text skill."""


def get_skill_md_path(path: str) -> str | None:
    for file in os.listdir(path):
        if file.lower() == "skill.md":
            return file
    return None


def _extract_leading_frontmatter_yaml(content: str) -> str | None:
    """Return the leading YAML frontmatter block, excluding delimiters."""
    lines = content.lstrip("\ufeff \t\r\n").splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    closing_delimiter = next(
        (index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---"),
        None,
    )
    if closing_delimiter is None:
        return None
    return "\n".join(lines[1:closing_delimiter]).strip()


def parse_skill_frontmatter(content: str, skill_path: str) -> SkillFrontmatter:
    """Parse and validate the required identity metadata in a SKILL.md file."""
    yaml_content = _extract_leading_frontmatter_yaml(content)
    if yaml_content is None:
        raise SkillInspectionError(
            f"Invalid SKILL.md file: {skill_path}. Could not find the YAML and the MD parts in the SKILL.md file."
        )
    try:
        yaml_data = yaml.safe_load(yaml_content)
    except YAMLError as e:
        raise SkillInspectionError(f"Invalid SKILL.md file: {skill_path}. YAML formatter contains invalid yaml.") from e
    if not isinstance(yaml_data, dict):
        raise SkillInspectionError(f"Invalid SKILL.md file: {skill_path}. YAML frontmatter must be a mapping.")
    for field in ("name", "description"):
        if field not in yaml_data:
            raise SkillInspectionError(f"Invalid SKILL.md file: {skill_path}. Missing {field} in the YAML frontmatter.")
        value = yaml_data[field]
        if not isinstance(value, str) or not value.strip():
            raise SkillInspectionError(
                f"Invalid SKILL.md file: {skill_path}. YAML frontmatter {field} must be a non-empty string."
            )
    return SkillFrontmatter(
        name=yaml_data["name"].strip(),
        description=yaml_data["description"].strip(),
    )


def resolve_skill_name(skill: DiscoveredSkill) -> str:
    """Resolve a directory skill's raw frontmatter name or preserve a command name."""
    expanded_path = os.path.expanduser(skill.path)
    if os.path.isfile(expanded_path):
        return skill.name

    skill_md_filename = get_skill_md_path(expanded_path)
    if skill_md_filename is None:
        raise SkillInspectionError(f"neither SKILL.md nor skill.md file found at path: {skill.path}")
    skill_md_path = os.path.realpath(os.path.join(expanded_path, skill_md_filename))
    if not is_path_within_boundary(skill_md_path, expanded_path):
        raise SkillInspectionError("SKILL.md resolves outside the skill root")
    try:
        content = _read_skill_file_bytes(skill_md_path).decode("utf-8")
    except UnicodeDecodeError as error:
        raise SkillInspectionError(str(error)) from error
    return parse_skill_frontmatter(content, skill.path).name


def _read_skill_file_bytes(full_path: str) -> bytes:
    full_path = os.path.expanduser(full_path)
    if not stat.S_ISREG(os.stat(full_path).st_mode):
        raise SkillInspectionError("Skill file is not a regular file")
    with open(full_path, "rb") as file:
        if os.fstat(file.fileno()).st_size > _MAX_SKILL_FILE_BYTES:
            raise SkillInspectionError(f"Skill file exceeds {_MAX_SKILL_FILE_BYTES} byte limit")
        content = file.read(_MAX_SKILL_FILE_BYTES + 1)
    if len(content) > _MAX_SKILL_FILE_BYTES:
        raise SkillInspectionError(f"Skill file exceeds {_MAX_SKILL_FILE_BYTES} byte limit")
    return content


def _read_skill_file_content(
    full_path: str,
    *,
    allow_binary: bool,
) -> str:
    """Read one skill file's content for the v2026-07-10 request payload.

    Secrets are redacted in place (this is the single point where the raw files
    are read for the request). When ``allow_binary`` is true, non-UTF-8 files
    collapse to a synthetic hash marker. The marker is self-generated and holds
    no user content, so it is not run through redaction.
    """
    raw_content = _read_skill_file_bytes(full_path)
    try:
        content = raw_content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        return redact_text(content) or ""
    except UnicodeDecodeError as error:
        if not allow_binary:
            raise SkillInspectionError(str(error)) from error
        logger.debug("File %s is not valid UTF-8; treating as binary", get_relative_path(full_path))
        return f"{BINARY_FILE_DESCRIPTION_PREFIX}{hashlib.sha256(raw_content).hexdigest()}"


def _record_skill_file_error(relative_path: str, error: Exception, errors: list[str] | None) -> None:
    reason = (error.strerror or type(error).__name__) if isinstance(error, OSError) else str(error)
    message = f"Skipped {relative_path}: {reason}"
    logger.warning("%s", message)
    if errors is not None:
        errors.append(message)


def _skill_link_target_category(target_path: str) -> str:
    """Classify a resolved target using metadata only; never return a local path."""
    try:
        os.stat(target_path)
    except (FileNotFoundError, NotADirectoryError):
        return "missing"
    except OSError:
        pass

    home = os.path.expanduser("~")
    for category, paths in _SKILL_LINK_CREDENTIAL_PATHS.items():
        if any(is_path_within_boundary(target_path, os.path.join(home, path)) for path in paths):
            return category
    if is_path_within_boundary(target_path, home):
        return "home"
    if any(is_path_within_boundary(target_path, path) for path in _SKILL_LINK_SYSTEM_PATHS):
        return "system"
    return "other"


def _outside_skill_link_placeholder(relative_path: str, target_path: str, errors: list[str] | None) -> SkillFile:
    _record_skill_file_error(relative_path, SkillInspectionError("Path resolves outside the skill root"), errors)
    return SkillFile(
        path=relative_path,
        content=f"[link outside skill folder: {_skill_link_target_category(target_path)}]",
    )


def _walk_skill_files(skill_root: str, *, errors: list[str] | None = None) -> Iterator[tuple[str, str] | SkillFile]:
    """Yield confined targets or explicit link placeholders, reporting skips per entry."""
    skill_root = os.path.realpath(skill_root)
    root_stat = os.stat(skill_root)
    root_identity = (root_stat.st_dev, root_stat.st_ino)
    pending = [(skill_root, frozenset({root_identity}), 0)]

    while pending:
        directory, ancestor_identities, depth = pending.pop()
        try:
            if not is_path_within_boundary(directory, skill_root):
                yield _outside_skill_link_placeholder(
                    os.path.relpath(directory, skill_root).replace(os.path.sep, "/"),
                    os.path.realpath(directory),
                    errors,
                )
                continue
            with os.scandir(directory) as entries:
                sorted_entries = sorted(entries, key=lambda entry: entry.name)
        except (OSError, ValueError, SkillInspectionError) as error:
            _record_skill_file_error(os.path.relpath(directory, skill_root).replace(os.path.sep, "/"), error, errors)
            continue

        child_directories: list[tuple[str, frozenset[tuple[int, int]], int]] = []
        for entry in sorted_entries:
            relative_path = os.path.relpath(entry.path, skill_root).replace(os.path.sep, "/")
            try:
                full_path = os.path.realpath(entry.path)
                if not is_path_within_boundary(full_path, skill_root):
                    yield _outside_skill_link_placeholder(relative_path, full_path, errors)
                    continue
                target_stat = os.stat(full_path)
                if stat.S_ISDIR(target_stat.st_mode):
                    identity = (target_stat.st_dev, target_stat.st_ino)
                    if identity in ancestor_identities:
                        raise SkillInspectionError("Skill directory must not contain a symbolic link cycle")
                    if depth + 1 >= _MAX_SKILL_WALK_DEPTH:
                        raise SkillInspectionError(f"Skill directory exceeds {_MAX_SKILL_WALK_DEPTH} level depth limit")
                    child_directories.append((entry.path, ancestor_identities | {identity}, depth + 1))
                elif stat.S_ISREG(target_stat.st_mode):
                    yield relative_path, full_path
                else:
                    raise SkillInspectionError("Skill file is not a regular file")
            except (OSError, ValueError, SkillInspectionError) as error:
                _record_skill_file_error(relative_path, error, errors)
                if isinstance(error, FileNotFoundError | NotADirectoryError) and entry.is_symlink():
                    yield SkillFile(path=relative_path, content="[broken skill link: missing]")

        pending.extend(reversed(child_directories))


def collect_skill_files(skill_path: str, *, errors: list[str] | None = None) -> list[SkillFile]:
    """Collect skill files as redacted ``SkillFile`` records for inspection and analysis.

    Skipped entries are logged and appended to ``errors`` for inspection output.
    Escaping and broken links also emit explicit synthetic markers, never target content.
    Traverses and reads confined files within a skill target without constructing
    intermediate MCP signature objects:
    - **Single-file command skills** (a flat ``*.md``): returns a single ``SkillFile``
      keyed by the file's basename (e.g., ``"deploy.md"``).
    - **Directory skills** (``<name>/SKILL.md`` + subdirectories and sibling files):
      walks all files in the directory and returns ``SkillFile`` records keyed by their
      path relative to the skill root with forward slashes (e.g., ``"SKILL.md"``, ``"scripts/run.py"``).
      Files are sorted deterministically across platforms.

    **File Content Handling:**
    - **Text files** (instruction markdown, scripts, configs, assets): UTF-8 text is read
      and run through secret redaction before being sent to the backend.
    - **Binary assets** (images, archives, compiled binaries): non-UTF-8 binary content is
      represented as ``"Binary file. Hash: <sha256_hex_digest>"``, preserving asset tracking
      without transmitting raw binary payloads. Instruction and script files remain UTF-8-only.
    """
    expanded_path = os.path.expanduser(skill_path)
    if not os.path.exists(expanded_path):
        raise FileNotFoundError(f"Skill path does not exist: {skill_path}")

    if os.path.isfile(expanded_path):
        relative_path = os.path.basename(expanded_path)
        try:
            return [
                SkillFile(
                    path=relative_path,
                    content=_read_skill_file_content(expanded_path, allow_binary=False),
                )
            ]
        except (OSError, ValueError, SkillInspectionError) as error:
            _record_skill_file_error(relative_path, error, errors)
            return []

    if not os.path.isdir(expanded_path):
        raise ValueError(f"Skill path is not a file or directory: {skill_path}")

    files: list[SkillFile] = []
    skill_root = os.path.realpath(expanded_path)
    for entry in _walk_skill_files(skill_root, errors=errors):
        if isinstance(entry, SkillFile):
            files.append(entry)
            continue
        relative_path, full_path = entry
        extension = relative_path.rsplit(".", 1)[-1].lower()
        try:
            if not is_path_within_boundary(full_path, skill_root):
                files.append(_outside_skill_link_placeholder(relative_path, os.path.realpath(full_path), errors))
                continue
            files.append(
                SkillFile(
                    path=relative_path,
                    content=_read_skill_file_content(
                        full_path,
                        allow_binary=extension not in ("md", "py", "js", "ts", "sh"),
                    ),
                )
            )
        except (OSError, ValueError, SkillInspectionError) as error:
            _record_skill_file_error(relative_path, error, errors)
    return files


def inspect_skills_dir(path: str, *, boundary: str | None = None) -> list[DiscoveredSkill]:
    logger.info("Scanning skills dir: %s", path)

    expanded_path = os.path.expanduser(path)
    candidate_skills_dirs = os.listdir(expanded_path)
    resolved_boundary = os.path.realpath(boundary) if boundary is not None else None
    skills: list[DiscoveredSkill] = []
    for candidate_skill_dir in candidate_skills_dirs:
        candidate_skill_dir_full_path = os.path.join(expanded_path, candidate_skill_dir)
        if not os.path.isdir(candidate_skill_dir_full_path):
            continue
        try:
            if resolved_boundary is not None and not is_path_within_boundary(
                candidate_skill_dir_full_path, resolved_boundary
            ):
                continue
            skill_md_path = get_skill_md_path(candidate_skill_dir_full_path)
            if (
                resolved_boundary is not None
                and skill_md_path is not None
                and not is_path_within_boundary(
                    os.path.join(candidate_skill_dir_full_path, skill_md_path), resolved_boundary
                )
            ):
                continue
        except (OSError, RuntimeError, ValueError):
            # ``get_skill_md_path`` lists the candidate, so an unreadable child (mode
            # 0o111, or another user's under ``--scan-all-users``) would otherwise cost
            # every readable sibling in this skills dir.
            logger.warning("Skipping unreadable skill dir: %s", candidate_skill_dir_full_path)
            continue
        if skill_md_path is None:
            continue
        skills.append(DiscoveredSkill(name=candidate_skill_dir, path=candidate_skill_dir_full_path))
    logger.info("Found %d skills", len(skills))
    return skills


def inspect_commands_dir(path: str) -> list[DiscoveredSkill]:
    """List command files under ``path`` as skill entries.

    Unlike :func:`inspect_skills_dir` (which expects ``<name>/SKILL.md``
    subdirectories), command files are flat ``*.md`` files. Claude Code
    namespaces nested command files by their relative path joined with ``:``
    (e.g. ``commands/git/commit.md`` -> ``git:commit``). Each file becomes one
    ``DiscoveredSkill`` pointing at the file itself.

    Traversal is depth-bounded by :data:`_MAX_COMMANDS_WALK_DEPTH`, pruning the
    walk once it would descend past the cap rather than walking the whole subtree
    first. This mirrors the discoverer plugin/extension walks
    (``agents.base._walk_under_depth``) so a pathologically deep tree under a
    commands dir can't blow up the scan. A ``.md`` file is surfaced only when its
    path relative to ``path`` is at most ``_MAX_COMMANDS_WALK_DEPTH`` components
    deep.
    """
    logger.info("Scanning commands dir: %s", path)

    expanded_path = os.path.expanduser(path)
    commands: list[DiscoveredSkill] = []
    for root, dirs, files in os.walk(expanded_path):
        relative_root = os.path.relpath(root, expanded_path)
        dir_depth = 0 if relative_root == os.curdir else len(relative_root.split(os.sep))
        for file in files:
            if not file.endswith(".md"):
                continue
            full_path = os.path.join(root, file)
            relative = os.path.relpath(full_path, expanded_path)
            name = os.path.splitext(relative)[0].replace(os.path.sep, ":")
            commands.append(DiscoveredSkill(name=name, path=full_path))
        # A file inside the current dir sits at depth+1; prune once that reaches
        # the cap so we don't descend into deeper subdirectories.
        if dir_depth + 1 >= _MAX_COMMANDS_WALK_DEPTH:
            dirs.clear()
    logger.info("Found %d command files", len(commands))
    return commands
