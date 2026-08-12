import hashlib
import logging
import os

import yaml
from mcp.types import (
    Implementation,
    InitializeResult,
    Prompt,
    PromptsCapability,
    Resource,
    ResourcesCapability,
    ServerCapabilities,
    Tool,
    ToolsCapability,
)
from yaml.error import YAMLError

from agent_scan.models.mcp import ServerSignature
from agent_scan.models.skill import SkillFile, SkillServer
from agent_scan.redact import redact_signature, redact_text
from agent_scan.utils import get_relative_path

logger = logging.getLogger(__name__)

# Synthetic description that ``traverse_skill_tree`` emits for a binary resource:
# this fixed prefix followed by the file's sha256 hex digest. It is generated
# entirely by us and contains no user content, so ``redact``'s
# ``_is_synthetic_binary_description`` exempts it from secret redaction --
# otherwise the 64-char digest trips the hex high-entropy detector and every
# binary collapses to an identical, useless description. ``redact`` imports this
# constant (lazily, to avoid an import cycle) so the marker and matcher cannot
# drift apart.
BINARY_FILE_DESCRIPTION_PREFIX = "Binary file. Hash: "

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


def _inspect_skill_file(expanded_path: str) -> ServerSignature:
    """Inspect a single-file skill/command (a flat ``*.md``).

    Command files (``~/.claude/commands/*.md``) are markdown files with optional
    YAML frontmatter, not ``<name>/SKILL.md`` directories. The name defaults to
    the file stem; an optional frontmatter ``name``/``description`` overrides it.
    """
    with open(expanded_path, encoding="utf-8") as f:
        content = f.read()

    name = os.path.splitext(os.path.basename(expanded_path))[0]
    description = ""
    # Only treat the file as having YAML frontmatter when it actually *starts*
    # with a ``---`` fence; otherwise ``---`` used as a markdown horizontal rule
    # in the body would be misread as frontmatter.
    content_chunks = content.split("---")
    if content.lstrip().startswith("---") and len(content_chunks) > 2:
        try:
            yaml_data = yaml.safe_load(content_chunks[1].strip())
        except YAMLError:
            yaml_data = None
        if isinstance(yaml_data, dict):
            # Guard against non-string frontmatter values (e.g. a YAML list),
            # which would otherwise fail Pydantic validation downstream.
            if isinstance(yaml_data.get("name"), str):
                name = yaml_data["name"]
            if isinstance(yaml_data.get("description"), str):
                description = yaml_data["description"]

    # Name the single prompt after the command's resolved ``name`` (file stem, or
    # a frontmatter ``name`` override) so it matches ``serverInfo`` below rather
    # than carrying the raw ``<stem>.md`` filename.
    base_prompt = Prompt(name=name, description=content)
    return ServerSignature(
        metadata=InitializeResult(
            protocolVersion="built-in",
            instructions=description,
            capabilities=ServerCapabilities(tools=ToolsCapability(listChanged=False)),
            prompts=PromptsCapability(listChanged=False),
            resources=ResourcesCapability(listChanged=False),
            serverInfo=Implementation(name=name, version="skills"),
        ),
        prompts=[base_prompt],
        resources=[],
        tools=[],
    )


def inspect_skill(config: SkillServer) -> ServerSignature:
    """Read a skill (single file or ``<name>/SKILL.md`` directory) into a signature.

    Secrets in the skill's contents are redacted in place here -- the single
    point where skill files are read -- so the signature is already sanitized by
    the time it reaches the analysis / upload calls.
    """
    return redact_signature(_inspect_skill(config))


def _parse_skill_manifest(content: str, skill_path: str) -> tuple[str, str]:
    """Validate directory-skill frontmatter and return its identity fields."""
    content_chunks = content.split("---")
    if len(content_chunks) <= 2:
        raise SkillInspectionError(
            f"Invalid SKILL.md file: {skill_path}. Could not find the YAML and the MD parts in the SKILL.md file."
        )
    yaml_content = content_chunks[1].strip()
    try:
        yaml_data = yaml.safe_load(yaml_content)
    except YAMLError as e:
        raise SkillInspectionError(f"Invalid SKILL.md file: {skill_path}. YAML formatter contains invalid yaml.") from e
    if not isinstance(yaml_data, dict):
        raise SkillInspectionError(f"Invalid SKILL.md file: {skill_path}. YAML frontmatter must be a mapping.")
    if "name" not in yaml_data:
        raise SkillInspectionError(f"Invalid SKILL.md file: {skill_path}. Missing name in the YAML frontmatter.")
    if "description" not in yaml_data:
        raise SkillInspectionError(f"Invalid SKILL.md file: {skill_path}. Missing description in the YAML frontmatter.")
    return yaml_data["name"], yaml_data["description"]


def _inspect_skill(config: SkillServer) -> ServerSignature:
    logger.info(f"Scanning skill at path: {config.path}")
    expanded_path = os.path.expanduser(config.path)
    if os.path.isfile(expanded_path):
        return _inspect_skill_file(expanded_path)
    skill_md_path = get_skill_md_path(config.path)
    if skill_md_path is None:
        raise Exception(f"neither SKILL.md nor skill.md file found at path: {config.path}")
    with open(os.path.expanduser(os.path.join(config.path, skill_md_path)), encoding="utf-8") as f:
        content = f.read()

    logger.debug("Skill file read successfully")

    name, description = _parse_skill_manifest(content, config.path)
    base_prompt = Prompt(
        name="SKILL.md",
        description=content,
        arguments=[],
    )
    prompts, resources, tools = traverse_skill_tree(config.path, None)
    return ServerSignature(
        metadata=InitializeResult(
            protocolVersion="built-in",
            instructions=description,
            capabilities=ServerCapabilities(tools=ToolsCapability(listChanged=False)),
            prompts=PromptsCapability(listChanged=False),
            resources=ResourcesCapability(listChanged=False),
            serverInfo=Implementation(name=name, version="skills"),
        ),
        prompts=[base_prompt, *prompts],
        resources=resources,
        tools=tools,
    )
    # skill tree traversal


def traverse_skill_tree(skill_path: str, relative_path: str | None) -> tuple[list[Prompt], list[Resource], list[Tool]]:
    path = os.path.join(skill_path, relative_path) if relative_path else skill_path

    prompts: list[Prompt] = []
    resources: list[Resource] = []
    tools: list[Tool] = []

    for file in os.listdir(os.path.expanduser(path)):
        full_path = os.path.join(path, file)
        relative_full_path = os.path.join(relative_path, file) if relative_path else file
        # The skill-relative path (with forward slashes) is the canonical entity
        # name: it preserves the directory (so subdir files don't collide on
        # basename) and matches the path the backend emits as the
        # ``=== FILE: ... ===`` header that line-location references resolve against.
        entity_name = relative_full_path.replace(os.path.sep, "/")
        if os.path.isdir(os.path.expanduser(full_path)):
            prompts_sub, resources_sub, tools_sub = traverse_skill_tree(skill_path, relative_full_path)
            prompts.extend(prompts_sub)
            resources.extend(resources_sub)
            tools.extend(tools_sub)
            continue
        elif file.lower() == "skill.md" and not relative_path:
            continue

        elif file.endswith(".md"):
            with open(os.path.expanduser(full_path), encoding="utf-8") as f:
                content = f.read()
                prompts.append(
                    Prompt(
                        name=entity_name,
                        description=content,
                    )
                )

        elif file.split(".")[-1] in ["py", "js", "ts", "sh"]:
            with open(os.path.expanduser(full_path), encoding="utf-8") as f:
                code = f.read()
            # The raw code is the description so its line numbers map 1:1 to the
            # file once serialized. The filename is already carried by the entity
            # name and the serialized ``=== FILE: ... ===`` header.
            tools.append(
                Tool(
                    name=entity_name,
                    description=code or "No code available",
                    inputSchema={},
                    outputSchema=None,
                    annotations=None,
                )
            )

        else:
            try:
                with open(os.path.expanduser(full_path), encoding="utf-8") as f:
                    content = f.read()
            except UnicodeDecodeError:
                # Expected for binary files: fall back to a hash-only description.
                logger.debug("File %s is not valid UTF-8; treating as binary", file)
                with open(os.path.expanduser(full_path), "rb") as f:
                    content_hash = hashlib.sha256(f.read()).hexdigest()
                content = f"{BINARY_FILE_DESCRIPTION_PREFIX}{content_hash}"
            resources.append(
                Resource(
                    name=entity_name,
                    uri=f"skill://{entity_name}",
                    description=content,
                )
            )

    return prompts, resources, tools


def _read_skill_file_content(
    full_path: str,
    *,
    allow_binary: bool,
    manifest_skill_path: str | None = None,
) -> str:
    """Read one skill file's content for the v2026-07-10 request payload.

    Secrets are redacted in place (this is the single point where the raw files
    are read for the request). When ``allow_binary`` is true, non-UTF-8 files
    collapse to the same synthetic hash marker ``traverse_skill_tree`` uses;
    that marker is self-generated and holds no user content, so it is not run
    through redaction.
    """
    expanded = os.path.expanduser(full_path)
    try:
        with open(expanded, encoding="utf-8") as f:
            content = f.read()
        if manifest_skill_path is not None:
            _parse_skill_manifest(content, manifest_skill_path)
        return redact_text(content) or ""
    except UnicodeDecodeError as error:
        if not allow_binary:
            raise SkillInspectionError(str(error)) from error
        logger.debug("File %s is not valid UTF-8; treating as binary", get_relative_path(full_path))
        hasher = hashlib.sha256()
        with open(expanded, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return f"{BINARY_FILE_DESCRIPTION_PREFIX}{hasher.hexdigest()}"


def collect_skill_files(skill_path: str, *, validate_manifest: bool = False) -> list[SkillFile]:
    """Collect all skill files as raw ``SkillFile`` records for the v2026-07-10 API payload.

    Traverses and reads every file within a skill target without requiring legacy wrapper objects:
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
      caught gracefully and represented as a synthetic hash marker. Instruction and script
      files remain UTF-8-only, matching legacy skill validation.
      (``"Binary file. Hash: <sha256_hex_digest>"``), preserving asset tracking without
      transmitting raw binary payloads.
    """
    expanded_path = os.path.expanduser(skill_path)
    if not os.path.exists(expanded_path):
        raise FileNotFoundError(f"Skill path does not exist: {skill_path}")
    if os.path.islink(expanded_path):
        raise ValueError("Skill path must not be a symbolic link")

    if os.path.isfile(expanded_path):
        return [
            SkillFile(
                path=os.path.basename(expanded_path),
                content=_read_skill_file_content(expanded_path, allow_binary=False),
            )
        ]

    if not os.path.isdir(expanded_path):
        raise ValueError(f"Skill path is not a file or directory: {skill_path}")

    files: list[SkillFile] = []
    found_manifest = False
    for root, dirs, filenames in os.walk(expanded_path):
        dirs.sort()  # deterministic traversal order across platforms
        if any(os.path.islink(os.path.join(root, dirname)) for dirname in dirs):
            raise ValueError("Skill directory must not contain symbolic links")
        for filename in sorted(filenames):
            full_path = os.path.join(root, filename)
            if os.path.islink(full_path):
                raise ValueError("Skill directory must not contain symbolic links")
            relative_path = os.path.relpath(full_path, expanded_path).replace(os.path.sep, "/")
            extension = filename.rsplit(".", 1)[-1].lower()
            is_manifest = relative_path.lower() == "skill.md"
            found_manifest = found_manifest or is_manifest
            files.append(
                SkillFile(
                    path=relative_path,
                    content=_read_skill_file_content(
                        full_path,
                        allow_binary=extension not in ("md", "py", "js", "ts", "sh"),
                        manifest_skill_path=skill_path if validate_manifest and is_manifest else None,
                    ),
                )
            )
    if validate_manifest and not found_manifest:
        raise SkillInspectionError(f"neither SKILL.md nor skill.md file found at path: {skill_path}")
    return files


def inspect_skills_dir(path: str) -> list[tuple[str, SkillServer]]:
    logger.info("Scanning skills dir: %s", path)

    expanded_path = os.path.expanduser(path)
    candidate_skills_dirs = os.listdir(expanded_path)
    skills_servers: list[tuple[str, SkillServer]] = []
    for candidate_skill_dir in candidate_skills_dirs:
        candidate_skill_dir_full_path = os.path.join(expanded_path, candidate_skill_dir)
        if os.path.isdir(candidate_skill_dir_full_path):
            skill_md_path = get_skill_md_path(candidate_skill_dir_full_path)
            if skill_md_path is None:
                continue
            skills_servers.append((candidate_skill_dir, SkillServer(path=candidate_skill_dir_full_path)))
    logger.info("Found %d skills servers", len(skills_servers))
    return skills_servers


def inspect_commands_dir(path: str) -> list[tuple[str, SkillServer]]:
    """List command files under ``path`` as skill entries.

    Unlike :func:`inspect_skills_dir` (which expects ``<name>/SKILL.md``
    subdirectories), command files are flat ``*.md`` files. Claude Code
    namespaces nested command files by their relative path joined with ``:``
    (e.g. ``commands/git/commit.md`` -> ``git:commit``). Each file becomes one
    ``SkillServer`` pointing at the file itself.

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
    commands: list[tuple[str, SkillServer]] = []
    for root, dirs, files in os.walk(expanded_path):
        relative_root = os.path.relpath(root, expanded_path)
        dir_depth = 0 if relative_root == os.curdir else len(relative_root.split(os.sep))
        for file in files:
            if not file.endswith(".md"):
                continue
            full_path = os.path.join(root, file)
            relative = os.path.relpath(full_path, expanded_path)
            name = os.path.splitext(relative)[0].replace(os.path.sep, ":")
            commands.append((name, SkillServer(path=full_path)))
        # A file inside the current dir sits at depth+1; prune once that reaches
        # the cap so we don't descend into deeper subdirectories.
        if dir_depth + 1 >= _MAX_COMMANDS_WALK_DEPTH:
            dirs.clear()
    logger.info("Found %d command files", len(commands))
    return commands
