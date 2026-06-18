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

from agent_scan.models import ServerSignature, SkillServer
from agent_scan.redact import redact_signature

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

    # parse SKILL.md file
    content_chunks = content.split("---")
    if len(content_chunks) <= 2:
        raise Exception(
            f"Invalid SKILL.md file: {config.path}. Could not find the YAML and the MD parts in the SKILL.md file."
        )
    yaml_content = content_chunks[1].strip()
    try:
        yaml_data = yaml.safe_load(yaml_content)
    except YAMLError as e:
        raise Exception(f"Invalid SKILL.md file: {config.path}. YAML formatter contains invalid yaml.") from e
    if "name" not in yaml_data:
        raise Exception(f"Invalid SKILL.md file: {config.path}. Missing name in the YAML frontmatter.")
    name = yaml_data["name"]
    if "description" not in yaml_data:
        raise Exception(f"Invalid SKILL.md file: {config.path}. Missing description in the YAML frontmatter.")
    description = yaml_data["description"]
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
                        name=os.path.join(relative_path or "", file),
                        description=content,
                    )
                )

        elif file.split(".")[-1] in ["py", "js", "ts", "sh"]:
            with open(os.path.expanduser(full_path), encoding="utf-8") as f:
                code = f.read()
            tools.append(
                Tool(
                    name=file,
                    description=f"Script: {file}. Code:\n{code or 'No code available'}",
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
                logger.exception(f"Error reading file: {file}. The file is not a bianry")
                with open(os.path.expanduser(full_path), "rb") as f:
                    content_hash = hashlib.sha256(f.read()).hexdigest()
                content = f"{BINARY_FILE_DESCRIPTION_PREFIX}{content_hash}"
            resources.append(
                Resource(
                    name=file,
                    uri=f"skill://{relative_full_path.replace(os.path.sep, '/')}",
                    description=content,
                )
            )

    return prompts, resources, tools


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
