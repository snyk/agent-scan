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

from agent_scan.models import ServerSignature, SkillServer

logger = logging.getLogger(__name__)


def get_skill_md_path(path: str) -> str | None:
    for file in os.listdir(path):
        if file.lower() == "skill.md":
            return file
    return None


def inspect_skill(config: SkillServer) -> ServerSignature:
    logger.info(f"Scanning skill at path: {config.path}")
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
    text_content = "---".join(content_chunks[2:])

    yaml_data = yaml.safe_load(yaml_content)
    if "name" not in yaml_data:
        raise Exception(f"Invalid SKILL.md file: {config.path}. Missing name in the YAML frontmatter.")
    name = yaml_data["name"]
    if "description" not in yaml_data:
        raise Exception(f"Invalid SKILL.md file: {config.path}. Missing description in the YAML frontmatter.")
    description = yaml_data["description"]
    base_prompt = Prompt(
        name="SKILL.md",
        description=text_content,
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
                content = f"Binary file. Hash: {content_hash}"
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
