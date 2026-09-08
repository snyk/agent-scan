import glob
import logging
import os
import sys
from pathlib import Path

from agent_scan.models import CandidateClient, DiscoveryLocationScope

# Set up logger for this module
logger = logging.getLogger(__name__)

# Canonical agent name for Claude Code. Used as ``CandidateClient.name`` in the
# per-OS lists below and as ``ClaudeCodeDiscoverer.name``; the Phase B merge in
# ``pipelines.discover_clients_to_inspect`` relies on these matching exactly.
CLAUDE_CODE_NAME = "claude code"


MACOS_WELL_KNOWN_CLIENTS: list[CandidateClient] = [
    CandidateClient(
        name="windsurf",
        client_exists_paths=["~/.codeium"],
        mcp_config_paths=["~/.codeium/windsurf/mcp_config.json"],
        skills_dir_paths=["~/.codeium/windsurf/skills"],
    ),
    CandidateClient(
        name="cursor",
        client_exists_paths=["~/.cursor"],
        mcp_config_paths=["~/.cursor/mcp.json"],
        skills_dir_paths=["~/.cursor/skills"],
    ),
    CandidateClient(
        name="vscode",
        client_exists_paths=["~/.vscode"],
        mcp_config_paths=[
            "~/Library/Application Support/Code/User/settings.json",
            "~/.vscode/mcp.json",
            "~/Library/Application Support/Code/User/mcp.json",
        ],
        skills_dir_paths=["~/.copilot/skills"],
    ),
    CandidateClient(
        name="claude desktop",
        client_exists_paths=["~/Library/Application Support/Claude"],
        mcp_config_paths=["~/Library/Application Support/Claude/claude_desktop_config.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name=CLAUDE_CODE_NAME,
        client_exists_paths=["~/.claude"],
        mcp_config_paths=["~/.claude.json"],
        skills_dir_paths=["~/.claude/skills"],
        mcp_config_globs=["~/.claude/plugins/cache/**/.mcp.json"],
        skills_dir_globs=["~/.claude/plugins/cache/**/skills"],
        mcp_config_glob_scopes={"~/.claude/plugins/cache/**/.mcp.json": DiscoveryLocationScope.EXTENSION_PLUGIN},
        skills_dir_glob_scopes={"~/.claude/plugins/cache/**/skills": DiscoveryLocationScope.EXTENSION_PLUGIN},
        # ``~/.claude.json`` nests per-project servers under ``projects.<path>``
        # alongside the user-global top-level ``mcpServers``.
        mcp_config_path_nested_scopes={"~/.claude.json": {DiscoveryLocationScope.PROJECT_WORKSPACE}},
    ),
    CandidateClient(
        name="gemini cli",
        client_exists_paths=["~/.gemini"],
        mcp_config_paths=["~/.gemini/settings.json"],
        skills_dir_paths=["~/.gemini/skills"],
    ),
    CandidateClient(
        name="openclaw",
        client_exists_paths=["~/.clawdbot", "~/.openclaw"],
        mcp_config_paths=[],
        skills_dir_paths=[
            "~/.clawdbot/skills",
            "~/.openclaw/skills",
            "~/.openclaw/workspace/skills",
        ],
        skills_dir_path_scopes={
            "~/.openclaw/workspace/skills": DiscoveryLocationScope.PROJECT_WORKSPACE,
        },
    ),
    CandidateClient(
        name="amp",
        client_exists_paths=["~/.config/agents"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.config/agents/skills"],
    ),
    CandidateClient(
        name="kiro",
        client_exists_paths=["~/.kiro"],
        mcp_config_paths=["~/.kiro/settings/mcp.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="opencode",
        client_exists_paths=["~/.config/opencode"],
        mcp_config_paths=[],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="antigravity",
        client_exists_paths=["~/.gemini/antigravity"],
        mcp_config_paths=["~/.gemini/antigravity/mcp_config.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="codex",
        client_exists_paths=["~/.codex"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.codex/skills"],
    ),
    CandidateClient(
        name="amazon_q",
        client_exists_paths=["~/.aws/amazonq"],
        mcp_config_paths=[
            "~/.aws/amazonq/agents/default.json",
            "~/.aws/amazonq/agents/mcp.json",
            "~/.aws/amazonq/mcp.json",
        ],
        skills_dir_paths=[],
    ),
]

LINUX_WELL_KNOWN_CLIENTS: list[CandidateClient] = [
    CandidateClient(
        name="windsurf",
        client_exists_paths=["~/.codeium"],
        mcp_config_paths=["~/.codeium/windsurf/mcp_config.json"],
        skills_dir_paths=["~/.codeium/windsurf/skills"],
    ),
    CandidateClient(
        name="cursor",
        client_exists_paths=["~/.cursor"],
        mcp_config_paths=["~/.cursor/mcp.json"],
        skills_dir_paths=["~/.cursor/skills"],
    ),
    CandidateClient(
        name="vscode",
        client_exists_paths=["~/.vscode", "~/.config/Code"],
        mcp_config_paths=[
            "~/.config/Code/User/settings.json",
            "~/.vscode/mcp.json",
            "~/.config/Code/User/mcp.json",
        ],
        skills_dir_paths=["~/.copilot/skills"],
    ),
    CandidateClient(
        name=CLAUDE_CODE_NAME,
        client_exists_paths=["~/.claude"],
        mcp_config_paths=["~/.claude.json"],
        skills_dir_paths=["~/.claude/skills"],
        mcp_config_globs=["~/.claude/plugins/cache/**/.mcp.json"],
        skills_dir_globs=["~/.claude/plugins/cache/**/skills"],
        mcp_config_glob_scopes={"~/.claude/plugins/cache/**/.mcp.json": DiscoveryLocationScope.EXTENSION_PLUGIN},
        skills_dir_glob_scopes={"~/.claude/plugins/cache/**/skills": DiscoveryLocationScope.EXTENSION_PLUGIN},
        # ``~/.claude.json`` nests per-project servers under ``projects.<path>``
        # alongside the user-global top-level ``mcpServers``.
        mcp_config_path_nested_scopes={"~/.claude.json": {DiscoveryLocationScope.PROJECT_WORKSPACE}},
    ),
    CandidateClient(
        name="gemini cli",
        client_exists_paths=["~/.gemini"],
        mcp_config_paths=["~/.gemini/settings.json"],
        skills_dir_paths=["~/.gemini/skills"],
    ),
    CandidateClient(
        name="openclaw",
        client_exists_paths=["~/.clawdbot", "~/.openclaw"],
        mcp_config_paths=[],
        skills_dir_paths=[
            "~/.clawdbot/skills",
            "~/.openclaw/skills",
            "~/.openclaw/workspace/skills",
        ],
        skills_dir_path_scopes={
            "~/.openclaw/workspace/skills": DiscoveryLocationScope.PROJECT_WORKSPACE,
        },
    ),
    CandidateClient(
        name="amp",
        client_exists_paths=["~/.config/agents"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.config/agents/skills"],
    ),
    CandidateClient(
        name="kiro",
        client_exists_paths=["~/.kiro"],
        mcp_config_paths=["~/.kiro/settings/mcp.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="opencode",
        client_exists_paths=["~/.config/opencode"],
        mcp_config_paths=[],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="antigravity",
        client_exists_paths=["~/.gemini/antigravity"],
        mcp_config_paths=["~/.gemini/antigravity/mcp_config.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="codex",
        client_exists_paths=["~/.codex"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.codex/skills"],
    ),
    CandidateClient(
        name="amazon_q",
        client_exists_paths=["~/.aws/amazonq"],
        mcp_config_paths=[
            "~/.aws/amazonq/agents/default.json",
            "~/.aws/amazonq/agents/mcp.json",
            "~/.aws/amazonq/mcp.json",
        ],
        skills_dir_paths=[],
    ),
]


WINDOWS_WELL_KNOWN_CLIENTS: list[CandidateClient] = [
    CandidateClient(
        name="windsurf",
        client_exists_paths=["~/.codeium"],
        mcp_config_paths=["~/.codeium/windsurf/mcp_config.json"],
        skills_dir_paths=["~/.codeium/windsurf/skills"],
    ),
    CandidateClient(
        name="cursor",
        client_exists_paths=["~/.cursor"],
        mcp_config_paths=["~/.cursor/mcp.json"],
        skills_dir_paths=["~/.cursor/skills"],
    ),
    CandidateClient(
        name="vscode",
        client_exists_paths=["~/.vscode", "~/AppData/Roaming/Code"],
        mcp_config_paths=[
            "~/AppData/Roaming/Code/User/settings.json",
            "~/.vscode/mcp.json",
            "~/AppData/Roaming/Code/User/mcp.json",
        ],
        skills_dir_paths=["~/.copilot/skills"],
    ),
    CandidateClient(
        name="claude desktop",
        client_exists_paths=["~/AppData/Roaming/Claude"],
        mcp_config_paths=["~/AppData/Roaming/Claude/claude_desktop_config.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name=CLAUDE_CODE_NAME,
        client_exists_paths=["~/.claude"],
        mcp_config_paths=["~/.claude.json"],
        skills_dir_paths=["~/.claude/skills"],
        mcp_config_globs=["~/.claude/plugins/cache/**/.mcp.json"],
        skills_dir_globs=["~/.claude/plugins/cache/**/skills"],
        mcp_config_glob_scopes={"~/.claude/plugins/cache/**/.mcp.json": DiscoveryLocationScope.EXTENSION_PLUGIN},
        skills_dir_glob_scopes={"~/.claude/plugins/cache/**/skills": DiscoveryLocationScope.EXTENSION_PLUGIN},
        # ``~/.claude.json`` nests per-project servers under ``projects.<path>``
        # alongside the user-global top-level ``mcpServers``.
        mcp_config_path_nested_scopes={"~/.claude.json": {DiscoveryLocationScope.PROJECT_WORKSPACE}},
    ),
    CandidateClient(
        name="gemini cli",
        client_exists_paths=["~/.gemini"],
        mcp_config_paths=["~/.gemini/settings.json"],
        skills_dir_paths=["~/.gemini/skills"],
    ),
    CandidateClient(
        name="openclaw",
        client_exists_paths=["~/.clawdbot", "~/.openclaw"],
        mcp_config_paths=[],
        skills_dir_paths=[
            "~/.clawdbot/skills",
            "~/.openclaw/skills",
            "~/.openclaw/workspace/skills",
        ],
        skills_dir_path_scopes={
            "~/.openclaw/workspace/skills": DiscoveryLocationScope.PROJECT_WORKSPACE,
        },
    ),
    CandidateClient(
        name="amp",
        client_exists_paths=["~/.config/agents"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.config/agents/skills"],
    ),
    CandidateClient(
        name="kiro",
        client_exists_paths=["~/.kiro"],
        mcp_config_paths=["~/.kiro/settings/mcp.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="opencode",
        client_exists_paths=["~/.config/opencode"],
        mcp_config_paths=[],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="antigravity",
        client_exists_paths=["~/.gemini/antigravity"],
        mcp_config_paths=["~/.gemini/antigravity/mcp_config.json"],
        skills_dir_paths=[],
    ),
]


def _discovery_identity(client: CandidateClient) -> str:
    """A stable key covering everything that makes a client's discovery distinct.

    Every discovery-relevant field is included, so two entries that differ only
    in their glob lists or their location-scope overrides stay distinct. A key
    that named only the path lists would silently collapse them and apply one
    platform's scope labels to the other.
    """
    return client.model_dump_json(
        include={
            "name",
            "client_exists_paths",
            "mcp_config_paths",
            "skills_dir_paths",
            "mcp_config_globs",
            "skills_dir_globs",
            "max_glob_depth",
            "default_location_scope",
            "mcp_config_path_scopes",
            "skills_dir_path_scopes",
            "mcp_config_glob_scopes",
            "skills_dir_glob_scopes",
            "mcp_config_path_nested_scopes",
        }
    )


def merge_platform_clients(primary: list[CandidateClient], secondary: list[CandidateClient]) -> list[CandidateClient]:
    """Concatenate two per-OS client lists, dropping structural duplicates.

    On Windows we may also be scanning Linux home directories that live inside
    WSL distros (exposed as ``\\\\wsl.localhost\\<Distro>\\home\\<user>``). The Linux
    client definitions use Linux-conventional paths (e.g. ``~/.config/Code``,
    ``~/.claude.json``), which only match when expanded against a WSL home; the
    Windows definitions only match against Windows-native homes. Merging both
    lists gets WSL homes probed with Linux paths, while dropping Linux entries
    whose discovery rules are identical to an existing Windows entry (e.g.
    ``cursor`` uses ``~/.cursor/mcp.json`` on both) avoids scanning the same MCP
    server twice per home.
    """
    seen: set[str] = set()
    merged: list[CandidateClient] = []
    for client in [*primary, *secondary]:
        key = _discovery_identity(client)
        if key in seen:
            continue
        seen.add(key)
        merged.append(client)
    return merged


def get_well_known_clients() -> list[CandidateClient]:
    if sys.platform == "linux" or sys.platform == "linux2":
        return LINUX_WELL_KNOWN_CLIENTS
    elif sys.platform == "darwin":
        return MACOS_WELL_KNOWN_CLIENTS
    elif sys.platform == "win32":
        return merge_platform_clients(WINDOWS_WELL_KNOWN_CLIENTS, LINUX_WELL_KNOWN_CLIENTS)
    else:
        return []


def get_client_from_path(path: str) -> str | None:
    """
    Returns the client name from a path.

    Args:
        path (str): The path to get the client from.

    Returns:
        str: The client name or None if it cannot be guessed from the path.
    """
    path = os.path.realpath(os.path.expanduser(path))
    for client in get_well_known_clients():
        real_paths = [os.path.realpath(os.path.expanduser(p)) for p in client.mcp_config_paths]
        if path in real_paths:
            return client.name
        for pattern in client.mcp_config_globs:
            expanded = os.path.expanduser(pattern)
            if path in [os.path.realpath(p) for p in glob.glob(expanded, recursive=True)]:
                return client.name
    return None


def expand_path(path: Path, home_directory: Path | None) -> Path:
    if home_directory is None or not str(path).startswith("~"):
        return path

    suffix = path.parts[1:]
    return home_directory / Path(*suffix)
