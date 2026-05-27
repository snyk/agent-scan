import glob
import logging
import os
import sys
from pathlib import Path

from agent_scan.models import CandidateClient

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
        name="claude",
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
            ".openclaw/skills",
        ],
    ),
    CandidateClient(
        name="amp",
        client_exists_paths=["~/.config/agents", ".amp"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.config/agents/skills", ".amp/skills"],
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
            ".openclaw/skills",
        ],
    ),
    CandidateClient(
        name="amp",
        client_exists_paths=["~/.config/agents", ".amp"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.config/agents/skills", ".amp/skills"],
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
        name="claude",
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
            ".openclaw/skills",
        ],
    ),
    CandidateClient(
        name="amp",
        client_exists_paths=["~/.config/agents", ".amp"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.config/agents/skills", ".amp/skills"],
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


def get_well_known_clients() -> list[CandidateClient]:
    if sys.platform == "linux" or sys.platform == "linux2":
        return LINUX_WELL_KNOWN_CLIENTS
    elif sys.platform == "darwin":
        return MACOS_WELL_KNOWN_CLIENTS
    elif sys.platform == "win32":
        # On Windows we may also be scanning Linux home directories that live
        # inside WSL distros (exposed as \\wsl.localhost\<Distro>\home\<user>).
        # The Linux client definitions use Linux-conventional paths
        # (e.g. ~/.config/Code, ~/.claude.json), which only match when
        # expanded against a WSL home; the Windows definitions only match
        # against Windows-native homes. Merge both lists so WSL homes get
        # probed with Linux paths, but drop Linux entries whose discovery
        # paths are structurally identical to an existing Windows entry
        # (e.g. `cursor` uses `~/.cursor/mcp.json` on both platforms) to
        # avoid scanning the same MCP server twice per home.
        seen: set[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = set()
        merged: list[CandidateClient] = []
        for client in WINDOWS_WELL_KNOWN_CLIENTS + LINUX_WELL_KNOWN_CLIENTS:
            key = (
                client.name,
                tuple(client.client_exists_paths),
                tuple(client.mcp_config_paths),
                tuple(client.skills_dir_paths),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(client)
        return merged
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
