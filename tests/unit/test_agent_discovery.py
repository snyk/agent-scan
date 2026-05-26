"""Tests for the per-agent discovery ABC (agent_discovery module)."""

from pathlib import Path
from unittest.mock import patch

import pytest

from agent_scan.models import (
    ClientToInspect,
    SkillServer,
    StdioServer,
)


# --- ClaudeCodeDiscoverer: client_exists ---


def test_claude_code_discoverer_detects_installation(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()

    discoverer = ClaudeCodeDiscoverer()
    result = discoverer.client_exists(tmp_path)

    assert result is not None
    assert result.endswith("/.claude")


def test_claude_code_discoverer_returns_none_when_absent(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    discoverer = ClaudeCodeDiscoverer()
    result = discoverer.client_exists(tmp_path)

    assert result is None


# --- ClaudeCodeDiscoverer: discover_mcp_servers ---


@pytest.mark.asyncio
async def test_claude_code_discoverer_parses_mcp_servers(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"mcpServers": {"my-server": {"command": "echo", "args": ["hi"]}}}'
    )

    discoverer = ClaudeCodeDiscoverer()
    mcp_configs = await discoverer.discover_mcp_servers(tmp_path)

    assert len(mcp_configs) == 1
    config_path = next(iter(mcp_configs))
    assert config_path.endswith("/.claude.json")
    entries = mcp_configs[config_path]
    assert isinstance(entries, list)
    assert len(entries) == 1
    name, server = entries[0]
    assert name == "my-server"
    assert isinstance(server, StdioServer)
    assert server.command == "echo"


@pytest.mark.asyncio
async def test_claude_code_discoverer_returns_empty_when_mcp_config_missing(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    # no ~/.claude.json on disk

    discoverer = ClaudeCodeDiscoverer()
    mcp_configs = await discoverer.discover_mcp_servers(tmp_path)

    # Missing config files are silently skipped (matches legacy behavior when
    # create_file_not_found_error=False).
    assert mcp_configs == {}


# --- ClaudeCodeDiscoverer: discover_skills ---


def test_claude_code_discoverer_parses_skills(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    skills_dir = tmp_path / ".claude" / "skills"
    skills_dir.mkdir(parents=True)
    my_skill = skills_dir / "my-skill"
    my_skill.mkdir()
    (my_skill / "SKILL.md").write_text(
        "---\nname: my-skill\ndescription: A test skill\n---\n\nBody.\n"
    )

    discoverer = ClaudeCodeDiscoverer()
    skills_dirs = discoverer.discover_skills(tmp_path)

    assert len(skills_dirs) == 1
    dir_path = next(iter(skills_dirs))
    assert dir_path.endswith("/.claude/skills")
    skills = skills_dirs[dir_path]
    assert isinstance(skills, list)
    assert len(skills) == 1
    skill_name, skill = skills[0]
    assert skill_name == "my-skill"
    assert isinstance(skill, SkillServer)


def test_claude_code_discoverer_skills_returns_empty_when_dir_missing(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    # no ~/.claude/skills on disk

    discoverer = ClaudeCodeDiscoverer()
    skills_dirs = discoverer.discover_skills(tmp_path)

    assert skills_dirs == {}


# --- ClaudeCodeDiscoverer: end-to-end discover() ---


@pytest.mark.asyncio
async def test_claude_code_discoverer_discover_assembles_client_to_inspect(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"mcpServers": {"toy": {"command": "echo", "args": []}}}'
    )
    my_skill = tmp_path / ".claude" / "skills" / "demo"
    my_skill.mkdir(parents=True)
    (my_skill / "SKILL.md").write_text(
        "---\nname: demo\ndescription: Demo skill\n---\n\nBody.\n"
    )

    discoverer = ClaudeCodeDiscoverer()
    cti = await discoverer.discover(tmp_path)

    assert cti is not None
    assert isinstance(cti, ClientToInspect)
    assert cti.name == "claude code"
    assert cti.client_path.endswith("/.claude")
    assert len(cti.mcp_configs) == 1
    assert len(cti.skills_dirs) == 1


@pytest.mark.asyncio
async def test_claude_code_discoverer_discover_returns_none_when_not_installed(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    discoverer = ClaudeCodeDiscoverer()
    cti = await discoverer.discover(tmp_path)

    assert cti is None


# --- get_discoverer factory ---


def test_get_discoverer_returns_claude_code_discoverer():
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer, get_discoverer

    discoverer = get_discoverer("claude code")
    assert isinstance(discoverer, ClaudeCodeDiscoverer)


@pytest.mark.parametrize(
    "agent_name",
    ["cursor", "vscode", "windsurf", "claude", "codex", "gemini cli", "amp", "kiro"],
)
def test_get_discoverer_raises_not_implemented_for_unregistered_agent(agent_name):
    from agent_scan.agent_discovery import get_discoverer

    with pytest.raises(NotImplementedError):
        get_discoverer(agent_name)


# --- Pipeline dispatch: ABC for Claude Code, legacy for everything else ---


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_uses_abc_for_claude_code(tmp_path):
    """Claude Code should be discovered via ClaudeCodeDiscoverer.discover, not the legacy path."""
    from agent_scan.models import CandidateClient
    from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {}}')

    candidate = CandidateClient(
        name="claude code",
        client_exists_paths=["~/.claude"],
        mcp_config_paths=["~/.claude.json"],
        skills_dir_paths=["~/.claude/skills"],
    )

    with (
        patch(
            "agent_scan.pipelines.get_readable_home_directories",
            return_value=[(tmp_path, "alice")],
        ),
        patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
        patch("agent_scan.pipelines.get_mcp_config_per_client") as spy_legacy,
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=[])
        ctis, _, _ = await discover_clients_to_inspect(args)

    assert not spy_legacy.called, "Legacy path must not be called for claude code"
    assert len(ctis) == 1
    assert ctis[0].name == "claude code"
    assert ctis[0].username == "alice"


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_falls_back_to_legacy_for_non_claude(tmp_path):
    """Non-Claude agents (e.g. cursor) should still go through get_mcp_config_per_client."""
    from agent_scan.models import CandidateClient
    from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect

    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text('{"mcpServers": {}}')

    candidate = CandidateClient(
        name="cursor",
        client_exists_paths=["~/.cursor"],
        mcp_config_paths=["~/.cursor/mcp.json"],
        skills_dir_paths=[],
    )

    with (
        patch(
            "agent_scan.pipelines.get_readable_home_directories",
            return_value=[(tmp_path, "alice")],
        ),
        patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=[])
        ctis, _, _ = await discover_clients_to_inspect(args)

    assert len(ctis) == 1
    assert ctis[0].name == "cursor"
    assert ctis[0].username == "alice"
