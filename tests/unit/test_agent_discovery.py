"""Tests for the per-agent discovery ABC (agent_discovery module)."""

from unittest.mock import patch

import pytest

from agent_scan.models import (
    ClientToInspect,
    CouldNotParseMCPConfig,
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
    (tmp_path / ".claude.json").write_text('{"mcpServers": {"my-server": {"command": "echo", "args": ["hi"]}}}')

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
async def test_claude_code_discoverer_returns_empty_when_json_has_no_mcp_fields(tmp_path):
    """JSON without top-level mcpServers and without projects returns no entries."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"unrelated": "data"}')

    discoverer = ClaudeCodeDiscoverer()
    mcp_configs = await discoverer.discover_mcp_servers(tmp_path)

    assert mcp_configs == {}


@pytest.mark.asyncio
async def test_claude_code_discoverer_records_could_not_parse_on_invalid_json(tmp_path):
    """Malformed JSON in ~/.claude.json becomes CouldNotParseMCPConfig with traceback."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text("{not valid json")

    discoverer = ClaudeCodeDiscoverer()
    mcp_configs = await discoverer.discover_mcp_servers(tmp_path)

    assert len(mcp_configs) == 1
    entry = next(iter(mcp_configs.values()))
    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure is True
    assert entry.traceback


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
    (my_skill / "SKILL.md").write_text("---\nname: my-skill\ndescription: A test skill\n---\n\nBody.\n")

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


# --- ClaudeCodeDiscoverer: private folder enumeration ---


def test_claude_code_discoverer_global_folders_returns_claude_dir(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    folders = ClaudeCodeDiscoverer()._discover_global_folders(tmp_path)

    assert len(folders) == 1
    assert folders[0].as_posix().endswith("/.claude")


def test_claude_code_discoverer_project_folders_lists_project_paths(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"projects": {"/Users/alice/repo-a": {"mcpServers": {}}, "/Users/alice/repo-b": {"mcpServers": {}}}}'
    )

    folders = ClaudeCodeDiscoverer()._discover_project_folders(tmp_path)

    folder_strs = {f.as_posix() for f in folders}
    assert folder_strs == {"/Users/alice/repo-a", "/Users/alice/repo-b"}


def test_claude_code_discoverer_project_folders_empty_when_no_projects_key(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {}}')

    folders = ClaudeCodeDiscoverer()._discover_project_folders(tmp_path)

    assert folders == []


def test_claude_code_discoverer_project_folders_empty_when_config_missing(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    folders = ClaudeCodeDiscoverer()._discover_project_folders(tmp_path)

    assert folders == []


# --- ClaudeCodeDiscoverer: project MCP servers ---


@pytest.mark.asyncio
async def test_claude_code_discoverer_parses_project_mcp_servers(tmp_path):
    """Each project's mcpServers becomes its own entry keyed by the project path."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"projects": {'
        '"/work/repo-a": {"mcpServers": {"srv-a": {"command": "echo", "args": ["a"]}}}, '
        '"/work/repo-b": {"mcpServers": {"srv-b": {"command": "echo", "args": ["b"]}}}'
        "}}"
    )

    mcp_configs = await ClaudeCodeDiscoverer()._discover_project_mcp_servers(tmp_path)

    assert set(mcp_configs) == {"/work/repo-a", "/work/repo-b"}
    entries_a = mcp_configs["/work/repo-a"]
    assert isinstance(entries_a, list) and len(entries_a) == 1
    name_a, server_a = entries_a[0]
    assert name_a == "srv-a"
    assert isinstance(server_a, StdioServer)


@pytest.mark.asyncio
async def test_claude_code_discoverer_project_mcp_servers_skips_projects_without_mcp(tmp_path):
    """Projects with no mcpServers key (or empty) don't produce entries."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"projects": {'
        '"/work/with-servers": {"mcpServers": {"srv": {"command": "echo"}}}, '
        '"/work/empty": {"mcpServers": {}}, '
        '"/work/no-key": {"otherField": 1}'
        "}}"
    )

    mcp_configs = await ClaudeCodeDiscoverer()._discover_project_mcp_servers(tmp_path)

    assert set(mcp_configs) == {"/work/with-servers"}


@pytest.mark.asyncio
async def test_claude_code_discoverer_discover_mcp_servers_combines_global_and_project(tmp_path):
    """The public discover_mcp_servers merges global + project results."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"mcpServers": {"global-srv": {"command": "g"}}, '
        '"projects": {"/work/repo": {"mcpServers": {"proj-srv": {"command": "p"}}}}}'
    )

    mcp_configs = await ClaudeCodeDiscoverer().discover_mcp_servers(tmp_path)

    # Two keys: one for the global file path, one for the project path.
    assert len(mcp_configs) == 2
    # Find the global entry by key suffix
    global_keys = [k for k in mcp_configs if k.endswith("/.claude.json")]
    project_keys = [k for k in mcp_configs if k == "/work/repo"]
    assert len(global_keys) == 1 and len(project_keys) == 1
    global_entry = mcp_configs[global_keys[0]]
    project_entry = mcp_configs[project_keys[0]]
    assert isinstance(global_entry, list) and global_entry[0][0] == "global-srv"
    assert isinstance(project_entry, list) and project_entry[0][0] == "proj-srv"


# --- ClaudeCodeDiscoverer: project skills ---


def test_claude_code_discoverer_project_skills_scans_per_project_dotclaude(tmp_path):
    """For each project listed in ~/.claude.json, scan <project>/.claude/skills."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    (project_root / ".claude" / "skills" / "proj-skill").mkdir(parents=True)
    (project_root / ".claude" / "skills" / "proj-skill" / "SKILL.md").write_text(
        "---\nname: proj-skill\ndescription: A project skill\n---\n\nBody.\n"
    )
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    skills_dirs = ClaudeCodeDiscoverer()._discover_project_skills(tmp_path)

    assert len(skills_dirs) == 1
    key = next(iter(skills_dirs))
    assert key.endswith("/.claude/skills")
    entries = skills_dirs[key]
    assert isinstance(entries, list) and len(entries) == 1
    skill_name, skill = entries[0]
    assert skill_name == "proj-skill"
    assert isinstance(skill, SkillServer)


def test_claude_code_discoverer_project_skills_skips_missing_project_folders(tmp_path):
    """Projects whose folders don't exist on disk are silently skipped."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"projects": {"/nonexistent/path/that/wont/be/here": {"mcpServers": {}}}}')

    skills_dirs = ClaudeCodeDiscoverer()._discover_project_skills(tmp_path)

    assert skills_dirs == {}


def test_claude_code_discoverer_discover_skills_combines_global_and_project(tmp_path):
    """The public discover_skills merges global + project results."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude" / "skills" / "global-skill").mkdir(parents=True)
    (tmp_path / ".claude" / "skills" / "global-skill" / "SKILL.md").write_text(
        "---\nname: global-skill\ndescription: g\n---\n\nB.\n"
    )
    project_root = tmp_path / "work" / "repo"
    (project_root / ".claude" / "skills" / "proj-skill").mkdir(parents=True)
    (project_root / ".claude" / "skills" / "proj-skill" / "SKILL.md").write_text(
        "---\nname: proj-skill\ndescription: p\n---\n\nB.\n"
    )
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    skills_dirs = ClaudeCodeDiscoverer().discover_skills(tmp_path)

    assert len(skills_dirs) == 2  # one global, one project


# --- ClaudeCodeDiscoverer: end-to-end discover() ---


@pytest.mark.asyncio
async def test_claude_code_discoverer_discover_assembles_client_to_inspect(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {"toy": {"command": "echo", "args": []}}}')
    my_skill = tmp_path / ".claude" / "skills" / "demo"
    my_skill.mkdir(parents=True)
    (my_skill / "SKILL.md").write_text("---\nname: demo\ndescription: Demo skill\n---\n\nBody.\n")

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


# --- ABC enforcement ---


def test_agent_discoverer_subclass_without_name_raises():
    """A subclass that forgets to set 'name' must fail at class-definition time."""
    from agent_scan.agent_discovery import AgentDiscoverer

    with pytest.raises(TypeError, match="must set a non-empty 'name'"):

        class BrokenDiscoverer(AgentDiscoverer):
            def client_exists(self, home_directory):
                return None

            async def discover_mcp_servers(self, home_directory):
                return {}

            def discover_skills(self, home_directory):
                return {}


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
