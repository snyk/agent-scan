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

    result = ClaudeCodeDiscoverer(tmp_path).client_exists()

    assert result is not None
    assert result.endswith("/.claude")


def test_claude_code_discoverer_returns_none_when_absent(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    result = ClaudeCodeDiscoverer(tmp_path).client_exists()

    assert result is None


# --- ClaudeCodeDiscoverer: discover_mcp_servers ---


@pytest.mark.asyncio
async def test_claude_code_discoverer_parses_mcp_servers(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {"my-server": {"command": "echo", "args": ["hi"]}}}')

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

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

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert mcp_configs == {}


@pytest.mark.asyncio
async def test_claude_code_discoverer_records_could_not_parse_on_invalid_json(tmp_path):
    """Malformed JSON in ~/.claude.json becomes CouldNotParseMCPConfig with traceback."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text("{not valid json")

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

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

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

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

    skills_dirs = ClaudeCodeDiscoverer(tmp_path).discover_skills()

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

    skills_dirs = ClaudeCodeDiscoverer(tmp_path).discover_skills()

    assert skills_dirs == {}


# --- ClaudeCodeDiscoverer: private folder enumeration ---


def test_claude_code_discoverer_global_folders_returns_claude_dir(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    folders = ClaudeCodeDiscoverer(tmp_path)._discover_global_folders()

    assert len(folders) == 1
    assert folders[0].as_posix().endswith("/.claude")


def test_claude_code_discoverer_project_folders_lists_project_paths(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"projects": {"/Users/alice/repo-a": {"mcpServers": {}}, "/Users/alice/repo-b": {"mcpServers": {}}}}'
    )

    folders = ClaudeCodeDiscoverer(tmp_path)._discover_project_folders()

    folder_strs = {f.as_posix() for f in folders}
    assert folder_strs == {"/Users/alice/repo-a", "/Users/alice/repo-b"}


def test_claude_code_discoverer_project_folders_empty_when_no_projects_key(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {}}')

    folders = ClaudeCodeDiscoverer(tmp_path)._discover_project_folders()

    assert folders == []


def test_claude_code_discoverer_project_folders_empty_when_config_missing(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    folders = ClaudeCodeDiscoverer(tmp_path)._discover_project_folders()

    assert folders == []


# --- ClaudeCodeDiscoverer: _project_paths_with_ancestors ---


def test_project_paths_with_ancestors_empty_when_no_projects(tmp_path):
    """No projects listed in ~/.claude.json → empty list."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"projects": {}}')

    paths = ClaudeCodeDiscoverer(tmp_path)._project_paths_with_ancestors()

    assert paths == []


def test_project_paths_with_ancestors_walks_up_to_filesystem_root(tmp_path):
    """A single project fans out into itself + every ancestor up to '/'."""
    from pathlib import Path

    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"projects": {"/a/b/c/d": {"mcpServers": {}}}}')

    paths = set(ClaudeCodeDiscoverer(tmp_path)._project_paths_with_ancestors())

    assert Path("/a/b/c/d") in paths
    assert Path("/a/b/c") in paths
    assert Path("/a/b") in paths
    assert Path("/a") in paths
    assert Path("/") in paths


def test_project_paths_with_ancestors_dedups_shared_ancestors(tmp_path):
    """Two sibling projects sharing ancestors yield each ancestor only once."""
    from pathlib import Path

    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"projects": {"/a/b/c/d": {"mcpServers": {}}, "/a/b/x/y": {"mcpServers": {}}}}'
    )

    paths = ClaudeCodeDiscoverer(tmp_path)._project_paths_with_ancestors()

    assert len(paths) == len(set(paths))  # no duplicates
    as_set = set(paths)
    assert {
        Path("/a/b/c/d"),
        Path("/a/b/c"),
        Path("/a/b/x/y"),
        Path("/a/b/x"),
        Path("/a/b"),
        Path("/a"),
        Path("/"),
    } <= as_set


def test_project_paths_with_ancestors_terminates_at_root(tmp_path):
    """Walk terminates at filesystem root (no infinite loop)."""
    from pathlib import Path

    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"projects": {"/": {"mcpServers": {}}}}')

    paths = ClaudeCodeDiscoverer(tmp_path)._project_paths_with_ancestors()

    assert paths == [Path("/")]


# --- ClaudeCodeDiscoverer: skill discovery walks ancestors ---


def test_claude_code_discoverer_project_skills_walks_ancestors(tmp_path):
    """An ancestor of a project with a .claude/skills dir is also scanned."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    # skills live at the *parent* of the project root, not the project itself
    ancestor_skills = tmp_path / "work" / ".claude" / "skills" / "ancestor-skill"
    ancestor_skills.mkdir(parents=True)
    (ancestor_skills / "SKILL.md").write_text(
        "---\nname: ancestor-skill\ndescription: An ancestor skill\n---\n\nBody.\n"
    )
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_project_skills()

    keys = list(skills_dirs)
    assert any(k.endswith("/work/.claude/skills") for k in keys)


def test_claude_code_discoverer_project_skills_dedups_shared_ancestor_skills(tmp_path):
    """Two sibling projects whose shared ancestor has skills produce a single entry."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    repo_a = tmp_path / "work" / "repo-a"
    repo_b = tmp_path / "work" / "repo-b"
    repo_a.mkdir(parents=True)
    repo_b.mkdir(parents=True)
    shared_skill = tmp_path / "work" / ".claude" / "skills" / "shared"
    shared_skill.mkdir(parents=True)
    (shared_skill / "SKILL.md").write_text("---\nname: shared\ndescription: s\n---\n\nB.\n")
    (tmp_path / ".claude.json").write_text(
        f'{{"projects": {{"{repo_a.as_posix()}": {{"mcpServers": {{}}}}, '
        f'"{repo_b.as_posix()}": {{"mcpServers": {{}}}}}}}}'
    )

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_project_skills()

    shared_keys = [k for k in skills_dirs if k.endswith("/work/.claude/skills")]
    assert len(shared_keys) == 1


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

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

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

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    assert set(mcp_configs) == {"/work/with-servers"}


@pytest.mark.asyncio
async def test_claude_code_discoverer_project_mcp_servers_reads_dotmcp_file(tmp_path):
    """A <project>/.mcp.json file is parsed as an additional MCP source for that project."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    (project_root / ".mcp.json").write_text('{"mcpServers": {"file-srv": {"command": "f"}}}')
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/repo/.mcp.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "file-srv"
    assert isinstance(server, StdioServer)


@pytest.mark.asyncio
async def test_claude_code_discoverer_project_mcp_servers_reads_ancestor_dotmcp(tmp_path):
    """A <ancestor>/.mcp.json is also discovered while walking up from a project."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    (tmp_path / "work" / ".mcp.json").write_text('{"mcpServers": {"anc-srv": {"command": "a"}}}')
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/work/.mcp.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list) and entries[0][0] == "anc-srv"


@pytest.mark.asyncio
async def test_claude_code_discoverer_project_mcp_servers_records_could_not_parse_for_dotmcp(tmp_path):
    """A malformed <project>/.mcp.json becomes a CouldNotParseMCPConfig entry."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    (project_root / ".mcp.json").write_text("{not valid json")
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/.mcp.json")]
    assert len(file_keys) == 1
    entry = mcp_configs[file_keys[0]]
    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure is True
    assert entry.traceback


@pytest.mark.asyncio
async def test_claude_code_discoverer_discover_mcp_servers_combines_global_and_project(tmp_path):
    """The public discover_mcp_servers merges global + project results."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"mcpServers": {"global-srv": {"command": "g"}}, '
        '"projects": {"/work/repo": {"mcpServers": {"proj-srv": {"command": "p"}}}}}'
    )

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    # Two keys: one for the global file path, one for the project path.
    assert len(mcp_configs) == 2
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

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_project_skills()

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

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_project_skills()

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

    skills_dirs = ClaudeCodeDiscoverer(tmp_path).discover_skills()

    assert len(skills_dirs) == 2  # one global, one project


# --- ClaudeCodeDiscoverer: plugin MCP + skills ---


@pytest.mark.asyncio
async def test_claude_code_discoverer_plugin_mcp_servers_parses_flat_format(tmp_path):
    """Plugin .mcp.json files use the flat {name: serverConfig} format."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "vendor" / "my-plugin" / "1.0.0"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text('{"plugin-srv": {"command": "echo", "args": ["p"]}}')

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert len(mcp_configs) == 1
    key = next(iter(mcp_configs))
    assert key.endswith("/1.0.0/.mcp.json")
    entries = mcp_configs[key]
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "plugin-srv"
    assert isinstance(server, StdioServer)


@pytest.mark.asyncio
async def test_claude_code_discoverer_plugin_mcp_servers_empty_when_cache_missing(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert mcp_configs == {}


@pytest.mark.asyncio
async def test_claude_code_discoverer_plugin_mcp_records_could_not_parse(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "bad" / "plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text("{not valid json")

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert len(mcp_configs) == 1
    entry = next(iter(mcp_configs.values()))
    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure is True


def test_claude_code_discoverer_plugin_skills_scans_cache(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    plugin_skill_dir = tmp_path / ".claude" / "plugins" / "cache" / "vendor" / "my-plugin" / "skills" / "plug-skill"
    plugin_skill_dir.mkdir(parents=True)
    (plugin_skill_dir / "SKILL.md").write_text("---\nname: plug-skill\ndescription: p\n---\n\nB.\n")

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_skills()

    assert len(skills_dirs) == 1
    key = next(iter(skills_dirs))
    assert key.endswith("/my-plugin/skills")
    entries = skills_dirs[key]
    assert isinstance(entries, list) and len(entries) == 1
    skill_name, skill = entries[0]
    assert skill_name == "plug-skill"
    assert isinstance(skill, SkillServer)


def test_claude_code_discoverer_plugin_skills_empty_when_cache_missing(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_skills()

    assert skills_dirs == {}


@pytest.mark.asyncio
async def test_claude_code_discoverer_discover_mcp_includes_plugin_servers(tmp_path):
    """Plugin MCP entries flow through public discover_mcp_servers."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "v" / "p"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text('{"plug": {"command": "x"}}')

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    plugin_keys = [k for k in mcp_configs if k.endswith("/p/.mcp.json")]
    assert len(plugin_keys) == 1


def test_claude_code_discoverer_discover_skills_includes_plugin_skills(tmp_path):
    """Plugin skill dirs flow through public discover_skills."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    plugin_skill_dir = tmp_path / ".claude" / "plugins" / "cache" / "v" / "p" / "skills" / "ps"
    plugin_skill_dir.mkdir(parents=True)
    (plugin_skill_dir / "SKILL.md").write_text("---\nname: ps\ndescription: x\n---\n\nB.\n")

    skills_dirs = ClaudeCodeDiscoverer(tmp_path).discover_skills()

    plugin_keys = [k for k in skills_dirs if "/plugins/cache/" in k]
    assert len(plugin_keys) == 1


@pytest.mark.asyncio
async def test_claude_code_discoverer_plugin_mcp_servers_scans_repos_dir(tmp_path):
    """Plugins staged under ~/.claude/plugins/repos/**/ are also discovered."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    repo_plugin = tmp_path / ".claude" / "plugins" / "repos" / "owner" / "plugin-repo"
    repo_plugin.mkdir(parents=True)
    (repo_plugin / ".mcp.json").write_text('{"repo-srv": {"command": "r"}}')

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    repos_keys = [k for k in mcp_configs if "/plugins/repos/" in k]
    assert len(repos_keys) == 1
    entries = mcp_configs[repos_keys[0]]
    assert isinstance(entries, list) and entries[0][0] == "repo-srv"


def test_claude_code_discoverer_plugin_skills_scans_repos_dir(tmp_path):
    """Plugin skills staged under ~/.claude/plugins/repos/**/ are also discovered."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    skills_dir = tmp_path / ".claude" / "plugins" / "repos" / "owner" / "plugin" / "skills" / "rs"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("---\nname: rs\ndescription: r\n---\n\nB.\n")

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_skills()

    repos_keys = [k for k in skills_dirs if "/plugins/repos/" in k]
    assert len(repos_keys) == 1


@pytest.mark.asyncio
async def test_claude_code_discoverer_plugin_mcp_servers_scans_both_cache_and_repos(tmp_path):
    """Both cache and repos contribute, keyed by their distinct file paths."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    cache_plugin = tmp_path / ".claude" / "plugins" / "cache" / "c" / "p"
    cache_plugin.mkdir(parents=True)
    (cache_plugin / ".mcp.json").write_text('{"c-srv": {"command": "c"}}')

    repo_plugin = tmp_path / ".claude" / "plugins" / "repos" / "r" / "p"
    repo_plugin.mkdir(parents=True)
    (repo_plugin / ".mcp.json").write_text('{"r-srv": {"command": "r"}}')

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert any("/plugins/cache/" in k for k in mcp_configs)
    assert any("/plugins/repos/" in k for k in mcp_configs)


# --- ClaudeCodeDiscoverer: end-to-end discover() ---


@pytest.mark.asyncio
async def test_claude_code_discoverer_discover_assembles_client_to_inspect(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {"toy": {"command": "echo", "args": []}}}')
    my_skill = tmp_path / ".claude" / "skills" / "demo"
    my_skill.mkdir(parents=True)
    (my_skill / "SKILL.md").write_text("---\nname: demo\ndescription: Demo skill\n---\n\nBody.\n")

    cti = await ClaudeCodeDiscoverer(tmp_path).discover()

    assert cti is not None
    assert isinstance(cti, ClientToInspect)
    assert cti.name == "claude code"
    assert cti.client_path.endswith("/.claude")
    assert len(cti.mcp_configs) == 1
    assert len(cti.skills_dirs) == 1


@pytest.mark.asyncio
async def test_claude_code_discoverer_discover_returns_none_when_not_installed(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    cti = await ClaudeCodeDiscoverer(tmp_path).discover()

    assert cti is None


# --- ABC enforcement ---


def test_agent_discoverer_subclass_without_name_raises():
    """A subclass that forgets to set 'name' must fail at class-definition time."""
    from agent_scan.agent_discovery import AgentDiscoverer

    with pytest.raises(TypeError, match="must set a non-empty 'name'"):

        class BrokenDiscoverer(AgentDiscoverer):
            def client_exists(self):
                return None

            async def discover_mcp_servers(self):
                return {}

            def discover_skills(self):
                return {}


# --- DISCOVERERS registry + find_discoverers ---


def test_DISCOVERERS_registers_only_claude_code():
    from agent_scan.agent_discovery import DISCOVERERS

    assert set(DISCOVERERS) == {"claude code"}


def test_find_discoverers_returns_claude_code_when_installed(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer, find_discoverers

    (tmp_path / ".claude").mkdir()

    found = find_discoverers(tmp_path)

    assert len(found) == 1
    assert isinstance(found[0], ClaudeCodeDiscoverer)
    assert found[0].home_directory == tmp_path


def test_find_discoverers_returns_empty_when_no_agents_installed(tmp_path):
    from agent_scan.agent_discovery import find_discoverers

    found = find_discoverers(tmp_path)

    assert found == []


# --- _dedup_mcp_servers (load-bearing helper) ---


def test_dedup_mcp_servers_keeps_each_server_in_latest_inserted_key():
    """Server names appearing in multiple keys are retained only under the latest one."""
    from agent_scan.pipelines import _dedup_mcp_servers

    srv1_a = StdioServer(command="a")
    srv1_b = StdioServer(command="b")
    srv2 = StdioServer(command="c")
    cti = ClientToInspect(
        name="claude code",
        client_path="/home/alice/.claude",
        mcp_configs={
            "/home/alice/.claude.json": [("srv1", srv1_a), ("srv2", srv2)],
            "/work/repo": [("srv1", srv1_b)],
        },
        skills_dirs={},
    )

    _dedup_mcp_servers(cti)

    assert cti.mcp_configs["/home/alice/.claude.json"] == [("srv2", srv2)]
    assert cti.mcp_configs["/work/repo"] == [("srv1", srv1_b)]


def test_dedup_mcp_servers_preserves_error_type_entries():
    """Error-type values (e.g., CouldNotParseMCPConfig) are not modified by dedup."""
    from agent_scan.pipelines import _dedup_mcp_servers

    err = CouldNotParseMCPConfig(message="boom", traceback="tb", is_failure=True)
    srv = StdioServer(command="x")
    cti = ClientToInspect(
        name="claude code",
        client_path="/home/alice/.claude",
        mcp_configs={
            "/home/alice/.claude.json": err,
            "/work/repo": [("srv", srv)],
        },
        skills_dirs={},
    )

    _dedup_mcp_servers(cti)

    assert cti.mcp_configs["/home/alice/.claude.json"] is err
    assert cti.mcp_configs["/work/repo"] == [("srv", srv)]


# --- Pipeline dispatch: legacy for all + ABC merge phase ---


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_runs_legacy_for_claude_code(tmp_path):
    """Legacy get_mcp_config_per_client is invoked for Claude Code (no longer bypassed)."""
    from agent_scan.inspect import get_mcp_config_per_client as real_legacy
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
        patch(
            "agent_scan.pipelines.get_mcp_config_per_client",
            side_effect=real_legacy,
        ) as spy_legacy,
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=[])
        await discover_clients_to_inspect(args)

    assert spy_legacy.called, "Legacy path must be called for claude code"
    called_names = {call.args[0].name for call in spy_legacy.call_args_list}
    assert "claude code" in called_names


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_merges_abc_into_legacy_cti_and_dedups_servers(tmp_path):
    """One CTI per (name, username); legacy + ABC keys both present; servers deduped to latest key."""
    from agent_scan.models import CandidateClient
    from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"projects": {"/work/repo": {"mcpServers": {"srv": {"command": "echo"}}}}}')

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
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=[])
        ctis, _, _ = await discover_clients_to_inspect(args)

    claude_ctis = [c for c in ctis if c.name == "claude code" and c.username == "alice"]
    assert len(claude_ctis) == 1
    merged = claude_ctis[0]

    keys = list(merged.mcp_configs)
    legacy_key = next(k for k in keys if k.endswith("/.claude.json"))
    abc_key = next(k for k in keys if k == "/work/repo")
    assert legacy_key and abc_key

    abc_entries = merged.mcp_configs[abc_key]
    legacy_entries = merged.mcp_configs[legacy_key]
    assert isinstance(abc_entries, list)
    assert isinstance(legacy_entries, list)
    # The single server "srv" survives only under the ABC's per-project key.
    assert [name for name, _ in abc_entries] == ["srv"]
    assert all(isinstance(s, StdioServer) for _, s in abc_entries)
    assert legacy_entries == []


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_dedup_keeps_global_only_servers_in_legacy_key(tmp_path):
    """When ABC produces no project entries, legacy's ~/.claude.json entry is untouched."""
    from agent_scan.models import CandidateClient
    from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"projects": {}}')

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
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=[])
        ctis, _, _ = await discover_clients_to_inspect(args)

    claude_ctis = [c for c in ctis if c.name == "claude code"]
    assert len(claude_ctis) == 1
    keys = list(claude_ctis[0].mcp_configs)
    # Only legacy keys present (no project keys from ABC to dedup against).
    assert keys == [k for k in keys if k.endswith("/.claude.json")]


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_abc_wins_on_same_key_collision(tmp_path):
    """Both paths produce a ~/.claude.json key; ABC's value wins after merge+dedup."""
    from agent_scan.models import CandidateClient
    from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"mcpServers": {"top": {"command": "from-top"}}, '
        '"projects": {"/work/repo": {"mcpServers": {"proj": {"command": "from-proj"}}}}}'
    )

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
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=[])
        ctis, _, _ = await discover_clients_to_inspect(args)

    claude_ctis = [c for c in ctis if c.name == "claude code"]
    assert len(claude_ctis) == 1
    merged = claude_ctis[0]

    legacy_key = next(k for k in merged.mcp_configs if k.endswith("/.claude.json"))
    entries = merged.mcp_configs[legacy_key]
    assert isinstance(entries, list)
    # After ABC's value overrides legacy under ~/.claude.json AND dedup moves "proj"
    # into /work/repo, the legacy key retains only the global "top".
    assert [name for name, _ in entries] == ["top"]


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_falls_back_to_legacy_for_non_claude(tmp_path):
    """Non-Claude agents (e.g. cursor) still go through get_mcp_config_per_client."""
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


# --- Plugin discovery depth cap ---


@pytest.mark.asyncio
async def test_plugin_mcp_servers_respects_max_depth_cap(tmp_path):
    """Plugin .mcp.json files deeper than _MAX_PLUGIN_RGLOB_DEPTH are not discovered.

    Depth is counted as ``len(match.relative_to(base).parts)`` where ``base``
    is ``~/.claude/plugins/cache``. A file directly in ``cache/`` is depth 1.
    """
    from agent_scan.agent_discovery import _MAX_PLUGIN_RGLOB_DEPTH, ClaudeCodeDiscoverer

    cache = tmp_path / ".claude" / "plugins" / "cache"
    # Depth = _MAX_PLUGIN_RGLOB_DEPTH (allowed): N-1 intermediate dirs + the file.
    allowed_dir = cache.joinpath(*[f"d{i}" for i in range(_MAX_PLUGIN_RGLOB_DEPTH - 1)])
    allowed_dir.mkdir(parents=True)
    (allowed_dir / ".mcp.json").write_text('{"allowed-srv": {"command": "a"}}')
    # Depth = _MAX_PLUGIN_RGLOB_DEPTH + 1 (skipped).
    too_deep_dir = cache.joinpath(*[f"x{i}" for i in range(_MAX_PLUGIN_RGLOB_DEPTH)])
    too_deep_dir.mkdir(parents=True)
    (too_deep_dir / ".mcp.json").write_text('{"too-deep-srv": {"command": "x"}}')

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    server_names = {name for entries in mcp_configs.values() if isinstance(entries, list) for name, _ in entries}
    assert "allowed-srv" in server_names
    assert "too-deep-srv" not in server_names


def test_plugin_skills_respects_max_depth_cap(tmp_path):
    """Plugin skills/ dirs deeper than _MAX_PLUGIN_RGLOB_DEPTH are not discovered."""
    from agent_scan.agent_discovery import _MAX_PLUGIN_RGLOB_DEPTH, ClaudeCodeDiscoverer

    cache = tmp_path / ".claude" / "plugins" / "cache"
    # The "skills" dir itself counts as one part, so put it at the allowed boundary.
    allowed_parent = cache.joinpath(*[f"d{i}" for i in range(_MAX_PLUGIN_RGLOB_DEPTH - 1)])
    allowed_skill = allowed_parent / "skills" / "allowed-skill"
    allowed_skill.mkdir(parents=True)
    (allowed_skill / "SKILL.md").write_text("---\nname: allowed-skill\ndescription: a\n---\n\nB.\n")
    too_deep_parent = cache.joinpath(*[f"x{i}" for i in range(_MAX_PLUGIN_RGLOB_DEPTH)])
    too_deep_skill = too_deep_parent / "skills" / "too-deep-skill"
    too_deep_skill.mkdir(parents=True)
    (too_deep_skill / "SKILL.md").write_text("---\nname: too-deep-skill\ndescription: x\n---\n\nB.\n")

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_skills()

    keys = list(skills_dirs)
    assert any(k.endswith(f"/{allowed_parent.name}/skills") for k in keys)
    assert not any(k.endswith(f"/{too_deep_parent.name}/skills") for k in keys)


# --- JSON5 parsing (comments + empty-file short-circuit) ---


@pytest.mark.asyncio
async def test_load_json_file_accepts_json5_comments_and_trailing_commas(tmp_path):
    """A ~/.claude.json with // comments and a trailing comma parses successfully."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        "{\n"
        "  // top-level comment\n"
        '  "mcpServers": {\n'
        '    "my-server": {"command": "echo", "args": ["hi"]},\n'  # trailing comma below
        "  },\n"
        "}\n"
    )

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert len(mcp_configs) == 1
    entries = next(iter(mcp_configs.values()))
    assert isinstance(entries, list)
    assert [name for name, _ in entries] == ["my-server"]


@pytest.mark.asyncio
async def test_load_json_file_treats_empty_file_as_empty_config(tmp_path):
    """An empty (or whitespace-only) ~/.claude.json returns no entries, not a parse error."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text("   \n  \n")

    mcp_configs = await ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert mcp_configs == {}


# --- _validate_servers writes check_server_signature result back into the dict ---


def test_validate_servers_writes_check_server_signature_result_into_dict(tmp_path):
    """_validate_servers must replace each stdio entry with the value returned by
    check_server_signature — not just rely on in-place mutation of the input."""
    from unittest.mock import patch as mock_patch

    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    replacement = StdioServer(command="replacement", binary_identifier="sig-from-mock")

    with mock_patch(
        "agent_scan.agent_discovery.check_server_signature",
        return_value=replacement,
    ) as signature_mock:
        result = ClaudeCodeDiscoverer(tmp_path)._validate_servers({"srv": {"command": "original"}}, source="test")

    assert signature_mock.called
    assert isinstance(result, list)
    assert len(result) == 1
    name, server = result[0]
    assert name == "srv"
    assert server is replacement


# --- find_discoverers exception safety ---


def test_find_discoverers_skips_discoverer_that_raises_unexpected_exception(tmp_path):
    """A discoverer whose client_exists() raises must not crash find_discoverers."""
    from agent_scan.agent_discovery import (
        DISCOVERERS,
        AgentDiscoverer,
        ClaudeCodeDiscoverer,
        find_discoverers,
    )

    class ExplodingDiscoverer(AgentDiscoverer):
        name = "exploding"

        def client_exists(self):
            raise RuntimeError("boom")

        async def discover_mcp_servers(self):
            return {}

        def discover_skills(self):
            return {}

    (tmp_path / ".claude").mkdir()
    DISCOVERERS["exploding"] = ExplodingDiscoverer
    try:
        found = find_discoverers(tmp_path)
    finally:
        del DISCOVERERS["exploding"]

    assert len(found) == 1
    assert isinstance(found[0], ClaudeCodeDiscoverer)
