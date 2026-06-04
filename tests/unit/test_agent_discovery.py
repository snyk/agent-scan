"""Tests for the per-agent discovery ABC (agent_scan.agents package)."""

import sys
from unittest.mock import patch

import pytest

from agent_scan.models import (
    ClientToInspect,
    CouldNotParseMCPConfig,
    RemoteServer,
    SkillServer,
    StdioServer,
)

# --- ClaudeCodeDiscoverer: client_exists ---


def test_claude_code_discoverer_detects_installation(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()

    result = ClaudeCodeDiscoverer(tmp_path).client_exists()

    assert result is not None
    assert result.endswith("/.claude")


def test_claude_code_discoverer_returns_none_when_absent(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    result = ClaudeCodeDiscoverer(tmp_path).client_exists()

    assert result is None


# --- ClaudeCodeDiscoverer: discover_mcp_servers ---


def test_claude_code_discoverer_parses_mcp_servers(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {"my-server": {"command": "echo", "args": ["hi"]}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

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


def test_claude_code_discoverer_streamable_http_server_does_not_sink_file(tmp_path):
    """A documented ``streamable-http`` remote must not sink its whole file.

    Coverage analysis §7.1: previously one server whose ``type`` wasn't
    ``sse``/``http`` raised a ValidationError that turned the entire
    ``mcpServers`` map into ``CouldNotParseMCPConfig`` -- losing every valid
    sibling server. Both servers below must survive, with ``streamable-http``
    normalized onto ``http``.
    """
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"mcpServers": {'
        '"good-stdio": {"command": "echo", "args": ["hi"]}, '
        '"streamable": {"url": "https://mcp.example.com/mcp", "type": "streamable-http"}'
        "}}"
    )

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    config_path = next(iter(mcp_configs))
    entries = mcp_configs[config_path]
    assert isinstance(entries, list), f"file was sunk: {entries!r}"
    by_name = dict(entries)
    assert set(by_name) == {"good-stdio", "streamable"}
    assert isinstance(by_name["good-stdio"], StdioServer)
    assert isinstance(by_name["streamable"], RemoteServer)
    assert by_name["streamable"].type == "http"


def test_claude_code_discoverer_ws_server_sinks_file_pending_ads_384(tmp_path):
    """A ``type: "ws"`` server is not yet supported and currently sinks its file.

    ``ws`` is a documented Claude Code WebSocket transport, but emitting it
    breaks the downstream backend/platform (which accept ``{sse, http}`` only),
    so ``RemoteServer`` rejects it for now. Because a config's ``mcpServers`` map
    validates as a single unit, one ``ws`` server turns the whole file into
    ``CouldNotParseMCPConfig`` -- losing its valid siblings too. Re-adding ``ws``
    end-to-end (and/or per-server validation so siblings survive) is tracked in
    TODO(ADS-384): https://snyksec.atlassian.net/browse/ADS-384
    """
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"mcpServers": {'
        '"good-stdio": {"command": "echo", "args": ["hi"]}, '
        '"socket": {"url": "wss://mcp.example.com/ws", "type": "ws"}'
        "}}"
    )

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    config_path = next(iter(mcp_configs))
    assert isinstance(mcp_configs[config_path], CouldNotParseMCPConfig)


def test_claude_code_discoverer_returns_empty_when_json_has_no_mcp_fields(tmp_path):
    """JSON without top-level mcpServers and without projects returns no entries."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"unrelated": "data"}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert mcp_configs == {}


def test_claude_code_discoverer_records_could_not_parse_on_invalid_json(tmp_path):
    """Malformed JSON in ~/.claude.json becomes CouldNotParseMCPConfig with traceback."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text("{not valid json")

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert len(mcp_configs) == 1
    entry = next(iter(mcp_configs.values()))
    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure is True
    assert entry.traceback


def test_claude_code_discoverer_returns_empty_when_mcp_config_missing(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    # no ~/.claude.json on disk

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    # Missing config files are silently skipped (matches legacy behavior when
    # create_file_not_found_error=False).
    assert mcp_configs == {}


# --- ClaudeCodeDiscoverer: discover_skills ---


def test_claude_code_discoverer_parses_skills(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

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
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    # no ~/.claude/skills on disk

    skills_dirs = ClaudeCodeDiscoverer(tmp_path).discover_skills()

    assert skills_dirs == {}


# --- ClaudeCodeDiscoverer: private folder enumeration ---


def test_claude_code_discoverer_global_folders_returns_claude_dir(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    folders = ClaudeCodeDiscoverer(tmp_path)._discover_global_folders()

    assert len(folders) == 1
    assert folders[0].as_posix().endswith("/.claude")


def test_claude_code_discoverer_project_folders_lists_project_paths(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"projects": {"/Users/alice/repo-a": {"mcpServers": {}}, "/Users/alice/repo-b": {"mcpServers": {}}}}'
    )

    folders = ClaudeCodeDiscoverer(tmp_path)._discover_project_folders()

    folder_strs = {f.as_posix() for f in folders}
    assert folder_strs == {"/Users/alice/repo-a", "/Users/alice/repo-b"}


def test_claude_code_discoverer_project_folders_empty_when_no_projects_key(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {}}')

    folders = ClaudeCodeDiscoverer(tmp_path)._discover_project_folders()

    assert folders == []


def test_claude_code_discoverer_project_folders_empty_when_config_missing(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    folders = ClaudeCodeDiscoverer(tmp_path)._discover_project_folders()

    assert folders == []


# --- ClaudeCodeDiscoverer: _project_paths_with_ancestors ---


def test_project_paths_with_ancestors_empty_when_no_projects(tmp_path):
    """No projects listed in ~/.claude.json → empty list."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"projects": {}}')

    paths = ClaudeCodeDiscoverer(tmp_path)._project_paths_with_ancestors()

    assert paths == []


def test_project_paths_with_ancestors_walks_up_to_filesystem_root(tmp_path):
    """A single project fans out into itself + every ancestor up to '/'."""
    from pathlib import Path

    from agent_scan.agents import ClaudeCodeDiscoverer

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

    from agent_scan.agents import ClaudeCodeDiscoverer

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

    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"projects": {"/": {"mcpServers": {}}}}')

    paths = ClaudeCodeDiscoverer(tmp_path)._project_paths_with_ancestors()

    assert paths == [Path("/")]


# --- ClaudeCodeDiscoverer: skill discovery walks ancestors ---


def test_claude_code_discoverer_project_skills_walks_ancestors(tmp_path):
    """An ancestor of a project with a .claude/skills dir is also scanned."""
    from agent_scan.agents import ClaudeCodeDiscoverer

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
    from agent_scan.agents import ClaudeCodeDiscoverer

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


def test_claude_code_discoverer_parses_project_mcp_servers(tmp_path):
    """Each project's mcpServers becomes its own entry keyed by the project path."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"projects": {'
        '"/work/repo-a": {"mcpServers": {"srv-a": {"command": "echo", "args": ["a"]}}}, '
        '"/work/repo-b": {"mcpServers": {"srv-b": {"command": "echo", "args": ["b"]}}}'
        "}}"
    )

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    assert set(mcp_configs) == {"/work/repo-a", "/work/repo-b"}
    entries_a = mcp_configs["/work/repo-a"]
    assert isinstance(entries_a, list) and len(entries_a) == 1
    name_a, server_a = entries_a[0]
    assert name_a == "srv-a"
    assert isinstance(server_a, StdioServer)


def test_claude_code_discoverer_project_mcp_servers_skips_projects_without_mcp(tmp_path):
    """Projects with no mcpServers key (or empty) don't produce entries."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"projects": {'
        '"/work/with-servers": {"mcpServers": {"srv": {"command": "echo"}}}, '
        '"/work/empty": {"mcpServers": {}}, '
        '"/work/no-key": {"otherField": 1}'
        "}}"
    )

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    assert set(mcp_configs) == {"/work/with-servers"}


def test_claude_code_discoverer_project_mcp_servers_reads_dotmcp_file(tmp_path):
    """A <project>/.mcp.json file is parsed as an additional MCP source for that project."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    (project_root / ".mcp.json").write_text('{"mcpServers": {"file-srv": {"command": "f"}}}')
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/repo/.mcp.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "file-srv"
    assert isinstance(server, StdioServer)


def test_claude_code_discoverer_project_mcp_servers_reads_ancestor_dotmcp(tmp_path):
    """A <ancestor>/.mcp.json is also discovered while walking up from a project."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    (tmp_path / "work" / ".mcp.json").write_text('{"mcpServers": {"anc-srv": {"command": "a"}}}')
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/work/.mcp.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list) and entries[0][0] == "anc-srv"


def test_claude_code_discoverer_project_mcp_servers_records_could_not_parse_for_dotmcp(tmp_path):
    """A malformed <project>/.mcp.json becomes a CouldNotParseMCPConfig entry."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    (project_root / ".mcp.json").write_text("{not valid json")
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/.mcp.json")]
    assert len(file_keys) == 1
    entry = mcp_configs[file_keys[0]]
    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure is True
    assert entry.traceback


def test_claude_code_discoverer_project_mcp_servers_reads_flat_format_dotmcp(tmp_path):
    """A flat-format ``<project>/.mcp.json`` is also parsed via the format-union
    (``ClaudeConfigFile``/``PluginMCPConfigFile``).

    Previously a flat-format project file was silently dropped (no top-level
    "mcpServers" key). The ``PluginMCPConfigFile`` fallback now recognises it.
    """
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    (project_root / ".mcp.json").write_text('{"flat-srv": {"command": "echo", "args": ["f"]}}')
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/.mcp.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "flat-srv"
    assert isinstance(server, StdioServer)
    assert server.command == "echo"


def test_claude_code_discoverer_project_mcp_servers_flat_dotmcp_with_server_named_mcpServers(tmp_path):
    """A flat-format ``<project>/.mcp.json`` whose single server is literally named
    "mcpServers" is parsed as flat (not misread as a wrapped payload)."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    (project_root / ".mcp.json").write_text('{"mcpServers": {"command": "echo", "args": ["adv"]}}')
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/.mcp.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "mcpServers"
    assert isinstance(server, StdioServer)
    assert server.command == "echo"
    assert server.args == ["adv"]


def test_claude_code_discoverer_discover_mcp_servers_combines_global_and_project(tmp_path):
    """The public discover_mcp_servers merges global + project results."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"mcpServers": {"global-srv": {"command": "g"}}, '
        '"projects": {"/work/repo": {"mcpServers": {"proj-srv": {"command": "p"}}}}}'
    )

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

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
    from agent_scan.agents import ClaudeCodeDiscoverer

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


def test_claude_code_discoverer_project_skills_scans_agents_skills(tmp_path):
    """For each project in ~/.claude.json, also scan <project>/.agents/skills.

    ``.agents/skills`` is the cross-agent compatibility convention (verified
    that Claude Code loads it) alongside the canonical ``.claude/skills``.
    """
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    (project_root / ".agents" / "skills" / "agents-skill").mkdir(parents=True)
    (project_root / ".agents" / "skills" / "agents-skill" / "SKILL.md").write_text(
        "---\nname: agents-skill\ndescription: A cross-agent project skill\n---\n\nBody.\n"
    )
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_project_skills()

    keys = [k for k in skills_dirs if k.endswith("/.agents/skills")]
    assert len(keys) == 1
    entries = skills_dirs[keys[0]]
    assert isinstance(entries, list) and len(entries) == 1
    skill_name, skill = entries[0]
    assert skill_name == "agents-skill"
    assert isinstance(skill, SkillServer)


def test_claude_code_discoverer_project_skills_skips_missing_project_folders(tmp_path):
    """Projects whose folders don't exist on disk are silently skipped."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"projects": {"/nonexistent/path/that/wont/be/here": {"mcpServers": {}}}}')

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_project_skills()

    assert skills_dirs == {}


def test_claude_code_discoverer_discover_skills_combines_global_and_project(tmp_path):
    """The public discover_skills merges global + project results."""
    from agent_scan.agents import ClaudeCodeDiscoverer

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


def test_claude_code_discoverer_plugin_mcp_servers_parses_flat_format(tmp_path):
    """Plugin .mcp.json files use the flat {name: serverConfig} format."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "vendor" / "my-plugin" / "1.0.0"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text('{"plugin-srv": {"command": "echo", "args": ["p"]}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert len(mcp_configs) == 1
    key = next(iter(mcp_configs))
    assert key.endswith("/1.0.0/.mcp.json")
    entries = mcp_configs[key]
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "plugin-srv"
    assert isinstance(server, StdioServer)


def test_claude_code_discoverer_plugin_mcp_flat_format_with_server_named_mcpServers(tmp_path):
    """Flat-format plugin where the single server is literally named "mcpServers".

    The wrapper-vs-flat detector inspects the inner dict's keys: a wrapped
    payload's value is a server *map* and won't contain server-config keys
    (``command``/``url``/``serverUrl``), while a flat-format payload here has
    ``command`` at the top level of the inner dict. We must take the flat
    interpretation and produce a single server named "mcpServers".
    """
    from agent_scan.agents import ClaudeCodeDiscoverer

    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "vendor" / "weird-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text('{"mcpServers": {"command": "echo", "args": ["x"]}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert len(mcp_configs) == 1
    entries = next(iter(mcp_configs.values()))
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "mcpServers"
    assert isinstance(server, StdioServer)
    assert server.command == "echo"
    assert server.args == ["x"]


def test_claude_code_discoverer_plugin_mcp_wrapped_format_still_works(tmp_path):
    """The wrapped format ``{"mcpServers": {<name>: <server-config>}}`` still parses
    correctly — i.e., the detection didn't break the common case."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "vendor" / "wrapped-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text('{"mcpServers": {"real-srv": {"command": "echo", "args": ["w"]}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert len(mcp_configs) == 1
    entries = next(iter(mcp_configs.values()))
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "real-srv"
    assert isinstance(server, StdioServer)
    assert server.command == "echo"


def _parse_claude_dotmcp(tmp_path, content: str):
    """Parse a ``.mcp.json`` body the way discovery does: through Claude Code's
    format-union (``_parse_mcp_file`` with ``_CLAUDE_MCP_FORMATS``)."""
    from agent_scan.agents import ClaudeCodeDiscoverer
    from agent_scan.agents.claude_code import _CLAUDE_MCP_FORMATS

    mcp_file = tmp_path / ".mcp.json"
    mcp_file.write_text(content)
    return ClaudeCodeDiscoverer(tmp_path)._parse_mcp_file(mcp_file, formats=_CLAUDE_MCP_FORMATS)


def test_parse_mcp_file_requires_explicit_formats(tmp_path):
    """``formats`` is a required keyword-only argument: the shared base parser must
    not privilege any single agent's config shape via a default. Each caller
    declares the format-union it expects (ordering/membership are load-bearing)."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    mcp_file = tmp_path / ".mcp.json"
    mcp_file.write_text('{"mcpServers": {"s": {"command": "echo"}}}')

    with pytest.raises(TypeError):
        ClaudeCodeDiscoverer(tmp_path)._parse_mcp_file(mcp_file)


def test_parse_mcp_file_no_matching_format_records_parse_failure(tmp_path, caplog):
    """Valid JSON that matches none of the supplied ``formats`` surfaces as a
    ``CouldNotParseMCPConfig`` (not silently dropped). The accompanying log must be
    a plain error: ``logger.exception`` here runs *outside* any active handler, so it
    would tack a bogus ``NoneType: None`` traceback onto the line."""
    import logging

    with caplog.at_level(logging.ERROR, logger="agent_scan.agents.base"):
        # The ``mcpServers`` wrapper is present (so the file is recognized), but the
        # inner server has neither a ``command`` nor a URL — it validates as no format.
        entry = _parse_claude_dotmcp(tmp_path, '{"mcpServers": {"srv": {"not": "a server"}}}')

    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure

    no_match = [r for r in caplog.records if "No MCP format matched" in r.getMessage()]
    assert len(no_match) == 1
    # The branch is not inside an ``except``; exc_info must be unset rather than the
    # empty ``(None, None, None)`` tuple that ``logger.exception`` would attach.
    assert no_match[0].exc_info is None


@pytest.mark.parametrize(
    "content",
    [
        '[{"command": "echo"}]',  # JSON array root
        '"just a string"',  # JSON string root
        "[1, 2, 3]",  # JSON array of scalars
    ],
)
def test_parse_mcp_file_non_dict_root_surfaces_parse_failure(tmp_path, content):
    """An explicitly-named config file whose JSON *root* is a non-object (array /
    scalar) is unsupported MCP and must surface as ``CouldNotParseMCPConfig`` — the
    legacy ``scan_mcp_config_file`` path fails every model on a non-dict and reports
    a parse error, so silently skipping it would lose that signal.
    """
    entry = _parse_claude_dotmcp(tmp_path, content)

    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure


def test_parse_mcp_file_non_dict_root_skipped_for_opportunistic_walk(tmp_path):
    """Under ``skip_unrecognized=True`` (the extension/plugin walks that match every
    file merely *named* ``mcp.json``), a non-object root is skipped (``None``), not
    surfaced — an unrelated array/scalar file that happens to share the name must not
    become a false-positive parse error, and the recognition check must not choke on
    a non-dict.
    """
    from agent_scan.agents import ClaudeCodeDiscoverer
    from agent_scan.agents.claude_code import _CLAUDE_MCP_FORMATS

    mcp_file = tmp_path / "mcp.json"
    mcp_file.write_text("[1, 2, 3]")

    entry = ClaudeCodeDiscoverer(tmp_path)._parse_mcp_file(
        mcp_file, formats=_CLAUDE_MCP_FORMATS, skip_unrecognized=True
    )

    assert entry is None


def test_claude_mcp_formats_flat_remote_server_named_mcpServers(tmp_path):
    """A flat-format payload with a single RemoteServer named "mcpServers" (``url``
    discriminator instead of ``command``) parses as flat — one server named
    "mcpServers" — not as a wrapped map."""
    entries = _parse_claude_dotmcp(tmp_path, '{"mcpServers": {"url": "https://example.com/mcp", "type": "http"}}')

    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "mcpServers"
    assert isinstance(server, RemoteServer)
    assert server.url == "https://example.com/mcp"


def test_claude_mcp_formats_wrapped_when_inner_has_no_discriminators(tmp_path):
    """When the ``mcpServers`` value has no server-config discriminator keys at its
    top level, it is a server map → wrapped (both servers surface)."""
    entries = _parse_claude_dotmcp(
        tmp_path, '{"mcpServers": {"srv-a": {"command": "a"}, "srv-b": {"url": "https://b"}}}'
    )

    assert isinstance(entries, list)
    assert {name for name, _ in entries} == {"srv-a", "srv-b"}


def test_claude_mcp_formats_wrapped_when_server_is_named_after_discriminator(tmp_path):
    """A wrapped-format payload whose server is *named* "command" / "url" / "serverUrl"
    must NOT be misread as flat. The inner discriminator key maps to a dict (the server
    config), never a string (which only a real top-level server config would have).
    """
    for discriminator in ("command", "url", "serverUrl"):
        entries = _parse_claude_dotmcp(tmp_path, f'{{"mcpServers": {{"{discriminator}": {{"command": "/bin/echo"}}}}}}')

        assert isinstance(entries, list) and len(entries) == 1, discriminator
        name, server = entries[0]
        assert name == discriminator
        assert isinstance(server, StdioServer)
        assert server.command == "/bin/echo"


def test_claude_mcp_formats_wrapped_multiple_servers_one_named_after_discriminator(tmp_path):
    """A wrapped-format payload with multiple servers, one of which happens to be
    named "command", still parses as wrapped (the inner "command" value is a dict)."""
    entries = _parse_claude_dotmcp(
        tmp_path,
        '{"mcpServers": {"command": {"command": "/bin/cmd"}, "other": {"command": "/bin/other"}}}',
    )

    assert isinstance(entries, list)
    assert {name for name, _ in entries} == {"command", "other"}


def test_claude_mcp_formats_empty_mcpservers_map_skipped(tmp_path):
    """A ``.mcp.json`` with an empty ``mcpServers`` map yields no servers and is
    omitted from results rather than recorded as an empty entry. Guards the
    ``if not parsed`` skip that replaces the old empty-payload check."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    project_root = tmp_path / "work" / "repo"
    project_root.mkdir(parents=True)
    (project_root / ".mcp.json").write_text('{"mcpServers": {}}')
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project_root.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_project_mcp_servers()

    assert [k for k in mcp_configs if k.endswith("/.mcp.json")] == []


def test_claude_code_discoverer_plugin_mcp_wrapped_server_named_command(tmp_path):
    """End-to-end: a wrapped plugin .mcp.json with a server *named* "command" parses
    as wrapped (single server named "command"), not as flat."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "vendor" / "wrapped-cmd-plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text('{"mcpServers": {"command": {"command": "/bin/echo", "args": ["c"]}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert len(mcp_configs) == 1
    entries = next(iter(mcp_configs.values()))
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "command"
    assert isinstance(server, StdioServer)
    assert server.command == "/bin/echo"
    assert server.args == ["c"]


def test_claude_code_discoverer_plugin_mcp_servers_empty_when_cache_missing(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert mcp_configs == {}


def test_claude_code_discoverer_plugin_mcp_records_could_not_parse(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "bad" / "plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text("{not valid json")

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert len(mcp_configs) == 1
    entry = next(iter(mcp_configs.values()))
    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure is True


def test_claude_code_discoverer_plugin_skills_scans_cache(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

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
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_skills()

    assert skills_dirs == {}


def test_claude_code_discoverer_discover_mcp_includes_plugin_servers(tmp_path):
    """Plugin MCP entries flow through public discover_mcp_servers."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "v" / "p"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text('{"plug": {"command": "x"}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    plugin_keys = [k for k in mcp_configs if k.endswith("/p/.mcp.json")]
    assert len(plugin_keys) == 1


def test_claude_code_discoverer_discover_skills_includes_plugin_skills(tmp_path):
    """Plugin skill dirs flow through public discover_skills."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    plugin_skill_dir = tmp_path / ".claude" / "plugins" / "cache" / "v" / "p" / "skills" / "ps"
    plugin_skill_dir.mkdir(parents=True)
    (plugin_skill_dir / "SKILL.md").write_text("---\nname: ps\ndescription: x\n---\n\nB.\n")

    skills_dirs = ClaudeCodeDiscoverer(tmp_path).discover_skills()

    plugin_keys = [k for k in skills_dirs if "/plugins/cache/" in k]
    assert len(plugin_keys) == 1


def test_claude_code_discoverer_plugin_mcp_servers_scans_repos_dir(tmp_path):
    """Plugins staged under ~/.claude/plugins/repos/**/ are also discovered."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    repo_plugin = tmp_path / ".claude" / "plugins" / "repos" / "owner" / "plugin-repo"
    repo_plugin.mkdir(parents=True)
    (repo_plugin / ".mcp.json").write_text('{"repo-srv": {"command": "r"}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    repos_keys = [k for k in mcp_configs if "/plugins/repos/" in k]
    assert len(repos_keys) == 1
    entries = mcp_configs[repos_keys[0]]
    assert isinstance(entries, list) and entries[0][0] == "repo-srv"


def test_claude_code_discoverer_plugin_skills_scans_repos_dir(tmp_path):
    """Plugin skills staged under ~/.claude/plugins/repos/**/ are also discovered."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    skills_dir = tmp_path / ".claude" / "plugins" / "repos" / "owner" / "plugin" / "skills" / "rs"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("---\nname: rs\ndescription: r\n---\n\nB.\n")

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_skills()

    repos_keys = [k for k in skills_dirs if "/plugins/repos/" in k]
    assert len(repos_keys) == 1


def test_claude_code_discoverer_plugin_mcp_servers_scans_both_cache_and_repos(tmp_path):
    """Both cache and repos contribute, keyed by their distinct file paths."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    cache_plugin = tmp_path / ".claude" / "plugins" / "cache" / "c" / "p"
    cache_plugin.mkdir(parents=True)
    (cache_plugin / ".mcp.json").write_text('{"c-srv": {"command": "c"}}')

    repo_plugin = tmp_path / ".claude" / "plugins" / "repos" / "r" / "p"
    repo_plugin.mkdir(parents=True)
    (repo_plugin / ".mcp.json").write_text('{"r-srv": {"command": "r"}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert any("/plugins/cache/" in k for k in mcp_configs)
    assert any("/plugins/repos/" in k for k in mcp_configs)


def test_claude_code_discoverer_plugin_mcp_servers_scans_marketplaces_dir(tmp_path):
    """Plugins staged under ~/.claude/plugins/marketplaces/**/ are discovered.

    ``marketplaces/`` is the current sibling of ``cache/`` (the legacy ``repos/``
    was renamed); a plugin's source ``.mcp.json`` can live there."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    mp_plugin = tmp_path / ".claude" / "plugins" / "marketplaces" / "official" / "plugin-x"
    mp_plugin.mkdir(parents=True)
    (mp_plugin / ".mcp.json").write_text('{"mp-srv": {"command": "m"}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    mp_keys = [k for k in mcp_configs if "/plugins/marketplaces/" in k]
    assert len(mp_keys) == 1
    entries = mcp_configs[mp_keys[0]]
    assert isinstance(entries, list) and entries[0][0] == "mp-srv"


def test_claude_code_discoverer_plugin_skills_scans_marketplaces_dir(tmp_path):
    """Plugin skills staged under ~/.claude/plugins/marketplaces/**/ are discovered."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    skills_dir = tmp_path / ".claude" / "plugins" / "marketplaces" / "official" / "p" / "skills" / "ms"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("---\nname: ms\ndescription: m\n---\n\nB.\n")

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_skills()

    mp_keys = [k for k in skills_dirs if "/plugins/marketplaces/" in k]
    assert len(mp_keys) == 1


def test_claude_code_honors_plugin_cache_dir_env_on_own_home_scan(tmp_path, monkeypatch):
    """CLAUDE_CODE_PLUGIN_CACHE_DIR relocates the plugins ROOT (cache/ and
    marketplaces/ live beneath it). Honored only on an own-home scan."""
    from pathlib import Path

    from agent_scan.agents import ClaudeCodeDiscoverer

    home = tmp_path / "me"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)

    plugin_root = tmp_path / "relocated-plugins"
    plugin = plugin_root / "marketplaces" / "official" / "p"
    plugin.mkdir(parents=True)
    (plugin / ".mcp.json").write_text('{"relocated-plugin": {"command": "p"}}')
    monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(plugin_root))

    mcp_configs = ClaudeCodeDiscoverer(home)._discover_plugin_mcp_servers()

    keys = [k for k in mcp_configs if "/relocated-plugins/marketplaces/" in k]
    assert len(keys) == 1, f"CLAUDE_CODE_PLUGIN_CACHE_DIR root must be scanned; got: {list(mcp_configs)}"
    assert mcp_configs[keys[0]][0][0] == "relocated-plugin"


def test_claude_code_honors_plugin_seed_dir_env_on_own_home_scan(tmp_path, monkeypatch):
    """CLAUDE_CODE_PLUGIN_SEED_DIR lists one or more os.pathsep-separated read-only
    seed roots (container/CI pre-seeding), each mirroring the plugins layout."""
    import os
    from pathlib import Path

    from agent_scan.agents import ClaudeCodeDiscoverer

    home = tmp_path / "me"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)

    seed_a = tmp_path / "seed-a"
    seed_b = tmp_path / "seed-b"
    (seed_a / "cache" / "mp" / "p").mkdir(parents=True)
    (seed_a / "cache" / "mp" / "p" / ".mcp.json").write_text('{"seed-a-srv": {"command": "a"}}')
    (seed_b / "marketplaces" / "mp" / "p").mkdir(parents=True)
    (seed_b / "marketplaces" / "mp" / "p" / ".mcp.json").write_text('{"seed-b-srv": {"command": "b"}}')
    monkeypatch.setenv("CLAUDE_CODE_PLUGIN_SEED_DIR", os.pathsep.join([str(seed_a), str(seed_b)]))

    mcp_configs = ClaudeCodeDiscoverer(home)._discover_plugin_mcp_servers()

    names = {n for v in mcp_configs.values() if isinstance(v, list) for n, _ in v}
    assert "seed-a-srv" in names, f"seed dir A must be scanned; got: {list(mcp_configs)}"
    assert "seed-b-srv" in names, f"seed dir B must be scanned; got: {list(mcp_configs)}"


def test_claude_code_ignores_plugin_env_dirs_under_multiuser_scan(tmp_path, monkeypatch):
    """Under a multi-user scan (an explicit other-user home is passed), the
    scanning process's plugin env vars must NOT relocate the target's plugins."""
    import os

    from agent_scan.agents import ClaudeCodeDiscoverer

    rogue = tmp_path / "rogue-plugins"
    (rogue / "marketplaces" / "mp" / "p").mkdir(parents=True)
    (rogue / "marketplaces" / "mp" / "p" / ".mcp.json").write_text('{"should-not-appear": {"command": "x"}}')
    monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(rogue))
    monkeypatch.setenv("CLAUDE_CODE_PLUGIN_SEED_DIR", str(rogue) + os.pathsep)

    alice = tmp_path / "alice"
    (alice / ".claude").mkdir(parents=True)

    mcp_configs = ClaudeCodeDiscoverer(alice)._discover_plugin_mcp_servers()

    names = {n for v in mcp_configs.values() if isinstance(v, list) for n, _ in v}
    assert "should-not-appear" not in names


# --- ClaudeCodeDiscoverer: end-to-end discover() ---


def test_claude_code_discoverer_discover_assembles_client_to_inspect(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {"toy": {"command": "echo", "args": []}}}')
    my_skill = tmp_path / ".claude" / "skills" / "demo"
    my_skill.mkdir(parents=True)
    (my_skill / "SKILL.md").write_text("---\nname: demo\ndescription: Demo skill\n---\n\nBody.\n")

    cti = ClaudeCodeDiscoverer(tmp_path).discover()

    assert cti is not None
    assert isinstance(cti, ClientToInspect)
    assert cti.name == "claude code"
    assert cti.client_path.endswith("/.claude")
    assert len(cti.mcp_configs) == 1
    assert len(cti.skills_dirs) == 1


def test_claude_code_discoverer_discover_returns_none_when_not_installed(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer

    cti = ClaudeCodeDiscoverer(tmp_path).discover()

    assert cti is None


# --- ABC enforcement ---


def test_agent_discoverer_subclass_without_name_raises():
    """A subclass that forgets to set 'name' must fail at class-definition time."""
    from agent_scan.agents import AgentDiscoverer

    with pytest.raises(TypeError, match="must set a non-empty 'name'"):

        class BrokenDiscoverer(AgentDiscoverer):
            def client_exists(self):
                return None

            def discover_mcp_servers(self):
                return {}

            def discover_skills(self):
                return {}


# --- DISCOVERERS registry + find_discoverers ---


def test_DISCOVERERS_registers_claude_code_and_vscode_family():
    """Registry must contain Claude Code plus the VSCode family discoverers.

    The exact set is asserted (rather than just inclusion) so adding a new
    discoverer requires a deliberate test update — silent additions would
    affect every multi-user scan.
    """
    from agent_scan.agents import DISCOVERERS

    assert set(DISCOVERERS) == {"claude code", "vscode", "cursor", "windsurf", "kiro", "antigravity", "codex"}


def test_find_discoverers_returns_claude_code_when_installed(tmp_path):
    from agent_scan.agents import ClaudeCodeDiscoverer, find_discoverers

    (tmp_path / ".claude").mkdir()

    found = find_discoverers(tmp_path)

    assert len(found) == 1
    assert isinstance(found[0], ClaudeCodeDiscoverer)
    assert found[0].home_directory == tmp_path


def test_find_discoverers_returns_empty_when_no_agents_installed(tmp_path):
    from agent_scan.agents import find_discoverers

    found = find_discoverers(tmp_path)

    assert found == []


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
async def test_discover_clients_to_inspect_merges_abc_into_legacy_cti_keeping_both_keys(tmp_path):
    """One CTI per (name, username); legacy and ABC keys for the same server both survive."""
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

    legacy_entries = merged.mcp_configs[legacy_key]
    abc_entries = merged.mcp_configs[abc_key]
    assert isinstance(legacy_entries, list)
    assert isinstance(abc_entries, list)
    # Without by-name dedup, "srv" is preserved in both phases' keys. Each represents
    # a distinct discovery source (legacy flattens projects.* into ~/.claude.json;
    # ABC reports it under the project path) and downstream scanning treats each
    # (key, name) pair on its own merits.
    assert [name for name, _ in legacy_entries] == ["srv"]
    assert [name for name, _ in abc_entries] == ["srv"]
    assert all(isinstance(s, StdioServer) for _, s in abc_entries)


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_preserves_same_named_server_across_projects(tmp_path):
    """Two projects each registering the same server name (different configs) both survive.

    This is the canonical multi-project case (e.g. `github` configured per-repo with
    different tokens). Treating same-name registrations as duplicates would silently
    drop one project's config; we want each project's entry to reach the inspector.
    """
    from agent_scan.models import CandidateClient
    from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        '{"projects": {'
        '"/work/repo-a": {"mcpServers": {"github": {"command": "gh-mcp", "args": ["--token", "orgA"]}}},'
        '"/work/repo-b": {"mcpServers": {"github": {"command": "gh-mcp", "args": ["--token", "orgB"]}}}'
        "}}"
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
    cti = claude_ctis[0]

    repo_a = cti.mcp_configs["/work/repo-a"]
    repo_b = cti.mcp_configs["/work/repo-b"]
    assert isinstance(repo_a, list)
    assert isinstance(repo_b, list)
    assert [name for name, _ in repo_a] == ["github"]
    assert [name for name, _ in repo_b] == ["github"]

    ((_, a_server),) = repo_a
    ((_, b_server),) = repo_b
    assert isinstance(a_server, StdioServer) and isinstance(b_server, StdioServer)
    assert a_server.args == ["--token", "orgA"]
    assert b_server.args == ["--token", "orgB"]


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_keeps_legacy_key_when_abc_adds_nothing(tmp_path):
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
    """Both paths produce a ~/.claude.json key; ABC's value wins via dict-union merge."""
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
    # Legacy stored "proj" under .claude.json (its ClaudeCodeConfigFile flattening
    # of projects.*). ABC stored "top" under .claude.json (top-level mcpServers).
    # Dict-union merge picks ABC's value on the colliding key, so .claude.json now
    # holds only "top"; "proj" lives under ABC's /work/repo key.
    assert [name for name, _ in entries] == ["top"]
    assert merged.mcp_configs["/work/repo"] == [("proj", merged.mcp_configs["/work/repo"][0][1])]


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


def test_plugin_mcp_servers_respects_max_depth_cap(tmp_path):
    """Plugin .mcp.json files deeper than _MAX_PLUGIN_RGLOB_DEPTH are not discovered.

    Depth is counted as ``len(match.relative_to(base).parts)`` where ``base``
    is ``~/.claude/plugins/cache``. A file directly in ``cache/`` is depth 1.
    """
    from agent_scan.agents.base import _MAX_PLUGIN_RGLOB_DEPTH
    from agent_scan.agents.claude_code import ClaudeCodeDiscoverer

    cache = tmp_path / ".claude" / "plugins" / "cache"
    # Depth = _MAX_PLUGIN_RGLOB_DEPTH (allowed): N-1 intermediate dirs + the file.
    allowed_dir = cache.joinpath(*[f"d{i}" for i in range(_MAX_PLUGIN_RGLOB_DEPTH - 1)])
    allowed_dir.mkdir(parents=True)
    (allowed_dir / ".mcp.json").write_text('{"allowed-srv": {"command": "a"}}')
    # Depth = _MAX_PLUGIN_RGLOB_DEPTH + 1 (skipped).
    too_deep_dir = cache.joinpath(*[f"x{i}" for i in range(_MAX_PLUGIN_RGLOB_DEPTH)])
    too_deep_dir.mkdir(parents=True)
    (too_deep_dir / ".mcp.json").write_text('{"too-deep-srv": {"command": "x"}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    server_names = {name for entries in mcp_configs.values() if isinstance(entries, list) for name, _ in entries}
    assert "allowed-srv" in server_names
    assert "too-deep-srv" not in server_names


def test_plugin_skills_respects_max_depth_cap(tmp_path):
    """Plugin skills/ dirs deeper than _MAX_PLUGIN_RGLOB_DEPTH are not discovered."""
    from agent_scan.agents.base import _MAX_PLUGIN_RGLOB_DEPTH
    from agent_scan.agents.claude_code import ClaudeCodeDiscoverer

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


def test_server_config_discriminator_keys_match_model_required_fields():
    """SERVER_CONFIG_DISCRIMINATOR_KEYS must stay in sync with the required
    top-level fields of StdioServer + RemoteServer (including validation aliases).

    The flat-payload gate in ``_looks_like_mcp_payload`` (and ``PluginMCPConfigFile``)
    relies on these keys to tell a single server config apart from a server-name map.
    If a new required field lands on either model (e.g. a new ``protocol`` discriminator)
    and isn't added to the constant, the gate goes blind to that shape and silently
    misreads adversarial inputs.
    """
    from pydantic import AliasChoices

    from agent_scan.models import SERVER_CONFIG_DISCRIMINATOR_KEYS, RemoteServer, StdioServer

    expected: set[str] = set()
    for model in (StdioServer, RemoteServer):
        for field_name, field in model.model_fields.items():
            if not field.is_required():
                continue
            expected.add(field_name)
            alias = field.validation_alias
            if isinstance(alias, str):
                expected.add(alias)
            elif isinstance(alias, AliasChoices):
                expected.update(c for c in alias.choices if isinstance(c, str))

    assert expected == set(SERVER_CONFIG_DISCRIMINATOR_KEYS), (
        f"Required model fields {expected} drifted from "
        f"SERVER_CONFIG_DISCRIMINATOR_KEYS {set(SERVER_CONFIG_DISCRIMINATOR_KEYS)}. "
        "Update the constant in models.py so the flat-vs-wrapped detector "
        "still recognises every required server-config key."
    )


def test_plugin_walk_prunes_traversal_beyond_cap(tmp_path, monkeypatch):
    """Traversal must be pruned at the depth cap, not just filtered post-hoc:
    ``os.walk`` is invoked once per plugin base dir and `dirs` is mutated so the
    walker never descends past the cap. We verify by spying on ``os.walk`` and
    asserting it never yields a root past the prune boundary.
    """
    from pathlib import Path

    import agent_scan.agents.base as ad

    cache = tmp_path / ".claude" / "plugins" / "cache"
    # Build a tree 3x deeper than the cap. If pruning didn't work, os.walk would
    # yield roots at all those levels.
    too_deep_dir = cache.joinpath(*[f"x{i}" for i in range(ad._MAX_PLUGIN_RGLOB_DEPTH * 3)])
    too_deep_dir.mkdir(parents=True)

    seen_depths: list[int] = []
    real_walk = ad.os.walk

    def spy_walk(p, *a, **k):
        for root, dirs, files in real_walk(p, *a, **k):
            try:
                depth = len(Path(root).relative_to(p).parts)
            except ValueError:
                depth = 0
            seen_depths.append(depth)
            yield root, dirs, files

    monkeypatch.setattr(ad.os, "walk", spy_walk)
    list(ad._walk_under_depth(cache, ".mcp.json", ad._MAX_PLUGIN_RGLOB_DEPTH, want_file=True))

    # Walker should never see a root whose depth would yield a path past the cap.
    # Roots at depth (cap - 1) are the last to be visited; deeper roots are pruned.
    assert seen_depths, "walk must run at least once"
    assert max(seen_depths) <= ad._MAX_PLUGIN_RGLOB_DEPTH - 1


# --- JSON5 parsing (comments + empty-file short-circuit) ---


def test_load_json_file_accepts_json5_comments_and_trailing_commas(tmp_path):
    """A ~/.claude.json with // comments and a trailing comma parses successfully."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(
        "{\n"
        "  // top-level comment\n"
        '  "mcpServers": {\n'
        '    "my-server": {"command": "echo", "args": ["hi"]},\n'  # trailing comma below
        "  },\n"
        "}\n"
    )

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert len(mcp_configs) == 1
    entries = next(iter(mcp_configs.values()))
    assert isinstance(entries, list)
    assert [name for name, _ in entries] == ["my-server"]


def test_load_json_file_treats_empty_file_as_empty_config(tmp_path):
    """An empty (or whitespace-only) ~/.claude.json returns no entries, not a parse error."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text("   \n  \n")

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert mcp_configs == {}


# --- _validate_servers writes check_server_signature result back into the dict ---


def test_validate_servers_writes_check_server_signature_result_into_dict(tmp_path):
    """_validate_servers must replace each stdio entry with the value returned by
    check_server_signature — not just rely on in-place mutation of the input."""
    from unittest.mock import patch as mock_patch

    from agent_scan.agents import ClaudeCodeDiscoverer

    replacement = StdioServer(command="replacement", binary_identifier="sig-from-mock")

    with mock_patch(
        "agent_scan.agents.base.check_server_signature",
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
    from agent_scan.agents import (
        DISCOVERERS,
        AgentDiscoverer,
        ClaudeCodeDiscoverer,
        find_discoverers,
    )

    class ExplodingDiscoverer(AgentDiscoverer):
        name = "exploding"

        def client_exists(self):
            raise RuntimeError("boom")

        def discover_mcp_servers(self):
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


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_skips_discoverer_whose_discover_raises(tmp_path):
    """A discoverer whose discover() raises mid-pipeline must not abort the loop —
    other discoverers' results (and the legacy CTI) still land in clients_to_inspect.
    """
    from agent_scan.agents import DISCOVERERS, AgentDiscoverer
    from agent_scan.models import CandidateClient
    from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect

    class ExplodingMidPipelineDiscoverer(AgentDiscoverer):
        name = "exploding-mid"

        def client_exists(self):
            # Returns truthy so it gets into find_discoverers' return list,
            # then blows up inside discover_mcp_servers.
            return "/fake/path"

        def discover_mcp_servers(self):
            raise RuntimeError("boom from discover_mcp_servers")

        def discover_skills(self):
            return {}

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {}}')

    candidate = CandidateClient(
        name="claude code",
        client_exists_paths=["~/.claude"],
        mcp_config_paths=["~/.claude.json"],
        skills_dir_paths=["~/.claude/skills"],
    )

    DISCOVERERS["exploding-mid"] = ExplodingMidPipelineDiscoverer
    try:
        with (
            patch(
                "agent_scan.pipelines.get_readable_home_directories",
                return_value=[(tmp_path, "alice")],
            ),
            patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
        ):
            args = InspectArgs(timeout=10, tokens=[], paths=[])
            ctis, _, _ = await discover_clients_to_inspect(args)
    finally:
        del DISCOVERERS["exploding-mid"]

    # The exploding discoverer's CTI is dropped, but Claude Code's still lands.
    names = {c.name for c in ctis}
    assert "claude code" in names
    assert "exploding-mid" not in names


# --- _load_json_file permission handling ---


def test_load_json_file_returns_none_on_permission_error(tmp_path, monkeypatch):
    """A ``PermissionError`` during read must return ``None`` (missing-file
    semantics), not a ``CouldNotParseMCPConfig`` entry.

    Under ``--scan-all-users`` an unprivileged process routinely hits homes it
    can't read; surfacing those as parse errors would misclassify access-control
    denials as malformed configs.
    """
    from pathlib import Path

    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"mcpServers": {"srv": {"command": "echo"}}}')

    real_read_text = Path.read_text

    def fake_read_text(self, *args, **kwargs):
        if self.name == ".claude.json":
            raise PermissionError(13, "Permission denied", str(self))
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fake_read_text)

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    # The unreadable file is silently skipped — no parse-error sentinel surfaces.
    assert mcp_configs == {}


def test_load_json_file_still_returns_could_not_parse_for_malformed_json(tmp_path):
    """Regression guard: real parse failures still produce ``CouldNotParseMCPConfig``.
    Splitting out the ``PermissionError`` branch must not weaken malformed-JSON handling.
    """
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text("{not valid json")

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert len(mcp_configs) == 1
    entry = next(iter(mcp_configs.values()))
    assert isinstance(entry, CouldNotParseMCPConfig)


# --- Multi-user pipeline (--scan-all-users) end-to-end ---


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_keeps_per_user_isolation_under_scan_all_users(tmp_path):
    """End-to-end multi-home test for the ``(name, username)`` merge predicate.

    Phase B looks up the existing CTI via
    ``c.name == cti.name and c.username == cti.username`` (pipelines.py:131).
    If the ``username`` half of that predicate ever regresses (e.g. someone
    simplifies to ``c.name == cti.name``), bob's ABC discoverer would merge
    into the *first* "claude code" CTI in insertion order — which is alice's —
    contaminating alice's CTI with bob's servers and leaving bob's CTI without
    its ABC-discovered project key.

    The test gives each user a *distinct* server name and a *distinct* project
    path so cross-contamination is trivially detectable.
    """
    from agent_scan.models import CandidateClient
    from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect

    alice_home = tmp_path / "alice"
    bob_home = tmp_path / "bob"
    (alice_home / ".claude").mkdir(parents=True)
    (bob_home / ".claude").mkdir(parents=True)
    (alice_home / ".claude.json").write_text(
        '{"projects": {"/alice/repo": {"mcpServers": {"alice-srv": {"command": "echo"}}}}}'
    )
    (bob_home / ".claude.json").write_text(
        '{"projects": {"/bob/repo": {"mcpServers": {"bob-srv": {"command": "echo"}}}}}'
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
            return_value=[(alice_home, "alice"), (bob_home, "bob")],
        ),
        patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=[], all_users=True)
        ctis, _, _ = await discover_clients_to_inspect(args)

    claude_ctis = [c for c in ctis if c.name == "claude code"]
    by_user = {c.username: c for c in claude_ctis}
    assert set(by_user) == {"alice", "bob"}, f"Expected one CTI per user, got {sorted(by_user)}"

    def server_names(cti):
        names = set()
        for entries in cti.mcp_configs.values():
            if isinstance(entries, list):
                for name, _ in entries:
                    names.add(name)
        return names

    alice_servers = server_names(by_user["alice"])
    bob_servers = server_names(by_user["bob"])

    # No cross-contamination: each user's CTI contains ONLY its own distinct server.
    assert alice_servers == {"alice-srv"}, (
        f"alice's CTI must contain only alice-srv (cross-contamination from bob "
        f"indicates the username predicate regressed); got {alice_servers}"
    )
    assert bob_servers == {"bob-srv"}, (
        f"bob's CTI must contain only bob-srv (cross-contamination from alice "
        f"indicates the username predicate regressed); got {bob_servers}"
    )

    # Each user's CTI carries its own ABC-discovered project key. If the
    # username predicate were dropped, bob's ABC would never reach bob's CTI
    # and /bob/repo would be missing from bob_keys.
    assert "/alice/repo" in by_user["alice"].mcp_configs
    assert "/bob/repo" in by_user["bob"].mcp_configs
    assert "/bob/repo" not in by_user["alice"].mcp_configs
    assert "/alice/repo" not in by_user["bob"].mcp_configs


@pytest.mark.asyncio
async def test_discover_clients_to_inspect_propagates_all_users_flag_to_home_enumeration(tmp_path):
    """The ``InspectArgs.all_users`` flag must reach
    ``get_readable_home_directories`` unmodified.

    Regression guard: if the pipeline ever drops the kwarg or hardcodes a
    value, ``--scan-all-users`` would silently degrade to scanning only the
    current user — every per-user assertion in the rest of the suite would
    still pass (they all mock the home list directly), but real CLI runs
    would skip every other user on the box.
    """
    from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect

    captured: dict = {}

    def fake_home_enum(*, all_users):
        captured.setdefault("calls", []).append(all_users)
        return [(tmp_path, "alice")]

    # all_users=True must reach the enumeration as True.
    with (
        patch("agent_scan.pipelines.get_readable_home_directories", side_effect=fake_home_enum),
        patch("agent_scan.pipelines.get_well_known_clients", return_value=[]),
    ):
        await discover_clients_to_inspect(InspectArgs(timeout=10, tokens=[], paths=[], all_users=True))

    # all_users=False (single-user default) must reach as False.
    with (
        patch("agent_scan.pipelines.get_readable_home_directories", side_effect=fake_home_enum),
        patch("agent_scan.pipelines.get_well_known_clients", return_value=[]),
    ):
        await discover_clients_to_inspect(InspectArgs(timeout=10, tokens=[], paths=[], all_users=False))

    assert captured["calls"] == [True, False], (
        f"Pipeline must pass all_users through unchanged to get_readable_home_directories; "
        f"got call sequence {captured['calls']}"
    )


# =============================================================================
# VSCode family discoverers (VSCode, Cursor, Windsurf, Kiro, Antigravity).
# =============================================================================
#
# The base class ``VSCodeFamilyDiscoverer`` encodes a shared layout: an install
# directory, user-scope MCP file(s), an optional ``settings.json`` with nested
# ``mcp.servers``, an optional workspaceStorage tree that points at opened
# workspace folders, and an optional skills directory.  Each concrete subclass
# only overrides path constants.  The tests below exercise the base behavior
# through the subclasses (no need for a synthetic "fake" subclass) because the
# real subclasses are tiny and the assertions are sharper that way.
#
# Tests use ``tmp_path`` as the discoverer's ``home_directory`` and lay out
# fixtures relative to it.  Where the layout is platform-specific
# (``~/Library/Application Support/...`` on macOS, ``~/.config/...`` on Linux,
# ``~/AppData/Roaming/...`` on Windows) we ask the discoverer itself for its
# resolved ``_user_data_dir`` so the test stays platform-agnostic.


def _userdata(discoverer):
    """Resolve the discoverer's per-platform ``<userdata>`` directory.

    Wrapping the call here keeps the platform branch out of every test body —
    if a discoverer has no userdata dir (e.g. Kiro/Antigravity, which only
    use dotfile paths) this returns ``None``.
    """
    return discoverer._user_data_dir()


# --- shared base-class behavior: install detection ---


def test_vscode_discoverer_detects_dotfile_install(tmp_path):
    from agent_scan.agents import VSCodeDiscoverer

    (tmp_path / ".vscode").mkdir()

    result = VSCodeDiscoverer(tmp_path).client_exists()

    assert result is not None
    assert result.endswith("/.vscode")


def test_vscode_discoverer_detects_userdata_install(tmp_path):
    """Even without ``~/.vscode``, the userdata dir alone is enough to say VSCode is installed."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    user_data = _userdata(discoverer)
    user_data.mkdir(parents=True)

    result = discoverer.client_exists()

    assert result is not None


def test_vscode_discoverer_returns_none_when_absent(tmp_path):
    from agent_scan.agents import VSCodeDiscoverer

    assert VSCodeDiscoverer(tmp_path).client_exists() is None


def test_cursor_discoverer_detects_installation(tmp_path):
    from agent_scan.agents import CursorDiscoverer

    (tmp_path / ".cursor").mkdir()

    assert CursorDiscoverer(tmp_path).client_exists() is not None


def test_windsurf_discoverer_detects_codeium_root(tmp_path):
    """Both the Codeium root ``~/.codeium`` and the IDE subdir ``~/.codeium/windsurf``
    count as installed (parity with legacy detection); the deeper, more specific
    path is reported as the client path when it exists."""
    from agent_scan.agents import WindsurfDiscoverer

    # Bare ``~/.codeium`` (Codeium root) is enough to detect.
    (tmp_path / ".codeium").mkdir()
    result = WindsurfDiscoverer(tmp_path).client_exists()
    assert result is not None
    assert result.endswith("/.codeium")

    # With the IDE subdir present, the deeper path is reported (listed first).
    (tmp_path / ".codeium" / "windsurf").mkdir()
    assert WindsurfDiscoverer(tmp_path).client_exists().endswith("/.codeium/windsurf")


def test_kiro_discoverer_detects_installation(tmp_path):
    from agent_scan.agents import KiroDiscoverer

    (tmp_path / ".kiro").mkdir()

    assert KiroDiscoverer(tmp_path).client_exists() is not None


def test_antigravity_discoverer_requires_antigravity_subdir(tmp_path):
    """``~/.gemini`` alone is the Gemini CLI — only ``~/.gemini/antigravity`` proves the Antigravity IDE is installed."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini").mkdir()
    assert AntigravityDiscoverer(tmp_path).client_exists() is None

    (tmp_path / ".gemini" / "antigravity").mkdir()
    assert AntigravityDiscoverer(tmp_path).client_exists() is not None


# --- user-scope MCP file parsing ---


def test_vscode_discoverer_parses_user_dotvscode_mcp_json(tmp_path):
    """``~/.vscode/mcp.json`` uses VSCode's flat ``{"servers": {...}}`` shape."""
    from agent_scan.agents import VSCodeDiscoverer

    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text('{"servers": {"my-srv": {"command": "echo", "args": ["a"]}}}')

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/.vscode/mcp.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "my-srv"
    assert isinstance(server, StdioServer)


def test_vscode_discoverer_parses_copilot_cli_user_mcp_config(tmp_path):
    """GitHub Copilot CLI stores its user-level MCP servers at
    ``~/.copilot/mcp-config.json`` in the wrapped ``{"mcpServers": {...}}`` shape
    (docs.github.com/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers).

    The VSCode discoverer already reads Copilot's ``~/.copilot/skills``; the
    matching MCP config under the same ``~/.copilot`` home must surface too.
    """
    from agent_scan.agents import VSCodeDiscoverer

    copilot_dir = tmp_path / ".copilot"
    copilot_dir.mkdir()
    (copilot_dir / "mcp-config.json").write_text('{"mcpServers": {"my-srv": {"command": "echo", "args": ["a"]}}}')
    # A ``~/.vscode`` dir marks the client as present (no mcp.json inside, so it
    # contributes no competing entry).
    (tmp_path / ".vscode").mkdir()

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/.copilot/mcp-config.json")]
    assert len(file_keys) == 1, f"~/.copilot/mcp-config.json must be discovered; got {list(mcp_configs)}"
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "my-srv"
    assert isinstance(server, StdioServer)


def test_vscode_discoverer_parses_settings_json_nested_mcp(tmp_path):
    """``<userdata>/User/settings.json`` carries MCP servers under a nested ``mcp.servers`` key."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    user_dir = _userdata(discoverer) / "User"
    user_dir.mkdir(parents=True)
    (user_dir / "settings.json").write_text(
        '{"editor.fontSize": 14, "mcp": {"servers": {"nested-srv": {"command": "n"}}}}'
    )

    mcp_configs = discoverer.discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/User/settings.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list)
    name, _server = entries[0]
    assert name == "nested-srv"


def test_vscode_discoverer_parses_settings_json_dotted_mcp_servers(tmp_path):
    """``settings.json`` may flatten the server map under the dotted ``"mcp.servers"``
    key instead of the nested ``{"mcp": {"servers": ...}}`` object.

    VSCode persists settings in either form (the UI writes the nested object, but a
    hand-edited / programmatically-written file may use the dotted key). The
    ``.code-workspace`` scan already accepts both shapes via
    ``_settings_mcp_server_map``; the user/profile ``settings.json`` path must too,
    or a dotted-key user would silently slip past discovery.
    """
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    user_dir = _userdata(discoverer) / "User"
    user_dir.mkdir(parents=True)
    (user_dir / "settings.json").write_text('{"editor.fontSize": 14, "mcp.servers": {"dotted-srv": {"command": "d"}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/User/settings.json")]
    assert len(file_keys) == 1, (
        f"settings.json with a dotted mcp.servers key must surface its servers; got keys: {list(mcp_configs)}"
    )
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "dotted-srv"
    assert isinstance(server, StdioServer)


def test_vscode_discoverer_skips_settings_json_without_mcp_section(tmp_path):
    """An editor-only ``settings.json`` (no ``mcp`` or ``mcpServers`` key) must produce
    no entries — neither a ``CouldNotParseMCPConfig`` parse failure nor garbage server
    entries materialized out of editor preferences.

    ``settings.json`` is multi-purpose; it carries MCP under a nested ``mcp`` key
    *if* the user configures one, but most users never will. We must not flag a
    typical editor-config file as a malformed MCP config, and we must not let a
    permissive flat format coerce keys like ``editor.fontSize`` into server entries.
    """
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    user_dir = _userdata(discoverer) / "User"
    user_dir.mkdir(parents=True)
    # Realistic editor-only settings.json — no `mcp` / `mcpServers` anywhere.
    (user_dir / "settings.json").write_text(
        '{"editor.fontSize": 14, "telemetry.level": "off", '
        '"workbench.colorTheme": "Default Dark+", '
        '"editor.formatOnSave": true}'
    )

    mcp_configs = discoverer.discover_mcp_servers()

    settings_keys = [k for k in mcp_configs if k.endswith("/User/settings.json")]
    assert settings_keys == [], (
        f"settings.json with no mcp section must not appear in mcp_configs at all, "
        f"got entries: {[(k, mcp_configs[k]) for k in settings_keys]}"
    )


def test_vscode_discoverer_skips_settings_json_mcp_without_servers(tmp_path):
    """A ``settings.json`` whose top-level ``mcp`` object carries no ``servers``
    (e.g. only ``inputs`` or ``mcp.discovery.enabled``) must produce no entry —
    not a ``CouldNotParseMCPConfig`` parse failure.

    The presence-gate keys off actual servers, not the bare ``mcp`` key: an
    ``mcp`` block without ``servers`` holds nothing to surface, so handing it to
    the format tuple (which would fail every model and report a malformed config)
    is a false positive we must avoid.
    """
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    user_dir = _userdata(discoverer) / "User"
    user_dir.mkdir(parents=True)
    # ``mcp`` present but server-less (inputs only) + the nested discovery toggle.
    (user_dir / "settings.json").write_text(
        '{"editor.fontSize": 14, "mcp": {"inputs": [{"id": "token", "type": "promptString"}]}, '
        '"chat": {"mcp": {"discovery": {"enabled": true}}}}'
    )

    mcp_configs = discoverer.discover_mcp_servers()

    settings_keys = [k for k in mcp_configs if k.endswith("/User/settings.json")]
    assert settings_keys == [], (
        f"settings.json with an mcp block but no servers must not appear in mcp_configs, "
        f"got entries: {[(k, mcp_configs[k]) for k in settings_keys]}"
    )


def test_vscode_discoverer_skips_settings_json_empty_mcp_servers(tmp_path):
    """A ``settings.json`` whose ``mcp.servers`` is present but *empty* carries no
    servers, so it must produce no entry — not a zero-server list keyed by the
    settings file.

    ``_settings_mcp_server_map`` already extracts a dict-shaped ``mcp.servers``;
    an empty one is falsy and falls through. It must short-circuit to ``None``
    rather than validating to ``[]`` via the format tuple (``VSCodeConfigFile``
    happily validates an empty ``servers`` map), which would surface a bogus
    zero-server entry for an ordinary editor settings file.
    """
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    user_dir = _userdata(discoverer) / "User"
    user_dir.mkdir(parents=True)
    (user_dir / "settings.json").write_text('{"editor.fontSize": 14, "mcp": {"servers": {}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    settings_keys = [k for k in mcp_configs if k.endswith("/User/settings.json")]
    assert settings_keys == [], (
        f"settings.json with an empty mcp.servers map must not appear in mcp_configs, "
        f"got entries: {[(k, mcp_configs[k]) for k in settings_keys]}"
    )


def test_vscode_discoverer_flags_malformed_mcp_servers(tmp_path):
    """A *non-dict* ``mcp.servers`` (e.g. a JSON list) is malformed MCP and must
    still be surfaced as ``CouldNotParseMCPConfig`` — the empty-servers
    short-circuit must not also swallow genuinely malformed shapes.
    """
    from agent_scan.agents import VSCodeDiscoverer
    from agent_scan.models import CouldNotParseMCPConfig

    discoverer = VSCodeDiscoverer(tmp_path)
    user_dir = _userdata(discoverer) / "User"
    user_dir.mkdir(parents=True)
    (user_dir / "settings.json").write_text('{"mcp": {"servers": [1, 2, 3]}}')

    mcp_configs = discoverer.discover_mcp_servers()

    settings_keys = [k for k in mcp_configs if k.endswith("/User/settings.json")]
    assert len(settings_keys) == 1
    assert isinstance(mcp_configs[settings_keys[0]], CouldNotParseMCPConfig)


def test_cursor_discoverer_parses_wrapped_mcp_servers(tmp_path):
    """``~/.cursor/mcp.json`` uses the wrapped ``{"mcpServers": {...}}`` shape."""
    from agent_scan.agents import CursorDiscoverer

    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text('{"mcpServers": {"cur-srv": {"command": "c"}}}')

    mcp_configs = CursorDiscoverer(tmp_path).discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/.cursor/mcp.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list)
    name, _ = entries[0]
    assert name == "cur-srv"


def test_windsurf_discoverer_parses_mcp_config_json(tmp_path):
    from agent_scan.agents import WindsurfDiscoverer

    cfg_dir = tmp_path / ".codeium" / "windsurf"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "mcp_config.json").write_text('{"mcpServers": {"ws-srv": {"command": "w"}}}')

    mcp_configs = WindsurfDiscoverer(tmp_path).discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/windsurf/mcp_config.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    name, _ = entries[0]
    assert name == "ws-srv"


def test_kiro_discoverer_parses_settings_mcp_json(tmp_path):
    from agent_scan.agents import KiroDiscoverer

    cfg_dir = tmp_path / ".kiro" / "settings"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "mcp.json").write_text('{"mcpServers": {"kr-srv": {"command": "k"}}}')

    mcp_configs = KiroDiscoverer(tmp_path).discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/.kiro/settings/mcp.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    name, _ = entries[0]
    assert name == "kr-srv"


def test_antigravity_discoverer_parses_mcp_config_json(tmp_path):
    from agent_scan.agents import AntigravityDiscoverer

    cfg_dir = tmp_path / ".gemini" / "antigravity"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "mcp_config.json").write_text('{"mcpServers": {"ag-srv": {"command": "a"}}}')

    mcp_configs = AntigravityDiscoverer(tmp_path).discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/antigravity/mcp_config.json")]
    assert len(file_keys) == 1
    entries = mcp_configs[file_keys[0]]
    name, _ = entries[0]
    assert name == "ag-srv"


def test_antigravity_discoverer_parses_settings_json_nested_mcp(tmp_path):
    """Antigravity is a VSCode fork; like VSCode/Cursor it carries a per-user
    ``User/settings.json`` that can hold MCP under a nested ``mcp.servers`` key.

    Without ``_user_settings_file`` set on ``AntigravityDiscoverer`` this file is
    never scanned, so users who configure MCP through the editor settings UI
    (rather than ``~/.gemini/antigravity/mcp_config.json``) would slip past discovery.
    """
    from agent_scan.agents import AntigravityDiscoverer

    discoverer = AntigravityDiscoverer(tmp_path)
    # Antigravity has two userdata names (``Antigravity`` for v1.x,
    # ``Antigravity IDE`` for v2.0). Use the first one; the discoverer must
    # scan every entry in ``_user_data_dirs()``.
    userdata_dirs = discoverer._user_data_dirs()
    assert userdata_dirs, "Antigravity must declare at least one userdata dir name"
    user_dir = userdata_dirs[0] / "User"
    user_dir.mkdir(parents=True)
    (user_dir / "settings.json").write_text(
        '{"editor.fontSize": 14, "mcp": {"servers": {"ag-nested": {"command": "x"}}}}'
    )

    mcp_configs = discoverer.discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/User/settings.json")]
    assert len(file_keys) == 1, (
        f"AntigravityDiscoverer must scan User/settings.json for nested mcp.servers; "
        f"got mcp_configs keys: {list(mcp_configs)}"
    )
    entries = mcp_configs[file_keys[0]]
    assert isinstance(entries, list)
    name, _ = entries[0]
    assert name == "ag-nested"


def test_antigravity_discoverer_parses_gemini_settings_http_url_server(tmp_path):
    """``~/.gemini/settings.json`` is shared with the Gemini CLI, whose remote
    (Streamable-HTTP) servers are declared with an ``httpUrl`` key. Such a server
    must be discovered as a RemoteServer — not surface the whole file as a parse
    failure (the original bug: ``httpUrl`` matched no server shape, so the entire
    ``mcpServers`` block failed validation and was reported malformed)."""
    from agent_scan.agents import AntigravityDiscoverer

    # Install marker so the discoverer treats Antigravity as present.
    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    (tmp_path / ".gemini" / "settings.json").write_text(
        '{"mcpServers": {"gemini-remote": {"httpUrl": "https://mcp.gemini.example/mcp"}}}'
    )

    mcp_configs = AntigravityDiscoverer(tmp_path).discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/.gemini/settings.json")]
    assert len(file_keys) == 1, f"~/.gemini/settings.json must be scanned; got keys: {list(mcp_configs)}"
    entry = mcp_configs[file_keys[0]]
    assert not isinstance(entry, CouldNotParseMCPConfig), "httpUrl server must not fail the whole file"
    assert isinstance(entry, list)
    name, server = entry[0]
    assert name == "gemini-remote"
    assert getattr(server, "url", None) == "https://mcp.gemini.example/mcp"


def test_looks_like_mcp_payload_recognizes_flat_http_url_map():
    """The opportunistic-walk gate must recognise a flat ``{name: {httpUrl: ...}}``
    map as MCP so extension/profile walks don't skip Gemini-style remote servers."""
    from agent_scan.agents.base import _looks_like_mcp_payload

    assert _looks_like_mcp_payload({"srv": {"httpUrl": "https://example.com/mcp"}})


def test_antigravity_discoverer_workspace_mcp_paths():
    """Antigravity's workspace-scoped MCP paths.

    None of these is documented by Google: Antigravity's official docs site is a
    client-rendered SPA that discloses no workspace ``mcp.json`` path, and its
    canonical sitemap lists none. They are wired up at user request as
    best-effort, speculative catches — each tagged ``inferred — verify`` at its
    definition in ``AntigravityDiscoverer``:

    * ``.mcp.json`` — the cross-tool project-root convention (Claude Code /
      Cline), mirroring the speculative entry already on ``KiroDiscoverer``.
    * ``.agents/mcp_config.json`` — community-floated Antigravity workspace
      candidate; matches Antigravity's ``mcp_config.json`` file naming and its
      ``.agents/`` workspace-dir convention (the same dir its workspace skills
      live under).
    * ``.gemini/mcp_config.json`` — a workspace mirror of the user-global
      ``~/.gemini/config/mcp_config.json`` the Antigravity stack consults.

    A wrong guess is a tolerated no-op (the file simply won't exist), but a path
    that collides with an unrelated user file could feed parse failures into a
    scan — so keep the set minimal and justified. If Google later publishes an
    official path, reconcile it here and in the discoverer comment.
    """
    from agent_scan.agents import AntigravityDiscoverer

    assert AntigravityDiscoverer._workspace_mcp_relative == (
        ".mcp.json",
        ".agents/mcp_config.json",
        ".gemini/mcp_config.json",
    )


# --- malformed MCP file surfaces as CouldNotParseMCPConfig ---


def test_vscode_discoverer_records_could_not_parse_on_invalid_mcp_json(tmp_path):
    from agent_scan.agents import VSCodeDiscoverer

    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text("{ not valid json")

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    file_keys = [k for k in mcp_configs if k.endswith("/mcp.json")]
    assert len(file_keys) == 1
    entry = mcp_configs[file_keys[0]]
    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure is True


def test_vscode_discoverer_returns_empty_when_no_mcp_sources(tmp_path):
    """Install dir present but no MCP config files anywhere — empty dict, no errors."""
    from agent_scan.agents import VSCodeDiscoverer

    (tmp_path / ".vscode").mkdir()

    assert VSCodeDiscoverer(tmp_path).discover_mcp_servers() == {}


# --- workspaceStorage walk: per-workspace MCP discovery ---


def test_vscode_discoverer_walks_workspace_storage_to_find_mcp(tmp_path):
    """A workspaceStorage entry pointing at a workspace with ``.vscode/mcp.json`` surfaces that file."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    workspace_hash = workspace_storage / "abc123"
    workspace_hash.mkdir(parents=True)

    # A workspace folder elsewhere on disk with a per-workspace MCP file.
    workspace = tmp_path / "code" / "my-repo"
    workspace.mkdir(parents=True)
    (workspace / ".vscode").mkdir()
    (workspace / ".vscode" / "mcp.json").write_text('{"servers": {"ws-mcp": {"command": "w"}}}')

    # VSCode's workspace.json records the folder URL. Use ``Path.as_uri`` so the
    # constructed URI is correct on both POSIX (``file:///tmp/...``) and Windows
    # (``file:///C:/Users/...``) — manually concatenating ``file://`` + ``as_posix``
    # produces a malformed two-slash URI on Windows.
    (workspace_hash / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    workspace_keys = [k for k in mcp_configs if k.endswith("/code/my-repo/.vscode/mcp.json")]
    assert len(workspace_keys) == 1
    entries = mcp_configs[workspace_keys[0]]
    assert isinstance(entries, list)
    name, _ = entries[0]
    assert name == "ws-mcp"


def test_vscode_discoverer_discovers_workspace_root_mcp_json(tmp_path):
    """VS Code reads a project-root ``.mcp.json`` in an opened workspace.

    Verified empirically; undocumented — the VS Code MCP docs list only the
    workspace ``.vscode/mcp.json`` and the user-profile ``mcp.json``.
    """
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    workspace_hash = workspace_storage / "ws"
    workspace_hash.mkdir(parents=True)

    workspace = tmp_path / "proj"
    workspace.mkdir()
    (workspace / ".mcp.json").write_text('{"servers": {"ws-root-srv": {"command": "w"}}}')

    (workspace_hash / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    workspace_keys = [k for k in mcp_configs if k.endswith("/proj/.mcp.json")]
    assert len(workspace_keys) == 1
    entries = mcp_configs[workspace_keys[0]]
    assert isinstance(entries, list) and len(entries) == 1
    name, _ = entries[0]
    assert name == "ws-root-srv"


def test_vscode_discoverer_workspace_storage_skips_malformed_workspace_json(tmp_path):
    """A malformed ``workspace.json`` is logged + skipped — does NOT surface as a CouldNotParseMCPConfig."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    bad = workspace_storage / "bad-hash"
    bad.mkdir(parents=True)
    (bad / "workspace.json").write_text("{ broken")

    # Also a working entry alongside the bad one, so we know the walk continues.
    good = workspace_storage / "good-hash"
    good.mkdir()
    workspace = tmp_path / "good-repo"
    workspace.mkdir()
    (workspace / ".vscode").mkdir()
    (workspace / ".vscode" / "mcp.json").write_text('{"servers": {"good": {"command": "g"}}}')
    (good / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    # No entry should reference the broken workspace.json itself.
    assert not any("bad-hash" in k for k in mcp_configs)
    # The good entry must still be found.
    assert any(k.endswith("/good-repo/.vscode/mcp.json") for k in mcp_configs)


def test_vscode_discoverer_workspace_storage_unreadable_does_not_abort_discovery(tmp_path, monkeypatch):
    """An unreadable ``<userdata>/User/workspaceStorage`` must degrade gracefully,
    not abort the whole discoverer.

    On Python 3.12+, ``Path.exists()`` re-raises ``PermissionError`` when an
    ancestor directory isn't traversable (rather than returning ``False``) — the
    routine ``--scan-all-users`` case where an unprivileged scan hits another
    user's home. An unguarded ``workspace_storage.exists()`` would propagate out
    of ``discover_mcp_servers()``; the pipeline catches that and skips the entire
    discoverer (``pipelines.py``), dropping every source for that IDE/user —
    including reachable user-scope MCP. The walk must skip the unreadable tree the
    same way ``_load_json_file`` and ``profiles_dir.iterdir`` already do.
    """
    from pathlib import Path

    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)

    # A reachable, home-relative user-scope MCP file (``~/.vscode/mcp.json``) that
    # lives outside the userdata subtree — it must survive an unreadable
    # workspaceStorage.
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text('{"servers": {"user-srv": {"command": "u"}}}')

    real_exists = Path.exists

    def fake_exists(self, *args, **kwargs):
        # Only the workspaceStorage probe is denied (parent not traversable);
        # every other existence check behaves normally.
        if self.name == "workspaceStorage":
            raise PermissionError(13, "Permission denied", str(self))
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)

    # Pre-fix this raises PermissionError and the discoverer is dropped wholesale.
    mcp_configs = discoverer.discover_mcp_servers()

    # The reachable user-scope MCP is still surfaced; no workspaceStorage entry.
    user_keys = [k for k in mcp_configs if k.endswith("/.vscode/mcp.json")]
    assert len(user_keys) == 1, f"user-scope ~/.vscode/mcp.json must survive; got {list(mcp_configs)}"
    name, _server = mcp_configs[user_keys[0]][0]
    assert name == "user-srv"
    assert not any("workspaceStorage" in k for k in mcp_configs)


def test_vscode_discoverer_workspace_storage_url_decodes_folder_path(tmp_path):
    """VSCode stores ``folder`` percent-encoded (e.g. ``My%20Projects``); the discoverer must
    decode before resolving, otherwise workspaces with spaces or special chars are silently missed."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    workspace_hash = workspace_storage / "h"
    workspace_hash.mkdir(parents=True)

    # Workspace with a literal space in the name; the file:// URL encodes it as %20.
    workspace = tmp_path / "My Projects" / "repo"
    workspace.mkdir(parents=True)
    (workspace / ".vscode").mkdir()
    (workspace / ".vscode" / "mcp.json").write_text('{"servers": {"s": {"command": "x"}}}')

    # ``Path.as_uri`` produces ``file:///.../My%20Projects/...`` — VSCode's exact
    # on-disk shape (percent-encoded). The discoverer must decode before
    # resolving the path.
    uri = workspace.as_uri()
    assert "%20" in uri  # sanity: the space really is encoded
    (workspace_hash / "workspace.json").write_text(f'{{"folder": "{uri}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    assert any(k.endswith("/My Projects/repo/.vscode/mcp.json") for k in mcp_configs)


def test_vscode_discoverer_workspace_storage_skips_when_folder_key_missing(tmp_path):
    """A ``workspace.json`` without a ``folder`` key (e.g. multi-root) is skipped."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    multi = workspace_storage / "multi-root"
    multi.mkdir(parents=True)
    # Multi-root workspaces use ``configuration`` instead of ``folder``.
    (multi / "workspace.json").write_text('{"configuration": "file:///some/multi-root.code-workspace"}')

    mcp_configs = discoverer.discover_mcp_servers()

    assert mcp_configs == {}


def test_vscode_discoverer_workspace_root_handles_windows_file_uri(monkeypatch):
    """Windows VSCode emits ``file:///C:/Users/me/repo`` — the leading ``/`` before the
    drive letter is a URL artifact, not a real path component. Naïve ``file://`` stripping
    leaves ``/C:/Users/me/repo``, which ``Path`` does not interpret as ``C:\\Users\\me\\repo``
    on Windows. ``_file_uri_to_path`` must delegate to ``urllib.request.url2pathname``
    so the URL is converted correctly per-platform.

    We don't import ``nturl2path`` (deprecated in Python 3.14+ and slated for removal).
    Instead we patch the module-level ``url2pathname`` binding with a tiny stand-in
    that mirrors Windows' conversion for our fixture (strip the URL artifact slash
    before the drive letter, swap ``/`` for ``\\``), and assert the production code
    returns that. This locks the "delegate to ``url2pathname``, don't strip ``file://``
    by hand" contract on every platform without depending on a deprecated module.
    """
    from pathlib import Path

    from agent_scan.agents.vscode import base as vscode_base
    from agent_scan.agents.vscode.base import _file_uri_to_path

    def fake_windows_url2pathname(url: str) -> str:
        return url.lstrip("/").replace("/", "\\")

    # ``url2pathname`` is resolved inside ``_file_uri_to_path`` (agents.vscode.base),
    # so patch it there.
    monkeypatch.setattr(vscode_base, "url2pathname", fake_windows_url2pathname, raising=False)

    root = _file_uri_to_path("file:///C:/Users/me/repo")

    assert root is not None
    # The production code must hand the URL path to the patched ``url2pathname``;
    # our stand-in returns Windows-form ``C:\Users\me\repo``.
    assert root == Path(fake_windows_url2pathname("/C:/Users/me/repo"))
    # And specifically NOT the buggy ``/C:/Users/me/repo`` shape that naïve
    # ``file://`` stripping would produce.
    assert "/C:" not in root.as_posix()


def test_vscode_discoverer_workspace_root_returns_none_for_non_file_uri():
    """Remote-workspace URIs (``vscode-remote://``, ``vscode-vfs://``, etc.) point
    at filesystems we can't scan from this process. ``_file_uri_to_path`` must
    return ``None`` for any non-``file://`` scheme rather than coercing the whole
    URL into a ``Path`` — that would surface a non-existent path downstream and
    risk silent garbage entries if any future caller stopped checking existence.
    """
    from agent_scan.agents.vscode.base import _file_uri_to_path

    for remote in (
        "vscode-remote://ssh-remote+host/home/me/repo",
        "vscode-vfs://github/owner/repo",
        "vscode-remote://wsl+Ubuntu/home/me/repo",
    ):
        assert _file_uri_to_path(remote) is None, remote


def test_file_uri_to_path_preserves_unc_host(tmp_path):
    """A UNC ``file://server/share/repo`` URI must keep its host. ``urlparse`` splits
    the host into ``netloc`` and leaves only ``/share/repo`` in ``path``; converting
    just ``path`` would silently rewrite the share to a bogus local ``/share/repo``.
    The host is re-attached as a UNC root instead (``\\\\server\\share`` on Windows,
    ``//server/share`` on POSIX — a non-mounted share just fails the downstream
    existence check and is skipped).
    """
    from agent_scan.agents.vscode.base import _file_uri_to_path

    root = _file_uri_to_path("file://server/share/repo")

    assert root is not None
    # Host preserved, not collapsed to a bogus local path.
    assert "server" in root.as_posix(), root.as_posix()
    assert root.as_posix() == "//server/share/repo"


def test_file_uri_to_path_treats_localhost_host_as_local(tmp_path):
    """An explicit ``localhost`` host (and the empty host) denote a plain local path
    per RFC 8089 — it must not be turned into a ``//localhost/...`` UNC path."""
    from pathlib import Path

    from agent_scan.agents.vscode.base import _file_uri_to_path

    assert _file_uri_to_path("file://localhost/home/me/repo") == Path("/home/me/repo")
    assert _file_uri_to_path("file:///home/me/repo") == Path("/home/me/repo")


def test_file_uri_to_path_returns_none_for_pathless_uri():
    """A degenerate ``file://`` / ``file://localhost`` carrying no path must not
    resolve to ``Path('')`` == ``Path('.')`` — the scanner's CWD, whose ancestors
    would then be walked for ``.vscode/mcp.json`` / ``.cursor/skills`` etc. Such a
    URI is unresolvable and must return ``None``.
    """
    from pathlib import Path

    from agent_scan.agents.vscode.base import _file_uri_to_path

    assert _file_uri_to_path("file://") is None
    assert _file_uri_to_path("file://localhost") is None
    # A genuine root path is still resolved — the guard only rejects an *empty* path.
    assert _file_uri_to_path("file:///") == Path("/")


def test_vscode_discoverer_workspace_storage_skips_remote_folder_uri(tmp_path):
    """End-to-end: a workspaceStorage entry pointing at a ``vscode-remote://`` folder
    must not surface anything in ``discover_mcp_servers`` — not even a parse failure."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    remote_hash = workspace_storage / "remote"
    remote_hash.mkdir(parents=True)
    (remote_hash / "workspace.json").write_text('{"folder": "vscode-remote://ssh-remote+host/home/me/repo"}')

    assert discoverer.discover_mcp_servers() == {}


def test_cursor_discoverer_walks_workspace_storage(tmp_path):
    """Cursor's workspaceStorage layout mirrors VSCode's; per-workspace MCP lives under ``.cursor/mcp.json``."""
    from agent_scan.agents import CursorDiscoverer

    discoverer = CursorDiscoverer(tmp_path)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    workspace_hash = workspace_storage / "ws"
    workspace_hash.mkdir(parents=True)

    workspace = tmp_path / "proj"
    workspace.mkdir()
    (workspace / ".cursor").mkdir()
    (workspace / ".cursor" / "mcp.json").write_text('{"mcpServers": {"cur-ws": {"command": "c"}}}')

    (workspace_hash / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    workspace_keys = [k for k in mcp_configs if k.endswith("/proj/.cursor/mcp.json")]
    assert len(workspace_keys) == 1


def test_windsurf_discoverer_discovers_workspace_root_mcp_json(tmp_path):
    """Windsurf reads a project-root ``.mcp.json`` in an opened workspace.

    Verified empirically; undocumented — the Windsurf MCP docs list only the
    global ``~/.codeium/windsurf/mcp_config.json``.
    """
    from agent_scan.agents import WindsurfDiscoverer

    discoverer = WindsurfDiscoverer(tmp_path)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    workspace_hash = workspace_storage / "ws"
    workspace_hash.mkdir(parents=True)

    workspace = tmp_path / "proj"
    workspace.mkdir()
    (workspace / ".mcp.json").write_text('{"mcpServers": {"ws-root-srv": {"command": "w"}}}')

    (workspace_hash / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    workspace_keys = [k for k in mcp_configs if k.endswith("/proj/.mcp.json")]
    assert len(workspace_keys) == 1
    entries = mcp_configs[workspace_keys[0]]
    assert isinstance(entries, list) and len(entries) == 1
    name, server = entries[0]
    assert name == "ws-root-srv"


def test_cursor_discoverer_discovers_workspace_root_mcp_json(tmp_path):
    """Cursor reads a project-root ``.mcp.json`` in an opened workspace.

    Verified empirically; undocumented — the Cursor MCP docs list only the
    workspace ``.cursor/mcp.json`` and the global ``~/.cursor/mcp.json``.
    """
    from agent_scan.agents import CursorDiscoverer

    discoverer = CursorDiscoverer(tmp_path)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    workspace_hash = workspace_storage / "ws"
    workspace_hash.mkdir(parents=True)

    workspace = tmp_path / "proj"
    workspace.mkdir()
    (workspace / ".mcp.json").write_text('{"mcpServers": {"ws-root-srv": {"command": "w"}}}')

    (workspace_hash / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    workspace_keys = [k for k in mcp_configs if k.endswith("/proj/.mcp.json")]
    assert len(workspace_keys) == 1
    entries = mcp_configs[workspace_keys[0]]
    assert isinstance(entries, list) and len(entries) == 1
    name, _ = entries[0]
    assert name == "ws-root-srv"


# --- skills discovery ---


def test_vscode_discoverer_parses_copilot_skills_dir(tmp_path):
    """VSCode reads skills from ``~/.copilot/skills`` (Copilot-installed skills)."""
    from agent_scan.agents import VSCodeDiscoverer

    skills_dir = tmp_path / ".copilot" / "skills"
    skills_dir.mkdir(parents=True)
    my_skill = skills_dir / "my-skill"
    my_skill.mkdir()
    (my_skill / "SKILL.md").write_text("---\nname: my-skill\ndescription: t\n---\n\nbody\n")
    (tmp_path / ".vscode").mkdir()

    skills_dirs = VSCodeDiscoverer(tmp_path).discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/.copilot/skills")]
    assert len(keys) == 1
    entries = skills_dirs[keys[0]]
    assert isinstance(entries, list)
    skill_name, skill = entries[0]
    assert skill_name == "my-skill"
    assert isinstance(skill, SkillServer)


@pytest.mark.parametrize("relative", ["~/.copilot/skills", "~/.claude/skills", "~/.agents/skills"])
def test_vscode_discoverer_reads_each_documented_user_skills_path(tmp_path, relative):
    """Per the official VS Code Agent Skills docs
    (code.visualstudio.com/docs/copilot/customization/agent-skills),
    VS Code reads user-level skills from three locations:
    ``~/.copilot/skills``, ``~/.claude/skills``, and ``~/.agents/skills``.

    Each must be picked up independently so users who store skills under
    only one of these paths still surface in scans.
    """
    from agent_scan.agents import VSCodeDiscoverer

    skills_dir = tmp_path / relative.replace("~/", "")
    _write_skill(skills_dir, "user-skill")
    (tmp_path / ".vscode").mkdir()

    skills_dirs = VSCodeDiscoverer(tmp_path).discover_skills()

    suffix = relative.replace("~", "")
    matching = [k for k in skills_dirs if k.endswith(suffix)]
    assert len(matching) == 1, f"VSCodeDiscoverer must surface skills at {relative}; got keys: {list(skills_dirs)}"
    entries = skills_dirs[matching[0]]
    assert isinstance(entries, list)
    skill_name, _ = entries[0]
    assert skill_name == "user-skill"


def _setup_vscode_workspace(tmp_path, workspace_relpath):
    """Helper: create a VSCode install with one opened workspace at ``tmp_path/<workspace_relpath>``."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir(exist_ok=True)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    workspace_hash = workspace_storage / "ws"
    workspace_hash.mkdir(parents=True)
    workspace = tmp_path / workspace_relpath
    workspace.mkdir(parents=True)
    (workspace_hash / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')
    return discoverer, workspace


@pytest.mark.parametrize("relative", [".github/skills", ".claude/skills", ".agents/skills"])
def test_vscode_discoverer_reads_each_documented_workspace_skills_path(tmp_path, relative):
    """Per the official VS Code Agent Skills docs
    (code.visualstudio.com/docs/copilot/customization/agent-skills),
    VS Code reads project skills from three locations inside the workspace:
    ``.github/skills``, ``.claude/skills``, and ``.agents/skills``.

    The ``.github/skills`` path is VS Code's canonical workspace skills location;
    the other two are documented cross-agent compatibility paths.
    """
    discoverer, workspace = _setup_vscode_workspace(tmp_path, "proj")
    _write_skill(workspace / relative, "ws-skill")

    skills_dirs = discoverer.discover_skills()

    matching = [k for k in skills_dirs if k.endswith(f"/proj/{relative}")]
    assert len(matching) == 1, (
        f"VSCodeDiscoverer must surface workspace skills at {relative}; got keys: {list(skills_dirs)}"
    )
    entries = skills_dirs[matching[0]]
    assert isinstance(entries, list)
    skill_name, skill = entries[0]
    assert skill_name == "ws-skill"
    assert isinstance(skill, SkillServer)


def test_kiro_discoverer_has_no_skills_dir(tmp_path):
    """Kiro doesn't ship a skills directory — ``discover_skills`` returns ``{}``."""
    from agent_scan.agents import KiroDiscoverer

    (tmp_path / ".kiro").mkdir()

    assert KiroDiscoverer(tmp_path).discover_skills() == {}


# --- integration: ``discover()`` returns ClientToInspect ---


def test_vscode_discoverer_discover_returns_client_to_inspect(tmp_path):
    from agent_scan.agents import VSCodeDiscoverer

    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text('{"servers": {"s": {"command": "x"}}}')

    cti = VSCodeDiscoverer(tmp_path).discover()

    assert isinstance(cti, ClientToInspect)
    assert cti.name == "vscode"
    assert cti.client_path.endswith("/.vscode")
    assert any(k.endswith("/.vscode/mcp.json") for k in cti.mcp_configs)


def test_cursor_discoverer_discover_returns_client_to_inspect(tmp_path):
    from agent_scan.agents import CursorDiscoverer

    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text('{"mcpServers": {"s": {"command": "x"}}}')

    cti = CursorDiscoverer(tmp_path).discover()

    assert isinstance(cti, ClientToInspect)
    assert cti.name == "cursor"


def test_discoverer_discover_returns_none_when_not_installed(tmp_path):
    """If the agent isn't installed, ``discover()`` short-circuits to None even with config dirs in place elsewhere."""
    from agent_scan.agents import VSCodeDiscoverer

    # Note: no ~/.vscode and no userdata Code dir → not installed.
    assert VSCodeDiscoverer(tmp_path).discover() is None


# --- DISCOVERERS registry & names ---


def test_discoverers_registry_includes_all_vscode_family():
    from agent_scan.agents import (
        DISCOVERERS,
        AntigravityDiscoverer,
        CursorDiscoverer,
        KiroDiscoverer,
        VSCodeDiscoverer,
        WindsurfDiscoverer,
    )

    assert DISCOVERERS["vscode"] is VSCodeDiscoverer
    assert DISCOVERERS["cursor"] is CursorDiscoverer
    assert DISCOVERERS["windsurf"] is WindsurfDiscoverer
    assert DISCOVERERS["kiro"] is KiroDiscoverer
    assert DISCOVERERS["antigravity"] is AntigravityDiscoverer


def test_vscode_family_discoverer_names_match_well_known_clients():
    """Every VSCode-family discoverer name MUST exist as a ``CandidateClient.name``
    in ``well_known_clients.py`` — the merge in
    ``pipelines.discover_clients_to_inspect`` keys on ``(name, username)``, so a
    discoverer whose name doesn't match its legacy entry produces duplicate
    (split) entries in scan output for the same agent.

    The expected set is read from the real ``well_known_clients`` module (not a
    hardcoded literal) and checked against *every* platform list, so a rename in
    any one of them is caught regardless of which OS the suite runs on. ``vscode``
    is the canonical 'still aligned' control; the others are the new family.
    """
    from agent_scan.agents import (
        AntigravityDiscoverer,
        CursorDiscoverer,
        KiroDiscoverer,
        VSCodeDiscoverer,
        WindsurfDiscoverer,
    )
    from agent_scan.well_known_clients import (
        LINUX_WELL_KNOWN_CLIENTS,
        MACOS_WELL_KNOWN_CLIENTS,
        WINDOWS_WELL_KNOWN_CLIENTS,
    )

    family_names = {
        cls.name
        for cls in (
            VSCodeDiscoverer,
            CursorDiscoverer,
            WindsurfDiscoverer,
            KiroDiscoverer,
            AntigravityDiscoverer,
        )
    }

    for label, clients in (
        ("macOS", MACOS_WELL_KNOWN_CLIENTS),
        ("Linux", LINUX_WELL_KNOWN_CLIENTS),
        ("Windows", WINDOWS_WELL_KNOWN_CLIENTS),
    ):
        well_known_names = {client.name for client in clients}
        missing = family_names - well_known_names
        assert not missing, (
            f"VSCode-family discoverer name(s) {sorted(missing)} have no matching "
            f"CandidateClient in the {label} well_known_clients list. A discoverer "
            f"name that drifts from its legacy entry splits one agent into two "
            f"(name, username) rows in scan output."
        )


def test_find_discoverers_picks_up_vscode_family_when_installed(tmp_path):
    """``find_discoverers`` returns one instance per registered class whose ``client_exists`` is true."""
    from agent_scan.agents import find_discoverers

    # Install just Cursor.
    (tmp_path / ".cursor").mkdir()

    found = find_discoverers(tmp_path)
    names = {d.name for d in found}

    assert "cursor" in names
    # The other VSCode-family agents shouldn't be reported as installed.
    assert "vscode" not in names
    assert "windsurf" not in names


# --- platform skip for user-data tests on platforms we don't lay out fixtures for ---


@pytest.mark.skipif(
    sys.platform not in ("darwin", "linux", "linux2", "win32"),
    reason="VSCode userdata path mapping only defined for macOS/Linux/Windows",
)
def test_vscode_user_data_dir_returns_platform_specific_path(tmp_path):
    """``_user_data_dir`` resolves to the canonical per-platform userdata folder for VSCode."""
    from agent_scan.agents import VSCodeDiscoverer

    user_data = _userdata(VSCodeDiscoverer(tmp_path))

    assert user_data is not None
    if sys.platform == "darwin":
        assert user_data.as_posix().endswith("/Library/Application Support/Code")
    elif sys.platform in ("linux", "linux2"):
        assert user_data.as_posix().endswith("/.config/Code")
    elif sys.platform == "win32":
        assert user_data.as_posix().endswith("/AppData/Roaming/Code")


# --- shared ancestor-walk now lives on AgentDiscoverer ---


def _setup_cursor_workspace(tmp_path, workspace_relpath):
    """Helper: create a Cursor install with one opened workspace at ``tmp_path/<workspace_relpath>``."""
    from agent_scan.agents import CursorDiscoverer

    discoverer = CursorDiscoverer(tmp_path)
    (tmp_path / ".cursor").mkdir(exist_ok=True)
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    workspace_hash = workspace_storage / "ws"
    workspace_hash.mkdir(parents=True)
    workspace = tmp_path / workspace_relpath
    workspace.mkdir(parents=True)
    (workspace_hash / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')
    return discoverer, workspace


def test_project_paths_with_ancestors_lives_on_agent_discoverer_base():
    """The ancestor walk is shared by every discoverer, so it lives on the abstract base."""
    from agent_scan.agents import AgentDiscoverer

    assert "_project_paths_with_ancestors" in AgentDiscoverer.__dict__


def test_vscode_family_project_paths_with_ancestors_uses_workspace_storage(tmp_path):
    """For VSCode family, project roots come from workspaceStorage, then fan out into ancestors."""
    discoverer, workspace = _setup_cursor_workspace(tmp_path, "deep/nested/repo")

    paths = set(discoverer._project_paths_with_ancestors())

    # Workspace + every ancestor up to filesystem root.
    cur = workspace
    while True:
        assert cur in paths
        if cur.parent == cur:
            break
        cur = cur.parent


def test_vscode_family_project_paths_empty_when_no_workspaces(tmp_path):
    """No workspaceStorage entries means no project paths and no ancestors."""
    from agent_scan.agents import CursorDiscoverer

    (tmp_path / ".cursor").mkdir()
    assert CursorDiscoverer(tmp_path)._project_paths_with_ancestors() == []


# --- Cursor workspace-scoped skills discovery ---


def _write_skill(dir_path, name):
    dir_path.mkdir(parents=True, exist_ok=True)
    skill = dir_path / name
    skill.mkdir()
    (skill / "SKILL.md").write_text(f"---\nname: {name}\ndescription: t\n---\n\nbody\n")


@pytest.mark.parametrize(
    "relative",
    [".cursor/skills", ".agents/skills", ".claude/skills", ".codex/skills"],
)
def test_cursor_discovers_workspace_skills_at_each_supported_relative_path(tmp_path, relative):
    """Cursor reads workspace-level skills from .cursor/skills, .agents/skills, .claude/skills, .codex/skills."""
    discoverer, workspace = _setup_cursor_workspace(tmp_path, "proj")
    _write_skill(workspace / relative, "ws-skill")

    skills_dirs = discoverer.discover_skills()

    matching = [k for k in skills_dirs if k.endswith(f"/proj/{relative}")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert isinstance(entries, list)
    skill_name, skill = entries[0]
    assert skill_name == "ws-skill"
    assert isinstance(skill, SkillServer)


def test_cursor_workspace_skills_picked_up_from_ancestor(tmp_path):
    """A skills dir at an ancestor of the opened workspace must be surfaced (monorepo case)."""
    discoverer, workspace = _setup_cursor_workspace(tmp_path, "monorepo/packages/web")
    # Skills live at the monorepo root, not inside the opened subpackage.
    _write_skill(tmp_path / "monorepo" / ".cursor" / "skills", "root-skill")

    skills_dirs = discoverer.discover_skills()

    assert any(k.endswith("/monorepo/.cursor/skills") for k in skills_dirs)


def test_cursor_workspace_skills_dedups_shared_ancestor(tmp_path):
    """Two opened workspaces under a shared ancestor with one skills dir → single entry."""
    from agent_scan.agents import CursorDiscoverer

    discoverer = CursorDiscoverer(tmp_path)
    (tmp_path / ".cursor").mkdir()
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"

    for slug, sub in (("ws-a", "monorepo/a"), ("ws-b", "monorepo/b")):
        wh = workspace_storage / slug
        wh.mkdir(parents=True)
        ws = tmp_path / sub
        ws.mkdir(parents=True)
        (wh / "workspace.json").write_text(f'{{"folder": "{ws.as_uri()}"}}')

    _write_skill(tmp_path / "monorepo" / ".cursor" / "skills", "shared")

    skills_dirs = discoverer.discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/monorepo/.cursor/skills")]
    assert len(keys) == 1


def test_cursor_workspace_skills_missing_dir_does_not_emit_key(tmp_path):
    """A workspace without any of the supported relative skill paths produces no workspace skill entries."""
    discoverer, _ = _setup_cursor_workspace(tmp_path, "bare")

    skills_dirs = discoverer.discover_skills()

    # No `bare/...` keys should be present — the workspace has no skills.
    assert not any("/bare/" in k for k in skills_dirs)


def test_cursor_user_level_skills_still_discovered(tmp_path):
    """Lifting the ancestor walk must not regress the existing ``~/.cursor/skills`` discovery."""
    from agent_scan.agents import CursorDiscoverer

    (tmp_path / ".cursor").mkdir()
    _write_skill(tmp_path / ".cursor" / "skills", "user-skill")

    skills_dirs = CursorDiscoverer(tmp_path).discover_skills()

    assert any(k.endswith("/.cursor/skills") for k in skills_dirs)


# --- Cursor workspace-scoped MCP picks up ancestor .cursor/mcp.json ---


def test_cursor_workspace_mcp_picked_up_from_ancestor(tmp_path):
    """``.cursor/mcp.json`` at an ancestor of the opened workspace is included — same as Claude Code's project walk."""
    discoverer, workspace = _setup_cursor_workspace(tmp_path, "monorepo/apps/web")
    ancestor_mcp = tmp_path / "monorepo" / ".cursor"
    ancestor_mcp.mkdir()
    (ancestor_mcp / "mcp.json").write_text('{"mcpServers": {"root-mcp": {"command": "r"}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/monorepo/.cursor/mcp.json")]
    assert len(matching) == 1


# --- VSCode-family extension walks (parity with Claude Code plugin walks) ---


def test_vscode_extension_mcp_discovers_wrapped_mcp_json(tmp_path):
    """An extension dropping ``mcp.json`` under ``~/.vscode/extensions/<ext>/`` is picked up."""
    from agent_scan.agents import VSCodeDiscoverer

    ext_dir = tmp_path / ".vscode" / "extensions" / "publisher.example-1.0.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text('{"mcpServers": {"ext-srv": {"command": "e"}}}')

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if "/extensions/publisher.example-1.0.0/mcp.json" in k]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "ext-srv"
    assert isinstance(server, StdioServer)


def test_vscode_extension_mcp_discovers_vscode_flat_servers_shape(tmp_path):
    """An extension shipping the VSCode-flat ``{"servers": {...}}`` shape also parses."""
    from agent_scan.agents import VSCodeDiscoverer

    ext_dir = tmp_path / ".vscode" / "extensions" / "x.flat-2.0.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text('{"servers": {"flat-srv": {"command": "f"}}}')

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/x.flat-2.0.0/mcp.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, _ = entries[0]
    assert name == "flat-srv"


def test_vscode_extension_mcp_empty_when_extensions_dir_missing(tmp_path, monkeypatch):
    """No *user* ``extensions/`` tree means no extension-scope keys in the result.

    Built-in (bundled) extension dirs are neutralized so the assertion stays
    hermetic on machines where VS Code is actually installed.
    """
    from agent_scan.agents import VSCodeDiscoverer

    monkeypatch.setattr(VSCodeDiscoverer, "_builtin_extension_dirs", lambda self: [])
    (tmp_path / ".vscode").mkdir()

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert not any("/extensions/" in k for k in mcp_configs)


def test_vscode_extension_mcp_records_could_not_parse_for_invalid_json(tmp_path):
    """A malformed ``mcp.json`` inside an extension dir surfaces as ``CouldNotParseMCPConfig``."""
    from agent_scan.agents import VSCodeDiscoverer

    ext_dir = tmp_path / ".vscode" / "extensions" / "x.bad-0.0.1"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text("{ not valid json")

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/x.bad-0.0.1/mcp.json")]
    assert len(matching) == 1
    entry = mcp_configs[matching[0]]
    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure is True


def test_vscode_extension_mcp_skips_unrelated_json_named_mcp_json(tmp_path):
    """An extension shipping a file *named* ``mcp.json`` that isn't an MCP config
    (e.g. a bundled JSON Schema) is skipped silently — not surfaced as a
    ``CouldNotParseMCPConfig`` false positive.

    The extension walk matches every file by that name, so only recognizably
    MCP-shaped files should produce entries. A JSON Schema has no
    ``mcpServers``/``mcp``/``servers`` wrapper and is not a flat server map, so it
    is correctly treated as "not MCP" rather than "malformed MCP".
    """
    from agent_scan.agents import VSCodeDiscoverer

    ext_dir = tmp_path / ".vscode" / "extensions" / "x.schema-1.0.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text(
        '{"$schema": "https://json-schema.org/draft-07/schema", '
        '"title": "config schema", "type": "object", '
        '"properties": {"foo": {"type": "string"}}}'
    )

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    leaked = [k for k in mcp_configs if "/x.schema-1.0.0/" in k]
    assert leaked == [], f"a non-MCP file named mcp.json must be skipped, got: {[(k, mcp_configs[k]) for k in leaked]}"


def test_vscode_extension_mcp_still_flags_malformed_mcp_shaped_file(tmp_path):
    """A walked ``mcp.json`` that *is* MCP-shaped (carries an ``mcpServers``
    wrapper) but fails validation is still reported as ``CouldNotParseMCPConfig``.

    The skip only suppresses files that were never plausibly MCP — a wrapper-keyed
    file with a broken server entry is a genuine malformation worth surfacing.
    """
    from agent_scan.agents import VSCodeDiscoverer

    ext_dir = tmp_path / ".vscode" / "extensions" / "x.brokenmcp-1.0.0"
    ext_dir.mkdir(parents=True)
    # Recognizably MCP (mcpServers wrapper), but the server has neither a
    # ``command`` (stdio) nor a ``url`` (remote), so no server model validates.
    (ext_dir / "mcp.json").write_text('{"mcpServers": {"bad": {"args": ["x"]}}}')

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/x.brokenmcp-1.0.0/mcp.json")]
    assert len(matching) == 1
    assert isinstance(mcp_configs[matching[0]], CouldNotParseMCPConfig)


def test_vscode_extension_skills_discovers_skills_dir(tmp_path):
    """An extension shipping a ``skills/`` directory is picked up."""
    from agent_scan.agents import VSCodeDiscoverer

    ext_skill_dir = tmp_path / ".vscode" / "extensions" / "p.ext-1.0.0" / "skills" / "ext-skill"
    ext_skill_dir.mkdir(parents=True)
    (ext_skill_dir / "SKILL.md").write_text("---\nname: ext-skill\ndescription: e\n---\n\nbody.\n")

    skills_dirs = VSCodeDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/p.ext-1.0.0/skills")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert isinstance(entries, list)
    name, skill = entries[0]
    assert name == "ext-skill"
    assert isinstance(skill, SkillServer)


def test_vscode_extension_skills_empty_when_extensions_dir_missing(tmp_path, monkeypatch):
    """No *user* ``extensions/`` tree means no extension-scope skill keys.

    Built-in (bundled) extension dirs are neutralized so the assertion stays
    hermetic on machines where VS Code is actually installed (it bundles Copilot
    Chat, whose skills would otherwise surface here).
    """
    from agent_scan.agents import VSCodeDiscoverer

    monkeypatch.setattr(VSCodeDiscoverer, "_builtin_extension_dirs", lambda self: [])
    (tmp_path / ".vscode").mkdir()

    skills_dirs = VSCodeDiscoverer(tmp_path).discover_skills()

    assert not any("/extensions/" in k for k in skills_dirs)


def test_cursor_extension_mcp_discovers_mcp_json(tmp_path):
    """Cursor's ``~/.cursor/extensions/<ext>/mcp.json`` is scanned the same way as VSCode's."""
    from agent_scan.agents import CursorDiscoverer

    ext_dir = tmp_path / ".cursor" / "extensions" / "vendor.curext-3.1.4"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text('{"mcpServers": {"cur-ext-srv": {"command": "c"}}}')

    mcp_configs = CursorDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/vendor.curext-3.1.4/mcp.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, _ = entries[0]
    assert name == "cur-ext-srv"


def test_cursor_extension_skills_discovers_skills_dir(tmp_path):
    """Cursor extensions can ship a ``skills/`` directory just like VSCode."""
    from agent_scan.agents import CursorDiscoverer

    ext_skill_dir = tmp_path / ".cursor" / "extensions" / "v.c-1.0.0" / "skills" / "cur-skill"
    ext_skill_dir.mkdir(parents=True)
    (ext_skill_dir / "SKILL.md").write_text("---\nname: cur-skill\ndescription: c\n---\n\nbody.\n")

    skills_dirs = CursorDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/v.c-1.0.0/skills")]
    assert len(matching) == 1


def test_windsurf_extension_mcp_discovers_mcp_json(tmp_path):
    """Windsurf is a VSCode fork; ``~/.codeium/windsurf/extensions/`` follows the same convention."""
    from agent_scan.agents import WindsurfDiscoverer

    ext_dir = tmp_path / ".codeium" / "windsurf" / "extensions" / "v.ws-1.0.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text('{"mcpServers": {"ws-ext-srv": {"command": "w"}}}')

    mcp_configs = WindsurfDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/v.ws-1.0.0/mcp.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, _ = entries[0]
    assert name == "ws-ext-srv"


def test_vscode_extension_walk_respects_max_depth_cap(tmp_path, monkeypatch):
    """An extension nested deeper than the depth cap is not scanned.

    Mirrors the Claude Code plugin-walk depth test: pruning protects against
    pathologically deep trees blowing up the walk.
    """
    from agent_scan.agents import VSCodeDiscoverer
    from agent_scan.agents.vscode import base as vscode_base

    # The extension walk reads ``_MAX_PLUGIN_RGLOB_DEPTH`` from its own module
    # (agents.vscode.base), so patch the cap there.
    monkeypatch.setattr(vscode_base, "_MAX_PLUGIN_RGLOB_DEPTH", 3)

    # Inside ``~/.vscode/extensions/`` the relative-parts depth of
    # ``a/b/c/d/mcp.json`` is 4 — beyond cap 3, so it must NOT be discovered.
    deep = tmp_path / ".vscode" / "extensions" / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    (deep / "mcp.json").write_text('{"mcpServers": {"deep": {"command": "x"}}}')

    mcp_configs = VSCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert not any("/a/b/c/d/mcp.json" in k for k in mcp_configs)


def test_kiro_discoverer_walks_kiro_extensions_dir(tmp_path):
    """Kiro is a VSCode fork using the OpenVSX registry, so installed extensions
    live at ``~/.kiro/extensions/`` and can ship ``mcp.json`` like any VSCode-family ext.

    The historical assertion that Kiro doesn't walk extensions was wrong — the path
    just hadn't been wired up yet.
    """
    from agent_scan.agents import KiroDiscoverer

    ext_dir = tmp_path / ".kiro" / "extensions" / "x.kr-1.0.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text('{"mcpServers": {"kr-ext": {"command": "k"}}}')

    mcp_configs = KiroDiscoverer(tmp_path).discover_mcp_servers()

    assert any("/extensions/" in k for k in mcp_configs)


def test_antigravity_discoverer_walks_gemini_extensions_dir(tmp_path):
    """Antigravity's documented extensions location is ``~/.gemini/extensions/`` (shared
    with the Gemini CLI), not ``~/.gemini/antigravity/extensions/``. Confirm we walk the
    correct path and ignore the wrong one."""
    from agent_scan.agents import AntigravityDiscoverer

    correct_ext_dir = tmp_path / ".gemini" / "extensions" / "x.ag-1.0.0"
    correct_ext_dir.mkdir(parents=True)
    (correct_ext_dir / "mcp.json").write_text('{"mcpServers": {"ag-ext": {"command": "a"}}}')

    wrong_ext_dir = tmp_path / ".gemini" / "antigravity" / "extensions" / "x.wrong-1.0.0"
    wrong_ext_dir.mkdir(parents=True)
    (wrong_ext_dir / "mcp.json").write_text('{"mcpServers": {"wrong-ext": {"command": "w"}}}')

    mcp_configs = AntigravityDiscoverer(tmp_path).discover_mcp_servers()

    assert any("/.gemini/extensions/x.ag-1.0.0/mcp.json" in k for k in mcp_configs)
    assert not any("/.gemini/antigravity/extensions/" in k for k in mcp_configs)


# --- Workspace-skill coverage for Windsurf / Kiro / Antigravity ---
#
# Per the agents' official docs:
#   - Windsurf: workspace skills at ``.windsurf/skills/`` + cross-agent compat
#     paths ``.agents/skills/`` and ``.claude/skills/``
#   - Kiro:    user-global ``~/.kiro/skills/`` and workspace ``.kiro/skills/``;
#     userdata lives at ``~/Library/Application Support/Kiro/`` (capital K).
#   - Antigravity: user-global ``~/.gemini/antigravity/skills/`` and workspace
#     ``.agent/skills/`` (singular ``.agent``, not ``.agents``); userdata at
#     ``~/Library/Application Support/Antigravity/``.


def _setup_workspace(discoverer, tmp_path, workspace_relpath):
    """Set up a workspaceStorage entry for any VSCode-family discoverer.

    Generalizes ``_setup_cursor_workspace`` so Windsurf, Kiro, and Antigravity
    tests can reuse the same scaffolding now that those discoverers also have
    a userdata dir.
    """
    workspace_storage = _userdata(discoverer) / "User" / "workspaceStorage"
    workspace_hash = workspace_storage / "ws"
    workspace_hash.mkdir(parents=True)
    workspace = tmp_path / workspace_relpath
    workspace.mkdir(parents=True)
    (workspace_hash / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')
    return workspace


@pytest.mark.parametrize(
    "relative",
    [".windsurf/skills", ".agents/skills", ".claude/skills"],
)
def test_windsurf_discovers_workspace_skills_at_each_supported_relative_path(tmp_path, relative):
    """Windsurf docs list ``.windsurf/skills`` plus cross-agent compat for ``.agents`` and ``.claude``."""
    from agent_scan.agents import WindsurfDiscoverer

    (tmp_path / ".codeium" / "windsurf").mkdir(parents=True)
    discoverer = WindsurfDiscoverer(tmp_path)
    workspace = _setup_workspace(discoverer, tmp_path, "proj")
    _write_skill(workspace / relative, "ws-skill")

    skills_dirs = discoverer.discover_skills()

    matching = [k for k in skills_dirs if k.endswith(f"/proj/{relative}")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert isinstance(entries, list)
    assert any(name == "ws-skill" for name, _ in entries)


def test_kiro_user_global_skills_discovered(tmp_path):
    """Kiro's user-global skills live at ``~/.kiro/skills/`` per the Kiro docs."""
    from agent_scan.agents import KiroDiscoverer

    _write_skill(tmp_path / ".kiro" / "skills", "kiro-user-skill")

    skills_dirs = KiroDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/.kiro/skills")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert any(name == "kiro-user-skill" for name, _ in entries)


def test_kiro_user_data_dir_resolves_to_capital_kiro(tmp_path):
    """Kiro's userdata folder is named ``Kiro`` (capital K) — observed on disk at
    ``~/Library/Application Support/Kiro/User/workspaceStorage/``. The lowercase
    ``kiro.kiroagent`` seen under ``globalStorage/`` is the extension id, not the
    userdata folder. The capitalized name matters on case-sensitive filesystems
    and under ``--scan-all-users``, where a lowercase name would miss the tree
    and silently drop all per-workspace (project) MCP/skills discovery."""
    from agent_scan.agents import KiroDiscoverer

    userdata = KiroDiscoverer(tmp_path)._user_data_dir()

    assert userdata is not None
    assert userdata.name == "Kiro"


@pytest.mark.parametrize(
    "relative",
    [".kiro/skills", ".agents/skills"],
)
def test_kiro_discovers_workspace_skills_at_each_supported_relative_path(tmp_path, relative):
    """Kiro docs list workspace skills at ``<project>/.kiro/skills/``; ``.agents/skills``
    is an inferred (undocumented) cross-tool compat path mirroring its VSCode-family
    siblings (Cursor/VSCode/Windsurf)."""
    from agent_scan.agents import KiroDiscoverer

    (tmp_path / ".kiro").mkdir()
    discoverer = KiroDiscoverer(tmp_path)
    workspace = _setup_workspace(discoverer, tmp_path, "myproj")
    _write_skill(workspace / relative, "kr-ws-skill")

    skills_dirs = discoverer.discover_skills()

    matching = [k for k in skills_dirs if k.endswith(f"/myproj/{relative}")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert any(name == "kr-ws-skill" for name, _ in entries)


def test_antigravity_user_global_skills_discovered(tmp_path):
    """Antigravity's user-global skills live at ``~/.gemini/antigravity/skills/``."""
    from agent_scan.agents import AntigravityDiscoverer

    _write_skill(tmp_path / ".gemini" / "antigravity" / "skills", "ag-user-skill")

    skills_dirs = AntigravityDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/.gemini/antigravity/skills")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert any(name == "ag-user-skill" for name, _ in entries)


def test_antigravity_user_data_dir_resolves_to_capital_antigravity(tmp_path):
    """Antigravity's userdata folder is named ``Antigravity`` — observed at
    ``~/Library/Application Support/Antigravity/`` and ``AppData/Roaming/Antigravity``."""
    from agent_scan.agents import AntigravityDiscoverer

    userdata = AntigravityDiscoverer(tmp_path)._user_data_dir()

    assert userdata is not None
    assert userdata.name == "Antigravity"


def test_antigravity_discovers_workspace_skills_at_singular_agent_relative(tmp_path):
    """Per Antigravity docs the workspace path is ``.agent/skills`` (singular ``agent``)."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    discoverer = AntigravityDiscoverer(tmp_path)
    workspace = _setup_workspace(discoverer, tmp_path, "myproj")
    _write_skill(workspace / ".agent" / "skills", "ag-ws-skill")

    skills_dirs = discoverer.discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/myproj/.agent/skills")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert any(name == "ag-ws-skill" for name, _ in entries)


# NOTE: ``.agents/skills`` (plural) IS now a documented Antigravity workspace
# skills path (the newer default alongside the singular ``.agent/skills``); the
# positive case is covered by
# ``test_antigravity_discovers_plural_agents_workspace_skills``.


# --- Antigravity opened-workspace discovery via the ~/.gemini/config/projects
# registry (NOT the VSCode workspaceStorage tree) ---------------------------------
#
# Antigravity's userdata dir is a bare Chromium profile with no ``User/`` subtree,
# so the inherited VSCode ``workspaceStorage`` walk never fires on a real install.
# The IDE instead records each opened workspace in
# ``~/.gemini/config/projects/<id>.json`` under
# ``projectResources.resources[].folderUri``. These tests pin that real source so
# workspace-scoped skills surface for an actually-open project (the inherited
# workspaceStorage path is still honored as a forward-compat fallback).


def _setup_gemini_project(tmp_path, workspace_relpath, *, filename="proj.json", project_name="proj"):
    """Register an opened Antigravity workspace the way the IDE actually does:
    a ``~/.gemini/config/projects/<filename>`` file whose
    ``projectResources.resources[].folderUri`` is the workspace's ``file://`` URI.

    Returns the created workspace Path.
    """
    projects_dir = tmp_path / ".gemini" / "config" / "projects"
    projects_dir.mkdir(parents=True, exist_ok=True)
    workspace = tmp_path / workspace_relpath
    workspace.mkdir(parents=True, exist_ok=True)
    (projects_dir / filename).write_text(
        f'{{"name": "{project_name}", "projectResources": {{"resources": [{{"folderUri": "{workspace.as_uri()}"}}]}}}}'
    )
    return workspace


def test_antigravity_project_folders_from_gemini_projects_registry(tmp_path):
    """Opened workspaces come from ``~/.gemini/config/projects/*.json`` (folderUri),
    not the absent ``workspaceStorage`` tree."""
    from agent_scan.agents import AntigravityDiscoverer

    workspace = _setup_gemini_project(tmp_path, "myproj")

    folders = AntigravityDiscoverer(tmp_path)._discover_project_folders()

    assert workspace in folders


def test_antigravity_workspace_skills_discovered_via_gemini_projects_registry(tmp_path):
    """End-to-end regression: a ``.agents/skills`` dir in a project recorded only in
    the ``~/.gemini/config/projects`` registry must surface (the reported bug)."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    workspace = _setup_gemini_project(tmp_path, "myproj")
    _write_skill(workspace / ".agents" / "skills", "ws-skill")

    skills_dirs = AntigravityDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/myproj/.agents/skills")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert any(name == "ws-skill" for name, _ in entries)


@pytest.mark.parametrize(
    "relative",
    [".mcp.json", ".agents/mcp_config.json", ".gemini/mcp_config.json"],
)
def test_antigravity_workspace_mcp_discovered_via_gemini_projects_registry(tmp_path, relative):
    """End-to-end regression: a project MCP file at each supported workspace-relative
    path, in a workspace recorded only in the ``~/.gemini/config/projects`` registry,
    must surface (the reported bug — Antigravity never scanned project-scoped MCP
    because ``_workspace_mcp_relative`` was empty)."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    workspace = _setup_gemini_project(tmp_path, "myproj")
    mcp_file = workspace / relative
    mcp_file.parent.mkdir(parents=True, exist_ok=True)
    mcp_file.write_text('{"mcpServers": {"ws-mcp": {"type": "http", "url": "https://ws-mcp.example/mcp"}}}')

    mcp_configs = AntigravityDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith(f"/myproj/{relative}")]
    assert len(matching) == 1, f"workspace MCP at {relative} must surface; got keys: {list(mcp_configs)}"
    entry = mcp_configs[matching[0]]
    assert not isinstance(entry, CouldNotParseMCPConfig)
    name, server = entry[0]
    assert name == "ws-mcp"
    assert getattr(server, "url", None) == "https://ws-mcp.example/mcp"


def test_antigravity_workspace_mcp_picked_up_from_ancestor(tmp_path):
    """A project MCP file at an *ancestor* of the opened workspace is included — the
    ancestor walk (monorepo root holding the config) applies to Antigravity's
    gemini-registry workspaces too, mirroring the Cursor/VSCode behavior."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    _setup_gemini_project(tmp_path, "monorepo/packages/app")
    (tmp_path / "monorepo" / ".mcp.json").write_text('{"mcpServers": {"root-mcp": {"command": "x"}}}')

    mcp_configs = AntigravityDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/monorepo/.mcp.json")]
    assert len(matching) == 1, f"ancestor project MCP must surface; got keys: {list(mcp_configs)}"
    # The file lives only at the ancestor, so the leaf's own .mcp.json must not
    # appear — proves it is genuinely the ancestor being walked, not the leaf.
    assert not any(k.endswith("/app/.mcp.json") for k in mcp_configs)


def test_antigravity_project_folders_empty_when_projects_dir_missing(tmp_path):
    """No ``~/.gemini/config/projects`` dir → no project folders (no crash)."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)

    assert AntigravityDiscoverer(tmp_path)._discover_project_folders() == []


def test_antigravity_project_folders_skips_malformed_project_json(tmp_path):
    """A malformed project file is skipped silently; sibling valid files still resolve."""
    from agent_scan.agents import AntigravityDiscoverer

    workspace = _setup_gemini_project(tmp_path, "good", filename="good.json")
    (tmp_path / ".gemini" / "config" / "projects" / "bad.json").write_text("{ not json")

    folders = AntigravityDiscoverer(tmp_path)._discover_project_folders()

    assert workspace in folders


def test_antigravity_project_folders_handles_multiple_resources_in_one_file(tmp_path):
    """Every resource within a single project file is surfaced; a resource missing a
    ``folderUri`` is skipped without affecting the others."""
    from agent_scan.agents import AntigravityDiscoverer

    projects_dir = tmp_path / ".gemini" / "config" / "projects"
    projects_dir.mkdir(parents=True)
    ws_a = tmp_path / "a"
    ws_a.mkdir()
    ws_b = tmp_path / "b"
    ws_b.mkdir()
    (projects_dir / "multi.json").write_text(
        f'{{"projectResources": {{"resources": ['
        f'{{"folderUri": "{ws_a.as_uri()}"}}, {{"note": "no folderUri"}}, '
        f'{{"folderUri": "{ws_b.as_uri()}"}}]}}}}'
    )

    folders = AntigravityDiscoverer(tmp_path)._discover_project_folders()

    assert ws_a in folders
    assert ws_b in folders


def test_antigravity_project_folders_skips_non_file_uri(tmp_path):
    """A non-``file://`` folderUri (e.g. a remote scheme) is skipped, not crashed on."""
    from agent_scan.agents import AntigravityDiscoverer

    projects_dir = tmp_path / ".gemini" / "config" / "projects"
    projects_dir.mkdir(parents=True)
    (projects_dir / "remote.json").write_text(
        '{"projectResources": {"resources": [{"folderUri": "vscode-remote://ssh/home/me/repo"}]}}'
    )

    assert AntigravityDiscoverer(tmp_path)._discover_project_folders() == []


# --- Antigravity v2.0: second userdata folder ("Antigravity IDE") ---
#
# v2.0 split the IDE into two AppData/Application-Support directories:
# v1.x writes to ``Antigravity``, v2.0 writes to ``Antigravity IDE``. Both
# must be scanned so users on either version don't fall off the radar.


def _platform_userdata_root():
    """Return the platform-specific ``<userdata>`` parent dir (e.g.
    ``~/Library/Application Support`` on macOS) as a relative-to-home path."""
    if sys.platform == "darwin":
        return "Library/Application Support"
    if sys.platform in ("linux", "linux2"):
        return ".config"
    if sys.platform == "win32":
        return "AppData/Roaming"
    pytest.skip("Unsupported platform for VSCode-family userdata tests")
    return ""  # unreachable


def test_antigravity_user_data_dirs_includes_both_v1_and_v2_names(tmp_path):
    """``_user_data_dirs()`` exposes every candidate userdata folder. For Antigravity
    that's both the v1.x ``Antigravity`` and the v2.0 ``Antigravity IDE``."""
    from agent_scan.agents import AntigravityDiscoverer

    dirs = AntigravityDiscoverer(tmp_path)._user_data_dirs()

    names = [d.name for d in dirs]
    assert "Antigravity" in names
    assert "Antigravity IDE" in names


def test_antigravity_v1_userdata_remains_first_candidate(tmp_path):
    """The v1.x ``Antigravity`` name stays the first candidate so existing single-userdata
    callers (and tests using ``_user_data_dir()``) keep their previous behavior."""
    from agent_scan.agents import AntigravityDiscoverer

    userdata = AntigravityDiscoverer(tmp_path)._user_data_dir()

    assert userdata is not None
    assert userdata.name == "Antigravity"


def test_antigravity_discovers_workspace_skills_via_v2_userdata(tmp_path):
    """A workspace registered under the v2.0 ``Antigravity IDE`` userdata folder must be
    walked for ``.agent/skills/`` just like one registered under v1.x."""
    from agent_scan.agents import AntigravityDiscoverer

    discoverer = AntigravityDiscoverer(tmp_path)
    v2_userdata = tmp_path / _platform_userdata_root() / "Antigravity IDE"
    workspace_storage = v2_userdata / "User" / "workspaceStorage" / "ws"
    workspace_storage.mkdir(parents=True)
    workspace = tmp_path / "v2proj"
    workspace.mkdir()
    (workspace_storage / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')

    _write_skill(workspace / ".agent" / "skills", "v2-skill")

    skills_dirs = discoverer.discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/v2proj/.agent/skills")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert any(name == "v2-skill" for name, _ in entries)


def test_antigravity_client_exists_detects_v2_userdata_only_install(tmp_path):
    """If only the v2.0 userdata folder exists (no ``~/.gemini/antigravity`` dotfile,
    no v1 userdata), ``client_exists`` still reports Antigravity as present."""
    from agent_scan.agents import AntigravityDiscoverer

    v2_userdata = tmp_path / _platform_userdata_root() / "Antigravity IDE"
    v2_userdata.mkdir(parents=True)

    assert AntigravityDiscoverer(tmp_path).client_exists() is not None


# --- Cross-agent user-level skill paths (Cursor + Windsurf) ---
#
# Per the official docs both IDEs honor cross-agent compatibility paths under
# the user's home dir (not just inside the workspace). For Cursor that's
# ``~/.agents/skills``, ``~/.claude/skills``, ``~/.codex/skills``; for
# Windsurf it's ``~/.agents/skills`` and ``~/.claude/skills``.


@pytest.mark.parametrize(
    "relative",
    [".agents/skills", ".claude/skills", ".codex/skills"],
)
def test_cursor_user_global_cross_compat_skills_discovered(tmp_path, relative):
    """Cursor docs (cursor.com/docs/skills) list user-level skill paths
    ``~/.agents/skills``, ``~/.claude/skills``, and ``~/.codex/skills`` in
    addition to ``~/.cursor/skills``."""
    from agent_scan.agents import CursorDiscoverer

    (tmp_path / ".cursor").mkdir()
    _write_skill(tmp_path / relative, "cur-user-cross-skill")

    skills_dirs = CursorDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith(f"/{relative}")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert any(name == "cur-user-cross-skill" for name, _ in entries)


@pytest.mark.parametrize(
    "relative",
    [".agents/skills", ".claude/skills"],
)
def test_windsurf_user_global_cross_compat_skills_discovered(tmp_path, relative):
    """Windsurf docs (docs.windsurf.com/windsurf/cascade/skills) list user-level
    cross-compat paths ``~/.agents/skills`` and ``~/.claude/skills`` alongside
    the canonical ``~/.codeium/windsurf/skills``."""
    from agent_scan.agents import WindsurfDiscoverer

    (tmp_path / ".codeium" / "windsurf").mkdir(parents=True)
    _write_skill(tmp_path / relative, "ws-user-cross-skill")

    skills_dirs = WindsurfDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith(f"/{relative}")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert any(name == "ws-user-cross-skill" for name, _ in entries)


# --- Kiro: workspace MCP under ``.kiro/settings/mcp.json`` ---
#
# Per kiro.dev/docs/mcp/configuration/, Kiro reads workspace MCP from
# ``<root>/.kiro/settings/mcp.json`` (parallel to user-global
# ``~/.kiro/settings/mcp.json``).


def test_kiro_discoverer_parses_workspace_settings_mcp_json(tmp_path):
    """A ``.kiro/settings/mcp.json`` inside an opened workspace surfaces in
    ``discover_mcp_servers``."""
    from agent_scan.agents import KiroDiscoverer

    (tmp_path / ".kiro").mkdir()
    discoverer = KiroDiscoverer(tmp_path)
    workspace = _setup_workspace(discoverer, tmp_path, "kproj")
    ws_settings = workspace / ".kiro" / "settings"
    ws_settings.mkdir(parents=True)
    (ws_settings / "mcp.json").write_text('{"mcpServers": {"kr-ws": {"command": "k"}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/kproj/.kiro/settings/mcp.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "kr-ws"
    assert isinstance(server, StdioServer)


# --- Kiro: extension walks ---
#
# Kiro is a VSCode fork that uses the OpenVSX extension registry. Installed
# extensions live under ``~/.kiro/extensions/`` and can ship an ``mcp.json``
# (VSCode/Copilot contribution-point convention) or a ``skills/`` dir, both of
# which a security scanner should discover.


def test_kiro_extension_mcp_discovers_mcp_json(tmp_path):
    """An extension dropping ``mcp.json`` under ``~/.kiro/extensions/<ext>/`` is picked up."""
    from agent_scan.agents import KiroDiscoverer

    ext_dir = tmp_path / ".kiro" / "extensions" / "p.kr-ext-1.0.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text('{"mcpServers": {"kr-ext-srv": {"command": "k"}}}')

    mcp_configs = KiroDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if "/extensions/p.kr-ext-1.0.0/mcp.json" in k]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "kr-ext-srv"
    assert isinstance(server, StdioServer)


def test_kiro_extension_skills_discovers_skills_dir(tmp_path):
    """An extension shipping a ``skills/`` directory under ``~/.kiro/extensions/`` surfaces."""
    from agent_scan.agents import KiroDiscoverer

    ext_skill_dir = tmp_path / ".kiro" / "extensions" / "p.kr-1.0.0" / "skills" / "kr-skill"
    ext_skill_dir.mkdir(parents=True)
    (ext_skill_dir / "SKILL.md").write_text("---\nname: kr-skill\ndescription: t\n---\n\nbody\n")

    skills_dirs = KiroDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/extensions/p.kr-1.0.0/skills")]
    assert len(matching) == 1


# --- Antigravity: shared MCP path under ``~/.gemini/config/`` ---
#
# Per Google Cloud Community docs on Antigravity, the unified MCP config that
# the CLI *and* IDE both consult lives at ``~/.gemini/config/mcp_config.json``
# (in addition to the IDE-specific ``~/.gemini/antigravity/mcp_config.json``).


def test_antigravity_shared_gemini_config_mcp_discovered(tmp_path):
    """``~/.gemini/config/mcp_config.json`` is read alongside the antigravity-specific
    file so users who set up shared MCP across Gemini CLI + Antigravity IDE surface here."""
    from agent_scan.agents import AntigravityDiscoverer

    config_dir = tmp_path / ".gemini" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "mcp_config.json").write_text('{"mcpServers": {"shared-srv": {"command": "g"}}}')
    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)

    mcp_configs = AntigravityDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/.gemini/config/mcp_config.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    name, server = entries[0]
    assert name == "shared-srv"
    assert isinstance(server, StdioServer)


# --- Antigravity: shared skills under ``~/.gemini/skills/`` ---


def test_antigravity_user_shared_skills_discovered(tmp_path):
    """Per the Antigravity docs, skills shared between CLI and IDE go under
    ``~/.gemini/skills/`` — distinct from the IDE-only ``~/.gemini/antigravity/skills/``."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    _write_skill(tmp_path / ".gemini" / "skills", "shared-skill")

    skills_dirs = AntigravityDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/.gemini/skills")]
    assert len(matching) == 1
    entries = skills_dirs[matching[0]]
    assert any(name == "shared-skill" for name, _ in entries)


# --- Antigravity: extension walks under ``~/.gemini/extensions/`` ---
#
# Reported in Antigravity / Gemini CLI docs: installed extensions land under
# ``~/.gemini/extensions/<ext>/`` (this is shared with the Gemini CLI, not under
# the ``antigravity/`` subdir). Walk this tree the same way as other VSCode forks.


def test_antigravity_extension_mcp_discovers_mcp_json(tmp_path):
    """``~/.gemini/extensions/<ext>/mcp.json`` is walked and parsed."""
    from agent_scan.agents import AntigravityDiscoverer

    ext_dir = tmp_path / ".gemini" / "extensions" / "v.ag-ext-2.0.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text('{"mcpServers": {"ag-ext-srv": {"command": "a"}}}')
    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)

    mcp_configs = AntigravityDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if "/extensions/v.ag-ext-2.0.0/mcp.json" in k]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "ag-ext-srv"
    assert isinstance(server, StdioServer)


def test_antigravity_extension_skills_discovers_skills_dir(tmp_path):
    """An extension shipping ``skills/`` under ``~/.gemini/extensions/`` surfaces."""
    from agent_scan.agents import AntigravityDiscoverer

    ext_skill_dir = tmp_path / ".gemini" / "extensions" / "p.ag-1.0.0" / "skills" / "ag-ext-skill"
    ext_skill_dir.mkdir(parents=True)
    (ext_skill_dir / "SKILL.md").write_text("---\nname: ag-ext-skill\ndescription: t\n---\n\nbody\n")
    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)

    skills_dirs = AntigravityDiscoverer(tmp_path).discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/extensions/p.ag-1.0.0/skills")]
    assert len(matching) == 1


# --- VSCode: profile-specific MCP discovery ---
#
# VSCode profiles live at ``<userdata>/User/profiles/<id>/`` and each profile
# can have its own ``mcp.json``. A user with multiple profiles can be running
# wildly different MCP server sets per profile — we must scan all of them.


def test_vscode_discoverer_parses_profile_specific_mcp_json(tmp_path):
    """Each ``<userdata>/User/profiles/<id>/mcp.json`` is parsed and keyed by absolute path."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    profile_dir = _userdata(discoverer) / "User" / "profiles" / "work"
    profile_dir.mkdir(parents=True)
    (profile_dir / "mcp.json").write_text('{"servers": {"profile-srv": {"command": "p"}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/profiles/work/mcp.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "profile-srv"
    assert isinstance(server, StdioServer)


def test_vscode_discoverer_walks_multiple_profile_mcp_files(tmp_path):
    """Multiple profile dirs each surface their own mcp.json."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    profiles_root = _userdata(discoverer) / "User" / "profiles"
    for name in ("work", "personal"):
        d = profiles_root / name
        d.mkdir(parents=True)
        (d / "mcp.json").write_text(f'{{"servers": {{"{name}-srv": {{"command": "x"}}}}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    keys = [k for k in mcp_configs if "/profiles/" in k]
    assert len(keys) == 2


def test_vscode_discoverer_profile_settings_json_nested_mcp(tmp_path):
    """A profile's ``settings.json`` with nested ``mcp.servers`` is parsed (same shape as the default profile)."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    profile_dir = _userdata(discoverer) / "User" / "profiles" / "team"
    profile_dir.mkdir(parents=True)
    (profile_dir / "settings.json").write_text('{"mcp": {"servers": {"settings-srv": {"command": "s"}}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/profiles/team/settings.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    name, server = entries[0]
    assert name == "settings-srv"
    assert isinstance(server, StdioServer)


def test_vscode_discoverer_profile_editor_only_settings_json_not_a_parse_failure(tmp_path):
    """A named profile's editor-only ``settings.json`` (no ``mcp`` section) must
    produce no entry — neither a ``CouldNotParseMCPConfig`` parse failure nor
    coerced server entries.

    ``settings.json`` is multi-purpose, so most profiles carry only editor prefs.
    The profile walk must gate it the same way the default profile's settings.json
    is gated (:meth:`_discover_user_settings_mcp`); parsing it directly as MCP
    surfaces a spurious parse failure per profile on every scan.
    """
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    profile_dir = _userdata(discoverer) / "User" / "profiles" / "work"
    profile_dir.mkdir(parents=True)
    # Realistic editor-only profile settings — no `mcp` / `mcpServers` anywhere.
    (profile_dir / "settings.json").write_text(
        '{"editor.fontSize": 14, "telemetry.level": "off", "workbench.colorTheme": "Default Dark+"}'
    )

    mcp_configs = discoverer.discover_mcp_servers()

    settings_keys = [k for k in mcp_configs if k.endswith("/profiles/work/settings.json")]
    assert settings_keys == [], (
        f"editor-only profile settings.json must not appear in mcp_configs at all, "
        f"got entries: {[(k, mcp_configs[k]) for k in settings_keys]}"
    )


def test_vscode_discoverer_profile_walk_skips_when_no_profiles(tmp_path):
    """If the user has no named profiles, ``discover_mcp_servers`` doesn't emit any profile keys."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    user_dir = _userdata(discoverer) / "User"
    user_dir.mkdir(parents=True)

    mcp_configs = discoverer.discover_mcp_servers()

    assert not any("/profiles/" in k for k in mcp_configs)


# --- Kiro Powers: per-power mcp.json under ~/.kiro/powers/installed/ ---
#
# A Kiro Power bundles MCP + steering into one installable unit. The official
# kirodotdev/powers repo (e.g. databricks/POWER.md) documents installed powers
# living at ``~/.kiro/powers/installed/<name>/`` and shipping their own
# ``mcp.json``. Powers are user-global only — no project-scoped equivalent.
# (Kiro does NOT write a separate merged ``~/.kiro/powers.mcp.json``; on install
# it namespaces each Power's servers into a ``powers`` block inside
# ``~/.kiro/settings/mcp.json``.)


def test_kiro_powers_per_power_mcp_json_discovered(tmp_path):
    """Each ``~/.kiro/powers/installed/<name>/mcp.json`` is parsed and keyed by absolute path."""
    from agent_scan.agents import KiroDiscoverer

    power_dir = tmp_path / ".kiro" / "powers" / "installed" / "stripe"
    power_dir.mkdir(parents=True)
    (power_dir / "POWER.md").write_text("---\nname: stripe\ndescription: t\n---\n\nbody\n")
    (power_dir / "mcp.json").write_text('{"mcpServers": {"stripe-mcp": {"command": "s"}}}')

    mcp_configs = KiroDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/installed/stripe/mcp.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "stripe-mcp"
    assert isinstance(server, StdioServer)


def test_kiro_powers_walk_finds_multiple_installed_powers(tmp_path):
    """Multiple installed powers each surface their own mcp.json."""
    from agent_scan.agents import KiroDiscoverer

    installed = tmp_path / ".kiro" / "powers" / "installed"
    for name in ("stripe", "supabase"):
        d = installed / name
        d.mkdir(parents=True)
        (d / "mcp.json").write_text(f'{{"mcpServers": {{"{name}-srv": {{"command": "x"}}}}}}')

    mcp_configs = KiroDiscoverer(tmp_path).discover_mcp_servers()

    keys = [k for k in mcp_configs if "/powers/installed/" in k and k.endswith("/mcp.json")]
    assert len(keys) == 2


# --- Kiro: custom agents / subagents with inline mcpServers ---
#
# Kiro custom agents live one-file-per-agent under ``~/.kiro/agents/`` (global)
# and ``<workspace>/.kiro/agents/`` (workspace). The CLI agent format is JSON and
# may define MCP servers *inline* via an ``mcpServers`` block — documented as the
# highest-priority MCP source (kiro.dev/docs/cli/mcp/configuration/) — so a server
# can be declared here and nowhere else. Files are named ``<agent>.json`` (not
# ``mcp.json``), so the whole dir is scanned for ``*.json`` and gated on MCP shape.


def test_kiro_agent_config_inline_mcp_discovered(tmp_path):
    """A ``~/.kiro/agents/<agent>.json`` carrying an inline ``mcpServers`` block surfaces."""
    from agent_scan.agents import KiroDiscoverer

    agents_dir = tmp_path / ".kiro" / "agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "reviewer.json").write_text('{"mcpServers": {"agent-srv": {"command": "k"}}}')

    mcp_configs = KiroDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/.kiro/agents/reviewer.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "agent-srv"
    assert isinstance(server, StdioServer)


def test_kiro_agent_config_ignores_non_mcp_keys(tmp_path):
    """An agent file mixes MCP with non-MCP keys (``name``/``description``/``tools``)
    and per-server extras (``timeout``); only the ``mcpServers`` block is lifted and
    the unknown keys are ignored rather than failing validation."""
    from agent_scan.agents import KiroDiscoverer

    agents_dir = tmp_path / ".kiro" / "agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "code-reviewer.json").write_text(
        '{"name": "code-reviewer", "description": "Reviews code", '
        '"tools": ["@figma/*", "fsRead"], '
        '"mcpServers": {"figma": {"command": "figma-mcp", "args": ["--stdio"], "timeout": 120000}}}'
    )

    mcp_configs = KiroDiscoverer(tmp_path).discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/.kiro/agents/code-reviewer.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "figma"
    assert isinstance(server, StdioServer)
    assert server.command == "figma-mcp"


def test_kiro_agent_config_without_mcp_servers_skipped(tmp_path):
    """An agent file with no inline ``mcpServers`` (the common case — it only
    references servers defined elsewhere) is skipped: no entry for it, and it is
    NOT reported as a ``CouldNotParseMCPConfig`` parse failure."""
    from agent_scan.agents import KiroDiscoverer

    agents_dir = tmp_path / ".kiro" / "agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "plain.json").write_text('{"name": "plain", "tools": ["@figma/*"]}')

    mcp_configs = KiroDiscoverer(tmp_path).discover_mcp_servers()

    assert not [k for k in mcp_configs if k.endswith("/.kiro/agents/plain.json")]
    assert not any(isinstance(v, CouldNotParseMCPConfig) for v in mcp_configs.values())


def test_kiro_workspace_agent_config_inline_mcp_discovered(tmp_path):
    """A ``<workspace>/.kiro/agents/<agent>.json`` with inline ``mcpServers`` surfaces."""
    from agent_scan.agents import KiroDiscoverer

    (tmp_path / ".kiro").mkdir()
    discoverer = KiroDiscoverer(tmp_path)
    workspace = _setup_workspace(discoverer, tmp_path, "kproj")
    ws_agents = workspace / ".kiro" / "agents"
    ws_agents.mkdir(parents=True)
    (ws_agents / "ws-agent.json").write_text('{"mcpServers": {"ws-agent-srv": {"command": "k"}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/kproj/.kiro/agents/ws-agent.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "ws-agent-srv"
    assert isinstance(server, StdioServer)


def test_kiro_workspace_root_mcp_json_discovered(tmp_path):
    """SPECULATIVE (undocumented for Kiro): a workspace-root ``.mcp.json`` is read,
    mirroring the cross-tool project-root convention."""
    from agent_scan.agents import KiroDiscoverer

    (tmp_path / ".kiro").mkdir()
    discoverer = KiroDiscoverer(tmp_path)
    workspace = _setup_workspace(discoverer, tmp_path, "kproj")
    (workspace / ".mcp.json").write_text('{"mcpServers": {"root-srv": {"command": "k"}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/kproj/.mcp.json")]
    assert len(matching) == 1
    entries = mcp_configs[matching[0]]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "root-srv"
    assert isinstance(server, StdioServer)


# --- ClaudeCodeDiscoverer: NEW gaps (managed-mcp, commands, CLAUDE_CONFIG_DIR, plugin manifest) ---


def test_claude_code_discovers_managed_mcp_servers(tmp_path, monkeypatch):
    """Enterprise managed-mcp.json (a system absolute path) is parsed as a
    wrapped ``mcpServers`` config and surfaced."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    managed = tmp_path / "managed-mcp.json"
    managed.write_text('{"mcpServers": {"corp-server": {"command": "corp"}}}')

    discoverer = ClaudeCodeDiscoverer(tmp_path)
    monkeypatch.setattr(discoverer, "_managed_mcp_path", lambda: managed)

    mcp_configs = discoverer.discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/managed-mcp.json")]
    assert len(keys) == 1
    name, server = mcp_configs[keys[0]][0]
    assert name == "corp-server"
    assert isinstance(server, StdioServer)


def test_managed_mcp_path_honors_program_files_env_on_windows(tmp_path, monkeypatch):
    """On Windows the enterprise ``managed-mcp.json`` lives under ``Program Files``,
    but that root can sit on a non-C: drive or be relocated. ``_managed_mcp_path``
    must resolve it from the machine-level env var (``ProgramW6432`` is the 64-bit
    root even from a 32-bit process), not a hardcoded ``C:\\Program Files``.

    ``Program Files`` is machine-global, so honoring the scanning process's env is
    correct even under ``--scan-all-users`` (unlike the per-user ``CLAUDE_CONFIG_DIR``).
    """
    import agent_scan.agents.claude_code as discovery_module
    from agent_scan.agents.claude_code import ClaudeCodeDiscoverer

    monkeypatch.setattr(discovery_module.sys, "platform", "win32")
    custom_pf = tmp_path / "CustomDrive" / "Program Files"
    # Python normalizes os.environ keys to uppercase on Windows; use the
    # uppercase form so the lookup also matches on case-sensitive test hosts.
    monkeypatch.setenv("PROGRAMW6432", str(custom_pf))
    monkeypatch.delenv("PROGRAMFILES", raising=False)

    path = ClaudeCodeDiscoverer(tmp_path)._managed_mcp_path()

    assert path is not None
    assert path.name == "managed-mcp.json"
    assert path.parent.name == "ClaudeCode"
    # Resolved under the relocated Program Files root, not a hardcoded C: drive.
    assert path.parent.parent == custom_pf


def test_managed_mcp_path_falls_back_to_default_program_files_on_windows(tmp_path, monkeypatch):
    """With no ``Program Files`` env var, fall back to the conventional default
    rather than returning ``None`` (an enterprise default install still resolves)."""
    import agent_scan.agents.claude_code as discovery_module
    from agent_scan.agents.claude_code import ClaudeCodeDiscoverer

    monkeypatch.setattr(discovery_module.sys, "platform", "win32")
    monkeypatch.delenv("PROGRAMW6432", raising=False)
    monkeypatch.delenv("PROGRAMFILES", raising=False)

    path = ClaudeCodeDiscoverer(tmp_path)._managed_mcp_path()

    assert path is not None
    assert path.as_posix().endswith("ClaudeCode/managed-mcp.json")
    assert "Program Files" in path.as_posix()


def test_claude_code_discovers_global_command_files(tmp_path):
    """``~/.claude/commands/*.md`` are surfaced as skill entries."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    commands = tmp_path / ".claude" / "commands"
    commands.mkdir(parents=True)
    (commands / "deploy.md").write_text("# Deploy")

    skills = ClaudeCodeDiscoverer(tmp_path).discover_skills()

    keys = [k for k in skills if k.endswith("/.claude/commands")]
    assert len(keys) == 1
    names = {n for n, _ in skills[keys[0]]}
    assert names == {"deploy"}


def test_claude_code_discovers_project_command_files(tmp_path):
    """``<project>/.claude/commands/*.md`` are surfaced for opened projects."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    project = tmp_path / "repo"
    cmds = project / ".claude" / "commands"
    cmds.mkdir(parents=True)
    (cmds / "test.md").write_text("# Test")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text(f'{{"projects": {{"{project.as_posix()}": {{"mcpServers": {{}}}}}}}}')

    skills = ClaudeCodeDiscoverer(tmp_path).discover_skills()

    keys = [k for k in skills if k.endswith("/repo/.claude/commands")]
    assert len(keys) == 1
    assert {n for n, _ in skills[keys[0]]} == {"test"}


def test_claude_code_honors_claude_config_dir_on_own_home_scan(tmp_path, monkeypatch):
    """When CLAUDE_CONFIG_DIR is set and no explicit home is passed (own-home
    scan), MCP config is read from ``<CLAUDE_CONFIG_DIR>/.claude.json``."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    cfg = tmp_path / "custom-claude"
    cfg.mkdir()
    (cfg / ".claude.json").write_text('{"mcpServers": {"relocated": {"command": "r"}}}')
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))

    mcp_configs = ClaudeCodeDiscoverer(None).discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/custom-claude/.claude.json")]
    assert len(keys) == 1
    assert mcp_configs[keys[0]][0][0] == "relocated"


def test_claude_code_ignores_claude_config_dir_when_home_passed(tmp_path, monkeypatch):
    """Under multi-user scans (an explicit home is passed) the scanning
    process's CLAUDE_CONFIG_DIR must NOT relocate the target user's config."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    cfg = tmp_path / "process-env-dir"
    cfg.mkdir()
    (cfg / ".claude.json").write_text('{"mcpServers": {"should-not-appear": {"command": "x"}}}')
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))

    home = tmp_path / "alice"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude.json").write_text('{"mcpServers": {"alice-server": {"command": "a"}}}')

    mcp_configs = ClaudeCodeDiscoverer(home).discover_mcp_servers()

    all_names = {n for v in mcp_configs.values() if isinstance(v, list) for n, _ in v}
    assert "alice-server" in all_names
    assert "should-not-appear" not in all_names


def test_claude_code_honors_claude_config_dir_when_home_equals_real_home(tmp_path, monkeypatch):
    """CLAUDE_CONFIG_DIR must also be honored when the discoverer's home equals the
    scanning process's own home (``Path.home()``), not only when it is ``None``.

    Production never passes ``None``: ``get_readable_home_directories`` returns
    ``(Path.home(), user)`` for the current user, so the pipeline constructs the
    discoverer with ``Path.home()``. Gating purely on ``is None`` left the
    relocation dead in every real single-user scan — this exercises the actual
    wiring (an explicit home == ``Path.home()``).
    """
    from pathlib import Path

    from agent_scan.agents import ClaudeCodeDiscoverer

    home = tmp_path / "me"
    (home / ".claude").mkdir(parents=True)
    # Patch Path.home() so the own-home check matches and all home-relative reads
    # stay inside tmp (hermetic — no access to the developer's real ~/.claude).
    monkeypatch.setattr(Path, "home", lambda: home)

    cfg = tmp_path / "relocated-claude"
    cfg.mkdir()
    (cfg / ".claude.json").write_text('{"mcpServers": {"relocated": {"command": "r"}}}')
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))

    mcp_configs = ClaudeCodeDiscoverer(home).discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/relocated-claude/.claude.json")]
    assert len(keys) == 1, (
        f"CLAUDE_CONFIG_DIR relocation must activate on an own-home scan passed as Path.home(); "
        f"got keys: {list(mcp_configs)}"
    )
    assert mcp_configs[keys[0]][0][0] == "relocated"


def test_discoverer_normalizes_none_home_to_real_home(tmp_path, monkeypatch):
    """``home_directory=None`` (the own-home sentinel) is normalized to ``Path.home()``
    at construction, so the stored home is always a concrete path and no ``~``-prefixed
    template can leak unexpanded into ``expand_path``."""
    from pathlib import Path

    from agent_scan.agents import ClaudeCodeDiscoverer

    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    assert ClaudeCodeDiscoverer(None).home_directory == tmp_path


def test_claude_base_dir_resolves_own_home_when_config_dir_unset(tmp_path, monkeypatch):
    """Own-home scan (``home_directory=None``) with ``CLAUDE_CONFIG_DIR`` unset must
    resolve ``~/.claude`` against the real home, not return a literal, unexpanded
    ``~/.claude``.

    Regression for the None-sentinel mismatch between ``_scans_own_home`` (where
    ``None`` means own home → ``Path.home()``) and ``expand_path`` (where ``None``
    means "don't expand" → return the path verbatim, leaving the ``~`` literal).
    """
    from pathlib import Path

    from agent_scan.agents import ClaudeCodeDiscoverer

    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    base = ClaudeCodeDiscoverer(None)._claude_base_dir()

    assert base == tmp_path / ".claude"
    assert "~" not in base.as_posix()


def test_vscode_user_data_dirs_resolve_own_home_when_not_portable(tmp_path, monkeypatch):
    """The None-sentinel fix lives in the shared base ``__init__``, so the whole
    VSCode family inherits it: an own-home scan (``None``) with ``VSCODE_PORTABLE``
    unset resolves ``~``-prefixed user-data templates against the real home instead
    of leaving a literal ``~``."""
    from pathlib import Path

    from agent_scan.agents import VSCodeDiscoverer

    monkeypatch.delenv("VSCODE_PORTABLE", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    dirs = VSCodeDiscoverer(None)._user_data_dirs()

    assert dirs, "expected at least one user-data dir on a supported platform"
    assert all(str(d).startswith(str(tmp_path)) for d in dirs)
    assert all("~" not in d.as_posix() for d in dirs)


def test_claude_code_discovers_inline_plugin_manifest_mcp_servers(tmp_path):
    """A plugin's ``.claude-plugin/plugin.json`` with an inline ``mcpServers``
    map is surfaced from the plugin walk."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    plugin = tmp_path / ".claude" / "plugins" / "cache" / "my-plugin"
    manifest_dir = plugin / ".claude-plugin"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "plugin.json").write_text('{"name": "my-plugin", "mcpServers": {"plugin-srv": {"command": "p"}}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/.claude-plugin/plugin.json")]
    assert len(keys) == 1
    assert mcp_configs[keys[0]][0][0] == "plugin-srv"


def test_claude_code_discovers_inline_plugin_manifest_skills(tmp_path):
    """A plugin manifest's ``skills`` list points at plugin-root-relative skill
    dirs, which are scanned for SKILL.md skills."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    plugin = tmp_path / ".claude" / "plugins" / "cache" / "my-plugin"
    manifest_dir = plugin / ".claude-plugin"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "plugin.json").write_text('{"name": "my-plugin", "skills": ["custom-skills"]}')
    _write_skill(plugin / "custom-skills", "special")

    skills = ClaudeCodeDiscoverer(tmp_path).discover_skills()

    keys = [k for k in skills if k.endswith("/my-plugin/custom-skills")]
    assert len(keys) == 1
    assert {n for n, _ in skills[keys[0]]} == {"special"}


# --- VSCode family: NEW gaps (agentSkillsLocations, devcontainer, .code-workspace,
#     Insiders, portable mode) ---


def test_vscode_agent_skills_locations_dotted_key_absolute_path(tmp_path):
    """``chat.agentSkillsLocations`` in User/settings.json (dotted form) points at
    an absolute custom skills dir that is scanned."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    custom = tmp_path / "my-custom-skills"
    _write_skill(custom, "custom-skill")
    settings = _userdata(discoverer) / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(f'{{"chat.agentSkillsLocations": ["{custom.as_posix()}"]}}')

    skills_dirs = discoverer.discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/my-custom-skills")]
    assert len(keys) == 1
    assert {n for n, _ in skills_dirs[keys[0]]} == {"custom-skill"}


def test_vscode_agent_skills_locations_nested_key(tmp_path):
    """Nested ``chat: {agentSkillsLocations: [...]}`` form is also honored."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    custom = tmp_path / "nested-skills"
    _write_skill(custom, "nested-skill")
    settings = _userdata(discoverer) / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(f'{{"chat": {{"agentSkillsLocations": ["{custom.as_posix()}"]}}}}')

    skills_dirs = discoverer.discover_skills()

    assert any(k.endswith("/nested-skills") for k in skills_dirs)


def test_vscode_agent_skills_locations_workspace_relative(tmp_path):
    """A relative ``chat.agentSkillsLocations`` entry in a workspace
    ``.vscode/settings.json`` resolves against the workspace root."""
    discoverer, workspace = _setup_vscode_workspace(tmp_path, "proj")
    _write_skill(workspace / "team-skills", "team-skill")
    vscode_settings = workspace / ".vscode" / "settings.json"
    vscode_settings.parent.mkdir(parents=True, exist_ok=True)
    vscode_settings.write_text('{"chat.agentSkillsLocations": ["team-skills"]}')

    skills_dirs = discoverer.discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/proj/team-skills")]
    assert len(keys) == 1
    assert {n for n, _ in skills_dirs[keys[0]]} == {"team-skill"}


def test_vscode_agent_skills_locations_object_form_enabled(tmp_path):
    """VS Code registers ``chat.agentSkillsLocations`` as an *object* mapping
    each path to a boolean (``{path: true}``); the array form is a defensive
    extra. A path with value ``true`` must be scanned."""
    import json

    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    custom = tmp_path / "object-skills"
    _write_skill(custom, "object-skill")
    settings = _userdata(discoverer) / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"chat.agentSkillsLocations": {custom.as_posix(): True}}))

    skills_dirs = discoverer.discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/object-skills")]
    assert len(keys) == 1, f"object-form agentSkillsLocations must be honored; got: {list(skills_dirs)}"
    assert {n for n, _ in skills_dirs[keys[0]]} == {"object-skill"}


def test_vscode_agent_skills_locations_object_form_false_excluded(tmp_path):
    """A path mapped to ``false`` in the object form must NOT be scanned."""
    import json

    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    custom = tmp_path / "disabled-skills"
    _write_skill(custom, "disabled-skill")
    settings = _userdata(discoverer) / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"chat.agentSkillsLocations": {custom.as_posix(): False}}))

    skills_dirs = discoverer.discover_skills()

    assert not any(k.endswith("/disabled-skills") for k in skills_dirs), "a location mapped to false must be excluded"


def test_vscode_discovers_devcontainer_mcp(tmp_path):
    """``.devcontainer/devcontainer.json`` with
    ``customizations.vscode.mcp.servers`` is surfaced."""
    discoverer, workspace = _setup_vscode_workspace(tmp_path, "proj")
    devc = workspace / ".devcontainer"
    devc.mkdir()
    (devc / "devcontainer.json").write_text(
        '{"customizations": {"vscode": {"mcp": {"servers": {"dc-srv": {"command": "d"}}}}}}'
    )

    mcp_configs = discoverer.discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/proj/.devcontainer/devcontainer.json")]
    assert len(keys) == 1
    assert mcp_configs[keys[0]][0][0] == "dc-srv"


def test_vscode_devcontainer_without_mcp_yields_no_entry(tmp_path):
    """A devcontainer.json without the nested mcp path produces no entry and no
    parse error."""
    discoverer, workspace = _setup_vscode_workspace(tmp_path, "proj")
    devc = workspace / ".devcontainer"
    devc.mkdir()
    (devc / "devcontainer.json").write_text('{"image": "ubuntu", "customizations": {"vscode": {}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    assert not any("devcontainer.json" in k for k in mcp_configs)


def test_vscode_discovers_code_workspace_mcp(tmp_path):
    """A ``.code-workspace`` referenced from workspaceStorage's ``workspace``
    pointer has its ``settings.mcp.servers`` surfaced."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    ws_file = tmp_path / "team.code-workspace"
    ws_file.write_text('{"folders": [{"path": "."}], "settings": {"mcp": {"servers": {"cw-srv": {"command": "c"}}}}}')
    storage = _userdata(discoverer) / "User" / "workspaceStorage" / "h1"
    storage.mkdir(parents=True)
    (storage / "workspace.json").write_text(f'{{"workspace": "{ws_file.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/team.code-workspace")]
    assert len(keys) == 1
    assert mcp_configs[keys[0]][0][0] == "cw-srv"


def test_vscode_discovers_code_workspace_dotted_mcp_servers(tmp_path):
    """``.code-workspace`` settings using the flattened ``mcp.servers`` key also work."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    ws_file = tmp_path / "dotted.code-workspace"
    ws_file.write_text('{"settings": {"mcp.servers": {"dotted-srv": {"command": "x"}}}}')
    storage = _userdata(discoverer) / "User" / "workspaceStorage" / "h2"
    storage.mkdir(parents=True)
    (storage / "workspace.json").write_text(f'{{"workspace": "{ws_file.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    assert any(k.endswith("/dotted.code-workspace") for k in mcp_configs)


def test_vscode_discovers_code_workspace_skill_locations(tmp_path):
    """``chat.agentSkillsLocations`` inside a ``.code-workspace`` settings block,
    relative to the workspace file, is scanned."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    _write_skill(tmp_path / "ws-skills", "cw-skill")
    ws_file = tmp_path / "team.code-workspace"
    ws_file.write_text('{"settings": {"chat.agentSkillsLocations": ["ws-skills"]}}')
    storage = _userdata(discoverer) / "User" / "workspaceStorage" / "h3"
    storage.mkdir(parents=True)
    (storage / "workspace.json").write_text(f'{{"workspace": "{ws_file.as_uri()}"}}')

    skills_dirs = discoverer.discover_skills()

    assert any(k.endswith("/ws-skills") for k in skills_dirs)


def test_vscode_discovers_multi_root_code_workspace_folder_mcp(tmp_path):
    """A multi-root ``.code-workspace`` lists its roots in ``folders[].path``
    (relative to the workspace file, incl. ``../``). Each such root must be scanned
    for its own ``.vscode/mcp.json`` — not just the file's inline ``settings`` block.

    Without expanding ``folders[]`` the workspace.json carries only ``workspace``
    (not ``folder``), so these per-folder configs would slip past discovery entirely.
    """
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()

    # Workspace file lives in monorepo/; one root is a sibling subdir, the other a
    # ``../``-relative dir that normalizes to tmp_path/shared-lib.
    ws_dir = tmp_path / "monorepo"
    ws_dir.mkdir()
    fe = ws_dir / "frontend"
    (fe / ".vscode").mkdir(parents=True)
    (fe / ".vscode" / "mcp.json").write_text('{"servers": {"fe-srv": {"command": "f"}}}')
    shared = tmp_path / "shared-lib"
    (shared / ".vscode").mkdir(parents=True)
    (shared / ".vscode" / "mcp.json").write_text('{"servers": {"shared-srv": {"command": "s"}}}')

    ws_file = ws_dir / "team.code-workspace"
    # No inline settings.mcp — the only servers come from the folder roots.
    ws_file.write_text('{"folders": [{"path": "frontend"}, {"path": "../shared-lib"}]}')
    storage = _userdata(discoverer) / "User" / "workspaceStorage" / "h-multi"
    storage.mkdir(parents=True)
    (storage / "workspace.json").write_text(f'{{"workspace": "{ws_file.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    assert any(k.endswith("/frontend/.vscode/mcp.json") for k in mcp_configs), (
        f"relative folders[].path root not scanned; keys: {list(mcp_configs)}"
    )
    assert any(k.endswith("/shared-lib/.vscode/mcp.json") for k in mcp_configs), (
        f"../-relative folders[].path root not scanned; keys: {list(mcp_configs)}"
    )


def test_vscode_discovers_multi_root_code_workspace_folder_uri(tmp_path):
    """A ``folders[]`` entry may use an explicit ``uri`` (``file://``) instead of a
    relative ``path``; that root is resolved and scanned the same way."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()

    svc = tmp_path / "service"
    (svc / ".vscode").mkdir(parents=True)
    (svc / ".vscode" / "mcp.json").write_text('{"servers": {"svc-srv": {"command": "v"}}}')

    ws_file = tmp_path / "byuri.code-workspace"
    ws_file.write_text(f'{{"folders": [{{"uri": "{svc.as_uri()}"}}]}}')
    storage = _userdata(discoverer) / "User" / "workspaceStorage" / "h-uri"
    storage.mkdir(parents=True)
    (storage / "workspace.json").write_text(f'{{"workspace": "{ws_file.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    assert any(k.endswith("/service/.vscode/mcp.json") for k in mcp_configs), (
        f"folders[].uri root not scanned; keys: {list(mcp_configs)}"
    )


def test_vscode_discovers_multi_root_code_workspace_folder_skills(tmp_path):
    """Per-folder workspace skills (``<root>/.github/skills``) are discovered for
    a multi-root ``.code-workspace`` root, mirroring the single-root folder path."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()

    fe = tmp_path / "ws" / "frontend"
    _write_skill(fe / ".github" / "skills", "fe-skill")

    ws_file = tmp_path / "ws" / "team.code-workspace"
    ws_file.write_text('{"folders": [{"path": "frontend"}]}')
    storage = _userdata(discoverer) / "User" / "workspaceStorage" / "h-skills"
    storage.mkdir(parents=True)
    (storage / "workspace.json").write_text(f'{{"workspace": "{ws_file.as_uri()}"}}')

    skills_dirs = discoverer.discover_skills()

    assert any(k.endswith("/frontend/.github/skills") for k in skills_dirs), (
        f"per-folder workspace skills not discovered; keys: {list(skills_dirs)}"
    )


def test_vscode_discovers_insiders_userdata_mcp(tmp_path):
    """MCP under the Insiders userdata (``Code - Insiders``) is surfaced."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    insiders = [d for d in discoverer._user_data_dirs() if d.as_posix().endswith("Code - Insiders")]
    assert insiders, "VSCode discoverer must include a 'Code - Insiders' userdata dir"
    mcp = insiders[0] / "User" / "mcp.json"
    mcp.parent.mkdir(parents=True)
    mcp.write_text('{"servers": {"insiders-srv": {"command": "i"}}}')

    mcp_configs = discoverer.discover_mcp_servers()

    assert any(k.endswith("Code - Insiders/User/mcp.json") for k in mcp_configs)


def test_vscode_honors_vscode_portable_on_own_home_scan(tmp_path, monkeypatch):
    """VSCODE_PORTABLE relocates userdata to ``<portable>/user-data`` on own-home scans."""
    from agent_scan.agents import VSCodeDiscoverer

    portable = tmp_path / "VSCode-portable"
    monkeypatch.setenv("VSCODE_PORTABLE", str(portable))
    mcp = portable / "user-data" / "User" / "mcp.json"
    mcp.parent.mkdir(parents=True)
    mcp.write_text('{"servers": {"portable-srv": {"command": "p"}}}')

    mcp_configs = VSCodeDiscoverer(None).discover_mcp_servers()

    assert any(k.endswith("/user-data/User/mcp.json") for k in mcp_configs)


def test_vscode_honors_vscode_portable_when_home_equals_real_home(tmp_path, monkeypatch):
    """VSCODE_PORTABLE must also activate when the discoverer's home equals the
    scanning process's own home (``Path.home()``), not only when it is ``None``.

    The pipeline constructs the current-user discoverer with ``Path.home()`` (never
    ``None``), so gating portable mode purely on ``is None`` left it dead in real
    single-user scans. This exercises the production wiring.
    """
    from pathlib import Path

    from agent_scan.agents import VSCodeDiscoverer

    home = tmp_path / "me"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)

    portable = tmp_path / "VSCode-portable"
    monkeypatch.setenv("VSCODE_PORTABLE", str(portable))
    mcp = portable / "user-data" / "User" / "mcp.json"
    mcp.parent.mkdir(parents=True)
    mcp.write_text('{"servers": {"portable-srv": {"command": "p"}}}')

    mcp_configs = VSCodeDiscoverer(home).discover_mcp_servers()

    assert any(k.endswith("/user-data/User/mcp.json") for k in mcp_configs), (
        f"VSCODE_PORTABLE must activate on an own-home scan passed as Path.home(); got keys: {list(mcp_configs)}"
    )


def test_vscode_ignores_vscode_portable_under_multiuser_scan(tmp_path, monkeypatch):
    """Under a multi-user scan (an explicit *other*-user home is passed), the
    scanning process's ``VSCODE_PORTABLE`` must NOT relocate the target user's
    userdata or extensions — the env var reflects the scanner's environment, not
    the scanned user's. Mirrors ``test_claude_code_ignores_plugin_env_dirs_under_multiuser_scan``;
    pins the ``_scans_own_home()`` gate on the portable path so a future refactor
    can't silently leak the scanner's portable tree into another user's scan.
    """
    from pathlib import Path

    from agent_scan.agents import VSCodeDiscoverer

    # The scanning process's own home is someone else's, so _scans_own_home() is
    # False for the alice discoverer below regardless of the host environment.
    own_home = tmp_path / "scanner_home"
    own_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: own_home)

    portable = tmp_path / "VSCode-portable"
    monkeypatch.setenv("VSCODE_PORTABLE", str(portable))
    # Both portable surfaces an own-home scan WOULD pick up: relocated userdata
    # mcp.json and a relocated extension's mcp.json.
    user_mcp = portable / "user-data" / "User" / "mcp.json"
    user_mcp.parent.mkdir(parents=True)
    user_mcp.write_text('{"servers": {"portable-srv": {"command": "p"}}}')
    ext_mcp = portable / "extensions" / "vendor.ext-1.0.0" / "mcp.json"
    ext_mcp.parent.mkdir(parents=True)
    ext_mcp.write_text('{"mcpServers": {"portable-ext-srv": {"command": "e"}}}')

    alice = tmp_path / "alice"
    (alice / ".vscode").mkdir(parents=True)
    discoverer = VSCodeDiscoverer(alice)
    assert not discoverer._scans_own_home()

    mcp_configs = discoverer.discover_mcp_servers()

    assert not any("/VSCode-portable/" in k for k in mcp_configs), (
        f"VSCODE_PORTABLE must not leak into another user's scan; got keys: {list(mcp_configs)}"
    )
    names = {n for v in mcp_configs.values() if isinstance(v, list) for n, _ in v}
    assert "portable-srv" not in names
    assert "portable-ext-srv" not in names


# --- Windsurf + Antigravity: NEW gaps ---


def test_windsurf_discovers_system_skills_dir(tmp_path, monkeypatch):
    """Windsurf reads machine-wide skills from a per-OS system path."""
    from agent_scan.agents import WindsurfDiscoverer

    (tmp_path / ".codeium" / "windsurf").mkdir(parents=True)
    system = tmp_path / "system-windsurf-skills"
    _write_skill(system, "system-skill")

    discoverer = WindsurfDiscoverer(tmp_path)
    monkeypatch.setattr(discoverer, "_platform_system_skills_dirs", lambda: [system])

    skills_dirs = discoverer.discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/system-windsurf-skills")]
    assert len(keys) == 1
    assert {n for n, _ in skills_dirs[keys[0]]} == {"system-skill"}


@pytest.mark.skipif(
    sys.platform not in ("darwin", "linux", "linux2", "win32"),
    reason="system skills path only defined for macOS/Linux/Windows",
)
def test_windsurf_system_skills_path_is_platform_specific():
    """The configured system skills path matches the documented per-OS location."""
    from agent_scan.agents import WindsurfDiscoverer

    dirs = WindsurfDiscoverer(None)._platform_system_skills_dirs()

    assert len(dirs) == 1
    p = dirs[0].as_posix()
    if sys.platform == "darwin":
        assert p == "/Library/Application Support/Windsurf/skills"
    elif sys.platform in ("linux", "linux2"):
        assert p == "/etc/windsurf/skills"
    elif sys.platform == "win32":
        assert p.endswith("ProgramData/Windsurf/skills")


def test_antigravity_discovers_gemini_settings_mcp(tmp_path):
    """Antigravity reads MCP from the shared ``~/.gemini/settings.json``."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    settings = tmp_path / ".gemini" / "settings.json"
    settings.write_text('{"mcpServers": {"gemini-srv": {"command": "g"}}}')

    mcp_configs = AntigravityDiscoverer(tmp_path).discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/.gemini/settings.json")]
    assert len(keys) == 1
    assert mcp_configs[keys[0]][0][0] == "gemini-srv"


def test_antigravity_gemini_settings_without_mcp_is_not_a_parse_error(tmp_path):
    """An editor-only ``~/.gemini/settings.json`` produces no entry, not a parse error."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    settings = tmp_path / ".gemini" / "settings.json"
    settings.write_text('{"theme": "dark", "telemetry": {"enabled": false}}')

    mcp_configs = AntigravityDiscoverer(tmp_path).discover_mcp_servers()

    assert not any(k.endswith("/.gemini/settings.json") for k in mcp_configs)


def test_antigravity_discovers_plural_agents_workspace_skills(tmp_path):
    """Antigravity reads workspace skills from the plural ``.agents/skills`` path."""
    from agent_scan.agents import AntigravityDiscoverer

    discoverer = AntigravityDiscoverer(tmp_path)
    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    workspace = tmp_path / "proj"
    workspace.mkdir()
    _write_skill(workspace / ".agents" / "skills", "plural-skill")
    storage = discoverer._user_data_dir() / "User" / "workspaceStorage" / "h"
    storage.mkdir(parents=True)
    (storage / "workspace.json").write_text(f'{{"folder": "{workspace.as_uri()}"}}')

    skills_dirs = discoverer.discover_skills()

    assert any(k.endswith("/proj/.agents/skills") for k in skills_dirs)


def test_antigravity_discovers_singular_agent_home_skills(tmp_path):
    """Antigravity reads user-global skills from the singular ``~/.agent/skills`` path."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    _write_skill(tmp_path / ".agent" / "skills", "home-skill")

    skills_dirs = AntigravityDiscoverer(tmp_path).discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/.agent/skills")]
    assert len(keys) == 1
    assert {n for n, _ in skills_dirs[keys[0]]} == {"home-skill"}


def test_antigravity_discovers_plural_agents_home_skills(tmp_path):
    """Antigravity 2.0's default global skills dir / npx install target is the
    PLURAL ``~/.agents/skills`` (the singular ``~/.agent/skills`` is the legacy
    back-compat path). The plural must be discovered at the user/home level."""
    from agent_scan.agents import AntigravityDiscoverer

    (tmp_path / ".gemini" / "antigravity").mkdir(parents=True)
    _write_skill(tmp_path / ".agents" / "skills", "plural-home-skill")

    skills_dirs = AntigravityDiscoverer(tmp_path).discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/.agents/skills")]
    assert len(keys) == 1, f"plural ~/.agents/skills must be scanned; got: {list(skills_dirs)}"
    assert {n for n, _ in skills_dirs[keys[0]]} == {"plural-home-skill"}


def test_vscode_devcontainer_non_dict_intermediate_does_not_crash(tmp_path):
    """A devcontainer.json whose ``customizations.vscode`` is a non-dict must not
    raise (which would abort the whole discoverer) — it yields no entry."""
    discoverer, workspace = _setup_vscode_workspace(tmp_path, "proj")
    devc = workspace / ".devcontainer"
    devc.mkdir()
    (devc / "devcontainer.json").write_text('{"customizations": {"vscode": "oops"}}')

    mcp_configs = discoverer.discover_mcp_servers()  # must not raise

    assert not any("devcontainer.json" in k for k in mcp_configs)


# ---------------------------------------------------------------------------
# Built-in (bundled) extension discovery
#
# VS Code-family editors ship "built-in" extensions INSIDE the application
# install (``<app>/…/resources/app/extensions``), not under the user
# ``~/.../extensions`` tree. These can contribute ``skills/`` and ``mcp.json``
# (e.g. VS Code now bundles Copilot Chat, whose skills regressed out of scans
# when the extension moved from user-installed to built-in). The family base
# exposes ``_builtin_extension_dir_templates`` (per-OS) → ``_builtin_extension_dirs()``,
# wired through ``_extension_base_dirs()`` so both the skills and MCP extension
# walks cover them.
# ---------------------------------------------------------------------------


def test_vscode_builtin_extension_skills_discovered(tmp_path, monkeypatch):
    """Skills shipped by a built-in (bundled) extension are surfaced by
    ``discover_skills`` — the layout that regressed when Copilot Chat became a
    built-in (skills at ``…/extensions/<ext>/assets/prompts/skills``)."""
    from agent_scan.agents import VSCodeDiscoverer

    builtin_extensions = tmp_path / "app" / "extensions"
    skill_dir = builtin_extensions / "github.copilot-chat" / "assets" / "prompts" / "skills" / "create-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: create-skill\ndescription: t\n---\n\nbody\n")
    (tmp_path / ".vscode").mkdir()

    discoverer = VSCodeDiscoverer(tmp_path)
    monkeypatch.setattr(discoverer, "_builtin_extension_dirs", lambda: [builtin_extensions])

    skills_dirs = discoverer.discover_skills()

    matching = [k for k in skills_dirs if k.endswith("/github.copilot-chat/assets/prompts/skills")]
    assert len(matching) == 1, f"built-in extension skills must surface; got: {list(skills_dirs)}"
    name, skill = skills_dirs[matching[0]][0]
    assert name == "create-skill"
    assert isinstance(skill, SkillServer)


def test_vscode_builtin_extension_mcp_discovered(tmp_path, monkeypatch):
    """A built-in (bundled) extension shipping ``mcp.json`` is parsed by
    ``discover_mcp_servers`` (the same walk as user extensions)."""
    from agent_scan.agents import VSCodeDiscoverer

    builtin_extensions = tmp_path / "app" / "extensions"
    ext_dir = builtin_extensions / "vendor.builtin-1.0.0"
    ext_dir.mkdir(parents=True)
    (ext_dir / "mcp.json").write_text('{"mcpServers": {"builtin-srv": {"command": "c"}}}')
    (tmp_path / ".vscode").mkdir()

    discoverer = VSCodeDiscoverer(tmp_path)
    monkeypatch.setattr(discoverer, "_builtin_extension_dirs", lambda: [builtin_extensions])

    mcp_configs = discoverer.discover_mcp_servers()

    matching = [k for k in mcp_configs if k.endswith("/vendor.builtin-1.0.0/mcp.json")]
    assert len(matching) == 1, f"built-in extension mcp.json must surface; got: {list(mcp_configs)}"
    name, _ = mcp_configs[matching[0]][0]
    assert name == "builtin-srv"


def test_builtin_extension_dir_templates_default_empty():
    """The family base declares no built-in templates; each fork opts in. This
    guards against a newly-added fork silently inheriting another fork's paths."""
    from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer

    assert VSCodeFamilyDiscoverer._builtin_extension_dir_templates == {}


def test_builtin_extension_dirs_empty_on_unsupported_platform(tmp_path, monkeypatch):
    """An unrecognized platform yields no built-in dirs (documented coverage gap)."""
    import agent_scan.agents.vscode.base as base
    from agent_scan.agents import VSCodeDiscoverer

    monkeypatch.setattr(base.sys, "platform", "sunos5")

    assert VSCodeDiscoverer(tmp_path)._builtin_extension_dirs() == []


@pytest.mark.skipif(sys.platform != "darwin", reason="verified .app paths are macOS-specific")
@pytest.mark.parametrize(
    "discoverer_name, app_name",
    [
        ("VSCodeDiscoverer", "Visual Studio Code.app"),
        ("CursorDiscoverer", "Cursor.app"),
        ("WindsurfDiscoverer", "Windsurf.app"),
    ],
)
def test_builtin_extension_dirs_macos_verified_app_paths(tmp_path, discoverer_name, app_name):
    """On macOS the ``/Applications/<app>.app/Contents/Resources/app/extensions``
    paths for VS Code, Cursor and Windsurf are verified on disk (not inferred)."""
    import agent_scan.agents as agents

    discoverer = getattr(agents, discoverer_name)(tmp_path)
    dirs = [p.as_posix() for p in discoverer._builtin_extension_dirs()]

    expected = f"/Applications/{app_name}/Contents/Resources/app/extensions"
    assert any(d == expected for d in dirs), f"{discoverer_name} must scan {expected}; got: {dirs}"


@pytest.mark.parametrize("linux_platform", ["linux", "linux2"])
def test_windsurf_builtin_extension_no_linux_path(tmp_path, monkeypatch, linux_platform):
    """Windsurf ships on Linux only as a tarball with no fixed install root, so
    built-in discovery is intentionally a documented gap there (not a guess)."""
    import agent_scan.agents.vscode.base as base
    from agent_scan.agents import WindsurfDiscoverer

    monkeypatch.setattr(base.sys, "platform", linux_platform)

    assert WindsurfDiscoverer(tmp_path)._builtin_extension_dirs() == []


@pytest.mark.skipif(
    sys.platform not in ("darwin", "linux", "linux2", "win32"),
    reason="built-in paths only defined for macOS/Linux/Windows",
)
def test_vscode_builtin_extension_dirs_per_platform(tmp_path):
    """VS Code's built-in extensions dir resolves to the documented per-OS
    install root (macOS .app verified; Windows documented; Linux deb/rpm)."""
    from agent_scan.agents import VSCodeDiscoverer

    dirs = [p.as_posix() for p in VSCodeDiscoverer(tmp_path)._builtin_extension_dirs()]

    if sys.platform == "darwin":
        assert any(d.endswith("/Applications/Visual Studio Code.app/Contents/Resources/app/extensions") for d in dirs)
    elif sys.platform in ("linux", "linux2"):
        assert any("/usr/share/code/resources/app/extensions" in d for d in dirs)
    elif sys.platform == "win32":
        assert any(d.endswith("Microsoft VS Code/resources/app/extensions") for d in dirs)


# --- _walk_under_depth: PermissionError tolerance (--scan-all-users) ---
# Every depth-bounded directory walk goes through ``_walk_under_depth``, which
# skips an unreadable base (the routine ``--scan-all-users`` case where an
# unprivileged scan hits another user's home, making ``Path.exists()`` re-raise
# ``PermissionError`` on Python 3.12+) rather than propagating out of
# ``discover()`` — which the pipeline would catch and use to drop the *whole*
# discoverer, losing every already-collected reachable source. Mirrors the
# precedent test ``..._workspace_storage_unreadable_does_not_abort_discovery``.


def test_walk_under_depth_skips_unreadable_base_permission_error(tmp_path, monkeypatch, caplog):
    """An ``exists()`` probe that raises ``PermissionError`` yields nothing and warns,
    rather than propagating."""
    from pathlib import Path

    from agent_scan.agents.base import _walk_under_depth

    denied = tmp_path / "denied"
    denied.mkdir()
    real_exists = Path.exists

    def fake_exists(self, *args, **kwargs):
        if self == denied:
            raise PermissionError(13, "Permission denied", str(self))
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)

    with caplog.at_level("WARNING"):
        hits = list(_walk_under_depth(denied, "mcp.json", 5, want_file=True))

    assert hits == []
    assert "Permission error walking" in caplog.text


def test_walk_under_depth_skips_unreadable_base_os_error(tmp_path, monkeypatch):
    """A generic ``OSError`` from the walk is tolerated the same way."""
    from pathlib import Path

    from agent_scan.agents.base import _walk_under_depth

    denied = tmp_path / "denied"
    denied.mkdir()
    real_exists = Path.exists

    def fake_exists(self, *args, **kwargs):
        if self == denied:
            raise OSError(5, "I/O error", str(self))
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)

    assert list(_walk_under_depth(denied, "mcp.json", 5, want_file=True)) == []


def test_walk_under_depth_yields_hits_for_readable_tree(tmp_path):
    """A readable tree yields its matching paths (the guard is transparent)."""
    from agent_scan.agents.base import _walk_under_depth

    target = tmp_path / "ext" / "nested"
    target.mkdir(parents=True)
    (target / "mcp.json").write_text("{}")

    hits = list(_walk_under_depth(tmp_path, "mcp.json", 10, want_file=True))

    assert [h.name for h in hits] == ["mcp.json"]
    assert hits[0] == target / "mcp.json"


def test_vscode_extension_walks_unreadable_do_not_abort_discovery(tmp_path, monkeypatch):
    """An unreadable ``~/.vscode/extensions`` base (shared by the extension-MCP and
    extension-skills walks) must degrade gracefully, not abort the whole discoverer.

    Pre-fix the unguarded ``base.exists()`` raised ``PermissionError`` out of
    ``discover_mcp_servers()`` / ``discover_skills()`` and the pipeline dropped the
    entire discoverer, losing the reachable user-scope ``~/.vscode/mcp.json``.
    """
    from pathlib import Path

    from agent_scan.agents import VSCodeDiscoverer

    # Built-in (bundled) extension dirs neutralized so the assertion stays hermetic
    # on machines where VS Code is actually installed.
    monkeypatch.setattr(VSCodeDiscoverer, "_builtin_extension_dirs", lambda self: [])

    # A reachable user-scope MCP outside the extensions subtree — must survive.
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text('{"servers": {"user-srv": {"command": "u"}}}')

    ext_base = tmp_path / ".vscode" / "extensions"
    ext_base.mkdir()
    real_exists = Path.exists

    def fake_exists(self, *args, **kwargs):
        # Only the extensions base probe is denied (parent not traversable).
        if self == ext_base:
            raise PermissionError(13, "Permission denied", str(self))
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)

    discoverer = VSCodeDiscoverer(tmp_path)
    # Both top-level scans must complete without raising.
    mcp_configs = discoverer.discover_mcp_servers()
    skills_dirs = discoverer.discover_skills()

    user_keys = [k for k in mcp_configs if k.endswith("/.vscode/mcp.json")]
    assert len(user_keys) == 1, f"user-scope ~/.vscode/mcp.json must survive; got {list(mcp_configs)}"
    name, _server = mcp_configs[user_keys[0]][0]
    assert name == "user-srv"
    assert not any("/extensions/" in k for k in mcp_configs)
    assert not any("/extensions/" in k for k in skills_dirs)


def test_claude_code_plugin_walks_unreadable_do_not_abort_discovery(tmp_path, monkeypatch):
    """An unreadable plugin base (walked by both ``_discover_plugin_mcp_servers`` and
    ``_plugin_manifests``) must not abort ``discover_mcp_servers()``; the reachable
    user-scope ``~/.claude.json`` MCP still surfaces."""
    from pathlib import Path

    from agent_scan.agents import ClaudeCodeDiscoverer

    (tmp_path / ".claude.json").write_text('{"mcpServers": {"my-server": {"command": "echo", "args": ["hi"]}}}')

    denied_plugin_base = tmp_path / ".claude" / "plugins" / "cache"
    monkeypatch.setattr(ClaudeCodeDiscoverer, "_plugin_base_dirs", lambda self: [denied_plugin_base])
    real_exists = Path.exists

    def fake_exists(self, *args, **kwargs):
        if self == denied_plugin_base:
            raise PermissionError(13, "Permission denied", str(self))
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    user_keys = [k for k in mcp_configs if k.endswith("/.claude.json")]
    assert len(user_keys) == 1, f"user-scope ~/.claude.json must survive; got {list(mcp_configs)}"
    name, _server = mcp_configs[user_keys[0]][0]
    assert name == "my-server"


# =====================================================================================
# Low / test-gap / nit follow-ups (PR #337 review)
# =====================================================================================


# --- #11: Claude Code skill scans tolerate a non-dir / unreadable path ---


def test_claude_code_global_skills_path_that_is_a_file_is_skipped(tmp_path):
    """If ``~/.claude/skills`` is a regular file (not a directory), discovery skips
    it instead of crashing — routed through ``_scan_skills_dir``'s is-dir guard."""
    from agent_scan.agents import ClaudeCodeDiscoverer

    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "skills").write_text("i am a file, not a directory")

    skills = ClaudeCodeDiscoverer(tmp_path).discover_skills()

    assert not any(k.endswith("/.claude/skills") for k in skills)


def test_claude_code_project_skills_path_that_is_a_file_is_skipped(tmp_path):
    """A project ``.claude/skills`` that is a file is skipped, not fatal."""
    import json

    from agent_scan.agents import ClaudeCodeDiscoverer

    project = tmp_path / "proj"
    project.mkdir()
    dotclaude = project / ".claude"
    dotclaude.mkdir()
    (dotclaude / "skills").write_text("not a dir")
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / ".claude.json").write_text("{}")  # placeholder; projects read from ~/.claude.json
    (tmp_path / ".claude.json").write_text(json.dumps({"projects": {project.as_posix(): {}}}))

    # Must not raise.
    skills = ClaudeCodeDiscoverer(tmp_path).discover_skills()
    assert not any(k.endswith("/proj/.claude/skills") for k in skills)


# --- #8: _scans_own_home resolves symlinks and accepts the uid's passwd home ---


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
def test_scans_own_home_true_for_symlinked_home(tmp_path, monkeypatch):
    """A ``home_directory`` that is a symlink to the real home is still recognized
    as own-home (both sides are resolved before comparing)."""
    from pathlib import Path

    from agent_scan.agents import VSCodeDiscoverer

    real_home = tmp_path / "real_home"
    real_home.mkdir()
    link_home = tmp_path / "link_home"
    link_home.symlink_to(real_home)
    monkeypatch.setattr(Path, "home", lambda: real_home)

    assert VSCodeDiscoverer(link_home)._scans_own_home() is True
    assert VSCodeDiscoverer(tmp_path / "someone_else")._scans_own_home() is False


@pytest.mark.skipif(sys.platform == "win32", reason="pwd is POSIX-only")
def test_scans_own_home_accepts_passwd_home_when_env_home_differs(tmp_path, monkeypatch):
    """Under ``--scan-all-users`` the current user's own home comes from ``pwd``
    (``pw_dir``), which can differ from ``$HOME`` (sudo-rewritten/relocated). The
    uid's passwd home is accepted as own-home too, so env relocations stay honored."""
    import os
    import pwd
    from pathlib import Path

    from agent_scan.agents import VSCodeDiscoverer

    pw_home = tmp_path / "pw_home"
    pw_home.mkdir()
    env_home = tmp_path / "env_home"
    env_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: env_home)
    fake = pwd.struct_passwd(("u", "x", os.getuid(), os.getgid(), "g", str(pw_home), "/bin/sh"))
    monkeypatch.setattr(pwd, "getpwuid", lambda _uid: fake)

    assert VSCodeDiscoverer(pw_home)._scans_own_home() is True  # passwd pw_dir
    assert VSCodeDiscoverer(env_home)._scans_own_home() is True  # $HOME (single-user mode)
    assert VSCodeDiscoverer(tmp_path / "bob")._scans_own_home() is False


# --- D3: oversized config files are skipped rather than read whole into memory ---


def test_load_json_file_skips_oversized_config(tmp_path, monkeypatch):
    """A file larger than the size cap is treated as unreadable (skipped)."""
    import agent_scan.agents.base as base_mod
    from agent_scan.agents import VSCodeDiscoverer

    monkeypatch.setattr(base_mod, "_MAX_CONFIG_FILE_BYTES", 10)
    discoverer = VSCodeDiscoverer(tmp_path)

    big = tmp_path / "big.json"
    big.write_text('{"mcpServers": {"s": {"command": "x"}}}')  # > 10 bytes
    assert discoverer._load_json_file(big) is None

    small = tmp_path / "small.json"
    small.write_text("{}")  # < 10 bytes
    assert discoverer._load_json_file(small) == {}


# --- #5: VSCode-only feature flags default off and forks don't silently inherit them ---


def test_vscode_family_feature_flags_default_false():
    """The VSCode-only feature flags default off on the family base, so a fork that
    doesn't opt in cannot silently inherit a True (which would widen discovery)."""
    from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer

    assert VSCodeFamilyDiscoverer._devcontainer_mcp_enabled is False
    assert VSCodeFamilyDiscoverer._code_workspace_enabled is False
    assert VSCodeFamilyDiscoverer._settings_skill_locations_enabled is False


@pytest.mark.parametrize("fork", ["cursor", "windsurf", "kiro", "antigravity"])
def test_vscode_forks_do_not_enable_vscode_only_features(fork):
    """Only VSCodeDiscoverer enables devcontainer / .code-workspace / agentSkillsLocations.
    A fork copy-pasting those flags would silently widen its file-read surface."""
    from agent_scan.agents import DISCOVERERS

    cls = DISCOVERERS[fork]
    assert cls._devcontainer_mcp_enabled is False
    assert cls._code_workspace_enabled is False
    assert cls._settings_skill_locations_enabled is False


def test_cursor_does_not_scan_devcontainer(tmp_path):
    """Behavioral check: Cursor (devcontainer flag off) yields no entry even when a
    devcontainer.json with MCP servers exists in an opened workspace."""
    discoverer, workspace = _setup_cursor_workspace(tmp_path, "proj")
    devc = workspace / ".devcontainer"
    devc.mkdir()
    (devc / "devcontainer.json").write_text(
        '{"customizations": {"vscode": {"mcp": {"servers": {"dc": {"command": "d"}}}}}}'
    )

    mcp_configs = discoverer.discover_mcp_servers()

    assert not any("devcontainer.json" in k for k in mcp_configs)


# --- #6: _setting_flag_enabled string-boolean ("true"/"false") semantics ---


def test_vscode_agent_skills_locations_string_true_enabled(tmp_path):
    """VS Code's asBoolean accepts the string ``"true"``; such a location is scanned."""
    import json

    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    custom = tmp_path / "str-true-skills"
    _write_skill(custom, "str-true-skill")
    settings = _userdata(discoverer) / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"chat.agentSkillsLocations": {custom.as_posix(): "true"}}))

    skills_dirs = discoverer.discover_skills()

    assert any(k.endswith("/str-true-skills") for k in skills_dirs)


@pytest.mark.parametrize("flag", ["false", "FALSE", "False"])
def test_vscode_agent_skills_locations_string_false_excluded(tmp_path, flag):
    """A location mapped to the case-insensitive string ``"false"`` is NOT scanned."""
    import json

    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    custom = tmp_path / "str-false-skills"
    _write_skill(custom, "str-false-skill")
    settings = _userdata(discoverer) / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"chat.agentSkillsLocations": {custom.as_posix(): flag}}))

    skills_dirs = discoverer.discover_skills()

    assert not any(k.endswith("/str-false-skills") for k in skills_dirs)


# --- #7: ``~``-prefixed and relative-in-userdata agentSkillsLocations branches ---


def test_vscode_agent_skills_locations_tilde_home_path(tmp_path):
    """A ``~``-prefixed agentSkillsLocations entry resolves against the scanned
    user's home and is scanned (the previously-untested ``~`` branch)."""
    import json

    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    _write_skill(tmp_path / "home-skills", "home-skill")
    settings = _userdata(discoverer) / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"chat.agentSkillsLocations": ["~/home-skills"]}))

    skills_dirs = discoverer.discover_skills()

    assert any(k.endswith("/home-skills") for k in skills_dirs)


def test_vscode_agent_skills_locations_relative_in_userdata_settings_dropped(tmp_path):
    """A *relative* agentSkillsLocations entry in a userdata settings.json has no
    base dir to resolve against, so it is dropped (no entry, no error)."""
    import json

    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    _write_skill(tmp_path / "rel-skills", "rel-skill")
    settings = _userdata(discoverer) / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"chat.agentSkillsLocations": ["rel-skills"]}))

    skills_dirs = discoverer.discover_skills()

    assert not any(k.endswith("/rel-skills") for k in skills_dirs)


# --- #9: profile-scoped agentSkillsLocations ---


def test_vscode_profile_agent_skills_locations(tmp_path):
    """A named profile's ``settings.json`` ``chat.agentSkillsLocations`` is scanned."""
    import json

    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    custom = tmp_path / "profile-skills"
    _write_skill(custom, "profile-skill")
    profile_dir = _userdata(discoverer) / "User" / "profiles" / "work"
    profile_dir.mkdir(parents=True)
    (profile_dir / "settings.json").write_text(json.dumps({"chat.agentSkillsLocations": {custom.as_posix(): True}}))

    skills_dirs = discoverer.discover_skills()

    assert any(k.endswith("/profile-skills") for k in skills_dirs)


# --- D6: the root-level ``.devcontainer.json`` variant ---


def test_vscode_discovers_root_dotted_devcontainer_mcp(tmp_path):
    """The root-level ``.devcontainer.json`` form (not the ``.devcontainer/`` subdir)
    is also scanned for ``customizations.vscode.mcp.servers``."""
    discoverer, workspace = _setup_vscode_workspace(tmp_path, "proj")
    (workspace / ".devcontainer.json").write_text(
        '{"customizations": {"vscode": {"mcp": {"servers": {"root-dc": {"command": "d"}}}}}}'
    )

    mcp_configs = discoverer.discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/proj/.devcontainer.json")]
    assert len(keys) == 1
    assert mcp_configs[keys[0]][0][0] == "root-dc"


# --- D7: a malformed ``.code-workspace`` is skipped, not surfaced as a parse failure ---


def test_vscode_code_workspace_malformed_file_skipped(tmp_path):
    """A malformed ``.code-workspace`` referenced via the workspace.json ``workspace``
    pointer is skipped silently; a sibling single-root window still resolves."""
    from agent_scan.agents import VSCodeDiscoverer

    discoverer = VSCodeDiscoverer(tmp_path)
    (tmp_path / ".vscode").mkdir()
    storage = _userdata(discoverer) / "User" / "workspaceStorage"

    bad_ws = tmp_path / "broken.code-workspace"
    bad_ws.write_text("{ not valid json")
    bad_hash = storage / "bad"
    bad_hash.mkdir(parents=True)
    (bad_hash / "workspace.json").write_text(f'{{"workspace": "{bad_ws.as_uri()}"}}')

    good_hash = storage / "good"
    good_hash.mkdir()
    good_repo = tmp_path / "good-repo"
    (good_repo / ".vscode").mkdir(parents=True)
    (good_repo / ".vscode" / "mcp.json").write_text('{"servers": {"good": {"command": "g"}}}')
    (good_hash / "workspace.json").write_text(f'{{"folder": "{good_repo.as_uri()}"}}')

    mcp_configs = discoverer.discover_mcp_servers()

    assert not any("broken.code-workspace" in k for k in mcp_configs)
    assert any(k.endswith("/good-repo/.vscode/mcp.json") for k in mcp_configs)


# --- CodexDiscoverer: client_exists ---


def test_codex_discoverer_detects_installation(tmp_path):
    from agent_scan.agents import CodexDiscoverer

    (tmp_path / ".codex").mkdir()

    result = CodexDiscoverer(tmp_path).client_exists()

    assert result is not None
    assert result.endswith("/.codex")


def test_codex_discoverer_returns_none_when_absent(tmp_path):
    from agent_scan.agents import CodexDiscoverer

    result = CodexDiscoverer(tmp_path).client_exists()

    assert result is None


# --- CodexDiscoverer: discover_mcp_servers (TOML config.toml) ---


def test_codex_discoverer_parses_stdio_mcp_server(tmp_path):
    """A stdio ``[mcp_servers.<name>]`` table becomes a StdioServer keyed by config path."""
    from agent_scan.agents import CodexDiscoverer

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        "[mcp_servers.context7]\n"
        'command = "npx"\n'
        'args = ["-y", "@upstash/context7-mcp"]\n'
        "\n"
        "[mcp_servers.context7.env]\n"
        'MY_ENV_VAR = "MY_ENV_VALUE"\n'
    )

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    assert len(mcp_configs) == 1
    config_path = next(iter(mcp_configs))
    assert config_path.endswith("/.codex/config.toml")
    entries = mcp_configs[config_path]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "context7"
    assert isinstance(server, StdioServer)
    assert server.command == "npx"
    assert server.args == ["-y", "@upstash/context7-mcp"]
    assert server.env == {"MY_ENV_VAR": "MY_ENV_VALUE"}


def test_codex_discoverer_parses_http_mcp_server(tmp_path):
    """An HTTP ``[mcp_servers.<name>]`` table (url) becomes a RemoteServer.

    Codex-only keys (``bearer_token_env_var``/``http_headers``) are ignored by
    the model's default ``extra="ignore"`` and must not sink validation.
    """
    from agent_scan.agents import CodexDiscoverer

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        "[mcp_servers.figma]\n"
        'url = "https://mcp.figma.com/mcp"\n'
        'bearer_token_env_var = "FIGMA_OAUTH_TOKEN"\n'
        'http_headers = { "X-Figma-Region" = "us-east-1" }\n'
    )

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    config_path = next(iter(mcp_configs))
    entries = mcp_configs[config_path]
    assert isinstance(entries, list)
    name, server = entries[0]
    assert name == "figma"
    assert isinstance(server, RemoteServer)
    assert server.url == "https://mcp.figma.com/mcp"


def test_codex_discoverer_mixes_stdio_and_http_servers(tmp_path):
    from agent_scan.agents import CodexDiscoverer

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        '[mcp_servers.local]\ncommand = "server"\n\n[mcp_servers.remote]\nurl = "https://mcp.example.com/mcp"\n'
    )

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    config_path = next(iter(mcp_configs))
    by_name = dict(mcp_configs[config_path])
    assert set(by_name) == {"local", "remote"}
    assert isinstance(by_name["local"], StdioServer)
    assert isinstance(by_name["remote"], RemoteServer)


def test_codex_discoverer_ignores_config_without_mcp_servers(tmp_path):
    """A ``config.toml`` carrying only model/approval settings (no ``mcp_servers``)
    returns no entries -- it is not a parse failure (Codex config is multi-purpose)."""
    from agent_scan.agents import CodexDiscoverer

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text('model = "gpt-5-codex"\napproval_policy = "on-request"\n')

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    assert mcp_configs == {}


def test_codex_discoverer_returns_empty_when_config_absent(tmp_path):
    from agent_scan.agents import CodexDiscoverer

    (tmp_path / ".codex").mkdir()

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    assert mcp_configs == {}


def test_codex_discoverer_malformed_toml_is_parse_error(tmp_path):
    from agent_scan.agents import CodexDiscoverer

    (tmp_path / ".codex").mkdir()
    # Unterminated table header -- not valid TOML.
    (tmp_path / ".codex" / "config.toml").write_text("[mcp_servers.broken\ncommand = ")

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    config_path = next(iter(mcp_configs))
    assert config_path.endswith("/.codex/config.toml")
    assert isinstance(mcp_configs[config_path], CouldNotParseMCPConfig)


def test_codex_discoverer_extra_codex_keys_do_not_sink_validation(tmp_path):
    """Codex-specific stdio keys (``env_vars``/``cwd``/``enabled``) are tolerated."""
    from agent_scan.agents import CodexDiscoverer

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        "[mcp_servers.ctx]\n"
        'command = "npx"\n'
        'args = ["-y", "pkg"]\n'
        'env_vars = ["LOCAL_TOKEN"]\n'
        'cwd = "/tmp"\n'
        "enabled = true\n"
    )

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    config_path = next(iter(mcp_configs))
    name, server = mcp_configs[config_path][0]
    assert name == "ctx"
    assert isinstance(server, StdioServer)
    assert server.command == "npx"


# --- CodexDiscoverer: CODEX_HOME relocation ---


def test_codex_discoverer_honors_codex_home_on_own_home_scan(tmp_path, monkeypatch):
    """On an own-home scan (``home_directory=None``), ``CODEX_HOME`` relocates the
    config dir, mirroring how Claude Code honors ``CLAUDE_CONFIG_DIR``."""
    from agent_scan.agents import CodexDiscoverer

    cfg = tmp_path / "custom-codex"
    cfg.mkdir()
    (cfg / "config.toml").write_text('[mcp_servers.relocated]\ncommand = "r"\n')
    monkeypatch.setenv("CODEX_HOME", str(cfg))

    mcp_configs = CodexDiscoverer(None).discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/custom-codex/config.toml")]
    assert len(keys) == 1
    assert mcp_configs[keys[0]][0][0] == "relocated"


def test_codex_discoverer_ignores_codex_home_when_home_passed(tmp_path, monkeypatch):
    """Under a multi-user scan (an explicit, different home is passed) the scanning
    process's ``CODEX_HOME`` must NOT relocate the target user's config."""
    from agent_scan.agents import CodexDiscoverer

    cfg = tmp_path / "process-env-dir"
    cfg.mkdir()
    (cfg / "config.toml").write_text('[mcp_servers.should-not-appear]\ncommand = "x"\n')
    monkeypatch.setenv("CODEX_HOME", str(cfg))

    home = tmp_path / "alice"
    (home / ".codex").mkdir(parents=True)
    (home / ".codex" / "config.toml").write_text('[mcp_servers.alice-server]\ncommand = "a"\n')

    mcp_configs = CodexDiscoverer(home).discover_mcp_servers()

    all_names = {n for v in mcp_configs.values() if isinstance(v, list) for n, _ in v}
    assert "alice-server" in all_names
    assert "should-not-appear" not in all_names


# --- CodexDiscoverer: discover_skills (documented dirs) ---


def test_codex_discoverer_discovers_user_skills(tmp_path, monkeypatch):
    """User skills live at ``$HOME/.agents/skills/<name>/SKILL.md`` per Codex docs."""
    from agent_scan.agents import CodexDiscoverer

    # Keep the admin path hermetic (point it somewhere that does not exist).
    monkeypatch.setattr(CodexDiscoverer, "_admin_skills_dir", str(tmp_path / "no-admin"))

    my_skill = tmp_path / ".agents" / "skills" / "my-skill"
    my_skill.mkdir(parents=True)
    (my_skill / "SKILL.md").write_text("---\nname: my-skill\ndescription: A test skill\n---\n\nBody.\n")

    skills_dirs = CodexDiscoverer(tmp_path).discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/.agents/skills")]
    assert len(keys) == 1
    assert {n for n, _ in skills_dirs[keys[0]]} == {"my-skill"}
    assert isinstance(skills_dirs[keys[0]][0][1], SkillServer)


def test_codex_discoverer_discovers_admin_skills(tmp_path, monkeypatch):
    """Admin skills live at ``/etc/codex/skills`` per Codex docs; retargeted here."""
    from agent_scan.agents import CodexDiscoverer

    admin = tmp_path / "etc-codex-skills"
    skill = admin / "ops-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: ops-skill\ndescription: admin\n---\n\nBody.\n")
    monkeypatch.setattr(CodexDiscoverer, "_admin_skills_dir", str(admin))

    skills_dirs = CodexDiscoverer(tmp_path).discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/etc-codex-skills")]
    assert len(keys) == 1
    assert {n for n, _ in skills_dirs[keys[0]]} == {"ops-skill"}


def test_codex_discoverer_returns_empty_skills_when_no_dirs(tmp_path, monkeypatch):
    from agent_scan.agents import CodexDiscoverer

    monkeypatch.setattr(CodexDiscoverer, "_admin_skills_dir", str(tmp_path / "no-admin"))

    skills_dirs = CodexDiscoverer(tmp_path).discover_skills()

    assert skills_dirs == {}


# --- CodexDiscoverer: full discover() + registry ---


def test_codex_discoverer_discover_assembles_client(tmp_path, monkeypatch):
    from agent_scan.agents import CodexDiscoverer
    from agent_scan.models import ClientToInspect

    monkeypatch.setattr(CodexDiscoverer, "_admin_skills_dir", str(tmp_path / "no-admin"))
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text('[mcp_servers.local]\ncommand = "server"\n')

    cti = CodexDiscoverer(tmp_path).discover()

    assert isinstance(cti, ClientToInspect)
    assert cti.name == "codex"
    assert cti.client_path.endswith("/.codex")


def test_codex_discoverer_discover_returns_none_when_absent(tmp_path):
    from agent_scan.agents import CodexDiscoverer

    assert CodexDiscoverer(tmp_path).discover() is None


def test_DISCOVERERS_registers_codex():
    from agent_scan.agents import DISCOVERERS, CodexDiscoverer

    assert DISCOVERERS["codex"] is CodexDiscoverer


def test_find_discoverers_returns_codex_when_installed(tmp_path):
    from agent_scan.agents import CodexDiscoverer, find_discoverers

    (tmp_path / ".codex").mkdir()

    found = find_discoverers(tmp_path)

    assert any(isinstance(d, CodexDiscoverer) for d in found)


# --- CodexDiscoverer: project-scoped discovery via the [projects] table ---


def test_codex_discoverer_enumerates_all_projects_ignoring_trust(tmp_path):
    """``_discover_project_folders`` returns every key in the ``[projects]`` table,
    regardless of (or absent) ``trust_level`` -- the value is never read."""
    from agent_scan.agents import CodexDiscoverer

    proj_trusted = tmp_path / "trusted-repo"
    proj_untrusted = tmp_path / "untrusted-repo"
    proj_bare = tmp_path / "bare-repo"
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        f'[projects."{proj_trusted.as_posix()}"]\n'
        'trust_level = "trusted"\n\n'
        f'[projects."{proj_untrusted.as_posix()}"]\n'
        'trust_level = "untrusted"\n\n'
        f'[projects."{proj_bare.as_posix()}"]\n'
    )

    folders = set(CodexDiscoverer(tmp_path)._discover_project_folders())

    assert folders == {proj_trusted, proj_untrusted, proj_bare}


def test_codex_discoverer_no_projects_table_yields_no_project_folders(tmp_path):
    from agent_scan.agents import CodexDiscoverer

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text('model = "gpt-5-codex"\n')

    assert CodexDiscoverer(tmp_path)._discover_project_folders() == []


def test_codex_discoverer_discovers_project_mcp_servers(tmp_path):
    """A project's ``<proj>/.codex/config.toml`` ``[mcp_servers]`` is discovered,
    keyed by that file -- and an untrusted project is scanned just the same."""
    from agent_scan.agents import CodexDiscoverer

    proj = tmp_path / "repo"
    (proj / ".codex").mkdir(parents=True)
    (proj / ".codex" / "config.toml").write_text('[mcp_servers.proj_srv]\ncommand = "p"\n')

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(f'[projects."{proj.as_posix()}"]\ntrust_level = "untrusted"\n')

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/repo/.codex/config.toml")]
    assert len(keys) == 1
    name, server = mcp_configs[keys[0]][0]
    assert name == "proj_srv"
    assert isinstance(server, StdioServer)


def test_codex_discoverer_surfaces_user_and_project_mcp_together(tmp_path):
    from agent_scan.agents import CodexDiscoverer

    proj = tmp_path / "repo"
    (proj / ".codex").mkdir(parents=True)
    (proj / ".codex" / "config.toml").write_text('[mcp_servers.proj_srv]\ncommand = "p"\n')

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(
        f'[mcp_servers.user_srv]\ncommand = "u"\n\n[projects."{proj.as_posix()}"]\ntrust_level = "trusted"\n'
    )

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    all_names = {n for v in mcp_configs.values() if isinstance(v, list) for n, _ in v}
    assert {"user_srv", "proj_srv"} <= all_names
    assert any(k.endswith("/.codex/config.toml") and "/repo/" not in k for k in mcp_configs)
    assert any(k.endswith("/repo/.codex/config.toml") for k in mcp_configs)


def test_codex_discoverer_malformed_project_config_is_parse_error(tmp_path):
    from agent_scan.agents import CodexDiscoverer

    proj = tmp_path / "repo"
    (proj / ".codex").mkdir(parents=True)
    (proj / ".codex" / "config.toml").write_text("[mcp_servers.broken\ncommand = ")

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(f'[projects."{proj.as_posix()}"]\n')

    mcp_configs = CodexDiscoverer(tmp_path).discover_mcp_servers()

    keys = [k for k in mcp_configs if k.endswith("/repo/.codex/config.toml")]
    assert len(keys) == 1
    assert isinstance(mcp_configs[keys[0]], CouldNotParseMCPConfig)


def test_codex_discoverer_discovers_project_skills(tmp_path):
    """A registered project's ``<proj>/.agents/skills`` is discovered."""
    from agent_scan.agents import CodexDiscoverer

    monkeypatch_admin = tmp_path / "no-admin"
    proj = tmp_path / "repo"
    skill = proj / ".agents" / "skills" / "proj-skill"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: proj-skill\ndescription: d\n---\n\nBody.\n")

    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text(f'[projects."{proj.as_posix()}"]\n')

    disc = CodexDiscoverer(tmp_path)
    disc._admin_skills_dir = str(monkeypatch_admin)
    skills_dirs = disc.discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/repo/.agents/skills")]
    assert len(keys) == 1
    assert {n for n, _ in skills_dirs[keys[0]]} == {"proj-skill"}


def test_codex_discoverer_walks_project_ancestors_for_skills(tmp_path):
    """``.agents/skills`` is found in an ancestor of a registered project root,
    matching Codex's walk from cwd up to the repository root."""
    from agent_scan.agents import CodexDiscoverer

    repo_root = tmp_path / "monorepo"
    subpkg = repo_root / "packages" / "app"
    subpkg.mkdir(parents=True)
    ancestor_skill = repo_root / ".agents" / "skills" / "root-skill"
    ancestor_skill.mkdir(parents=True)
    (ancestor_skill / "SKILL.md").write_text("---\nname: root-skill\ndescription: d\n---\n\nB.\n")

    (tmp_path / ".codex").mkdir()
    # Only the sub-package is registered as a project; the skills live at the repo root.
    (tmp_path / ".codex" / "config.toml").write_text(f'[projects."{subpkg.as_posix()}"]\n')

    disc = CodexDiscoverer(tmp_path)
    disc._admin_skills_dir = str(tmp_path / "no-admin")
    skills_dirs = disc.discover_skills()

    keys = [k for k in skills_dirs if k.endswith("/monorepo/.agents/skills")]
    assert len(keys) == 1
    assert {n for n, _ in skills_dirs[keys[0]]} == {"root-skill"}
