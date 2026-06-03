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


def test_claude_code_discoverer_parses_mcp_servers(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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


def test_claude_code_discoverer_returns_empty_when_json_has_no_mcp_fields(tmp_path):
    """JSON without top-level mcpServers and without projects returns no entries."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text('{"unrelated": "data"}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert mcp_configs == {}


def test_claude_code_discoverer_records_could_not_parse_on_invalid_json(tmp_path):
    """Malformed JSON in ~/.claude.json becomes CouldNotParseMCPConfig with traceback."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text("{not valid json")

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert len(mcp_configs) == 1
    entry = next(iter(mcp_configs.values()))
    assert isinstance(entry, CouldNotParseMCPConfig)
    assert entry.is_failure is True
    assert entry.traceback


def test_claude_code_discoverer_returns_empty_when_mcp_config_missing(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    # no ~/.claude.json on disk

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

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


def test_claude_code_discoverer_parses_project_mcp_servers(tmp_path):
    """Each project's mcpServers becomes its own entry keyed by the project path."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    """A flat-format ``<project>/.mcp.json`` is also parsed via _select_servers_payload.

    Previously a flat-format project file was silently dropped (no top-level
    "mcpServers" key). The shared payload selector now recognises it.
    """
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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


def test_claude_code_discoverer_plugin_mcp_servers_parses_flat_format(tmp_path):
    """Plugin .mcp.json files use the flat {name: serverConfig} format."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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


def test_select_servers_payload_flat_remote_server_named_mcpServers():
    """A flat-format payload with a single RemoteServer named "mcpServers"
    (``url`` discriminator instead of ``command``) is also detected as flat."""
    from agent_scan.agent_discovery import _select_servers_payload

    file_data = {"mcpServers": {"url": "https://example.com/mcp", "type": "http"}}

    payload = _select_servers_payload(file_data)

    # Whole file returned (flat); the inner dict is the RemoteServer config.
    assert payload is file_data


def test_select_servers_payload_wrapped_when_inner_has_no_discriminators():
    """When file_data["mcpServers"] has no server-config discriminator keys at its
    top level, it's a server map → wrapped."""
    from agent_scan.agent_discovery import _select_servers_payload

    file_data = {"mcpServers": {"srv-a": {"command": "a"}, "srv-b": {"url": "https://b"}}}

    payload = _select_servers_payload(file_data)

    assert payload is file_data["mcpServers"]


def test_select_servers_payload_wrapped_when_server_is_named_after_discriminator():
    """A wrapped-format payload whose server is *named* "command" / "url" / "serverUrl"
    must NOT be misread as flat. The inner discriminator key maps to a dict (the server
    config), never a string (which only a real top-level server config would have).
    """
    from agent_scan.agent_discovery import _select_servers_payload

    for discriminator in ("command", "url", "serverUrl"):
        file_data = {"mcpServers": {discriminator: {"command": "/bin/echo"}}}

        payload = _select_servers_payload(file_data)

        assert payload is file_data["mcpServers"], (
            f"Wrapped server named {discriminator!r} was misread as flat — "
            f"detector must inspect value types, not just key presence"
        )


def test_select_servers_payload_wrapped_multiple_servers_one_named_after_discriminator():
    """A wrapped-format payload with multiple servers, one of which happens to be
    named "command", still parses as wrapped (the inner "command" value is a dict)."""
    from agent_scan.agent_discovery import _select_servers_payload

    file_data = {
        "mcpServers": {
            "command": {"command": "/bin/cmd"},
            "other": {"command": "/bin/other"},
        }
    }

    payload = _select_servers_payload(file_data)

    assert payload is file_data["mcpServers"]


def test_claude_code_discoverer_plugin_mcp_wrapped_server_named_command(tmp_path):
    """End-to-end: a wrapped plugin .mcp.json with a server *named* "command" parses
    as wrapped (single server named "command"), not as flat."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert mcp_configs == {}


def test_claude_code_discoverer_plugin_mcp_records_could_not_parse(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "bad" / "plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text("{not valid json")

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

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


def test_claude_code_discoverer_discover_mcp_includes_plugin_servers(tmp_path):
    """Plugin MCP entries flow through public discover_mcp_servers."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    plugin_dir = tmp_path / ".claude" / "plugins" / "cache" / "v" / "p"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text('{"plug": {"command": "x"}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

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


def test_claude_code_discoverer_plugin_mcp_servers_scans_repos_dir(tmp_path):
    """Plugins staged under ~/.claude/plugins/repos/**/ are also discovered."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    skills_dir = tmp_path / ".claude" / "plugins" / "repos" / "owner" / "plugin" / "skills" / "rs"
    skills_dir.mkdir(parents=True)
    (skills_dir / "SKILL.md").write_text("---\nname: rs\ndescription: r\n---\n\nB.\n")

    skills_dirs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_skills()

    repos_keys = [k for k in skills_dirs if "/plugins/repos/" in k]
    assert len(repos_keys) == 1


def test_claude_code_discoverer_plugin_mcp_servers_scans_both_cache_and_repos(tmp_path):
    """Both cache and repos contribute, keyed by their distinct file paths."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    cache_plugin = tmp_path / ".claude" / "plugins" / "cache" / "c" / "p"
    cache_plugin.mkdir(parents=True)
    (cache_plugin / ".mcp.json").write_text('{"c-srv": {"command": "c"}}')

    repo_plugin = tmp_path / ".claude" / "plugins" / "repos" / "r" / "p"
    repo_plugin.mkdir(parents=True)
    (repo_plugin / ".mcp.json").write_text('{"r-srv": {"command": "r"}}')

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

    assert any("/plugins/cache/" in k for k in mcp_configs)
    assert any("/plugins/repos/" in k for k in mcp_configs)


# --- ClaudeCodeDiscoverer: end-to-end discover() ---


def test_claude_code_discoverer_discover_assembles_client_to_inspect(tmp_path):
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    cti = ClaudeCodeDiscoverer(tmp_path).discover()

    assert cti is None


# --- ABC enforcement ---


def test_agent_discoverer_subclass_without_name_raises():
    """A subclass that forgets to set 'name' must fail at class-definition time."""
    from agent_scan.agent_discovery import AgentDiscoverer

    with pytest.raises(TypeError, match="must set a non-empty 'name'"):

        class BrokenDiscoverer(AgentDiscoverer):
            def client_exists(self):
                return None

            def discover_mcp_servers(self):
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

    mcp_configs = ClaudeCodeDiscoverer(tmp_path)._discover_plugin_mcp_servers()

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


def test_server_config_discriminator_keys_match_model_required_fields():
    """_SERVER_CONFIG_DISCRIMINATOR_KEYS must stay in sync with the required
    top-level fields of StdioServer + RemoteServer (including validation aliases).

    The flat-vs-wrapped detector in ``_select_servers_payload`` relies on these
    keys to tell a single server config apart from a server-name map. If a new
    required field lands on either model (e.g. a new ``protocol`` discriminator)
    and isn't added to the constant, the detector goes blind to that shape and
    silently misreads adversarial inputs as wrapped maps.
    """
    from pydantic import AliasChoices

    from agent_scan.agent_discovery import _SERVER_CONFIG_DISCRIMINATOR_KEYS
    from agent_scan.models import RemoteServer, StdioServer

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

    assert expected == set(_SERVER_CONFIG_DISCRIMINATOR_KEYS), (
        f"Required model fields {expected} drifted from "
        f"_SERVER_CONFIG_DISCRIMINATOR_KEYS {set(_SERVER_CONFIG_DISCRIMINATOR_KEYS)}. "
        "Update the constant in agent_discovery.py so the flat-vs-wrapped detector "
        "still recognises every required server-config key."
    )


def test_plugin_walk_prunes_traversal_beyond_cap(tmp_path, monkeypatch):
    """Traversal must be pruned at the depth cap, not just filtered post-hoc:
    ``os.walk`` is invoked once per plugin base dir and `dirs` is mutated so the
    walker never descends past the cap. We verify by spying on ``os.walk`` and
    asserting it never yields a root past the prune boundary.
    """
    from pathlib import Path

    import agent_scan.agent_discovery as ad

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

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

    assert len(mcp_configs) == 1
    entries = next(iter(mcp_configs.values()))
    assert isinstance(entries, list)
    assert [name for name, _ in entries] == ["my-server"]


def test_load_json_file_treats_empty_file_as_empty_config(tmp_path):
    """An empty (or whitespace-only) ~/.claude.json returns no entries, not a parse error."""
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude.json").write_text("   \n  \n")

    mcp_configs = ClaudeCodeDiscoverer(tmp_path).discover_mcp_servers()

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
    from agent_scan.agent_discovery import DISCOVERERS, AgentDiscoverer
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

    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
    from agent_scan.agent_discovery import ClaudeCodeDiscoverer

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
