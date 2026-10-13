import json
from pathlib import Path

import pytest

from agent_scan.agents import GitHubCopilotDiscoverer
from agent_scan.agents.github_copilot import _MAX_WORKSPACE_FILE_BYTES


def _workspace(home: Path, cwd: Path | None, git_root: Path | None, session: str = "e1c6d9ab") -> Path:
    path = home / "session-state" / session / "workspace.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "branch: main\n"
        "client_name: copilot-cli\n"
        "created_at: 2026-06-01T09:00:00.000Z\n"
        f"cwd: {json.dumps(str(cwd)) if cwd is not None else 'null'}\n"
        "fork_count: 0\n"
        f"git_root: {json.dumps(str(git_root)) if git_root is not None else 'null'}\n"
        f"id: {session}\n"
        "name: Project inspection\n"
        "summary_count: 0\n"
        "updated_at: 2026-06-01T09:00:01.000Z\n"
        "user_named: false\n",
        encoding="utf-8",
    )
    return path


def _project(path: Path) -> Path:
    github = path / ".github"
    skill = github / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: demo\ndescription: Demo skill\n---\nInstructions\n")
    (path / ".mcp.json").write_text(json.dumps({"mcpServers": {"root": {"command": "echo"}}}))
    (github / "mcp.json").write_text(json.dumps({"mcpServers": {"github": {"command": "echo"}}}))
    return path


def _assert_project(discoverer: GitHubCopilotDiscoverer, project: Path) -> None:
    configs = discoverer.discover_mcp_servers()
    assert set(configs) == {
        (project / ".mcp.json").resolve().as_posix(),
        (project / ".github/mcp.json").resolve().as_posix(),
    }
    names: set[str] = set()
    for servers in configs.values():
        assert isinstance(servers, list)
        names.update(name for name, _ in servers)
    assert names == {"root", "github"}
    skills = discoverer.discover_skills()
    assert set(skills) == {(project / ".github/skills").resolve().as_posix()}
    entries = next(iter(skills.values()))
    assert isinstance(entries, list)
    assert [skill.name for skill in entries] == ["demo"]


@pytest.mark.parametrize("source", ["session", "trusted_folders"])
@pytest.mark.parametrize("override", [False, True])
def test_project_discovered_from_one_source_only(tmp_path, monkeypatch, source, override):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.delenv("COPILOT_HOME", raising=False)
    home = tmp_path / ("relocated-copilot" if override else ".copilot")
    home.mkdir()
    if override:
        monkeypatch.setenv("COPILOT_HOME", str(home))
        _workspace(tmp_path / ".copilot", _project(tmp_path / "ignored-default-home-project"), None)
    project = _project(tmp_path / "project with spaces")
    if source == "session":
        package = project / "package"
        package.mkdir()
        _workspace(home, package, project)
    else:
        (home / "config.json").write_text(
            '// Copilot CLI configuration\n{"trusted_folders": [' + json.dumps(str(project)) + ",],}\n"
        )

    discoverer = GitHubCopilotDiscoverer(None)

    assert discoverer.client_exists() == str(home)
    _assert_project(discoverer, project)


@pytest.mark.parametrize(
    "content", [b"cwd: [unterminated", b"- list\n", b"null\n", b"cwd: 123\ngit_root: []\n", b"\xff"]
)
def test_malformed_workspace_skipped_without_losing_other_sessions(tmp_path, content):
    home = tmp_path / ".copilot"
    project = _project(tmp_path / "project")
    _workspace(home, project, project, "valid")
    malformed = _workspace(home, tmp_path / "ignored", None, "malformed")
    malformed.write_bytes(content)
    (home / "permissions-config.json").write_text("invalid JSON")
    (home / "config.json").write_text("invalid JSON")

    _assert_project(GitHubCopilotDiscoverer(tmp_path), project)


def test_unreadable_workspace_skipped(tmp_path, monkeypatch):
    home = tmp_path / ".copilot"
    project = _project(tmp_path / "project")
    _workspace(home, project, None, "valid")
    unreadable = _workspace(home, tmp_path / "ignored", None, "unreadable")
    original_open = Path.open

    def guarded_open(path, *args, **kwargs):
        if path == unreadable:
            raise PermissionError("denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    _assert_project(GitHubCopilotDiscoverer(tmp_path), project)


def test_unreadable_session_directory_does_not_hide_trusted_folders(tmp_path, monkeypatch):
    home = tmp_path / ".copilot"
    home.mkdir()
    project = _project(tmp_path / "project")
    (home / "config.json").write_text(json.dumps({"trusted_folders": [str(project)]}))
    original_iterdir = Path.iterdir

    def guarded_iterdir(path):
        if path == home / "session-state":
            raise PermissionError("denied")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", guarded_iterdir)
    _assert_project(GitHubCopilotDiscoverer(tmp_path), project)


def test_duplicate_roots_are_deduped_across_sources_and_targets(tmp_path):
    home = tmp_path / ".copilot"
    project = _project(tmp_path / "project")
    _workspace(home, project, project, "first")
    _workspace(home, project, project, "second")
    (home / "permissions-config.json").write_text(json.dumps({"locations": {str(project): {}}}))
    (home / "config.json").write_text(
        json.dumps({"trusted_folders": [str(project), f"  {project}  ", str(project / ".")]})
    )
    discoverer = GitHubCopilotDiscoverer(tmp_path, target_folders=[project, project])

    assert discoverer._discover_project_folders() == [project]
    assert discoverer._all_discovery_folders() == [project]
    assert discoverer._discovery_paths_with_ancestors().count(project) == 1
    _assert_project(discoverer, project)


def test_symlink_alias_keeps_literal_ancestor_walk(tmp_path):
    home = tmp_path / ".copilot"
    home.mkdir()
    project = _project(tmp_path / "project")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(project, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlinks are unavailable")
    (home / "permissions-config.json").write_text(json.dumps({"locations": {str(alias): {}}}))
    _workspace(home, project, project)
    discoverer = GitHubCopilotDiscoverer(tmp_path)

    assert discoverer._discover_project_folders() == [alias]
    assert discoverer._discovery_paths_with_ancestors()[0] == alias
    _assert_project(discoverer, project)


def test_git_root_bridges_symlinked_cwd(tmp_path):
    home = tmp_path / ".copilot"
    project = _project(tmp_path / "project")
    package = project / "package"
    package.mkdir()
    alias = tmp_path / "package-alias"
    try:
        alias.symlink_to(package, target_is_directory=True)
    except OSError:
        pytest.skip("Directory symlinks are unavailable")
    _workspace(home, alias, project)
    discoverer = GitHubCopilotDiscoverer(tmp_path)

    assert discoverer._discover_project_folders() == [alias, project]
    _assert_project(discoverer, project)


@pytest.mark.parametrize("source", ["session", "trusted_folders", "permissions"])
def test_only_local_existing_directories_are_roots(tmp_path, source):
    home = tmp_path / ".copilot"
    home.mkdir()
    not_directory = tmp_path / "file"
    not_directory.touch()
    invalid = [
        None,
        12,
        {},
        "",
        "  ",
        ".",
        "../project",
        "https://example.com/project",
        "file:///project",
        str(not_directory),
        str(tmp_path / "missing"),
        "/bad\x00path",
    ]
    if source == "session":
        for index, value in enumerate(invalid):
            path = _workspace(home, None, None, str(index))
            path.write_text(json.dumps({"cwd": value, "git_root": value}))
    elif source == "trusted_folders":
        (home / "config.json").write_text(json.dumps({"trusted_folders": invalid}))
    else:
        (home / "permissions-config.json").write_text(
            json.dumps({"locations": {v: {} for v in invalid if isinstance(v, str)}})
        )

    discoverer = GitHubCopilotDiscoverer(tmp_path)
    assert discoverer._discover_project_folders() == []
    assert discoverer.discover_mcp_servers() == {}
    assert discoverer.discover_skills() == {}


@pytest.mark.parametrize("trusted", [None, "not-a-list", {}, [None, {}]])
def test_unusable_trusted_folders_does_not_hide_sessions(tmp_path, trusted):
    home = tmp_path / ".copilot"
    project = _project(tmp_path / "project")
    _workspace(home, project, None)
    (home / "config.json").write_text(json.dumps({"trusted_folders": trusted}))

    _assert_project(GitHubCopilotDiscoverer(tmp_path), project)


@pytest.mark.parametrize("cwd_kind", ["missing", "null", "nested", "unrelated"])
def test_git_root_only_used_when_it_contains_cwd_or_cwd_is_absent(tmp_path, cwd_kind):
    home = tmp_path / ".copilot"
    project = _project(tmp_path / "project")
    cwd = {
        "missing": project / "deleted-package",
        "null": None,
        "nested": project / "package",
        "unrelated": tmp_path / "elsewhere",
    }[cwd_kind]
    if cwd_kind in {"nested", "unrelated"}:
        cwd.mkdir()
    _workspace(home, cwd, project)
    discoverer = GitHubCopilotDiscoverer(tmp_path)

    if cwd_kind == "unrelated":
        assert discoverer._discover_project_folders() == [cwd]
        assert discoverer.discover_mcp_servers() == {}
        assert discoverer.discover_skills() == {}
    else:
        _assert_project(discoverer, project)


def test_session_scan_reads_only_small_direct_workspace_files(tmp_path, monkeypatch):
    home = tmp_path / ".copilot"
    project = _project(tmp_path / "project")
    workspace = _workspace(home, project, None)
    events = workspace.parent / "events.jsonl"
    with events.open("wb") as stream:
        stream.truncate(100 * 1024 * 1024)
    ignored = _project(tmp_path / "ignored")
    nested = _workspace(home / "session-state" / "nested", ignored, None)
    oversized = _workspace(home, ignored, None, "oversized")
    oversized.write_bytes(b" " * (_MAX_WORKSPACE_FILE_BYTES + 1))
    original_open = Path.open

    def guarded_open(path, *args, **kwargs):
        assert path not in {events, nested}, "Discovery must not read session events or recurse"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    _assert_project(GitHubCopilotDiscoverer(tmp_path), project)


@pytest.mark.parametrize("source", ["session", "trusted_folders"])
def test_copilot_home_override_does_not_affect_other_users(tmp_path, monkeypatch, source):
    home = tmp_path / "alice" / ".copilot"
    home.mkdir(parents=True)
    relocated = tmp_path / "process-copilot"
    relocated.mkdir()
    project = _project(tmp_path / "project")
    if source == "session":
        _workspace(relocated, project, None)
    else:
        (relocated / "config.json").write_text(json.dumps({"trusted_folders": [str(project)]}))
    monkeypatch.setenv("COPILOT_HOME", str(relocated))

    discoverer = GitHubCopilotDiscoverer(home.parent)
    assert discoverer._discover_project_folders() == []
    assert discoverer.discover_mcp_servers() == {}
    assert discoverer.discover_skills() == {}
