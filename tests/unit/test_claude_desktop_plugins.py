import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_scan.agents import claude_desktop
from agent_scan.agents.claude_code import ClaudeCodeDiscoverer
from agent_scan.models import CouldNotParseMCPConfig, RemoteServer


@pytest.fixture
def desktop(tmp_path, monkeypatch):
    monkeypatch.setattr(claude_desktop.sys, "platform", "darwin")
    return claude_desktop.ClaudeDesktopDiscoverer(tmp_path)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


def rpm_dir(desktop, account="account-a", org="org-a"):
    return desktop._install_dir() / "local-agent-mode-sessions" / account / org / "rpm"


def install_plugin(desktop, plugin_id="plugin_gossamer", account="account-a", org="org-a"):
    rpm = rpm_dir(desktop, account, org)
    write_json(
        rpm / "manifest.json",
        {
            "plugins": [
                {"id": plugin_id, "name": "gossamer", "installedBy": "user", "installationPreference": "available"}
            ]
        },
    )
    plugin = rpm / plugin_id
    plugin.mkdir(exist_ok=True)
    return plugin


def add_skill(plugin, directory="skills", name="gossamer"):
    path = plugin / directory / name
    path.mkdir(parents=True)
    (path / "SKILL.md").write_text(f"---\nname: {name}\ndescription: A test skill\n---\nInstructions")
    return path


def test_desktop_plugin_skills_and_mcp_are_attributed_to_desktop(desktop):
    plugin = install_plugin(desktop)
    write_json(plugin / ".claude-plugin/plugin.json", {"name": "gossamer"})
    skill = add_skill(plugin)
    mcp = write_json(
        plugin / ".mcp.json", {"mcpServers": {"slack": {"type": "http", "url": "https://example.com/mcp"}}}
    )
    client = desktop.discover()
    assert client.name == "claude desktop"
    assert client.skills_dirs[str(skill.parent.resolve())][0].name == "gossamer"
    assert client.skills_dirs[str(skill.parent.resolve())][0].path == str(skill)
    servers = dict(client.mcp_configs[str(mcp.resolve())])
    assert isinstance(servers["slack"], RemoteServer)
    assert servers["slack"].url == "https://example.com/mcp"


@pytest.mark.parametrize("source", ["wrapped", "flat", "inline"])
@pytest.mark.parametrize("client", ["desktop", "code"])
def test_plugin_connectors_without_url_do_not_hide_configured_servers(desktop, tmp_path, source, client):
    if client == "desktop":
        discoverer = desktop
        plugin = install_plugin(desktop)
    else:
        discoverer = ClaudeCodeDiscoverer(tmp_path)
        plugin = tmp_path / ".claude/plugins/cache/test"
    servers = {
        "slack": {"type": "http", "url": "https://example.com/mcp"},
        "unconfigured": {"type": "http"},
    }
    if source == "inline":
        path = write_json(plugin / ".claude-plugin/plugin.json", {"mcpServers": servers})
        result = discoverer._discover_plugin_manifest_mcp_servers()
    else:
        path = write_json(plugin / ".mcp.json", {"mcpServers": servers} if source == "wrapped" else servers)
        result = discoverer._discover_plugin_mcp_servers()
    assert set(dict(result[str(path)])) == {"slack"}


@pytest.mark.parametrize("wrapped", [True, False])
def test_only_unconfigured_connectors_are_skipped(desktop, wrapped):
    plugin = install_plugin(desktop)
    servers = {"pending": {"type": "http"}}
    write_json(plugin / ".mcp.json", {"mcpServers": servers} if wrapped else servers)
    assert desktop.discover_mcp_servers() == {}


def test_desktop_plugin_manifest_skills_and_inline_servers(desktop):
    plugin = install_plugin(desktop)
    skill = add_skill(plugin, "extra-skills")
    manifest = write_json(
        plugin / ".claude-plugin/plugin.json",
        {
            "skills": ["./extra-skills", "../outside", "/outside", "C:\\outside", None],
            "mcpServers": {"inline": {"url": "https://example.com/mcp"}},
        },
    )
    assert set(desktop.discover_skills()) == {str(skill.parent.resolve())}
    assert set(dict(desktop.discover_mcp_servers()[str(manifest.resolve())])) == {"inline"}


def test_desktop_reads_only_listed_plugins_and_not_session_files(desktop):
    plugin = install_plugin(desktop)
    add_skill(plugin)
    unlisted = plugin.parent / "plugin_unlisted"
    add_skill(unlisted, name="unlisted")
    write_json(unlisted / ".mcp.json", {"mcpServers": {"unlisted": {"url": "https://example.com"}}})
    write_json(plugin.parent.parent / "local_session.json", {"private": "not a plugin"})
    write_json(plugin.parent.parent / "cowork/cache/.mcp.json", {"private": "not a plugin"})
    write_json(plugin / ".tessl-plugin/plugin.json", {"mcpServers": {"ignored": {"url": "https://example.com"}}})
    original = Path.read_text
    reads = []

    def guarded_read(path, *args, **kwargs):
        reads.append(path)
        assert path == plugin.parent / "manifest.json" or path.is_relative_to(plugin)
        assert ".tessl-plugin" not in path.parts
        return original(path, *args, **kwargs)

    with patch.object(Path, "read_text", guarded_read):
        assert desktop.discover_mcp_servers() == {}
        skills = desktop.discover_skills()
    assert {s.name for entries in skills.values() for s in entries} == {"gossamer"}
    assert reads == [plugin.parent / "manifest.json"]


@pytest.mark.parametrize("contents", ["{broken", "[]", "null", "{}", '{"plugins": {}}', '{"plugins": [null, 42, {}]}'])
def test_malformed_registry_does_not_hide_other_accounts(desktop, contents):
    broken = rpm_dir(desktop)
    broken.mkdir(parents=True)
    (broken / "manifest.json").write_text(contents)
    add_skill(broken / "plugin_unlisted", name="unlisted")
    plugin = install_plugin(desktop, account="account-b", org="org-b")
    skill = add_skill(plugin)
    assert set(desktop.discover_skills()) == {str(skill.parent.resolve())}


def test_multiple_accounts_and_orgs_and_missing_plugins(desktop):
    expected = set()
    for account, org in [("account-a", "org-a"), ("account-a", "org-b"), ("account-b", "org-a")]:
        plugin = install_plugin(desktop, account=account, org=org)
        expected.add(str(add_skill(plugin).parent.resolve()))
        write_json(
            plugin.parent / "manifest.json", {"plugins": [{"id": plugin.name}, {"id": plugin.name}, {"id": "missing"}]}
        )
    assert set(desktop.discover_skills()) == expected
    assert len(desktop._plugin_base_dirs()) == 3


@pytest.mark.parametrize(
    "plugin_id",
    ["../outside", ".", "..", "/tmp/outside", "C:\\outside", "..\\outside", "a/b", "a\\b", "\x00", "", " ", None, 12],
)
def test_registry_rejects_unsafe_ids(desktop, plugin_id):
    rpm = rpm_dir(desktop)
    add_skill(rpm.parent / "outside")
    write_json(rpm / "manifest.json", {"plugins": [{"id": plugin_id}]})
    assert desktop.discover_skills() == {}
    assert desktop._plugin_base_dirs() == []


@pytest.mark.parametrize(
    "link_kind", ["plugin", "manifest", "mcp", "skills", "skill", "skill_md", "plugin_manifest", "extra_skills"]
)
def test_symlinks_cannot_escape_listed_plugin(desktop, tmp_path, link_kind):
    plugin = install_plugin(desktop)
    outside = tmp_path / "outside"
    skill = add_skill(outside)
    mcp = write_json(outside / ".mcp.json", {"mcpServers": {"outside": {"url": "https://example.com"}}})
    manifest = write_json(outside / ".claude-plugin/plugin.json", {"skills": ["./skills"]})
    if link_kind == "plugin":
        plugin.rmdir()
        plugin.symlink_to(outside, target_is_directory=True)
    elif link_kind == "manifest":
        registry = plugin.parent / "manifest.json"
        registry.unlink()
        registry.symlink_to(write_json(outside / "manifest.json", {"plugins": [{"id": plugin.name}]}))
    elif link_kind == "mcp":
        (plugin / ".mcp.json").symlink_to(mcp)
    elif link_kind == "skills":
        (plugin / "skills").symlink_to(skill.parent, target_is_directory=True)
    elif link_kind == "skill":
        (plugin / "skills").mkdir()
        (plugin / "skills/outside").symlink_to(skill, target_is_directory=True)
    elif link_kind == "skill_md":
        (plugin / "skills/outside").mkdir(parents=True)
        (plugin / "skills/outside/SKILL.md").symlink_to(skill / "SKILL.md")
    elif link_kind == "plugin_manifest":
        (plugin / ".claude-plugin").symlink_to(manifest.parent, target_is_directory=True)
    else:
        write_json(plugin / ".claude-plugin/plugin.json", {"skills": ["./extra"]})
        (plugin / "extra").symlink_to(skill.parent, target_is_directory=True)
    original = Path.read_text

    def guarded_read(path, *args, **kwargs):
        assert not path.resolve().is_relative_to(outside.resolve())
        return original(path, *args, **kwargs)

    with patch.object(Path, "read_text", guarded_read):
        assert desktop.discover_mcp_servers() == {}
        assert not any(desktop.discover_skills().values())


def test_bad_global_config_and_plugin_manifest_do_not_hide_plugin_files(desktop):
    plugin = install_plugin(desktop)
    add_skill(plugin)
    (desktop._config_path()).write_text("{broken")
    (plugin / ".claude-plugin").mkdir()
    (plugin / ".claude-plugin/plugin.json").write_text("{broken")
    path = write_json(plugin / ".mcp.json", {"mcpServers": {"remote": {"url": "https://example.com"}}})
    result = desktop.discover_mcp_servers()
    assert isinstance(result[str(desktop._config_path().resolve())], CouldNotParseMCPConfig)
    assert set(dict(result[str(path.resolve())])) == {"remote"}
    assert any(desktop.discover_skills().values())


def test_windows_plugins_are_not_guessed(tmp_path, monkeypatch):
    monkeypatch.setattr(claude_desktop.sys, "platform", "win32")
    desktop = claude_desktop.ClaudeDesktopDiscoverer(tmp_path)
    add_skill(install_plugin(desktop))
    assert desktop.discover_skills() == {}
    assert desktop.discover_mcp_servers() == {}
