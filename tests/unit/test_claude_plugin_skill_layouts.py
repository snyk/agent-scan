import json

import pytest

from agent_scan.agents.claude_code import ClaudeCodeDiscoverer
from agent_scan.agents.claude_desktop import ClaudeDesktopDiscoverer


def skill(path):
    path.mkdir(parents=True, exist_ok=True)
    (path / "SKILL.md").write_text("---\nname: example\ndescription: Example\n---\nInstructions")
    return path


def entries(discoverer):
    return [entry for group in discoverer.discover_skills().values() if isinstance(group, list) for entry in group]


@pytest.fixture(params=["code", "desktop"])
def plugin(tmp_path, request, monkeypatch):
    if request.param == "code":
        discoverer = ClaudeCodeDiscoverer(tmp_path)
        root = tmp_path / ".claude/plugins/cache/market/plugin/1.2.3"
    else:
        monkeypatch.setattr("agent_scan.agents.claude_desktop.sys.platform", "linux")
        discoverer = ClaudeDesktopDiscoverer(tmp_path)
        root = tmp_path / "installed-plugin"
        monkeypatch.setattr(discoverer, "_plugin_base_dirs", lambda: [root])
    root.mkdir(parents=True)
    return discoverer, root


def test_manifest_individual_skills_and_containers_exclude_drafts(plugin):
    discoverer, root = plugin
    expected = [
        skill(root / "skills/engineering/tdd"),
        skill(root / "skills/productivity/grill-me"),
        skill(root / "skills/standard"),
        skill(root / "custom/container/member"),
    ]
    skill(root / "skills/in-progress/draft")
    skill(root / "skills/misc/unlisted")
    manifest = root / ".claude-plugin/plugin.json"
    manifest.parent.mkdir()
    manifest.write_text(
        json.dumps(
            {
                "skills": [
                    "./skills/engineering/tdd",
                    "./skills/productivity/grill-me",
                    "./skills/standard",
                    "./custom/container",
                    "./skills/engineering/tdd",
                ]
            }
        )
    )
    found = entries(discoverer)
    assert sorted(entry.path for entry in found) == sorted(str(path) for path in expected)
    assert {entry.name for entry in found} == {path.name for path in expected}


def test_root_skill_without_manifest(plugin):
    discoverer, root = plugin
    skill(root)
    found = entries(discoverer)
    assert [(entry.name, entry.path) for entry in found] == [
        ("plugin" if root.name == "1.2.3" else root.name, str(root))
    ]


@pytest.mark.parametrize("base", ["cache", "repos", "synced"])
def test_version_root_skill(tmp_path, base):
    root = skill(tmp_path / f".claude/plugins/{base}/terrashark/terrashark/2.3.0")
    found = entries(ClaudeCodeDiscoverer(tmp_path))
    assert [(entry.name, entry.path) for entry in found] == [("terrashark", str(root))]


@pytest.mark.parametrize("location", ["in-place", ".claude/plugins/cache/custom"])
def test_registry_root_skill(tmp_path, location):
    root = skill(tmp_path / location)
    registry = tmp_path / ".claude/plugins/installed_plugins.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(json.dumps({"version": 2, "plugins": {"example@market": [{"installPath": str(root)}]}}))
    assert [entry.path for entry in entries(ClaudeCodeDiscoverer(tmp_path))] == [str(root)]


def test_root_skill_and_manifest_reference_are_deduplicated(plugin):
    discoverer, root = plugin
    skill(root)
    manifest = root / ".claude-plugin/plugin.json"
    manifest.parent.mkdir()
    manifest.write_text(json.dumps({"skills": ["."]}))
    assert [entry.path for entry in entries(discoverer)] == [str(root)]


def test_desktop_rejects_root_skill_marker_outside_boundary(tmp_path, monkeypatch):
    root = tmp_path / "plugin"
    root.mkdir()
    outside = skill(tmp_path / "outside")
    (root / "SKILL.md").symlink_to(outside / "SKILL.md")
    discoverer = ClaudeDesktopDiscoverer(tmp_path)
    monkeypatch.setattr(discoverer, "_plugin_base_dirs", lambda: [root])
    assert entries(discoverer) == []


def test_root_skill_walk_does_not_follow_directory_symlinks(tmp_path):
    root = tmp_path / ".claude/plugins/cache/market/plugin"
    root.mkdir(parents=True)
    outside = skill(tmp_path / "outside")
    (root / "1.2.3").symlink_to(outside, target_is_directory=True)
    assert entries(ClaudeCodeDiscoverer(tmp_path)) == []
