"""Tests for glob expansion of skills_dir_paths and discover_cowork_skills_dirs."""

import json
import os
import tempfile
import time
import uuid

import pytest

from agent_scan.inspect import get_mcp_config_per_client
from agent_scan.models import CandidateClient, FileNotFoundConfig
from agent_scan.well_known_clients import discover_cowork_skills_dirs


SKILL_MD_CONTENT = """\
---
name: test-skill
description: A test skill for unit testing glob expansion.
---

# Test Skill

This skill exists only for testing purposes.
"""


def _make_skill_dir(parent: str, skill_name: str = "my-skill") -> str:
    """Create a minimal skill directory with a SKILL.md inside parent."""
    skill_path = os.path.join(parent, skill_name)
    os.makedirs(skill_path, exist_ok=True)
    with open(os.path.join(skill_path, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(SKILL_MD_CONTENT)
    return skill_path


@pytest.mark.asyncio
async def test_glob_expansion_finds_nested_dxt_skills():
    """Skills under {uuid1}/{uuid2}/skills/ are discovered when the path uses wildcards."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dxt_uuid = str(uuid.uuid4())
        session_uuid = str(uuid.uuid4())
        skills_dir = os.path.join(tmpdir, dxt_uuid, session_uuid, "skills")
        os.makedirs(skills_dir, exist_ok=True)
        _make_skill_dir(skills_dir, "my-dxt-skill")

        glob_pattern = os.path.join(tmpdir, "*", "*", "skills")
        # Use a real directory for client_exists_paths
        client = CandidateClient(
            name="test-client",
            client_exists_paths=[tmpdir],
            mcp_config_paths=[],
            skills_dir_paths=[glob_pattern],
        )

        result = await get_mcp_config_per_client(client)

        assert result is not None
        # The resolved path (not the pattern) should be the key
        assert glob_pattern not in result.skills_dirs
        assert skills_dir in result.skills_dirs
        entries = result.skills_dirs[skills_dir]
        assert not isinstance(entries, FileNotFoundConfig)
        skill_names = [name for name, _ in entries]
        assert "my-dxt-skill" in skill_names


@pytest.mark.asyncio
async def test_glob_expansion_missing_path_returns_file_not_found():
    """A pattern that matches nothing produces a FileNotFoundConfig entry."""
    with tempfile.TemporaryDirectory() as tmpdir:
        glob_pattern = os.path.join(tmpdir, "*", "*", "skills")
        client = CandidateClient(
            name="test-client",
            client_exists_paths=[tmpdir],
            mcp_config_paths=[],
            skills_dir_paths=[glob_pattern],
        )

        result = await get_mcp_config_per_client(client)

        assert result is not None
        assert glob_pattern in result.skills_dirs
        assert isinstance(result.skills_dirs[glob_pattern], FileNotFoundConfig)


@pytest.mark.asyncio
async def test_glob_expansion_plain_path_still_works():
    """A plain (non-glob) path continues to work as before."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skills_dir = os.path.join(tmpdir, "skills")
        os.makedirs(skills_dir, exist_ok=True)
        _make_skill_dir(skills_dir, "plain-skill")

        client = CandidateClient(
            name="test-client",
            client_exists_paths=[tmpdir],
            mcp_config_paths=[],
            skills_dir_paths=[skills_dir],
        )

        result = await get_mcp_config_per_client(client)

        assert result is not None
        assert skills_dir in result.skills_dirs
        entries = result.skills_dirs[skills_dir]
        assert not isinstance(entries, FileNotFoundConfig)
        skill_names = [name for name, _ in entries]
        assert "plain-skill" in skill_names


@pytest.mark.asyncio
async def test_glob_expansion_multiple_matches():
    """Multiple directories matching a glob pattern are all discovered."""
    with tempfile.TemporaryDirectory() as tmpdir:
        plugin_pattern = os.path.join(tmpdir, "*", "*", "*")
        # Create two plugin skill directories
        for marketplace in ("official", "community"):
            for plugin in ("plugin-a", "plugin-b"):
                version_dir = os.path.join(tmpdir, marketplace, plugin, "1.0.0")
                os.makedirs(version_dir, exist_ok=True)
                _make_skill_dir(version_dir, "skill")

        client = CandidateClient(
            name="test-client",
            client_exists_paths=[tmpdir],
            mcp_config_paths=[],
            skills_dir_paths=[plugin_pattern],
        )

        result = await get_mcp_config_per_client(client)

        assert result is not None
        # Pattern itself should not be a key; resolved dirs should be
        assert plugin_pattern not in result.skills_dirs
        resolved_paths = list(result.skills_dirs.keys())
        assert len(resolved_paths) == 4  # official/{a,b}/1.0.0 + community/{a,b}/1.0.0


# ── discover_cowork_skills_dirs tests ────────────────────────────────────────


def test_discover_cowork_dxt_picks_newest_session(monkeypatch, tmp_path):
    """Only the session with the newest manifest.json mtime is returned per DXT UUID."""
    skills_plugin_base = tmp_path / "skills-plugin"
    dxt_dir = skills_plugin_base / str(uuid.uuid4())

    old_session = dxt_dir / "old-session"
    new_session = dxt_dir / "new-session"
    for session in (old_session, new_session):
        (session / "skills").mkdir(parents=True)
        (session / "manifest.json").write_text("{}")

    # Make old_session clearly older
    old_time = time.time() - 1000
    os.utime(old_session / "manifest.json", (old_time, old_time))

    _real = os.path.expanduser
    monkeypatch.setattr(
        "agent_scan.well_known_clients.os.path.expanduser",
        lambda p: str(skills_plugin_base) if "local-agent-mode-sessions" in p
        else str(tmp_path / "nonexistent_plugins.json") if "installed_plugins.json" in p
        else _real(p),
    )

    result = discover_cowork_skills_dirs()
    assert len(result) == 1
    assert result[0] == str(new_session / "skills")


def test_discover_cowork_dxt_skips_session_without_skills_dir(monkeypatch, tmp_path):
    """Sessions whose skills/ dir doesn't exist are skipped."""
    skills_plugin_base = tmp_path / "skills-plugin"
    dxt_dir = skills_plugin_base / str(uuid.uuid4())
    session = dxt_dir / "session-no-skills"
    session.mkdir(parents=True)
    (session / "manifest.json").write_text("{}")
    # No skills/ subdir created

    _real = os.path.expanduser
    monkeypatch.setattr(
        "agent_scan.well_known_clients.os.path.expanduser",
        lambda p: str(skills_plugin_base) if "local-agent-mode-sessions" in p
        else str(tmp_path / "nonexistent_plugins.json") if "installed_plugins.json" in p
        else _real(p),
    )

    result = discover_cowork_skills_dirs()
    assert result == []


def test_discover_cowork_plugins_json(monkeypatch, tmp_path):
    """Skills discovered via installed_plugins.json installPath are returned."""
    plugin_install = tmp_path / "my-plugin"
    skills_dir = plugin_install / "skills"
    skills_dir.mkdir(parents=True)

    plugins_json = tmp_path / "installed_plugins.json"
    plugins_json.write_text(json.dumps({
        "plugins": {
            "my-plugin": [{"installPath": str(plugin_install)}]
        }
    }))

    _real = os.path.expanduser

    def fake_expanduser(p: str) -> str:
        if "local-agent-mode-sessions" in p:
            return str(tmp_path / "nonexistent")
        if "installed_plugins.json" in p:
            return str(plugins_json)
        return _real(p)

    monkeypatch.setattr("agent_scan.well_known_clients.os.path.expanduser", fake_expanduser)

    result = discover_cowork_skills_dirs()
    assert str(skills_dir) in result


def test_discover_cowork_plugins_json_missing_skills_subdir(monkeypatch, tmp_path):
    """A plugin installPath without a skills/ subdir is skipped."""
    plugin_install = tmp_path / "no-skills-plugin"
    plugin_install.mkdir()
    # No skills/ subdir

    plugins_json = tmp_path / "installed_plugins.json"
    plugins_json.write_text(json.dumps({
        "plugins": {
            "no-skills-plugin": [{"installPath": str(plugin_install)}]
        }
    }))

    _real = os.path.expanduser

    def fake_expanduser(p: str) -> str:
        if "local-agent-mode-sessions" in p:
            return str(tmp_path / "nonexistent")
        if "installed_plugins.json" in p:
            return str(plugins_json)
        return _real(p)

    monkeypatch.setattr("agent_scan.well_known_clients.os.path.expanduser", fake_expanduser)

    result = discover_cowork_skills_dirs()
    assert result == []


def test_discover_cowork_plugins_json_corrupt(monkeypatch, tmp_path):
    """A corrupt installed_plugins.json is handled gracefully (no exception raised)."""
    plugins_json = tmp_path / "installed_plugins.json"
    plugins_json.write_text("not valid json{{{")

    _real = os.path.expanduser

    def fake_expanduser(p: str) -> str:
        if "local-agent-mode-sessions" in p:
            return str(tmp_path / "nonexistent")
        if "installed_plugins.json" in p:
            return str(plugins_json)
        return _real(p)

    monkeypatch.setattr("agent_scan.well_known_clients.os.path.expanduser", fake_expanduser)

    result = discover_cowork_skills_dirs()
    assert result == []
