import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from agent_scan.agents import claude_desktop
from agent_scan.agents.base import _MAX_CONFIG_FILE_BYTES


@pytest.fixture
def desktop(tmp_path, monkeypatch):
    monkeypatch.setattr(claude_desktop.sys, "platform", "darwin")
    return claude_desktop.ClaudeDesktopDiscoverer(tmp_path)


def connector(uuid="connector", **fields):
    return {"uuid": uuid, "name": "Slack", "url": "https://example.com/mcp", **fields}


def write_session(
    desktop, entries, *, directory="claude-code-sessions", account="account", org="org", session="one", **fields
):
    path = desktop._install_dir() / directory / account / org / f"local_{session}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"remoteMcpServersConfig": entries, **fields}), encoding="utf-8")
    return path


def test_both_session_directories_are_grouped_by_org_and_deduplicated_across_accounts(desktop):
    write_session(desktop, [connector()], lastActivityAt=100)
    write_session(desktop, [connector()], account="another", lastActivityAt=200)
    write_session(desktop, [connector("cowork")], directory="local-agent-mode-sessions")
    write_session(desktop, [connector(name="Other org")], org="other")

    result = desktop.discover_logged_mcp_servers()

    assert sorted(result["org"], key=lambda entry: entry["uuid"]) == [connector(), connector("cowork")]
    assert result["other"] == [connector(name="Other org")]


@pytest.mark.parametrize(
    "older_fields,newer_fields,older_mtime,newer_mtime",
    [
        ({"lastActivityAt": 100, "createdAt": 300}, {"lastActivityAt": 200, "createdAt": 100}, 300, 100),
        ({"lastActivityAt": 200, "createdAt": 100}, {"lastActivityAt": 200, "createdAt": 300}, 300, 100),
        ({}, {}, 100, 300),
        ({"lastActivityAt": None, "createdAt": "invalid"}, {}, 100, 300),
    ],
)
def test_newest_session_wins_by_activity_then_creation_then_mtime(
    desktop, older_fields, newer_fields, older_mtime, newer_mtime
):
    older = write_session(desktop, [connector(name="Old")], session="older", **older_fields)
    newer = write_session(desktop, [connector(name="New")], session="newer", **newer_fields)
    os.utime(older, (older_mtime, older_mtime))
    os.utime(newer, (newer_mtime, newer_mtime))

    assert desktop.discover_logged_mcp_servers() == {"org": [connector(name="New")]}


def test_url_query_is_redacted_and_entire_entry_is_preserved(desktop):
    entry = connector(
        url="https://example.com/mcp?token=secret&region=eu",
        tools=[{"name": "read", "description": "Read something", "inputSchema": {"type": "object"}}],
        instructions="Use this connector to read messages",
        extra={"future": True},
    )
    path = write_session(desktop, [entry])

    result = desktop.discover_logged_mcp_servers()["org"][0]

    assert parse_qs(urlsplit(result["url"]).query) == {"token": ["**REDACTED**"], "region": ["**REDACTED**"]}
    assert result == {**entry, "url": result["url"]}
    assert json.loads(path.read_text())["remoteMcpServersConfig"] == [entry]


@pytest.mark.parametrize(
    "bad_entry", [None, [], "bad", {}, {"uuid": 1, "url": "https://example.com"}, {"uuid": "x", "url": None}]
)
def test_invalid_entries_do_not_hide_valid_siblings(desktop, bad_entry):
    write_session(desktop, [bad_entry, connector()])
    assert desktop.discover_logged_mcp_servers() == {"org": [connector()]}


@pytest.mark.parametrize("bad_content", ["{broken", "[]", "null", "", '{"remoteMcpServersConfig": {}}'])
def test_malformed_session_does_not_hide_valid_files(desktop, bad_content):
    write_session(desktop, [connector()], session="good")
    bad = write_session(desktop, [], session="bad")
    bad.write_text(bad_content)
    assert desktop.discover_logged_mcp_servers() == {"org": [connector()]}


def test_oversized_session_is_skipped(desktop):
    write_session(desktop, [connector()], session="good")
    oversized = write_session(desktop, [connector("oversized")], session="oversized")
    with oversized.open("ab") as stream:
        stream.truncate(_MAX_CONFIG_FILE_BYTES + 1)
    assert desktop.discover_logged_mcp_servers() == {"org": [connector()]}


@pytest.mark.parametrize("level", ["file", "org", "account", "sessions"])
def test_symlinked_session_or_parent_is_skipped(desktop, tmp_path, level):
    write_session(desktop, [connector()], directory="local-agent-mode-sessions")
    source = write_session(desktop, [connector("symlink")])
    link = {"file": source, "org": source.parent, "account": source.parent.parent, "sessions": source.parents[2]}[level]
    target = tmp_path / "outside"
    link.rename(target)
    link.symlink_to(target, target_is_directory=level != "file")
    assert desktop.discover_logged_mcp_servers() == {"org": [connector()]}


@pytest.mark.parametrize("error", [PermissionError, OSError, RuntimeError, ValueError])
def test_unreadable_session_does_not_hide_valid_files(desktop, monkeypatch, error):
    write_session(desktop, [connector()], session="good")
    bad = write_session(desktop, [connector("bad")], session="bad")
    original_stat = Path.stat

    def stat(path, *args, **kwargs):
        if path == bad:
            raise error("Cannot access session")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", stat)
    assert desktop.discover_logged_mcp_servers() == {"org": [connector()]}


def test_linux_returns_no_connectors(desktop, monkeypatch):
    write_session(desktop, [connector()])
    monkeypatch.setattr(claude_desktop.sys, "platform", "linux")
    assert desktop.discover_logged_mcp_servers() == {}


def test_windows_session_layout_is_supported(desktop, monkeypatch):
    monkeypatch.setattr(claude_desktop.sys, "platform", "win32")
    write_session(desktop, [connector()])
    write_session(desktop, [connector("cowork")], directory="local-agent-mode-sessions")
    assert desktop.discover_logged_mcp_servers() == {"org": [connector(), connector("cowork")]}


def test_missing_install_returns_no_connectors(desktop):
    assert desktop.discover_logged_mcp_servers() == {}
