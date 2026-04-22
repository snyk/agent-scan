"""Tests for agent_scan.guard — install, uninstall, detect for Claude Code and Cursor."""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_scan.guard import (
    _PERMISSION_DENIED,
    CLAUDE_EVENTS_WITH_MATCHER,
    CLAUDE_HOOK_EVENTS,
    CLAUDE_MANAGED_SETTINGS_PATH,
    CLAUDE_SETTINGS_PATH,
    CURSOR_HOOK_EVENTS,
    CURSOR_HOOKS_PATH,
    CURSOR_MANAGED_HOOKS_PATH,
    _build_hook_command,
    _build_hook_command_powershell,
    _compact_events,
    _config_path,
    _detect_claude_install,
    _detect_cursor_install,
    _ensure_guard_enabled_for_tenant,
    _extract_env_from_cmd,
    _filter_claude_hooks,
    _filter_cursor_hooks,
    _install_claude,
    _install_cursor,
    _is_agent_scan_command,
    _mask_key,
    _parse_command_info,
    _preflight_writable,
    _print_client_status,
    _run_install,
    _shell_quote,
    _uninstall_claude,
    _uninstall_cursor,
)
from agent_scan.pushkeys import GuardEnabledAccessDeniedError

# ---------------------------------------------------------------------------
# Helpers to build hook data
# ---------------------------------------------------------------------------

AGENT_SCAN_CMD = (
    "PUSH_KEY='pk-1234' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' "
    "TENANT_ID='tid-1' bash '/home/u/.claude/hooks/snyk-agent-guard.sh' --client claude-code"
)

OTHER_CMD = "some-other-tool hook --client claude-code"

AGENTGUARD_CMD = (
    "PUSH_KEY='pk-old' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' "
    "'/usr/local/bin/agentguard' hook --client claude-code"
)


def _claude_group(command: str, matcher: str | None = None) -> dict:
    g: dict = {"hooks": [{"type": "command", "command": command}]}
    if matcher:
        g["matcher"] = matcher
    return g


def _cursor_entry(command: str) -> dict:
    return {"command": command}


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


# ===================================================================
# Unit tests for pure helpers
# ===================================================================


class TestIsAgentScanCommand:
    def test_matches_snyk_agent_guard_in_path(self):
        assert _is_agent_scan_command("bash /home/u/.claude/hooks/snyk-agent-guard.sh")

    def test_matches_agent_scan_marker_in_env(self):
        assert _is_agent_scan_command("PUSH_KEY='x' bash snyk-agent-guard.sh --client c")

    def test_no_match_other_tool(self):
        assert not _is_agent_scan_command("some-other-tool hook --client claude")

    def test_no_match_agentguard(self):
        assert not _is_agent_scan_command("/usr/local/bin/agentguard hook --client claude-code")

    def test_no_match_empty(self):
        assert not _is_agent_scan_command("")


class TestShellQuote:
    def test_simple(self):
        assert _shell_quote("hello") == "'hello'"

    def test_with_single_quote(self):
        assert _shell_quote("it's") == "'it'\"'\"'s'"

    def test_empty(self):
        assert _shell_quote("") == "''"


class TestMaskKey:
    def test_short_key(self):
        assert _mask_key("abcd") == "abcd"

    def test_exactly_8(self):
        assert _mask_key("12345678") == "12345678"

    def test_long_key(self):
        assert _mask_key("abcdefghijklmnop") == "abcd...mnop"


class TestCompactEvents:
    def test_empty(self):
        assert _compact_events([]) == "(no hooks)"

    def test_one(self):
        assert _compact_events(["A"]) == "(A)"

    def test_two(self):
        assert _compact_events(["A", "B"]) == "(A, B)"

    def test_three(self):
        assert _compact_events(["A", "B", "C"]) == "(A, B + 1 more)"

    def test_nine(self):
        assert _compact_events(list("ABCDEFGHI")) == "(A, B + 7 more)"


class TestExtractEnvFromCmd:
    def test_single_quoted(self):
        assert _extract_env_from_cmd("PUSH_KEY='abc-123' bash x", "PUSH_KEY") == "abc-123"

    def test_unquoted(self):
        assert _extract_env_from_cmd("PUSH_KEY=abc123 bash x", "PUSH_KEY") == "abc123"

    def test_missing(self):
        assert _extract_env_from_cmd("bash x", "PUSH_KEY") == ""

    def test_multiple_keys(self):
        cmd = "PUSH_KEY='pk' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash x"
        assert _extract_env_from_cmd(cmd, "PUSH_KEY") == "pk"
        assert _extract_env_from_cmd(cmd, "REMOTE_HOOKS_BASE_URL") == "https://api.snyk.io"

    def test_tenant_id(self):
        cmd = "PUSH_KEY='pk' TENANT_ID='tid-1' bash x"
        assert _extract_env_from_cmd(cmd, "TENANT_ID") == "tid-1"


class TestBuildHookCommand:
    @pytest.mark.skipif(sys.platform == "win32", reason="bash command format")
    def test_without_tenant_bash(self):
        cmd = _build_hook_command("pk", "https://api.snyk.io", Path("/x/hook.sh"), "claude-code")
        assert "PUSH_KEY='pk'" in cmd
        assert "REMOTE_HOOKS_BASE_URL='https://api.snyk.io'" in cmd
        assert "TENANT_ID" not in cmd
        assert "bash '/x/hook.sh'" in cmd
        assert "--client claude-code" in cmd

    @pytest.mark.skipif(sys.platform == "win32", reason="bash command format")
    def test_with_tenant_bash(self):
        cmd = _build_hook_command("pk", "https://api.snyk.io", Path("/x/hook.sh"), "cursor", tenant_id="tid")
        assert "TENANT_ID='tid'" in cmd

    @pytest.mark.skipif(sys.platform != "win32", reason="powershell command format")
    def test_without_tenant_powershell(self):
        cmd = _build_hook_command("pk", "https://api.snyk.io", Path("/x/hook.ps1"), "claude-code")
        assert "-PushKey 'pk'" in cmd
        assert "-RemoteUrl 'https://api.snyk.io'" in cmd
        assert "powershell -File" in cmd
        assert "-Client claude-code" in cmd

    @pytest.mark.skipif(sys.platform != "win32", reason="powershell command format")
    def test_without_tenant_powershell_no_tenant_id(self):
        cmd = _build_hook_command("pk", "https://api.snyk.io", Path("/x/hook.ps1"), "claude-code")
        assert "TENANT_ID" not in cmd

    def test_roundtrip_extract(self):
        cmd = _build_hook_command(
            "my-key", "https://example.com", Path("/x/snyk-agent-guard.sh"), "claude-code", tenant_id="t-1"
        )
        assert _extract_env_from_cmd(cmd, "PUSH_KEY") == "my-key"
        assert _extract_env_from_cmd(cmd, "REMOTE_HOOKS_BASE_URL") == "https://example.com"
        # tenant_id is only in bash commands, not powershell
        if sys.platform != "win32":
            assert _extract_env_from_cmd(cmd, "TENANT_ID") == "t-1"


class TestParseCommandInfo:
    def test_full_command(self):
        info = _parse_command_info(AGENT_SCAN_CMD, ["PreToolUse", "Stop"])
        assert info["host"] == "api.snyk.io"
        assert info["auth_value"] == "pk-1234"
        assert info["tenant_id"] == "tid-1"
        assert info["events"] == ["PreToolUse", "Stop"]

    def test_no_tenant(self):
        cmd = "PUSH_KEY='pk' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash snyk-agent-guard.sh --client c"
        info = _parse_command_info(cmd, ["Stop"])
        assert info["tenant_id"] == ""


# ===================================================================
# Claude Code: install
# ===================================================================


class TestInstallClaude:
    def test_creates_file_when_missing(self, tmp_path):
        path = tmp_path / "settings.json"
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        hooks = data["hooks"]
        assert set(hooks.keys()) == set(CLAUDE_HOOK_EVENTS)
        for event in CLAUDE_HOOK_EVENTS:
            groups = hooks[event]
            assert len(groups) == 1
            assert groups[0]["hooks"][0]["command"] == AGENT_SCAN_CMD
            if event in CLAUDE_EVENTS_WITH_MATCHER:
                assert groups[0]["matcher"] == "*"
            else:
                assert "matcher" not in groups[0]

    def test_preserves_other_top_level_keys(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"allowedTools": ["Bash"], "theme": "dark"})
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert data["allowedTools"] == ["Bash"]
        assert data["theme"] == "dark"
        assert "hooks" in data

    def test_preserves_other_hooks(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(OTHER_CMD, "*")],
                    "Stop": [_claude_group(OTHER_CMD)],
                }
            },
        )
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        # PreToolUse should have the other hook + our hook
        groups = data["hooks"]["PreToolUse"]
        assert len(groups) == 2
        assert groups[0]["hooks"][0]["command"] == OTHER_CMD
        assert groups[1]["hooks"][0]["command"] == AGENT_SCAN_CMD

    def test_replaces_old_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "settings.json"
        old_cmd = AGENT_SCAN_CMD.replace("pk-1234", "pk-old")
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(old_cmd, "*")],
                    "Stop": [_claude_group(old_cmd)],
                }
            },
        )
        new_cmd = AGENT_SCAN_CMD.replace("pk-1234", "pk-new")
        _install_claude(new_cmd, path)

        data = json.loads(path.read_text())
        # Old hooks replaced, not duplicated
        for event in CLAUDE_HOOK_EVENTS:
            groups = data["hooks"][event]
            assert len(groups) == 1
            assert groups[0]["hooks"][0]["command"] == new_cmd

    def test_preserves_agentguard_hooks(self, tmp_path):
        """agentguard (Go CLI) hooks should not be touched."""
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(AGENTGUARD_CMD, "*")],
                }
            },
        )
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        groups = data["hooks"]["PreToolUse"]
        assert len(groups) == 2
        assert groups[0]["hooks"][0]["command"] == AGENTGUARD_CMD
        assert groups[1]["hooks"][0]["command"] == AGENT_SCAN_CMD

    def test_idempotent_no_rewrite(self, tmp_path):
        path = tmp_path / "settings.json"
        _install_claude(AGENT_SCAN_CMD, path)
        mtime1 = path.stat().st_mtime_ns

        _install_claude(AGENT_SCAN_CMD, path)
        mtime2 = path.stat().st_mtime_ns
        assert mtime1 == mtime2, "File should not have been rewritten"

    def test_backup_created_on_change(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"existing": True})
        _install_claude(AGENT_SCAN_CMD, path)

        backup = Path(str(path) + ".backup")
        assert backup.exists()
        backup_data = json.loads(backup.read_text())
        assert backup_data == {"existing": True}

    def test_no_backup_when_file_missing(self, tmp_path):
        path = tmp_path / "settings.json"
        _install_claude(AGENT_SCAN_CMD, path)

        backup = Path(str(path) + ".backup")
        assert not backup.exists()

    def test_empty_hooks_object(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"hooks": {}})
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]) == len(CLAUDE_HOOK_EVENTS)

    def test_partial_hooks_existing(self, tmp_path):
        """File has hooks for only some events."""
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(OTHER_CMD, "*")],
                }
            },
        )
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert set(data["hooks"].keys()) == set(CLAUDE_HOOK_EVENTS)
        # PreToolUse has both
        assert len(data["hooks"]["PreToolUse"]) == 2

    def test_extra_unknown_events_preserved(self, tmp_path):
        """Hooks for events we don't manage should be left alone."""
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "FutureEvent": [_claude_group(OTHER_CMD)],
                }
            },
        )
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert "FutureEvent" in data["hooks"]
        assert data["hooks"]["FutureEvent"][0]["hooks"][0]["command"] == OTHER_CMD

    def test_deprecated_agent_scan_events_removed(self, tmp_path):
        """Old agent-scan hooks for events no longer in our list get cleaned up."""
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "DeprecatedEvent": [_claude_group(AGENT_SCAN_CMD)],
                    "PreToolUse": [_claude_group(AGENT_SCAN_CMD, "*")],
                }
            },
        )
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert "DeprecatedEvent" not in data["hooks"]
        assert "PreToolUse" in data["hooks"]

    def test_deprecated_event_preserves_other_hooks(self, tmp_path):
        """Deprecated event with mixed hooks: agent-scan removed, others kept."""
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "DeprecatedEvent": [
                        _claude_group(OTHER_CMD),
                        _claude_group(AGENT_SCAN_CMD),
                    ],
                }
            },
        )
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert "DeprecatedEvent" in data["hooks"]
        assert len(data["hooks"]["DeprecatedEvent"]) == 1
        assert data["hooks"]["DeprecatedEvent"][0]["hooks"][0]["command"] == OTHER_CMD


# ===================================================================
# Claude Code: uninstall
# ===================================================================


class TestUninstallClaude:
    def test_missing_file(self, tmp_path):
        path = tmp_path / "settings.json"
        _uninstall_claude(path)  # should not raise

    def test_no_hooks_key(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"allowedTools": ["Bash"]})
        _uninstall_claude(path)

        data = json.loads(path.read_text())
        assert data == {"allowedTools": ["Bash"]}

    def test_no_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(OTHER_CMD, "*")]}})
        _uninstall_claude(path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1

    def test_removes_only_agent_scan(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [
                        _claude_group(OTHER_CMD, "*"),
                        _claude_group(AGENT_SCAN_CMD, "*"),
                    ],
                    "Stop": [_claude_group(AGENT_SCAN_CMD)],
                }
            },
        )
        _uninstall_claude(path)

        data = json.loads(path.read_text())
        # PreToolUse keeps the other hook
        assert len(data["hooks"]["PreToolUse"]) == 1
        assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == OTHER_CMD
        # Stop was only agent-scan, so the event key is removed
        assert "Stop" not in data["hooks"]

    def test_removes_hooks_key_when_empty(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(AGENT_SCAN_CMD, "*")],
                }
            },
        )
        _uninstall_claude(path)

        data = json.loads(path.read_text())
        assert "hooks" not in data

    def test_preserves_agentguard(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [
                        _claude_group(AGENTGUARD_CMD, "*"),
                        _claude_group(AGENT_SCAN_CMD, "*"),
                    ],
                }
            },
        )
        _uninstall_claude(path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1
        assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == AGENTGUARD_CMD

    def test_backup_created(self, tmp_path):
        path = tmp_path / "settings.json"
        original = {"hooks": {"Stop": [_claude_group(AGENT_SCAN_CMD)]}}
        _write(path, original)
        _uninstall_claude(path)

        backup = Path(str(path) + ".backup")
        assert backup.exists()
        assert json.loads(backup.read_text()) == original

    def test_full_install_then_uninstall(self, tmp_path):
        """Install all events, then uninstall — should leave a clean file."""
        path = tmp_path / "settings.json"
        _write(path, {"allowedTools": ["Bash"]})
        _install_claude(AGENT_SCAN_CMD, path)
        _uninstall_claude(path)

        data = json.loads(path.read_text())
        assert "hooks" not in data
        assert data["allowedTools"] == ["Bash"]


# ===================================================================
# Claude Code: detect
# ===================================================================


class TestDetectClaude:
    def test_missing_file(self, tmp_path):
        assert _detect_claude_install(tmp_path / "nope.json") is None

    def test_empty_file(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {})
        assert _detect_claude_install(path) is None

    def test_no_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(OTHER_CMD, "*")]}})
        assert _detect_claude_install(path) is None

    def test_detects_installed(self, tmp_path):
        path = tmp_path / "settings.json"
        _install_claude(AGENT_SCAN_CMD, path)

        info = _detect_claude_install(path)
        assert info is not None
        assert info["host"] == "api.snyk.io"
        assert info["auth_value"] == "pk-1234"
        assert info["tenant_id"] == "tid-1"
        assert len(info["events"]) == len(CLAUDE_HOOK_EVENTS)

    def test_detects_partial_install(self, tmp_path):
        """Only some events have our hooks."""
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(AGENT_SCAN_CMD, "*")],
                    "Stop": [_claude_group(AGENT_SCAN_CMD)],
                }
            },
        )
        info = _detect_claude_install(path)
        assert info is not None
        assert info["events"] == ["PreToolUse", "Stop"]

    def test_ignores_agentguard(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(AGENTGUARD_CMD, "*")]}})
        assert _detect_claude_install(path) is None

    def test_detects_among_other_hooks(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [
                        _claude_group(AGENTGUARD_CMD, "*"),
                        _claude_group(AGENT_SCAN_CMD, "*"),
                    ],
                }
            },
        )
        info = _detect_claude_install(path)
        assert info is not None
        assert info["events"] == ["PreToolUse"]

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "settings.json"
        path.write_text("not json at all")
        with pytest.raises(json.JSONDecodeError):
            _detect_claude_install(path)


# ===================================================================
# Cursor: install
# ===================================================================

CURSOR_AGENT_SCAN_CMD = (
    "PUSH_KEY='pk-1234' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' "
    "TENANT_ID='tid-1' bash '/home/u/.cursor/hooks/snyk-agent-guard.sh' --client cursor"
)

CURSOR_OTHER_CMD = "some-other-cursor-hook --flag"

CURSOR_AGENTGUARD_CMD = (
    "PUSH_KEY='pk-old' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' '/usr/local/bin/agentguard' hook --client cursor"
)


class TestInstallCursor:
    def test_creates_file_when_missing(self, tmp_path):
        path = tmp_path / "hooks.json"
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert data["version"] == 1
        hooks = data["hooks"]
        assert set(hooks.keys()) == set(CURSOR_HOOK_EVENTS)
        for event in CURSOR_HOOK_EVENTS:
            entries = hooks[event]
            assert len(entries) == 1
            assert entries[0]["command"] == CURSOR_AGENT_SCAN_CMD

    def test_preserves_version(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 2, "hooks": {}})
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert data["version"] == 2

    def test_adds_version_if_missing(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {}})
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert data["version"] == 1

    def test_preserves_other_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "beforeSubmitPrompt": [_cursor_entry(CURSOR_OTHER_CMD)],
                },
            },
        )
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        entries = data["hooks"]["beforeSubmitPrompt"]
        assert len(entries) == 2
        assert entries[0]["command"] == CURSOR_OTHER_CMD
        assert entries[1]["command"] == CURSOR_AGENT_SCAN_CMD

    def test_replaces_old_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        old_cmd = CURSOR_AGENT_SCAN_CMD.replace("pk-1234", "pk-old")
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "beforeSubmitPrompt": [_cursor_entry(old_cmd)],
                    "stop": [_cursor_entry(old_cmd)],
                },
            },
        )
        new_cmd = CURSOR_AGENT_SCAN_CMD.replace("pk-1234", "pk-new")
        _install_cursor(new_cmd, path)

        data = json.loads(path.read_text())
        for event in CURSOR_HOOK_EVENTS:
            entries = data["hooks"][event]
            assert len(entries) == 1
            assert entries[0]["command"] == new_cmd

    def test_preserves_agentguard_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "beforeSubmitPrompt": [_cursor_entry(CURSOR_AGENTGUARD_CMD)],
                },
            },
        )
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        entries = data["hooks"]["beforeSubmitPrompt"]
        assert len(entries) == 2
        assert entries[0]["command"] == CURSOR_AGENTGUARD_CMD

    def test_idempotent_no_rewrite(self, tmp_path):
        path = tmp_path / "hooks.json"
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)
        mtime1 = path.stat().st_mtime_ns

        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)
        mtime2 = path.stat().st_mtime_ns
        assert mtime1 == mtime2

    def test_backup_created_on_change(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {}})
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        backup = Path(str(path) + ".backup")
        assert backup.exists()

    def test_empty_hooks_object(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {}})
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]) == len(CURSOR_HOOK_EVENTS)

    def test_partial_hooks_existing(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "stop": [_cursor_entry(CURSOR_OTHER_CMD)],
                },
            },
        )
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert set(data["hooks"].keys()) == set(CURSOR_HOOK_EVENTS)
        assert len(data["hooks"]["stop"]) == 2

    def test_extra_unknown_events_preserved(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "futureEvent": [_cursor_entry(CURSOR_OTHER_CMD)],
                },
            },
        )
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert "futureEvent" in data["hooks"]

    def test_more_events_than_supported(self, tmp_path):
        """File has hooks for events beyond what we manage — they should survive."""
        path = tmp_path / "hooks.json"
        hooks = {event: [_cursor_entry(CURSOR_OTHER_CMD)] for event in CURSOR_HOOK_EVENTS}
        hooks["extraEvent1"] = [_cursor_entry(CURSOR_OTHER_CMD)]
        hooks["extraEvent2"] = [_cursor_entry(CURSOR_OTHER_CMD)]
        _write(path, {"version": 1, "hooks": hooks})
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert "extraEvent1" in data["hooks"]
        assert "extraEvent2" in data["hooks"]
        # Each managed event has 2 entries (other + ours)
        for event in CURSOR_HOOK_EVENTS:
            assert len(data["hooks"][event]) == 2

    def test_deprecated_agent_scan_events_removed(self, tmp_path):
        """Old agent-scan hooks for events no longer in our list get cleaned up."""
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "deprecatedEvent": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)],
                    "stop": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)],
                },
            },
        )
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert "deprecatedEvent" not in data["hooks"]
        assert "stop" in data["hooks"]

    def test_deprecated_event_preserves_other_hooks(self, tmp_path):
        """Deprecated event with mixed hooks: agent-scan removed, others kept."""
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "deprecatedEvent": [
                        _cursor_entry(CURSOR_OTHER_CMD),
                        _cursor_entry(CURSOR_AGENT_SCAN_CMD),
                    ],
                },
            },
        )
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        assert "deprecatedEvent" in data["hooks"]
        assert len(data["hooks"]["deprecatedEvent"]) == 1
        assert data["hooks"]["deprecatedEvent"][0]["command"] == CURSOR_OTHER_CMD


# ===================================================================
# Cursor: uninstall
# ===================================================================


class TestUninstallCursor:
    def test_missing_file(self, tmp_path):
        path = tmp_path / "hooks.json"
        _uninstall_cursor(path)  # should not raise

    def test_no_hooks_key(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1})
        _uninstall_cursor(path)

        data = json.loads(path.read_text())
        assert data == {"version": 1}

    def test_no_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {"stop": [_cursor_entry(CURSOR_OTHER_CMD)]}})
        _uninstall_cursor(path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["stop"]) == 1

    def test_removes_only_agent_scan(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "stop": [
                        _cursor_entry(CURSOR_OTHER_CMD),
                        _cursor_entry(CURSOR_AGENT_SCAN_CMD),
                    ],
                    "sessionStart": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)],
                },
            },
        )
        _uninstall_cursor(path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["stop"]) == 1
        assert data["hooks"]["stop"][0]["command"] == CURSOR_OTHER_CMD
        assert "sessionStart" not in data["hooks"]

    def test_leaves_empty_hooks_when_all_removed(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {"stop": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)]}})
        _uninstall_cursor(path)

        data = json.loads(path.read_text())
        assert data["hooks"] == {}

    def test_preserves_agentguard(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "stop": [
                        _cursor_entry(CURSOR_AGENTGUARD_CMD),
                        _cursor_entry(CURSOR_AGENT_SCAN_CMD),
                    ],
                },
            },
        )
        _uninstall_cursor(path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["stop"]) == 1
        assert data["hooks"]["stop"][0]["command"] == CURSOR_AGENTGUARD_CMD

    def test_backup_created(self, tmp_path):
        path = tmp_path / "hooks.json"
        original = {"version": 1, "hooks": {"stop": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)]}}
        _write(path, original)
        _uninstall_cursor(path)

        backup = Path(str(path) + ".backup")
        assert backup.exists()
        assert json.loads(backup.read_text()) == original

    def test_full_install_then_uninstall(self, tmp_path):
        path = tmp_path / "hooks.json"
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)
        _uninstall_cursor(path)

        data = json.loads(path.read_text())
        assert data["hooks"] == {}
        assert data["version"] == 1


# ===================================================================
# Cursor: detect
# ===================================================================


class TestDetectCursor:
    def test_missing_file(self, tmp_path):
        assert _detect_cursor_install(tmp_path / "nope.json") is None

    def test_empty_file(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1})
        assert _detect_cursor_install(path) is None

    def test_no_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {"stop": [_cursor_entry(CURSOR_OTHER_CMD)]}})
        assert _detect_cursor_install(path) is None

    def test_detects_installed(self, tmp_path):
        path = tmp_path / "hooks.json"
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        info = _detect_cursor_install(path)
        assert info is not None
        assert info["host"] == "api.snyk.io"
        assert info["auth_value"] == "pk-1234"
        assert info["tenant_id"] == "tid-1"
        assert len(info["events"]) == len(CURSOR_HOOK_EVENTS)

    def test_detects_partial_install(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "stop": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)],
                    "sessionEnd": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)],
                },
            },
        )
        info = _detect_cursor_install(path)
        assert info is not None
        assert info["events"] == ["stop", "sessionEnd"]

    def test_ignores_agentguard(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {"stop": [_cursor_entry(CURSOR_AGENTGUARD_CMD)]}})
        assert _detect_cursor_install(path) is None

    def test_detects_among_other_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "stop": [
                        _cursor_entry(CURSOR_AGENTGUARD_CMD),
                        _cursor_entry(CURSOR_AGENT_SCAN_CMD),
                    ],
                },
            },
        )
        info = _detect_cursor_install(path)
        assert info is not None
        assert info["events"] == ["stop"]

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "hooks.json"
        path.write_text("{broken json")
        with pytest.raises(json.JSONDecodeError):
            _detect_cursor_install(path)


# ===================================================================
# Filter functions
# ===================================================================


class TestFilterClaudeHooks:
    def test_empty(self):
        assert _filter_claude_hooks({}) == {}

    def test_removes_agent_scan(self):
        hooks = {"PreToolUse": [_claude_group(AGENT_SCAN_CMD, "*")]}
        assert _filter_claude_hooks(hooks) == {}

    def test_keeps_other(self):
        hooks = {"PreToolUse": [_claude_group(OTHER_CMD, "*")]}
        result = _filter_claude_hooks(hooks)
        assert len(result["PreToolUse"]) == 1

    def test_mixed(self):
        hooks = {
            "PreToolUse": [
                _claude_group(OTHER_CMD, "*"),
                _claude_group(AGENT_SCAN_CMD, "*"),
            ]
        }
        result = _filter_claude_hooks(hooks)
        assert len(result["PreToolUse"]) == 1
        assert result["PreToolUse"][0]["hooks"][0]["command"] == OTHER_CMD


class TestFilterCursorHooks:
    def test_empty(self):
        assert _filter_cursor_hooks({}) == {}

    def test_removes_agent_scan(self):
        hooks = {"stop": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)]}
        assert _filter_cursor_hooks(hooks) == {}

    def test_keeps_other(self):
        hooks = {"stop": [_cursor_entry(CURSOR_OTHER_CMD)]}
        result = _filter_cursor_hooks(hooks)
        assert len(result["stop"]) == 1

    def test_mixed(self):
        hooks = {
            "stop": [
                _cursor_entry(CURSOR_OTHER_CMD),
                _cursor_entry(CURSOR_AGENT_SCAN_CMD),
            ]
        }
        result = _filter_cursor_hooks(hooks)
        assert len(result["stop"]) == 1
        assert result["stop"][0]["command"] == CURSOR_OTHER_CMD


# ===================================================================
# Config path resolution (user vs managed)
# ===================================================================


class TestConfigPath:
    def test_claude_user_default(self):
        assert _config_path("claude") == CLAUDE_SETTINGS_PATH

    def test_cursor_user_default(self):
        assert _config_path("cursor") == CURSOR_HOOKS_PATH

    def test_claude_managed(self):
        assert _config_path("claude", managed=True) == CLAUDE_MANAGED_SETTINGS_PATH

    def test_cursor_managed(self):
        assert _config_path("cursor", managed=True) == CURSOR_MANAGED_HOOKS_PATH

    def test_file_override_takes_precedence_over_managed(self):
        override = "/custom/path/settings.json"
        assert _config_path("claude", override=override, managed=True) == Path(override)

    def test_file_override_takes_precedence_over_user(self):
        override = "/custom/path/settings.json"
        assert _config_path("claude", override=override) == Path(override)


class TestManagedPathConstants:
    def test_claude_managed_path_is_absolute(self):
        assert CLAUDE_MANAGED_SETTINGS_PATH.is_absolute()

    def test_cursor_managed_path_is_absolute(self):
        assert CURSOR_MANAGED_HOOKS_PATH.is_absolute()

    def test_claude_managed_filename(self):
        assert CLAUDE_MANAGED_SETTINGS_PATH.name == "managed-settings.json"

    def test_cursor_managed_filename(self):
        assert CURSOR_MANAGED_HOOKS_PATH.name == "hooks.json"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-specific paths")
    def test_macos_claude_managed_path(self):
        assert str(CLAUDE_MANAGED_SETTINGS_PATH) == "/Library/Application Support/ClaudeCode/managed-settings.json"

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-specific paths")
    def test_macos_cursor_managed_path(self):
        assert str(CURSOR_MANAGED_HOOKS_PATH) == "/Library/Application Support/Cursor/hooks.json"

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux-specific paths")
    def test_linux_claude_managed_path(self):
        assert str(CLAUDE_MANAGED_SETTINGS_PATH) == "/etc/claude-code/managed-settings.json"

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux-specific paths")
    def test_linux_cursor_managed_path(self):
        assert str(CURSOR_MANAGED_HOOKS_PATH) == "/etc/cursor/hooks.json"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific paths")
    def test_windows_claude_managed_path(self):
        assert "ClaudeCode" in str(CLAUDE_MANAGED_SETTINGS_PATH)
        assert "managed-settings.json" in str(CLAUDE_MANAGED_SETTINGS_PATH)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific paths")
    def test_windows_cursor_managed_path(self):
        assert "Cursor" in str(CURSOR_MANAGED_HOOKS_PATH)
        assert "hooks.json" in str(CURSOR_MANAGED_HOOKS_PATH)


class TestManagedInstallClaude:
    """Verify hooks can be installed/detected/uninstalled at a managed path."""

    def test_install_to_managed_path(self, tmp_path):
        path = tmp_path / "managed-settings.json"
        _install_claude(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        hooks = data["hooks"]
        assert set(hooks.keys()) == set(CLAUDE_HOOK_EVENTS)

    def test_detect_at_managed_path(self, tmp_path):
        path = tmp_path / "managed-settings.json"
        _install_claude(AGENT_SCAN_CMD, path)

        info = _detect_claude_install(path)
        assert info is not None
        assert info["auth_value"] == "pk-1234"

    def test_uninstall_from_managed_path(self, tmp_path):
        path = tmp_path / "managed-settings.json"
        _install_claude(AGENT_SCAN_CMD, path)
        _uninstall_claude(path)

        data = json.loads(path.read_text())
        assert "hooks" not in data


class TestManagedInstallCursor:
    """Verify hooks can be installed/detected/uninstalled at a managed path."""

    def test_install_to_managed_path(self, tmp_path):
        path = tmp_path / "hooks.json"
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        hooks = data["hooks"]
        assert set(hooks.keys()) == set(CURSOR_HOOK_EVENTS)

    def test_detect_at_managed_path(self, tmp_path):
        path = tmp_path / "hooks.json"
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)

        info = _detect_cursor_install(path)
        assert info is not None
        assert info["auth_value"] == "pk-1234"

    def test_uninstall_from_managed_path(self, tmp_path):
        path = tmp_path / "hooks.json"
        _install_cursor(CURSOR_AGENT_SCAN_CMD, path)
        _uninstall_cursor(path)

        data = json.loads(path.read_text())
        assert data["hooks"] == {}


# ===================================================================
# Permission denied handling (managed paths)
# ===================================================================


class TestPermissionDeniedStatus:
    """Managed configs may be unreadable — status should not crash."""

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod has no effect on Windows")
    def test_detect_claude_raises_on_unreadable(self, tmp_path):
        path = tmp_path / "managed-settings.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(AGENT_SCAN_CMD, "*")]}})
        path.chmod(0o000)
        try:
            with pytest.raises(PermissionError):
                _detect_claude_install(path)
        finally:
            path.chmod(0o644)

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod has no effect on Windows")
    def test_detect_cursor_raises_on_unreadable(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {"stop": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)]}})
        path.chmod(0o000)
        try:
            with pytest.raises(PermissionError):
                _detect_cursor_install(path)
        finally:
            path.chmod(0o644)

    def test_print_client_status_permission_denied(self, tmp_path, capsys):
        _print_client_status("Claude Code", tmp_path / "managed-settings.json", _PERMISSION_DENIED)
        output = capsys.readouterr().out
        assert "UNREADABLE" in output or "permission denied" in output.lower()

    def test_print_client_status_not_installed(self, tmp_path, capsys):
        _print_client_status("Claude Code", tmp_path / "settings.json", None)
        output = capsys.readouterr().out
        assert "NOT INSTALLED" in output

    def test_print_client_status_installed(self, tmp_path, capsys):
        info = {
            "host": "api.snyk.io",
            "auth_type": "pushkey",
            "auth_value": "pk-1234567890",
            "tenant_id": "tid-1",
            "url": "https://api.snyk.io",
            "events": ["PreToolUse"],
        }
        _print_client_status("Claude Code", tmp_path / "settings.json", info)
        output = capsys.readouterr().out
        assert "INSTALLED" in output


# ===================================================================
# Preflight writability check
# ===================================================================


class TestPreflightWritable:
    def test_passes_when_parent_writable(self, tmp_path):
        config = tmp_path / "subdir" / "settings.json"
        config.parent.mkdir(parents=True)
        _preflight_writable(config)  # should not raise

    def test_passes_when_parent_does_not_exist(self, tmp_path):
        config = tmp_path / "nonexistent" / "settings.json"
        _preflight_writable(config)  # parent doesn't exist yet, nothing to check

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod has no effect on Windows")
    def test_raises_when_parent_not_writable(self, tmp_path):
        config_dir = tmp_path / "locked"
        config_dir.mkdir()
        config_dir.chmod(0o555)
        try:
            with pytest.raises(PermissionError, match="not writable"):
                _preflight_writable(config_dir / "settings.json")
        finally:
            config_dir.chmod(0o755)


# ===================================================================
# Hook script integration tests
# ===================================================================


class _HookHandler(BaseHTTPRequestHandler):
    """Captures the last POST request for assertions."""

    last_request: dict | None = None

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        _HookHandler.last_request = {
            "path": self.path,
            "body": body,
            "headers": dict(self.headers),
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, format, *args):
        pass  # silence logs


@pytest.fixture()
def hook_server():
    """Start a throwaway HTTP server and yield its base URL."""
    server = HTTPServer(("127.0.0.1", 0), _HookHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    _HookHandler.last_request = None
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _get_script_path(name: str) -> Path:
    from importlib import resources as importlib_resources

    return Path(str(importlib_resources.files("agent_scan.hooks").joinpath(name)))


IS_WINDOWS = sys.platform == "win32"


@pytest.mark.skipif(IS_WINDOWS, reason="bash script; skipped on Windows")
class TestBashHookScript:
    """Integration: invoke the real .sh script against a local HTTP server."""

    @pytest.fixture(autouse=True)
    def _skip_no_bash(self):
        if not shutil.which("bash"):
            pytest.skip("bash not available")

    def test_posts_base64_payload(self, hook_server):
        script = _get_script_path("snyk-agent-guard.sh")
        payload = '{"hook_event_name":"test","session_id":"s1"}'
        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "PUSH_KEY": "test-pk-123",
                "REMOTE_HOOKS_BASE_URL": hook_server,
            },
        )
        assert result.returncode == 0, result.stderr

        req = _HookHandler.last_request
        assert req is not None
        assert "/hidden/agent-monitor/hooks/claude-code" in req["path"]
        assert req["headers"]["X-Client-Id"] == "test-pk-123"
        assert req["body"].startswith("base64:")
        decoded = base64.b64decode(req["body"].removeprefix("base64:"))
        assert json.loads(decoded) == json.loads(payload)

    def test_cursor_endpoint(self, hook_server):
        script = _get_script_path("snyk-agent-guard.sh")
        payload = '{"hook_event_name":"test","conversation_id":"c1"}'
        result = subprocess.run(
            ["bash", str(script), "--client", "cursor"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "PUSH_KEY": "test-pk-456",
                "REMOTE_HOOKS_BASE_URL": hook_server,
            },
        )
        assert result.returncode == 0, result.stderr
        assert "/hidden/agent-monitor/hooks/cursor" in _HookHandler.last_request["path"]

    def test_missing_push_key_fails(self, hook_server):
        script = _get_script_path("snyk-agent-guard.sh")
        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code"],
            input="{}",
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "REMOTE_HOOKS_BASE_URL": hook_server,
            },
        )
        assert result.returncode != 0
        assert "PUSH_KEY" in result.stderr

    def test_missing_url_fails(self):
        script = _get_script_path("snyk-agent-guard.sh")
        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code"],
            input="{}",
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "PUSH_KEY": "pk",
            },
        )
        assert result.returncode != 0
        assert "REMOTE_HOOKS_BASE_URL" in result.stderr


@pytest.mark.skipif(not IS_WINDOWS, reason="PowerShell script; Windows only")
class TestPowerShellHookScript:
    """Integration: invoke the real .ps1 script against a local HTTP server."""

    @pytest.fixture(autouse=True)
    def _skip_no_powershell(self):
        if not shutil.which("powershell") and not shutil.which("pwsh"):
            pytest.skip("powershell not available")

    @staticmethod
    def _ps_cmd():
        return "powershell" if shutil.which("powershell") else "pwsh"

    def test_posts_base64_payload(self, hook_server):
        script = _get_script_path("snyk-agent-guard.ps1")
        payload = '{"hook_event_name":"test","session_id":"s1"}'
        result = subprocess.run(
            [
                self._ps_cmd(),
                "-File",
                str(script),
                "-Client",
                "claude-code",
                "-PushKey",
                "test-pk-123",
                "-RemoteUrl",
                hook_server,
            ],
            input=payload,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr

        req = _HookHandler.last_request
        assert req is not None
        assert "/hidden/agent-monitor/hooks/claude-code" in req["path"]
        assert req["headers"]["X-Client-Id"] == "test-pk-123"
        assert req["body"].startswith("base64:")
        decoded = base64.b64decode(req["body"].removeprefix("base64:"))
        assert json.loads(decoded) == json.loads(payload)

    def test_cursor_endpoint(self, hook_server):
        script = _get_script_path("snyk-agent-guard.ps1")
        payload = '{"hook_event_name":"test","conversation_id":"c1"}'
        result = subprocess.run(
            [
                self._ps_cmd(),
                "-File",
                str(script),
                "-Client",
                "cursor",
                "-PushKey",
                "test-pk-456",
                "-RemoteUrl",
                hook_server,
            ],
            input=payload,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert "/hidden/agent-monitor/hooks/cursor" in _HookHandler.last_request["path"]

    def test_missing_push_key_fails(self, hook_server):
        script = _get_script_path("snyk-agent-guard.ps1")
        env = dict(__import__("os").environ)
        env.pop("PUSH_KEY", None)
        env.pop("PUSHKEY", None)
        result = subprocess.run(
            [self._ps_cmd(), "-File", str(script), "-Client", "claude-code", "-RemoteUrl", hook_server],
            input="{}",
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        assert result.returncode != 0


# ===================================================================
# End-to-end: command string invoked the way the client shell does it
# ===================================================================


@pytest.mark.skipif(not IS_WINDOWS, reason="PowerShell Cursor invocation; Windows only")
class TestCursorStylePowerShellInvocation:
    """Verify the built command string works when Cursor passes it to
    ``powershell -Command "..."``.

    An earlier version that used ``$env:KEY='...'; ...`` broke because
    PowerShell rejected chained expressions in that context.
    """

    @pytest.fixture(autouse=True)
    def _skip_no_powershell(self):
        if not shutil.which("powershell") and not shutil.which("pwsh"):
            pytest.skip("powershell not available")

    @staticmethod
    def _ps_cmd():
        return "powershell" if shutil.which("powershell") else "pwsh"

    def test_cursor_invokes_command_string(self, hook_server):
        script = _get_script_path("snyk-agent-guard.ps1")
        command = _build_hook_command_powershell(
            "test-pk-cursor",
            hook_server,
            script,
            "claude-code",
        )
        payload = '{"hook_event_name":"test","session_id":"cursor-test"}'
        result = subprocess.run(
            [self._ps_cmd(), "-Command", command],
            input=payload,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"Command failed:\n{command}\nstderr: {result.stderr}"

        req = _HookHandler.last_request
        assert req is not None
        assert "/hidden/agent-monitor/hooks/claude-code" in req["path"]
        assert req["headers"]["X-Client-Id"] == "test-pk-cursor"
        decoded = base64.b64decode(req["body"].removeprefix("base64:"))
        assert json.loads(decoded) == json.loads(payload)


@pytest.mark.skipif(IS_WINDOWS, reason="bash invocation; non-Windows only")
class TestCursorStyleBashInvocation:
    """Verify the built command string works when passed to ``bash -c``."""

    @pytest.fixture(autouse=True)
    def _skip_no_bash(self):
        if not shutil.which("bash"):
            pytest.skip("bash not available")

    def test_cursor_invokes_command_string(self, hook_server):
        script = _get_script_path("snyk-agent-guard.sh")
        command = _build_hook_command(
            "test-pk-cursor",
            hook_server,
            script,
            "cursor",
        )
        payload = '{"hook_event_name":"test","conversation_id":"cursor-test"}'
        result = subprocess.run(
            ["bash", "-c", command],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
        )
        assert result.returncode == 0, f"Command failed:\n{command}\nstderr: {result.stderr}"

        req = _HookHandler.last_request
        assert req is not None
        assert "/hidden/agent-monitor/hooks/cursor" in req["path"]
        assert req["headers"]["X-Client-Id"] == "test-pk-cursor"
        decoded = base64.b64decode(req["body"].removeprefix("base64:"))
        assert json.loads(decoded) == json.loads(payload)


# ===================================================================
# _ensure_guard_enabled_for_tenant + _run_install integration
# ===================================================================


class TestEnsureGuardEnabledForTenant:
    """Branch coverage for guard tenant verification (non-local API, Flipt / agent-monitor)."""

    @patch("agent_scan.guard.fetch_guard_enabled")
    def test_empty_tenant_returns_without_fetch(self, mock_fetch, capsys):
        _ensure_guard_enabled_for_tenant("https://api.snyk.io", "", "token")
        mock_fetch.assert_not_called()

    def test_missing_token_non_localhost_exits(self, capsys):
        with pytest.raises(SystemExit) as e:
            _ensure_guard_enabled_for_tenant("https://api.snyk.io", "550e8400-e29b-41d4-a716-446655440000", "")
        assert e.value.args[0] == 1
        out = capsys.readouterr().out
        assert "SNYK_TOKEN is required" in out

    def test_whitespace_token_treated_as_missing(self, capsys):
        with pytest.raises(SystemExit) as e:
            _ensure_guard_enabled_for_tenant("https://api.snyk.io", "550e8400-e29b-41d4-a716-446655440000", "   ")
        assert e.value.args[0] == 1
        assert "SNYK_TOKEN is required" in capsys.readouterr().out

    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_localhost_allows_empty_token(self, mock_fetch):
        _ensure_guard_enabled_for_tenant("http://127.0.0.1:9", "550e8400-e29b-41d4-a716-446655440000", "")
        mock_fetch.assert_called_once_with("http://127.0.0.1:9", "550e8400-e29b-41d4-a716-446655440000", "")

    @patch("agent_scan.guard.fetch_guard_enabled")
    def test_access_denied_exits(self, mock_fetch, capsys):
        mock_fetch.side_effect = GuardEnabledAccessDeniedError("forbidden")
        with pytest.raises(SystemExit) as e:
            _ensure_guard_enabled_for_tenant("https://api.snyk.io", "550e8400-e29b-41d4-a716-446655440000", "tok")
        assert e.value.args[0] == 1
        out = capsys.readouterr().out
        assert "Access denied" in out
        assert "not eligible" in out

    @patch("agent_scan.guard.fetch_guard_enabled")
    def test_endpoint_error_exits(self, mock_fetch, capsys):
        mock_fetch.side_effect = RuntimeError("Guard enabled check failed: HTTP 502")
        with pytest.raises(SystemExit) as e:
            _ensure_guard_enabled_for_tenant("https://api.snyk.io", "550e8400-e29b-41d4-a716-446655440000", "tok")
        assert e.value.args[0] == 1
        out = capsys.readouterr().out
        assert "Could not verify Agent Guard status" in out
        assert "HTTP 502" in out
        assert "Ensure --url" in out

    @patch("agent_scan.guard.fetch_guard_enabled", return_value=False)
    def test_guard_disabled_tenant_exits(self, mock_fetch, capsys):
        with pytest.raises(SystemExit) as e:
            _ensure_guard_enabled_for_tenant("https://api.snyk.io", "550e8400-e29b-41d4-a716-446655440000", "tok")
        assert e.value.args[0] == 1
        out = capsys.readouterr().out
        assert "not enabled for this Snyk tenant" in out
        assert "550e8400-e29b-41d4-a716-446655440000" in out

    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_guard_enabled_continues(self, mock_fetch):
        _ensure_guard_enabled_for_tenant("https://api.snyk.io", "550e8400-e29b-41d4-a716-446655440000", "tok")
        mock_fetch.assert_called_once_with("https://api.snyk.io", "550e8400-e29b-41d4-a716-446655440000", "tok")


class TestRunInstallCallsEnsureGuardEnabled:
    """_run_install invokes _ensure_guard_enabled_for_tenant only in the interactive (mint) path."""

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_interactive_mint_path_calls_ensure_with_token(
        self, mock_fetch, mock_mint, mock_install, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "snyk-from-env")
        config = tmp_path / "settings.json"
        args = SimpleNamespace(
            client="claude",
            url="https://api.snyk.io",
            tenant_id="tid-interactive",
            file=str(config),
            managed=False,
            test=False,
        )
        _run_install(args)
        mock_fetch.assert_called_once_with("https://api.snyk.io", "tid-interactive", "snyk-from-env")
        mock_mint.assert_called_once()
        mock_install.assert_called_once()

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_headless_with_push_key_skips_ensure(self, mock_fetch, mock_install, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "existing-pk")
        monkeypatch.setenv("TENANT_ID", "tid-headless")
        monkeypatch.setenv("SNYK_TOKEN", "headless-token")
        config = tmp_path / "hooks.json"
        args = SimpleNamespace(
            client="cursor",
            url="https://api.snyk.io",
            tenant_id="",
            file=str(config),
            managed=False,
            test=False,
        )
        _run_install(args)
        mock_fetch.assert_not_called()
        mock_install.assert_called_once()

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_headless_installs_without_snyk_token(self, mock_fetch, mock_install, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "existing-pk")
        monkeypatch.setenv("TENANT_ID", "tid-hl")
        monkeypatch.delenv("SNYK_TOKEN", raising=False)
        config = tmp_path / "hooks.json"
        args = SimpleNamespace(
            client="cursor",
            url="https://api.snyk.io",
            tenant_id="tid-hl",
            file=str(config),
            managed=False,
            test=False,
        )
        _run_install(args)
        mock_fetch.assert_not_called()
        mock_install.assert_called_once()
