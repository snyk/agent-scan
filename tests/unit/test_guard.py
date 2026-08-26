"""Tests for agent_scan.guard — install, uninstall, detect for Claude Code and Cursor."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from unittest.mock import call as mock_call

import pytest

import agent_scan.guard as guard_module
from agent_scan.guard import (
    _PERMISSION_DENIED,
    ALL_CLIENTS,
    CLAUDE_HOOK_EVENTS,
    CLAUDE_MANAGED_SETTINGS_PATH,
    CLAUDE_SETTINGS_PATH,
    CODEX_HOOK_EVENTS,
    CODEX_HOOKS_PATH,
    CODEX_MANAGED_HOOKS_PATH,
    CURSOR_HOOK_EVENTS,
    CURSOR_HOOKS_PATH,
    CURSOR_MANAGED_HOOKS_PATH,
    _build_hook_command,
    _build_hook_command_powershell,
    _compact_events,
    _compute_hooks_diff,
    _config_path,
    _detect_claude_install,
    _detect_codex_install,
    _detect_cursor_install,
    _ensure_guard_enabled_for_tenant,
    _extract_env_from_cmd,
    _filter_claude_hooks,
    _filter_cursor_hooks,
    _install_hooks,
    _is_agent_scan_command,
    _is_client_installed,
    _mask_key,
    _parse_codex_requirements_toml,
    _parse_command_info,
    _preflight_writable,
    _prepare_claude_config,
    _prepare_codex_config,
    _prepare_codex_managed_config,
    _prepare_cursor_config,
    _print_client_status,
    _run_install,
    _run_uninstall,
    _send_test_event,
    _shell_quote,
    _uninstall_hooks,
    _write_codex_managed_config,
    _write_config,
)
from agent_scan.models import ClientToInspect, InspectedPath, InspectedServer, RemoteServer, StdioServer
from agent_scan.models.errors import CouldNotParseMCPConfig, FileNotFoundConfig
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


def _setup_claude_hooks(cmd: str, path: Path) -> None:
    settings, _, preserved = _prepare_claude_config(cmd, path)
    _write_config(settings, path, preserved)


def _setup_cursor_hooks(cmd: str, path: Path) -> None:
    data, _, preserved = _prepare_cursor_config(cmd, path)
    _write_config(data, path, preserved)


def _setup_codex_hooks(cmd: str, path: Path) -> None:
    data, _, preserved = _prepare_codex_config(cmd, path)
    _write_config(data, path, preserved)


def _setup_codex_managed_hooks(cmd: str, path: Path) -> None:
    content, _ = _prepare_codex_managed_config(cmd, path)
    _write_codex_managed_config(content, path)


def _uninstall_test_client(client: str, path: Path) -> None:
    _uninstall_hooks(
        path,
        filter_hooks=_filter_cursor_hooks if client == "cursor" else _filter_claude_hooks,
        prune_empty_hooks=client != "cursor",
    )


def _detect_test_client(client: str, path: Path) -> dict | None:
    detect = {
        "claude": _detect_claude_install,
        "cursor": _detect_cursor_install,
        "codex": _detect_codex_install,
    }[client]
    return detect(path)


# ===================================================================
# Unit tests for pure helpers
# ===================================================================


class TestIsAgentScanCommand:
    def test_matches_bash_format(self):
        assert _is_agent_scan_command("PUSH_KEY='x' bash snyk-agent-guard.sh --client c")

    def test_matches_bash_full_command(self):
        assert _is_agent_scan_command(
            "PUSH_KEY='pk-1234' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' "
            "bash '/home/u/.claude/hooks/snyk-agent-guard.sh' --client claude-code"
        )

    def test_matches_powershell_format(self):
        assert _is_agent_scan_command(
            "powershell -File 'snyk-agent-guard.ps1' -Client claude-code -PushKey 'pk' -RemoteUrl 'url'"
        )

    def test_no_match_snyk_agent_guard_without_push_key(self):
        assert not _is_agent_scan_command("bash /home/u/.claude/hooks/snyk-agent-guard.sh")

    def test_no_match_push_key_without_snyk_agent_guard(self):
        assert not _is_agent_scan_command("PUSH_KEY='pk' bash /some/other-tool.sh --client claude")

    def test_no_match_other_tool(self):
        assert not _is_agent_scan_command("some-other-tool hook --client claude")

    def test_no_match_agentguard(self):
        assert not _is_agent_scan_command("PUSH_KEY='pk' /usr/local/bin/agentguard hook --client claude-code")

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


@pytest.mark.parametrize(
    "variant,is_windows,expected",
    [
        (
            "main",
            False,
            "PUSH_KEY='pk' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' TENANT_ID='tenant' "
            "MACHINE_ID='machine' bash '/x/snyk-agent-guard.sh' --client claude-code",
        ),
        (
            "main",
            True,
            "powershell -File 'C:\\hooks\\snyk-agent-guard.ps1' -Client claude-code -PushKey 'pk' "
            "-RemoteUrl 'https://api.snyk.io' -MachineId 'machine'",
        ),
        (
            "discover",
            False,
            "PUSH_KEY='pk' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' MACHINE_ID='machine' "
            "AGENT_SCAN_COMMAND='/usr/local/bin/snyk-agent-scan' bash '/x/snyk-agent-guard-discover.sh' "
            "--client 'claude-code' --scope servers",
        ),
        (
            "discover",
            True,
            "powershell -File 'C:\\hooks\\snyk-agent-guard-discover.ps1' -Client claude-code -PushKey 'pk' "
            "-RemoteUrl 'https://api.snyk.io' -MachineId 'machine' "
            "-AgentScanCommand 'C:\\Program Files\\Snyk\\snyk-agent-scan.exe' -Scope servers",
        ),
    ],
)
def test_build_hook_command_preserves_exact_output(variant, is_windows, expected):
    script_path = Path(
        r"C:\hooks\snyk-agent-guard.ps1"
        if is_windows and variant == "main"
        else r"C:\hooks\snyk-agent-guard-discover.ps1"
        if is_windows
        else f"/x/snyk-agent-guard{'-discover' if variant == 'discover' else ''}.sh"
    )

    with patch(f"{_G}.IS_WINDOWS", is_windows):
        if variant == "main":
            command = _build_hook_command(
                "pk",
                "https://api.snyk.io",
                script_path,
                "claude-code",
                tenant_id="tenant",
                machine_id="machine",
            )
        else:
            command = guard_module._build_discover_hook_command(
                "pk",
                "https://api.snyk.io",
                script_path,
                "claude-code",
                agent_scan_command=(
                    r"C:\Program Files\Snyk\snyk-agent-scan.exe" if is_windows else "/usr/local/bin/snyk-agent-scan"
                ),
                tenant_id="tenant",
                machine_id="machine",
            )

    assert command == expected


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

    @pytest.mark.skipif(sys.platform == "win32", reason="bash command format")
    def test_with_machine_id_bash(self):
        cmd = _build_hook_command("pk", "https://api.snyk.io", Path("/x/hook.sh"), "cursor", machine_id="machine-42")
        assert "MACHINE_ID='machine-42'" in cmd

    @pytest.mark.skipif(sys.platform == "win32", reason="bash command format")
    def test_without_machine_id_bash(self):
        cmd = _build_hook_command("pk", "https://api.snyk.io", Path("/x/hook.sh"), "cursor")
        assert "MACHINE_ID" not in cmd

    def test_with_machine_id_powershell(self):
        cmd = _build_hook_command_powershell(
            "pk", "https://api.snyk.io", Path("C:/x/hook.ps1"), "codex", machine_id="machine-42"
        )
        assert "-MachineId 'machine-42'" in cmd

    def test_without_machine_id_powershell(self):
        cmd = _build_hook_command_powershell("pk", "https://api.snyk.io", Path("C:/x/hook.ps1"), "codex")
        assert "-MachineId" not in cmd

    def test_machine_id_powershell_escapes_single_quotes(self):
        cmd = _build_hook_command_powershell(
            "pk", "https://api.snyk.io", Path("C:/x/hook.ps1"), "codex", machine_id="O'Brien-laptop"
        )
        assert "-MachineId 'O''Brien-laptop'" in cmd

    def test_powershell_escapes_single_quotes_in_all_literals(self):
        script_path = Path("C:/Users/O'Brien/hook.ps1")
        cmd = _build_hook_command_powershell(
            "pk'quoted",
            "https://example.com/O'Brien",
            script_path,
            "codex",
        )

        expected_path = str(script_path).replace("'", "''")
        assert f"-File '{expected_path}'" in cmd
        assert "-PushKey 'pk''quoted'" in cmd
        assert "-RemoteUrl 'https://example.com/O''Brien'" in cmd

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


class TestAgentScanCommand:
    def test_uses_environment_value(self, monkeypatch):
        monkeypatch.setenv("AGENT_SCAN_COMMAND", "cd /repo; uv run -m src.agent_scan.cli")

        assert guard_module._agent_scan_command() == "cd /repo; uv run -m src.agent_scan.cli"

    def test_returns_none_when_environment_unset(self, monkeypatch):
        monkeypatch.delenv("AGENT_SCAN_COMMAND", raising=False)

        assert guard_module._agent_scan_command() is None

    @pytest.mark.parametrize("value", ["", "   "])
    def test_returns_none_when_environment_value_is_blank(self, monkeypatch, value):
        monkeypatch.setenv("AGENT_SCAN_COMMAND", value)

        assert guard_module._agent_scan_command() is None


class TestBuildDiscoverHookCommand:
    @pytest.mark.parametrize(
        "client, expected_field",
        [("claude-code", "cwd"), ("cursor", "workspace_roots"), ("codex", "cwd")],
    )
    def test_client_payload_fields_match_hook_schemas(self, client, expected_field):
        from agent_scan.hook_events import HOOK_CLIENTS

        assert HOOK_CLIENTS[client].target_folder_field == expected_field

    @pytest.mark.parametrize("client", ["claude-code", "cursor", "codex"])
    def test_builds_quoted_environment_prefix_with_agent_scan_command(self, client):
        with patch(f"{_G}.IS_WINDOWS", False):
            command = guard_module._build_discover_hook_command(
                "pk",
                "https://api.snyk.io",
                Path("/x/snyk-agent-guard-discover.sh"),
                client,
                agent_scan_command="/opt/Snyk's bin/snyk-agent-scan",
                tenant_id="tenant",
                machine_id="machine",
            )

        assert "PUSH_KEY='pk'" in command
        assert "REMOTE_HOOKS_BASE_URL='https://api.snyk.io'" in command
        assert "TENANT_ID=" not in command
        assert "MACHINE_ID='machine'" in command
        assert "AGENT_SCAN_COMMAND='/opt/Snyk'\"'\"'s bin/snyk-agent-scan'" in command
        assert command.endswith(f"bash '/x/snyk-agent-guard-discover.sh' --client '{client}' --scope servers")
        assert _is_agent_scan_command(command)

    @pytest.mark.parametrize("client", ["claude-code", "cursor", "codex"])
    def test_builds_powershell_command_for_each_client(self, client):
        with patch(f"{_G}.IS_WINDOWS", True):
            command = guard_module._build_discover_hook_command(
                "pk",
                "https://api.snyk.io",
                Path(r"C:\hooks\snyk-agent-guard-discover.ps1"),
                client,
                agent_scan_command=r"C:\Program Files\Snyk\snyk-agent-scan.exe",
                tenant_id="ignored",
                machine_id="machine's-id",
            )

        assert command == (
            rf"powershell -File 'C:\hooks\snyk-agent-guard-discover.ps1' -Client {client} "
            "-PushKey 'pk' -RemoteUrl 'https://api.snyk.io' -MachineId 'machine''s-id' "
            r"-AgentScanCommand 'C:\Program Files\Snyk\snyk-agent-scan.exe' -Scope servers"
        )

    def test_powershell_escapes_single_quotes_in_paths(self):
        with patch(f"{_G}.IS_WINDOWS", True):
            command = guard_module._build_discover_hook_command(
                "pk",
                "https://api.snyk.io",
                Path(r"C:\Users\O'Brien\discover.ps1"),
                "claude-code",
                agent_scan_command=r"C:\Users\O'Brien\snyk-agent-scan.exe",
            )

        assert r"-File 'C:\Users\O''Brien\discover.ps1'" in command
        assert r"-AgentScanCommand 'C:\Users\O''Brien\snyk-agent-scan.exe'" in command

    @pytest.mark.parametrize(
        "is_windows, expected",
        [
            (False, "AGENT_SCAN_COMMAND='cd /repo; uv run -m src.agent_scan.cli'"),
            (True, "-AgentScanCommand 'cd /repo; uv run -m src.agent_scan.cli'"),
        ],
    )
    def test_preserves_multi_word_shell_command(self, is_windows, expected):
        script = Path(r"C:\hooks\snyk-agent-guard-discover.ps1" if is_windows else "/hooks/discover.sh")
        with patch(f"{_G}.IS_WINDOWS", is_windows):
            command = guard_module._build_discover_hook_command(
                "pk",
                "https://api.snyk.io",
                script,
                "claude-code",
                agent_scan_command="cd /repo; uv run -m src.agent_scan.cli",
            )

        assert expected in command


class TestHookInvocationRenderers:
    def test_render_argv_posix_returns_unquoted_argv_and_merged_environment(self):
        invocation = guard_module._HookInvocation(
            script_path=Path("/hooks/snyk-agent-guard.sh"),
            hook_client="claude-code",
            push_key="pk'raw",
            url="https://example.test/hook's",
            machine_id="machine'raw",
        )

        with patch.dict(os.environ, {"EXISTING": "value"}, clear=True), patch(f"{_G}.IS_WINDOWS", False):
            argv, env = guard_module._render_argv(invocation)

        assert argv == ["bash", "/hooks/snyk-agent-guard.sh", "--client", "claude-code"]
        assert env == {
            "EXISTING": "value",
            "PUSH_KEY": "pk'raw",
            "REMOTE_HOOKS_BASE_URL": "https://example.test/hook's",
            "MACHINE_ID": "machine'raw",
        }

    def test_render_argv_windows_returns_unquoted_argv_without_environment(self):
        invocation = guard_module._HookInvocation(
            script_path=Path(r"C:\hooks\snyk-agent-guard.ps1"),
            hook_client="codex",
            push_key="pk'raw",
            url="https://example.test/hook's",
            machine_id="machine'raw",
        )

        with patch(f"{_G}.IS_WINDOWS", True):
            argv, env = guard_module._render_argv(invocation)

        assert argv == [
            "powershell",
            "-File",
            str(Path(r"C:\hooks\snyk-agent-guard.ps1")),
            "-Client",
            "codex",
            "-PushKey",
            "pk'raw",
            "-RemoteUrl",
            "https://example.test/hook's",
            "-MachineId",
            "machine'raw",
        ]
        assert env is None

    def test_render_argv_posix_carries_discovery_fields(self):
        """The discovery trampoline forwards ``"$@"`` to ``guard discover``, so scope travels in argv."""
        invocation = guard_module._HookInvocation(
            script_path=Path("/hooks/snyk-agent-guard-discover.sh"),
            hook_client="cursor",
            push_key="pk",
            url="https://api.snyk.io",
            machine_id="machine",
            tenant_id="tenant",
            agent_scan_command="/opt/Snyk's bin/snyk-agent-scan",
            scope="servers",
            quote_client=True,
        )

        with patch.dict(os.environ, {"EXISTING": "value"}, clear=True), patch(f"{_G}.IS_WINDOWS", False):
            argv, env = guard_module._render_argv(invocation)

        assert argv == [
            "bash",
            "/hooks/snyk-agent-guard-discover.sh",
            "--client",
            "cursor",
            "--scope",
            "servers",
        ]
        assert env == {
            "EXISTING": "value",
            "PUSH_KEY": "pk",
            "REMOTE_HOOKS_BASE_URL": "https://api.snyk.io",
            "TENANT_ID": "tenant",
            "MACHINE_ID": "machine",
            "AGENT_SCAN_COMMAND": "/opt/Snyk's bin/snyk-agent-scan",
        }

    def test_render_argv_windows_carries_discovery_fields(self):
        invocation = guard_module._HookInvocation(
            script_path=Path(r"C:\hooks\snyk-agent-guard-discover.ps1"),
            hook_client="codex",
            push_key="pk",
            url="https://api.snyk.io",
            machine_id="machine",
            tenant_id="tenant",
            agent_scan_command=r"C:\Program Files\Snyk\snyk-agent-scan.exe",
            scope="servers",
        )

        with patch(f"{_G}.IS_WINDOWS", True):
            argv, env = guard_module._render_argv(invocation)

        assert argv == [
            "powershell",
            "-File",
            str(Path(r"C:\hooks\snyk-agent-guard-discover.ps1")),
            "-Client",
            "codex",
            "-PushKey",
            "pk",
            "-RemoteUrl",
            "https://api.snyk.io",
            "-MachineId",
            "machine",
            "-AgentScanCommand",
            r"C:\Program Files\Snyk\snyk-agent-scan.exe",
            "-Scope",
            "servers",
        ]
        assert env is None

    def test_render_posix_command_skips_empty_optional_fields(self):
        invocation = guard_module._HookInvocation(
            script_path=Path("/hooks/snyk-agent-guard.sh"),
            hook_client="claude-code",
            push_key="pk",
            url="https://api.snyk.io",
        )

        command = guard_module._render_posix_command(invocation)

        assert command == (
            "PUSH_KEY='pk' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' "
            "bash '/hooks/snyk-agent-guard.sh' --client claude-code"
        )


class TestPrepareClaudeDiscoveryHook:
    discover_command = (
        "PUSH_KEY='pk' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash '/x/snyk-agent-guard-discover.sh'"
    )

    def test_adds_separate_async_matcherless_session_start_group(self, tmp_path):
        with patch(f"{_G}.IS_WINDOWS", False):
            settings, _, _ = _prepare_claude_config(
                AGENT_SCAN_CMD,
                tmp_path / "settings.json",
                discover_command=self.discover_command,
            )

        for event in CLAUDE_HOOK_EVENTS:
            expected_count = 2 if event == "SessionStart" else 1
            assert len(settings["hooks"][event]) == expected_count
        assert settings["hooks"]["SessionStart"][1] == {
            "hooks": [{"type": "command", "command": self.discover_command, "async": True}]
        }

    def test_none_preserves_current_hook_shape(self, tmp_path):
        settings, _, _ = _prepare_claude_config(
            AGENT_SCAN_CMD,
            tmp_path / "settings.json",
            discover_command=None,
        )

        assert all(len(settings["hooks"][event]) == 1 for event in CLAUDE_HOOK_EVENTS)

    def test_windows_discovery_entry_uses_powershell_shell(self, tmp_path):
        with patch(f"{_G}.IS_WINDOWS", True):
            settings, _, _ = _prepare_claude_config(
                AGENT_SCAN_CMD,
                tmp_path / "settings.json",
                discover_command=self.discover_command,
            )

        assert settings["hooks"]["SessionStart"][1] == {
            "hooks": [
                {
                    "type": "command",
                    "command": self.discover_command,
                    "async": True,
                    "shell": "powershell",
                }
            ]
        }

    def test_reprepare_is_idempotent(self, tmp_path):
        path = tmp_path / "settings.json"
        settings, _, preserved = _prepare_claude_config(
            AGENT_SCAN_CMD,
            path,
            discover_command=self.discover_command,
        )
        _write_config(settings, path, preserved)

        _, diff, _ = _prepare_claude_config(
            AGENT_SCAN_CMD,
            path,
            discover_command=self.discover_command,
        )

        assert diff == {"added": {}, "modified": {}, "removed": {}}


class TestPrepareCursorDiscoveryHook:
    discover_command = (
        "PUSH_KEY='pk' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash '/x/snyk-agent-guard-discover.sh'"
    )

    def test_adds_flat_session_start_entry(self, tmp_path):
        data, _, _ = _prepare_cursor_config(
            AGENT_SCAN_CMD,
            tmp_path / "hooks.json",
            discover_command=self.discover_command,
        )

        assert data["hooks"]["sessionStart"][1] == {"command": self.discover_command}

    def test_none_preserves_current_hook_shape(self, tmp_path):
        data, _, _ = _prepare_cursor_config(
            AGENT_SCAN_CMD,
            tmp_path / "hooks.json",
            discover_command=None,
        )

        assert all(len(data["hooks"][event]) == 1 for event in CURSOR_HOOK_EVENTS)

    def test_reprepare_is_idempotent(self, tmp_path):
        path = tmp_path / "hooks.json"
        data, _, preserved = _prepare_cursor_config(
            AGENT_SCAN_CMD,
            path,
            discover_command=self.discover_command,
        )
        _write_config(data, path, preserved)

        _, diff, _ = _prepare_cursor_config(
            AGENT_SCAN_CMD,
            path,
            discover_command=self.discover_command,
        )

        assert diff == {"added": {}, "modified": {}, "removed": {}}

    def test_uninstall_removes_discovery_entry(self, tmp_path):
        path = tmp_path / "hooks.json"
        data, _, preserved = _prepare_cursor_config(
            AGENT_SCAN_CMD,
            path,
            discover_command=self.discover_command,
        )
        _write_config(data, path, preserved)

        _uninstall_test_client("cursor", path)

        assert not any(
            self.discover_command == entry.get("command")
            for entries in json.loads(path.read_text())["hooks"].values()
            for entry in entries
        )


class TestPrepareCodexDiscoveryHook:
    discover_command = (
        "PUSH_KEY='pk' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash '/x/snyk-agent-guard-discover.sh'"
    )

    def test_adds_async_matcherless_session_start_group(self, tmp_path):
        data, _, _ = _prepare_codex_config(
            AGENT_SCAN_CMD,
            tmp_path / "hooks.json",
            discover_command=self.discover_command,
        )

        assert data["hooks"]["SessionStart"][1] == {
            "hooks": [{"type": "command", "command": self.discover_command, "async": True}]
        }

    def test_none_preserves_current_hook_shape(self, tmp_path):
        data, _, _ = _prepare_codex_config(
            AGENT_SCAN_CMD,
            tmp_path / "hooks.json",
            discover_command=None,
        )

        assert all(len(data["hooks"][event]) == 1 for event in CODEX_HOOK_EVENTS)

    def test_reprepare_is_idempotent(self, tmp_path):
        path = tmp_path / "hooks.json"
        data, _, preserved = _prepare_codex_config(
            AGENT_SCAN_CMD,
            path,
            discover_command=self.discover_command,
        )
        _write_config(data, path, preserved)

        _, diff, _ = _prepare_codex_config(
            AGENT_SCAN_CMD,
            path,
            discover_command=self.discover_command,
        )

        assert diff == {"added": {}, "modified": {}, "removed": {}}

    def test_uninstall_removes_discovery_entry(self, tmp_path):
        path = tmp_path / "hooks.json"
        data, _, preserved = _prepare_codex_config(
            AGENT_SCAN_CMD,
            path,
            discover_command=self.discover_command,
        )
        _write_config(data, path, preserved)

        _uninstall_test_client("codex", path)

        assert "hooks" not in json.loads(path.read_text())


class TestWriteConfig:
    def test_unknown_client_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="Unknown client: unknown"):
            guard_module._write_client_config("unknown", tmp_path / "hooks.json", {}, None, 0)

    def test_returns_false_and_prints_nothing_when_content_unchanged(self, tmp_path, capsys):
        path = tmp_path / "hooks.json"
        config = {"hooks": {}}
        assert _write_config(config, path, 0) is True
        capsys.readouterr()

        assert _write_config(config, path, 0) is False

        assert capsys.readouterr().out == ""
        assert not Path(f"{path}.backup").exists()

    def test_returns_true_and_backs_up_when_content_changed(self, tmp_path, capsys):
        path = tmp_path / "hooks.json"
        original = {"version": 1}
        updated = {"version": 1, "hooks": {}}
        assert _write_config(original, path, 0) is True
        capsys.readouterr()

        assert _write_config(updated, path, 0) is True

        backup = Path(f"{path}.backup")
        assert json.loads(backup.read_text()) == original
        assert json.loads(path.read_text()) == updated
        output = capsys.readouterr().out
        assert "Backed up" in output
        assert "Written" in output

    def test_creates_parent_directory_when_missing(self, tmp_path):
        path = tmp_path / "missing" / "nested" / "hooks.json"

        assert _write_config({"hooks": {}}, path, 0) is True

        assert json.loads(path.read_text()) == {"hooks": {}}

    def test_preserved_note_omitted_when_zero(self, tmp_path, capsys):
        _write_config({"hooks": {}}, tmp_path / "hooks.json", 0)

        output = capsys.readouterr().out
        assert "Written" in output
        assert "other hook(s) preserved" not in output

    def test_preserved_note_included_when_nonzero(self, tmp_path, capsys):
        _write_config({"hooks": {}}, tmp_path / "hooks.json", 2)

        # rich soft-wraps the line at the terminal width, so collapse whitespace first
        assert "(2 other hook(s) preserved)" in " ".join(capsys.readouterr().out.split())

    def test_codex_managed_writer_is_not_routed_through_write_config(self, tmp_path):
        path = tmp_path / "requirements.toml"
        with (
            patch(f"{_G}._write_config") as write,
            patch(f"{_G}._write_codex_managed_config", return_value=True) as write_managed,
        ):
            result = guard_module._write_client_config("codex", path, None, "toml-content", 2)

        assert result is True
        write.assert_not_called()
        write_managed.assert_called_once_with("toml-content", path)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX discovery script")
class TestDiscoveryHookScriptFiles:
    def test_copy_writes_executable_discovery_script_next_to_forwarder(self, tmp_path):
        config = tmp_path / "settings.json"

        discover_script = guard_module._discover_script_path(config)
        guard_module._copy_hook_script(discover_script)

        assert discover_script.read_text() == (
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            '[[ -n "${MACHINE_ID:-}" ]] || exit 0\n'
            '[[ -n "${AGENT_SCAN_COMMAND:-}" ]] || exit 0\n'
            'if [[ -x "$AGENT_SCAN_COMMAND" ]]; then\n'
            '  "$AGENT_SCAN_COMMAND" guard discover "$@" >/dev/null 2>&1 || true\n'
            "else\n"
            '  eval "$AGENT_SCAN_COMMAND guard discover \\"\\$@\\"" >/dev/null 2>&1 || true\n'
            "fi\n"
            "exit 0\n"
        )
        assert os.access(discover_script, os.X_OK)

    def test_copy_reports_discovery_script_checksums(self, tmp_path):
        import hashlib

        config = tmp_path / "settings.json"
        discover_script = guard_module._discover_script_path(config)
        script = guard_module._copy_hook_script(discover_script)

        assert script.current_checksum is None
        assert script.new_checksum == hashlib.sha256(discover_script.read_bytes()).hexdigest()

        discover_script.write_text("stale discovery script\n")
        script = guard_module._copy_hook_script(discover_script)

        assert script.current_checksum == hashlib.sha256(b"stale discovery script\n").hexdigest()
        assert script.new_checksum == hashlib.sha256(discover_script.read_bytes()).hexdigest()

    def test_stale_absolute_command_does_not_fall_back_to_path(self, tmp_path):
        script = Path(guard_module.__file__).parent / "hooks" / "snyk-agent-guard-discover.sh"
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "snyk-agent-scan"
        marker = tmp_path / "invoked"
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$MARKER"\n')
        stub.chmod(0o755)
        env = {
            **os.environ,
            "AGENT_SCAN_COMMAND": str(tmp_path / "deleted" / "snyk-agent-scan"),
            "MACHINE_ID": "machine-42",
            "MARKER": str(marker),
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        }

        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code"],
            input="{}",
            text=True,
            capture_output=True,
            timeout=5,
            env=env,
        )

        assert result.returncode == 0
        assert not marker.exists()

    def test_unset_command_does_not_fall_back_to_path(self, tmp_path):
        script = Path(guard_module.__file__).parent / "hooks" / "snyk-agent-guard-discover.sh"
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        stub = bin_dir / "snyk-agent-scan"
        marker = tmp_path / "invoked"
        stub.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        stub.chmod(0o755)
        env = {
            **os.environ,
            "MACHINE_ID": "machine-42",
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        }
        env.pop("AGENT_SCAN_COMMAND", None)

        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code"],
            input="{}",
            text=True,
            capture_output=True,
            timeout=5,
            env=env,
        )

        assert result.returncode == 0
        assert not marker.exists()

    def test_multi_word_command_receives_prefix_and_hook_arguments(self, tmp_path):
        script = Path(guard_module.__file__).parent / "hooks" / "snyk-agent-guard-discover.sh"
        marker = tmp_path / "invoked"
        stub = tmp_path / "runner"
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$MARKER"\n')
        stub.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code", "--scope", "servers"],
            input="{}",
            text=True,
            capture_output=True,
            timeout=5,
            env={
                **os.environ,
                "AGENT_SCAN_COMMAND": f"{stub} arg1",
                "MACHINE_ID": "machine-42",
                "MARKER": str(marker),
            },
        )

        assert result.returncode == 0
        assert marker.read_text() == "arg1 guard discover --client claude-code --scope servers\n"

    def test_shell_syntax_command_runs_from_requested_directory(self, tmp_path):
        script = Path(guard_module.__file__).parent / "hooks" / "snyk-agent-guard-discover.sh"
        marker = tmp_path / "invoked"
        stub = tmp_path / "runner"
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$MARKER"\n')
        stub.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script), "--client", "cursor", "--scope", "servers"],
            input="{}",
            text=True,
            capture_output=True,
            timeout=5,
            env={
                **os.environ,
                "AGENT_SCAN_COMMAND": f"cd {_shell_quote(str(tmp_path))}; ./runner",
                "MACHINE_ID": "machine-42",
                "MARKER": str(marker),
            },
        )

        assert result.returncode == 0
        assert marker.read_text() == "guard discover --client cursor --scope servers\n"

    def test_executable_path_with_spaces_is_invoked_verbatim(self, tmp_path):
        script = Path(guard_module.__file__).parent / "hooks" / "snyk-agent-guard-discover.sh"
        marker = tmp_path / "invoked"
        stub_dir = tmp_path / "dir with spaces"
        stub_dir.mkdir()
        stub = stub_dir / "runner"
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$MARKER"\n')
        stub.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script), "--client", "codex", "--scope", "servers"],
            input="{}",
            text=True,
            capture_output=True,
            timeout=5,
            env={
                **os.environ,
                "AGENT_SCAN_COMMAND": str(stub),
                "MACHINE_ID": "machine-42",
                "MARKER": str(marker),
            },
        )

        assert result.returncode == 0
        assert marker.read_text() == "guard discover --client codex --scope servers\n"

    def test_nonzero_discovery_exit_is_swallowed(self, tmp_path):
        script = Path(guard_module.__file__).parent / "hooks" / "snyk-agent-guard-discover.sh"
        stub = tmp_path / "snyk-agent-scan"
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(0o755)

        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code", "--scope", "servers"],
            input="{}",
            text=True,
            capture_output=True,
            timeout=5,
            env={**os.environ, "AGENT_SCAN_COMMAND": str(stub), "MACHINE_ID": "machine-42"},
        )

        assert result.returncode == 0

    def test_missing_machine_id_exits_zero_without_invoking_command(self, tmp_path):
        script = Path(guard_module.__file__).parent / "hooks" / "snyk-agent-guard-discover.sh"
        marker = tmp_path / "invoked"
        stub = tmp_path / "snyk-agent-scan"
        stub.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        stub.chmod(0o755)
        env = {**os.environ, "AGENT_SCAN_COMMAND": str(stub)}
        env.pop("MACHINE_ID", None)

        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code"],
            input="{}",
            text=True,
            capture_output=True,
            timeout=5,
            env=env,
        )

        assert result.returncode == 0
        assert not marker.exists()

    def test_copy_restores_missing_discovery_script_when_forwarder_is_current(self, tmp_path):
        config = tmp_path / "settings.json"
        guard_module._copy_hook_script(guard_module._forwarder_script_path(config))
        discover_script = guard_module._discover_script_path(config)
        guard_module._copy_hook_script(discover_script)
        discover_script.unlink()

        guard_module._copy_hook_script(discover_script)

        assert discover_script.exists()

    def test_copy_reports_update_when_only_discovery_script_changed(self, tmp_path):
        config = tmp_path / "settings.json"
        main_script = guard_module._forwarder_script_path(config)
        discover_script = guard_module._discover_script_path(config)
        guard_module._copy_hook_script(main_script)
        guard_module._copy_hook_script(discover_script)
        discover_script.unlink()

        copied_discovery = guard_module._copy_hook_script(discover_script)

        assert copied_discovery.updated is True

    def test_copy_reports_no_update_when_both_scripts_are_current(self, tmp_path):
        config = tmp_path / "settings.json"
        main_script = guard_module._forwarder_script_path(config)
        discover_script = guard_module._discover_script_path(config)
        guard_module._copy_hook_script(main_script)
        guard_module._copy_hook_script(discover_script)

        copied_main = guard_module._copy_hook_script(main_script)
        copied_discovery = guard_module._copy_hook_script(discover_script)

        assert copied_main.updated is False
        assert copied_discovery.updated is False

    def test_remove_deletes_both_scripts(self, tmp_path):
        config = tmp_path / "settings.json"
        main_script = guard_module._forwarder_script_path(config)
        discover_script = guard_module._discover_script_path(config)
        guard_module._copy_hook_script(main_script)
        guard_module._copy_hook_script(discover_script)

        guard_module._remove_hook_script("claude", config)

        assert not main_script.exists()
        assert not discover_script.exists()

    def test_full_claude_install_shape_then_uninstall_removes_entries_and_scripts(self, tmp_path):
        config = tmp_path / "settings.json"
        discover_command = (
            "PUSH_KEY='pk' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash '/x/snyk-agent-guard-discover.sh'"
        )
        settings, _, preserved = _prepare_claude_config(
            AGENT_SCAN_CMD,
            config,
            discover_command=discover_command,
        )
        _write_config(settings, config, preserved)
        main_script = guard_module._forwarder_script_path(config)
        discover_script = guard_module._discover_script_path(config)
        guard_module._copy_hook_script(main_script)
        guard_module._copy_hook_script(discover_script)

        _run_uninstall(SimpleNamespace(client="claude", file=str(config), managed=False))

        assert "hooks" not in json.loads(config.read_text())
        assert not main_script.exists()
        assert not discover_script.exists()


class TestWindowsDiscoveryHookScriptFiles:
    def test_copy_writes_discovery_script_next_to_forwarder(self, tmp_path):
        config = tmp_path / "settings.json"

        with patch(f"{_G}.IS_WINDOWS", True):
            discover_script = guard_module._discover_script_path(config)
            guard_module._copy_hook_script(discover_script)

        assert (
            discover_script.read_bytes()
            == (Path(guard_module.__file__).parent / "hooks" / "snyk-agent-guard-discover.ps1").read_bytes()
        )

    def test_copy_restores_missing_script_and_reports_update(self, tmp_path):
        config = tmp_path / "settings.json"
        with patch(f"{_G}.IS_WINDOWS", True):
            discover_script = guard_module._discover_script_path(config)
            guard_module._copy_hook_script(discover_script)
            discover_script.unlink()

            copied_discovery = guard_module._copy_hook_script(discover_script)

        assert discover_script.exists()
        assert copied_discovery.updated is True

    def test_remove_deletes_both_scripts(self, tmp_path):
        config = tmp_path / "settings.json"
        with patch(f"{_G}.IS_WINDOWS", True):
            main_script = guard_module._forwarder_script_path(config)
            discover_script = guard_module._discover_script_path(config)
            guard_module._copy_hook_script(main_script)
            guard_module._copy_hook_script(discover_script)

            guard_module._remove_hook_script("claude", config)

        assert not main_script.exists()
        assert not discover_script.exists()


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
# Claude Code: uninstall
# ===================================================================


class TestUninstallClaude:
    def test_missing_file(self, tmp_path):
        path = tmp_path / "settings.json"
        _uninstall_test_client("claude", path)  # should not raise

    def test_no_hooks_key(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"allowedTools": ["Bash"]})
        _uninstall_test_client("claude", path)

        data = json.loads(path.read_text())
        assert data == {"allowedTools": ["Bash"]}

    def test_no_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(OTHER_CMD, "*")]}})
        _uninstall_test_client("claude", path)

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
        _uninstall_test_client("claude", path)

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
        _uninstall_test_client("claude", path)

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
        _uninstall_test_client("claude", path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1
        assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == AGENTGUARD_CMD

    def test_backup_created(self, tmp_path):
        path = tmp_path / "settings.json"
        original = {"hooks": {"Stop": [_claude_group(AGENT_SCAN_CMD)]}}
        _write(path, original)
        _uninstall_test_client("claude", path)

        backup = Path(str(path) + ".backup")
        assert backup.exists()
        assert json.loads(backup.read_text()) == original

    def test_full_install_then_uninstall(self, tmp_path):
        """Install all events, then uninstall — should leave a clean file."""
        path = tmp_path / "settings.json"
        _write(path, {"allowedTools": ["Bash"]})
        _setup_claude_hooks(AGENT_SCAN_CMD, path)
        _uninstall_test_client("claude", path)

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
        _setup_claude_hooks(AGENT_SCAN_CMD, path)

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


# ===================================================================
# Cursor: uninstall
# ===================================================================


class TestUninstallCursor:
    def test_missing_file(self, tmp_path):
        path = tmp_path / "hooks.json"
        _uninstall_test_client("cursor", path)  # should not raise

    def test_no_hooks_key(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1})
        _uninstall_test_client("cursor", path)

        data = json.loads(path.read_text())
        assert data == {"version": 1}

    def test_no_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {"stop": [_cursor_entry(CURSOR_OTHER_CMD)]}})
        _uninstall_test_client("cursor", path)

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
        _uninstall_test_client("cursor", path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["stop"]) == 1
        assert data["hooks"]["stop"][0]["command"] == CURSOR_OTHER_CMD
        assert "sessionStart" not in data["hooks"]

    def test_leaves_empty_hooks_when_all_removed(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {"stop": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)]}})
        _uninstall_test_client("cursor", path)

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
        _uninstall_test_client("cursor", path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["stop"]) == 1
        assert data["hooks"]["stop"][0]["command"] == CURSOR_AGENTGUARD_CMD

    def test_backup_created(self, tmp_path):
        path = tmp_path / "hooks.json"
        original = {"version": 1, "hooks": {"stop": [_cursor_entry(CURSOR_AGENT_SCAN_CMD)]}}
        _write(path, original)
        _uninstall_test_client("cursor", path)

        backup = Path(str(path) + ".backup")
        assert backup.exists()
        assert json.loads(backup.read_text()) == original

    def test_full_install_then_uninstall(self, tmp_path):
        path = tmp_path / "hooks.json"
        _setup_cursor_hooks(CURSOR_AGENT_SCAN_CMD, path)
        _uninstall_test_client("cursor", path)

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
        _setup_cursor_hooks(CURSOR_AGENT_SCAN_CMD, path)

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

    def test_codex_user_default(self):
        assert _config_path("codex") == CODEX_HOOKS_PATH

    def test_claude_managed(self):
        assert _config_path("claude", managed=True) == CLAUDE_MANAGED_SETTINGS_PATH

    def test_cursor_managed(self):
        assert _config_path("cursor", managed=True) == CURSOR_MANAGED_HOOKS_PATH

    def test_codex_managed(self):
        assert _config_path("codex", managed=True) == CODEX_MANAGED_HOOKS_PATH

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

    def test_codex_managed_path_is_absolute(self):
        assert CODEX_MANAGED_HOOKS_PATH.is_absolute()

    def test_claude_managed_filename(self):
        assert CLAUDE_MANAGED_SETTINGS_PATH.name == "managed-settings.json"

    def test_cursor_managed_filename(self):
        assert CURSOR_MANAGED_HOOKS_PATH.name == "hooks.json"

    def test_codex_managed_filename(self):
        assert CODEX_MANAGED_HOOKS_PATH.name == "requirements.toml"

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

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-specific path")
    def test_unix_codex_managed_path(self):
        assert str(CODEX_MANAGED_HOOKS_PATH) == "/etc/codex/requirements.toml"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific paths")
    def test_windows_codex_managed_path(self):
        assert "Codex" in str(CODEX_MANAGED_HOOKS_PATH)
        assert "requirements.toml" in str(CODEX_MANAGED_HOOKS_PATH)


class TestManagedInstallClaude:
    """Verify hooks can be installed/detected/uninstalled at a managed path."""

    def test_install_to_managed_path(self, tmp_path):
        path = tmp_path / "managed-settings.json"
        _setup_claude_hooks(AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        hooks = data["hooks"]
        assert set(hooks.keys()) == set(CLAUDE_HOOK_EVENTS)

    def test_detect_at_managed_path(self, tmp_path):
        path = tmp_path / "managed-settings.json"
        _setup_claude_hooks(AGENT_SCAN_CMD, path)

        info = _detect_claude_install(path)
        assert info is not None
        assert info["auth_value"] == "pk-1234"

    def test_uninstall_from_managed_path(self, tmp_path):
        path = tmp_path / "managed-settings.json"
        _setup_claude_hooks(AGENT_SCAN_CMD, path)
        _uninstall_test_client("claude", path)

        data = json.loads(path.read_text())
        assert "hooks" not in data


class TestManagedInstallCursor:
    """Verify hooks can be installed/detected/uninstalled at a managed path."""

    def test_install_to_managed_path(self, tmp_path):
        path = tmp_path / "hooks.json"
        _setup_cursor_hooks(CURSOR_AGENT_SCAN_CMD, path)

        data = json.loads(path.read_text())
        hooks = data["hooks"]
        assert set(hooks.keys()) == set(CURSOR_HOOK_EVENTS)

    def test_detect_at_managed_path(self, tmp_path):
        path = tmp_path / "hooks.json"
        _setup_cursor_hooks(CURSOR_AGENT_SCAN_CMD, path)

        info = _detect_cursor_install(path)
        assert info is not None
        assert info["auth_value"] == "pk-1234"

    def test_uninstall_from_managed_path(self, tmp_path):
        path = tmp_path / "hooks.json"
        _setup_cursor_hooks(CURSOR_AGENT_SCAN_CMD, path)
        _uninstall_test_client("cursor", path)

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

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod has no effect on Windows")
    def test_detect_codex_raises_on_unreadable(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(CODEX_AGENT_SCAN_CMD)]}})
        path.chmod(0o000)
        try:
            with pytest.raises(PermissionError):
                _detect_codex_install(path)
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


class TestRunStatus:
    @staticmethod
    def _info() -> dict:
        return {
            "host": "guard.example",
            "auth_type": "pushkey",
            "auth_value": "pk-1234567890",
            "tenant_id": "tid-1",
            "url": "https://guard.example",
            "events": ["PreToolUse", "Stop"],
        }

    def test_prints_user_then_managed_sections_in_client_order(self, capsys):
        with (
            patch(f"{_G}._detect_claude_install", return_value=None),
            patch(f"{_G}._detect_cursor_install", return_value=None),
            patch(f"{_G}._detect_codex_install", return_value=None),
        ):
            guard_module._run_status()

        output = capsys.readouterr().out
        expected_paths = [
            CLAUDE_SETTINGS_PATH,
            CURSOR_HOOKS_PATH,
            CODEX_HOOKS_PATH,
            CLAUDE_MANAGED_SETTINGS_PATH,
            CURSOR_MANAGED_HOOKS_PATH,
            CODEX_MANAGED_HOOKS_PATH,
        ]
        positions = [output.index(str(path)) for path in expected_paths]
        assert positions == sorted(positions)
        assert output.index("User-level hooks:") < positions[0]
        assert positions[2] < output.index("Managed hooks:") < positions[3]
        lines = output.splitlines()
        assert sum(line.startswith("Claude Code   ") for line in lines) == 2
        assert sum(line.startswith("Cursor   ") for line in lines) == 2
        assert sum(line.startswith("Codex   ") for line in lines) == 2

    def test_all_not_installed(self, capsys):
        with (
            patch(f"{_G}._detect_claude_install", return_value=None),
            patch(f"{_G}._detect_cursor_install", return_value=None),
            patch(f"{_G}._detect_codex_install", return_value=None),
        ):
            guard_module._run_status()

        assert capsys.readouterr().out.count("NOT INSTALLED") == 6

    def test_installed_shows_host_masked_key_and_events(self, capsys):
        with (
            patch(f"{_G}._detect_claude_install", return_value=self._info()),
            patch(f"{_G}._detect_cursor_install", return_value=None),
            patch(f"{_G}._detect_codex_install", return_value=None),
        ):
            guard_module._run_status()

        output = capsys.readouterr().out
        assert "guard.example" in output
        assert "pk-1...7890" in output
        assert "(PreToolUse, Stop)" in output

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_managed_permission_error_renders_unreadable(self, capsys, client):
        def detector(name):
            def detect(*args):
                if name == client and args:
                    raise PermissionError("denied")
                return None

            return detect

        with (
            patch(f"{_G}._detect_claude_install", side_effect=detector("claude")),
            patch(f"{_G}._detect_cursor_install", side_effect=detector("cursor")),
            patch(f"{_G}._detect_codex_install", side_effect=detector("codex")),
        ):
            guard_module._run_status()

        assert capsys.readouterr().out.count("UNREADABLE") == 1

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_user_level_permission_error_propagates(self, capsys, client):
        def detector(name):
            def detect(*_args):
                if name == client:
                    raise PermissionError("denied")
                return None

            return detect

        with (
            patch(f"{_G}._detect_claude_install", side_effect=detector("claude")),
            patch(f"{_G}._detect_cursor_install", side_effect=detector("cursor")),
            patch(f"{_G}._detect_codex_install", side_effect=detector("codex")),
        ):
            with pytest.raises(PermissionError, match="denied"):
                guard_module._run_status()
            capsys.readouterr()

            result = guard_module.run_guard(SimpleNamespace(guard_command="status"))

        assert result == 1
        assert "Permission denied: denied" in capsys.readouterr().out

    def test_help_footer_present(self, capsys):
        with (
            patch(f"{_G}._detect_claude_install", return_value=None),
            patch(f"{_G}._detect_cursor_install", return_value=None),
            patch(f"{_G}._detect_codex_install", return_value=None),
        ):
            guard_module._run_status()

        output = capsys.readouterr().out
        assert "interactive flow (user-level)" in output
        assert "managed flow" in output
        assert "headless flow (MDM)" in output
        assert "guard uninstall <client>" in output


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


# ===================================================================
# Codex: install / uninstall / detect
# ===================================================================


CODEX_AGENT_SCAN_CMD = (
    "PUSH_KEY='pk-codex' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' "
    "TENANT_ID='tid-1' bash '/home/u/.codex/hooks/snyk-agent-guard.sh' --client codex"
)
CODEX_DISCOVER_CMD = (
    "PUSH_KEY='pk-discover' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' "
    "AGENT_SCAN_COMMAND='/usr/local/bin/snyk-agent-scan' "
    "bash '/home/u/.codex/hooks/snyk-agent-guard-discover.sh' --client codex --scope servers"
)


class TestUninstallCodex:
    def test_missing_file(self, tmp_path):
        _uninstall_test_client("codex", tmp_path / "hooks.json")  # should not raise

    def test_no_hooks_key(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"allowedTools": ["Bash"]})
        _uninstall_test_client("codex", path)

        data = json.loads(path.read_text())
        assert data == {"allowedTools": ["Bash"]}

    def test_no_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(OTHER_CMD)]}})
        _uninstall_test_client("codex", path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1

    def test_removes_only_agent_scan(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(OTHER_CMD), _claude_group(CODEX_AGENT_SCAN_CMD)],
                    "Stop": [_claude_group(CODEX_AGENT_SCAN_CMD)],
                }
            },
        )
        _uninstall_test_client("codex", path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1
        assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == OTHER_CMD
        assert "Stop" not in data["hooks"]

    def test_removes_hooks_key_when_empty(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(CODEX_AGENT_SCAN_CMD)]}})
        _uninstall_test_client("codex", path)

        data = json.loads(path.read_text())
        assert "hooks" not in data

    def test_preserves_agentguard(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [
                        _claude_group(AGENTGUARD_CMD),
                        _claude_group(CODEX_AGENT_SCAN_CMD),
                    ],
                }
            },
        )
        _uninstall_test_client("codex", path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1
        assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == AGENTGUARD_CMD

    def test_backup_created(self, tmp_path):
        path = tmp_path / "hooks.json"
        original = {"hooks": {"Stop": [_claude_group(CODEX_AGENT_SCAN_CMD)]}}
        _write(path, original)
        _uninstall_test_client("codex", path)

        backup = Path(str(path) + ".backup")
        assert backup.exists()
        assert json.loads(backup.read_text()) == original

    def test_full_install_then_uninstall(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"unrelated": True})
        _setup_codex_hooks(CODEX_AGENT_SCAN_CMD, path)
        _uninstall_test_client("codex", path)

        data = json.loads(path.read_text())
        assert "hooks" not in data
        assert data["unrelated"] is True


class TestDetectCodex:
    def test_missing_file(self, tmp_path):
        assert _detect_codex_install(tmp_path / "nope.json") is None

    def test_empty_file(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {})
        assert _detect_codex_install(path) is None

    def test_no_hooks_key(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"other": 1})
        assert _detect_codex_install(path) is None

    def test_no_agent_scan_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(OTHER_CMD)]}})
        assert _detect_codex_install(path) is None

    def test_detects_after_install(self, tmp_path):
        path = tmp_path / "hooks.json"
        _setup_codex_hooks(CODEX_AGENT_SCAN_CMD, path)

        info = _detect_codex_install(path)
        assert info is not None
        assert info["auth_type"] == "pushkey"
        assert info["auth_value"] == "pk-codex"
        assert info["tenant_id"] == "tid-1"
        assert info["host"] == "api.snyk.io"
        assert set(info["events"]) == set(CODEX_HOOK_EVENTS)

    def test_detects_partial_install(self, tmp_path):
        """Only some events have our hooks."""
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(CODEX_AGENT_SCAN_CMD)],
                    "Stop": [_claude_group(CODEX_AGENT_SCAN_CMD)],
                }
            },
        )
        info = _detect_codex_install(path)
        assert info is not None
        assert info["events"] == ["PreToolUse", "Stop"]

    def test_ignores_agentguard(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(AGENTGUARD_CMD)]}})
        assert _detect_codex_install(path) is None

    def test_detects_among_other_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [
                        _claude_group(AGENTGUARD_CMD),
                        _claude_group(CODEX_AGENT_SCAN_CMD),
                    ],
                }
            },
        )
        info = _detect_codex_install(path)
        assert info is not None
        assert info["events"] == ["PreToolUse"]

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "hooks.json"
        path.write_text("not json at all")
        with pytest.raises(json.JSONDecodeError):
            _detect_codex_install(path)


class TestDetectInstall:
    @staticmethod
    def _events(client: str) -> list[str]:
        return {
            "claude": CLAUDE_HOOK_EVENTS,
            "cursor": CURSOR_HOOK_EVENTS,
            "codex": CODEX_HOOK_EVENTS,
        }[client]

    @staticmethod
    def _entries(client: str, *commands: str) -> list[dict]:
        if client == "cursor":
            return [_cursor_entry(command) for command in commands]
        return [_claude_group(command) for command in commands]

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_events_follow_constant_order_not_file_order(self, tmp_path, client):
        first, last = self._events(client)[0], self._events(client)[-1]
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "hooks": {
                    last: self._entries(client, CODEX_AGENT_SCAN_CMD),
                    first: self._entries(client, CODEX_AGENT_SCAN_CMD),
                }
            },
        )

        info = _detect_test_client(client, path)

        assert info is not None
        assert info["events"] == [first, last]

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_event_listed_once_when_multiple_commands_match(self, tmp_path, client):
        event = self._events(client)[0]
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {event: self._entries(client, CODEX_AGENT_SCAN_CMD, CODEX_DISCOVER_CMD)}})

        info = _detect_test_client(client, path)

        assert info is not None
        assert info["events"] == [event]

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_first_match_in_constant_order_supplies_parsed_command(self, tmp_path, client):
        first, last = self._events(client)[0], self._events(client)[-1]
        first_command = (
            "PUSH_KEY='pk-first' REMOTE_HOOKS_BASE_URL='https://first.example' "
            "bash '/x/snyk-agent-guard.sh' --client test"
        )
        later_discovery_command = (
            "PUSH_KEY='pk-later' REMOTE_HOOKS_BASE_URL='https://later.example' "
            "bash '/x/snyk-agent-guard-discover.sh' --client test --scope servers"
        )
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "hooks": {
                    last: self._entries(client, later_discovery_command),
                    first: self._entries(client, first_command),
                }
            },
        )

        info = _detect_test_client(client, path)

        assert info is not None
        assert info["auth_value"] == "pk-first"
        assert info["host"] == "first.example"

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_group_without_hooks_key(self, tmp_path, client):
        event = self._events(client)[0]
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {event: [{"type": "command"}]}})

        assert _detect_test_client(client, path) is None

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_entry_without_command_key(self, tmp_path, client):
        event = self._events(client)[0]
        entries = [{"hooks": [{"type": "command"}]}] if client != "cursor" else [{"other": True}]
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {event: entries}})

        assert _detect_test_client(client, path) is None

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    @pytest.mark.parametrize("entry", ["string", None])
    def test_non_dict_entry_in_event_list(self, tmp_path, client, entry):
        event = self._events(client)[0]
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {event: [entry]}})

        with pytest.raises(AttributeError):
            _detect_test_client(client, path)

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_unknown_events_ignored(self, tmp_path, client):
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {"CustomEvent": self._entries(client, CODEX_AGENT_SCAN_CMD)}})

        assert _detect_test_client(client, path) is None

    def test_claude_shaped_file_read_by_cursor_detector_returns_none(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {"stop": [_claude_group(CODEX_AGENT_SCAN_CMD)]}})

        assert _detect_cursor_install(path) is None

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_permission_error_propagates(self, tmp_path, client):
        path = tmp_path / "hooks.json"
        _write(path, {})
        with patch(f"{_G}._read_json_or_empty", side_effect=PermissionError("denied")):
            with pytest.raises(PermissionError, match="denied"):
                _detect_test_client(client, path)


class TestUninstallHooks:
    @staticmethod
    def _event_and_entry(client: str, command: str) -> tuple[str, dict]:
        if client == "cursor":
            return "stop", _cursor_entry(command)
        return "Stop", _claude_group(command)

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_removes_both_forwarder_and_discover_commands(self, tmp_path, capsys, client):
        path = tmp_path / ("settings.json" if client == "claude" else "hooks.json")
        prepare = {
            "claude": _prepare_claude_config,
            "cursor": _prepare_cursor_config,
            "codex": _prepare_codex_config,
        }[client]
        config, _, preserved = prepare(CODEX_AGENT_SCAN_CMD, path, discover_command=CODEX_DISCOVER_CMD)
        _write_config(config, path, preserved)
        capsys.readouterr()

        _uninstall_test_client(client, path)

        expected_removed = len(self._events_for(client)) + 1
        assert f"Removed {expected_removed} Agent Guard hook(s)" in capsys.readouterr().out

    @staticmethod
    def _events_for(client: str) -> list[str]:
        return {
            "claude": CLAUDE_HOOK_EVENTS,
            "cursor": CURSOR_HOOK_EVENTS,
            "codex": CODEX_HOOK_EVENTS,
        }[client]

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    @pytest.mark.parametrize("filename", ["settings.json", "managed-settings.json", "custom.json"])
    def test_missing_file_message_names_the_actual_file(self, tmp_path, capsys, client, filename):
        _uninstall_test_client(client, tmp_path / filename)

        assert f"No {filename} found. Nothing to uninstall." in capsys.readouterr().out

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_overwrites_existing_backup(self, tmp_path, client):
        event, entry = self._event_and_entry(client, CODEX_AGENT_SCAN_CMD)
        path = tmp_path / ("settings.json" if client == "claude" else "hooks.json")
        original = {"hooks": {event: [entry]}, "current": True}
        _write(path, original)
        backup = Path(f"{path}.backup")
        backup.write_text("stale backup")

        _uninstall_test_client(client, path)

        assert json.loads(backup.read_text()) == original

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_no_backup_when_nothing_matched(self, tmp_path, client):
        event, entry = self._event_and_entry(client, OTHER_CMD)
        path = tmp_path / ("settings.json" if client == "claude" else "hooks.json")
        _write(path, {"hooks": {event: [entry]}})

        _uninstall_test_client(client, path)

        assert not Path(f"{path}.backup").exists()

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    @pytest.mark.parametrize("entry", ["string", None])
    def test_survives_non_dict_entries_in_hook_list(self, tmp_path, client, entry):
        event, _ = self._event_and_entry(client, OTHER_CMD)
        path = tmp_path / ("settings.json" if client == "claude" else "hooks.json")
        original = {"hooks": {event: [entry]}}
        _write(path, original)

        with pytest.raises(AttributeError):
            _uninstall_test_client(client, path)

        assert json.loads(path.read_text()) == original
        assert not Path(f"{path}.backup").exists()

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    @pytest.mark.parametrize("hooks", [[], "x"])
    def test_hooks_value_not_a_dict(self, tmp_path, client, hooks):
        path = tmp_path / ("settings.json" if client == "claude" else "hooks.json")
        _write(path, {"hooks": hooks})

        with pytest.raises(AttributeError):
            _uninstall_test_client(client, path)

    def test_codex_toml_path_routes_to_managed_uninstall(self, tmp_path):
        path = tmp_path / "requirements.toml"
        args = SimpleNamespace(file=str(path))
        with (
            patch(f"{_G}._detect_existing_install", return_value=None),
            patch(f"{_G}._uninstall_hooks") as uninstall,
            patch(f"{_G}._uninstall_codex_managed") as uninstall_managed,
            patch(f"{_G}._remove_hook_script"),
            patch(f"{_G}.rich"),
        ):
            guard_module._uninstall_single_client("codex", args, managed=True)

        uninstall.assert_not_called()
        uninstall_managed.assert_called_once_with(path)

    @pytest.mark.parametrize("client", ["claude", "cursor", "codex"])
    def test_preserves_unknown_events(self, tmp_path, client):
        known_event, guard_entry = self._event_and_entry(client, CODEX_AGENT_SCAN_CMD)
        _, foreign_entry = self._event_and_entry(client, OTHER_CMD)
        path = tmp_path / ("settings.json" if client == "claude" else "hooks.json")
        _write(
            path,
            {
                "hooks": {
                    known_event: [guard_entry],
                    "CustomEvent": [foreign_entry],
                }
            },
        )

        _uninstall_test_client(client, path)

        data = json.loads(path.read_text())
        assert known_event not in data["hooks"]
        assert data["hooks"]["CustomEvent"] == [foreign_entry]


# ===================================================================
# Codex managed: requirements.toml install / uninstall / detect
# ===================================================================


class TestCodexManagedRequirementsToml:
    def _import_managed_helpers(self):
        from agent_scan.guard import (
            _detect_codex_managed_install,
            _render_codex_requirements_toml,
            _uninstall_codex_managed,
        )

        def _install(command, path, _script=None, *, discover_command=None):
            content, _ = _prepare_codex_managed_config(
                command,
                path,
                discover_command=discover_command,
            )
            return _write_codex_managed_config(content, path)

        return (
            _install,
            _uninstall_codex_managed,
            _detect_codex_managed_install,
            _render_codex_requirements_toml,
        )

    def test_render_contains_features_and_all_events(self, tmp_path):
        _, _, _, render = self._import_managed_helpers()
        path = tmp_path / "requirements.toml"
        content = render(CODEX_AGENT_SCAN_CMD, path)
        assert "[features]" in content
        assert "hooks = true" in content
        assert "[hooks]" in content
        assert "managed_dir" in content
        assert "windows_managed_dir" in content
        for event in CODEX_HOOK_EVENTS:
            assert f"[[hooks.{event}]]" in content
            assert f"[[hooks.{event}.hooks]]" in content

    def test_render_adds_async_discovery_group_only_to_session_start(self, tmp_path):
        _, _, _, render = self._import_managed_helpers()

        content = render(
            CODEX_AGENT_SCAN_CMD,
            tmp_path / "requirements.toml",
            discover_command=CODEX_DISCOVER_CMD,
        )

        assert content.count("[[hooks.SessionStart]]") == 2
        assert CODEX_DISCOVER_CMD in content
        assert f'command = "{CODEX_DISCOVER_CMD}"\nasync = true' in content
        for event in set(CODEX_HOOK_EVENTS) - {"SessionStart"}:
            assert content.count(f"[[hooks.{event}]]") == 1

    def test_render_none_preserves_existing_output(self, tmp_path):
        _, _, _, render = self._import_managed_helpers()
        path = tmp_path / "requirements.toml"
        if IS_WINDOWS:
            managed_dir = "/etc/codex/hooks"
            windows_managed_dir = str(tmp_path / "hooks")
        else:
            managed_dir = (tmp_path / "hooks").as_posix()
            windows_managed_dir = r"C:\ProgramData\OpenAI\Codex\hooks"
        expected_lines = [
            "[features]",
            "hooks = true",
            "",
            "[hooks]",
            f'managed_dir = "{managed_dir}"',
            f"windows_managed_dir = '{windows_managed_dir}'",
            "",
        ]
        for event in CODEX_HOOK_EVENTS:
            expected_lines.extend(
                [
                    f"[[hooks.{event}]]",
                    f"[[hooks.{event}.hooks]]",
                    'type = "command"',
                    f'command = "{CODEX_AGENT_SCAN_CMD}"',
                    "",
                ]
            )

        assert render(CODEX_AGENT_SCAN_CMD, path, discover_command=None) == "\n".join(expected_lines).rstrip() + "\n"

    def test_rendered_discovery_toml_is_valid(self, tmp_path):
        tomllib = pytest.importorskip("tomllib")
        _, _, _, render = self._import_managed_helpers()

        parsed = tomllib.loads(
            render(
                CODEX_AGENT_SCAN_CMD,
                tmp_path / "requirements.toml",
                discover_command=CODEX_DISCOVER_CMD,
            )
        )

        assert len(parsed["hooks"]["SessionStart"]) == 2
        assert parsed["hooks"]["SessionStart"][1]["hooks"] == [
            {"type": "command", "command": CODEX_DISCOVER_CMD, "async": True}
        ]

    def test_render_parse_round_trip_splits_guard_and_discovery_commands(self, tmp_path):
        _, _, _, render = self._import_managed_helpers()
        content = render(
            CODEX_AGENT_SCAN_CMD,
            tmp_path / "requirements.toml",
            discover_command=CODEX_DISCOVER_CMD,
        )

        events, guard_command, discover_command = _parse_codex_requirements_toml(content)

        assert events == CODEX_HOOK_EVENTS
        assert guard_command == CODEX_AGENT_SCAN_CMD
        assert discover_command == CODEX_DISCOVER_CMD

    def test_install_writes_toml(self, tmp_path):
        install, _, _, _ = self._import_managed_helpers()
        path = tmp_path / "requirements.toml"
        script = tmp_path / "hooks" / "snyk-agent-guard.sh"
        changed = install(CODEX_AGENT_SCAN_CMD, path, script)
        assert changed
        text = path.read_text()
        assert "PUSH_KEY" in text
        assert CODEX_AGENT_SCAN_CMD in text

    def test_install_idempotent(self, tmp_path):
        install, _, _, _ = self._import_managed_helpers()
        path = tmp_path / "requirements.toml"
        script = tmp_path / "hooks" / "snyk-agent-guard.sh"
        install(CODEX_AGENT_SCAN_CMD, path, script)
        assert install(CODEX_AGENT_SCAN_CMD, path, script) is False

    def test_guard_install_writes_discovery_script_and_toml_entry(self, tmp_path):
        path = tmp_path / "requirements.toml"

        with (
            patch(f"{_G}.IS_WINDOWS", False),
            patch(f"{_G}._send_test_event", return_value=True),
            patch(f"{_G}.rich"),
            patch.dict(os.environ, {"AGENT_SCAN_COMMAND": "/usr/local/bin/snyk-agent-scan"}),
        ):
            _install_hooks(
                "codex",
                "codex",
                "pk-test",
                "https://api.snyk.io",
                path,
                "managed",
                "Codex",
                False,
                "tid-1",
                "snyk-token",
                "machine-42",
            )

        assert (tmp_path / "hooks" / "snyk-agent-guard.sh").exists()
        assert (tmp_path / "hooks" / "snyk-agent-guard-discover.sh").exists()
        text = path.read_text()
        assert text.count("[[hooks.SessionStart]]") == 2
        assert "snyk-agent-guard-discover.sh" in text
        assert "AGENT_SCAN_COMMAND='/usr/local/bin/snyk-agent-scan'" in text

    def test_guard_install_without_agent_scan_command_warns_and_removes_stale_discovery_script(self, tmp_path):
        path = tmp_path / "requirements.toml"
        discover_script = tmp_path / "hooks" / "snyk-agent-guard-discover.sh"
        discover_script.parent.mkdir(parents=True)
        discover_script.write_text("stale\n")

        with (
            patch(f"{_G}.IS_WINDOWS", False),
            patch(f"{_G}._agent_scan_command", return_value=None),
            patch(f"{_G}._send_test_event", return_value=True),
            patch(f"{_G}.rich") as rich,
        ):
            _install_hooks(
                "codex",
                "codex",
                "pk-test",
                "https://api.snyk.io",
                path,
                "managed",
                "Codex",
                False,
                "tid-1",
                "snyk-token",
                "machine-42",
            )

        assert not discover_script.exists()
        assert "snyk-agent-guard-discover" not in path.read_text()
        assert any("AGENT_SCAN_COMMAND is not set" in call.args[0] for call in rich.print.call_args_list if call.args)

    def test_detect_after_install(self, tmp_path):
        install, _, detect, _ = self._import_managed_helpers()
        path = tmp_path / "requirements.toml"
        script = tmp_path / "hooks" / "snyk-agent-guard.sh"
        install(CODEX_AGENT_SCAN_CMD, path, script)

        info = detect(path)
        assert info is not None
        assert info["auth_value"] == "pk-codex"
        assert info["tenant_id"] == "tid-1"
        assert set(info["events"]) == set(CODEX_HOOK_EVENTS)

    def test_detect_uses_guard_command_when_discovery_block_is_first(self, tmp_path):
        _, _, detect, _ = self._import_managed_helpers()
        path = tmp_path / "requirements.toml"
        path.write_text(
            "[[hooks.SessionStart]]\n"
            "[[hooks.SessionStart.hooks]]\n"
            'type = "command"\n'
            f'command = "{CODEX_DISCOVER_CMD}"\n'
            "async = true\n\n"
            "[[hooks.PreToolUse]]\n"
            "[[hooks.PreToolUse.hooks]]\n"
            'type = "command"\n'
            f'command = "{CODEX_AGENT_SCAN_CMD}"\n'
        )

        info = detect(path)

        assert info is not None
        assert info["auth_value"] == "pk-codex"
        assert info["tenant_id"] == "tid-1"

    def test_prepare_with_same_commands_is_idempotent(self, tmp_path):
        path = tmp_path / "requirements.toml"
        content, _ = _prepare_codex_managed_config(
            CODEX_AGENT_SCAN_CMD,
            path,
            discover_command=CODEX_DISCOVER_CMD,
        )
        path.write_text(content)

        _, diff = _prepare_codex_managed_config(
            CODEX_AGENT_SCAN_CMD,
            path,
            discover_command=CODEX_DISCOVER_CMD,
        )

        assert diff == {"added": {}, "modified": {}, "removed": {}}

    def test_prepare_marks_discover_only_change_as_session_start_modified(self, tmp_path):
        path = tmp_path / "requirements.toml"
        content, _ = _prepare_codex_managed_config(
            CODEX_AGENT_SCAN_CMD,
            path,
            discover_command=CODEX_DISCOVER_CMD,
        )
        path.write_text(content)
        new_discover_command = CODEX_DISCOVER_CMD.replace("/usr/local/bin", "/opt/snyk/bin")

        _, diff = _prepare_codex_managed_config(
            CODEX_AGENT_SCAN_CMD,
            path,
            discover_command=new_discover_command,
        )

        assert set(diff["modified"]) == {"SessionStart"}
        assert diff["modified"]["SessionStart"]["expected_value"][1]["command"] == new_discover_command
        assert diff["modified"]["SessionStart"]["actual_value"][1]["command"] == CODEX_DISCOVER_CMD

    def test_detect_dispatches_via_extension(self, tmp_path):
        install, _, _, _ = self._import_managed_helpers()
        path = tmp_path / "requirements.toml"
        script = tmp_path / "hooks" / "snyk-agent-guard.sh"
        install(CODEX_AGENT_SCAN_CMD, path, script)

        info = _detect_codex_install(path)
        assert info is not None
        assert info["auth_value"] == "pk-codex"

    def test_uninstall_removes_file(self, tmp_path):
        install, uninstall, _, _ = self._import_managed_helpers()
        path = tmp_path / "requirements.toml"
        script = tmp_path / "hooks" / "snyk-agent-guard.sh"
        install(CODEX_AGENT_SCAN_CMD, path, script)
        assert path.exists()
        uninstall(path)
        assert not path.exists()

    def test_uninstall_missing_file_is_noop(self, tmp_path):
        _, uninstall, _, _ = self._import_managed_helpers()
        uninstall(tmp_path / "requirements.toml")  # should not raise

    def test_parse_backslash_path_no_unicode_escape(self):
        toml = (
            "[[hooks.PreToolUse.hooks]]\n"
            'type = "command"\n'
            "command = \"PUSH_KEY='pk' bash 'C:\\\\Users\\\\me\\\\hooks\\\\snyk-agent-guard.sh' --client codex\"\n"
        )
        events, cmd, discover_cmd = _parse_codex_requirements_toml(toml)
        assert "PreToolUse" in events
        assert "C:\\Users\\me\\hooks\\snyk-agent-guard.sh" in cmd
        assert discover_cmd is None

    def test_discovery_backslash_path_round_trips(self, tmp_path):
        _, _, _, render = self._import_managed_helpers()
        discover_command = CODEX_DISCOVER_CMD.replace(
            "bash '/home/u/.codex/hooks/snyk-agent-guard-discover.sh'",
            r"bash 'C:\ProgramData\OpenAI\Codex\hooks\snyk-agent-guard-discover.sh'",
        )

        content = render(
            CODEX_AGENT_SCAN_CMD,
            tmp_path / "requirements.toml",
            discover_command=discover_command,
        )
        _, _, parsed_discover = _parse_codex_requirements_toml(content)

        assert parsed_discover == discover_command

    def test_prepare_survives_unparseable_existing_toml(self, tmp_path):
        path = tmp_path / "requirements.toml"
        path.write_text('command = "C:\\Users\\bad"\n')
        content, diff = _prepare_codex_managed_config(CODEX_AGENT_SCAN_CMD, path)
        assert "[features]" in content
        assert diff["removed"]


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
                "MACHINE_ID": "machine-42",
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

    def test_posts_large_payload_without_exec_argument_limit(self, hook_server):
        script = _get_script_path("snyk-agent-guard.sh")
        payload = json.dumps(
            {
                "hook_event_name": "serversDiscovered",
                "session_id": "s1",
                "servers": ["x" * (1024 * 1024)],
            }
        )
        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "PUSH_KEY": "test-pk-large-payload",
                "REMOTE_HOOKS_BASE_URL": hook_server,
                "MACHINE_ID": "machine-42",
            },
        )

        assert result.returncode == 0, result.stderr
        req = _HookHandler.last_request
        assert req is not None
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
                "MACHINE_ID": "machine-42",
            },
        )
        assert result.returncode == 0, result.stderr
        assert "/hidden/agent-monitor/hooks/cursor" in _HookHandler.last_request["path"]

    def test_codex_endpoint(self, hook_server):
        script = _get_script_path("snyk-agent-guard.sh")
        payload = '{"hook_event_name":"hooksConfigured","session_id":"s1"}'
        result = subprocess.run(
            ["bash", str(script), "--client", "codex"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "PUSH_KEY": "test-pk-codex",
                "REMOTE_HOOKS_BASE_URL": hook_server,
                "MACHINE_ID": "machine-42",
            },
        )
        assert result.returncode == 0, result.stderr
        assert "/hidden/agent-monitor/hooks/codex" in _HookHandler.last_request["path"]

    def test_machine_id_sets_x_user_identifier(self, hook_server):
        script = _get_script_path("snyk-agent-guard.sh")
        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code"],
            input='{"hook_event_name":"test","session_id":"s1"}',
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "PUSH_KEY": "test-pk",
                "REMOTE_HOOKS_BASE_URL": hook_server,
                "MACHINE_ID": "machine-42",
            },
        )
        assert result.returncode == 0, result.stderr
        x_user = json.loads(_HookHandler.last_request["headers"]["X-User"])
        assert x_user["identifier"] == "machine-42"

    def test_missing_machine_id_fails(self, hook_server):
        script = _get_script_path("snyk-agent-guard.sh")
        result = subprocess.run(
            ["bash", str(script), "--client", "claude-code"],
            input='{"hook_event_name":"test","session_id":"s1"}',
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "PUSH_KEY": "test-pk",
                "REMOTE_HOOKS_BASE_URL": hook_server,
            },
        )
        assert result.returncode != 0
        assert "MACHINE_ID" in result.stderr

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
                "MACHINE_ID": "machine-42",
            },
        )
        assert result.returncode != 0
        assert "REMOTE_HOOKS_BASE_URL" in result.stderr


@pytest.mark.skipif(not IS_WINDOWS, reason="PowerShell script; Windows only")
class TestPowerShellDiscoveryHookScript:
    """Integration: execute the real discover .ps1, mirroring the POSIX .sh coverage.

    The POSIX trampoline lets the child inherit stdin; these tests pin the same
    behaviour on Windows, which is the contract the script relies on.
    """

    @pytest.fixture(autouse=True)
    def _skip_no_powershell(self):
        if not shutil.which("powershell") and not shutil.which("pwsh"):
            pytest.skip("powershell not available")

    @staticmethod
    def _ps_cmd():
        return "powershell" if shutil.which("powershell") else "pwsh"

    @staticmethod
    def _recording_stub(tmp_path: Path, marker: Path) -> Path:
        """A ``snyk-agent-scan.cmd`` stub recording its argv and stdin to *marker*."""
        helper = tmp_path / "record.py"
        helper.write_text(
            "import os, sys\n"
            "with open(os.environ['MARKER'], 'w') as fh:\n"
            "    fh.write(' '.join(sys.argv[1:]) + '\\n')\n"
            "    fh.write(sys.stdin.read())\n"
        )
        stub = tmp_path / "snyk-agent-scan.cmd"
        stub.write_text(f'@echo off\r\n"{sys.executable}" "{helper}" %*\r\n')
        return stub

    def _run(self, script: Path, extra_args: list[str], env: dict, payload: str = "{}"):
        return subprocess.run(
            [self._ps_cmd(), "-File", str(script), "-Client", "claude-code", *extra_args],
            input=payload,
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def test_stdin_payload_and_arguments_reach_the_child(self, tmp_path):
        """The whole point of inheriting stdin: guard discover sees the hook payload."""
        script = _get_script_path("snyk-agent-guard-discover.ps1")
        marker = tmp_path / "invoked"
        stub = self._recording_stub(tmp_path, marker)
        payload = '{"cwd":"C:\\\\work\\\\project","session_id":"s1"}'

        result = self._run(
            script,
            ["-AgentScanCommand", str(stub), "-MachineId", "machine-42"],
            {**os.environ, "MARKER": str(marker)},
            payload=payload,
        )

        assert result.returncode == 0, result.stderr
        recorded = marker.read_text().splitlines()
        assert recorded[0] == "guard discover --client claude-code --scope servers"
        assert json.loads("\n".join(recorded[1:])) == json.loads(payload)

    def test_nonzero_discovery_exit_is_swallowed(self, tmp_path):
        script = _get_script_path("snyk-agent-guard-discover.ps1")
        stub = tmp_path / "snyk-agent-scan.cmd"
        stub.write_text("@echo off\r\nexit /b 1\r\n")

        result = self._run(
            script,
            ["-AgentScanCommand", str(stub), "-MachineId", "machine-42"],
            dict(os.environ),
        )

        assert result.returncode == 0
        assert result.stderr == ""

    def test_missing_machine_id_exits_zero_without_invoking_command(self, tmp_path):
        script = _get_script_path("snyk-agent-guard-discover.ps1")
        marker = tmp_path / "invoked"
        stub = self._recording_stub(tmp_path, marker)
        env = {**os.environ, "MARKER": str(marker)}
        env.pop("MACHINE_ID", None)

        result = self._run(script, ["-AgentScanCommand", str(stub)], env)

        assert result.returncode == 0
        assert not marker.exists()

    def test_stale_absolute_command_does_not_fall_back_to_path(self, tmp_path):
        script = _get_script_path("snyk-agent-guard-discover.ps1")
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        marker = tmp_path / "invoked"
        self._recording_stub(bin_dir, marker)
        env = {
            **os.environ,
            "MARKER": str(marker),
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        }

        result = self._run(
            script,
            ["-AgentScanCommand", str(tmp_path / "deleted" / "snyk-agent-scan.exe"), "-MachineId", "machine-42"],
            env,
        )

        assert result.returncode == 0, result.stderr
        assert not marker.exists()

    def test_unset_command_does_not_fall_back_to_path(self, tmp_path):
        script = _get_script_path("snyk-agent-guard-discover.ps1")
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        marker = tmp_path / "invoked"
        self._recording_stub(bin_dir, marker)
        env = {
            **os.environ,
            "MARKER": str(marker),
            "MACHINE_ID": "machine-42",
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        }
        env.pop("AGENT_SCAN_COMMAND", None)

        result = self._run(script, [], env)

        assert result.returncode == 0, result.stderr
        assert not marker.exists()


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
                "-MachineId",
                "machine-42",
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
                "-MachineId",
                "machine-42",
            ],
            input=payload,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        assert "/hidden/agent-monitor/hooks/cursor" in _HookHandler.last_request["path"]

    def test_machine_id_sets_x_user_identifier(self, hook_server):
        script = _get_script_path("snyk-agent-guard.ps1")
        result = subprocess.run(
            [
                self._ps_cmd(),
                "-File",
                str(script),
                "-Client",
                "claude-code",
                "-PushKey",
                "test-pk",
                "-RemoteUrl",
                hook_server,
                "-MachineId",
                "machine-42",
            ],
            input='{"hook_event_name":"test","session_id":"s1"}',
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr
        x_user = json.loads(_HookHandler.last_request["headers"]["X-User"])
        assert x_user["identifier"] == "machine-42"

    def test_missing_machine_id_fails(self, hook_server):
        script = _get_script_path("snyk-agent-guard.ps1")
        env = dict(__import__("os").environ)
        env.pop("MACHINE_ID", None)
        result = subprocess.run(
            [
                self._ps_cmd(),
                "-File",
                str(script),
                "-Client",
                "claude-code",
                "-PushKey",
                "test-pk",
                "-RemoteUrl",
                hook_server,
            ],
            input='{"hook_event_name":"test","session_id":"s1"}',
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        assert result.returncode != 0
        assert "MACHINE_ID" in result.stderr

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
            machine_id="machine-42",
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
            machine_id="machine-42",
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
        assert "Please reach out to your Snyk administrators" in out

    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_guard_enabled_continues(self, mock_fetch):
        _ensure_guard_enabled_for_tenant("https://api.snyk.io", "550e8400-e29b-41d4-a716-446655440000", "tok")
        mock_fetch.assert_called_once_with("https://api.snyk.io", "550e8400-e29b-41d4-a716-446655440000", "tok")


class TestRunInstallCallsEnsureGuardEnabled:
    """_run_install invokes _ensure_guard_enabled_for_tenant only in the interactive (mint) path."""

    @pytest.fixture(autouse=True)
    def _no_servers_discovered_event(self):
        # _install_hooks is mocked below, so without this the real post-install
        # send would run actual machine discovery and invoke the hook script.
        with (
            patch("agent_scan.guard._send_servers_discovered_event", return_value=True),
            patch.dict(os.environ, {"MACHINE_ID": "machine-42"}),
        ):
            yield

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
        )
        _run_install(args)
        mock_fetch.assert_not_called()
        mock_install.assert_called_once()

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_test_flag_true_does_not_change_install_hooks_call(
        self, mock_fetch, mock_mint, mock_install, tmp_path, monkeypatch
    ):
        """--test flag is a no-op: _install_hooks receives the same args regardless of args.test."""
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "snyk-from-env")
        config = tmp_path / "settings.json"
        args = SimpleNamespace(
            client="claude",
            url="https://api.snyk.io",
            tenant_id="tid-interactive",
            file=str(config),
            managed=False,
            test=True,
        )
        _run_install(args)
        mock_install.assert_called_once()
        call_args = mock_install.call_args
        assert "test" not in (call_args.kwargs or {})
        assert len(call_args.args) == 11, "args.test must not be forwarded to _install_hooks"

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
        )
        _run_install(args)
        mock_fetch.assert_not_called()
        mock_install.assert_called_once()


# ===================================================================
# _install_hooks orchestration: detect → test event → write
# ===================================================================

_G = "agent_scan.guard"
_NO_RETURN_VALUE = object()

_DIFF_REMOVED = {
    "added": {},
    "modified": {},
    "removed": {"SessionStart": [{"hooks": [{"type": "command", "command": "cmd"}]}]},
}

_DIFF_MODIFIED = {
    "added": {},
    "modified": {
        "PreToolUse": {
            "expected_value": [{"hooks": [{"type": "command", "command": "new-cmd"}]}],
            "actual_value": [{"hooks": [{"type": "command", "command": "old-cmd"}]}],
        }
    },
    "removed": {},
}

_DIFF_ADDED = {
    "added": {"OldEvent": [{"hooks": [{"type": "command", "command": "old-cmd"}]}]},
    "modified": {},
    "removed": {},
}

_DIFF_EMPTY: dict = {"added": {}, "modified": {}, "removed": {}}

_PREPARED: dict[str, dict[str, list[object]]] = {"hooks": {"SessionStart": []}}

_CURRENT_CHECKSUM = "a" * 64
_NEW_CHECKSUM = "b" * 64
_DISCOVER_CURRENT_CHECKSUM = "c" * 64
_DISCOVER_NEW_CHECKSUM = "d" * 64


class TestInstallHooksOrchestration:
    """Tests for _install_hooks: detect changes → send test event → write config."""

    @pytest.fixture
    def ctx(self):
        """Patch all _install_hooks dependencies; yield a dict of mock objects.

        Defaults: script existed & not updated, diff has additions,
        test event succeeds, write returns True.
        """
        dest = MagicMock(name="dest_path")
        targets = {
            "copy": (f"{_G}._copy_hook_script", _NO_RETURN_VALUE),
            "agent_scan_command": (f"{_G}._agent_scan_command", "/usr/local/bin/snyk-agent-scan"),
            "build": (f"{_G}._build_hook_command", "test-cmd"),
            "build_discover": (f"{_G}._build_discover_hook_command", "discover-cmd"),
            "prep_claude": (f"{_G}._prepare_claude_config", (_PREPARED, _DIFF_REMOVED, 0)),
            "prep_cursor": (f"{_G}._prepare_cursor_config", (_PREPARED, _DIFF_REMOVED, 0)),
            "prep_codex": (f"{_G}._prepare_codex_config", (_PREPARED, _DIFF_REMOVED, 0)),
            "prep_codex_managed": (f"{_G}._prepare_codex_managed_config", ("toml-content", _DIFF_REMOVED)),
            "is_toml": (f"{_G}._is_codex_requirements_toml", False),
            "detect_existing": (f"{_G}._detect_existing_install", None),
            "test_event": (f"{_G}._send_test_event", True),
            "write": (f"{_G}._write_config", True),
            "write_codex_managed": (f"{_G}._write_codex_managed_config", True),
            "revoke": (f"{_G}._revoke_after_failure", _NO_RETURN_VALUE),
            "rich": (f"{_G}.rich", _NO_RETURN_VALUE),
        }
        active = {}
        m = {
            "dest": dest,
            "main_script": guard_module._CopiedScript(
                dest,
                True,
                False,
                _CURRENT_CHECKSUM,
                _NEW_CHECKSUM,
            ),
            "discover_script": guard_module._CopiedScript(
                MagicMock(name="discover_dest_path"),
                True,
                False,
                _DISCOVER_CURRENT_CHECKSUM,
                _DISCOVER_NEW_CHECKSUM,
            ),
        }
        for key, (target, rv) in targets.items():
            p = patch(target) if rv is _NO_RETURN_VALUE else patch(target, return_value=rv)
            active[key] = p
            m[key] = p.start()

        def copy_script(script_dest):
            return m["discover_script"] if "discover" in script_dest.name else m["main_script"]

        m["copy"].side_effect = copy_script
        yield m
        for p in active.values():
            p.stop()

    def _call(
        self,
        tmp_path,
        client="claude",
        hook_client="claude-code",
        minted=False,
        config_exists=False,
        machine_id="",
    ):
        config = tmp_path / "config.json"
        if config_exists:
            config.write_text("{}")
        _install_hooks(
            client,
            hook_client,
            "pk-test",
            "https://api.snyk.io",
            config,
            "user",
            "Claude Code",
            minted,
            "tid-1",
            "snyk-tok",
            machine_id,
        )
        return config

    def _print_messages(self, ctx):
        return [c.args[0] for c in ctx["rich"].print.call_args_list if c.args]

    # ---------------------------------------------------------------
    # _copy_hook_script receives one destination path per script
    # ---------------------------------------------------------------

    def test_copy_hook_script_includes_discovery_for_regular_config(self, ctx, tmp_path):
        config = self._call(tmp_path, client="claude", config_exists=True)
        assert ctx["copy"].call_args_list == [
            mock_call(guard_module._forwarder_script_path(config)),
            mock_call(guard_module._discover_script_path(config)),
        ]

    def test_machine_id_forwarded_to_command_and_test_event(self, ctx, tmp_path):
        self._call(tmp_path, machine_id="machine-42")
        assert ctx["build"].call_args.kwargs["machine_id"] == "machine-42"
        assert ctx["test_event"].call_args.kwargs["machine_id"] == "machine-42"

    def test_claude_builds_and_prepares_async_discovery_hook(self, ctx, tmp_path):
        with patch(f"{_G}.IS_WINDOWS", False):
            self._call(tmp_path, client="claude", machine_id="machine-42")

        ctx["build_discover"].assert_called_once()
        assert ctx["build_discover"].call_args.kwargs == {
            "agent_scan_command": "/usr/local/bin/snyk-agent-scan",
            "tenant_id": "tid-1",
            "machine_id": "machine-42",
            "hook_client": "claude-code",
        }
        assert ctx["prep_claude"].call_args.kwargs["discover_command"] == "discover-cmd"

    def test_cursor_builds_discovery_hook(self, ctx, tmp_path):
        self._call(tmp_path, client="cursor", hook_client="cursor")

        ctx["build_discover"].assert_called_once()
        assert ctx["build_discover"].call_args.kwargs["hook_client"] == "cursor"
        assert ctx["prep_cursor"].call_args.kwargs["discover_command"] == "discover-cmd"

    def test_windows_builds_discovery_hook(self, ctx, tmp_path):
        with patch(f"{_G}.IS_WINDOWS", True):
            self._call(tmp_path, client="claude")

        ctx["build_discover"].assert_called_once()
        assert ctx["build_discover"].call_args.args[2] == tmp_path / "hooks" / "snyk-agent-guard-discover.ps1"
        assert ctx["prep_claude"].call_args.kwargs["discover_command"] == "discover-cmd"

    def test_codex_json_builds_discovery_hook(self, ctx, tmp_path):
        self._call(tmp_path, client="codex", hook_client="codex")

        ctx["build_discover"].assert_called_once()
        assert ctx["build_discover"].call_args.kwargs["hook_client"] == "codex"
        assert ctx["prep_codex"].call_args.kwargs["discover_command"] == "discover-cmd"

    def test_codex_managed_builds_discovery_hook(self, ctx, tmp_path):
        ctx["is_toml"].return_value = True

        config = self._call(tmp_path, client="codex", hook_client="codex")

        ctx["build_discover"].assert_called_once()
        assert ctx["copy"].call_args_list == [
            mock_call(guard_module._forwarder_script_path(config)),
            mock_call(guard_module._discover_script_path(config)),
        ]
        assert ctx["prep_codex_managed"].call_args.kwargs["discover_command"] == "discover-cmd"

    def test_unset_agent_scan_command_skips_discovery_without_aborting(self, ctx, tmp_path):
        ctx["agent_scan_command"].return_value = None

        config = self._call(tmp_path, client="claude")

        ctx["copy"].assert_called_once_with(guard_module._forwarder_script_path(config))
        ctx["build_discover"].assert_not_called()
        assert ctx["prep_claude"].call_args.kwargs["discover_command"] is None

    @pytest.mark.parametrize(
        "client, hook_client",
        [("claude", "claude-code"), ("cursor", "cursor"), ("codex", "codex")],
    )
    def test_unset_agent_scan_command_warns_once_per_client(self, ctx, tmp_path, client, hook_client):
        ctx["agent_scan_command"].return_value = None

        self._call(tmp_path, client=client, hook_client=hook_client)

        warnings = [message for message in self._print_messages(ctx) if "AGENT_SCAN_COMMAND is not set" in message]
        assert warnings == [
            "[yellow]Warning:[/yellow] AGENT_SCAN_COMMAND is not set; "
            "the session-start discovery hook will not be installed"
        ]

    def test_unset_agent_scan_command_removes_stale_script_after_config_write(self, ctx, tmp_path):
        ctx["agent_scan_command"].return_value = None
        discover_script = guard_module._discover_script_path(tmp_path / "config.json")
        discover_script.parent.mkdir(parents=True)
        discover_script.write_text("stale\n")

        def assert_stale_script_still_exists(*_args):
            assert discover_script.exists()
            return True

        ctx["write"].side_effect = assert_stale_script_still_exists

        self._call(tmp_path, client="claude")

        assert not discover_script.exists()
        assert any("Removed stale hook script" in message for message in self._print_messages(ctx))

    def test_unset_agent_scan_command_keeps_stale_script_when_test_event_fails(self, ctx, tmp_path):
        ctx["agent_scan_command"].return_value = None
        ctx["test_event"].return_value = False
        discover_script = guard_module._discover_script_path(tmp_path / "config.json")
        discover_script.parent.mkdir(parents=True)
        discover_script.write_text("stale\n")

        with pytest.raises(SystemExit):
            self._call(tmp_path, client="claude")

        assert discover_script.read_text() == "stale\n"

    def test_install_hooks_returns_none(self, ctx, tmp_path):
        result = _install_hooks(
            "claude",
            "claude-code",
            "pk-test",
            "https://api.snyk.io",
            tmp_path / "config.json",
            "user",
            "Claude Code",
            False,
            "tid-1",
            "snyk-tok",
            "",
        )
        assert result is None

    # ---------------------------------------------------------------
    # Client routing: each client calls its own prepare + the shared writer
    # ---------------------------------------------------------------

    def test_claude_routes_to_claude_functions(self, ctx, tmp_path):
        self._call(tmp_path, client="claude", config_exists=True)
        ctx["prep_claude"].assert_called_once()
        ctx["write"].assert_called_once()
        ctx["prep_cursor"].assert_not_called()
        ctx["prep_codex"].assert_not_called()

    def test_cursor_routes_to_cursor_functions(self, ctx, tmp_path):
        self._call(tmp_path, client="cursor", hook_client="cursor", config_exists=True)
        ctx["prep_cursor"].assert_called_once()
        ctx["write"].assert_called_once()
        ctx["prep_claude"].assert_not_called()

    def test_codex_json_routes_to_codex_functions(self, ctx, tmp_path):
        self._call(tmp_path, client="codex", hook_client="codex", config_exists=True)
        ctx["prep_codex"].assert_called_once()
        ctx["write"].assert_called_once()
        ctx["prep_codex_managed"].assert_not_called()

    def test_codex_managed_routes_to_toml_functions(self, ctx, tmp_path):
        ctx["is_toml"].return_value = True
        self._call(tmp_path, client="codex", hook_client="codex", config_exists=True)
        ctx["prep_codex_managed"].assert_called_once()
        ctx["write_codex_managed"].assert_called_once()
        ctx["prep_codex"].assert_not_called()
        ctx["write"].assert_not_called()

    # ---------------------------------------------------------------
    # Detection: config_changed derived from diff
    # ---------------------------------------------------------------

    def test_config_changed_true_when_additions(self, ctx, tmp_path):
        ctx["prep_claude"].return_value = (_PREPARED, _DIFF_REMOVED, 0)
        self._call(tmp_path, minted=True, config_exists=True)
        ctx["test_event"].assert_called_once()
        _, kwargs = ctx["test_event"].call_args
        assert kwargs["config_changed"] is True

    def test_config_changed_true_when_modifications(self, ctx, tmp_path):
        ctx["prep_claude"].return_value = (_PREPARED, _DIFF_MODIFIED, 0)
        self._call(tmp_path, minted=True, config_exists=True)
        _, kwargs = ctx["test_event"].call_args
        assert kwargs["config_changed"] is True

    def test_config_changed_true_when_removals(self, ctx, tmp_path):
        ctx["prep_claude"].return_value = (_PREPARED, _DIFF_ADDED, 0)
        self._call(tmp_path, minted=True, config_exists=True)
        _, kwargs = ctx["test_event"].call_args
        assert kwargs["config_changed"] is True

    def test_config_changed_false_when_diff_empty(self, ctx, tmp_path):
        ctx["prep_claude"].return_value = (_PREPARED, _DIFF_EMPTY, 0)
        self._call(tmp_path, minted=True, config_exists=True)
        _, kwargs = ctx["test_event"].call_args
        assert kwargs["config_changed"] is False

    # ---------------------------------------------------------------
    # Test event: send conditions
    # ---------------------------------------------------------------

    def test_test_event_sent_when_script_new(self, ctx, tmp_path):
        """first_install=True because script did not exist prior."""
        ctx["main_script"] = guard_module._CopiedScript(ctx["dest"], False, True, None, _NEW_CHECKSUM)
        self._call(tmp_path, config_exists=True)
        ctx["test_event"].assert_called_once()
        _, kwargs = ctx["test_event"].call_args
        assert kwargs["first_install"] is True

    def test_test_event_sent_when_minted(self, ctx, tmp_path):
        self._call(tmp_path, minted=True, config_exists=True)
        ctx["test_event"].assert_called_once()

    def test_test_event_always_sent(self, ctx, tmp_path):
        self._call(tmp_path, config_exists=True, minted=False)
        ctx["test_event"].assert_called_once()

    # ---------------------------------------------------------------
    # Test event: payload carries diff
    # ---------------------------------------------------------------

    def test_test_event_receives_diff(self, ctx, tmp_path):
        ctx["prep_claude"].return_value = (_PREPARED, _DIFF_REMOVED, 0)
        ctx["main_script"] = guard_module._CopiedScript(ctx["dest"], False, True, None, _NEW_CHECKSUM)
        self._call(tmp_path)
        ctx["test_event"].assert_called_once_with(
            "pk-test",
            "https://api.snyk.io",
            "claude-code",
            ctx["dest"],
            first_install=True,
            config_changed=True,
            hooks_diff=_DIFF_REMOVED,
            push_key_changed=False,
            current_checksum=None,
            new_checksum=_NEW_CHECKSUM,
            discover_current_checksum=_DISCOVER_CURRENT_CHECKSUM,
            discover_new_checksum=_DISCOVER_NEW_CHECKSUM,
            machine_id="",
        )

    def test_test_event_receives_empty_diff(self, ctx, tmp_path):
        ctx["prep_claude"].return_value = (_PREPARED, _DIFF_EMPTY, 0)
        ctx["main_script"] = guard_module._CopiedScript(ctx["dest"], False, True, None, _NEW_CHECKSUM)
        self._call(tmp_path)
        ctx["test_event"].assert_called_once_with(
            "pk-test",
            "https://api.snyk.io",
            "claude-code",
            ctx["dest"],
            first_install=True,
            config_changed=False,
            hooks_diff=_DIFF_EMPTY,
            push_key_changed=False,
            current_checksum=None,
            new_checksum=_NEW_CHECKSUM,
            discover_current_checksum=_DISCOVER_CURRENT_CHECKSUM,
            discover_new_checksum=_DISCOVER_NEW_CHECKSUM,
            machine_id="",
        )

    def test_test_event_not_first_install(self, ctx, tmp_path):
        ctx["prep_claude"].return_value = (_PREPARED, _DIFF_REMOVED, 0)
        self._call(tmp_path, minted=True, config_exists=True)
        ctx["test_event"].assert_called_once_with(
            "pk-test",
            "https://api.snyk.io",
            "claude-code",
            ctx["dest"],
            first_install=False,
            config_changed=True,
            hooks_diff=_DIFF_REMOVED,
            push_key_changed=False,
            current_checksum=_CURRENT_CHECKSUM,
            new_checksum=_NEW_CHECKSUM,
            discover_current_checksum=_DISCOVER_CURRENT_CHECKSUM,
            discover_new_checksum=_DISCOVER_NEW_CHECKSUM,
            machine_id="",
        )

    def test_test_event_push_key_changed(self, ctx, tmp_path):
        ctx["detect_existing"].return_value = {"auth_value": "old-push-key"}
        ctx["main_script"] = guard_module._CopiedScript(ctx["dest"], False, True, None, _NEW_CHECKSUM)
        self._call(tmp_path)
        ctx["test_event"].assert_called_once_with(
            "pk-test",
            "https://api.snyk.io",
            "claude-code",
            ctx["dest"],
            first_install=True,
            config_changed=True,
            hooks_diff=_DIFF_REMOVED,
            push_key_changed=True,
            current_checksum=None,
            new_checksum=_NEW_CHECKSUM,
            discover_current_checksum=_DISCOVER_CURRENT_CHECKSUM,
            discover_new_checksum=_DISCOVER_NEW_CHECKSUM,
            machine_id="",
        )

    def test_test_event_push_key_unchanged(self, ctx, tmp_path):
        ctx["detect_existing"].return_value = {"auth_value": "pk-test"}
        ctx["main_script"] = guard_module._CopiedScript(ctx["dest"], False, True, None, _NEW_CHECKSUM)
        self._call(tmp_path)
        ctx["test_event"].assert_called_once_with(
            "pk-test",
            "https://api.snyk.io",
            "claude-code",
            ctx["dest"],
            first_install=True,
            config_changed=True,
            hooks_diff=_DIFF_REMOVED,
            push_key_changed=False,
            current_checksum=None,
            new_checksum=_NEW_CHECKSUM,
            discover_current_checksum=_DISCOVER_CURRENT_CHECKSUM,
            discover_new_checksum=_DISCOVER_NEW_CHECKSUM,
            machine_id="",
        )

    # ---------------------------------------------------------------
    # Test event: hooks_script checksums
    # ---------------------------------------------------------------

    def test_test_event_checksums_first_install(self, ctx, tmp_path):
        """First install: current_checksum is None, new_checksum is populated."""
        ctx["main_script"] = guard_module._CopiedScript(ctx["dest"], False, True, None, _NEW_CHECKSUM)
        self._call(tmp_path)
        _, kwargs = ctx["test_event"].call_args
        assert kwargs["current_checksum"] is None
        assert kwargs["new_checksum"] == _NEW_CHECKSUM

    def test_test_event_checksums_existing_install(self, ctx, tmp_path):
        """Existing install: both checksums are populated."""
        self._call(tmp_path, minted=True, config_exists=True)
        _, kwargs = ctx["test_event"].call_args
        assert kwargs["current_checksum"] == _CURRENT_CHECKSUM
        assert kwargs["new_checksum"] == _NEW_CHECKSUM

    def test_test_event_receives_discovery_script_checksums(self, ctx, tmp_path):
        ctx["discover_script"] = guard_module._CopiedScript(
            MagicMock(name="discover_dest_path"),
            True,
            False,
            "discover-current",
            "discover-new",
        )

        self._call(tmp_path, minted=True, config_exists=True)

        _, kwargs = ctx["test_event"].call_args
        assert kwargs["discover_current_checksum"] == "discover-current"
        assert kwargs["discover_new_checksum"] == "discover-new"

    # ---------------------------------------------------------------
    # Test event failure: abort, cleanup, revoke
    # ---------------------------------------------------------------

    def test_test_event_failure_raises_system_exit(self, ctx, tmp_path):
        ctx["test_event"].return_value = False
        with pytest.raises(SystemExit):
            self._call(tmp_path, minted=True, config_exists=True)

    def test_test_event_failure_does_not_revoke_in_install_hooks(self, ctx, tmp_path):
        ctx["test_event"].return_value = False
        with pytest.raises(SystemExit):
            self._call(tmp_path, minted=True, config_exists=True)
        ctx["revoke"].assert_not_called()

    def test_test_event_failure_no_revoke_when_not_minted(self, ctx, tmp_path):
        ctx["main_script"] = guard_module._CopiedScript(ctx["dest"], False, True, None, _NEW_CHECKSUM)
        ctx["test_event"].return_value = False
        with pytest.raises(SystemExit):
            self._call(tmp_path, minted=False, config_exists=True)
        ctx["revoke"].assert_not_called()

    def test_test_event_failure_cleans_new_script(self, ctx, tmp_path):
        ctx["main_script"] = guard_module._CopiedScript(ctx["dest"], False, True, None, _NEW_CHECKSUM)
        ctx["test_event"].return_value = False
        with pytest.raises(SystemExit):
            self._call(tmp_path)
        ctx["dest"].unlink.assert_called_once_with(missing_ok=True)

    def test_test_event_failure_cleans_new_discovery_script(self, ctx, tmp_path):
        discover_script_name = (
            "snyk-agent-guard-discover.ps1" if guard_module.IS_WINDOWS else "snyk-agent-guard-discover.sh"
        )
        discover_script = tmp_path / "hooks" / discover_script_name

        def copy_scripts(dest):
            if "discover" not in dest.name:
                return ctx["main_script"]
            discover_script.parent.mkdir(parents=True)
            discover_script.write_text("#!/bin/sh\n")
            return guard_module._CopiedScript(
                discover_script,
                False,
                True,
                None,
                _DISCOVER_NEW_CHECKSUM,
            )

        ctx["copy"].side_effect = copy_scripts
        ctx["test_event"].return_value = False

        with pytest.raises(SystemExit):
            self._call(tmp_path)

        assert not discover_script.exists()

    def test_test_event_failure_keeps_existing_discovery_script(self, ctx, tmp_path):
        discover_script_name = (
            "snyk-agent-guard-discover.ps1" if guard_module.IS_WINDOWS else "snyk-agent-guard-discover.sh"
        )
        discover_script = tmp_path / "hooks" / discover_script_name
        discover_script.parent.mkdir(parents=True)
        discover_script.write_text("existing\n")
        ctx["main_script"] = guard_module._CopiedScript(ctx["dest"], False, True, None, _NEW_CHECKSUM)
        ctx["test_event"].return_value = False

        with pytest.raises(SystemExit):
            self._call(tmp_path)

        assert discover_script.read_text() == "existing\n"

    def test_test_event_failure_keeps_existing_script(self, ctx, tmp_path):
        ctx["main_script"] = guard_module._CopiedScript(
            ctx["dest"],
            True,
            False,
            _CURRENT_CHECKSUM,
            _NEW_CHECKSUM,
        )
        ctx["test_event"].return_value = False
        with pytest.raises(SystemExit):
            self._call(tmp_path, minted=True, config_exists=True)
        ctx["dest"].unlink.assert_not_called()

    def test_test_event_failure_does_not_write_config(self, ctx, tmp_path):
        ctx["test_event"].return_value = False
        with pytest.raises(SystemExit):
            self._call(tmp_path, minted=True, config_exists=True)
        ctx["write"].assert_not_called()
        ctx["write_codex_managed"].assert_not_called()

    # ---------------------------------------------------------------
    # Write phase: prepared config forwarded to writer
    # ---------------------------------------------------------------

    def test_write_receives_prepared_claude_config(self, ctx, tmp_path):
        prepared = {"hooks": {"PreToolUse": [{"test": True}]}}
        ctx["prep_claude"].return_value = (prepared, _DIFF_REMOVED, 2)
        config = self._call(tmp_path, config_exists=True)
        ctx["write"].assert_called_once_with(prepared, config, 2)

    def test_write_receives_prepared_cursor_config(self, ctx, tmp_path):
        prepared = {"version": 1, "hooks": {"stop": [{"command": "x"}]}}
        ctx["prep_cursor"].return_value = (prepared, _DIFF_REMOVED, 1)
        config = self._call(tmp_path, client="cursor", hook_client="cursor", config_exists=True)
        ctx["write"].assert_called_once_with(prepared, config, 1)

    def test_write_receives_prepared_codex_config(self, ctx, tmp_path):
        prepared = {"hooks": {"Stop": [{"hooks": []}]}}
        ctx["prep_codex"].return_value = (prepared, _DIFF_REMOVED, 3)
        config = self._call(tmp_path, client="codex", hook_client="codex", config_exists=True)
        ctx["write"].assert_called_once_with(prepared, config, 3)

    def test_write_receives_prepared_codex_managed_content(self, ctx, tmp_path):
        ctx["is_toml"].return_value = True
        ctx["prep_codex_managed"].return_value = ("toml-data-xyz", _DIFF_REMOVED)
        config = self._call(tmp_path, client="codex", hook_client="codex", config_exists=True)
        ctx["write_codex_managed"].assert_called_once_with("toml-data-xyz", config)

    def test_config_written_after_test_event(self, ctx, tmp_path):
        self._call(tmp_path, config_exists=True, minted=False)
        ctx["test_event"].assert_called_once()
        ctx["write"].assert_called_once()

    # ---------------------------------------------------------------
    # Status output
    # ---------------------------------------------------------------

    def test_status_installed_when_config_written(self, ctx, tmp_path):
        ctx["write"].return_value = True
        self._call(tmp_path, config_exists=True)
        assert any("hooks installed" in m for m in self._print_messages(ctx))

    def test_status_installed_when_script_updated(self, ctx, tmp_path):
        ctx["main_script"] = guard_module._CopiedScript(
            ctx["dest"],
            True,
            True,
            _CURRENT_CHECKSUM,
            _NEW_CHECKSUM,
        )
        ctx["write"].return_value = False
        self._call(tmp_path, config_exists=True)
        assert any("hooks installed" in m for m in self._print_messages(ctx))

    def test_status_installed_when_discovery_script_updated(self, ctx, tmp_path):
        ctx["discover_script"] = ctx["discover_script"]._replace(updated=True)
        ctx["write"].return_value = False

        self._call(tmp_path, config_exists=True)

        assert any("hooks installed" in m for m in self._print_messages(ctx))

    def test_status_installed_when_minted(self, ctx, tmp_path):
        ctx["write"].return_value = False
        self._call(tmp_path, minted=True, config_exists=True)
        assert any("hooks installed" in m for m in self._print_messages(ctx))

    def test_status_up_to_date_when_nothing_changed(self, ctx, tmp_path):
        ctx["write"].return_value = False
        self._call(tmp_path, minted=False, config_exists=True)
        assert any("up to date" in m for m in self._print_messages(ctx))


# ===================================================================
# _send_test_event: hooks_script payload
# ===================================================================


class TestSendTestEventHooksScript:
    """Verify the hooks_script checksum fields in the test event payload."""

    def _capture_payload(self, **kwargs):
        """Call _send_test_event with a fake script, capture the JSON payload."""
        import subprocess

        captured = {}

        def fake_run(cmd, *, input, **kw):
            captured["payload"] = json.loads(input)
            return subprocess.CompletedProcess(cmd, 0)

        with patch("subprocess.run", side_effect=fake_run), patch(f"{_G}.rich"):
            _send_test_event(
                "pk-test",
                "https://api.snyk.io",
                "claude-code",
                Path("/fake/script.sh"),
                machine_id="machine-42",
                **kwargs,
            )
        return captured["payload"]

    def test_first_install_only_new_checksum(self):
        payload = self._capture_payload(
            first_install=True,
            new_checksum="abc123",
        )
        assert payload["hooks_script"] == {"new_checksum": "abc123"}

    def test_existing_install_both_checksums(self):
        payload = self._capture_payload(
            first_install=False,
            current_checksum="old111",
            new_checksum="new222",
        )
        assert payload["hooks_script"] == {
            "current_checksum": "old111",
            "new_checksum": "new222",
        }

    def test_discovery_script_checksums_are_included(self):
        payload = self._capture_payload(
            current_checksum="old111",
            new_checksum="new222",
            discover_current_checksum="discover-old",
            discover_new_checksum="discover-new",
        )

        assert payload["hooks_script"] == {
            "current_checksum": "old111",
            "new_checksum": "new222",
            "discover_current_checksum": "discover-old",
            "discover_new_checksum": "discover-new",
        }

    def test_no_checksums_omits_hooks_script(self):
        payload = self._capture_payload(first_install=True)
        assert "hooks_script" not in payload


class TestServersDiscoveredPayload:
    @staticmethod
    def _client(*, mcp_configs, name="claude code", path=None):
        return ClientToInspect(
            name=name,
            client_path=path or (Path.home() / ".claude").as_posix(),
            mcp_configs=mcp_configs,
            skills_dirs={},
        )

    def test_builds_one_entry_per_client_and_merges_config_paths(self):
        stdio = StdioServer(
            command="npx",
            args=["-y", "@mcp/github"],
            env={"GITHUB_TOKEN": "secret-token"},
            binary_identifier="pkg:npm/%40mcp/github@1.0.0",
        )
        remote = RemoteServer(
            url="https://mcp.example.com/mcp?token=remote-secret",
            type="http",
            headers={"Authorization": "Bearer remote-secret"},
        )
        home = Path.home()
        clients = [
            self._client(
                mcp_configs={
                    (home / ".claude.json").as_posix(): [("github", stdio)],
                    (home / "project" / ".mcp.json").as_posix(): [("remote", remote)],
                }
            ),
            self._client(mcp_configs={}, name="cursor", path=(home / ".cursor").as_posix()),
        ]

        result = guard_module._servers_discovered_entries(clients)

        assert [(entry["client"], entry["path"]) for entry in result] == [
            ("claude code", "~/.claude"),
            ("cursor", "~/.cursor"),
        ]
        assert [(server["name"], server["config_path"]) for server in result[0]["servers"]] == [
            ("github", (home / ".claude.json").as_posix()),
            ("remote", (home / "project" / ".mcp.json").as_posix()),
        ]
        assert result[1]["servers"] == []

    def test_reports_config_discovery_errors(self):
        client = self._client(
            mcp_configs={
                "/bad.json": CouldNotParseMCPConfig(message="bad", traceback=None),
                "/missing.json": FileNotFoundConfig(message="missing", traceback=None),
                "/good.json": [("good", StdioServer(command="good"))],
            }
        )

        result = guard_module._servers_discovered_entries([client])

        assert [server["name"] for server in result[0]["servers"]] == ["good"]
        assert result[0]["error"]["category"] == "parse_error"

    def test_client_with_only_error_configs_still_emits_entry(self):
        client = self._client(
            mcp_configs={
                "/bad.json": CouldNotParseMCPConfig(message="bad", traceback=None),
                "/missing.json": FileNotFoundConfig(message="missing", traceback=None),
            }
        )

        result = guard_module._servers_discovered_entries([client])

        assert [(entry["client"], entry["servers"]) for entry in result] == [("claude code", [])]
        assert result[0]["error"]["category"] == "parse_error"

    def test_unnamed_server_gets_attributable_name(self):
        config_path = (Path.home() / "project" / ".mcp.json").as_posix()
        client = self._client(mcp_configs={config_path: [("", StdioServer(command="server"))]})

        result = guard_module._servers_discovered_entries([client])

        assert result[0]["servers"][0]["name"] == "unnamed server (~/project/.mcp.json)"

    def test_top_level_paths_match_scan_transport_boundary(self):
        from agent_scan.verify_api import build_scan_request

        clients = [
            self._client(mcp_configs={}),
            self._client(mcp_configs={}, name="cursor", path=(Path.home() / ".cursor").as_posix()),
        ]
        inspected_paths = [InspectedPath(client=client.name, path=client.client_path, servers=[]) for client in clients]

        discovered = guard_module._servers_discovered_entries(clients)
        scanned = build_scan_request(inspected_paths).scan_path_requests

        assert [entry["path"] for entry in discovered] == [entry.path for entry in scanned]

    def test_empty_input_returns_empty_list(self):
        assert guard_module._servers_discovered_entries([]) == []

    def test_matches_scan_path_request_wire_shape(self):
        from agent_scan.verify_api import build_scan_request

        server = StdioServer(command="npx", args=["--mode", "read-only"], binary_identifier="binary-id")
        client = self._client(mcp_configs={"/config.json": [("github", server)]})
        inspected = InspectedPath(
            client=client.name,
            path=client.client_path,
            servers=[InspectedServer(name="github", config_path="/config.json", server=server)],
        )

        result = guard_module._servers_discovered_entries([client])

        expected = build_scan_request([inspected]).scan_path_requests[0].model_dump(mode="json")
        assert result == [expected]
        assert set(result[0]) == {"client", "path", "servers", "skills", "error"}
        assert set(result[0]["servers"][0]) == {"name", "config_path", "server", "signature", "error"}
        assert result[0]["servers"][0]["server"] == {
            "command": "npx",
            "args": ["--mode", "read-only"],
            "type": "stdio",
            "env": None,
            "binary_identifier": "binary-id",
        }

    def test_redacts_stdio_env_without_mutating_discovery_result(self):
        server = StdioServer(command="npx", env={"TOKEN": "raw-secret"})
        client = self._client(mcp_configs={"/config.json": [("github", server)]})

        result = guard_module._servers_discovered_entries([client])

        assert result[0]["servers"][0]["server"]["env"] == {"TOKEN": "**REDACTED**"}
        assert "raw-secret" not in json.dumps(result)
        assert server.env == {"TOKEN": "raw-secret"}

    def test_redacts_remote_headers_and_url_query(self):
        server = RemoteServer(
            url="https://mcp.example.com/mcp?token=raw-secret",
            headers={"Authorization": "Bearer raw-secret"},
        )
        client = self._client(mcp_configs={"/config.json": [("remote", server)]})

        result = guard_module._servers_discovered_entries([client])

        dumped = json.dumps(result)
        wire_server = result[0]["servers"][0]["server"]
        assert wire_server["headers"] == {"Authorization": "**REDACTED**"}
        assert "token=%2A%2AREDACTED%2A%2A" in wire_server["url"]
        assert "raw-secret" not in dumped


class TestDiscoverServersPayload:
    def test_uses_current_user_server_only_discovery(self):
        clients = [ClientToInspect(name="cursor", client_path="/cursor", mcp_configs={}, skills_dirs={})]
        discover = AsyncMock(return_value=(clients, [], ["me"]))

        with patch("agent_scan.pipelines.discover_clients_to_inspect", discover):
            result = guard_module._discover_servers_payload()

        args = discover.await_args.args[0]
        assert args.timeout == 0
        assert args.tokens == []
        assert args.paths == []
        assert args.all_users is False
        assert args.scan_skills is False
        assert discover.await_args.kwargs == {}
        assert result == guard_module._servers_discovered_entries(clients)

    def test_forwards_discovery_scope(self):
        from agent_scan.agents import DiscoveryScope

        discover = AsyncMock(return_value=([], [], []))

        with patch("agent_scan.pipelines.discover_clients_to_inspect", discover):
            guard_module._discover_servers_payload(discovery_scope=DiscoveryScope.SERVERS)

        assert discover.await_args.args[0].discovery_scope is DiscoveryScope.SERVERS

    def test_threads_target_folders_to_inspect_args(self):
        discover = AsyncMock(return_value=([], [], []))

        with patch("agent_scan.pipelines.discover_clients_to_inspect", discover):
            result = guard_module._discover_servers_payload(["/repo/one", "/repo/two"])

        args = discover.await_args.args[0]
        assert args.target_folders == ["/repo/one", "/repo/two"]
        assert result == []

    def test_discovery_timeout_is_60_seconds(self):
        assert guard_module._DISCOVERY_TIMEOUT_SECONDS == 60.0


class TestInvokeHookScript:
    def test_posix_invocation_sets_machine_id(self, monkeypatch):
        monkeypatch.delenv("MACHINE_ID", raising=False)
        completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        with patch(f"{_G}.IS_WINDOWS", False), patch("subprocess.run", return_value=completed) as run:
            result = guard_module._invoke_hook_script(
                PurePosixPath("/hook.sh"),
                "claude-code",
                "pk",
                "https://api.snyk.io",
                "{}",
                machine_id="machine-42",
            )

        assert result == (True, "")
        assert run.call_args.args[0] == ["bash", "/hook.sh", "--client", "claude-code"]
        assert run.call_args.kwargs["env"]["MACHINE_ID"] == "machine-42"
        assert run.call_args.kwargs["input"] == "{}"

    def test_posix_invocation_overwrites_ambient_machine_id(self, monkeypatch):
        monkeypatch.setenv("MACHINE_ID", "ambient-machine")
        completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        with patch(f"{_G}.IS_WINDOWS", False), patch("subprocess.run", return_value=completed) as run:
            result = guard_module._invoke_hook_script(
                PurePosixPath("/hook.sh"),
                "cursor",
                "pk",
                "https://api.snyk.io",
                "{}",
                machine_id="chosen-machine",
            )

        assert result == (True, "")
        assert run.call_args.kwargs["env"]["MACHINE_ID"] == "chosen-machine"

    def test_empty_machine_id_is_rejected(self):
        with pytest.raises(ValueError, match="machine ID"):
            guard_module._invoke_hook_script(
                Path("/hook.sh"), "cursor", "pk", "https://api.snyk.io", "{}", machine_id="  "
            )

    def test_windows_invocation_machine_id_shape(self):
        completed = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        with patch(f"{_G}.IS_WINDOWS", True), patch("subprocess.run", return_value=completed) as run:
            result = guard_module._invoke_hook_script(
                Path("C:/hook.ps1"),
                "codex",
                "pk",
                "https://api.snyk.io",
                "{}",
                machine_id="machine-42",
            )

        assert result == (True, "")
        assert run.call_args.args[0] == [
            "powershell",
            "-File",
            str(Path("C:/hook.ps1")),
            "-Client",
            "codex",
            "-PushKey",
            "pk",
            "-RemoteUrl",
            "https://api.snyk.io",
            "-MachineId",
            "machine-42",
        ]
        assert run.call_args.kwargs["env"] is None

    def test_nonzero_exit_returns_stderr(self):
        completed = subprocess.CompletedProcess([], 7, stdout="", stderr="bad request\n")
        with patch(f"{_G}.IS_WINDOWS", False), patch("subprocess.run", return_value=completed):
            result = guard_module._invoke_hook_script(
                Path("/hook.sh"), "cursor", "pk", "url", "{}", machine_id="machine-42"
            )
        assert result == (False, "bad request")


def test_run_with_timeout_raises_when_worker_exceeds_deadline():
    stop = threading.Event()

    def worker():
        stop.wait(5)

    try:
        with pytest.raises(TimeoutError, match="timed out"):
            guard_module._run_with_timeout(worker, 0.01)
    finally:
        stop.set()


class TestSendServersDiscoveredEvent:
    @staticmethod
    def _capture(hook_client="claude-code", entries=None, machine_id="machine-42"):
        captured = {}

        def fake_send(url, client, push_key, payload, identifier, **kwargs):
            captured.update(
                url=url,
                client=client,
                push_key=push_key,
                payload=json.loads(payload),
                machine_id=identifier,
            )
            return True, ""

        with (
            patch(f"{_G}._discover_servers_payload", return_value=[] if entries is None else entries),
            patch(f"{_G}.send_hook_event", side_effect=fake_send),
            patch(f"{_G}.rich"),
        ):
            ok = guard_module._send_servers_discovered_event("pk-test", "https://api.snyk.io", hook_client, machine_id)
        return ok, captured

    @pytest.mark.parametrize(
        "hook_client, id_key",
        [("claude-code", "session_id"), ("codex", "session_id"), ("cursor", "conversation_id")],
    )
    def test_payload_contract_for_client(self, hook_client, id_key):
        push_key = "12345678-1234-1234-1234-123456789abc"
        entries = [{"command": f"PUSH_KEY='{push_key}'", "servers": []}]
        ok, captured = self._capture(hook_client=hook_client, entries=entries)

        assert ok is True
        payload = captured["payload"]
        assert payload["hook_event_name"] == "serversDiscovered"
        assert payload[id_key] == "hooks-setup"
        assert ({"session_id", "conversation_id"} - {id_key}).isdisjoint(payload)
        assert payload["servers"][0]["command"] == "PUSH_KEY='**REDACTED**'"
        assert isinstance(payload["discovery_duration_ms"], int)
        assert payload["discovery_duration_ms"] >= 0
        assert push_key not in json.dumps(payload)
        assert captured["url"] == "https://api.snyk.io"
        assert captured["client"] == hook_client
        assert captured["push_key"] == "pk-test"
        assert captured["machine_id"] == "machine-42"

    def test_empty_discovery_is_still_sent(self):
        ok, captured = self._capture(entries=[])
        assert ok is True
        assert captured["payload"]["servers"] == []

    def test_event_name_and_session_marker_can_be_overridden(self):
        captured = {}

        def fake_send(_url, _client, _push_key, payload, _machine_id, **kwargs):
            captured["payload"] = json.loads(payload)
            return True, ""

        with (
            patch(f"{_G}._discover_servers_payload", return_value=[]),
            patch(f"{_G}.send_hook_event", side_effect=fake_send),
            patch(f"{_G}.rich"),
        ):
            ok = guard_module._send_servers_discovered_event(
                "pk",
                "https://api.snyk.io",
                "claude-code",
                "machine-42",
                event_name="SessionStartServerDiscovery",
                session_marker="session-start-server-discovery",
            )

        assert ok is True
        assert captured["payload"]["hook_event_name"] == "SessionStartServerDiscovery"
        assert captured["payload"]["session_id"] == "session-start-server-discovery"

    def test_payload_includes_discovery_duration_ms_from_monotonic_clock(self):
        captured = {}

        def fake_send(_url, _client, _push_key, payload, _machine_id, **kwargs):
            captured["payload"] = json.loads(payload)
            return True, ""

        with (
            patch(f"{_G}._discover_servers_payload", return_value=[]),
            patch(f"{_G}.send_hook_event", side_effect=fake_send),
            patch("time.monotonic", side_effect=[100.0, 100.25]),
            patch(f"{_G}.rich"),
        ):
            ok = guard_module._send_servers_discovered_event(
                "pk-test", "https://api.snyk.io", "claude-code", "machine-42"
            )

        assert ok is True
        assert captured["payload"]["discovery_duration_ms"] == 250
        assert isinstance(captured["payload"]["discovery_duration_ms"], int)

    def test_send_failure_warns_and_returns_false(self):
        with (
            patch(f"{_G}._discover_servers_payload", return_value=[]),
            patch(f"{_G}.send_hook_event", return_value=(False, "HTTP 500")),
            patch(f"{_G}.rich") as rich_mock,
        ):
            result = guard_module._send_servers_discovered_event("pk", "url", "cursor", "")
        assert result is False
        assert "HTTP 500" in rich_mock.print.call_args.args[0]

    def test_discovery_exception_does_not_send(self):
        with (
            patch(f"{_G}._discover_servers_payload", side_effect=RuntimeError("discovery failed")),
            patch(f"{_G}.send_hook_event") as send,
            patch(f"{_G}.rich") as rich_mock,
        ):
            result = guard_module._send_servers_discovered_event("pk", "url", "cursor", "")
        assert result is False
        send.assert_not_called()
        assert "discovery failed" in rich_mock.print.call_args.args[0]

    def test_discovery_timeout_warns_without_sending(self):
        import asyncio
        import time as test_time

        async def slow_discovery(_inspect_args):
            await asyncio.sleep(0.5)
            return [], [], []

        with (
            patch("agent_scan.pipelines.discover_clients_to_inspect", side_effect=slow_discovery),
            patch(f"{_G}._DISCOVERY_TIMEOUT_SECONDS", 0.01),
            patch(f"{_G}.send_hook_event") as send,
            patch(f"{_G}.rich") as rich_mock,
        ):
            started = test_time.monotonic()
            result = guard_module._send_servers_discovered_event("pk", "url", "cursor", "")
            elapsed = test_time.monotonic() - started

        assert result is False
        assert elapsed < 0.2
        send.assert_not_called()
        assert "timed out" in rich_mock.print.call_args.args[0]


class TestGuardInstallMachineIdCli:
    def test_guard_install_accepts_machine_id(self, monkeypatch):
        from agent_scan import cli

        monkeypatch.setattr(sys, "argv", ["agent-scan", "guard", "install", "claude", "--machine-id", "machine-42"])
        with patch(f"{_G}.run_guard", return_value=0) as run:
            with pytest.raises(SystemExit) as exc:
                cli.main()

        assert exc.value.code == 0
        assert run.call_args.args[0].machine_id == "machine-42"

    def test_guard_install_rejects_control_identifier(self, monkeypatch):
        """--machine-id is the only spelling here; --control-identifier belongs to scan's
        control-server blocks, where it means a different dest."""
        from agent_scan import cli

        monkeypatch.setattr(
            sys, "argv", ["agent-scan", "guard", "install", "claude", "--control-identifier", "machine-42"]
        )
        # Patched so a regression that re-accepts the flag fails the assertion below
        # instead of running a real install against the developer's own config.
        with patch(f"{_G}.run_guard", return_value=0) as run:
            with pytest.raises(SystemExit) as exc:
                cli.main()

        assert exc.value.code == 2
        run.assert_not_called()


class TestGuardDiscoverCli:
    def test_parses_url(self, monkeypatch):
        from agent_scan import cli

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "agent-scan",
                "guard",
                "discover",
                "--url",
                "https://hooks.example",
                "--client",
                "claude-code",
            ],
        )
        with patch(f"{_G}.run_guard", return_value=0) as run:
            with pytest.raises(SystemExit) as exc:
                cli.main()

        assert exc.value.code == 0
        args = run.call_args.args[0]
        assert args.guard_command == "discover"
        assert args.url == "https://hooks.example"
        assert args.scope == "all"
        assert not hasattr(args, "file")

    @pytest.mark.parametrize("scope", ["servers", "skills", "all"])
    def test_parses_discovery_scope(self, scope, monkeypatch):
        from agent_scan import cli

        monkeypatch.setattr(
            sys,
            "argv",
            ["agent-scan", "guard", "discover", "--client", "claude-code", "--scope", scope],
        )
        with patch(f"{_G}.run_guard", return_value=0) as run:
            with pytest.raises(SystemExit) as exc:
                cli.main()

        assert exc.value.code == 0
        assert run.call_args.args[0].scope == scope

    def test_rejects_removed_file_option(self, monkeypatch):
        from agent_scan import cli

        monkeypatch.setattr(
            sys,
            "argv",
            ["agent-scan", "guard", "discover", "--client", "claude-code", "--file", "/tmp/settings.json"],
        )
        with pytest.raises(SystemExit) as exc:
            cli.main()

        assert exc.value.code == 2

    def test_requires_discovery_client(self, monkeypatch):
        from agent_scan import cli

        monkeypatch.setattr(sys, "argv", ["agent-scan", "guard", "discover"])
        with pytest.raises(SystemExit) as exc:
            cli.main()

        assert exc.value.code == 2

    @pytest.mark.parametrize("agent", ["claude-code", "cursor", "codex"])
    def test_parses_discovery_client(self, agent, monkeypatch):
        from agent_scan import cli

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "agent-scan",
                "guard",
                "discover",
                "--client",
                agent,
            ],
        )
        with patch(f"{_G}.run_guard", return_value=0) as run:
            with pytest.raises(SystemExit) as exc:
                cli.main()

        assert exc.value.code == 0
        assert run.call_args.args[0].client == agent


class TestRunDiscover:
    @pytest.fixture(autouse=True)
    def _posix_mode(self):
        with patch(f"{_G}.IS_WINDOWS", False), patch.dict(os.environ, {"MACHINE_ID": "machine-42"}):
            yield

    @staticmethod
    def _args(config: Path, url=None, **overrides):
        values = {
            "guard_command": "discover",
            "url": url,
            "client": "claude-code",
            "scope": "all",
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_happy_path_sends_session_start_discovery_from_environment(self, tmp_path, monkeypatch):
        config = tmp_path / "custom" / "settings.json"
        captured = {}

        def fake_send(url, client, push_key, payload, machine_id, **kwargs):
            captured.update(
                url=url,
                client=client,
                push_key=push_key,
                payload=json.loads(payload),
                machine_id=machine_id,
            )
            return True, ""

        monkeypatch.setenv("PUSH_KEY", "env-pk")
        monkeypatch.setenv("REMOTE_HOOKS_BASE_URL", "https://env-hooks.example")
        monkeypatch.setenv("MACHINE_ID", "env-machine")
        with (
            patch(f"{_G}._discover_servers_payload", return_value=[]),
            patch(f"{_G}.send_hook_event", side_effect=fake_send),
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(self._args(config))

        assert result == 0
        duration = captured["payload"].pop("discovery_duration_ms")
        assert isinstance(duration, int)
        assert duration >= 0
        assert captured["payload"] == {
            "hook_event_name": "SessionStartServerDiscovery",
            "servers": [],
            "session_id": "session-start-server-discovery",
        }
        assert captured["url"] == "https://env-hooks.example"
        assert captured["client"] == "claude-code"
        assert captured["push_key"] == "env-pk"
        assert captured["machine_id"] == "env-machine"

    def test_explicit_url_overrides_environment(self, tmp_path, monkeypatch):
        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        monkeypatch.setenv("REMOTE_HOOKS_BASE_URL", "https://env-hooks.example")
        with (
            patch(f"{_G}._discover_servers_payload", return_value=[]),
            patch(f"{_G}.send_hook_event", return_value=(True, "")) as send,
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(self._args(config, url="https://flag-hooks.example"))

        assert result == 0
        assert send.call_args.args[0] == "https://flag-hooks.example"

    def test_missing_push_key_returns_one_without_invoking_script(self, tmp_path, monkeypatch):
        config = tmp_path / "settings.json"
        monkeypatch.delenv("PUSH_KEY", raising=False)
        with patch(f"{_G}.send_hook_event") as send:
            result = guard_module.run_guard(self._args(config))

        assert result == 1
        send.assert_not_called()

    def test_missing_machine_id_returns_one_without_discovery(self, tmp_path, monkeypatch):
        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        monkeypatch.delenv("MACHINE_ID")
        with (
            patch(f"{_G}._discover_servers_payload") as discover,
            patch(f"{_G}.send_hook_event") as send,
            patch(f"{_G}.rich") as rich_mock,
        ):
            result = guard_module.run_guard(self._args(config))

        assert result == 1
        discover.assert_not_called()
        send.assert_not_called()
        assert "MACHINE_ID is required" in rich_mock.print.call_args.args[0]

    def test_no_forwarding_script_is_needed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        with (
            patch(f"{_G}._discover_servers_payload", return_value=[]),
            patch(f"{_G}.send_hook_event", return_value=(True, "")) as send,
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(self._args(tmp_path / "settings.json"))

        assert result == 0
        send.assert_called_once()

    def test_hook_stdin_reads_cwd_for_claude_code(self, tmp_path, monkeypatch):
        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        stdin = MagicMock()
        stdin.isatty.return_value = False
        stdin.read.return_value = '{"cwd":"/session/project","session_id":"session"}'
        discover = MagicMock(return_value=[])
        with (
            patch.object(sys, "stdin", stdin),
            patch(f"{_G}._discover_servers_payload", discover),
            patch(f"{_G}.send_hook_event", return_value=(True, "")) as send,
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(
                self._args(
                    config,
                    client="claude-code",
                )
            )

        assert result == 0
        stdin.read.assert_called_once_with(1024 * 1024)
        discover.assert_called_once_with(["/session/project"], discovery_scope="all")
        assert json.loads(send.call_args.args[3])["session_id"] == "session"

    def test_hook_stdin_reads_cwd_for_codex(self, tmp_path, monkeypatch):
        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        stdin = MagicMock()
        stdin.isatty.return_value = False
        stdin.read.return_value = (
            '{"cwd":"/session/project","workspace_roots":["/wrong/project"],"session_id":"session"}'
        )
        discover = MagicMock(return_value=[])
        with (
            patch.object(sys, "stdin", stdin),
            patch(f"{_G}._discover_servers_payload", discover),
            patch(f"{_G}.send_hook_event", return_value=(True, "")) as send,
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(self._args(config, client="codex"))

        assert result == 0
        stdin.read.assert_called_once_with(1024 * 1024)
        discover.assert_called_once_with(["/session/project"], discovery_scope="all")
        assert json.loads(send.call_args.args[3])["session_id"] == "session"

    def test_hook_stdin_accepts_workspace_roots_list(self, tmp_path, monkeypatch):
        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        stdin = MagicMock()
        stdin.isatty.return_value = False
        stdin.read.return_value = (
            '{"workspace_roots":["/workspace/one","/workspace/two"],"conversation_id":"conversation"}'
        )
        discover = MagicMock(return_value=[])
        with (
            patch.object(sys, "stdin", stdin),
            patch(f"{_G}._discover_servers_payload", discover),
            patch(f"{_G}.send_hook_event", return_value=(True, "")) as send,
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(self._args(config, client="cursor"))

        assert result == 0
        discover.assert_called_once_with(["/workspace/one", "/workspace/two"], discovery_scope="all")
        assert send.call_args.args[:3] == ("https://api.snyk.io", "cursor", "env-pk")
        assert json.loads(send.call_args.args[3])["conversation_id"] == "conversation"

    def test_malformed_hook_stdin_is_ignored(self, tmp_path, monkeypatch):
        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        stdin = MagicMock()
        stdin.isatty.return_value = False
        stdin.read.return_value = "not-json"
        discover = MagicMock(return_value=[])
        with (
            patch.object(sys, "stdin", stdin),
            patch(f"{_G}._discover_servers_payload", discover),
            patch(f"{_G}.send_hook_event", return_value=(True, "")) as send,
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(
                self._args(
                    config,
                    client="claude-code",
                )
            )

        assert result == 0
        discover.assert_called_once_with([], discovery_scope="all")
        assert json.loads(send.call_args.args[3])["session_id"] == "session-start-server-discovery"

    def test_tty_stdin_is_not_read(self, tmp_path, monkeypatch):
        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        stdin = MagicMock()
        stdin.isatty.return_value = True
        stdin.read.side_effect = AssertionError("tty stdin must not be read")
        discover = MagicMock(return_value=[])

        with (
            patch.object(sys, "stdin", stdin),
            patch(f"{_G}._discover_servers_payload", discover),
            patch(f"{_G}.send_hook_event", return_value=(True, "")),
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(self._args(config, client="claude-code"))

        assert result == 0
        stdin.read.assert_not_called()
        discover.assert_called_once_with([], discovery_scope="all")

    def test_pipe_that_never_closes_does_not_block_discovery(self, tmp_path, monkeypatch):
        import time as test_time

        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        release_read = threading.Event()
        stdin = MagicMock()
        stdin.isatty.return_value = False
        stdin.read.side_effect = lambda _limit: release_read.wait(0.5) and "{}"

        try:
            with (
                patch.object(sys, "stdin", stdin),
                patch(f"{_G}._STDIN_READ_TIMEOUT_SECONDS", 0.01),
                patch(f"{_G}._discover_servers_payload", return_value=[]),
                patch(f"{_G}.send_hook_event", return_value=(True, "")),
                patch(f"{_G}.rich"),
            ):
                started = test_time.monotonic()
                result = guard_module.run_guard(self._args(config, client="claude-code"))
                elapsed = test_time.monotonic() - started
        finally:
            release_read.set()

        assert result == 0
        assert elapsed < 0.2

    @pytest.mark.parametrize(
        "client,session_field,event_session_field",
        [
            ("claude-code", "session_id", "session_id"),
            ("cursor", "conversation_id", "conversation_id"),
            ("codex", "session_id", "session_id"),
        ],
    )
    @pytest.mark.parametrize(
        "session_value,expected_marker",
        [
            ("real-session", "real-session"),
            (None, "session-start-server-discovery"),
            ("", "session-start-server-discovery"),
            (123, "session-start-server-discovery"),
        ],
    )
    def test_hook_stdin_forwards_valid_session_marker_or_falls_back(
        self,
        tmp_path,
        monkeypatch,
        client,
        session_field,
        event_session_field,
        session_value,
        expected_marker,
    ):
        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        hook_payload = {} if session_value is None else {session_field: session_value}
        stdin = MagicMock()
        stdin.isatty.return_value = False
        stdin.read.return_value = json.dumps(hook_payload)
        with (
            patch.object(sys, "stdin", stdin),
            patch(f"{_G}._discover_servers_payload", return_value=[]),
            patch(f"{_G}.send_hook_event", return_value=(True, "")) as send,
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(self._args(config, client=client))

        assert result == 0
        event_payload = json.loads(send.call_args.args[3])
        assert event_payload[event_session_field] == expected_marker

    def test_missing_client_fails_without_discovery_or_send(self, tmp_path, monkeypatch):
        config = tmp_path / "settings.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        stdin = MagicMock()
        stdin.isatty.return_value = False
        stdin.read.side_effect = AssertionError("stdin must not be read")
        with (
            patch.object(sys, "stdin", stdin),
            patch(f"{_G}._discover_servers_payload") as discover,
            patch(f"{_G}.send_hook_event") as send,
            patch(f"{_G}.rich") as rich_mock,
        ):
            result = guard_module.run_guard(self._args(config, client=None))

        assert result == 1
        stdin.read.assert_not_called()
        discover.assert_not_called()
        send.assert_not_called()
        assert "--client is required" in rich_mock.print.call_args.args[0]

    def test_windows_uses_direct_sender(self, tmp_path, monkeypatch):
        config = tmp_path / "hooks.json"
        monkeypatch.setenv("PUSH_KEY", "env-pk")
        monkeypatch.setenv("REMOTE_HOOKS_BASE_URL", "https://env-hooks.example")
        monkeypatch.setenv("MACHINE_ID", "env-machine")
        with (
            patch(f"{_G}.IS_WINDOWS", True),
            patch(f"{_G}._discover_servers_payload", return_value=[]),
            patch(f"{_G}.send_hook_event", return_value=(True, "")) as send,
            patch(f"{_G}.rich"),
        ):
            result = guard_module.run_guard(self._args(config, client="codex"))

        assert result == 0
        assert send.call_args.args[:3] == ("https://env-hooks.example", "codex", "env-pk")
        assert send.call_args.args[4] == "env-machine"


class TestRunInstallSendsServersDiscovered:
    @staticmethod
    def _args(tmp_path, *, client="claude", file_override=True, managed=False, machine_id="machine-42"):
        return SimpleNamespace(
            client=client,
            url="https://api.snyk.io",
            tenant_id="tid-1",
            file=str(tmp_path / "config.json") if file_override else None,
            managed=managed,
            machine_id=machine_id,
        )

    @staticmethod
    def _fake_paths(tmp_path, installed):
        paths = {}
        for client in ALL_CLIENTS:
            path = tmp_path / client
            if client in installed:
                path.mkdir(exist_ok=True)
            paths[client] = path
        return paths

    def test_single_client_sends_once_directly(self, tmp_path, monkeypatch):
        from agent_scan.agents import DiscoveryScope

        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        script = Path("/installed/claude/hook.sh")
        with (
            patch(f"{_G}._install_hooks", return_value=script) as install,
            patch(f"{_G}._send_servers_discovered_event", return_value=True) as send,
        ):
            _run_install(self._args(tmp_path, machine_id="machine-42"))

        assert install.call_args.args[-1] == "machine-42"
        send.assert_called_once_with(
            "headless-pk",
            "https://api.snyk.io",
            "claude-code",
            "machine-42",
            discovery_scope=DiscoveryScope.SERVERS,
            max_retries=2,
        )

    def test_install_does_not_request_skills_discovery(self, tmp_path, monkeypatch):
        """The install event only ever reports servers, so it must not pay for a skills sweep."""
        from agent_scan.agents import DiscoveryScope

        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        with (
            patch(f"{_G}._install_hooks", return_value=Path("/installed/claude/hook.sh")),
            patch(f"{_G}._send_servers_discovered_event", return_value=True) as send,
        ):
            _run_install(self._args(tmp_path, machine_id="machine-42"))

        assert send.call_args.kwargs["discovery_scope"] is DiscoveryScope.SERVERS

    def test_install_retries_delivery_unlike_session_start(self, tmp_path, monkeypatch):
        """``guard install`` is a one-shot the user is watching, so a transport blip retries."""
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        with (
            patch(f"{_G}._install_hooks", return_value=Path("/installed/claude/hook.sh")),
            patch(f"{_G}._send_servers_discovered_event", return_value=True) as send,
        ):
            _run_install(self._args(tmp_path, machine_id="machine-42"))

        assert send.call_args.kwargs["max_retries"] == 2

    def test_cursor_install_uses_cursor_endpoint(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        script = Path("/installed/cursor/hook.sh")
        with (
            patch(f"{_G}._install_hooks", return_value=script),
            patch(f"{_G}._send_servers_discovered_event", return_value=True) as send,
        ):
            _run_install(self._args(tmp_path, client="cursor"))

        assert send.call_args.args[2] == "cursor"

    def test_install_all_sends_once_after_all_installs(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        scripts = [Path(f"/installed/{client}/hook.sh") for client in ALL_CLIENTS]
        order = []

        def install(*args):
            order.append(f"install:{args[0]}")
            return scripts[len(order) - 1]

        def send(*args, **kwargs):
            order.append("send")
            return True

        with (
            patch(f"{_G}._CLIENT_INSTALL_PATHS", self._fake_paths(tmp_path, ALL_CLIENTS)),
            patch(f"{_G}._install_hooks", side_effect=install) as install_mock,
            patch(f"{_G}._send_servers_discovered_event", side_effect=send) as send_mock,
        ):
            _run_install(self._args(tmp_path, client="all", file_override=False))

        assert install_mock.call_count == 3
        assert send_mock.call_count == 1
        assert send_mock.call_args.args[2] == "claude-code"
        assert order == ["install:claude", "install:cursor", "install:codex", "send"]

    def test_nothing_installed_does_not_send(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        with (
            patch(f"{_G}._CLIENT_INSTALL_PATHS", self._fake_paths(tmp_path, [])),
            patch(f"{_G}._install_hooks") as install,
            patch(f"{_G}._send_servers_discovered_event") as send,
        ):
            _run_install(self._args(tmp_path, file_override=False))

        install.assert_not_called()
        send.assert_not_called()

    def test_install_failure_revokes_minted_key_and_does_not_send(self, tmp_path, monkeypatch):
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "token")
        with (
            patch(f"{_G}.fetch_guard_enabled", return_value=True),
            patch(f"{_G}.mint_push_key", return_value="minted-pk"),
            patch(f"{_G}._install_hooks", side_effect=RuntimeError("install failed")),
            patch(f"{_G}._revoke_after_failure") as revoke,
            patch(f"{_G}._send_servers_discovered_event") as send,
        ):
            with pytest.raises(RuntimeError, match="install failed"):
                _run_install(self._args(tmp_path))

        revoke.assert_called_once_with("https://api.snyk.io", "tid-1", "token", "minted-pk")
        send.assert_not_called()

    def test_send_failure_keeps_success_exit_and_does_not_revoke(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        args = self._args(tmp_path)
        args.guard_command = "install"
        with (
            patch(f"{_G}._install_hooks", return_value=Path("/installed/hook.sh")),
            patch(f"{_G}._send_servers_discovered_event", return_value=False),
            patch(f"{_G}._revoke_after_failure") as revoke,
        ):
            result = guard_module.run_guard(args)

        assert result == 0
        revoke.assert_not_called()

    @pytest.mark.parametrize(
        "arg_machine_id, env_machine_id, expected",
        [("args-id", "env-id", "args-id"), (None, "env-id", "env-id")],
    )
    def test_machine_id_precedence_reaches_install_and_send(
        self, tmp_path, monkeypatch, arg_machine_id, env_machine_id, expected
    ):
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        if env_machine_id is None:
            monkeypatch.delenv("MACHINE_ID", raising=False)
        else:
            monkeypatch.setenv("MACHINE_ID", env_machine_id)
        with (
            patch(f"{_G}._install_hooks", return_value=Path("/installed/hook.sh")) as install,
            patch(f"{_G}._send_servers_discovered_event", return_value=True) as send,
        ):
            _run_install(self._args(tmp_path, machine_id=arg_machine_id))

        assert install.call_args.args[-1] == expected
        assert send.call_args.args[-1] == expected

    def test_missing_machine_id_aborts_before_install(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        monkeypatch.delenv("MACHINE_ID", raising=False)
        with (
            patch(f"{_G}._install_hooks") as install,
            patch(f"{_G}._send_servers_discovered_event") as send,
            pytest.raises(SystemExit) as exc,
        ):
            _run_install(self._args(tmp_path, machine_id=None))

        assert exc.value.code == 1
        install.assert_not_called()
        send.assert_not_called()

    def test_managed_install_sends(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        with (
            patch(f"{_G}._CLIENT_INSTALL_PATHS", self._fake_paths(tmp_path, ["claude"])),
            patch(f"{_G}._install_hooks", return_value=Path("/managed/hook.sh")),
            patch(f"{_G}._send_servers_discovered_event", return_value=True) as send,
        ):
            _run_install(self._args(tmp_path, file_override=False, managed=True))

        send.assert_called_once()


# ===================================================================
# _compute_hooks_diff
# ===================================================================


class TestComputeHooksDiff:
    def test_both_empty(self):
        result = _compute_hooks_diff({}, {})
        assert result == {"added": {}, "modified": {}, "removed": {}}

    def test_identical(self):
        cmd = "PUSH_KEY='x' bash '/path/snyk-agent-guard.sh' --client claude-code"
        hooks = {"PreToolUse": [{"hooks": [{"type": "command", "command": cmd}]}]}
        result = _compute_hooks_diff(hooks, hooks)
        assert result == {"added": {}, "modified": {}, "removed": {}}

    def test_key_only_in_new_is_removed(self):
        cmd = "PUSH_KEY='x' bash '/path/snyk-agent-guard.sh' --client claude-code"
        old = {}
        new = {"PreToolUse": [{"hooks": [{"type": "command", "command": cmd}]}]}
        result = _compute_hooks_diff(old, new)
        assert result["removed"] == {"PreToolUse": new["PreToolUse"]}
        assert result["added"] == {}
        assert result["modified"] == {}

    def test_key_only_in_old_is_added(self):
        cmd = "PUSH_KEY='x' bash '/path/snyk-agent-guard.sh' --client claude-code"
        old = {"Stop": [{"hooks": [{"type": "command", "command": cmd}]}]}
        new = {}
        result = _compute_hooks_diff(old, new)
        assert result["added"] == {"Stop": old["Stop"]}
        assert result["removed"] == {}
        assert result["modified"] == {}

    def test_same_key_different_value_is_modified(self):
        old_val = [
            {"hooks": [{"type": "command", "command": "PUSH_KEY='x' bash '/old/snyk-agent-guard.sh' --client claude"}]}
        ]
        new_val = [
            {"hooks": [{"type": "command", "command": "PUSH_KEY='x' bash '/new/snyk-agent-guard.sh' --client claude"}]}
        ]
        result = _compute_hooks_diff({"PreToolUse": old_val}, {"PreToolUse": new_val})
        assert result["modified"] == {"PreToolUse": {"expected_value": new_val, "actual_value": old_val}}
        assert result["added"] == {}
        assert result["removed"] == {}

    def test_multiple_removed(self):
        new = {
            "PreToolUse": [{"hooks": [{"command": "PUSH_KEY='x' bash snyk-agent-guard.sh --a"}]}],
            "Stop": [{"hooks": [{"command": "PUSH_KEY='x' bash snyk-agent-guard.sh --b"}]}],
        }
        result = _compute_hooks_diff({}, new)
        assert set(result["removed"]) == {"PreToolUse", "Stop"}

    def test_multiple_added(self):
        old = {
            "PreToolUse": [{"hooks": [{"command": "PUSH_KEY='x' bash snyk-agent-guard.sh --a"}]}],
            "Stop": [{"hooks": [{"command": "PUSH_KEY='x' bash snyk-agent-guard.sh --b"}]}],
        }
        result = _compute_hooks_diff(old, {})
        assert set(result["added"]) == {"PreToolUse", "Stop"}

    def test_added_removed_and_modified_combined(self):
        old_val = [{"hooks": [{"command": "PUSH_KEY='x' bash '/old/snyk-agent-guard.sh'"}]}]
        new_val = [{"hooks": [{"command": "PUSH_KEY='x' bash '/new/snyk-agent-guard.sh'"}]}]
        old = {
            "PreToolUse": old_val,
            "ExtraEvent": [{"hooks": [{"command": "PUSH_KEY='x' bash '/extra/snyk-agent-guard.sh'"}]}],
        }
        new = {
            "PreToolUse": new_val,
            "Stop": [{"hooks": [{"command": "PUSH_KEY='x' bash '/stop/snyk-agent-guard.sh'"}]}],
        }
        result = _compute_hooks_diff(old, new)
        assert result["added"] == {
            "ExtraEvent": [{"hooks": [{"command": "PUSH_KEY='x' bash '/extra/snyk-agent-guard.sh'"}]}]
        }
        assert result["removed"] == {
            "Stop": [{"hooks": [{"command": "PUSH_KEY='x' bash '/stop/snyk-agent-guard.sh'"}]}]
        }
        assert result["modified"] == {"PreToolUse": {"expected_value": new_val, "actual_value": old_val}}

    def test_unchanged_keys_excluded_from_all_categories(self):
        cmd = "PUSH_KEY='x' bash '/path/snyk-agent-guard.sh'"
        shared = [{"hooks": [{"command": cmd}]}]
        old = {
            "PreToolUse": shared,
            "Extra": [{"hooks": [{"command": "PUSH_KEY='x' bash '/extra/snyk-agent-guard.sh'"}]}],
        }
        new = {
            "PreToolUse": shared,
            "Stop": [{"hooks": [{"command": "PUSH_KEY='x' bash '/stop/snyk-agent-guard.sh'"}]}],
        }
        result = _compute_hooks_diff(old, new)
        assert "PreToolUse" not in result["added"]
        assert "PreToolUse" not in result["removed"]
        assert "PreToolUse" not in result["modified"]

    def test_old_empty_new_has_guard_hooks(self):
        cmd = "PUSH_KEY='x' bash '/path/snyk-agent-guard.sh'"
        new = {
            "A": [{"hooks": [{"command": cmd}]}],
            "B": [{"hooks": [{"command": cmd}]}],
            "C": [{"hooks": [{"command": cmd}]}],
        }
        result = _compute_hooks_diff({}, new)
        assert result["removed"] == new
        assert result["added"] == {}
        assert result["modified"] == {}

    def test_new_empty_old_has_guard_hooks(self):
        cmd = "PUSH_KEY='x' bash '/path/snyk-agent-guard.sh'"
        old = {
            "A": [{"hooks": [{"command": cmd}]}],
            "B": [{"hooks": [{"command": cmd}]}],
        }
        result = _compute_hooks_diff(old, {})
        assert result["added"] == old
        assert result["removed"] == {}
        assert result["modified"] == {}

    def test_nested_value_difference_is_modified(self):
        old_val = [{"hooks": [{"type": "command", "command": "PUSH_KEY='x' bash snyk-agent-guard.sh", "timeout": 10}]}]
        new_val = [{"hooks": [{"type": "command", "command": "PUSH_KEY='x' bash snyk-agent-guard.sh", "timeout": 30}]}]
        result = _compute_hooks_diff({"PreToolUse": old_val}, {"PreToolUse": new_val})
        assert "PreToolUse" in result["modified"]
        assert result["modified"]["PreToolUse"]["expected_value"] == new_val
        assert result["modified"]["PreToolUse"]["actual_value"] == old_val

    def test_push_key_only_difference_not_modified(self):
        """Hooks differing only by push key UUID should not appear as modified."""
        old = {
            "PreToolUse": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "PUSH_KEY='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash '/path/to/snyk-agent-guard.sh' --client claude",
                        }
                    ]
                }
            ]
        }
        new = {
            "PreToolUse": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "PUSH_KEY='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash '/path/to/snyk-agent-guard.sh' --client claude",
                        }
                    ]
                }
            ]
        }
        result = _compute_hooks_diff(old, new)
        assert result == {"added": {}, "modified": {}, "removed": {}}

    def test_push_key_only_difference_powershell_not_modified(self):
        """PowerShell-style -PushKey difference should also be ignored."""
        old = {
            "PreToolUse": [
                {
                    "command": "powershell -File 'snyk-agent-guard.ps1' -Client claude -PushKey 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -RemoteUrl 'https://api.snyk.io'"
                }
            ]
        }
        new = {
            "PreToolUse": [
                {
                    "command": "powershell -File 'snyk-agent-guard.ps1' -Client claude -PushKey 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' -RemoteUrl 'https://api.snyk.io'"
                }
            ]
        }
        result = _compute_hooks_diff(old, new)
        assert result == {"added": {}, "modified": {}, "removed": {}}

    def test_push_key_plus_other_change_is_modified(self):
        """If the command differs by push key AND something else, it IS modified."""
        old = {
            "PreToolUse": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "PUSH_KEY='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' REMOTE_HOOKS_BASE_URL='https://old.example.com' bash '/path/to/snyk-agent-guard.sh' --client claude",
                        }
                    ]
                }
            ]
        }
        new = {
            "PreToolUse": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "PUSH_KEY='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' REMOTE_HOOKS_BASE_URL='https://new.example.com' bash '/path/to/snyk-agent-guard.sh' --client claude",
                        }
                    ]
                }
            ]
        }
        result = _compute_hooks_diff(old, new)
        assert "PreToolUse" in result["modified"]
        assert result["modified"]["PreToolUse"]["expected_value"] == new["PreToolUse"]
        assert result["modified"]["PreToolUse"]["actual_value"] == old["PreToolUse"]

    def test_diff_is_deep_copied_from_sources(self):
        extra_cmd = "PUSH_KEY='x' bash '/extra/snyk-agent-guard.sh'"
        new_cmd = "PUSH_KEY='x' bash '/new/snyk-agent-guard.sh'"
        old = {"Extra": [{"hooks": [{"command": extra_cmd}]}]}
        new = {
            "Stop": [{"hooks": [{"command": new_cmd}]}],
            "PreToolUse": [{"hooks": [{"command": "PUSH_KEY='x' bash '/different/snyk-agent-guard.sh'"}]}],
        }
        old["PreToolUse"] = [{"hooks": [{"command": "PUSH_KEY='x' bash '/original/snyk-agent-guard.sh'"}]}]
        result = _compute_hooks_diff(old, new)

        result["added"]["Extra"][0]["hooks"][0]["command"] = "MUTATED"
        assert old["Extra"][0]["hooks"][0]["command"] == extra_cmd

        result["removed"]["Stop"][0]["hooks"][0]["command"] = "MUTATED"
        assert new["Stop"][0]["hooks"][0]["command"] == new_cmd

        result["modified"]["PreToolUse"]["expected_value"][0]["hooks"][0]["command"] = "MUTATED"
        assert new["PreToolUse"][0]["hooks"][0]["command"] == "PUSH_KEY='x' bash '/different/snyk-agent-guard.sh'"

        result["modified"]["PreToolUse"]["actual_value"][0]["hooks"][0]["command"] = "MUTATED"
        assert old["PreToolUse"][0]["hooks"][0]["command"] == "PUSH_KEY='x' bash '/original/snyk-agent-guard.sh'"

    def test_customer_hooks_only_are_ignored(self):
        """Events with only customer (non-guard) hooks produce no diff."""
        old = {"PreToolUse": [{"hooks": [{"command": "customer-tool-old"}]}]}
        new = {"PreToolUse": [{"hooks": [{"command": "customer-tool-new"}]}]}
        result = _compute_hooks_diff(old, new)
        assert result == {"added": {}, "modified": {}, "removed": {}}

    def test_customer_hooks_added_or_removed_are_ignored(self):
        """Adding or removing customer-only events should not appear in diff."""
        old = {"PreToolUse": [{"hooks": [{"command": "customer-tool"}]}]}
        new = {"Stop": [{"hooks": [{"command": "other-customer-tool"}]}]}
        result = _compute_hooks_diff(old, new)
        assert result == {"added": {}, "modified": {}, "removed": {}}

    def test_mixed_hooks_only_guard_diffed(self):
        """When events have both guard and customer hooks, only guard hooks are compared."""
        guard_old = {"hooks": [{"command": "PUSH_KEY='x' bash '/old/snyk-agent-guard.sh'"}]}
        guard_new = {"hooks": [{"command": "PUSH_KEY='x' bash '/new/snyk-agent-guard.sh'"}]}
        customer = {"hooks": [{"command": "customer-tool"}]}
        old = {"PreToolUse": [customer, guard_old]}
        new = {"PreToolUse": [customer, guard_new]}
        result = _compute_hooks_diff(old, new)
        assert result["modified"] == {
            "PreToolUse": {
                "expected_value": [guard_new],
                "actual_value": [guard_old],
            }
        }

    def test_customer_hook_changes_do_not_mask_guard_identity(self):
        """Changing customer hooks while guard hooks stay the same produces no diff."""
        guard = {"hooks": [{"command": "PUSH_KEY='x' bash snyk-agent-guard.sh"}]}
        old = {"PreToolUse": [{"hooks": [{"command": "old-customer"}]}, guard]}
        new = {"PreToolUse": [{"hooks": [{"command": "new-customer"}]}, guard]}
        result = _compute_hooks_diff(old, new)
        assert result == {"added": {}, "modified": {}, "removed": {}}

    def test_cursor_format_guard_hooks_diffed(self):
        """Cursor-format entries (flat dict with 'command') are correctly extracted."""
        old = {"preToolUse": [{"command": "PUSH_KEY='x' bash snyk-agent-guard.sh --old"}]}
        new = {"preToolUse": [{"command": "PUSH_KEY='x' bash snyk-agent-guard.sh --new"}]}
        result = _compute_hooks_diff(old, new)
        assert "preToolUse" in result["modified"]

    def test_cursor_format_customer_hooks_ignored(self):
        """Cursor-format customer hooks are ignored in diff."""
        old = {"preToolUse": [{"command": "customer-tool --old"}]}
        new = {"preToolUse": [{"command": "customer-tool --new"}]}
        result = _compute_hooks_diff(old, new)
        assert result == {"added": {}, "modified": {}, "removed": {}}


# ===================================================================
# Prepare functions: custom hooks on unknown events must be preserved
# ===================================================================


class TestPrepareHandlesUnknownEvents:
    """Custom (non-agent-scan) hooks on events not in *_HOOK_EVENTS must
    be preserved in the prepared config.  Agent-scan hooks on unknown
    events are still dropped (filtered out)."""

    def test_claude_preserves_unknown_event_non_agent_scan(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"hooks": {"UnknownEvent": [_claude_group(OTHER_CMD)]}})
        settings, diff, preserved = _prepare_claude_config(AGENT_SCAN_CMD, path)
        assert "UnknownEvent" in settings["hooks"]
        assert settings["hooks"]["UnknownEvent"] == [_claude_group(OTHER_CMD)]
        assert "UnknownEvent" not in diff["added"]
        assert preserved == 0

    def test_claude_drops_unknown_event_agent_scan(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"hooks": {"UnknownEvent": [_claude_group(AGENT_SCAN_CMD)]}})
        settings, _, _ = _prepare_claude_config(AGENT_SCAN_CMD, path)
        assert "UnknownEvent" not in settings["hooks"]

    def test_claude_preserves_known_event_other_hooks(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(path, {"hooks": {"PreToolUse": [_claude_group(OTHER_CMD, "*")]}})
        settings, _, preserved = _prepare_claude_config(AGENT_SCAN_CMD, path)
        commands = [h["command"] for g in settings["hooks"]["PreToolUse"] for h in g.get("hooks", [])]
        assert OTHER_CMD in commands
        assert preserved == 1

    def test_cursor_preserves_unknown_event(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"version": 1, "hooks": {"unknownEvent": [_cursor_entry(CURSOR_OTHER_CMD)]}})
        data, diff, preserved = _prepare_cursor_config(CURSOR_AGENT_SCAN_CMD, path)
        assert "unknownEvent" in data["hooks"]
        assert data["hooks"]["unknownEvent"] == [_cursor_entry(CURSOR_OTHER_CMD)]
        assert "unknownEvent" not in diff["added"]
        assert preserved == 0

    def test_codex_preserves_unknown_event(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(path, {"hooks": {"UnknownEvent": [_claude_group(OTHER_CMD)]}})
        data, diff, preserved = _prepare_codex_config(CODEX_AGENT_SCAN_CMD, path)
        assert "UnknownEvent" in data["hooks"]
        assert data["hooks"]["UnknownEvent"] == [_claude_group(OTHER_CMD)]
        assert "UnknownEvent" not in diff["added"]
        assert preserved == 0


# ===================================================================
# Install preserves custom hooks (known + unknown events)
# ===================================================================


class TestInstallPreservesCustomHooks:
    """Installing agent-scan hooks must keep all custom (non-agent-scan)
    hooks, on both known and unknown events."""

    def test_claude_preserves_custom_hooks_on_known_and_unknown_events(self, tmp_path):
        path = tmp_path / "settings.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(OTHER_CMD, "*")],
                    "CustomEvent": [_claude_group(OTHER_CMD)],
                }
            },
        )
        settings, _, preserved = _prepare_claude_config(AGENT_SCAN_CMD, path)
        hooks = settings["hooks"]

        commands_pre = [h["command"] for g in hooks["PreToolUse"] for h in g.get("hooks", [])]
        assert OTHER_CMD in commands_pre
        assert any(AGENT_SCAN_CMD in c for c in commands_pre)

        assert "CustomEvent" in hooks
        assert hooks["CustomEvent"] == [_claude_group(OTHER_CMD)]

        assert preserved == 1

    def test_cursor_preserves_custom_hooks_on_known_and_unknown_events(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "version": 1,
                "hooks": {
                    "stop": [_cursor_entry(CURSOR_OTHER_CMD)],
                    "customEvent": [_cursor_entry(CURSOR_OTHER_CMD)],
                },
            },
        )
        data, _, preserved = _prepare_cursor_config(CURSOR_AGENT_SCAN_CMD, path)
        hooks = data["hooks"]

        commands_stop = [e["command"] for e in hooks["stop"]]
        assert CURSOR_OTHER_CMD in commands_stop
        assert CURSOR_AGENT_SCAN_CMD in commands_stop

        assert "customEvent" in hooks
        assert hooks["customEvent"] == [_cursor_entry(CURSOR_OTHER_CMD)]

        assert preserved == 1

    def test_codex_preserves_custom_hooks_on_known_and_unknown_events(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [_claude_group(OTHER_CMD)],
                    "CustomEvent": [_claude_group(OTHER_CMD)],
                }
            },
        )
        data, _, preserved = _prepare_codex_config(CODEX_AGENT_SCAN_CMD, path)
        hooks = data["hooks"]

        commands_pre = [h["command"] for g in hooks["PreToolUse"] for h in g.get("hooks", [])]
        assert OTHER_CMD in commands_pre

        assert "CustomEvent" in hooks
        assert hooks["CustomEvent"] == [_claude_group(OTHER_CMD)]

        assert preserved == 1


# ===================================================================
# Uninstall preserves custom hooks (known + unknown events)
# ===================================================================


class TestUninstallPreservesCustomHooks:
    """Uninstalling agent-scan hooks must keep all custom (non-agent-scan)
    hooks, including those on events not in the agent-scan event list."""

    def test_claude_uninstall_preserves_custom_hooks(self, tmp_path):
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
                    "CustomEvent": [_claude_group(OTHER_CMD)],
                }
            },
        )
        _uninstall_test_client("claude", path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1
        assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == OTHER_CMD
        assert "Stop" not in data["hooks"]
        assert "CustomEvent" in data["hooks"]
        assert data["hooks"]["CustomEvent"] == [_claude_group(OTHER_CMD)]

    def test_cursor_uninstall_preserves_custom_hooks(self, tmp_path):
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
                    "customEvent": [_cursor_entry(CURSOR_OTHER_CMD)],
                },
            },
        )
        _uninstall_test_client("cursor", path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["stop"]) == 1
        assert data["hooks"]["stop"][0]["command"] == CURSOR_OTHER_CMD
        assert "sessionStart" not in data["hooks"]
        assert "customEvent" in data["hooks"]
        assert data["hooks"]["customEvent"] == [_cursor_entry(CURSOR_OTHER_CMD)]

    def test_codex_uninstall_preserves_custom_hooks(self, tmp_path):
        path = tmp_path / "hooks.json"
        _write(
            path,
            {
                "hooks": {
                    "PreToolUse": [
                        _claude_group(OTHER_CMD),
                        _claude_group(CODEX_AGENT_SCAN_CMD),
                    ],
                    "Stop": [_claude_group(CODEX_AGENT_SCAN_CMD)],
                    "CustomEvent": [_claude_group(OTHER_CMD)],
                }
            },
        )
        _uninstall_test_client("codex", path)

        data = json.loads(path.read_text())
        assert len(data["hooks"]["PreToolUse"]) == 1
        assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == OTHER_CMD
        assert "Stop" not in data["hooks"]
        assert "CustomEvent" in data["hooks"]
        assert data["hooks"]["CustomEvent"] == [_claude_group(OTHER_CMD)]


# ===================================================================
# client="all" support
# ===================================================================


class TestRunInstallAll:
    """_run_install with client='all' installs all three clients with a single push key."""

    @pytest.fixture(autouse=True)
    def _all_clients_installed(self, tmp_path):
        fake_paths = {}
        for client in ALL_CLIENTS:
            d = tmp_path / f".{client}"
            d.mkdir()
            fake_paths[client] = d
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", fake_paths):
            yield

    @pytest.fixture(autouse=True)
    def _no_servers_discovered_event(self):
        # _install_hooks is mocked below, so without this the real post-install
        # send would run actual machine discovery and invoke the hook script.
        with (
            patch("agent_scan.guard._send_servers_discovered_event", return_value=True),
            patch.dict(os.environ, {"MACHINE_ID": "machine-42"}),
        ):
            yield

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_install_all_calls_install_hooks_for_each_client(
        self, mock_fetch, mock_mint, mock_install, tmp_path, monkeypatch
    ):
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "tok")
        args = SimpleNamespace(
            client="all",
            url="https://api.snyk.io",
            tenant_id="tid-1",
            file=None,
            managed=False,
        )
        _run_install(args)
        mock_mint.assert_called_once()
        assert mock_install.call_count == len(ALL_CLIENTS)
        called_clients = [c.args[0] for c in mock_install.call_args_list]
        assert called_clients == ALL_CLIENTS

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_install_all_reuses_single_push_key(self, mock_fetch, mock_mint, mock_install, tmp_path, monkeypatch):
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "tok")
        args = SimpleNamespace(
            client="all",
            url="https://api.snyk.io",
            tenant_id="tid-1",
            file=None,
            managed=False,
        )
        _run_install(args)
        for call in mock_install.call_args_list:
            assert call.args[2] == "minted-pk"

    @patch("agent_scan.guard._install_hooks")
    def test_install_all_headless(self, mock_install, tmp_path, monkeypatch):
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        monkeypatch.setenv("TENANT_ID", "tid-hl")
        args = SimpleNamespace(
            client="all",
            url="https://api.snyk.io",
            tenant_id="",
            file=None,
            managed=False,
        )
        _run_install(args)
        assert mock_install.call_count == len(ALL_CLIENTS)
        for call in mock_install.call_args_list:
            assert call.args[2] == "headless-pk"

    def test_install_all_with_file_override_exits(self, monkeypatch):
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "tok")
        args = SimpleNamespace(
            client="all",
            url="https://api.snyk.io",
            tenant_id="tid-1",
            file="/tmp/override.json",
            managed=False,
        )
        with pytest.raises(SystemExit):
            _run_install(args)

    @patch("agent_scan.guard._revoke_after_failure")
    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_install_all_partial_failure_does_not_revoke(
        self, mock_fetch, mock_mint, mock_install, mock_revoke, tmp_path, monkeypatch
    ):
        """First client succeeds, second raises — push key must NOT be revoked."""
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "tok")

        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None
            raise RuntimeError("config write failed")

        mock_install.side_effect = side_effect
        args = SimpleNamespace(
            client="all",
            url="https://api.snyk.io",
            tenant_id="tid-1",
            file=None,
            managed=False,
        )
        with pytest.raises(RuntimeError, match="config write failed"):
            _run_install(args)
        mock_revoke.assert_not_called()

    @patch("agent_scan.guard._revoke_after_failure")
    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_install_all_first_client_failure_revokes(
        self, mock_fetch, mock_mint, mock_install, mock_revoke, tmp_path, monkeypatch
    ):
        """First client fails — push key must be revoked."""
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "tok")
        mock_install.side_effect = RuntimeError("first client failed")
        args = SimpleNamespace(
            client="all",
            url="https://api.snyk.io",
            tenant_id="tid-1",
            file=None,
            managed=False,
        )
        with pytest.raises(RuntimeError, match="first client failed"):
            _run_install(args)
        mock_revoke.assert_called_once_with("https://api.snyk.io", "tid-1", "tok", "minted-pk")


class TestRunUninstallAll:
    """_run_uninstall with client='all' uninstalls all three clients."""

    @patch("agent_scan.guard._uninstall_single_client")
    def test_uninstall_all_calls_each_client(self, mock_single):
        args = SimpleNamespace(
            client="all",
            file=None,
            managed=False,
        )
        _run_uninstall(args)
        assert mock_single.call_count == len(ALL_CLIENTS)
        called_clients = [c.args[0] for c in mock_single.call_args_list]
        assert called_clients == ALL_CLIENTS

    def test_uninstall_all_with_file_override_exits(self):
        args = SimpleNamespace(
            client="all",
            file="/tmp/override.json",
            managed=False,
        )
        with pytest.raises(SystemExit):
            _run_uninstall(args)


# ===================================================================
# _is_client_installed: agent presence check
# ===================================================================


class TestIsClientInstalled:
    def test_installed_when_config_dir_exists(self, tmp_path):
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", {"claude": tmp_path / ".claude"}):
            (tmp_path / ".claude").mkdir()
            assert _is_client_installed("claude") is True

    def test_not_installed_when_config_dir_missing(self, tmp_path):
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", {"claude": tmp_path / ".claude"}):
            assert _is_client_installed("claude") is False

    def test_not_installed_when_path_is_file_not_dir(self, tmp_path):
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", {"claude": tmp_path / ".claude"}):
            (tmp_path / ".claude").write_text("")
            assert _is_client_installed("claude") is False

    def test_unknown_client_returns_true(self):
        assert _is_client_installed("unknown-client") is True

    def test_permission_error_returns_false(self, tmp_path):
        path = MagicMock()
        path.is_dir.side_effect = PermissionError("denied")
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", {"claude": path}):
            assert _is_client_installed("claude") is False


# ===================================================================
# _run_install: skip clients not installed on machine
# ===================================================================


class TestRunInstallSkipsUninstalledClients:
    """_run_install should skip hook installation for agents not present on the machine."""

    @pytest.fixture(autouse=True)
    def _no_servers_discovered_event(self):
        # _install_hooks is mocked below, so without this the real post-install
        # send would run actual machine discovery and invoke the hook script.
        with (
            patch("agent_scan.guard._send_servers_discovered_event", return_value=True),
            patch.dict(os.environ, {"MACHINE_ID": "machine-42"}),
        ):
            yield

    @staticmethod
    def _fake_paths(tmp_path, installed_clients):
        """Build a _CLIENT_INSTALL_PATHS dict where only *installed_clients* have real dirs."""
        paths = {}
        for client in ALL_CLIENTS:
            d = tmp_path / f".{client}"
            if client in installed_clients:
                d.mkdir(exist_ok=True)
            paths[client] = d
        return paths

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_single_client_not_installed_returns_gracefully(
        self, mock_fetch, mock_mint, mock_install, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "tok")
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", self._fake_paths(tmp_path, [])):
            _run_install(
                SimpleNamespace(
                    client="claude",
                    url="https://api.snyk.io",
                    tenant_id="tid-1",
                    file=None,
                    managed=False,
                )
            )
        mock_mint.assert_not_called()
        mock_install.assert_not_called()
        out = capsys.readouterr().out
        assert "not installed" in out.lower()

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_all_clients_none_installed_returns_gracefully(
        self, mock_fetch, mock_mint, mock_install, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "tok")
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", self._fake_paths(tmp_path, [])):
            _run_install(
                SimpleNamespace(
                    client="all",
                    url="https://api.snyk.io",
                    tenant_id="tid-1",
                    file=None,
                    managed=False,
                )
            )
        mock_mint.assert_not_called()
        mock_install.assert_not_called()
        out = capsys.readouterr().out
        assert "No installed agents found" in out

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_all_clients_some_installed_skips_missing(
        self, mock_fetch, mock_mint, mock_install, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "tok")
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", self._fake_paths(tmp_path, ["claude"])):
            _run_install(
                SimpleNamespace(
                    client="all",
                    url="https://api.snyk.io",
                    tenant_id="tid-1",
                    file=None,
                    managed=False,
                )
            )
        mock_mint.assert_called_once()
        mock_install.assert_called_once()
        assert mock_install.call_args.args[0] == "claude"
        out = capsys.readouterr().out
        assert "Cursor" in out and "not installed" in out.lower()
        assert "Codex" in out

    @patch("agent_scan.guard._install_hooks")
    def test_headless_skips_uninstalled_client(self, mock_install, tmp_path, monkeypatch, capsys):
        monkeypatch.setenv("PUSH_KEY", "headless-pk")
        monkeypatch.setenv("TENANT_ID", "tid-hl")
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", self._fake_paths(tmp_path, [])):
            _run_install(
                SimpleNamespace(
                    client="cursor",
                    url="https://api.snyk.io",
                    tenant_id="",
                    file=None,
                    managed=False,
                )
            )
        mock_install.assert_not_called()
        out = capsys.readouterr().out
        assert "not installed" in out.lower()

    @patch("agent_scan.guard._install_hooks")
    @patch("agent_scan.guard.mint_push_key", return_value="minted-pk")
    @patch("agent_scan.guard.fetch_guard_enabled", return_value=True)
    def test_all_clients_all_installed_installs_all(self, mock_fetch, mock_mint, mock_install, tmp_path, monkeypatch):
        monkeypatch.delenv("PUSH_KEY", raising=False)
        monkeypatch.setenv("SNYK_TOKEN", "tok")
        with patch("agent_scan.guard._CLIENT_INSTALL_PATHS", self._fake_paths(tmp_path, ALL_CLIENTS)):
            _run_install(
                SimpleNamespace(
                    client="all",
                    url="https://api.snyk.io",
                    tenant_id="tid-1",
                    file=None,
                    managed=False,
                )
            )
        assert mock_install.call_count == len(ALL_CLIENTS)
        called_clients = [c.args[0] for c in mock_install.call_args_list]
        assert called_clients == ALL_CLIENTS
