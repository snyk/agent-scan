"""E2E test for guard install — ensures the bundled hook scripts are accessible."""

import base64
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest


class _FakeHookServer(BaseHTTPRequestHandler):
    """Accepts any POST and returns 200 — enough for the test-event handshake."""

    requests: ClassVar[list[dict]] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        _FakeHookServer.requests.append(
            {
                "body": json.loads(base64.b64decode(body.removeprefix("base64:"))),
                "headers": dict(self.headers),
            }
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, format, *args):
        pass


@pytest.fixture()
def fake_hook_server():
    server = HTTPServer(("127.0.0.1", 0), _FakeHookServer)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    _FakeHookServer.requests = []
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestGuardInstallE2E:
    """Guard install must work end-to-end, including from the PyInstaller binary.

    This catches regressions where bundled data files (hook scripts) are
    missing from the binary.
    """

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_guard_install_claude(self, agent_scan_cmd, tmp_path, fake_hook_server):
        config_file = tmp_path / "settings.json"
        install_env = {**os.environ, "PUSH_KEY": "test-pk-e2e"}
        install_env.pop("AGENT_SCAN_COMMAND", None)
        install_env.pop("MACHINE_ID", None)
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "guard",
                "install",
                "claude",
                "--file",
                str(config_file),
                "--url",
                fake_hook_server,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            env=install_env,
        )
        assert result.returncode == 0, f"guard install failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        # The config file should exist and contain valid JSON with hooks
        settings = json.loads(config_file.read_text())
        assert "hooks" in settings
        # Should have entries for standard Claude hook events
        assert "PreToolUse" in settings["hooks"]
        assert "Stop" in settings["hooks"]
        discovery_groups = [
            group for group in settings["hooks"]["SessionStart"] if group.get("hooks", [{}])[0].get("async") is True
        ]
        assert len(discovery_groups) == 1
        assert "matcher" not in discovery_groups[0]
        discover_command = discovery_groups[0]["hooks"][0]["command"]
        discover_script = "snyk-agent-guard-discover.ps1" if os.name == "nt" else "snyk-agent-guard-discover.sh"
        assert discover_script in discover_command
        assert ("-SkipDiscoveryScopes" if os.name == "nt" else "--skip-discovery-scopes") in discover_command
        assert "project_workspace" in discover_command
        assert str(config_file) not in discover_command
        assert ("-ConfigFile" if os.name == "nt" else "--file") not in discover_command
        assert [request["body"]["hook_event_name"] for request in _FakeHookServer.requests] == [
            "hooksConfigured",
            "hooksConfiguredServerDiscovery",
        ]
        discovered = _FakeHookServer.requests[1]
        assert discovered["body"]["session_id"] == "hooks-setup"
        assert isinstance(discovered["body"]["servers"], list)
        assert isinstance(discovered["body"]["discovery_duration_ms"], int)
        assert discovered["body"]["discovery_duration_ms"] >= 0
        discovered_user = json.loads(discovered["headers"]["X-User"])
        assert discovered_user["identifier"] == discovered_user["hostname"]

        discover_result = subprocess.run(
            [*agent_scan_cmd, "guard", "discover", "--client", "claude-code"],
            capture_output=True,
            text=True,
            timeout=60,
            env={
                **os.environ,
                "PUSH_KEY": "test-pk-e2e",
                "REMOTE_HOOKS_BASE_URL": fake_hook_server,
                "MACHINE_ID": "e2e-machine-id",
            },
        )
        assert discover_result.returncode == 0, (
            f"guard discover failed:\nstdout: {discover_result.stdout}\nstderr: {discover_result.stderr}"
        )
        session_discovery = _FakeHookServer.requests[-1]
        assert session_discovery["body"]["hook_event_name"] == "sessionStartServerDiscovery"
        assert session_discovery["body"]["session_id"] == "session-start-server-discovery"
        assert isinstance(session_discovery["body"]["servers"], list)
        assert isinstance(session_discovery["body"]["discovery_duration_ms"], int)
        assert session_discovery["body"]["discovery_duration_ms"] >= 0

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_guard_install_cursor(self, agent_scan_cmd, agent_scan_command, tmp_path, fake_hook_server):
        config_file = tmp_path / "hooks.json"
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "guard",
                "install",
                "cursor",
                "--file",
                str(config_file),
                "--url",
                fake_hook_server,
                "--machine-id",
                "e2e-machine-id",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "PUSH_KEY": "test-pk-e2e", "AGENT_SCAN_COMMAND": str(agent_scan_command)},
        )
        assert result.returncode == 0, f"guard install failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        data = json.loads(config_file.read_text())
        assert "hooks" in data
        assert "preToolUse" in data["hooks"]
        assert "stop" in data["hooks"]

        discover_script = "snyk-agent-guard-discover.ps1" if os.name == "nt" else "snyk-agent-guard-discover.sh"
        discovery_entries = [
            entry for entry in data["hooks"]["sessionStart"] if discover_script in entry.get("command", "")
        ]
        assert len(discovery_entries) == 1
        assert set(discovery_entries[0]) == {"command"}
        assert ("-SkipDiscoveryScopes" if os.name == "nt" else "--skip-discovery-scopes") in discovery_entries[0][
            "command"
        ]
        assert "project_workspace" in discovery_entries[0]["command"]
        assert str(config_file) not in discovery_entries[0]["command"]

        discover_result = subprocess.run(
            [*agent_scan_cmd, "guard", "discover", "--client", "cursor"],
            input=json.dumps({"workspace_roots": [str(tmp_path)], "conversation_id": "e2e-conversation"}),
            capture_output=True,
            text=True,
            timeout=60,
            env={
                **os.environ,
                "PUSH_KEY": "test-pk-e2e",
                "REMOTE_HOOKS_BASE_URL": fake_hook_server,
                "MACHINE_ID": "e2e-machine-id",
            },
        )
        assert discover_result.returncode == 0, (
            f"guard discover failed:\nstdout: {discover_result.stdout}\nstderr: {discover_result.stderr}"
        )
        session_discovery = _FakeHookServer.requests[-1]
        assert session_discovery["body"]["hook_event_name"] == "sessionStartServerDiscovery"
        assert session_discovery["body"]["conversation_id"] == "e2e-conversation"
        assert "session_id" not in session_discovery["body"]
        assert isinstance(session_discovery["body"]["servers"], list)
        assert isinstance(session_discovery["body"]["discovery_duration_ms"], int)
        assert session_discovery["body"]["discovery_duration_ms"] >= 0

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_guard_install_codex(self, agent_scan_cmd, agent_scan_command, tmp_path, fake_hook_server):
        config_file = tmp_path / "hooks.json"
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "guard",
                "install",
                "codex",
                "--file",
                str(config_file),
                "--url",
                fake_hook_server,
                "--machine-id",
                "e2e-machine-id",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "PUSH_KEY": "test-pk-e2e", "AGENT_SCAN_COMMAND": str(agent_scan_command)},
        )
        assert result.returncode == 0, f"guard install failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        data = json.loads(config_file.read_text())
        assert "PreToolUse" in data["hooks"]
        assert "Stop" in data["hooks"]

        discover_script = "snyk-agent-guard-discover.ps1" if os.name == "nt" else "snyk-agent-guard-discover.sh"
        discovery_groups = [
            group
            for group in data["hooks"]["SessionStart"]
            if discover_script in group.get("hooks", [{}])[0].get("command", "")
        ]
        assert len(discovery_groups) == 1
        assert "matcher" not in discovery_groups[0]
        assert discovery_groups[0]["hooks"][0]["async"] is True
        assert ("-SkipDiscoveryScopes" if os.name == "nt" else "--skip-discovery-scopes") in discovery_groups[0][
            "hooks"
        ][0]["command"]
        assert "project_workspace" in discovery_groups[0]["hooks"][0]["command"]
        assert str(config_file) not in discovery_groups[0]["hooks"][0]["command"]

        discover_result = subprocess.run(
            [*agent_scan_cmd, "guard", "discover", "--client", "codex"],
            input=json.dumps({"cwd": str(tmp_path), "session_id": "e2e"}),
            capture_output=True,
            text=True,
            timeout=60,
            env={
                **os.environ,
                "PUSH_KEY": "test-pk-e2e",
                "REMOTE_HOOKS_BASE_URL": fake_hook_server,
                "MACHINE_ID": "e2e-machine-id",
            },
        )
        assert discover_result.returncode == 0, (
            f"guard discover failed:\nstdout: {discover_result.stdout}\nstderr: {discover_result.stderr}"
        )
        session_discovery = _FakeHookServer.requests[-1]
        assert session_discovery["body"]["hook_event_name"] == "sessionStartServerDiscovery"
        assert session_discovery["body"]["session_id"] == "e2e"
        assert isinstance(session_discovery["body"]["servers"], list)
        assert isinstance(session_discovery["body"]["discovery_duration_ms"], int)
        assert session_discovery["body"]["discovery_duration_ms"] >= 0
