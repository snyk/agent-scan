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
                "--machine-id",
                "e2e-machine-id",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "PUSH_KEY": "test-pk-e2e"},
        )
        assert result.returncode == 0, f"guard install failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        # The config file should exist and contain valid JSON with hooks
        settings = json.loads(config_file.read_text())
        assert "hooks" in settings
        # Should have entries for standard Claude hook events
        assert "PreToolUse" in settings["hooks"]
        assert "Stop" in settings["hooks"]
        if os.name != "nt":
            discovery_groups = [
                group for group in settings["hooks"]["SessionStart"] if group.get("hooks", [{}])[0].get("async") is True
            ]
            assert len(discovery_groups) == 1
            assert "matcher" not in discovery_groups[0]
            assert "snyk-agent-guard-discover.sh" in discovery_groups[0]["hooks"][0]["command"]
        assert [request["body"]["hook_event_name"] for request in _FakeHookServer.requests] == [
            "hooksConfigured",
            "serversDiscovered",
        ]
        discovered = _FakeHookServer.requests[1]
        assert discovered["body"]["session_id"] == "hooks-setup"
        assert isinstance(discovered["body"]["servers"], list)
        assert json.loads(discovered["headers"]["X-User"])["identifier"] == "e2e-machine-id"

        if os.name != "nt":
            discover_result = subprocess.run(
                [*agent_scan_cmd, "guard", "discover", "--file", str(config_file)],
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
            assert session_discovery["body"]["hook_event_name"] == "SessionStartServerDiscovery"
            assert session_discovery["body"]["session_id"] == "session-start-server-discovery"
            assert isinstance(session_discovery["body"]["servers"], list)

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_guard_install_cursor(self, agent_scan_cmd, tmp_path, fake_hook_server):
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
            ],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, "PUSH_KEY": "test-pk-e2e"},
        )
        assert result.returncode == 0, f"guard install failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        data = json.loads(config_file.read_text())
        assert "hooks" in data
        assert "preToolUse" in data["hooks"]
        assert "stop" in data["hooks"]
