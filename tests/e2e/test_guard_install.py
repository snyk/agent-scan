"""E2E test for guard install — ensures the bundled hook scripts are accessible."""

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest


class _FakeHookServer(BaseHTTPRequestHandler):
    """Accepts any POST and returns 200 — enough for the test-event handshake."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
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
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "PUSH_KEY": "test-pk-e2e"},
        )
        assert result.returncode == 0, f"guard install failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        # The config file should exist and contain valid JSON with hooks
        settings = json.loads(config_file.read_text())
        assert "hooks" in settings
        # Should have entries for standard Claude hook events
        assert "PreToolUse" in settings["hooks"]
        assert "Stop" in settings["hooks"]

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
            timeout=30,
            env={**os.environ, "PUSH_KEY": "test-pk-e2e"},
        )
        assert result.returncode == 0, f"guard install failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"

        data = json.loads(config_file.read_text())
        assert "hooks" in data
        assert "preToolUse" in data["hooks"]
        assert "stop" in data["hooks"]
