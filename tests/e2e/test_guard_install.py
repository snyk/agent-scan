"""E2E test for guard install — ensures the bundled hook scripts are accessible."""

import base64
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

import pytest


class _FakeHookServer(BaseHTTPRequestHandler):
    """Accepts any POST and returns 200 — enough for the test-event handshake."""

    requests: ClassVar[list[dict]] = []
    deletes: ClassVar[list[dict]] = []

    def do_DELETE(self):
        _FakeHookServer.deletes.append({"method": "DELETE", "path": self.path, "headers": dict(self.headers)})
        self.send_response(204)
        self.end_headers()

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
        self.wfile.write(b'{"success":true}')

    def log_message(self, format, *args):
        pass


@pytest.fixture()
def fake_hook_server():
    server = HTTPServer(("127.0.0.1", 0), _FakeHookServer)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    _FakeHookServer.requests = []
    _FakeHookServer.deletes = []
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


_FORWARDER_SCRIPT = "snyk-agent-guard.ps1" if os.name == "nt" else "snyk-agent-guard.sh"
_DISCOVER_SCRIPT = "snyk-agent-guard-discover.ps1" if os.name == "nt" else "snyk-agent-guard-discover.sh"
_GROUPED_USER_HOOK = {"matcher": "", "hooks": [{"type": "command", "command": "echo user-hook"}]}

# (client, config path relative to tmp_path, user-owned hook to preserve, event it lives under)
CLIENT_CASES = [
    pytest.param("claude", "settings.json", _GROUPED_USER_HOOK, "PreToolUse", id="claude"),
    pytest.param("cursor", "hooks.json", {"command": "echo user-hook"}, "preToolUse", id="cursor"),
    pytest.param("codex", "hooks.json", _GROUPED_USER_HOOK, "PreToolUse", id="codex"),
    pytest.param(
        "github-copilot",
        "hooks/snyk-agent-guard.json",
        {"type": "command", "bash": "echo user-hook"},
        "PreToolUse",
        id="github-copilot",
    ),
]


def _guard_env(**extra: str) -> dict[str, str]:
    """Environment isolated from the developer's own Snyk/guard settings.

    COLUMNS keeps rich from wrapping output lines that the tests match against.
    """
    env = {
        k: v for k, v in os.environ.items() if k not in {"SNYK_TOKEN", "TENANT_ID", "MACHINE_ID", "AGENT_SCAN_COMMAND"}
    }
    return {**env, "COLUMNS": "500", **extra}


def _run_cli(agent_scan_cmd, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([*agent_scan_cmd, *args], capture_output=True, text=True, timeout=60, env=env)


def _describe(result: subprocess.CompletedProcess) -> str:
    return f"stdout: {result.stdout}\nstderr: {result.stderr}"


def _scripts_dir(config_file: Path) -> Path:
    # Mirrors guard._hooks_dir: scripts sit beside a config inside a "hooks" dir, else in ./hooks.
    return config_file.parent if config_file.parent.name == "hooks" else config_file.parent / "hooks"


def _install(agent_scan_cmd, agent_scan_command, client: str, config_file: Path, url: str) -> None:
    result = _run_cli(
        agent_scan_cmd,
        "guard",
        "install",
        client,
        "--file",
        str(config_file),
        "--url",
        url,
        "--machine-id",
        "e2e-machine-id",
        env=_guard_env(PUSH_KEY="test-pk-e2e", AGENT_SCAN_COMMAND=str(agent_scan_command)),
    )
    assert result.returncode == 0, f"guard install failed:\n{_describe(result)}"
    scripts_dir = _scripts_dir(config_file)
    assert (scripts_dir / _FORWARDER_SCRIPT).is_file()
    assert (scripts_dir / _DISCOVER_SCRIPT).is_file()


def _uninstall(agent_scan_cmd, client: str, config_file: Path, **env: str) -> subprocess.CompletedProcess:
    result = _run_cli(agent_scan_cmd, "guard", "uninstall", client, "--file", str(config_file), env=_guard_env(**env))
    assert result.returncode == 0, f"guard uninstall failed:\n{_describe(result)}"
    return result


def _assert_scripts_removed(config_file: Path) -> None:
    scripts_dir = _scripts_dir(config_file)
    assert not (scripts_dir / _FORWARDER_SCRIPT).exists()
    assert not (scripts_dir / _DISCOVER_SCRIPT).exists()


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
        assert _DISCOVER_SCRIPT in discover_command
        assert str(config_file) not in discover_command
        assert ("-ConfigFile" if os.name == "nt" else "--file") not in discover_command

        # The per-install values live in the guard configuration file next to the scripts,
        # not in the hook commands.
        guard_config = (tmp_path / "hooks" / "snyk-agent-guard.conf").read_text()
        assert "PUSH_KEY=test-pk-e2e\n" in guard_config
        assert f"REMOTE_HOOKS_BASE_URL={fake_hook_server}\n" in guard_config
        hook_commands = [h["command"] for groups in settings["hooks"].values() for g in groups for h in g["hooks"]]
        assert hook_commands
        assert all("test-pk-e2e" not in c and fake_hook_server not in c for c in hook_commands)

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
        _install(agent_scan_cmd, agent_scan_command, "cursor", config_file, fake_hook_server)

        data = json.loads(config_file.read_text())
        assert "hooks" in data
        assert "preToolUse" in data["hooks"]
        assert "stop" in data["hooks"]

        discovery_entries = [
            entry for entry in data["hooks"]["sessionStart"] if _DISCOVER_SCRIPT in entry.get("command", "")
        ]
        assert len(discovery_entries) == 1
        assert set(discovery_entries[0]) == {"command"}
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
        _install(agent_scan_cmd, agent_scan_command, "codex", config_file, fake_hook_server)

        data = json.loads(config_file.read_text())
        assert "PreToolUse" in data["hooks"]
        assert "Stop" in data["hooks"]
        assert "SubagentStart" in data["hooks"]

        discovery_groups = [
            group
            for group in data["hooks"]["SessionStart"]
            if _DISCOVER_SCRIPT in group.get("hooks", [{}])[0].get("command", "")
        ]
        assert len(discovery_groups) == 1
        assert "matcher" not in discovery_groups[0]
        assert discovery_groups[0]["hooks"][0]["async"] is True
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

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_guard_install_github_copilot(self, agent_scan_cmd, agent_scan_command, tmp_path, fake_hook_server):
        # Mirror the real ~/.copilot/hooks/snyk-agent-guard.json layout: scripts land
        # next to the config because its parent directory is named "hooks".
        config_file = tmp_path / "hooks" / "snyk-agent-guard.json"
        _install(agent_scan_cmd, agent_scan_command, "github-copilot", config_file, fake_hook_server)

        data = json.loads(config_file.read_text())
        assert data["version"] == 1
        assert "PreToolUse" in data["hooks"]
        assert "Stop" in data["hooks"]
        assert "SubagentStart" in data["hooks"]

        script_key = "powershell" if os.name == "nt" else "bash"
        assert all(entry.get("type") == "command" for entry in data["hooks"]["SessionStart"])
        discovery_entries = [
            entry for entry in data["hooks"]["SessionStart"] if _DISCOVER_SCRIPT in entry.get(script_key, "")
        ]
        assert len(discovery_entries) == 1
        assert set(discovery_entries[0]) == {"type", script_key}
        assert str(config_file) not in discovery_entries[0][script_key]

        discover_result = subprocess.run(
            [*agent_scan_cmd, "guard", "discover", "--client", "github-copilot"],
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


class TestGuardUninstallE2E:
    """Guard uninstall must remove only Agent Guard's hooks and scripts, via uv and the binary."""

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(("client", "config_name", "user_hook", "event"), CLIENT_CASES)
    def test_uninstall_preserves_user_hooks(
        self, agent_scan_cmd, agent_scan_command, tmp_path, fake_hook_server, client, config_name, user_hook, event
    ):
        config_file = tmp_path / config_name
        config_file.parent.mkdir(parents=True, exist_ok=True)
        seeded: dict = {"hooks": {event: [user_hook]}}
        if client in {"cursor", "github-copilot"}:
            seeded = {"version": 1, **seeded}
        config_file.write_text(json.dumps(seeded))

        _install(agent_scan_cmd, agent_scan_command, client, config_file, fake_hook_server)
        assert "snyk-agent-guard" in config_file.read_text()

        result = _uninstall(agent_scan_cmd, client, config_file)
        content = config_file.read_text()
        assert "snyk-agent-guard" not in content
        assert json.loads(content)["hooks"] == {event: [user_hook]}
        _assert_scripts_removed(config_file)
        assert Path(f"{config_file}.backup").is_file()
        assert "was not revoked" in result.stdout
        assert _FakeHookServer.deletes == []

        # A second uninstall is a no-op that leaves the file untouched.
        again = _uninstall(agent_scan_cmd, client, config_file)
        assert "No Agent Guard hooks found" in again.stdout
        assert config_file.read_text() == content

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(("client", "config_name", "user_hook", "event"), CLIENT_CASES)
    def test_uninstall_clean_config(
        self, agent_scan_cmd, agent_scan_command, tmp_path, fake_hook_server, client, config_name, user_hook, event
    ):
        config_file = tmp_path / config_name
        _install(agent_scan_cmd, agent_scan_command, client, config_file, fake_hook_server)

        _uninstall(agent_scan_cmd, client, config_file)
        data = json.loads(config_file.read_text())
        if client == "cursor":
            # Cursor keeps an empty hooks object; the other clients drop the key entirely.
            assert data["hooks"] == {}
        else:
            assert "hooks" not in data
        _assert_scripts_removed(config_file)

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(("client", "config_name", "user_hook", "event"), CLIENT_CASES)
    def test_uninstall_revokes_push_key(
        self, agent_scan_cmd, agent_scan_command, tmp_path, fake_hook_server, client, config_name, user_hook, event
    ):
        config_file = tmp_path / config_name
        _install(agent_scan_cmd, agent_scan_command, client, config_file, fake_hook_server)

        result = _uninstall(agent_scan_cmd, client, config_file, SNYK_TOKEN="e2e-token", TENANT_ID="e2e-tenant")
        assert "revoked" in result.stdout
        assert "not revoked" not in result.stdout
        assert len(_FakeHookServer.deletes) == 1
        delete = _FakeHookServer.deletes[0]
        assert delete["path"].startswith("/hidden/tenants/e2e-tenant/mcp-scan/push-key")
        headers = {k.lower(): v for k, v in delete["headers"].items()}
        assert headers["x-client-id"] == "test-pk-e2e"
        # Localhost targets never receive the Snyk token.
        assert "authorization" not in headers

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_uninstall_all_rejects_file(self, agent_scan_cmd, tmp_path):
        result = _run_cli(
            agent_scan_cmd, "guard", "uninstall", "all", "--file", str(tmp_path / "x.json"), env=_guard_env()
        )
        assert result.returncode != 0
        assert "--file cannot be used with client 'all'" in result.stdout + result.stderr
