"""E2E test for guard install — ensures the bundled hook scripts are accessible."""

import hashlib
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_scan import guard, guard_platform
from agent_scan.run import run
from agent_scan.version import version_info
from tests.e2e.conftest import _FakeHookServer

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
        k: v
        for k, v in os.environ.items()
        if k
        not in {
            "SNYK_TOKEN",
            "TENANT_ID",
            "MACHINE_ID",
            "AGENT_SCAN_COMMAND",
            "SNYK_GUARD_INSTALL_SOURCE",
            "SNYK_GUARD_INSTALL_CONFIG",
        }
    }
    return {**env, "COLUMNS": "500", **extra}


def _run_cli(agent_scan_cmd, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([*agent_scan_cmd, *args], capture_output=True, text=True, timeout=60, env=env)


def _describe(result: subprocess.CompletedProcess) -> str:
    return f"stdout: {result.stdout}\nstderr: {result.stderr}"


def _scripts_dir(config_file: Path) -> Path:
    # Mirrors guard._hooks_dir: scripts sit beside a config inside a "hooks" dir, else in ./hooks.
    return config_file.parent if config_file.parent.name == "hooks" else config_file.parent / "hooks"


def _install(
    agent_scan_cmd, agent_scan_command, client: str, config_file: Path, url: str, machine_id: str = "e2e-machine-id"
) -> None:
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
        machine_id,
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


@pytest.mark.parametrize("managed", [False, True], ids=["user", "managed"])
@pytest.mark.parametrize("first_source", ["ads", "manual"])
def test_installed_hooks_report_provenance(fake_hook_server, agent_scan_command, tmp_path, managed, first_source):
    config_file = tmp_path / "installation with spaces" / "settings.json"
    scripts_dir = _scripts_dir(config_file)
    bundled_scripts = Path(__file__).resolve().parents[2] / "src" / "agent_scan" / "hooks"
    mode = "managed" if managed else "user"

    # Reinstall with the other source to verify that the installed observation is refreshed.
    for source in (first_source, "manual" if first_source == "ads" else "ads"):
        _FakeHookServer.requests.clear()
        marker = {"SNYK_GUARD_INSTALL_SOURCE": "ads"} if source == "ads" else {}
        result = _run_cli(
            [sys.executable, "-m", "src.agent_scan.run"],
            "guard",
            "install",
            "claude",
            "--file",
            str(config_file),
            "--url",
            fake_hook_server,
            *(["--managed"] if managed else []),
            env=_guard_env(
                PUSH_KEY="test-pk-e2e",
                MACHINE_ID="e2e-machine-id",
                AGENT_SCAN_COMMAND=str(agent_scan_command),
                **marker,
            ),
        )
        assert result.returncode == 0, _describe(result)

        adjacent_config = scripts_dir / "snyk-agent-guard.conf"
        contents = adjacent_config.read_text()
        assert f"INSTALL_SOURCE={source}\n" in contents
        assert f"INSTALL_MODE={mode}\n" in contents
        if os.name != "nt":
            assert adjacent_config.stat().st_mode & 0o777 == (0o644 if managed else 0o600)
        for script in (_FORWARDER_SCRIPT, _DISCOVER_SCRIPT):
            assert (scripts_dir / script).read_bytes() == (bundled_scripts / script).read_bytes()

        settings = json.loads(config_file.read_text())
        forwarder = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        discovery = next(
            hook["command"]
            for group in settings["hooks"]["SessionStart"]
            for hook in group["hooks"]
            if _DISCOVER_SCRIPT in hook["command"]
        )
        other_source = "manual" if source == "ads" else "ads"
        other_mode = "user" if managed else "managed"
        inherited_config = tmp_path / "inherited.conf"
        inherited_config.write_text(f"INSTALL_SOURCE={other_source}\nINSTALL_MODE={other_mode}\n")
        inherited = _guard_env(
            SNYK_GUARD_INSTALL_SOURCE=other_source,
            SNYK_GUARD_INSTALL_CONFIG=str(inherited_config),
            INSTALL_SOURCE=other_source,
            INSTALL_MODE=other_mode,
            CFG_INSTALL_SOURCE=other_source,
            CFG_INSTALL_MODE=other_mode,
        )
        for command, event in [(forwarder, "PreToolUse"), (discovery, "SessionStart")]:
            argv = ["powershell", "-Command", command] if os.name == "nt" else shlex.split(command)
            response = subprocess.run(
                argv,
                input=json.dumps({"hook_event_name": event, "session_id": "captured-session"}),
                env=inherited,
                capture_output=True,
                text=True,
                timeout=60,
            )
            assert response.returncode == 0, _describe(response)

        assert [request["body"]["hook_event_name"] for request in _FakeHookServer.requests] == [
            "hooksConfigured",
            "hooksConfiguredServerDiscovery",
            "PreToolUse",
            "sessionStartServerDiscovery",
        ]
        for request in _FakeHookServer.requests:
            user = json.loads(request["headers"]["X-User"])
            assert (user["install_source"], user["install_mode"]) == (source, mode)
            assert user["identifier"] == "e2e-machine-id"
            if os.name == "nt":
                assert user["os"] == "Windows"
            if request["body"]["hook_event_name"].endswith("ServerDiscovery"):
                assert user["cli_version"] == version_info
            else:
                # Source checkouts ship the placeholder, which the forwarders report as unknown.
                assert user["cli_version"] == "unknown"


_PLATFORM_FIELDS = ("os", "arch")


def _run_installed_grouped_hooks(config_file, *, powershell=False):
    tmp_path = config_file.parent
    discovery_script = "snyk-agent-guard-discover.ps1" if powershell else "snyk-agent-guard-discover.sh"
    settings = json.loads(config_file.read_text())
    forwarder = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    discovery = next(
        hook["command"]
        for group in settings["hooks"]["SessionStart"]
        for hook in group["hooks"]
        if discovery_script in hook["command"]
    )
    inherited_config = tmp_path / "inherited.conf"
    inherited_config.write_text("OS=incorrect\nOS_VERSION=incorrect\nARCH=incorrect\nKERNEL_RELEASE=incorrect\n")
    for command, event in [(forwarder, "PreToolUse"), (discovery, "SessionStart")]:
        argv = ["powershell", "-NoProfile", "-Command", command] if powershell else shlex.split(command)
        response = subprocess.run(
            argv,
            input=json.dumps({"hook_event_name": event, "session_id": "captured-session"}),
            env=_guard_env(
                SNYK_GUARD_INSTALL_CONFIG=str(inherited_config),
                OS="incorrect",
                OS_VERSION="incorrect",
                ARCH="incorrect",
                KERNEL_RELEASE="incorrect",
                CFG_OS="incorrect",
                CFG_OS_VERSION="incorrect",
                CFG_ARCH="incorrect",
                CFG_KERNEL_RELEASE="incorrect",
            ),
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert response.returncode == 0, _describe(response)


@pytest.mark.skipif(sys.platform not in ("linux", "darwin"), reason="Linux and macOS snapshot")
def test_installed_hooks_report_platform(fake_hook_server, agent_scan_command, tmp_path):
    config_file = tmp_path / "settings.json"
    _install([sys.executable, "-m", "src.agent_scan.run"], agent_scan_command, "claude", config_file, fake_hook_server)
    bundled_scripts = Path(__file__).resolve().parents[2] / "src" / "agent_scan" / "hooks"
    scripts_dir = _scripts_dir(config_file)
    for script in (_FORWARDER_SCRIPT, _DISCOVER_SCRIPT):
        assert (scripts_dir / script).read_bytes() == (bundled_scripts / script).read_bytes()

    _run_installed_grouped_hooks(config_file)

    assert [request["body"]["hook_event_name"] for request in _FakeHookServer.requests] == [
        "hooksConfigured",
        "hooksConfiguredServerDiscovery",
        "PreToolUse",
        "sessionStartServerDiscovery",
    ]
    first_user = json.loads(_FakeHookServer.requests[0]["headers"]["X-User"])
    expected = {field: first_user[field] for field in _PLATFORM_FIELDS}
    assert expected["os"] == {"linux": "Linux", "darwin": "Darwin"}[sys.platform]
    assert expected["arch"] in {"x64", "arm64"}
    for request in _FakeHookServer.requests:
        user = json.loads(request["headers"]["X-User"])
        assert {field: user[field] for field in expected} == expected
        assert "os_version" not in user and "kernel_release" not in user


_PLATFORM_EVENTS = (
    "hooksConfigured",
    "hooksConfiguredServerDiscovery",
    "PreToolUse",
    "sessionStartServerDiscovery",
)


def _assert_windows_http(platform, events=_PLATFORM_EVENTS, *, script_version="unknown"):
    assert tuple(request["body"]["hook_event_name"] for request in _FakeHookServer.requests) == events
    for request in _FakeHookServer.requests:
        event = request["body"]["hook_event_name"]
        user = json.loads(request["headers"]["X-User"])
        assert {field: user[field] for field in _PLATFORM_FIELDS if field in user} == platform
        assert user["identifier"] == "e2e-machine-id"
        assert user["cli_version"] == (version_info if event.endswith("ServerDiscovery") else script_version)
    _FakeHookServer.requests.clear()


def _windows_executable_arch(executable):
    # The COFF Machine field identifies the executable, independent of the host
    # architecture or how Python's sysconfig describes its own build.
    with Path(executable).open("rb") as binary:
        binary.seek(0x3C)
        pe_offset = struct.unpack("<I", binary.read(4))[0]
        binary.seek(pe_offset)
        assert binary.read(4) == b"PE\0\0"
        machine = struct.unpack("<H", binary.read(2))[0]
    return {0x014C: "386", 0x01C4: "arm", 0x8664: "x64", 0xAA64: "arm64"}[machine]


@pytest.mark.skipif(sys.platform != "win32", reason="Requires native Windows and Windows PowerShell 5.1")
@pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
def test_native_windows_install_reports_platform(
    fake_hook_server, agent_scan_cmd, agent_scan_command, tmp_path, monkeypatch
):
    ps_version = subprocess.check_output(
        ["powershell", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"], text=True, timeout=15
    )
    assert ps_version.strip().startswith("5.1.")
    binary = agent_scan_cmd[0] if len(agent_scan_cmd) == 1 else sys.executable
    expected = {"os": "Windows", "arch": _windows_executable_arch(binary)}

    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    config_file = tmp_path / "installation with spaces" / "settings.json"
    _install(agent_scan_cmd, agent_scan_command, "claude", config_file, fake_hook_server)
    bundled_scripts = Path(__file__).resolve().parents[2] / "src" / "agent_scan" / "hooks"
    scripts_dir = _scripts_dir(config_file)
    checksums = _FakeHookServer.requests[0]["body"]["hooks_script"]
    for script, checksum in ((_FORWARDER_SCRIPT, "new_checksum"), (_DISCOVER_SCRIPT, "discover_new_checksum")):
        installed_bytes = (scripts_dir / script).read_bytes()
        assert installed_bytes == (bundled_scripts / script).read_bytes()
        assert checksums[checksum] == hashlib.sha256(installed_bytes).hexdigest()
    _run_installed_grouped_hooks(config_file, powershell=True)
    _assert_windows_http(expected)


def test_installed_powershell_hooks_use_the_windows_install_snapshot(
    fake_hook_server, agent_scan_command, tmp_path, monkeypatch
):
    if os.name != "nt":
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            pytest.skip("PowerShell is unavailable")
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "powershell").symlink_to(pwsh)
        monkeypatch.setenv("PATH", str(bin_dir), prepend=os.pathsep)
        monkeypatch.setattr(guard, "IS_WINDOWS", True)
    monkeypatch.setenv("USERPROFILE" if os.name == "nt" else "HOME", str(tmp_path))

    # An x64 process running on an ARM64 Windows machine.
    monkeypatch.setattr(guard_platform, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(guard_platform, "sysconfig", SimpleNamespace(get_platform=lambda: "win-amd64"))
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "ARM64")
    monkeypatch.setenv("PROCESSOR_ARCHITEW6432", "ARM64")
    # Model the released artifact one version ahead of the running discovery CLI.
    script_version = "9.9.9-test"
    bundled_scripts = guard.importlib_resources.files("agent_scan.hooks")
    stamped_bundle = tmp_path / "release"
    stamped_bundle.mkdir()
    bundled_script = stamped_bundle / "snyk-agent-guard.ps1"
    original = bundled_scripts.joinpath(bundled_script.name).read_bytes()
    stamped = original.replace(
        b'$AGENT_SCAN_VERSION = "__AGENT_SCAN_VERSION__"', f'$AGENT_SCAN_VERSION = "{script_version}"'.encode(), 1
    )
    assert stamped != original
    bundled_script.write_bytes(stamped)
    trampoline = "snyk-agent-guard-discover.ps1"
    (stamped_bundle / trampoline).write_bytes(bundled_scripts.joinpath(trampoline).read_bytes())
    monkeypatch.setattr(guard, "importlib_resources", SimpleNamespace(files=lambda _: stamped_bundle))

    config_file = tmp_path / "installation with spaces" / "settings.json"
    monkeypatch.setattr(
        sys, "argv", ["agent-scan", "guard", "install", "claude", "--file", str(config_file), "--url", fake_hook_server]
    )
    monkeypatch.setenv("PUSH_KEY", "test-pk-e2e")
    monkeypatch.setenv("MACHINE_ID", "e2e-machine-id")
    monkeypatch.setenv("AGENT_SCAN_COMMAND", str(agent_scan_command))
    for key in ("SNYK_TOKEN", "TENANT_ID", "SNYK_GUARD_INSTALL_CONFIG", "SNYK_GUARD_INSTALL_SOURCE"):
        monkeypatch.delenv(key, raising=False)

    def install():
        with pytest.raises(SystemExit) as result:
            run()
        assert result.value.code == 0
        assert (_scripts_dir(config_file) / bundled_script.name).read_bytes() == stamped

    initial = {"os": "Windows", "arch": "x64"}
    install()
    _assert_windows_http(initial, _PLATFORM_EVENTS[:2], script_version=script_version)

    monkeypatch.setattr(guard_platform, "sysconfig", SimpleNamespace(get_platform=lambda: "win-arm64"))
    _run_installed_grouped_hooks(config_file, powershell=True)
    _assert_windows_http(initial, _PLATFORM_EVENTS[2:], script_version=script_version)

    install()
    _run_installed_grouped_hooks(config_file, powershell=True)
    _assert_windows_http({**initial, "arch": "arm64"}, script_version=script_version)

    # A failed probe must replace stale observations and leave both senders usable.
    monkeypatch.setattr(guard_platform, "sysconfig", SimpleNamespace(get_platform=lambda: "win-unrecognized"))
    install()
    _run_installed_grouped_hooks(config_file, powershell=True)
    _assert_windows_http({"os": "Windows"}, script_version=script_version)


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
        seeded_text = json.dumps(seeded)
        config_file.write_text(seeded_text)

        _install(agent_scan_cmd, agent_scan_command, client, config_file, fake_hook_server)
        assert "snyk-agent-guard" in config_file.read_text()
        # Install backed up the seeded user config under Guard's own backup name.
        assert Path(f"{config_file}.snyk-agent-guard.backup").read_text() == seeded_text

        result = _uninstall(agent_scan_cmd, client, config_file)
        content = config_file.read_text()
        assert "snyk-agent-guard" not in content
        assert json.loads(content)["hooks"] == {event: [user_hook]}
        _assert_scripts_removed(config_file)
        # Uninstall removes Guard's backup once the file is Guard-free.
        assert not Path(f"{config_file}.snyk-agent-guard.backup").exists()
        assert "was not revoked" in result.stdout
        assert _FakeHookServer.deletes == []

        # A second uninstall is a no-op that leaves the file untouched.
        again = _uninstall(agent_scan_cmd, client, config_file)
        assert "No Agent Guard hooks found" in again.stdout
        assert config_file.read_text() == content

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(("client", "config_name", "user_hook", "event"), CLIENT_CASES)
    def test_reinstall_with_new_machine_id_backs_up_user_config(
        self, agent_scan_cmd, agent_scan_command, tmp_path, fake_hook_server, client, config_name, user_hook, event
    ):
        config_file = tmp_path / config_name
        config_file.parent.mkdir(parents=True, exist_ok=True)
        seeded: dict = {"hooks": {event: [user_hook]}}
        if client in {"cursor", "github-copilot"}:
            seeded = {"version": 1, **seeded}
        config_file.write_text(json.dumps(seeded))

        _install(agent_scan_cmd, agent_scan_command, client, config_file, fake_hook_server, "machine-1")
        # The re-install rewrites Guard's previous config; the backup is that config minus Guard.
        _install(agent_scan_cmd, agent_scan_command, client, config_file, fake_hook_server, "machine-2")
        # The machine ID lives in the guard configuration file, not on the hook command.
        assert "MACHINE_ID=machine-2\n" in (_scripts_dir(config_file) / "snyk-agent-guard.conf").read_text()
        backup = Path(f"{config_file}.snyk-agent-guard.backup")
        assert json.loads(backup.read_text()) == seeded

        _uninstall(agent_scan_cmd, client, config_file)
        assert json.loads(config_file.read_text()) == seeded
        assert not backup.exists()

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(("client", "config_name", "user_hook", "event"), CLIENT_CASES)
    def test_uninstall_clean_config(
        self, agent_scan_cmd, agent_scan_command, tmp_path, fake_hook_server, client, config_name, user_hook, event
    ):
        config_file = tmp_path / config_name
        _install(agent_scan_cmd, agent_scan_command, client, config_file, fake_hook_server)

        _uninstall(agent_scan_cmd, client, config_file)
        _assert_scripts_removed(config_file)
        # Install created the file and the hooks dir (Copilot's config lives inside it);
        # nothing else was in them, so both are gone.
        assert list(tmp_path.iterdir()) == []

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
