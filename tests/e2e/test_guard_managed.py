"""E2E tests for the *managed* guard install/uninstall path (``--managed``).

Managed mode writes to real system locations (``/etc``, ``/Library``, ``C:/Program Files``,
``C:/ProgramData``) and therefore needs root / Administrator. These tests are opt-in: they are
skipped unless ``AGENT_SCAN_E2E_MANAGED=1`` is set, which the release CI does (see ``make ci-managed``).
Never enable them on a machine whose managed agent configs you care about.

Only the CLI under test runs elevated (``sudo -n`` on POSIX, an already-elevated session on Windows);
pytest itself stays an ordinary user so the virtualenv is not polluted with root-owned files.
"""

import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_scan.guard import (
    CLAUDE_MANAGED_SETTINGS_PATH,
    CODEX_MANAGED_HOOKS_PATH,
    COPILOT_MANAGED_HOOKS_PATH,
    CURSOR_MANAGED_HOOKS_PATH,
)
from tests.e2e.conftest import _FakeHookServer
from tests.e2e.test_guard_install import (
    _DISCOVER_SCRIPT,
    _FORWARDER_SCRIPT,
    CLIENT_CASES,
    _describe,
    _guard_env,
    _scripts_dir,
)

OPT_IN_ENV = "AGENT_SCAN_E2E_MANAGED"
IS_WINDOWS = sys.platform == "win32"

pytestmark = [
    pytest.mark.managed,
    pytest.mark.skipif(os.environ.get(OPT_IN_ENV) != "1", reason=f"managed e2e tests need {OPT_IN_ENV}=1"),
    # Managed mode is only exercised through the shipped PyInstaller binary.
    pytest.mark.parametrize("agent_scan_cmd", ["binary"], indirect=True),
]

MANAGED_PATHS = {
    "claude": CLAUDE_MANAGED_SETTINGS_PATH,
    "cursor": CURSOR_MANAGED_HOOKS_PATH,
    "codex": CODEX_MANAGED_HOOKS_PATH,
    "github-copilot": COPILOT_MANAGED_HOOKS_PATH,
}
ALL_CLIENTS = list(MANAGED_PATHS)
# Clients whose managed config is JSON with a preservable user hook (Codex managed is TOML, edited in place).
JSON_CASES = [case for case in CLIENT_CASES if case.values[0] != "codex"]

_IS_ROOT = not IS_WINDOWS and os.geteuid() == 0
# Prefix for commands that must run as root; empty on Windows (session must be elevated) or when already root.
_SUDO: list[str] = [] if (IS_WINDOWS or _IS_ROOT) else ["sudo", "-n"]


def _is_elevated() -> bool:
    if IS_WINDOWS:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    if _IS_ROOT:
        return True
    return subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0


def _managed_artifacts(client: str) -> list[Path]:
    config = MANAGED_PATHS[client]
    scripts = _scripts_dir(config)
    return [
        config,
        _guard_backup(config),
        _legacy_backup(config),
        scripts / _FORWARDER_SCRIPT,
        scripts / _DISCOVER_SCRIPT,
    ]


def _guard_backup(config: Path) -> Path:
    return Path(f"{config}.snyk-agent-guard.backup")


def _legacy_backup(config: Path) -> Path:
    # Name used by Guard versions before ADS-1612; only cleaned up here.
    return Path(f"{config}.backup")


def _remove(path: Path) -> None:
    if IS_WINDOWS:
        path.unlink(missing_ok=True)
    else:
        subprocess.run([*_SUDO, "rm", "-f", str(path)], check=True, capture_output=True)


def _remove_dir_if_empty(path: Path) -> None:
    """Remove ``path`` if it is an empty directory; leave it otherwise."""
    if IS_WINDOWS:
        with contextlib.suppress(OSError):
            path.rmdir()
    else:
        subprocess.run([*_SUDO, "rmdir", str(path)], capture_output=True)


def _write_privileged(path: Path, text: str) -> None:
    if IS_WINDOWS:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return
    subprocess.run([*_SUDO, "mkdir", "-p", str(path.parent)], check=True, capture_output=True)
    subprocess.run([*_SUDO, "tee", str(path)], input=text, text=True, check=True, capture_output=True)


@pytest.fixture(autouse=True)
def _managed_sandbox():
    """Require elevation, refuse to clobber a real install locally, and clean up before and after."""
    assert _is_elevated(), (
        "managed e2e tests need root/Administrator "
        "(passwordless `sudo -n` on Linux/macOS, an elevated shell on Windows)"
    )
    existing = [p for client in ALL_CLIENTS for p in _managed_artifacts(client) if p.exists()]
    if existing and not os.environ.get("CI"):
        pytest.skip(f"refusing to overwrite existing managed agent config outside CI: {existing}")
    for client in ALL_CLIENTS:
        for path in _managed_artifacts(client):
            _remove(path)
        _remove_dir_if_empty(_scripts_dir(MANAGED_PATHS[client]))
    yield
    for client in ALL_CLIENTS:
        for path in _managed_artifacts(client):
            _remove(path)
        _remove_dir_if_empty(_scripts_dir(MANAGED_PATHS[client]))


def _run_managed(
    agent_scan_cmd, *args: str, elevated: bool = True, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """Run the CLI, elevated by default. Env is passed through `sudo env` since sudo scrubs the environment."""
    env = {"COLUMNS": "500", **(env or {})}
    prefix = _SUDO if elevated else []
    cmd = [
        *prefix,
        *(["env", *[f"{k}={v}" for k, v in env.items()]] if prefix else []),
        *map(str, agent_scan_cmd),
        *args,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=_guard_env(**env))


def _install(agent_scan_cmd, agent_scan_command, client: str, url: str) -> subprocess.CompletedProcess:
    result = _run_managed(
        agent_scan_cmd,
        "guard",
        "install",
        client,
        "--managed",
        "--url",
        url,
        "--machine-id",
        "e2e-machine-id",
        env={"PUSH_KEY": "test-pk-e2e", "AGENT_SCAN_COMMAND": str(agent_scan_command)},
    )
    assert result.returncode == 0, f"managed guard install failed:\n{_describe(result)}"
    return result


def _uninstall(agent_scan_cmd, client: str, **env: str) -> subprocess.CompletedProcess:
    result = _run_managed(agent_scan_cmd, "guard", "uninstall", client, "--managed", env=env)
    assert result.returncode == 0, f"managed guard uninstall failed:\n{_describe(result)}"
    return result


class TestManagedInstallE2E:
    @pytest.mark.parametrize("client", ALL_CLIENTS)
    def test_install_writes_system_config(self, agent_scan_cmd, agent_scan_command, fake_hook_server, client):
        config = MANAGED_PATHS[client]
        _install(agent_scan_cmd, agent_scan_command, client, fake_hook_server)

        assert config.is_file(), f"managed config was not written to {config}"
        text = config.read_text()
        assert "snyk-agent-guard" in text
        scripts_dir = _scripts_dir(config)
        assert (scripts_dir / _FORWARDER_SCRIPT).is_file()
        assert (scripts_dir / _DISCOVER_SCRIPT).is_file()

        if client == "codex":
            # Managed Codex hooks live in requirements.toml and point at the script directory.
            assert "[hooks]" in text
            assert "managed_dir" in text
            assert "[[hooks.PreToolUse]]" in text
        else:
            # Cursor uses camelCase event names; the other JSON clients use PascalCase.
            pre_tool_event = "preToolUse" if client == "cursor" else "PreToolUse"
            assert pre_tool_event in json.loads(text)["hooks"]

        events = [request["body"]["hook_event_name"] for request in _FakeHookServer.requests]
        assert "hooksConfigured" in events

    @pytest.mark.skipif(IS_WINDOWS, reason="POSIX ownership/permission semantics")
    @pytest.mark.parametrize("client", ALL_CLIENTS)
    def test_install_is_root_owned_and_not_group_or_world_writable(
        self, agent_scan_cmd, agent_scan_command, fake_hook_server, client
    ):
        config = MANAGED_PATHS[client]
        _install(agent_scan_cmd, agent_scan_command, client, fake_hook_server)

        scripts_dir = _scripts_dir(config)
        for path in (config, scripts_dir / _FORWARDER_SCRIPT, scripts_dir / _DISCOVER_SCRIPT):
            st = path.stat()
            assert st.st_uid == 0, f"{path} should be root-owned, got uid {st.st_uid}"
            assert st.st_mode & 0o022 == 0, f"{path} must not be group/world-writable: {oct(st.st_mode)}"

    @pytest.mark.parametrize("client", ALL_CLIENTS)
    def test_install_is_idempotent(self, agent_scan_cmd, agent_scan_command, fake_hook_server, client):
        config = MANAGED_PATHS[client]
        _install(agent_scan_cmd, agent_scan_command, client, fake_hook_server)
        first = config.read_text()
        _install(agent_scan_cmd, agent_scan_command, client, fake_hook_server)
        assert config.read_text() == first

    @pytest.mark.skipif(IS_WINDOWS or _IS_ROOT, reason="needs a non-root POSIX user to prove the elevation requirement")
    def test_install_without_elevation_fails_and_writes_nothing(
        self, agent_scan_cmd, agent_scan_command, fake_hook_server
    ):
        result = _run_managed(
            agent_scan_cmd,
            "guard",
            "install",
            "claude",
            "--managed",
            "--url",
            fake_hook_server,
            "--machine-id",
            "e2e-machine-id",
            elevated=False,
            env={"PUSH_KEY": "test-pk-e2e", "AGENT_SCAN_COMMAND": str(agent_scan_command)},
        )
        assert result.returncode != 0, f"unprivileged managed install unexpectedly succeeded:\n{_describe(result)}"
        assert not MANAGED_PATHS["claude"].exists()
        assert not (_scripts_dir(MANAGED_PATHS["claude"]) / _FORWARDER_SCRIPT).exists()


class TestManagedUninstallE2E:
    @pytest.mark.parametrize("client", ALL_CLIENTS)
    def test_uninstall_removes_hooks_and_scripts(self, agent_scan_cmd, agent_scan_command, fake_hook_server, client):
        config = MANAGED_PATHS[client]
        _install(agent_scan_cmd, agent_scan_command, client, fake_hook_server)

        _uninstall(agent_scan_cmd, client)

        if client == "codex":
            # Managed Codex requirements.toml is the admin's policy file: edited in place, never deleted.
            assert config.is_file()
            assert "snyk-agent-guard" not in config.read_text()
        else:
            # Install created the file and only Guard's scaffolding is left, so uninstall deletes it.
            assert not config.exists()
        scripts_dir = _scripts_dir(config)
        assert not (scripts_dir / _FORWARDER_SCRIPT).exists()
        assert not (scripts_dir / _DISCOVER_SCRIPT).exists()
        # Nothing existed before install, so there is no backup; uninstall never writes one.
        assert not _guard_backup(config).exists()
        assert not _legacy_backup(config).exists()

    @pytest.mark.parametrize("client", ALL_CLIENTS)
    def test_uninstall_removes_hooks_dir_install_created(
        self, agent_scan_cmd, agent_scan_command, fake_hook_server, client
    ):
        # Relies on a clean e2e machine: the hooks dir must not exist before install.
        scripts_dir = _scripts_dir(MANAGED_PATHS[client])
        assert not scripts_dir.exists(), f"{scripts_dir} already exists; run on a clean machine"
        _install(agent_scan_cmd, agent_scan_command, client, fake_hook_server)
        assert scripts_dir.is_dir()

        _uninstall(agent_scan_cmd, client)

        # Removing Guard's scripts left the hooks dir empty, so uninstall removes it.
        assert not scripts_dir.exists()

    @pytest.mark.parametrize(("client", "config_name", "user_hook", "event"), JSON_CASES)
    def test_uninstall_preserves_user_hooks(
        self, agent_scan_cmd, agent_scan_command, fake_hook_server, client, config_name, user_hook, event
    ):
        config = MANAGED_PATHS[client]
        seeded: dict = {"hooks": {event: [user_hook]}}
        if client in {"cursor", "github-copilot"}:
            seeded = {"version": 1, **seeded}
        seeded_text = json.dumps(seeded)
        _write_privileged(config, seeded_text)

        _install(agent_scan_cmd, agent_scan_command, client, fake_hook_server)
        assert "snyk-agent-guard" in config.read_text()
        # Install backed up the seeded admin config under Guard's own backup name.
        assert _guard_backup(config).read_text() == seeded_text

        _uninstall(agent_scan_cmd, client)
        content = config.read_text()
        assert "snyk-agent-guard" not in content
        assert json.loads(content)["hooks"] == {event: [user_hook]}
        # Uninstall removes Guard's backup once the file is Guard-free.
        assert not _guard_backup(config).exists()

    @pytest.mark.parametrize("client", ALL_CLIENTS)
    def test_uninstall_revokes_push_key(self, agent_scan_cmd, agent_scan_command, fake_hook_server, client):
        _install(agent_scan_cmd, agent_scan_command, client, fake_hook_server)

        result = _uninstall(agent_scan_cmd, client, SNYK_TOKEN="e2e-token", TENANT_ID="e2e-tenant")
        assert "not revoked" not in result.stdout
        assert len(_FakeHookServer.deletes) == 1
        assert _FakeHookServer.deletes[0]["path"].startswith("/hidden/tenants/e2e-tenant/mcp-scan/push-key")

    def test_uninstall_when_nothing_installed_is_a_noop(self, agent_scan_cmd):
        result = _uninstall(agent_scan_cmd, "claude")
        assert not MANAGED_PATHS["claude"].exists()
        assert result.returncode == 0
