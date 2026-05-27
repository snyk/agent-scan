import io
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from agent_scan import utils as utils_module
from agent_scan.models import CommandParsingError, rebalance_command_args
from agent_scan.utils import (
    _probe_tool_version,
    calculate_distance,
    get_readable_home_directories,
    get_relative_path,
    get_tool_versions,
    suppress_stdout,
)


class TestGetRelativePath:
    def test_path_in_home_directory(self):
        home = os.path.expanduser("~")
        path = os.path.join(home, ".cursor", "mcp.json")
        result = get_relative_path(path)
        assert result == "~/.cursor/mcp.json"

    def test_path_with_tilde(self):
        result = get_relative_path("~/.cursor/mcp.json")
        assert result == "~/.cursor/mcp.json"

    def test_path_outside_home(self):
        result = get_relative_path("/etc/config.json")
        assert result == "/etc/config.json"

    def test_empty_path(self):
        result = get_relative_path("")
        assert result == ""


@pytest.mark.parametrize(
    "input_command, input_args, expected_command, expected_args, raises_error",
    [
        ("ls -l", ["-a"], "ls", ["-l", "-a"], False),
        ("ls -l", [], "ls", ["-l"], False),
        ("ls -lt", ["-r", "-a"], "ls", ["-lt", "-r", "-a"], False),
        ("ls   -l    ", [], "ls", ["-l"], False),
        ("ls   -l    .local", [], "ls", ["-l", ".local"], False),
        ("ls   -l    example.local", [], "ls", ["-l", "example.local"], False),
        ('ls "hello"', [], "ls", ['"hello"'], False),
        ("ls -l \"my file.txt\" 'data.csv'", [], "ls", ["-l", '"my file.txt"', "'data.csv'"], False),
        ('ls "unterminated', [], "", [], True),
    ],
)
def test_rebalance_command_args(
    input_command: str, input_args: list[str], expected_command: str, expected_args: list[str], raises_error: bool
):
    try:
        command, args = rebalance_command_args(input_command, input_args)
        assert command == expected_command
        assert args == expected_args
        assert not raises_error
    except CommandParsingError:
        assert raises_error


class TestRebalanceCommandArgsWithSpacesInPath:
    """Test that paths containing spaces (e.g. macOS Application Support) are not split."""

    def test_full_command_is_path_with_spaces(self, tmp_path):
        spaced_dir = tmp_path / "Application Support" / "bin"
        spaced_dir.mkdir(parents=True)
        executable = spaced_dir / "my-tool"
        executable.touch()

        command, args = rebalance_command_args(str(executable), ["--flag"])
        assert command == str(executable)
        assert args == ["--flag"]

    def test_full_command_is_path_with_spaces_no_args(self, tmp_path):
        spaced_dir = tmp_path / "Library" / "Application Support" / "tool"
        spaced_dir.mkdir(parents=True)
        executable = spaced_dir / "server"
        executable.touch()

        command, args = rebalance_command_args(str(executable), None)
        assert command == str(executable)
        assert args is None


def test_calculate_distance():
    assert calculate_distance(["a", "b", "c"], "b")[0] == ("b", 0)


class TestSuppressStdout:
    """Test suite for suppress_stdout context manager."""

    def test_suppress_stdout_suppresses_print(self):
        """Test that suppress_stdout suppresses print statements."""
        # Capture what would be printed to stdout
        captured_output = io.StringIO()
        original_stdout = sys.stdout

        try:
            sys.stdout = captured_output
            with suppress_stdout():
                print("This should be suppressed")
                print("This too")
            # After context, stdout should be restored
            print("This should appear")
        finally:
            sys.stdout = original_stdout

        # Only the print after the context should appear
        assert captured_output.getvalue() == "This should appear\n"

    def test_suppress_stdout_restores_stdout_after_context(self):
        """Test that stdout is properly restored after suppress_stdout context."""
        original_stdout = sys.stdout
        captured_output = io.StringIO()

        try:
            sys.stdout = captured_output
            with suppress_stdout():
                pass
            # After context, stdout should be the same as before
            assert sys.stdout is captured_output
            print("Restored stdout works")
        finally:
            sys.stdout = original_stdout

        assert captured_output.getvalue() == "Restored stdout works\n"

    def test_suppress_stdout_works_with_multiple_prints(self):
        """Test that suppress_stdout works with multiple print statements."""
        captured_output = io.StringIO()
        original_stdout = sys.stdout

        try:
            sys.stdout = captured_output
            with suppress_stdout():
                for i in range(10):
                    print(f"Line {i}")
            print("Final line")
        finally:
            sys.stdout = original_stdout

        # Only the final print should appear
        assert captured_output.getvalue() == "Final line\n"


class TestProbeToolVersion:
    """`_probe_tool_version` runs `<cmd> --version` and must never raise.

    Bootstrap folds its result straight into telemetry; an exception here
    would break the whole payload build. These tests pin each failure
    mode to None explicitly, so future refactors that swap one exception
    type for another can't accidentally turn "tool missing" into a crash.
    """

    def test_returns_first_stdout_line_on_success(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout="v20.10.0\nextra debug line\n",
                stderr="",
            )

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        assert _probe_tool_version("node") == "v20.10.0"

    def test_falls_back_to_stderr_when_stdout_empty(self, monkeypatch):
        # Older npm versions and some Java tools print --version to stderr.
        # We don't want to specialize per tool, so stderr is the documented
        # fallback when stdout is empty but the exit code is clean.
        def fake_run(cmd, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout="",
                stderr="6.14.18\n",
            )

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        assert _probe_tool_version("npm") == "6.14.18"

    def test_missing_binary_returns_none(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            raise FileNotFoundError(cmd)

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        assert _probe_tool_version("definitely-not-installed") is None

    def test_timeout_returns_none(self, monkeypatch):
        # A hung `docker --version` (Docker Desktop spinning up on macOS)
        # must not stall the bootstrap — the timeout converts to None.
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, timeout=2.0)

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        assert _probe_tool_version("docker") is None

    def test_nonzero_exit_returns_none(self, monkeypatch):
        # A binary that exists but exits non-zero is treated as unprobeable
        # rather than returning a garbage version string.
        def fake_run(cmd, **kwargs):
            return SimpleNamespace(returncode=2, stdout="usage: ...", stderr="")

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        assert _probe_tool_version("broken") is None

    def test_permission_error_returns_none(self, monkeypatch):
        def fake_run(cmd, **kwargs):
            raise PermissionError("nope")

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        assert _probe_tool_version("locked-down") is None


@pytest.mark.asyncio
async def test_get_tool_versions_returns_one_entry_per_tool(monkeypatch):
    # `get_tool_versions` must always return a key for every requested
    # tool, even when probing fails. The dict shape — keys for asked-about
    # tools, None for unprobeable ones — is the contract the bootstrap
    # payload depends on to distinguish "not installed" from "not asked."
    fake_results = {"node": "v20.10.0", "docker": None}

    def fake_probe(command):
        return fake_results[command]

    monkeypatch.setattr(utils_module, "_probe_tool_version", fake_probe)

    result = await get_tool_versions(("node", "docker"))

    assert result == {"node": "v20.10.0", "docker": None}


@pytest.mark.asyncio
async def test_get_tool_versions_runs_probes_concurrently(monkeypatch):
    # Probes are I/O-bound (subprocess + waitpid) and independent, so they
    # must run in parallel via asyncio.to_thread. If a future refactor
    # accidentally serializes them, total wall time would be sum(per-probe),
    # which violates the 2s-per-bootstrap budget on hosts with 4+ probed
    # tools. We assert parallelism by ensuring all probes have started
    # before any has finished — a serial implementation can't satisfy this.
    import asyncio
    import threading

    started = threading.Event()
    pending = [threading.Event() for _ in range(3)]
    release = threading.Event()

    counter = {"started": 0}
    lock = threading.Lock()

    def slow_probe(command):
        with lock:
            counter["started"] += 1
            idx = counter["started"] - 1
        pending[idx].set()
        if counter["started"] == 3:
            started.set()
        release.wait(timeout=2)
        return f"{command}-ok"

    monkeypatch.setattr(utils_module, "_probe_tool_version", slow_probe)

    async def driver():
        task = asyncio.create_task(get_tool_versions(("a", "b", "c")))
        # Wait until all three probes have entered slow_probe before
        # releasing them. If probes ran serially, only one would be
        # in-flight at a time and `started` would never set.
        await asyncio.to_thread(started.wait, 2)
        release.set()
        return await task

    result = await driver()
    assert set(result) == {"a", "b", "c"}
    assert started.is_set(), "probes did not run concurrently"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only behavior")
class TestGetReadableHomeDirectoriesWindowsTimeout:
    """`Get-CimInstance Win32_UserProfile` can hang indefinitely when WMI is
    stuck (corrupted repository, unresponsive WinMgmt service, slow domain
    controller). Without a timeout, both scan discovery and bootstrap payload
    build block before any network timeout could fire — and bootstrap is
    documented as best-effort, so a hung profile query would defeat that.

    These tests pin the timeout contract: the function returns rather than
    raising, WSL enumeration still proceeds (so a hung CIM query doesn't
    erase the WSL half of the result), and the failure is logged.
    """

    def test_windows_profile_query_timeout_does_not_hang(self, monkeypatch, caplog):
        from pathlib import Path

        def fake_run(cmd, **kwargs):
            assert "timeout" in kwargs, "PowerShell CIM call must be invoked with a timeout to prevent indefinite hang"
            raise subprocess.TimeoutExpired(cmd, timeout=kwargs["timeout"])

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        monkeypatch.setattr(
            utils_module,
            "get_wsl_home_directories",
            lambda: [(Path(r"\\wsl.localhost\Ubuntu\home\alice"), "alice")],
        )

        import logging

        with caplog.at_level(logging.WARNING, logger="agent_scan.utils"):
            result = get_readable_home_directories(all_users=True)

        # WSL enumeration still runs even when CIM times out — the two
        # signal sources are independent, so a stuck WMI must not erase
        # the WSL half.
        assert any("wsl.localhost" in str(p).lower() for p, _ in result), (
            f"expected WSL home preserved when CIM times out; got {result}"
        )
        # Operator-facing warning surfaces the hang in logs so misconfigured
        # WMI is debuggable.
        assert "timed out" in caplog.text.lower(), f"expected timeout warning in logs; got {caplog.text!r}"

    def test_windows_profile_query_called_with_timeout_kwarg(self, monkeypatch):
        """Pin the timeout kwarg on the actual subprocess.run call — guards
        against a refactor that drops the kwarg while keeping the except
        TimeoutExpired branch (which would silently never fire)."""

        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        monkeypatch.setattr(utils_module, "get_wsl_home_directories", lambda: [])

        get_readable_home_directories(all_users=True)

        assert "timeout" in captured, (
            f"subprocess.run for Win32_UserProfile must be invoked with a timeout; got kwargs={captured}"
        )
        assert isinstance(captured["timeout"], int | float)
        assert captured["timeout"] > 0


@pytest.mark.skipif(sys.platform == "win32", reason="pwd module is POSIX-only")
class TestGetReadableHomeDirectoriesPosix:
    """Cover the Linux/Darwin branch of ``get_readable_home_directories``.

    The ``--scan-all-users`` flag depends on this enumeration returning every
    accessible human-user home. The previous coverage was Windows-only, so
    regressions in the POSIX path (e.g. wrong UID threshold, dropping the
    ``nobody`` filter, skipping the ``os.access`` gate) would silently
    degrade multi-user scans.
    """

    def _fake_pwd_entry(self, name, uid, home):
        return SimpleNamespace(pw_name=name, pw_uid=uid, pw_dir=home)

    def test_single_user_when_all_users_false(self, monkeypatch):
        """Single-user mode is the default and must return exactly the current
        process's home — never call into pwd enumeration."""

        def boom():
            raise AssertionError("pwd.getpwall() must NOT be consulted when all_users=False")

        import pwd as pwd_module

        monkeypatch.setattr(pwd_module, "getpwall", boom)

        result = get_readable_home_directories(all_users=False)

        assert len(result) == 1
        home_path, username = result[0]
        assert home_path == os.path.expanduser("~") or str(home_path) == os.path.expanduser("~")

    def test_all_users_linux_enumerates_above_uid_threshold(self, monkeypatch, tmp_path):
        """Linux uses UID >= 1000 as the human-user threshold. System accounts
        (root=0, daemon=1, etc.) must be excluded."""
        monkeypatch.setattr(utils_module.platform, "system", lambda: "Linux")

        alice_home = tmp_path / "alice"
        bob_home = tmp_path / "bob"
        alice_home.mkdir()
        bob_home.mkdir()

        import pwd as pwd_module

        monkeypatch.setattr(
            pwd_module,
            "getpwall",
            lambda: [
                self._fake_pwd_entry("root", 0, "/root"),
                self._fake_pwd_entry("daemon", 1, "/usr/sbin"),
                self._fake_pwd_entry("alice", 1000, str(alice_home)),
                self._fake_pwd_entry("bob", 1001, str(bob_home)),
            ],
        )
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice", "bob"}, f"system users must be filtered out; got {usernames}"

    def test_all_users_darwin_uses_lower_uid_threshold(self, monkeypatch, tmp_path):
        """macOS human UIDs start at 500, so a UID-501 user must be included
        on Darwin but excluded on Linux (verified by the previous test)."""
        monkeypatch.setattr(utils_module.platform, "system", lambda: "Darwin")

        alice_home = tmp_path / "alice"
        alice_home.mkdir()

        import pwd as pwd_module

        monkeypatch.setattr(
            pwd_module,
            "getpwall",
            lambda: [
                self._fake_pwd_entry("_some_macos_service", 200, "/var/empty"),
                self._fake_pwd_entry("alice", 501, str(alice_home)),
            ],
        )
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice"}, f"UID-200 must be filtered, UID-501 kept; got {usernames}"

    def test_all_users_excludes_nobody(self, monkeypatch, tmp_path):
        """The ``nobody`` account often has a high UID (macOS: -2 / 4294967294,
        Linux distros: 65534) and must be filtered by name regardless of UID."""
        monkeypatch.setattr(utils_module.platform, "system", lambda: "Linux")

        alice_home = tmp_path / "alice"
        nobody_home = tmp_path / "nobody"
        alice_home.mkdir()
        nobody_home.mkdir()

        import pwd as pwd_module

        monkeypatch.setattr(
            pwd_module,
            "getpwall",
            lambda: [
                self._fake_pwd_entry("nobody", 65534, str(nobody_home)),
                self._fake_pwd_entry("alice", 1000, str(alice_home)),
            ],
        )
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice"}, f"'nobody' must be filtered by name; got {usernames}"

    def test_all_users_excludes_inaccessible_homes(self, monkeypatch, tmp_path):
        """A user whose home fails ``os.access(R_OK | X_OK)`` must be dropped —
        without this filter, an unprivileged ``--scan-all-users`` run would
        attempt to read homes it cannot traverse and surface spurious errors."""
        monkeypatch.setattr(utils_module.platform, "system", lambda: "Linux")

        alice_home = tmp_path / "alice"
        bob_home = tmp_path / "bob"
        alice_home.mkdir()
        bob_home.mkdir()

        import pwd as pwd_module

        monkeypatch.setattr(
            pwd_module,
            "getpwall",
            lambda: [
                self._fake_pwd_entry("alice", 1000, str(alice_home)),
                self._fake_pwd_entry("bob", 1001, str(bob_home)),
            ],
        )
        # Only alice's home is accessible.
        monkeypatch.setattr(utils_module.os, "access", lambda path, _mode: str(path) == str(alice_home))

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice"}, f"inaccessible home must be dropped; got {usernames}"

    def test_all_users_excludes_missing_home_dirs(self, monkeypatch, tmp_path):
        """A pwd entry whose ``pw_dir`` doesn't exist on disk must be dropped
        (stale /etc/passwd entries, deprovisioned accounts)."""
        monkeypatch.setattr(utils_module.platform, "system", lambda: "Linux")

        alice_home = tmp_path / "alice"
        alice_home.mkdir()
        ghost_home = tmp_path / "ghost-never-created"  # not mkdir'd

        import pwd as pwd_module

        monkeypatch.setattr(
            pwd_module,
            "getpwall",
            lambda: [
                self._fake_pwd_entry("alice", 1000, str(alice_home)),
                self._fake_pwd_entry("ghost", 1001, str(ghost_home)),
            ],
        )
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice"}, f"non-existent home must be dropped; got {usernames}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only behavior")
class TestGetReadableHomeDirectoriesWindows:
    """Cover the Windows branch of ``get_readable_home_directories``.

    Parallels :class:`TestGetReadableHomeDirectoriesPosix` for the Win32
    profile enumeration path: every LocalPath emitted by Win32_UserProfile is
    filtered through ``Path.is_dir()`` + ``os.access(R_OK)`` and the username
    is derived from the directory's basename. WSL homes are merged in afterward
    so a Windows-only run still picks up Linux-side scan targets.

    Skipped on POSIX hosts — runs only on actual Windows CI so the platform
    branch is exercised against real Windows path semantics, not via a
    ``platform.system`` mock.
    """

    def _stub_subprocess_run_with_paths(self, monkeypatch, paths):
        """Make ``subprocess.run`` return the given paths as Win32_UserProfile output."""
        stdout = "\n".join(str(p) for p in paths) + "\n"

        def fake_run(_cmd, **_kwargs):
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)

    def test_single_user_when_all_users_false(self, monkeypatch):
        """Single-user mode on Windows must short-circuit before invoking the
        PowerShell CIM query — a hung WMI must never block the default path."""

        def boom(*_a, **_kw):
            raise AssertionError("subprocess.run must NOT be invoked when all_users=False")

        monkeypatch.setattr(utils_module.subprocess, "run", boom)

        result = get_readable_home_directories(all_users=False)

        assert len(result) == 1
        home_path, _username = result[0]
        assert str(home_path) == os.path.expanduser("~")

    def test_all_users_enumerates_local_paths(self, monkeypatch, tmp_path):
        """Every non-empty LocalPath line from Win32_UserProfile must surface as
        a (path, username) tuple where the username is the directory basename."""
        alice_home = tmp_path / "alice"
        bob_home = tmp_path / "bob"
        alice_home.mkdir()
        bob_home.mkdir()

        self._stub_subprocess_run_with_paths(monkeypatch, [alice_home, bob_home])
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)
        monkeypatch.setattr(utils_module, "get_wsl_home_directories", lambda: [])

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice", "bob"}, f"expected both profiles enumerated; got {usernames}"

    def test_all_users_excludes_inaccessible_profiles(self, monkeypatch, tmp_path):
        """A profile whose directory fails ``os.access(R_OK)`` must be dropped —
        without this filter, an unprivileged ``--scan-all-users`` run on Windows
        would surface other users' profiles it cannot actually read."""
        alice_home = tmp_path / "alice"
        bob_home = tmp_path / "bob"
        alice_home.mkdir()
        bob_home.mkdir()

        self._stub_subprocess_run_with_paths(monkeypatch, [alice_home, bob_home])
        # Only alice's home is readable.
        monkeypatch.setattr(utils_module.os, "access", lambda path, _mode: str(path) == str(alice_home))
        monkeypatch.setattr(utils_module, "get_wsl_home_directories", lambda: [])

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice"}, f"inaccessible profile must be dropped; got {usernames}"

    def test_all_users_excludes_missing_profile_dirs(self, monkeypatch, tmp_path):
        """A LocalPath whose directory doesn't exist on disk must be dropped
        (stale Win32_UserProfile entries, deprovisioned accounts)."""
        alice_home = tmp_path / "alice"
        alice_home.mkdir()
        ghost_home = tmp_path / "ghost-never-created"  # not mkdir'd

        self._stub_subprocess_run_with_paths(monkeypatch, [alice_home, ghost_home])
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)
        monkeypatch.setattr(utils_module, "get_wsl_home_directories", lambda: [])

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice"}, f"non-existent profile must be dropped; got {usernames}"

    def test_all_users_skips_blank_local_path_lines(self, monkeypatch, tmp_path):
        """Win32_UserProfile output can include blank lines (trailing newline,
        whitespace-only entries). These must be skipped, not coerced into a
        ``Path('')`` which would resolve to the CWD."""
        alice_home = tmp_path / "alice"
        alice_home.mkdir()

        def fake_run(_cmd, **_kwargs):
            stdout = f"\n   \n{alice_home}\n\n"
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)
        monkeypatch.setattr(utils_module, "get_wsl_home_directories", lambda: [])

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice"}, f"blank lines must be ignored; got {usernames}"

    def test_all_users_merges_wsl_homes_alongside_win32_profiles(self, monkeypatch, tmp_path):
        """WSL enumeration runs after Win32 profile collection; both result
        sets must appear in the merged output so a Windows scan reaches
        Linux-side agent state too."""
        alice_home = tmp_path / "alice"
        wsl_home = tmp_path / "wsl_ubuntu_alice"
        alice_home.mkdir()
        wsl_home.mkdir()

        self._stub_subprocess_run_with_paths(monkeypatch, [alice_home])
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)
        monkeypatch.setattr(
            utils_module,
            "get_wsl_home_directories",
            lambda: [(wsl_home, "wsl_alice")],
        )

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"alice", "wsl_alice"}, f"WSL homes must merge with Win32 profiles; got {usernames}"

    def test_all_users_wsl_does_not_overwrite_existing_win32_path(self, monkeypatch, tmp_path):
        """If WSL enumeration emits a path already covered by a Win32 profile,
        the Win32 username (set first) must win — otherwise a stale WSL entry
        could rename a legitimate Windows profile in scan output."""
        shared_home = tmp_path / "alice"
        shared_home.mkdir()

        self._stub_subprocess_run_with_paths(monkeypatch, [shared_home])
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)
        monkeypatch.setattr(
            utils_module,
            "get_wsl_home_directories",
            lambda: [(shared_home, "wsl_alice_collision")],
        )

        result = get_readable_home_directories(all_users=True)

        assert len(result) == 1, f"duplicate path must be deduped; got {result}"
        _path, username = result[0]
        assert username == "alice", f"Win32 username must win on collision; got {username!r}"

    def test_all_users_subprocess_failure_still_returns_wsl_homes(self, monkeypatch, tmp_path):
        """A PowerShell failure (CalledProcessError / FileNotFoundError) must
        be logged and swallowed so WSL enumeration still runs — the two signal
        sources are independent."""
        wsl_home = tmp_path / "wsl_alice_home"
        wsl_home.mkdir()

        def fake_run(cmd, **_kwargs):
            raise subprocess.CalledProcessError(returncode=1, cmd=cmd)

        monkeypatch.setattr(utils_module.subprocess, "run", fake_run)
        monkeypatch.setattr(utils_module.os, "access", lambda *_a, **_k: True)
        monkeypatch.setattr(
            utils_module,
            "get_wsl_home_directories",
            lambda: [(wsl_home, "wsl_alice")],
        )

        result = get_readable_home_directories(all_users=True)

        usernames = {u for _p, u in result}
        assert usernames == {"wsl_alice"}, f"WSL homes must still surface when CIM query fails; got {usernames}"
