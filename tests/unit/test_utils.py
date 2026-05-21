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

        monkeypatch.setattr(utils_module.platform, "system", lambda: "Windows")

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

        monkeypatch.setattr(utils_module.platform, "system", lambda: "Windows")

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
