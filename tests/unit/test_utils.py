import io
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_scan.models import CommandParsingError, StdioServer, rebalance_command_args
from agent_scan.utils import (
    calculate_distance,
    get_relative_path,
    resolve_command_and_args,
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


class TestResolveCommandAndArgs:
    """Tests for the home_directory parameter of resolve_command_and_args."""

    def _make_executable(self, path: Path) -> None:
        """Create a file and make it executable."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        path.chmod(0o755)

    def test_resolve_command_and_args_no_home_directory_searches_current_user_dirs(self, tmp_path):
        """When home_directory=None, a command in ~/.local/bin is found via the current user's dirs."""
        # Arrange
        local_bin = tmp_path / ".local" / "bin"
        executable = local_bin / "mycommand"
        self._make_executable(executable)

        server_config = StdioServer(command="mycommand")

        # Act
        with patch("agent_scan.utils.os.path.expanduser", return_value=str(tmp_path)):
            resolved_command, resolved_args = resolve_command_and_args(server_config, home_directory=None)

        # Assert
        assert resolved_command == str(executable)
        assert not resolved_args  # no args were passed; model normalises None -> []

    def test_resolve_command_and_args_with_home_directory_searches_owner_home_first(self, tmp_path):
        """When home_directory differs from current home, the owner's dirs are searched first."""
        # Arrange
        owner_home = tmp_path / "owner"
        current_home = tmp_path / "current"

        owner_local_bin = owner_home / ".local" / "bin"
        owner_executable = owner_local_bin / "mycommand"
        self._make_executable(owner_executable)

        # mycommand does NOT exist in current user's dirs
        (current_home / ".local" / "bin").mkdir(parents=True, exist_ok=True)

        server_config = StdioServer(command="mycommand")

        # Act
        with patch("agent_scan.utils.os.path.expanduser", return_value=str(current_home)):
            resolved_command, resolved_args = resolve_command_and_args(server_config, home_directory=owner_home)

        # Assert
        assert resolved_command == str(owner_executable)
        assert not resolved_args  # no args were passed; model normalises None -> []

    def test_resolve_command_and_args_with_home_directory_same_as_current_user_no_duplication(self, tmp_path):
        """When home_directory equals the current user's home, dirs are searched once and command is found."""
        # Arrange
        local_bin = tmp_path / ".local" / "bin"
        executable = local_bin / "mycommand"
        self._make_executable(executable)

        server_config = StdioServer(command="mycommand")

        # Act — home_directory is the same Path as the mocked current home
        with patch("agent_scan.utils.os.path.expanduser", return_value=str(tmp_path)):
            resolved_command, resolved_args = resolve_command_and_args(server_config, home_directory=tmp_path)

        # Assert — command is found exactly once, no error raised
        assert resolved_command == str(executable)
        assert not resolved_args  # no args were passed; model normalises None -> []

    def test_resolve_command_and_args_with_home_directory_falls_back_to_current_user_dirs(self, tmp_path):
        """When command is absent from owner's dirs but present in current user's dirs, it is still found."""
        # Arrange
        owner_home = tmp_path / "owner"
        current_home = tmp_path / "current"

        # mycommand only exists in the current user's .local/bin
        current_local_bin = current_home / ".local" / "bin"
        current_executable = current_local_bin / "mycommand"
        self._make_executable(current_executable)

        # Owner's .local/bin exists but does NOT contain mycommand
        (owner_home / ".local" / "bin").mkdir(parents=True, exist_ok=True)

        server_config = StdioServer(command="mycommand")

        # Act
        with patch("agent_scan.utils.os.path.expanduser", return_value=str(current_home)):
            resolved_command, resolved_args = resolve_command_and_args(server_config, home_directory=owner_home)

        # Assert — falls back to current user's path
        assert resolved_command == str(current_executable)
        assert not resolved_args  # no args were passed; model normalises None -> []

    def test_resolve_command_and_args_raises_when_not_found_anywhere(self, tmp_path):
        """When home_directory is provided but the command doesn't exist anywhere, ValueError is raised."""
        # Arrange
        owner_home = tmp_path / "owner"
        current_home = tmp_path / "current"
        owner_home.mkdir(parents=True, exist_ok=True)
        current_home.mkdir(parents=True, exist_ok=True)

        server_config = StdioServer(command="nonexistentcommand")

        # Act & Assert
        with patch("agent_scan.utils.os.path.expanduser", return_value=str(current_home)):
            with pytest.raises(ValueError, match="not found"):
                resolve_command_and_args(server_config, home_directory=owner_home)

    def test_resolve_command_and_args_with_home_directory_owner_wins_when_both_have_command(self, tmp_path):
        """When both owner and current user have the command, the owner's binary is returned."""
        # Arrange
        owner_home = tmp_path / "owner"
        current_home = tmp_path / "current"

        owner_executable = owner_home / ".local" / "bin" / "mycommand"
        self._make_executable(owner_executable)

        current_executable = current_home / ".local" / "bin" / "mycommand"
        self._make_executable(current_executable)

        server_config = StdioServer(command="mycommand")

        # Act — owner's home is provided; current user's home is mocked to current_home
        with patch("agent_scan.utils.os.path.expanduser", return_value=str(current_home)):
            resolved_command, resolved_args = resolve_command_and_args(server_config, home_directory=owner_home)

        # Assert — owner's path wins over current user's path
        assert resolved_command == str(owner_executable)
        assert not resolved_args  # no args were passed; model normalises None -> []
