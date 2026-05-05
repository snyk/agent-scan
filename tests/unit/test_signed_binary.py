from pathlib import Path
from unittest.mock import patch

import pytest

from agent_scan.models import StdioServer
from agent_scan.signed_binary import _is_code_launcher, check_server_signature


@pytest.mark.parametrize(
    "command",
    [
        "uv",
        "uvx",
        "docker",
        "bash",
    ],
)
def test_check_server_signature(command: str):
    server = check_server_signature(StdioServer(command=command, args=None))
    assert server.binary_identifier is None


@pytest.mark.parametrize(
    "command,is_code_launcher",
    [
        ("python", True),
        ("node", True),
        ("npm", True),
        ("uv", True),
        ("uvx", True),
        ("docker", True),
        ("bash", True),
        ("cargo", True),
        ("snyk-macos-arm64", False),
        ("github-mcp-server", False),
        ("terraform-mcp-server", False),
    ],
)
def test_is_code_launcher(command: str, is_code_launcher: bool):
    assert _is_code_launcher(command) == is_code_launcher


def test_check_server_signature_forwards_home_directory_to_resolve():
    """home_directory must reach resolve_command_and_args. check_server_signature
    is called from get_mcp_config_per_home_directory during --scan-all-users, so the
    config owner's per-user binary dirs must be searched when resolving the binary
    to codesign-check.

    Forces sys.platform to "darwin" so the test runs on all CI platforms instead of
    no-op'ing on Linux/Windows, and patches resolve_command_and_args to short-circuit
    before any subprocess call.
    """
    expected_home = Path("/fake/owner/home")
    server = StdioServer(command="dummycmd", args=[])

    with (
        patch("sys.platform", "darwin"),
        patch(
            "agent_scan.signed_binary.resolve_command_and_args",
            side_effect=RuntimeError("short-circuit after capture"),
        ) as mock_resolve,
    ):
        # check_server_signature swallows the exception (broad except) and returns
        # the original server unchanged — fine: we only assert how resolve was called.
        result = check_server_signature(server, home_directory=expected_home)

    assert result is server
    assert mock_resolve.called, "resolve_command_and_args was never invoked"
    assert mock_resolve.call_args.kwargs.get("home_directory") == expected_home


def test_check_server_signature_forwards_none_home_directory_when_unset():
    """When called without home_directory, resolve_command_and_args must receive
    home_directory=None (the explicit default), not a stale value."""
    server = StdioServer(command="dummycmd", args=[])

    with (
        patch("sys.platform", "darwin"),
        patch(
            "agent_scan.signed_binary.resolve_command_and_args",
            side_effect=RuntimeError("short-circuit after capture"),
        ) as mock_resolve,
    ):
        check_server_signature(server)

    assert mock_resolve.called
    assert mock_resolve.call_args.kwargs.get("home_directory") is None
