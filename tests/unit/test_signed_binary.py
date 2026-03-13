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
