import stat
import subprocess
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


def test_check_server_signature_resolves_path_command_on_path(tmp_path, monkeypatch):
    """PATH-only commands must be passed to codesign as an absolute executable path."""
    snyk = tmp_path / "snyk"
    snyk.write_text("#!/bin/sh\necho snyk\n")
    snyk.chmod(snyk.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(tmp_path), prepend=False)

    codesign_output = (
        "Authority=Developer ID Application: Snyk Ltd\n"
        "Authority=Developer ID Certification Authority\n"
        "Authority=Apple Root CA\n"
        "Identifier=com.snyk.cli\n"
    )
    captured: list[list[str]] = []

    def fake_codesign(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", codesign_output)

    with patch.object(subprocess, "run", side_effect=fake_codesign):
        with patch("agent_scan.signed_binary.sys.platform", "darwin"):
            server = check_server_signature(StdioServer(command="snyk", args=None))

    assert captured == [["codesign", "-dvvv", str(snyk)]]
    assert server.command == "snyk"
    assert server.binary_identifier == "com.snyk.cli"
