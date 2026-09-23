import os
import stat
from subprocess import CompletedProcess
from unittest.mock import call, patch

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


def test_check_server_signature_resolves_named_binary_from_path(tmp_path, monkeypatch):
    binary = tmp_path / "snyk"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    server = StdioServer(command="snyk", args=["mcp", "-t", "stdio"])
    details = "\n".join(
        (
            "Identifier=com.snyk.cli",
            "Authority=Developer ID Application: Snyk Limited",
            "Authority=Apple Root CA",
        )
    )

    with (
        patch("agent_scan.signed_binary.sys.platform", "darwin"),
        patch(
            "agent_scan.signed_binary.subprocess.run",
            side_effect=(
                CompletedProcess(args=[], returncode=0),
                CompletedProcess(args=[], returncode=0, stderr=details),
            ),
        ) as run,
    ):
        check_server_signature(server)

    binary_path = str(binary.resolve())
    assert server.binary_identifier == "com.snyk.cli"
    assert run.call_args_list == [
        call(
            ["codesign", "--verify", "--strict", "--verbose=3", binary_path],
            capture_output=True,
            text=True,
            check=False,
        ),
        call(["codesign", "-dvvv", binary_path], capture_output=True, text=True, check=False),
    ]


def test_check_server_signature_rejects_failed_verification(tmp_path):
    binary = tmp_path / "snyk"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    server = StdioServer(command=str(binary), args=["mcp", "-t", "stdio"])

    with (
        patch("agent_scan.signed_binary.sys.platform", "darwin"),
        patch(
            "agent_scan.signed_binary.subprocess.run",
            return_value=CompletedProcess(args=[], returncode=1, stderr="invalid signature"),
        ) as run,
    ):
        check_server_signature(server)

    assert server.binary_identifier is None
    run.assert_called_once_with(
        ["codesign", "--verify", "--strict", "--verbose=3", str(binary.resolve())],
        capture_output=True,
        text=True,
        check=False,
    )


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
