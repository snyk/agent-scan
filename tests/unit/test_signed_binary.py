import os
import stat
from subprocess import CompletedProcess
from unittest.mock import call, patch

import pytest

from agent_scan.models import InspectedPath, InspectedServer, StdioServer
from agent_scan.models.mcp import BinaryCheck
from agent_scan.signed_binary import _is_code_launcher, check_server_signature
from agent_scan.verify_api import build_scan_request


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


@pytest.mark.parametrize(
    "expected,platform,resolution_error,path,processes",
    [
        (
            "signed",
            "darwin",
            None,
            "/opt/bin/server",
            [(0, ""), (0, "Authority=Apple Root CA\nIdentifier=example.server")],
        ),
        ("not_macos", "linux", None, None, []),
        ("not_found", "darwin", ValueError("missing command"), None, []),
        ("code_launcher", "darwin", None, "/opt/bin/node", []),
        ("unsigned", "darwin", None, "/opt/bin/server", [(1, "unsigned")]),
        ("unsigned", "darwin", None, "/opt/bin/server", [(0, ""), (1, "details unavailable")]),
        (
            "not_apple_root",
            "darwin",
            None,
            "/opt/bin/server",
            [(0, ""), (0, "Authority=Other CA\nIdentifier=example.server")],
        ),
        ("no_identifier", "darwin", None, "/opt/bin/server", [(0, ""), (0, "Authority=Apple Root CA")]),
        ("error", "darwin", None, "/opt/bin/server", RuntimeError("private exception text")),
        ("error", "darwin", RuntimeError("resolver failure"), None, []),
    ],
)
def test_binary_check_outcomes(expected, platform, resolution_error, path, processes):
    server = StdioServer(command="server", args=["mcp"])
    assert server.binary_check is None
    runs = (
        processes
        if isinstance(processes, Exception)
        else [CompletedProcess(args=[], returncode=code, stderr=stderr) for code, stderr in processes]
    )
    with (
        patch("agent_scan.signed_binary.sys.platform", platform),
        patch(
            "agent_scan.signed_binary.resolve_command_and_args",
            return_value=("server", ["mcp"]),
            side_effect=resolution_error,
        ) as resolve,
        patch("agent_scan.signed_binary.shutil.which", return_value="/opt/bin/server-link") as which,
        patch("agent_scan.signed_binary.os.path.realpath", return_value=path) as realpath,
        patch("agent_scan.signed_binary.subprocess.run", side_effect=runs) as run,
    ):
        assert check_server_signature(server) is server

    resolved = platform == "darwin" and resolution_error is None
    assert server.binary_check.model_dump() == {
        "result": expected,
        "resolved_command": "server" if resolved else None,
        "resolved_path": path,
    }
    assert server.binary_identifier == ("example.server" if expected == "signed" else None)
    assert "private exception text" not in server.model_dump_json()
    assert resolve.call_count == int(platform == "darwin")
    assert which.call_count == realpath.call_count == int(resolved)
    if resolved:
        which.assert_called_once_with("server")
        realpath.assert_called_once_with("/opt/bin/server-link")
    assert run.call_count == (1 if isinstance(processes, Exception) else len(processes))
    assert (server.command, server.args) == ("server", ["mcp"])
    assert server.runtime_command is None


def test_binary_check_signature_command_and_realpath_fallback():
    server = StdioServer(command="configured", args=["mcp"])
    with (
        patch("agent_scan.signed_binary.sys.platform", "darwin"),
        patch("agent_scan.signed_binary.resolve_command_and_args") as resolve,
        patch("agent_scan.signed_binary.shutil.which", return_value=None),
        patch("agent_scan.signed_binary.os.path.realpath", return_value="/opt/bin/node") as realpath,
        patch("agent_scan.signed_binary.subprocess.run") as run,
    ):
        check_server_signature(server, signature_command="/opt/bin/launcher")
    resolve.assert_not_called()
    run.assert_not_called()
    realpath.assert_called_once_with("/opt/bin/launcher")
    assert server.binary_check == BinaryCheck(
        result="code_launcher", resolved_command="/opt/bin/launcher", resolved_path="/opt/bin/node"
    )
    assert server.command == "configured"


def test_binary_check_serialized_in_inspect_and_backend_payload():
    server = StdioServer(command="server", binary_identifier="example.server")
    server.binary_check = BinaryCheck(result="signed", resolved_command="server", resolved_path="/opt/bin/server")
    inspected = InspectedPath(path="/config.json", servers=[InspectedServer(name="example", server=server)])
    local = inspected.model_dump(mode="json")["servers"][0]["server"]
    outgoing = build_scan_request([inspected]).model_dump(mode="json")["scan_path_requests"][0]["servers"][0]["server"]
    assert (
        local["binary_check"]
        == outgoing["binary_check"]
        == {"result": "signed", "resolved_command": "server", "resolved_path": "/opt/bin/server"}
    )
    assert outgoing["binary_identifier"] == "example.server"


def test_binary_check_input_cannot_change_launch_resolution():
    from agent_scan.utils import resolve_command_and_args

    server = StdioServer(
        command="server",
        args=["mcp"],
        binary_check=BinaryCheck(result="signed", resolved_command="other", resolved_path="/other"),
    )
    with patch("agent_scan.utils.check_executable_exists", return_value=True):
        assert resolve_command_and_args(server) == ("server", ["mcp"])
    assert server.runtime_command is None
    assert server.runtime_cwd is None
