import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time

from agent_scan.models import StdioServer
from agent_scan.utils import resolve_command_and_args

logger = logging.getLogger(__name__)

# Binaries that execute arbitrary user-supplied code. Even when properly signed,
# they don't make the MCP server itself trustworthy — the real code being run
# is whatever script/package the user pointed them at.
_CODE_LAUNCHER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^python\d?(\.\d+)*$"),
    re.compile(r"^(node|nodejs|npx|npm|bun|deno)$"),
    re.compile(r"^(ruby|irb)$"),
    re.compile(r"^php$"),
    re.compile(r"^perl$"),
    re.compile(r"^(java|javaw)$"),
    re.compile(r"^(bash|sh|zsh|fish|dash|ksh|csh|tcsh)$"),
    re.compile(r"^cargo$"),
    re.compile(r"^(uv|uvx|mise|docker|podman|pipx|poetry|pdm|rye)$"),
    re.compile(r"^dotnet$"),
]


def _is_code_launcher(command: str) -> bool:
    """Return True if the resolved command is a known code-launcher binary."""
    basename = os.path.basename(command)
    return any(p.match(basename) for p in _CODE_LAUNCHER_PATTERNS)


def check_server_signature(server: StdioServer, *, signature_command: str | None = None) -> StdioServer:
    """Get detailed code signing information.

    ``signature_command`` lets a discoverer supply the effective executable path
    without changing the configured command used to start the server.
    """
    if sys.platform != "darwin":
        logger.info(f"Binary signature check not supported on {sys.platform}. Only supported on macOS.")
        return server
    try:
        command, _ = (
            (signature_command, server.args) if signature_command is not None else resolve_command_and_args(server)
        )
        binary_path = os.path.realpath(shutil.which(command) or command)

        # region agent log
        try:
            open("/opt/cursor/logs/debug.log", "a").write(
                json.dumps(
                    {
                        "hypothesisId": "C,D",
                        "location": "signed_binary.py:check_server_signature",
                        "message": "Resolved signature target",
                        "data": {
                            "usedOverride": signature_command is not None,
                            "binaryBasename": os.path.basename(binary_path),
                            "binaryExists": os.path.isfile(binary_path),
                            "isCodeLauncher": _is_code_launcher(binary_path),
                        },
                        "timestamp": time.time_ns() // 1_000_000,
                    }
                )
                + "\n"
            )
        except OSError:
            pass
        # endregion
        if _is_code_launcher(binary_path):
            logger.info(
                f"Binary {server.command} ({binary_path}) is a code launcher — "
                "signature does not imply trust in the executed code"
            )
            return server

        verification = subprocess.run(
            ["codesign", "--verify", "--strict", "--verbose=3", binary_path],
            capture_output=True,
            text=True,
            check=False,
        )
        # region agent log
        try:
            open("/opt/cursor/logs/debug.log", "a").write(
                json.dumps(
                    {
                        "hypothesisId": "D",
                        "location": "signed_binary.py:check_server_signature:verify",
                        "message": "codesign verification completed",
                        "data": {"returnCode": verification.returncode},
                        "timestamp": time.time_ns() // 1_000_000,
                    }
                )
                + "\n"
            )
        except OSError:
            pass
        # endregion
        if verification.returncode != 0:
            logger.info(f"Binary signature verification failed for server {server.command}")
            return server

        result = subprocess.run(["codesign", "-dvvv", binary_path], capture_output=True, text=True, check=False)
        output = result.stderr

        authorities = re.findall(r"Authority=(.+)", output)
        identifier_match = re.search(r"Identifier=(.+)", output)
        # region agent log
        try:
            open("/opt/cursor/logs/debug.log", "a").write(
                json.dumps(
                    {
                        "hypothesisId": "D",
                        "location": "signed_binary.py:check_server_signature:details",
                        "message": "codesign identity details parsed",
                        "data": {
                            "returnCode": result.returncode,
                            "hasAppleRoot": "Apple Root CA" in authorities,
                            "identifier": identifier_match.group(1) if identifier_match else None,
                        },
                        "timestamp": time.time_ns() // 1_000_000,
                    }
                )
                + "\n"
            )
        except OSError:
            pass
        # endregion
        if result.returncode != 0:
            return server
        if "Apple Root CA" not in authorities:
            logger.info(f"Binary {server.command} is signed but not by Apple Root CA (authorities: {authorities})")
            return server

        if identifier_match:
            binary_identifier = identifier_match.group(1)
            logger.info(f"Binary {server.command} is signed as {binary_identifier}")
            assert isinstance(binary_identifier, str), f"Binary identifier is not a string: {binary_identifier}"
            server.binary_identifier = binary_identifier
        else:
            logger.info(f"Binary {server.command} is signed but could not get identifier. Output: {output}")
        return server

    except Exception as e:
        logger.info(f"Error checking binary signature of server {server.command}: {e}")
        return server
