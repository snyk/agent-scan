import logging
import os
import re
import shutil
import subprocess
import sys

from agent_scan.models import StdioServer
from agent_scan.models.mcp import BinaryCheck
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
    check = BinaryCheck(result="error")
    server.binary_check = check
    if sys.platform != "darwin":
        check.result = "not_macos"
        logger.info(f"Binary signature check not supported on {sys.platform}. Only supported on macOS.")
        return server
    try:
        try:
            command, _ = (
                (signature_command, server.args) if signature_command is not None else resolve_command_and_args(server)
            )
        except ValueError:
            # The resolver raises ValueError when no executable can be found.
            check.result = "not_found"
            return server
        check.resolved_command = command
        binary_path = os.path.realpath(shutil.which(command) or command)
        check.resolved_path = binary_path

        if _is_code_launcher(binary_path):
            check.result = "code_launcher"
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
        if verification.returncode != 0:
            check.result = "unsigned"
            logger.info(f"Binary signature verification failed for server {server.command}")
            return server

        result = subprocess.run(["codesign", "-dvvv", binary_path], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            check.result = "unsigned"
            return server

        output = result.stderr

        authorities = re.findall(r"Authority=(.+)", output)
        if "Apple Root CA" not in authorities:
            check.result = "not_apple_root"
            logger.info(f"Binary {server.command} is signed but not by Apple Root CA (authorities: {authorities})")
            return server

        if match := re.search(r"Identifier=(.+)", output):
            binary_identifier = match.group(1)
            logger.info(f"Binary {server.command} is signed as {binary_identifier}")
            assert isinstance(binary_identifier, str), f"Binary identifier is not a string: {binary_identifier}"
            server.binary_identifier = binary_identifier
            check.result = "signed"
        else:
            check.result = "no_identifier"
            logger.info(f"Binary {server.command} is signed but could not get identifier. Output: {output}")
        return server

    except Exception as e:
        check.result = "error"
        logger.info(f"Error checking binary signature of server {server.command}: {e}")
        return server
