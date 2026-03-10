import logging
import re
import subprocess
import sys

from agent_scan.models import StdioServer
from agent_scan.utils import resolve_command_and_args

logger = logging.getLogger(__name__)


def check_server_signature(server: StdioServer) -> StdioServer:
    """Get detailed code signing information."""
    if sys.platform != "darwin":
        logger.info(f"Binary signature check not supported on {sys.platform}. Only supported on macOS.")
        return server
    try:
        command, _ = resolve_command_and_args(server)
        result = subprocess.run(["codesign", "-dvvv", command], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return server

        output = result.stderr

        if match := re.search(r"Identifier=(.+)", output):
            binary_identifier = match.group(1)
            logger.info(f"Binary {server.command} is signed as {binary_identifier}")
            assert isinstance(binary_identifier, str), f"Binary identifier is not a string: {binary_identifier}"
            server.binary_identifier = binary_identifier
        else:
            logger.info(f"Binary {server.command} is signed but could not get identifier. Output: {output}")
        return server

    except Exception as e:
        logger.info(f"Error checking binary signature of server {server.command}: {e}")
        return server
