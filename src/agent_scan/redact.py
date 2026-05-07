"""
Redaction utilities for sanitizing sensitive information from scan results.

This module provides functions to redact sensitive data like:
- Environment variables
- Command line argument values
- HTTP headers
- URL query parameters
- File paths in tracebacks
"""

import logging
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from agent_scan.models import RemoteServer, ScanPathResult, ServerScanResult, StdioServer

logger = logging.getLogger(__name__)

REDACTED = "**REDACTED**"


def redact_absolute_paths(text: str | None) -> str | None:
    """
    Redact all absolute file paths in a string.

    Replaces absolute paths (starting with / or drive letters like C:, or ~/)
    with **REDACTED**, preserving the structure of the text.

    Args:
        text: The text string, or None

    Returns:
        Text with absolute paths redacted, or None if input was None
    """
    if not text:
        return text

    # Pattern matches absolute paths:
    # - Unix: /path/to/something (but not single /)
    # - Windows: C:\path\to\something or C:/path/to/something
    # - Home: ~/path/to/something
    # Stops at whitespace, quotes, or common delimiters
    patterns = [
        # Unix absolute paths (at least one directory component)
        r'/(?:[^/\s"\'<>|:]+/)+[^/\s"\'<>|:]*',
        # Home directory paths
        r'~/[^\s"\'<>|:]+',
        # Windows paths with drive letter
        r'[A-Za-z]:[/\\](?:[^/\\\s"\'<>|:]+[/\\])*[^/\\\s"\'<>|:]*',
    ]

    result = text
    for pattern in patterns:
        result = re.sub(pattern, REDACTED, result)

    return result


def _is_path(arg: str) -> bool:
    """Check if an argument looks like a file path that should be redacted."""
    # Unix absolute path
    if arg.startswith("/") and len(arg) > 1:
        return True
    # Home directory path
    if arg.startswith("~/"):
        return True
    # Windows absolute path (C:\, D:\, etc.)
    return len(arg) >= 3 and arg[1] == ":" and arg[2] in "/\\"


def redact_args(args: list[str]) -> list[str]:
    """
    Redact values of key-value arguments in a command line argument list.

    Identifies flags (arguments starting with - or --) and redacts their values.
    Handles both space-separated (--arg value) and equals-separated (--arg=value) syntax.
    The -y flag is treated as a boolean flag (common in npx) and doesn't consume the next arg.
    Also redacts file paths (arguments starting with /, ~/, or drive letters).

    Args:
        args: List of command line arguments

    Returns:
        List of arguments with values redacted
    """
    if not args:
        return []

    redacted: list[str] = []
    i = 0

    while i < len(args):
        arg = args[i]

        # Check for --flag=value or -f=value syntax
        if arg.startswith("-") and "=" in arg:
            # Split on first = only, preserve the flag part
            eq_idx = arg.index("=")
            flag_part = arg[: eq_idx + 1]  # includes the =
            redacted.append(flag_part + REDACTED)
            i += 1
        # Check for --flag or -f followed by a value (but not -y which is a boolean flag)
        elif arg.startswith("-") and arg != "-y":
            redacted.append(arg)
            # Look ahead to see if next arg is a value (not a flag)
            if i + 1 < len(args) and not args[i + 1].startswith("-"):
                # Next arg is likely a value for this flag - redact it
                redacted.append(REDACTED)
                i += 2
            else:
                # Flag with no value or next arg is also a flag
                i += 1
        elif _is_path(arg):
            # Redact file paths
            redacted.append(REDACTED)
            i += 1
        else:
            # Positional argument - preserve as-is
            redacted.append(arg)
            i += 1

    return redacted


def redact_server(server_scan_result: ServerScanResult) -> ServerScanResult:
    """
    Redact sensitive information from a server scan result.

    For StdioServer:
    - Redacts all environment variable values
    - Redacts command line argument values (flag values)

    For RemoteServer:
    - Redacts all HTTP header values
    - Redacts all URL query parameter values

    Args:
        server_scan_result: The server scan result to redact

    Returns:
        The same server scan result with sensitive data redacted
    """
    if isinstance(server_scan_result.server, StdioServer):
        # Redact all environment variables
        if server_scan_result.server.env:
            server_scan_result.server.env = dict.fromkeys(server_scan_result.server.env, REDACTED)
        # Redact argument values (e.g., --api-key secret → --api-key **REDACTED**)
        if server_scan_result.server.args:
            server_scan_result.server.args = redact_args(server_scan_result.server.args)

    elif isinstance(server_scan_result.server, RemoteServer):
        # Redact all headers
        if server_scan_result.server.headers:
            server_scan_result.server.headers = dict.fromkeys(server_scan_result.server.headers, REDACTED)
        # Redact all query parameter values in the URL
        try:
            parts = urlsplit(server_scan_result.server.url)
            if parts.query:
                qs = parse_qsl(parts.query)
                redacted_qs = [(k, REDACTED) for k, _ in qs]
                new_query = urlencode(redacted_qs)
                server_scan_result.server.url = urlunsplit(
                    (parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)
                )
        except Exception:
            logger.error("Failed to redact URL: %s", server_scan_result.server.url)

    # Redact traceback in server error
    if server_scan_result.error and server_scan_result.error.traceback:
        server_scan_result.error.traceback = redact_absolute_paths(server_scan_result.error.traceback)

    # Redact all absolute paths in server output (stderr, protocol messages)
    if server_scan_result.error and server_scan_result.error.server_output:
        server_scan_result.error.server_output = redact_absolute_paths(server_scan_result.error.server_output)

    return server_scan_result


def redact_scan_result(result: ScanPathResult) -> ScanPathResult:
    """
    Redact sensitive information from a scan path result before upload.

    This redacts:
    - Tracebacks in path-level errors
    - Server-level sensitive data (via redact_server)

    Args:
        result: The scan path result to redact

    Returns:
        The same result with sensitive data redacted
    """
    # Redact path-level error traceback
    if result.error and result.error.traceback:
        result.error.traceback = redact_absolute_paths(result.error.traceback)

    # Redact all server-level sensitive data
    if result.servers:
        for i, server in enumerate(result.servers):
            result.servers[i] = redact_server(server)

    return result
