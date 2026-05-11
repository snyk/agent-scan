"""
Redaction utilities for sanitizing sensitive information from scan results.

This module provides functions to redact sensitive data like:
- Environment variables
- Command line argument values (detected via the detect-secrets library)
- HTTP headers
- URL query parameters
- File paths in tracebacks
"""

import logging
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from detect_secrets.plugins.high_entropy_strings import HighEntropyStringsPlugin
from detect_secrets.settings import default_settings, get_plugins, transient_settings

from agent_scan.models import RemoteServer, ScanPathResult, ServerScanResult, StdioServer

logger = logging.getLogger(__name__)

REDACTED = "**REDACTED**"

_EXCLUDED_PLUGINS = frozenset({"IPPublicDetector"})


def _build_detect_secrets_config() -> dict:
    """
    Build a ``transient_settings`` config from detect-secrets' default
    plugin set, excluding plugins listed in ``_EXCLUDED_PLUGINS``.

    IPPublicDetector is excluded because public IP addresses are common,
    legitimate CLI argument values (e.g. ``--host 8.8.8.8``) and should
    not be redacted as secrets.
    """
    with default_settings() as settings:
        plugins_used = [
            {"name": name, **kwargs} for name, kwargs in settings.plugins.items() if name not in _EXCLUDED_PLUGINS
        ]
    return {"plugins_used": plugins_used}


_DETECT_SECRETS_CONFIG: dict = _build_detect_secrets_config()


def _redaction_marker(plugin_name: str) -> str:
    """Format the redaction marker for a triggering detect-secrets plugin."""
    return f"**REDACTED_SECRET_{plugin_name.upper()}***"


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


def _wrap_for_entropy(value: str) -> str:
    """
    Wrap ``value`` in quotes so the entropy plugins' quoted-literal
    regex (``(['"])(token)(\\1)``) can tokenize it.

    Returns one of ``"<value>"``, ``'<value>'``, or ``"<escaped>"``
    (when both quote styles appear in ``value``).
    """
    if '"' not in value:
        return f'"{value}"'
    if "'" not in value:
        return f"'{value}'"
    return '"' + value.replace('"', r"\"") + '"'


def _detect_secret(value: str) -> str | None:
    """
    Return the class name of the first detect-secrets plugin that flags
    ``value``, or ``None`` if no plugin flags it.

    Two-pass scan to give each plugin family the input format it expects:

    1. Named-format detectors (``AWSKeyDetector``, ``GitHubTokenDetector``,
       etc.) match self-contained format patterns and work on the raw
       value directly.
    2. ``HighEntropyStringsPlugin`` subclasses default to scanning quoted
       string literals (``(['"])(token)(\\1)``); they receive the value
       wrapped as ``"<value>"``, ``'<value>'``, or ``"<escaped>"`` so
       their regex tokenizes the whole value, then the entropy ``limit``
       filter is applied.
    """
    if not value:
        return None
    with transient_settings(_DETECT_SECRETS_CONFIG):
        plugins = list(get_plugins())
        # Pass 1: format-based named detectors on the bare value.
        for plugin in plugins:
            if isinstance(plugin, HighEntropyStringsPlugin):
                continue
            if plugin.analyze_line(filename="adhoc", line=value, line_number=1):
                return type(plugin).__name__
        # Pass 2: entropy plugins on the quote-wrapped value.
        wrapped = _wrap_for_entropy(value)
        for plugin in plugins:
            if not isinstance(plugin, HighEntropyStringsPlugin):
                continue
            if plugin.analyze_line(filename="adhoc", line=wrapped, line_number=1):
                return type(plugin).__name__
    return None


def _redact_one_arg(arg: str) -> str:
    """Return ``arg`` with any detect-secrets-flagged value replaced by a plugin-named marker.

    For ``--flag=value`` / ``-f=value``, the value half is scanned and
    the flag prefix is preserved. For everything else (bare positional,
    flag-without-value), the whole token is scanned.
    """
    if arg.startswith("-") and "=" in arg:
        flag, _, value = arg.partition("=")
        plugin_name = _detect_secret(value)
        return f"{flag}={_redaction_marker(plugin_name)}" if plugin_name else arg
    plugin_name = _detect_secret(arg)
    return _redaction_marker(plugin_name) if plugin_name else arg


def redact_args(args: list[str]) -> list[str]:
    """Redact only the secret-bearing values of CLI argument tokens."""
    return [_redact_one_arg(arg) for arg in args]


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
        # Redact argument values via detect-secrets (plugin-named markers).
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
