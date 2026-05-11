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
import os
import re
import tempfile
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings

from agent_scan.models import RemoteServer, ScanPathResult, ServerScanResult, StdioServer

logger = logging.getLogger(__name__)

REDACTED = "**REDACTED**"
REDACTED_SECRET = "**REDACTED_SECRET***"


# detect-secrets plugin configuration used by redact_args to scan CLI
# argument values for high-entropy and known-format tokens. Default
# entropy limits (Base64=4.5, Hex=3.0) converged cleanly against the
# realistic must-pass-through / must-flag corpus during empirical
# probing; raising them was unnecessary. KeywordDetector is omitted on
# purpose to avoid false positives on common substrings like "token="
# or "password=".
_DETECT_SECRETS_CONFIG: dict = {
    "plugins_used": [
        {"name": "Base64HighEntropyString", "limit": 4.5},
        {"name": "HexHighEntropyString", "limit": 3.0},
        {"name": "AWSKeyDetector"},
        {"name": "GitHubTokenDetector"},
        {"name": "OpenAIDetector"},
        {"name": "PrivateKeyDetector"},
        {"name": "JwtTokenDetector"},
        {"name": "SlackDetector"},
        {"name": "StripeDetector"},
        {"name": "TwilioKeyDetector"},
        {"name": "AzureStorageKeyDetector"},
        {"name": "MailchimpDetector"},
        {"name": "ArtifactoryDetector"},
        {"name": "CloudantDetector"},
        {"name": "DiscordBotTokenDetector"},
        {"name": "GitLabTokenDetector"},
        {"name": "IbmCloudIamDetector"},
        {"name": "IbmCosHmacDetector"},
        {"name": "IPPublicDetector"},
        {"name": "NpmDetector"},
        {"name": "PypiTokenDetector"},
        {"name": "SendGridDetector"},
        {"name": "SquareOAuthDetector"},
        {"name": "TelegramBotTokenDetector"},
    ],
}


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


def _contains_secret(value: str) -> bool:
    """
    Return True if detect-secrets flags any token in ``value``.

    Uses ``SecretsCollection.scan_file`` (the canonical detect-secrets
    API, which respects per-plugin entropy ``limit`` values). The value
    is written to a temporary file because ``scan_file`` reads paths
    rather than in-memory strings.

    The value is also wrapped in matching quotes before being written:
    the ``Base64HighEntropyString`` plugin's tokenizing regex requires
    the candidate string to appear inside a quoted literal (its pattern
    is ``(['"])(token)(\\1)``). CLI argument values arrive unquoted, so
    we add quotes purely as a tokenization aid. This does not change
    detection semantics — entropy and named-detector logic operate on
    the inner value either way.
    """
    if not value:
        return False

    if '"' not in value:
        wrapped = f'"{value}"'
    elif "'" not in value:
        wrapped = f"'{value}'"
    else:
        # Both quote types present in the value: escape inner double quotes
        # so the outer wrapping still matches as a quoted literal.
        wrapped = '"' + value.replace('"', '\\"') + '"'

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write(wrapped)
        tmp_path = tf.name
    try:
        with transient_settings(_DETECT_SECRETS_CONFIG):
            secrets = SecretsCollection()
            secrets.scan_file(tmp_path)
            return bool(list(secrets))
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            logger.debug("Failed to remove temp file used for secret scan: %s", tmp_path)


def redact_args(args: list[str]) -> list[str]:
    """
    Redact only the **secret-bearing** values of CLI argument tokens.

    Each argument is inspected independently (no look-ahead between
    tokens). Detection uses detect-secrets via :func:`_contains_secret`:

    - ``--flag=value`` / ``-f=value``: the value half is replaced with
      :data:`REDACTED_SECRET` if and only if the value contains a
      detect-secrets-flagged token. The flag prefix (and the ``=``) is
      preserved as-is.
    - Bare tokens (no ``=``, or that don't start with ``-``): the entire
      token is replaced with :data:`REDACTED_SECRET` if and only if it
      contains a detect-secrets-flagged token.
    - Low-entropy values, flags-without-values, package names, paths,
      and other non-secret tokens are preserved verbatim.

    Args:
        args: List of command line arguments.

    Returns:
        A new list with secret-bearing values replaced; non-secret
        tokens passed through unchanged. An empty input yields an empty
        list.
    """
    if not args:
        return []

    redacted: list[str] = []
    for arg in args:
        # --flag=value or -f=value: only inspect/replace the value half.
        if arg.startswith("-") and "=" in arg:
            eq_idx = arg.index("=")
            flag_part = arg[: eq_idx + 1]  # includes the trailing '='
            value_part = arg[eq_idx + 1 :]
            if _contains_secret(value_part):
                redacted.append(flag_part + REDACTED_SECRET)
            else:
                redacted.append(arg)
            continue

        # Bare token (positional or flag-without-value): inspect whole arg.
        if _contains_secret(arg):
            redacted.append(REDACTED_SECRET)
        else:
            redacted.append(arg)

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
        # Redact argument values (e.g., --api-key secret → --api-key **REDACTED_SECRET***)
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
