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
from detect_secrets.plugins.keyword import KeywordDetector
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
    """Format the redaction marker for a triggering detect-secrets plugin.

    Uses the same ``**...**`` delimiter shape as the legacy ``REDACTED`` constant
    so both marker styles render and grep consistently.
    """
    return f"**REDACTED_SECRET_{plugin_name.upper()}**"


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


def _detect_keyword(prev_normalized: str, curr_raw: str) -> str | None:
    """
    Run only ``KeywordDetector`` against a synthetic assignment line
    ``f'{prev_normalized}={_wrap_for_entropy(curr_raw)}'``.

    ``KeywordDetector`` matches denylist tokens like ``api_?key``,
    ``password``, ``secret`` (see upstream ``DENYLIST`` in
    ``detect_secrets/plugins/keyword.py``) when they appear next to a
    quoted literal. The bare-value scan in ``_detect_secret`` never
    fires this plugin; this helper supplies the missing keyword
    context via a previous-token-as-key lookup.

    Returns ``"KeywordDetector"`` on a hit, else ``None``.
    """
    if not prev_normalized or not curr_raw:
        return None
    plugin = KeywordDetector()
    synthetic = f"{prev_normalized}={_wrap_for_entropy(curr_raw)}"
    if plugin.analyze_line(filename="adhoc", line=synthetic, line_number=1):
        return type(plugin).__name__
    return None


_HEADER_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")

# Flag names whose value is *always* a credential, regardless of shape or
# entropy. Names are stored in the same normalized form produced during
# tokenization (leading dashes stripped, internal dashes -> underscores)
# so a user typing --push-key, --push_key, or -push-key all match.
# Note: --control-server-H is NOT in this list because its value is a
# `name:value` header pair where only some header names carry secrets;
# `_SENSITIVE_HEADER_NAMES` handles those cases by header name instead.
_SENSITIVE_FLAG_NAMES = frozenset(
    {
        "push_key",
    }
)

# Header names whose value is always a credential when seen as the
# `name:value` half of a positional token (e.g. via --control-server-H).
# Stored lowercase; matching is case-insensitive on the name side.
_SENSITIVE_HEADER_NAMES = frozenset(
    {
        "x-client-id",
        "authorization",
    }
)


def redact_args(args: list[str]) -> list[str]:
    """Redact secret-bearing values in CLI argument tokens.

    Detection runs in four passes against a tokenized view of ``args``
    (each ``--flag=value`` arg yields two tokens; everything else
    yields one):

    1. Format detectors (AWSKeyDetector, GitHubTokenDetector, ...) on
       the bare token value.
    2. High-entropy string detectors on the quote-wrapped token value.
    3. KeywordDetector via a sliding window of 2: for each adjacent
       ``(prev, curr)`` pair, build a synthetic ``prev="curr"`` line
       and ask the keyword plugin whether ``prev`` is in its denylist.
    4. Header-shape detection: for a bare positional token of the form
       ``name:value`` where ``name`` looks like an HTTP header name,
       split on the first colon and rerun format/entropy/keyword
       detection against the value half (with ``name`` as the keyword
       context). This catches secrets passed as a single argv token
       (e.g. ``--control-server-H x-client-id:<hex>``), which Pass A
       tends to miss because the header-name prefix dilutes the
       entropy score and Pass B has no separate ``prev`` token to pair
       the value with.
    5. Known-sensitive flag/header name allowlist: redact the value of
       any flag listed in ``_SENSITIVE_FLAG_NAMES`` and any
       ``name:value`` token whose ``name`` is in
       ``_SENSITIVE_HEADER_NAMES``. This catches low-entropy
       credentials (e.g. ``--push-key foo123`` or
       ``--control-server-H x-client-id:short``) that the
       entropy/keyword/header passes cannot detect on shape alone.

    Pass order is format -> entropy -> keyword -> header -> name; the
    most-specific detector wins (later passes skip tokens an earlier
    pass already marked). Pass B is also skipped when ``curr`` looks
    like another CLI flag (starts with ``-``), so ``["--password",
    "--api-key"]`` does not redact the second flag.

    The flag half of a ``--flag=value`` arg is never replaced; only
    the value half (or a bare positional) can be redacted.

    A bare token that happens to contain a secret-shaped substring (e.g.
    a positional ``AKIAIOSFODNN7EXAMPLE`` or even a flag-shaped token
    ``--AKIAIOSFODNN7EXAMPLE`` with no ``=``) is replaced wholesale by
    the marker. This is intentionally conservative: a secret-looking
    token should never appear verbatim in upload payloads, even if it
    masquerades as a CLI flag.
    """
    # Tokenize args into a flat token list with positional metadata.
    # Each token is a tuple (arg_idx, slot, raw, normalized) where
    # slot 0 is the "whole arg" or the flag half of --flag=value,
    # and slot 1 is the value half of --flag=value.
    tokens: list[tuple[int, int, str, str]] = []
    for i, arg in enumerate(args):
        if arg.startswith("-") and "=" in arg:
            flag, _, value = arg.partition("=")
            tokens.append((i, 0, flag, flag.lstrip("-").replace("-", "_")))
            tokens.append((i, 1, value, value.lstrip("-").replace("-", "_")))
        else:
            tokens.append((i, 0, arg, arg.lstrip("-").replace("-", "_")))

    marks: list[str | None] = [None] * len(tokens)

    # Pass A: format + entropy on each token's raw value.
    for t_idx, (_, _, raw, _) in enumerate(tokens):
        triggering_plugin = _detect_secret(raw)
        if triggering_plugin is not None:
            marks[t_idx] = triggering_plugin

    # Pass B: sliding window of 2 for keyword detection.
    for t_idx in range(1, len(tokens)):
        if marks[t_idx] is not None:
            continue
        prev = tokens[t_idx - 1]
        curr = tokens[t_idx]
        if curr[2].startswith("-"):
            # Defensive: skip Pass B when the candidate looks like a CLI flag.
            continue
        triggering_plugin = _detect_keyword(prev[3], curr[2])
        if triggering_plugin is not None:
            marks[t_idx] = triggering_plugin

    # Pass C: header-shape detection on intra-token "name:value" pairs.
    for t_idx, (_, _, raw, _) in enumerate(tokens):
        if marks[t_idx] is not None:
            continue
        if raw.startswith("-"):
            continue
        name, sep, value = raw.partition(":")
        if not sep or not value or not _HEADER_TOKEN_RE.match(name):
            continue
        triggering_plugin = _detect_secret(value)
        if triggering_plugin is None:
            normalized_name = name.replace("-", "_")
            triggering_plugin = _detect_keyword(normalized_name, value)
        if triggering_plugin is not None:
            marks[t_idx] = triggering_plugin

    # Pass D: known-sensitive flag/header name allowlist.
    # Catches low-entropy credentials that the detect-secrets heuristics
    # cannot identify on shape alone, by matching on the flag/header name
    # we already know carries a secret.
    for t_idx, (_arg_idx, slot, raw, _normalized) in enumerate(tokens):
        if marks[t_idx] is not None:
            continue
        # Case 1: value half of --flag=value where flag is sensitive.
        if slot == 1:
            flag_normalized = tokens[t_idx - 1][3]
            if flag_normalized in _SENSITIVE_FLAG_NAMES:
                marks[t_idx] = "SensitiveFlagName"
                continue
        # Case 2: bare token following a sensitive --flag (space-separated).
        if slot == 0 and not raw.startswith("-") and t_idx > 0:
            prev = tokens[t_idx - 1]
            if prev[1] == 0 and prev[2].startswith("-") and prev[3] in _SENSITIVE_FLAG_NAMES:
                marks[t_idx] = "SensitiveFlagName"
                continue
        # Case 3: name:value token where name is a sensitive header.
        if slot == 0 and not raw.startswith("-"):
            name, sep, value = raw.partition(":")
            if sep and value and name.lower() in _SENSITIVE_HEADER_NAMES:
                marks[t_idx] = "SensitiveHeaderName"

    # Reassemble.
    out = list(args)
    # Iterate each token once; for slot-1 tokens we look up the sibling
    # flag (slot 0 of the same arg_idx) directly from args[arg_idx].
    for t_idx, (arg_idx, slot, _raw, _normalized) in enumerate(tokens):
        mark = marks[t_idx]
        if mark is None:
            continue
        if slot == 0:
            # If the original arg had "=" in it, slot 0 is the flag name;
            # never replace the flag name itself.
            original = args[arg_idx]
            if original.startswith("-") and "=" in original:
                continue
            out[arg_idx] = _redaction_marker(mark)
        else:
            # slot == 1: replace only the value half, preserve flag name.
            flag = args[arg_idx].partition("=")[0]
            out[arg_idx] = f"{flag}={_redaction_marker(mark)}"
    return out


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
