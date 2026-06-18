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

from agent_scan.models import RemoteServer, ScanPathResult, ServerScanResult, ServerSignature, StdioServer

logger = logging.getLogger(__name__)

REDACTED = "**REDACTED**"

_PUSH_KEY_CONTEXTS = [
    re.compile(r"(PUSH_KEY=')(.*?)(')", re.IGNORECASE),
    re.compile(r"(-PushKey\s+')(.*?)(')", re.IGNORECASE),
]


_MAX_EXTRA_HEX_DIGITS = 3


def _is_uuid_like(s: str) -> bool:
    """Return True if *s* looks like a (possibly malformed) UUID.

    A well-formed UUID has exactly 32 hex digits.  This helper also matches
    strings with up to ``_MAX_EXTRA_HEX_DIGITS`` additional hex digits mixed
    in, because the original UUID can be recovered by brute-forcing which
    digits to drop (at most C(35, 3) = 6 545 attempts for 3 extra digits).

    Non-hex noise characters (dashes, spaces, underscores, …) are always
    stripped before counting.
    """
    hex_only = re.sub(r"[^0-9a-fA-F]", "", s)
    return 32 <= len(hex_only) <= 32 + _MAX_EXTRA_HEX_DIGITS


def redact_push_keys(text: str, replacement: str = REDACTED) -> str:
    """Redact push-key values in *text*, including malformed UUIDs.

    Recognises two context patterns (``PUSH_KEY='…'`` and ``-PushKey '…'``)
    and replaces the value portion when it looks UUID-like — even when the
    UUID contains noise characters (extra dashes, spaces, underscores, …).
    """
    result = text
    for pattern in _PUSH_KEY_CONTEXTS:

        def _replace(m: re.Match, *, _repl: str = replacement) -> str:
            value = m.group(2)
            if _is_uuid_like(value):
                return m.group(1) + _repl + m.group(3)
            return m.group(0)

        result = pattern.sub(_replace, result)
    return result


def redact_push_keys_in_data(data: dict) -> dict:
    """Deep-traverse *data* and apply :func:`redact_push_keys` to every string value.

    Mutates *data* in place **and** returns it for convenience (same
    contract as :func:`redact_data`).
    """

    def _walk(obj: object) -> None:
        if isinstance(obj, dict):
            for key in obj:
                if isinstance(obj[key], str):
                    obj[key] = redact_push_keys(obj[key])
                else:
                    _walk(obj[key])
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    obj[i] = redact_push_keys(item)
                else:
                    _walk(item)

    _walk(data)
    return data


_EXCLUDED_PLUGINS = frozenset({"IPPublicDetector"})

# Matches the synthetic binary-file marker that ``skill_client`` emits for a
# binary resource (its ``BINARY_FILE_DESCRIPTION_PREFIX`` followed by a sha256
# hex digest). Compiled lazily on first use: the prefix lives in
# ``skill_client``, which imports ``redact_signature`` from this module, so
# importing it at module scope here would create a circular import.
_BINARY_FILE_DESCRIPTION_RE: re.Pattern[str] | None = None


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


def _detect_secret_in_plugins(value: str, plugins: list) -> str | None:
    """Two-pass scan of ``value`` against an already-built ``plugins`` list.

    Each plugin family gets the input format it expects:

    1. Named-format detectors (``AWSKeyDetector``, ``GitHubTokenDetector``,
       etc.) match self-contained format patterns and work on the raw
       value directly.
    2. ``HighEntropyStringsPlugin`` subclasses default to scanning quoted
       string literals (``(['"])(token)(\\1)``); they receive the value
       wrapped as ``"<value>"``, ``'<value>'``, or ``"<escaped>"`` so
       their regex tokenizes the whole value, then the entropy ``limit``
       filter is applied.

    The caller is responsible for holding an active
    ``transient_settings(_DETECT_SECRETS_CONFIG)`` context that ``plugins``
    was built under.
    """
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


def _detect_secret(value: str, plugins: list | None = None) -> str | None:
    """
    Return the class name of the first detect-secrets plugin that flags
    ``value``, or ``None`` if no plugin flags it. See
    :func:`_detect_secret_in_plugins` for the two-pass detection logic.

    When ``plugins`` is supplied, the caller is assumed to already hold an
    active ``transient_settings(_DETECT_SECRETS_CONFIG)`` context (as
    :func:`redact_text` does), so this reuses that plugin set and does NOT
    re-enter the context. Re-entering it per call runs detect-secrets'
    ``cache_bust`` twice each time (~1.3ms), so a per-token caller would be
    O(tokens) in context churn -- tens of seconds for a large bundled script.

    With ``plugins=None`` (the :func:`redact_args` path) it builds and tears
    down its own context per call, exactly as before.
    """
    if not value:
        return None
    if plugins is not None:
        return _detect_secret_in_plugins(value, plugins)
    with transient_settings(_DETECT_SECRETS_CONFIG):
        return _detect_secret_in_plugins(value, list(get_plugins()))


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


# Markup/punctuation that commonly *wraps* a secret in skill docs/code but is
# never part of the secret itself: matched-pair wrappers (quotes, backticks,
# brackets, parens, angle brackets) plus trailing sentence punctuation. Used to
# recover a detectable "core" from a whitespace token whose glued wrappers defeat
# detection (a trailing ``"`` breaks the entropy plugin's quoted-literal regex; a
# leading backtick fails a format detector's boundary class). Deliberately
# excludes ``= + / - _`` (legitimate secret characters); ``.`` is only removed as
# an edge character (``str.strip`` touches the ends only), never internally.
_TOKEN_EDGE_CHARS = "`'\"()[]{}<>.,;:!?"


def _unwrapped_token_core(token: str) -> str | None:
    """Return ``token``'s inner core with wrapping markup/punctuation stripped
    from its edges -- a fresh candidate to re-scan for secrets.

    Returns ``None`` when stripping yields nothing new: either no wrapper was
    present (the core equals ``token``) or the token was all edge characters
    (the core is empty). In both cases the caller has already scanned that exact
    value, so it can skip a redundant re-scan.
    """
    core = token.strip(_TOKEN_EDGE_CHARS)
    return core if core and core != token else None


# Structural delimiters that commonly *separate* a secret from surrounding text
# inside one whitespace token -- URL path/query separators, dotted paths, colon-
# or comma-joined values. When the whole-token and edge-stripped-core scans both
# come up clean, the token is split on these and each segment re-checked, so a
# secret embedded between them is still found. The base64/base64url secret
# characters ``= + _ -`` are deliberately NOT split on, so a real secret that
# contains them is never fragmented. ``/`` is split on despite being a base64
# char: URL-embedded tokens are overwhelmingly base64url/hex/alnum (which never
# contain ``/``), and because this runs only as a fallback it can add coverage
# but never remove what the earlier scans already catch.
_TOKEN_SPLIT_DELIMS = re.compile(r"[/:.,;@?&#|\\]")


def _redact_secrets_in_line(line: str, plugins: list) -> str:
    """Redact secret-bearing substrings within a single line of free text.

    Reuses the detect-secrets plugin set in two complementary passes that each
    preserve the line's surrounding text and whitespace:

    1. Raw-line scan with the high-entropy plugins only. They report the
       *complete* secret value via ``secret_value`` (unlike some format
       detectors -- e.g. the GitHub token detector reports only the ``ghp``
       prefix), so their value is safe to splice out by substring. They fire on
       the quoted forms common in skill code snippets (``key = "value"``).
    2. Whitespace-token scan with :func:`_detect_secret`, which runs format
       detectors on the bare token and entropy detectors on a quote-wrapped
       copy. A whole secret-shaped token (AWS key, GitHub token, bare
       high-entropy string) is therefore replaced wholesale -- no partial
       prefix can leak. The raw token is tried first; when it is not flagged,
       an edge-stripped *core* (see :func:`_unwrapped_token_core`) is tried as a
       fallback, so a secret wrapped in markdown/punctuation (a backtick code
       span, or a trailing ``"`` from a longer quoted string) is still
       detected. Only the matched candidate substring is replaced, so the
       surrounding markup stays intact. When neither the token nor its core is
       flagged, the token is split on structural delimiters
       (see :data:`_TOKEN_SPLIT_DELIMS`) and each segment re-checked, so a
       secret embedded as a URL path/query segment or a dotted/colon-joined
       value is recovered without disturbing the surrounding structure.

    Replacements are applied longest-first so a secret that is a substring of
    another does not corrupt the marker inserted for the longer one.
    """
    replacements: dict[str, str] = {}

    # Pass 1: high-entropy detectors on the raw line (catches quoted literals).
    for plugin in plugins:
        if not isinstance(plugin, HighEntropyStringsPlugin):
            continue
        for secret in plugin.analyze_line(filename="adhoc", line=line, line_number=1) or []:
            value = getattr(secret, "secret_value", None)
            if value:
                replacements.setdefault(value, _redaction_marker(type(plugin).__name__))

    # Pass 2: whole-token detection for format/entropy-shaped tokens. Reuse the
    # caller's already-built ``plugins`` (under its single transient_settings
    # context) so we don't re-enter that context per token. The raw token is
    # tried first (preserving prior behaviour); only when it is not flagged is
    # the edge-stripped core consulted as a fallback.
    for token in line.split():
        core = _unwrapped_token_core(token)
        candidates = [token] if core is None else [token, core]
        handled = False
        for candidate in candidates:
            if candidate in replacements:
                handled = True
                break
            plugin_name = _detect_secret(candidate, plugins)
            if plugin_name is not None:
                replacements[candidate] = _redaction_marker(plugin_name)
                handled = True
                break
        if handled:
            continue
        # Fallback: a secret separated from surrounding text by a structural
        # delimiter (a URL path/query segment, a dotted or colon-joined value)
        # rides along inside one whitespace token and escapes the whole-token
        # scan above. Split on those delimiters and flag each secret-shaped
        # segment; only the matched segment is replaced, so the structure stays.
        for segment in _TOKEN_SPLIT_DELIMS.split(token):
            if not segment or segment in replacements:
                continue
            plugin_name = _detect_secret(segment, plugins)
            if plugin_name is not None:
                replacements[segment] = _redaction_marker(plugin_name)

    redacted = line
    for value in sorted(replacements, key=len, reverse=True):
        redacted = redacted.replace(value, replacements[value])
    return redacted


def redact_text(text: str | None) -> str | None:
    """Redact secrets from a block of free text.

    Used for content read out of skill files (SKILL.md, command markdown,
    bundled scripts, and other resources), which may contain credentials a
    user pasted into a skill.

    Absolute paths are intentionally left intact: skill content is documentation
    and code that legitimately references real paths, and stripping them would
    remove context the downstream analysis relies on. (Path redaction still
    applies to tracebacks and server output via :func:`redact_server` /
    :func:`redact_scan_result`, where paths are noise rather than user content.)

    Detection runs line by line so the plugin set is built once and reused;
    secret values are spliced out in place (see :func:`_redact_secrets_in_line`).
    Returns ``None`` for ``None`` input and the input unchanged when it is empty.
    """
    if not text:
        return text
    with transient_settings(_DETECT_SECRETS_CONFIG):
        plugins = list(get_plugins())
        return "\n".join(_redact_secrets_in_line(line, plugins) for line in text.split("\n"))


def _is_synthetic_binary_description(text: str) -> bool:
    """True if ``text`` is the synthetic binary-file marker emitted for a binary
    skill resource (see ``skill_client.BINARY_FILE_DESCRIPTION_PREFIX``).

    Such a description is self-generated (a fixed prefix + sha256 digest) and
    contains no user content, so it is left untouched by redaction.

    The prefix is imported lazily and the compiled pattern cached, so the
    per-entity redaction path stays off the import and ``skill_client`` (which
    imports :func:`redact_signature` from this module) can own the constant
    without a circular import.
    """
    global _BINARY_FILE_DESCRIPTION_RE
    if _BINARY_FILE_DESCRIPTION_RE is None:
        from agent_scan.skill_client import BINARY_FILE_DESCRIPTION_PREFIX

        _BINARY_FILE_DESCRIPTION_RE = re.compile(rf"^{re.escape(BINARY_FILE_DESCRIPTION_PREFIX)}[0-9a-f]{{64}}$")
    return bool(_BINARY_FILE_DESCRIPTION_RE.match(text))


def redact_signature(signature: ServerSignature) -> ServerSignature:
    """Redact secrets from a (skill) ``ServerSignature`` in place.

    Skill signatures embed raw file contents in their prompt / resource / tool
    ``description`` fields, and the skill's frontmatter description in
    ``metadata.instructions``. Any of these can carry secrets, so every
    free-text field is run through :func:`redact_text` before the signature
    leaves the machine. The one exception is a resource whose description is the
    synthetic binary-file marker (see :func:`_is_synthetic_binary_description`),
    which is left intact so the file's hash digest survives.

    This is the single redaction point for skill content: nothing downstream
    redacts the signature (``redact_scan_result`` / ``redact_server`` only touch
    the server config and errors, never ``.signature``), so it must be sanitized
    here. It runs once when the skill is read (in ``skill_client.inspect_skill``).
    """
    if signature.metadata is not None and signature.metadata.instructions:
        signature.metadata.instructions = redact_text(signature.metadata.instructions)
    for entity in signature.entities:
        if entity.description and not _is_synthetic_binary_description(entity.description):
            entity.description = redact_text(entity.description)
    return signature


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


def redact_data(data: dict, redact_patterns: list[re.Pattern[str]]) -> dict:
    """Deep-traverse a dictionary and apply *redact_patterns* to every string value.

    Each pattern must use a capturing group around the sensitive portion.
    The first capturing group match is replaced with ``**REDACTED**``.

    Lists and nested dicts are traversed recursively.  The original
    *data* dict is mutated in place **and** returned for convenience.
    """

    def _redact_str(s: str) -> str:
        for pat in redact_patterns:

            def _replace(m: re.Match[str]) -> str:
                full = m.group(0)
                start = m.start(1) - m.start(0)
                end = m.end(1) - m.start(0)
                return full[:start] + REDACTED + full[end:]

            s = pat.sub(_replace, s)
        return s

    def _walk(obj: object) -> None:
        if isinstance(obj, dict):
            for key in obj:
                if isinstance(obj[key], str):
                    obj[key] = _redact_str(obj[key])
                else:
                    _walk(obj[key])
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, str):
                    obj[i] = _redact_str(item)
                else:
                    _walk(item)

    _walk(data)
    return data


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
