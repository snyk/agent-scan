"""
Redaction utilities for sanitizing sensitive information from scan results.

This module provides functions to redact sensitive data like:
- Environment variables
- Command line argument values (detected via the detect-secrets library)
- HTTP headers
- URL query parameters
- File paths in tracebacks
"""

import functools
import logging
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from detect_secrets.plugins.high_entropy_strings import HighEntropyStringsPlugin
from detect_secrets.plugins.keyword import KeywordDetector
from detect_secrets.settings import default_settings, get_plugins, transient_settings

from agent_scan.models.errors import ScanError
from agent_scan.models.inspect import InspectedPath, InspectedServer
from agent_scan.models.mcp import RemoteServer, StdioServer

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

# Lazily-built, process-wide cache of the plugin list for _DETECT_SECRETS_CONFIG.
# Plugin instances are self-contained after construction (their regexes/config are
# bound at init -- see _detect_secret's docstring on reusing an already-built
# ``plugins`` list outside its constructing context), so building them once and
# reusing across every redact_text() call is safe. This avoids re-entering
# transient_settings per call: its cache_bust() (on both enter and exit, ~1.3ms
# each) would otherwise run once per redact_text() call, which redact_error_text
# makes twice per failing server (traceback + server_output) -- real overhead
# when a scan has many failing servers.
_CACHED_PLUGINS: list | None = None


def _get_cached_plugins() -> list:
    global _CACHED_PLUGINS
    if _CACHED_PLUGINS is None:
        with transient_settings(_DETECT_SECRETS_CONFIG):
            _CACHED_PLUGINS = list(get_plugins())
    return _CACHED_PLUGINS


def _partition_plugins(plugins: list) -> tuple[list, list]:
    """Split *plugins* into ``(format_detectors, entropy_detectors)``.

    The two families need different handling in the scan loops, so we sort them
    once here. ``entropy_detectors`` are the ``HighEntropyStringsPlugin``
    subclasses; ``format_detectors`` are the rest (AWS, GitHub, etc.). Doing this
    split once means the hot loops can just iterate the family they need, instead
    of calling ``isinstance`` on every plugin for every token which is slow and
    adds up over a large scan.
    """
    entropy = [p for p in plugins if isinstance(p, HighEntropyStringsPlugin)]
    formats = [p for p in plugins if not isinstance(p, HighEntropyStringsPlugin)]
    return formats, entropy


# Process-wide cache of the partitioned plugin lists (see _get_cached_plugins).
_CACHED_PLUGINS_SPLIT: tuple[list, list] | None = None


def _get_cached_plugins_split() -> tuple[list, list]:
    global _CACHED_PLUGINS_SPLIT
    if _CACHED_PLUGINS_SPLIT is None:
        _CACHED_PLUGINS_SPLIT = _partition_plugins(_get_cached_plugins())
    return _CACHED_PLUGINS_SPLIT


def _redaction_marker(plugin_name: str) -> str:
    """Format the redaction marker for a triggering detect-secrets plugin.

    Uses the same ``**...**`` delimiter shape as the ``REDACTED`` constant
    so both marker styles render and grep consistently.
    """
    return f"**REDACTED_SECRET_{plugin_name.upper()}**"


_BEARER_TOKEN_RE = re.compile(r"bearer\s+[\w.\-~+/]+=*", re.IGNORECASE)


def redact_bearer_tokens(text: str | None) -> str | None:
    """Replace ``Bearer <token>`` values with the redaction marker.

    OAuth access tokens are applied at the HTTP transport layer and do not reach
    the captured MCP protocol messages, so this is defense-in-depth for the
    ``server_output`` (and traceback) uploaded on errors — a 401 dump is the one
    place a bearer token could plausibly surface.
    """
    if not text:
        return text
    return _BEARER_TOKEN_RE.sub(f"Bearer {REDACTED}", text)


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


# Longest pure-ASCII-lowercase token (``^[a-z]+$``) safe to skip without running
# any plugin: it matches no format detector (all need a digit/uppercase/special/
# prefix) and no HexHighEntropyString (only [a-f] is hex -> entropy <2.58 < 3.0
# limit). Base64HighEntropyString (limit 4.5) is bounded by log2(len), so a cap
# up to 22 is provably safe; 15 is a conservative margin. A lower cap only skips
# fewer tokens, never one a plugin would flag.
_PROSE_MAX_LEN = 15


def _could_be_secret(value: str) -> bool:
    """Cheap O(len) pre-filter: ``True`` for every value any plugin could flag,
    ``False`` only for short pure-ASCII-lowercase tokens (see
    :data:`_PROSE_MAX_LEN`), which dominate prose/code and match no detector.

    Must never reject a value that would match, or a secret leaks; passing
    through a non-match is fine (it just falls to the full scan).
    """
    return (
        len(value) > _PROSE_MAX_LEN  # long enough to reach a high-entropy threshold
        or not value.isalpha()  # has a digit, separator, or other non-letter
        or not value.islower()  # has an uppercase letter (or no cased letters at all)
        or not value.isascii()  # has a non-ASCII character
    )


def _detect_secret_in_plugins(value: str, format_plugins: list, entropy_plugins: list) -> str | None:
    """Two-pass scan of ``value`` against pre-partitioned plugin lists.

    Each plugin family gets the input format it expects:

    1. ``format_plugins`` -- named-format detectors (``AWSKeyDetector``,
       ``GitHubTokenDetector``, etc.) match self-contained format patterns and
       work on the raw value directly.
    2. ``entropy_plugins`` -- ``HighEntropyStringsPlugin`` subclasses default to
       scanning quoted string literals (``(['"])(token)(\\1)``); they receive the
       value wrapped as ``"<value>"``, ``'<value>'``, or ``"<escaped>"`` so their
       regex tokenizes the whole value, then the entropy ``limit`` filter applies.

    Callers pass the split from :func:`_partition_plugins` (usually the cached
    :func:`_get_cached_plugins_split`) so the per-value hot loop does zero
    ``isinstance`` work. The caller is responsible for holding an active
    ``transient_settings(_DETECT_SECRETS_CONFIG)`` context the plugins were built
    under.
    """
    # Cheap pre-filter: skip the full plugin battery for values that provably
    # match nothing (see :func:`_could_be_secret`). Conservative -- never
    # rejects a value a plugin would flag -- so output is unchanged.
    if not _could_be_secret(value):
        return None
    # Pass 1: format-based named detectors on the bare value.
    for plugin in format_plugins:
        if plugin.analyze_line(filename="adhoc", line=value, line_number=1):
            return type(plugin).__name__
    # Pass 2: entropy plugins on the quote-wrapped value.
    wrapped = _wrap_for_entropy(value)
    for plugin in entropy_plugins:
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
        return _detect_secret_in_plugins(value, *_partition_plugins(plugins))
    with transient_settings(_DETECT_SECRETS_CONFIG):
        return _detect_secret_in_plugins(value, *_partition_plugins(list(get_plugins())))


@functools.lru_cache(maxsize=200_000)
def _detect_secret_cached(value: str) -> str | None:
    """Cache _detect_secret_in_plugins results by token value.

    Skill text repeats the same tokens (prose words, punctuation, keywords)
    thousands of times per run. Detection depends only on the token and the
    fixed plugin set (_get_cached_plugins), so the result is the same
    every time caching by value skips the repeated work without changing output.
    """
    return _detect_secret_in_plugins(value, *_get_cached_plugins_split())


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

    Positional environment assignments are parsed first so their name and
    separator are never treated as secret material. Their value is processed
    by the same syntax-preserving assignment path used for free text. All
    other arguments enter five detection passes against a tokenized view
    (each ``--flag=value`` arg yields two tokens; everything else yields one):

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
    out = list(args)
    assignment_entropy_plugins: list | None = None
    assignments: dict[int, re.Match] = {}

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
            assignment = _ENV_ASSIGNMENT_RE.fullmatch(arg)
            if assignment is not None:
                if assignment_entropy_plugins is None:
                    _, assignment_entropy_plugins = _get_cached_plugins_split()
                out[i] = _redact_assignment(assignment, assignment_entropy_plugins)
                assignments[i] = assignment
                _, value, _ = _split_assignment_value(assignment.group("value"))
                # The value core participates in the ordinary token passes so
                # a preceding flag can still provide keyword/sensitive-name
                # context. Reassembly below restores the assignment syntax.
                tokens.append((i, 0, value, value.lstrip("-").replace("-", "_")))
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
    # Iterate each token once; for slot-1 tokens we look up the sibling
    # flag (slot 0 of the same arg_idx) directly from args[arg_idx].
    for t_idx, (arg_idx, slot, _raw, _normalized) in enumerate(tokens):
        mark = marks[t_idx]
        if mark is None:
            continue
        if arg_idx in assignments:
            assert assignment_entropy_plugins is not None
            out[arg_idx] = _redact_assignment(assignments[arg_idx], assignment_entropy_plugins, triggering_plugin=mark)
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

# Shell-style environment assignments may use horizontal whitespace around
# ``=`` and may quote a value containing spaces. Named groups retain the exact
# separator and value spelling so redaction can replace only the value content.
# The left boundary excludes URL/query/path punctuation, avoiding matches such
# as the ``token=...`` portion of a URL. ``(?![=])`` excludes comparison-like
# ``NAME==value`` text.
_ENV_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_?&./:-])"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<separator>[ \t]*=[ \t]*)(?![=])"
    r'(?P<value>"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[^\s]*)'
)


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


def _split_assignment_value(value: str) -> tuple[str, str, str]:
    """Return an assignment value's leading wrapper, core, and trailing wrapper."""
    if len(value) >= 2 and value[0] in {'"', "'"} and value[-1] == value[0]:
        return value[0], value[1:-1], value[-1]

    core = value.strip(_TOKEN_EDGE_CHARS)
    if not core:
        return value, "", ""
    core_start = value.find(core)
    core_end = core_start + len(core)
    return value[:core_start], core, value[core_end:]


def _redact_assignment(
    assignment: re.Match,
    entropy_plugins: list,
    triggering_plugin: str | None = None,
) -> str:
    """Redact only the value content of a parsed environment assignment."""
    name = assignment.group("name")
    separator = assignment.group("separator")
    value = assignment.group("value")
    leading, core, trailing = _split_assignment_value(value)

    plugin_name = triggering_plugin or _detect_secret_cached(core)
    if plugin_name is None:
        plugin_name = _detect_keyword(name, core)

    if plugin_name is not None:
        redacted_core = _redaction_marker(plugin_name)
    else:
        redacted_core = _redact_non_assignment_text(core, entropy_plugins)

    return f"{name}{separator}{leading}{redacted_core}{trailing}"


def _redact_non_assignment_text(text: str, entropy_plugins: list) -> str:
    """Redact secrets in text known not to contain an environment assignment."""
    if not text:
        return text

    replacements: dict[str, str] = {}

    # Pass 1: high-entropy detectors on the raw text (catches quoted literals).
    for plugin in entropy_plugins:
        for secret in plugin.analyze_line(filename="adhoc", line=text, line_number=1) or []:
            value = getattr(secret, "secret_value", None)
            if value:
                replacements.setdefault(value, _redaction_marker(type(plugin).__name__))

    # Pass 2: whole-token detection for format/entropy-shaped tokens. The raw
    # token is tried first; only when it is not flagged is its edge-stripped
    # core consulted as a fallback.
    for token in text.split():
        core = _unwrapped_token_core(token)
        candidates = [token] if core is None else [token, core]
        handled = False
        for candidate in candidates:
            if candidate in replacements:
                handled = True
                break
            plugin_name = _detect_secret_cached(candidate)
            if plugin_name is not None:
                replacements[candidate] = _redaction_marker(plugin_name)
                handled = True
                break
        if handled:
            continue
        # A secret separated from surrounding text by a structural delimiter
        # can escape whole-token detection. Re-scan each segment and replace
        # only the segment so the surrounding structure stays intact.
        for segment in _TOKEN_SPLIT_DELIMS.split(token):
            if not segment or segment in replacements:
                continue
            plugin_name = _detect_secret_cached(segment)
            if plugin_name is not None:
                replacements[segment] = _redaction_marker(plugin_name)

    redacted = text
    for value in sorted(replacements, key=len, reverse=True):
        redacted = redacted.replace(value, replacements[value])
    return redacted


def _redact_secrets_in_line(line: str, entropy_plugins: list) -> str:
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
       copy. Shell-style ``NAME=value`` assignments are split first: only the
       value is entropy-scanned, while the name supplies keyword context. A
       whole non-assignment secret-shaped token (AWS key, GitHub token, bare
       high-entropy string) is replaced wholesale -- no partial prefix can
       leak. The raw token is tried first; when it is not flagged, an
       edge-stripped *core* (see :func:`_unwrapped_token_core`) is tried as a
       fallback, so a secret wrapped in markdown/punctuation (a backtick code
       span, or a trailing ``"`` from a longer quoted string) is still
       detected. Only the matched candidate substring is replaced, so the
       surrounding markup stays intact. When neither the token nor its core is
       flagged, the token is split on structural delimiters
       (see :data:`_TOKEN_SPLIT_DELIMS`) and each segment re-checked, so a
       secret embedded as a URL path/query segment or a dotted/colon-joined
       value is recovered without disturbing the surrounding structure.

    Environment assignments are parsed before these passes. Only their value
    content is scanned; whitespace, quotes, and wrapping punctuation are kept
    byte-for-byte. Non-assignment spans retain the general detection behavior.
    """
    parts: list[str] = []
    cursor = 0
    for assignment in _ENV_ASSIGNMENT_RE.finditer(line):
        parts.append(_redact_non_assignment_text(line[cursor : assignment.start()], entropy_plugins))
        parts.append(_redact_assignment(assignment, entropy_plugins))
        cursor = assignment.end()
    parts.append(_redact_non_assignment_text(line[cursor:], entropy_plugins))
    return "".join(parts)


def redact_text(text: str | None) -> str | None:
    """Redact secrets from a block of free text.

    Used for content read out of skill files (SKILL.md, command markdown,
    bundled scripts, and other resources), which may contain credentials a
    user pasted into a skill.

    Absolute paths are intentionally left intact: skill content is documentation
    and code that legitimately references real paths, and stripping them would
    remove context the downstream analysis relies on. Error paths are sanitized
    separately at the API boundary, where they are noise rather than user content.

    Detection runs line by line against the process-wide cached plugin set (see
    :func:`_get_cached_plugins`); secret values are spliced out in place (see
    :func:`_redact_secrets_in_line`). Returns ``None`` for ``None`` input and the
    input unchanged when it is empty.
    """
    if not text:
        return text
    _, entropy_plugins = _get_cached_plugins_split()
    return "\n".join(_redact_secrets_in_line(line, entropy_plugins) for line in text.split("\n"))


def redact_error_text(text: str | None) -> str | None:
    """Redact a traceback or captured server output string.

    These fields are diagnostic noise, not user content, so absolute paths,
    secret-shaped values, and bearer tokens are all stripped: a traceback can
    embed a local filesystem layout, and captured protocol traffic / stderr
    (``server_output``) can echo back a header, token, or other secret a
    misbehaving server included in its response -- a 401 dump is the one place
    an OAuth bearer token could plausibly surface, since tokens are applied at
    the HTTP transport layer and don't otherwise reach captured MCP protocol
    messages. Paths are stripped first so the subsequent detect-secrets pass
    runs over already-shortened text.
    """
    return redact_bearer_tokens(redact_text(redact_absolute_paths(text)))


def redact_server_config(server: StdioServer | RemoteServer) -> StdioServer | RemoteServer:
    """Redact sensitive values from an MCP server configuration in place."""
    if isinstance(server, StdioServer):
        # Redact all environment variables
        if server.env:
            server.env = dict.fromkeys(server.env, REDACTED)
        # Redact argument values via detect-secrets (plugin-named markers).
        if server.args:
            server.args = redact_args(server.args)

    elif isinstance(server, RemoteServer):
        # Redact all headers
        if server.headers:
            server.headers = dict.fromkeys(server.headers, REDACTED)
        # Redact all query parameter values in the URL
        try:
            parts = urlsplit(server.url)
            if parts.query:
                qs = parse_qsl(parts.query)
                redacted_qs = [(key, REDACTED) for key, _value in qs]
                new_query = urlencode(redacted_qs)
                server.url = urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
        except Exception:
            logger.error("Failed to redact URL: %s", server.url)

    return server


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


def _redact_scan_error_in_place(error: ScanError | None) -> None:
    """Redact the traceback and server output of a ``ScanError`` in place.

    Only these two fields are touched: they are diagnostic noise (a local
    filesystem layout, captured stderr/protocol traffic), not user content,
    so they are safe to sanitize with :func:`redact_error_text`. ``message``
    and ``exception`` are left as-is here, matching the analyze/push API
    boundary's own error sanitization in ``models/api/v20260710.py``.
    """
    if error is None:
        return
    error.traceback = redact_error_text(error.traceback)
    error.server_output = redact_error_text(error.server_output)


def redact_inspected_server(inspected: InspectedServer) -> InspectedServer:
    """Redact sensitive values from one ``InspectedServer`` in place.

    Redacts the server config (env/args/headers/URL query params, via
    :func:`redact_server_config`) and the server-level error's traceback and
    server output.
    """
    redact_server_config(inspected.server)
    _redact_scan_error_in_place(inspected.error)
    return inspected


def redact_inspected_path(path: InspectedPath) -> InspectedPath:
    """Redact sensitive information from an ``InspectedPath`` in place.

    ``mcp-scan inspect`` prints/dumps ``InspectedPath`` results directly,
    without going through the analyze/push pipeline's API-boundary
    sanitization (``_server_for_request`` / ``_error_for_request`` in
    ``models/api/v20260710.py``). This applies the equivalent local
    redaction so every caller of ``inspect_pipeline`` -- both `mcp-scan
    scan` and `mcp-scan inspect` -- gets sanitized results.
    """
    _redact_scan_error_in_place(path.error)
    for server in path.servers:
        redact_inspected_server(server)
    return path
