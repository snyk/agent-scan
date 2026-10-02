"""Extraction of MCP servers that a VS Code *extension* registers in code.

Unlike an extension that merely drops an ``mcp.json`` on disk (handled by the
``_discover_extension_mcp_servers`` walk), an extension can register servers
through the VS Code API. That path leaves two traces:

1. A **declaration** in ``package.json`` under
   ``contributes.mcpServerDefinitionProviders`` — an ``{id, label}`` entry per
   provider. VS Code requires this static declaration before the extension may
   call ``vscode.lm.registerMcpServerDefinitionProvider``, so it is a reliable,
   cheap gate: an extension without it ships no code-registered MCP server.
   https://code.visualstudio.com/api/extension-guides/ai/mcp#register-an-mcp-server-in-your-extension

2. The **definitions themselves**, constructed in the extension's JavaScript as
   ``new vscode.McpStdioServerDefinition(label, command, args, env, version)``
   or ``new vscode.McpHttpServerDefinition(label, uri, headers, version)``.
   https://code.visualstudio.com/api/extension-guides/ai/mcp#2.-implement-the-provider

Shipped extension code is bundled and minified, so there is no config file to
parse — the server is only visible in the JS. This module therefore does a
*static, best-effort* extraction: locate each constructor call and evaluate the
arguments that are literals (strings, template literals, arrays, object
literals, ``Uri.parse("...")``). Anything computed at runtime is left
unresolved rather than guessed.

Known limits, all of them *under*-reporting rather than over-reporting:

* A constructor reached only through a renamed/destructured binding (so the
  class name no longer appears at the call site) is not found. Bundlers keep
  ``vscode.McpXServerDefinition`` as a property access, so this is rare.
* Values assembled at runtime are not resolved. A template literal keeps its
  ``${...}`` holes verbatim (e.g. Pylance's ``http://localhost:${n}/stream``,
  whose port is picked at activation), which is the honest rendering: the
  server exists, its address is dynamic.
* Fields set by assignment after construction (``def.headers.authorization = …``)
  are not picked up; only constructor arguments are read.
"""

import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ``contributes.mcpServerDefinitionProviders`` is the manifest key VS Code reads.
_PROVIDERS_KEY = "mcpServerDefinitionProviders"

# Suffixes of the bundle files worth grepping. ``main`` in package.json names the
# entry point, but larger extensions split activation code across lazily-imported
# chunks, so the whole extension tree is walked (entry point first).
_JS_SUFFIXES = (".js", ".cjs", ".mjs")

# Only these two classes exist in the API. Both are matched in one pass so a file
# is read once.
_DEFINITION_RE = re.compile(r"\bMcp(Stdio|Http)ServerDefinition\s*\(")

# Don't read a single bundle larger than this into memory. Pylance's biggest
# chunk is ~6 MiB; extension trees under ``--scan-all-users`` are
# attacker-influenceable, so an oversized file is skipped rather than parsed.
_MAX_JS_FILE_BYTES = 16 * 1024 * 1024
# Cap the per-extension walk so a pathological tree can't stall discovery.
_MAX_JS_FILES_PER_EXTENSION = 2000
_MAX_JS_WALK_DEPTH = 12
# A constructor call spans a few hundred characters even minified. Give up on
# one whose argument list doesn't close within this window — that means the
# scanner desynchronized (most likely on a regex literal, which is not
# distinguishable from division without a full JS parse).
_MAX_CALL_SCAN_CHARS = 16 * 1024
# Stop after this many constructor calls in one file. A real extension registers
# a handful (Pylance: one), so this only ever bites a file crafted to be
# expensive: without it, a bundle repeating the class name tens of thousands of
# times costs one full ``_MAX_CALL_SCAN_CHARS`` window *each*, and the per-call
# bound alone leaves the total unbounded.
_MAX_DEFINITIONS_PER_FILE = 256

# ``new <ns>.Uri.parse(<expr>)`` / ``Uri.file(<expr>)`` wrap the real URL in the
# HTTP definition's second argument.
_URI_FACTORY_RE = re.compile(r"^(?:[\w$]+\.)*Uri\s*\.\s*(?:parse|file)\s*\(")

_SIMPLE_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "0": "\0",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "`": "`",
    "\n": "",  # line continuation
}


def provider_declarations(manifest: dict) -> list[dict]:
    """The ``mcpServerDefinitionProviders`` entries declared in an extension manifest.

    Read from ``contributes`` (where VS Code defines the contribution point) and
    also accepted at the top level, so a hand-written or trimmed manifest still
    registers. Non-dict entries are dropped; the list is returned as-is
    otherwise, since only ``id`` and ``label`` are consumed.
    """
    for container in (manifest.get("contributes"), manifest):
        if not isinstance(container, dict):
            continue
        declared = container.get(_PROVIDERS_KEY)
        if isinstance(declared, list):
            return [entry for entry in declared if isinstance(entry, dict)]
    return []


def extension_js_files(extension_dir: Path, manifest: dict) -> list[Path]:
    """Candidate JS bundles inside one extension, entry point first.

    ``main`` in package.json is the activation entry point and holds the provider
    registration in most extensions, so it leads. It is not sufficient on its own
    — bundlers split lazily-imported code into sibling chunks — so the rest of the
    extension tree follows in walk order, deduplicated against the entry point.
    """
    found: list[Path] = []
    seen: set[Path] = set()

    main = manifest.get("main")
    if isinstance(main, str) and main:
        # ``main`` is extension-relative (``./dist/extension.bundle.js``). Confine
        # it to the extension dir: the manifest is attacker-influenceable under
        # ``--scan-all-users`` and must not redirect the read elsewhere.
        candidate = Path(os.path.normpath(extension_dir / main))
        if candidate.is_relative_to(extension_dir):
            try:
                if candidate.is_file():
                    found.append(candidate)
                    seen.add(candidate)
            except OSError:
                pass

    try:
        for root_str, dirs, files in os.walk(extension_dir):
            root = Path(root_str)
            if len(root.relative_to(extension_dir).parts) + 1 >= _MAX_JS_WALK_DEPTH:
                dirs.clear()
            for name in files:
                if not name.endswith(_JS_SUFFIXES):
                    continue
                path = root / name
                if path in seen:
                    continue
                seen.add(path)
                found.append(path)
                if len(found) >= _MAX_JS_FILES_PER_EXTENSION:
                    return found
    except (PermissionError, OSError, ValueError):
        logger.warning("Skipping unreadable extension tree %s", extension_dir.as_posix())
    return found


def servers_in_js_file(path: Path) -> list[tuple[str, dict]]:
    """Statically-resolvable MCP servers constructed in one JS file.

    Returns ``(name, raw server config)`` pairs in the raw dict shape the
    discoverer's ``_validate_servers`` consumes, so these entries go through the
    same validation and binary-signature checks as file-based configs. Empty when
    the file holds no constructor call, is unreadable, or every call is too
    dynamic to resolve.
    """
    text = _read_text(path)
    if text is None:
        return []
    servers: list[tuple[str, dict]] = []
    for seen, match in enumerate(_DEFINITION_RE.finditer(text)):
        if seen >= _MAX_DEFINITIONS_PER_FILE:
            logger.warning("Stopping after %d MCP definition calls in %s", _MAX_DEFINITIONS_PER_FILE, path.as_posix())
            break
        args = _split_call_args(text, match.end() - 1)
        if args is None:
            logger.debug("Unparseable MCP definition call at %s:%d", path.as_posix(), match.start())
            continue
        entry = _server_from_args(match.group(1), args)
        if entry is not None:
            servers.append(entry)
    return servers


def _read_text(path: Path) -> str | None:
    """Read a JS bundle, or ``None`` if it is absent, oversized, or unreadable.

    Only files actually containing a definition class name are decoded — the
    substring probe runs on bytes, so the common case (a chunk with no MCP code)
    costs a read and a scan rather than a decode of several MiB.
    """
    try:
        if path.stat().st_size > _MAX_JS_FILE_BYTES:
            logger.debug("Skipping oversized extension bundle %s", path.as_posix())
            return None
        raw = path.read_bytes()
    except (PermissionError, OSError, ValueError):
        logger.debug("Skipping unreadable extension bundle %s", path.as_posix())
        return None
    if b"ServerDefinition" not in raw:
        return None
    return raw.decode("utf-8", errors="replace")


def _server_from_args(kind: str, args: list[str]) -> tuple[str, dict] | None:
    """Build a ``(name, raw config)`` pair from one constructor's argument sources.

    Argument order follows the API:
    ``McpStdioServerDefinition(label, command, args?, env?, version?)`` and
    ``McpHttpServerDefinition(label, uri, headers?, version?)``.

    Returns ``None`` when the argument that *identifies* the server (the command
    or the URI) is computed at runtime — without it there is nothing to report
    beyond the manifest declaration the caller already has.
    """
    label = _js_string(args[0]) if args else None
    if kind == "Stdio":
        command = _js_string(args[1]) if len(args) > 1 else None
        if not command:
            return None
        config: dict[str, Any] = {"command": command, "type": "stdio"}
        argv = _js_string_array(args[2]) if len(args) > 2 else None
        if argv:
            config["args"] = argv
        env = _js_string_object(args[3]) if len(args) > 3 else None
        if env:
            config["env"] = env
        return (label or command, config)

    url = _js_string(_unwrap_uri(args[1])) if len(args) > 1 else None
    if not url:
        return None
    # ``McpHttpServerDefinition`` is VS Code's Streamable HTTP transport; it has
    # no SSE variant, so the type is fixed rather than sniffed from the URL.
    config = {"url": url, "type": "http"}
    headers = _js_string_object(args[2]) if len(args) > 2 else None
    if headers:
        config["headers"] = headers
    return (label or url, config)


def _unwrap_uri(expr: str) -> str:
    """Peel a ``Uri.parse(...)`` / ``Uri.file(...)`` wrapper off the HTTP
    definition's URI argument, returning the inner expression source.

    The API types that argument as ``vscode.Uri``, so at the call site it is
    virtually always one of these factories. A bare variable (``u``) is returned
    unchanged and fails to resolve downstream, as it should.
    """
    stripped = expr.strip()
    match = _URI_FACTORY_RE.match(stripped)
    if match is None:
        return stripped
    inner = _split_call_args(stripped, match.end() - 1)
    return inner[0] if inner else stripped


# --- static evaluation of JS literal expressions ---


def _js_string(expr: str) -> str | None:
    """The value of ``expr`` if it is a single string or template literal, else ``None``.

    A template literal keeps its ``${...}`` holes verbatim: the surrounding text
    is the part we know, and blanking the hole would fabricate an address that
    never exists. Concatenations (``"a" + b``) and every other expression form
    are unresolved — the literal must span the *whole* expression, so ``'a'+'b'``
    is rejected rather than silently read as ``a``.
    """
    stripped = expr.strip()
    if not stripped or stripped[0] not in "'\"`":
        return None
    end = _skip_string(stripped, 0, len(stripped))
    if end != len(stripped):
        return None
    return _unescape(stripped[1:-1])


def _js_string_array(expr: str) -> list[str] | None:
    """The elements of ``expr`` if it is an array literal of resolvable strings.

    All-or-nothing: one computed element (``[script, port]``) yields ``None``
    rather than a partial list, because a half-reported argv reads as the real
    one and would misrepresent how the server is launched.
    """
    stripped = expr.strip()
    if not (stripped.startswith("[") and stripped.endswith("]")):
        return None
    elements = _split_call_args(stripped, 0, closing="]")
    if elements is None:
        return None
    values: list[str] = []
    for element in elements:
        value = _js_string(element)
        if value is None:
            return None
        values.append(value)
    return values


def _js_string_object(expr: str) -> dict[str, str] | None:
    """``expr`` as a ``{key: "value"}`` map, or ``None`` if it isn't fully static.

    Keys may be identifiers, string literals, or numbers; values must resolve to
    strings. VS Code allows numeric and ``null`` env values, so a number is
    stringified and a ``null`` entry dropped (it means "unset this variable").
    Anything else — a spread, a computed key, a method — yields ``None``, by the
    same all-or-nothing reasoning as :func:`_js_string_array`.
    """
    stripped = expr.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    entries = _split_call_args(stripped, 0, closing="}")
    if entries is None:
        return None
    result: dict[str, str] = {}
    for entry in entries:
        key_source, _, value_source = entry.partition(":")
        if not value_source:
            return None
        key = _object_key(key_source)
        if key is None:
            return None
        value_stripped = value_source.strip()
        if value_stripped == "null" or value_stripped == "undefined":
            continue
        value = _js_string(value_source)
        if value is None:
            if not _NUMBER_RE.fullmatch(value_stripped):
                return None
            value = value_stripped
        result[key] = value
    return result


_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][\w$]*")
_NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")


def _object_key(source: str) -> str | None:
    """An object literal's key as text, or ``None`` for a computed/invalid one."""
    stripped = source.strip()
    if not stripped:
        return None
    if stripped[0] in "'\"`":
        return _js_string(stripped)
    if _IDENTIFIER_RE.fullmatch(stripped) or _NUMBER_RE.fullmatch(stripped):
        return stripped
    return None


def _unescape(source: str) -> str:
    r"""Resolve backslash escapes in a literal's body, preserving ``${...}``.

    Handles the simple escapes plus ``\xNN`` / ``\uNNNN`` / ``\u{...}``; an
    unrecognized escape yields the escaped character itself, which is what
    JavaScript does. ``${`` is deliberately left untouched — see :func:`_js_string`.
    """
    if "\\" not in source:
        return source
    out: list[str] = []
    i = 0
    while i < len(source):
        char = source[i]
        if char != "\\" or i + 1 >= len(source):
            out.append(char)
            i += 1
            continue
        nxt = source[i + 1]
        if nxt in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[nxt])
            i += 2
            continue
        if nxt in "xu":
            decoded, consumed = _unescape_code_point(source, i)
            if decoded is not None:
                out.append(decoded)
                i += consumed
                continue
        out.append(nxt)
        i += 2
    return "".join(out)


def _unescape_code_point(source: str, start: int) -> tuple[str | None, int]:
    """Decode ``\\xNN``/``\\uNNNN``/``\\u{...}`` at ``start``; ``(None, 0)`` if malformed."""
    kind = source[start + 1]
    body_start = start + 2
    if kind == "u" and source[body_start : body_start + 1] == "{":
        close = source.find("}", body_start)
        if close == -1:
            return None, 0
        digits = source[body_start + 1 : close]
        consumed = close + 1 - start
    else:
        width = 2 if kind == "x" else 4
        digits = source[body_start : body_start + width]
        consumed = width + 2
    try:
        return chr(int(digits, 16)), consumed
    except ValueError:
        return None, 0


# --- source-level scanning (no JS parse) ---


def _skip_string(source: str, start: int, limit: int) -> int:
    """Index just past the string/template literal opening at ``start``, or ``-1``
    if it is not closed before ``limit``.

    The ``-1`` matters: an unterminated literal is reported rather than folded
    into ``limit``, so ``_js_string`` can't read ``"unterminated`` as the value
    ``unterminate`` (its end-of-expression check would otherwise pass).
    Template substitutions are skipped as balanced ``${...}`` regions so a nested
    literal inside one (`` `a${b("`")}c` ``) doesn't end the scan early.

    ``limit`` is mandatory rather than defaulted to ``len(source)`` because this
    runs once per constructor call in a file an attacker may have planted
    (``--scan-all-users``). Scanning to end-of-file here would make the whole
    pass quadratic: a bundle repeating ``McpStdioServerDefinition("`` with the
    string never closed costs one full-file scan *per occurrence*.
    """
    quote = source[start]
    i = start + 1
    while i < limit:
        char = source[i]
        if char == "\\":
            i += 2
            continue
        if char == quote:
            return i + 1
        if quote == "`" and char == "$" and source[i + 1 : i + 2] == "{":
            i = _skip_balanced(source, i + 1, limit)
            continue
        i += 1
    return -1


def _skip_balanced(source: str, start: int, limit: int) -> int:
    """Index just past the ``{``-opened region at ``start``, nesting-aware.

    Returns ``limit`` for a region left open, which ends the enclosing scan
    rather than restarting it — see :func:`_skip_string` on why the bound is
    mandatory.
    """
    depth = 0
    i = start
    while i < limit:
        char = source[i]
        if char in "'\"`":
            nxt = _skip_string(source, i, limit)
            if nxt < 0:
                break
            i = nxt
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return limit


_OPENERS = {"(": ")", "[": "]", "{": "}"}


def _split_call_args(source: str, open_index: int, closing: str = ")") -> list[str] | None:
    """Split the bracketed group opening at ``open_index`` into its top-level items.

    Used for both call arguments (``closing=")"``) and array/object literals.
    Returns the *source text* of each item — evaluation is the caller's job — or
    ``None`` if the group doesn't close within :data:`_MAX_CALL_SCAN_CHARS`.
    That bound also contains the one case this scanner cannot handle: a regex
    literal, indistinguishable from division without parsing the whole file, may
    desynchronize the bracket depth, and the cap turns that into a skipped
    definition rather than a runaway scan.

    An empty group (``()``) yields ``[]``, not ``[""]``, so argument-count checks
    upstream stay honest.
    """
    items: list[str] = []
    item_start = open_index + 1
    depth = 0
    i = open_index
    limit = min(len(source), open_index + _MAX_CALL_SCAN_CHARS)
    while i < limit:
        char = source[i]
        if char in "'\"`":
            nxt = _skip_string(source, i, limit)
            if nxt < 0:
                return None
            i = nxt
            continue
        if char == "/" and source[i + 1 : i + 2] in ("/", "*"):
            i = _skip_comment(source, i, limit)
            continue
        if char in _OPENERS:
            depth += 1
            i += 1
            continue
        if char in ")]}":
            depth -= 1
            if depth == 0:
                if char != closing:
                    return None
                items.append(source[item_start:i])
                return [] if len(items) == 1 and not items[0].strip() else items
            i += 1
            continue
        if char == "," and depth == 1:
            items.append(source[item_start:i])
            item_start = i + 1
        i += 1
    return None


def _skip_comment(source: str, start: int, limit: int) -> int:
    """Index just past the comment opening at ``start``, clamped to ``limit``.

    The clamp keeps an unterminated ``/*`` from costing a scan to end-of-file per
    occurrence — the same quadratic exposure described in :func:`_skip_string`.
    ``str.find`` is given an explicit end so the search itself stays bounded,
    not just its result.
    """
    if source[start + 1] == "/":
        end = source.find("\n", start, limit)
        return limit if end == -1 else min(end + 1, limit)
    end = source.find("*/", start + 2, limit)
    return limit if end == -1 else min(end + 2, limit)
