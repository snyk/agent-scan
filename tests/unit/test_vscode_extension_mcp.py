"""Tests for static extraction of code-registered MCP servers from VS Code extensions.

The companion end-to-end tests (extension dir -> ``discover_mcp_servers``) live in
``test_agent_discovery.py``; this module covers the JS-source scanner itself,
where the interesting edge cases are.
"""

from pathlib import Path

import pytest

from agent_scan.agents.vscode.extension_mcp import (
    _js_string,
    _js_string_array,
    _js_string_object,
    _split_call_args,
    extension_js_files,
    provider_declarations,
    servers_in_js_file,
)


def _write_js(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "bundle.js"
    path.write_text(source)
    return path


# --- manifest declaration gate ---


def test_provider_declarations_read_from_contributes():
    manifest = {"contributes": {"mcpServerDefinitionProviders": [{"id": "pylanceMcp", "label": "pylance mcp server"}]}}

    assert provider_declarations(manifest) == [{"id": "pylanceMcp", "label": "pylance mcp server"}]


def test_provider_declarations_accepts_top_level_key():
    """A trimmed/hand-written manifest that omits the ``contributes`` wrapper still registers."""
    assert provider_declarations({"mcpServerDefinitionProviders": [{"id": "x"}]}) == [{"id": "x"}]


def test_provider_declarations_empty_without_key():
    assert provider_declarations({"contributes": {"commands": []}}) == []


def test_provider_declarations_drops_non_dict_entries():
    manifest = {"contributes": {"mcpServerDefinitionProviders": ["bogus", {"id": "ok"}]}}

    assert provider_declarations(manifest) == [{"id": "ok"}]


# --- candidate bundle enumeration ---


def test_extension_js_files_puts_main_entry_point_first(tmp_path):
    """``main`` leads because it holds the registration in most extensions, but the
    rest of the tree still follows — bundlers split activation code into chunks."""
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "extension.bundle.js").write_text("")
    (tmp_path / "dist" / "chunk.js").write_text("")
    (tmp_path / "other.js").write_text("")

    found = extension_js_files(tmp_path, {"main": "./dist/extension.bundle.js"})

    assert found[0] == tmp_path / "dist" / "extension.bundle.js"
    assert set(found) == {
        tmp_path / "dist" / "extension.bundle.js",
        tmp_path / "dist" / "chunk.js",
        tmp_path / "other.js",
    }


def test_extension_js_files_ignores_main_escaping_the_extension_dir(tmp_path):
    """``main`` is attacker-influenceable under ``--scan-all-users``; a traversing
    value must not pull a file from outside the extension into the scan."""
    outside = tmp_path / "outside.js"
    outside.write_text("")
    ext = tmp_path / "ext"
    ext.mkdir()

    assert extension_js_files(ext, {"main": "../outside.js"}) == []


def test_extension_js_files_skips_non_js(tmp_path):
    (tmp_path / "readme.md").write_text("")
    (tmp_path / "a.mjs").write_text("")
    (tmp_path / "b.cjs").write_text("")

    assert {p.name for p in extension_js_files(tmp_path, {})} == {"a.mjs", "b.cjs"}


# --- stdio definitions ---


def test_stdio_definition_fully_static(tmp_path):
    js = _write_js(
        tmp_path,
        'let d = new vscode.McpStdioServerDefinition("my server", "node", ["server.js", "--stdio"], {"TOKEN": "abc"});',
    )

    assert servers_in_js_file(js) == [
        ("my server", {"command": "node", "type": "stdio", "args": ["server.js", "--stdio"], "env": {"TOKEN": "abc"}}),
    ]


def test_stdio_definition_minified_namespace(tmp_path):
    """Bundlers rename the ``vscode`` import but keep the class as a property access."""
    js = _write_js(tmp_path, 'let s=new n$.McpStdioServerDefinition(`srv`,"uvx",["pkg"]);')

    assert servers_in_js_file(js) == [("srv", {"command": "uvx", "type": "stdio", "args": ["pkg"]})]


def test_stdio_definition_without_static_command_is_dropped(tmp_path):
    """The command is what identifies a stdio server; without it there is nothing
    to report beyond the manifest declaration the caller already has."""
    js = _write_js(tmp_path, 'new vscode.McpStdioServerDefinition("srv", resolveInterpreter(), ["s.py"]);')

    assert servers_in_js_file(js) == []


def test_stdio_definition_with_computed_arg_drops_the_whole_argv(tmp_path):
    """A half-resolved argv reads as the real one, so it is omitted entirely rather
    than reported with the computed element silently missing."""
    js = _write_js(tmp_path, 'new vscode.McpStdioServerDefinition("srv", "node", ["s.js", port]);')

    assert servers_in_js_file(js) == [("srv", {"command": "node", "type": "stdio"})]


def test_stdio_definition_falls_back_to_command_when_label_is_computed(tmp_path):
    js = _write_js(tmp_path, "new vscode.McpStdioServerDefinition(t.name, 'node', []);")

    assert servers_in_js_file(js) == [("node", {"command": "node", "type": "stdio"})]


# --- http definitions ---


def test_http_definition_with_uri_parse(tmp_path):
    js = _write_js(
        tmp_path,
        'new vscode.McpHttpServerDefinition("remote", vscode.Uri.parse("https://example.test/mcp"), {"X-Key": "v"});',
    )

    assert servers_in_js_file(js) == [
        ("remote", {"url": "https://example.test/mcp", "type": "http", "headers": {"X-Key": "v"}}),
    ]


def test_http_definition_keeps_template_holes_verbatim(tmp_path):
    """The Pylance shape: the port is chosen at activation. Blanking the hole would
    fabricate an address that never exists, so the substitution is kept as-is."""
    js = _write_js(
        tmp_path,
        'let s = new n$.McpHttpServerDefinition("pylance mcp server", n$.Uri.parse(`http://localhost:${n}/stream`));',
    )

    assert servers_in_js_file(js) == [
        ("pylance mcp server", {"url": "http://localhost:${n}/stream", "type": "http"}),
    ]


def test_http_definition_without_static_uri_is_dropped(tmp_path):
    js = _write_js(tmp_path, "new vscode.McpHttpServerDefinition('srv', vscode.Uri.parse(endpoint));")

    assert servers_in_js_file(js) == []


def test_multiple_definitions_in_one_bundle(tmp_path):
    js = _write_js(
        tmp_path,
        'new vscode.McpStdioServerDefinition("a","node");'
        'if(x){new vscode.McpHttpServerDefinition("b",vscode.Uri.parse("http://h/mcp"))}',
    )

    assert servers_in_js_file(js) == [
        ("a", {"command": "node", "type": "stdio"}),
        ("b", {"url": "http://h/mcp", "type": "http"}),
    ]


def test_type_annotation_without_call_is_not_a_definition(tmp_path):
    """A bare reference to the class (a TS type, a re-export) constructs nothing."""
    js = _write_js(tmp_path, "exports.McpStdioServerDefinition = X; let t: vscode.McpHttpServerDefinition;")

    assert servers_in_js_file(js) == []


def test_file_without_definitions_is_skipped_cheaply(tmp_path):
    js = _write_js(tmp_path, "console.log('nothing to see');")

    assert servers_in_js_file(js) == []


def test_missing_file_is_skipped(tmp_path):
    assert servers_in_js_file(tmp_path / "absent.js") == []


def test_oversized_bundle_is_skipped(tmp_path, monkeypatch):
    """An extension tree is attacker-influenceable under ``--scan-all-users``; a
    multi-GB 'bundle' must not be read whole into memory."""
    monkeypatch.setattr("agent_scan.agents.vscode.extension_mcp._MAX_JS_FILE_BYTES", 8)
    js = _write_js(tmp_path, 'new vscode.McpStdioServerDefinition("a","node");')

    assert servers_in_js_file(js) == []


def test_unterminated_call_is_skipped_not_hung(tmp_path):
    """A desynchronized scan (the regex-literal case) gives up on that definition
    rather than running away."""
    js = _write_js(tmp_path, 'new vscode.McpStdioServerDefinition("a","node"')

    assert servers_in_js_file(js) == []


def test_definition_beyond_the_call_scan_cap_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_scan.agents.vscode.extension_mcp._MAX_CALL_SCAN_CHARS", 16)
    js = _write_js(tmp_path, 'new vscode.McpStdioServerDefinition("a","node",["{}"]);'.replace("{}", "x" * 64))

    assert servers_in_js_file(js) == []


# --- literal evaluation ---


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('"plain"', "plain"),
        ("'single'", "single"),
        ("`template`", "template"),
        (r'"tab\there"', "tab\there"),
        (r'"A\x42"', "AB"),
        (r'"\u{1F600}"', "\U0001f600"),
        (r'"unknown \q escape"', "unknown q escape"),
        ("`keeps ${hole} verbatim`", "keeps ${hole} verbatim"),
        ("  `padded`  ", "padded"),
    ],
)
def test_js_string_resolves_literals(source, expected):
    assert _js_string(source) == expected


@pytest.mark.parametrize(
    "source",
    [
        "identifier",
        '"a" + b',
        # Starts and ends with a quote but is a concatenation, not one literal —
        # a naive first-and-last-char check would misread this as ``a``.
        "'a'+'b'",
        'f("x")',
        '"unterminated',
        "",
    ],
)
def test_js_string_rejects_non_literals(source):
    assert _js_string(source) is None


def test_js_string_array_resolves_static_elements():
    assert _js_string_array("[\"a\", `b`, 'c']") == ["a", "b", "c"]


def test_js_string_array_rejects_partially_computed():
    assert _js_string_array('["a", b]') is None


def test_js_string_array_empty():
    assert _js_string_array("[]") == []


def test_js_string_object_accepts_identifier_and_quoted_keys():
    assert _js_string_object('{PATH: "/usr/bin", "X-Key": `v`}') == {"PATH": "/usr/bin", "X-Key": "v"}


def test_js_string_object_stringifies_numbers_and_drops_nulls():
    """VS Code types env values as ``string | number | null``; ``null`` means
    "unset this variable", so it contributes no entry."""
    assert _js_string_object('{PORT: 8080, UNSET: null, NAME: "x"}') == {"PORT": "8080", "NAME": "x"}


def test_js_string_object_rejects_computed_values():
    assert _js_string_object('{TOKEN: getToken(), NAME: "x"}') is None


def test_js_string_object_rejects_spread():
    assert _js_string_object('{...base, NAME: "x"}') is None


# --- the source scanner ---


def test_split_call_args_handles_nesting_and_strings():
    source = 'f("a,b", [1, 2], {k: "v,w"}, g(h(1)))'

    assert _split_call_args(source, source.index("(")) == ['"a,b"', " [1, 2]", ' {k: "v,w"}', " g(h(1))"]


def test_split_call_args_handles_nested_template_substitution():
    """A string inside a ``${...}`` hole must not terminate the enclosing template."""
    source = 'f(`a${g(")")}b`, 2)'

    assert _split_call_args(source, source.index("(")) == ['`a${g(")")}b`', " 2"]


def test_split_call_args_empty_group():
    assert _split_call_args("f()", 1) == []


def test_split_call_args_skips_comments():
    source = 'f("a" /* , fake */, "b") // trailing'

    assert _split_call_args(source, source.index("(")) == ['"a" /* , fake */', ' "b"']


def test_split_call_args_unclosed_returns_none():
    assert _split_call_args('f("a", "b"', 1) is None


def test_split_call_args_mismatched_closer_returns_none():
    assert _split_call_args("[1, 2]", 0) is None


# --- scan cost on hostile input ---


@pytest.mark.parametrize(
    ("label", "unit"),
    [
        ("unterminated string", 'new v.McpStdioServerDefinition("' + "a" * 40),
        ("unterminated block comment", "new v.McpStdioServerDefinition(/*" + "a" * 40),
        ("unterminated template substitution", "new v.McpStdioServerDefinition(`${" + "a" * 40),
    ],
)
def test_hostile_bundle_scan_stays_bounded(tmp_path, label, unit):
    """A bundle repeating the class name with a construct that never closes must
    not cost a scan to end-of-file per occurrence.

    Extension trees are attacker-influenceable under ``--scan-all-users``. Each
    delegate (``_skip_string``, ``_skip_comment``, ``_skip_balanced``) takes an
    explicit limit so one call can't outrun its window, and
    ``_MAX_DEFINITIONS_PER_FILE`` bounds the number of windows — without both,
    this input took ~46s at 5 MiB and grew quadratically.
    """
    import time

    js = _write_js(tmp_path, unit * 20000 + "x" * 4_000_000)

    started = time.monotonic()
    assert servers_in_js_file(js) == []
    assert time.monotonic() - started < 10.0, f"{label} scan did not stay bounded"


def test_definition_count_per_file_is_capped(tmp_path, monkeypatch):
    """Past the cap the remaining calls are ignored rather than scanned."""
    monkeypatch.setattr("agent_scan.agents.vscode.extension_mcp._MAX_DEFINITIONS_PER_FILE", 2)
    js = _write_js(tmp_path, 'new v.McpStdioServerDefinition("a","node");' * 5)

    assert [name for name, _ in servers_in_js_file(js)] == ["a", "a"]


def test_oversized_file_is_rejected_before_any_scanning(tmp_path, monkeypatch):
    """The size cap is checked via ``stat``, so a huge file costs no read."""
    monkeypatch.setattr("agent_scan.agents.vscode.extension_mcp._MAX_JS_FILE_BYTES", 1024)
    js = _write_js(tmp_path, 'new v.McpStdioServerDefinition("a","node");' + "x" * 4096)

    assert servers_in_js_file(js) == []
