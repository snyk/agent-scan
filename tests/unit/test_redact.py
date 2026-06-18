"""Unit tests for the redaction module."""

import re
from urllib.parse import parse_qsl, urlsplit

import pytest
from mcp.types import (
    Implementation,
    InitializeResult,
    Prompt,
    Resource,
    ServerCapabilities,
    Tool,
)

from agent_scan.models import RemoteServer, ScanPathResult, ServerScanResult, ServerSignature, StdioServer
from agent_scan.redact import (
    _is_uuid_like,
    redact_absolute_paths,
    redact_args,
    redact_data,
    redact_push_keys,
    redact_push_keys_in_data,
    redact_scan_result,
    redact_signature,
    redact_text,
)
from tests.unit._secret_fixtures import synthetic_secret

# High-entropy fake credential that detect-secrets' default high-entropy plugins
# flag. Derived at runtime (see ``synthetic_secret``) rather than a hardcoded
# literal so repo secret scanners don't flag a checked-in secret. NOT a
# known-prefix token (ghp_/sk-proj-/etc. are intentionally avoided).
FAKE_API_KEY = synthetic_secret()

# Artifactory-format fake token (matches ``AKC[A-Za-z0-9]{10,}``). Built from a
# synthetic seed so no high-entropy literal is checked in. ArtifactoryDetector
# anchors on the char *before* ``AKC`` (must be one of ``\s = : " ^``), so a bare
# token is flagged but a backtick-wrapped one is not -- the edge-strip fallback
# is what closes that gap.
FAKE_ARTIFACTORY_TOKEN = "AKC" + synthetic_secret(b"artifactory fixture token")

# Match the **REDACTED_SECRET_<PLUGIN>** marker shape without hardcoding which
# detect-secrets plugin won the race. The plugin set may change across
# detect-secrets versions; the marker shape will not.
_SECRET_MARKER_RE = re.compile(r"^\*\*REDACTED_SECRET_[A-Z0-9_]+\*\*$")


def is_secret_marker(value: str) -> bool:
    """Return True if ``value`` is a plugin-named redaction marker."""
    return bool(_SECRET_MARKER_RE.fullmatch(value))


class TestRedactAbsolutePaths:
    """Unit tests for redact_absolute_paths function."""

    def test_redact_absolute_paths_none(self):
        """Test that None input returns None."""
        assert redact_absolute_paths(None) is None

    def test_redact_absolute_paths_empty(self):
        """Test that empty string returns empty string."""
        assert redact_absolute_paths("") == ""

    def test_redact_absolute_paths_preserves_non_paths(self):
        """Test that non-path content is preserved."""
        text = "Error: Something went wrong with value 123"
        assert redact_absolute_paths(text) == text

    def test_redact_absolute_paths_home_directory(self):
        """Test that home directory paths are redacted."""
        text = "Loading config from ~/Documents/config.json"
        result = redact_absolute_paths(text)
        assert "~/Documents/config.json" not in result
        assert "**REDACTED**" in result

    def test_redact_absolute_paths_multiple(self):
        """Test that multiple paths are all redacted."""
        text = "Error in /usr/local/bin/node processing /home/user/project/file.js"
        result = redact_absolute_paths(text)
        assert "/usr/local/bin/node" not in result
        assert "/home/user/project/file.js" not in result
        assert result.count("**REDACTED**") == 2


class TestRedactArgs:
    """Unit tests for redact_args function (detect-secrets-based)."""

    def test_redact_args_empty(self):
        """Empty list returns empty list."""
        assert redact_args([]) == []

    def test_redact_args_positional_non_secret(self):
        """Plain positional args (no secrets) are preserved."""
        args = ["script.js", "input.txt", "output.txt"]
        assert redact_args(args) == ["script.js", "input.txt", "output.txt"]

    def test_redact_args_flag_alone_preserved(self):
        """A flag with no value attached is preserved (no look-ahead)."""
        args = ["--api-key"]
        assert redact_args(args) == ["--api-key"]

    def test_redact_args_short_flag_alone_preserved(self):
        """A short flag with no value attached is preserved."""
        args = ["-k"]
        assert redact_args(args) == ["-k"]

    def test_redact_args_flag_then_low_entropy_value_redacts_via_keyword(self):
        """Flag followed by a low-entropy value: keyword-detector pass redacts the value.

        With the sliding-window keyword pass, the previous token (--api-key)
        provides the keyword context that makes a synthetic line
        'api_key="secret123"' fire detect-secrets' KeywordDetector. The flag
        name itself is preserved; only the value half is replaced with a
        plugin-named marker.
        """
        args = ["--api-key", "secret123"]
        result = redact_args(args)
        assert result[0] == "--api-key"
        assert is_secret_marker(result[1])
        assert "secret123" not in result[1]

    def test_redact_args_flag_then_high_entropy_value_redacted(self):
        """Flag followed by a high-entropy secret value: the value (only) is redacted."""
        args = ["--api-key", FAKE_API_KEY]
        result = redact_args(args)
        assert result[0] == "--api-key"
        assert is_secret_marker(result[1])
        assert FAKE_API_KEY not in result[1]

    def test_redact_args_equals_high_entropy_value_redacted(self):
        """--flag=<high-entropy-value> redacts only the value half."""
        args = [f"--api-key={FAKE_API_KEY}"]
        result = redact_args(args)
        assert len(result) == 1
        flag, sep, value = result[0].partition("=")
        assert (flag, sep) == ("--api-key", "=")
        assert is_secret_marker(value)
        assert FAKE_API_KEY not in result[0]

    def test_redact_args_equals_low_entropy_value_preserved(self):
        """--flag=<low-entropy-value> is preserved (not flagged by detect-secrets)."""
        args = ["--port=3000"]
        assert redact_args(args) == ["--port=3000"]

    def test_redact_args_short_equals_high_entropy_value_redacted(self):
        """-k=<high-entropy-value> redacts only the value half."""
        args = [f"-k={FAKE_API_KEY}"]
        result = redact_args(args)
        assert len(result) == 1
        flag, sep, value = result[0].partition("=")
        assert (flag, sep) == ("-k", "=")
        assert is_secret_marker(value)
        assert FAKE_API_KEY not in result[0]

    def test_redact_args_boolean_flags_preserved(self):
        """Boolean flags without values are preserved."""
        args = ["--verbose", "--debug", "-y"]
        assert redact_args(args) == ["--verbose", "--debug", "-y"]

    def test_redact_args_unix_path_preserved(self):
        """Absolute Unix paths are NOT redacted by redact_args anymore (handled elsewhere)."""
        args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/developer/code"]
        assert redact_args(args) == ["-y", "@modelcontextprotocol/server-filesystem", "/Users/developer/code"]

    def test_redact_args_home_path_preserved(self):
        """Home-directory paths are NOT redacted by redact_args anymore."""
        args = ["-y", "some-server", "~/Documents/projects"]
        assert redact_args(args) == ["-y", "some-server", "~/Documents/projects"]

    def test_redact_args_package_name_preserved(self):
        """npm-style package names are preserved (no entropy)."""
        args = ["-y", "@modelcontextprotocol/server-github"]
        assert redact_args(args) == ["-y", "@modelcontextprotocol/server-github"]

    def test_redact_args_positional_high_entropy_redacted(self):
        """A bare positional arg that itself contains a secret is redacted with the plugin-named marker."""
        args = [FAKE_API_KEY]
        result = redact_args(args)
        assert len(result) == 1
        assert is_secret_marker(result[0])
        assert FAKE_API_KEY not in result[0]

    def test_redact_args_header_token_high_entropy_value_redacted(self):
        """An HTTP-header-shaped token "name:value" with a high-entropy value is fully redacted."""
        header_token = f"x-client-id:{FAKE_API_KEY}"
        args = ["--control-server-H", header_token]
        result = redact_args(args)
        assert result[0] == "--control-server-H"
        assert is_secret_marker(result[1])
        # Neither the header name nor the value half may leak through.
        assert "x-client-id" not in result[1]
        assert FAKE_API_KEY not in result[1]

    def test_redact_args_header_token_keyword_match_redacted(self):
        """A "name:value" token whose name is a known secret keyword is redacted even at low entropy."""
        args = ["--header", "api-key:hello-world"]
        result = redact_args(args)
        assert result[0] == "--header"
        assert is_secret_marker(result[1])
        assert "api-key" not in result[1]
        assert "hello-world" not in result[1]

    def test_redact_args_header_token_innocuous_value_preserved(self):
        """A "name:value" token with no secret signal is preserved verbatim."""
        args = ["--header", "Accept:application/json"]
        assert redact_args(args) == ["--header", "Accept:application/json"]

    def test_redact_args_url_with_port_preserved(self):
        """URLs containing ':' (e.g. host:port) are not mistaken for header tokens."""
        args = ["--server", "http://example.com:8080/path"]
        assert redact_args(args) == ["--server", "http://example.com:8080/path"]

    def test_redact_args_single_char_header_name_high_entropy_value_redacted(self):
        """Pass C accepts single-char HTTP header names (e.g. RFC-valid `X:value`).

        Prior regex required ≥2 chars on the name half, silently skipping
        Pass C for tokens like "X:<secret>". Widening to ≥1 char closes
        that gap; the value-side detectors still gate the actual redaction.
        """
        header_token = f"X:{FAKE_API_KEY}"
        args = ["--control-server-H", header_token]
        result = redact_args(args)
        assert result[0] == "--control-server-H"
        assert is_secret_marker(result[1])
        assert FAKE_API_KEY not in result[1]
        # The header name itself is part of the redacted token, never leaked.
        assert "X:" not in result[1]

    def test_redact_args_single_char_header_name_innocuous_value_preserved(self):
        """Widening the header-name regex must not cause over-redaction.

        A single-char name with a non-secret value is still preserved
        verbatim, because Pass C only marks a token when the value half
        triggers an independent secret detector.
        """
        args = ["--control-server-H", "X:application/json"]
        assert redact_args(args) == ["--control-server-H", "X:application/json"]

    def test_redact_args_mixed_realistic(self):
        """Realistic mix: package name, boolean flag, low-entropy flag value, high-entropy flag value."""
        args = ["-y", "some-server", "--port", "3000", "--api-key", FAKE_API_KEY, f"--token={FAKE_API_KEY}"]
        result = redact_args(args)
        assert result[:5] == ["-y", "some-server", "--port", "3000", "--api-key"]
        assert is_secret_marker(result[5])
        flag, sep, value = result[6].partition("=")
        assert (flag, sep) == ("--token", "=")
        assert is_secret_marker(value)
        assert FAKE_API_KEY not in " ".join(result)

    def test_redact_args_marker_names_triggering_plugin(self):
        """The marker has the form **REDACTED_SECRET_<PLUGIN_NAME>** with balanced asterisks matching the legacy **REDACTED** constant."""
        args = ["--api-key", FAKE_API_KEY]
        result = redact_args(args)
        joined = " ".join(result)
        assert joined.endswith("**")
        assert not joined.endswith("***")
        assert "**REDACTED_SECRET_" in joined
        assert is_secret_marker(result[1])

    def test_redact_args_known_format_token_uses_named_detector(self):
        """A recognized-format token (e.g. AWS) is flagged by its named detector, not by entropy."""
        aws_token = "AKIAIOSFODNN7EXAMPLE"
        args = [f"--aws-key={aws_token}"]
        result = redact_args(args)
        assert result == ["--aws-key=**REDACTED_SECRET_AWSKEYDETECTOR**"]

    def test_redact_args_equals_form_keyword_low_entropy_redacted(self):
        """--api-key=<low-entropy-value> redacts only the value half via keyword pass.

        Pass A (format + entropy) does not flag a bare 'hello123' (low entropy,
        no recognised format). Pass B builds the synthetic line
        'api_key="hello123"' and KeywordDetector fires on the api_?key
        denylist entry.
        """
        args = ["--api-key=hello123"]
        result = redact_args(args)
        assert len(result) == 1
        flag, sep, value = result[0].partition("=")
        assert (flag, sep) == ("--api-key", "=")
        assert is_secret_marker(value)
        assert "hello123" not in result[0]

    def test_redact_args_space_form_keyword_low_entropy_redacted(self):
        """--api-key <low-entropy-value> (space-separated) redacts the value, preserves the flag.

        Same denylist hit as the equals form, exercised via the sliding-window
        path where prev and curr live in separate args list entries.
        """
        args = ["--api-key", "hello123"]
        result = redact_args(args)
        assert result[0] == "--api-key"
        assert is_secret_marker(result[1])
        assert "hello123" not in result[1]

    def test_redact_args_equals_form_password_redacted(self):
        """--password=<value> redacts via keyword pass (password denylist family).

        Exercises a different denylist family than api_?key, confirming the
        keyword pass is not hardcoded to a single keyword.
        """
        args = ["--password=swordfish"]
        result = redact_args(args)
        assert len(result) == 1
        flag, sep, value = result[0].partition("=")
        assert (flag, sep) == ("--password", "=")
        assert is_secret_marker(value)
        assert "swordfish" not in result[0]

    def test_redact_args_space_form_password_redacted(self):
        """--password <value> (space-separated) redacts the value via keyword pass."""
        args = ["--password", "swordfish"]
        result = redact_args(args)
        assert result[0] == "--password"
        assert is_secret_marker(result[1])
        assert "swordfish" not in result[1]

    def test_redact_args_compound_flag_keyword_match_redacted(self):
        """--openai-api-key=<value> redacts via keyword pass.

        Verifies that compound flag names containing a denylist substring
        (openai_api_key contains api_key) trigger the keyword pass via the
        upstream regex's natural prefix/suffix handling.
        """
        args = ["--openai-api-key=hello123"]
        result = redact_args(args)
        assert len(result) == 1
        flag, sep, value = result[0].partition("=")
        assert (flag, sep) == ("--openai-api-key", "=")
        assert is_secret_marker(value)
        assert "hello123" not in result[0]

    def test_redact_args_format_detector_wins_over_keyword(self):
        """Format detector (AWSKeyDetector) wins over keyword pass on the same token.

        Pass-order requirement: format > entropy > keyword. The marker must
        identify the AWS detector, not KeywordDetector. This asserts the
        specific plugin name (rather than is_secret_marker) to lock in the
        precedence.
        """
        args = ["--api-key", "AKIAIOSFODNN7EXAMPLE"]
        result = redact_args(args)
        assert result == ["--api-key", "**REDACTED_SECRET_AWSKEYDETECTOR**"]

    def test_redact_args_keyword_flag_then_flag_value_preserved(self):
        """D1 defensive guard: when curr looks like a CLI flag, Pass B is skipped.

        Without the D1 guard, the sliding-window pass would feed
        'password="--debug"' to KeywordDetector and redact ``--debug`` as a
        secret. The guard ensures that follow-on flags are never confused
        for values.
        """
        args = ["--password", "--debug"]
        assert redact_args(args) == ["--password", "--debug"]

    def test_redact_args_push_key_low_entropy_space_form_redacted(self):
        """Pass D: --push-key <low-entropy> redacts the value by flag-name allowlist.

        Detect-secrets entropy/keyword heuristics do not recognize the custom
        "push-key" name. The known-sensitive flag allowlist catches it
        regardless of value shape.
        """
        args = ["--push-key", "foo123"]
        result = redact_args(args)
        assert result[0] == "--push-key"
        assert is_secret_marker(result[1])
        assert "foo123" not in result[1]

    def test_redact_args_push_key_low_entropy_equals_form_redacted(self):
        """Pass D: --push-key=<low-entropy> redacts the value half via flag-name allowlist."""
        args = ["--push-key=foo123"]
        result = redact_args(args)
        flag, sep, value = result[0].partition("=")
        assert (flag, sep) == ("--push-key", "=")
        assert is_secret_marker(value)
        assert "foo123" not in result[0]

    def test_redact_args_x_client_id_header_low_entropy_redacted(self):
        """Pass D: x-client-id:<low-entropy> token is redacted by header-name allowlist."""
        args = ["--control-server-H", "x-client-id:foo123"]
        result = redact_args(args)
        assert result[0] == "--control-server-H"
        assert is_secret_marker(result[1])
        assert "foo123" not in result[1]
        assert "x-client-id" not in result[1]

    def test_redact_args_authorization_header_low_entropy_redacted(self):
        """Pass D: authorization:<low-entropy> redacts via header-name allowlist."""
        args = ["--control-server-H", "Authorization:Bearer-foo"]
        result = redact_args(args)
        assert result[0] == "--control-server-H"
        assert is_secret_marker(result[1])
        assert "Bearer-foo" not in result[1]

    def test_redact_args_unrelated_header_low_entropy_preserved(self):
        """Pass D does not over-redact: headers not on the allowlist stay verbatim when value has no secret signal."""
        args = ["--control-server-H", "Accept:application/json"]
        assert redact_args(args) == ["--control-server-H", "Accept:application/json"]

    def test_redact_args_sensitive_flag_marker_name(self):
        """Pass D uses a distinct marker so the source of redaction is traceable in logs."""
        args = ["--push-key", "foo123"]
        result = redact_args(args)
        assert result[1] == "**REDACTED_SECRET_SENSITIVEFLAGNAME**"


class TestRedactData:
    """Unit tests for redact_data function."""

    def test_no_match_preserves_values(self):
        patterns = [re.compile(r"SECRET=(\w+)")]
        data = {"key": "no match here", "nested": {"deep": "also safe"}}
        redact_data(data, patterns)
        assert data == {"key": "no match here", "nested": {"deep": "also safe"}}

    def test_simple_capture_group_replaced(self):
        patterns = [re.compile(r"TOKEN=(\w+)")]
        data = {"cmd": "TOKEN=abc123 OTHER=keep"}
        redact_data(data, patterns)
        assert data["cmd"] == "TOKEN=**REDACTED** OTHER=keep"

    def test_multiple_patterns_applied(self):
        patterns = [
            re.compile(r"KEY='([^']*)'"),
            re.compile(r"SECRET='([^']*)'"),
        ]
        data = {"cmd": "KEY='val1' SECRET='val2' FLAG=ok"}
        redact_data(data, patterns)
        assert data["cmd"] == "KEY='**REDACTED**' SECRET='**REDACTED**' FLAG=ok"

    def test_deep_nested_dict(self):
        patterns = [re.compile(r"password=(\S+)")]
        data = {"a": {"b": {"c": "password=hunter2 user=admin"}}}
        redact_data(data, patterns)
        assert data["a"]["b"]["c"] == "password=**REDACTED** user=admin"

    def test_list_values_traversed(self):
        patterns = [re.compile(r"secret:(\w+)")]
        data = {"items": ["secret:abc", "safe", "secret:def"]}
        redact_data(data, patterns)
        assert data["items"] == ["secret:**REDACTED**", "safe", "secret:**REDACTED**"]

    def test_nested_list_of_dicts(self):
        patterns = [re.compile(r"KEY='([^']*)'")]
        data = {"hooks": [{"command": "KEY='secret1'"}, {"command": "KEY='secret2'"}]}
        redact_data(data, patterns)
        assert data["hooks"][0]["command"] == "KEY='**REDACTED**'"
        assert data["hooks"][1]["command"] == "KEY='**REDACTED**'"

    def test_multiple_matches_in_same_string(self):
        patterns = [re.compile(r"TOKEN=([0-9a-f]+)", re.IGNORECASE)]
        data = {"cmd": "TOKEN=aabb TOKEN=ccdd"}
        redact_data(data, patterns)
        assert data["cmd"] == "TOKEN=**REDACTED** TOKEN=**REDACTED**"

    def test_capture_group_with_lookahead(self):
        patterns = [re.compile(r"PUSH_KEY='([^']*)'")]
        data = {"cmd": "PUSH_KEY='my-secret' URL='https://example.com'"}
        redact_data(data, patterns)
        assert data["cmd"] == "PUSH_KEY='**REDACTED**' URL='https://example.com'"

    def test_uuid_pattern(self):
        uuid_re = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        patterns = [re.compile(rf"PUSH_KEY='({uuid_re})'", re.IGNORECASE)]
        data = {"cmd": "PUSH_KEY='a1b2c3d4-e5f6-7890-abcd-ef1234567890' bash script.sh"}
        redact_data(data, patterns)
        assert data["cmd"] == "PUSH_KEY='**REDACTED**' bash script.sh"

    def test_uuid_pattern_non_uuid_value_preserved(self):
        uuid_re = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        patterns = [re.compile(rf"PUSH_KEY='({uuid_re})'", re.IGNORECASE)]
        data = {"cmd": "PUSH_KEY='not-a-uuid' bash script.sh"}
        redact_data(data, patterns)
        assert data["cmd"] == "PUSH_KEY='not-a-uuid' bash script.sh"

    def test_non_string_values_ignored(self):
        patterns = [re.compile(r"secret=(\w+)")]
        data = {"count": 42, "flag": True, "empty": None, "text": "secret=abc"}
        redact_data(data, patterns)
        assert data["count"] == 42
        assert data["flag"] is True
        assert data["empty"] is None
        assert data["text"] == "secret=**REDACTED**"

    def test_empty_dict(self):
        patterns = [re.compile(r"KEY=(\w+)")]
        data: dict = {}
        result = redact_data(data, patterns)
        assert result == {}

    def test_empty_patterns_list(self):
        data = {"cmd": "KEY='secret' VALUE=123"}
        redact_data(data, [])
        assert data == {"cmd": "KEY='secret' VALUE=123"}

    def test_mutates_in_place_and_returns(self):
        patterns = [re.compile(r"KEY=(\w+)")]
        data = {"cmd": "KEY=secret"}
        result = redact_data(data, patterns)
        assert result is data
        assert data["cmd"] == "KEY=**REDACTED**"

    def test_mixed_list_with_non_strings(self):
        patterns = [re.compile(r"tok=(\w+)")]
        data = {"items": ["tok=abc", 42, {"nested": "tok=def"}, True, None]}
        redact_data(data, patterns)
        assert data["items"][0] == "tok=**REDACTED**"
        assert data["items"][1] == 42
        assert data["items"][2] == {"nested": "tok=**REDACTED**"}
        assert data["items"][3] is True
        assert data["items"][4] is None

    def test_hooks_diff_realistic_payload(self):
        """Realistic hooks diff payload with push keys in command strings."""
        uuid_re = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        patterns = [
            re.compile(rf"PUSH_KEY='({uuid_re})'", re.IGNORECASE),
            re.compile(rf"-PushKey\s+'({uuid_re})'", re.IGNORECASE),
        ]
        push_key = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        command = f"PUSH_KEY='{push_key}' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash /path/to/script.sh --client claude-code"
        data = {
            "hook_event_name": "hooksConfigured",
            "session_id": "hooks-setup",
            "first_install": False,
            "config_changed": True,
            "added": {},
            "modified": {
                "PreToolUse": {
                    "expected_value": [{"hooks": [{"type": "command", "command": command}]}],
                    "actual_value": [{"hooks": [{"type": "command", "command": "old-command"}]}],
                },
            },
            "removed": {
                "Stop": [{"hooks": [{"type": "command", "command": command}]}],
            },
        }
        redact_data(data, patterns)
        assert push_key not in str(data)
        assert "**REDACTED**" in data["modified"]["PreToolUse"]["expected_value"][0]["hooks"][0]["command"]
        assert (
            "REMOTE_HOOKS_BASE_URL='https://api.snyk.io'"
            in data["modified"]["PreToolUse"]["expected_value"][0]["hooks"][0]["command"]
        )
        assert data["session_id"] == "hooks-setup"


class TestRedactText:
    """Unit tests for redact_text (free-text secret + path redaction)."""

    def test_redact_text_none(self):
        assert redact_text(None) is None

    def test_redact_text_empty(self):
        assert redact_text("") == ""

    def test_redact_text_preserves_innocuous_content(self):
        text = "# My Skill\n\nThis skill fetches the weather for a given city.\n"
        assert redact_text(text) == text

    def test_redact_text_redacts_bare_high_entropy_token(self):
        text = f"Use this token: {FAKE_API_KEY}\n"
        result = redact_text(text)
        assert FAKE_API_KEY not in result
        assert "**REDACTED_SECRET_" in result

    def test_redact_text_redacts_known_format_token(self):
        text = "Authenticate with AKIAIOSFODNN7EXAMPLE before running."
        result = redact_text(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "**REDACTED_SECRET_AWSKEYDETECTOR**" in result

    def test_redact_text_preserves_low_entropy_keyword_value(self):
        """Keyword-only, low-entropy values are intentionally NOT redacted.

        Skill content is documentation/code where a ``password``/``api_key``
        keyword next to a value is usually legitimate context, not a live
        secret. Redacting on keyword alone would strip analysis context, so
        only high-entropy / known-format secrets are removed.
        """
        text = 'config = {"password": "changeme"}'
        result = redact_text(text)
        assert result == text

    def test_redact_text_redacts_high_entropy_keyword_value(self):
        """A keyword value that IS high-entropy is still redacted (by the
        entropy detector, not by keyword context)."""
        text = f'config = {{"password": "{FAKE_API_KEY}"}}'
        result = redact_text(text)
        assert FAKE_API_KEY not in result
        assert "**REDACTED_SECRET_" in result

    def test_redact_text_preserves_absolute_paths(self):
        """Skill content (docs/code) routinely references real paths as legitimate
        context, so redact_text leaves absolute paths intact and only strips
        secrets. (Tracebacks and server output still get path redaction via
        redact_server / redact_scan_result.)"""
        text = "Loading from /Users/alice/project/config.json"
        result = redact_text(text)
        assert result == text

    def test_redact_text_preserves_line_structure(self):
        text = f"line one\n{FAKE_API_KEY}\nline three"
        result = redact_text(text)
        lines = result.split("\n")
        assert lines[0] == "line one"
        assert is_secret_marker(lines[1])
        assert lines[2] == "line three"

    def test_redact_text_enters_detect_secrets_context_once(self, monkeypatch):
        """redact_text must enter the detect-secrets settings context exactly
        once for the whole text, not once per token.

        Re-entering ``transient_settings`` runs detect-secrets' ``cache_bust``
        twice each time (~1.3ms), so a per-token re-entry makes redaction
        O(tokens) -- a large bundled script then takes tens of seconds. The
        per-token detection path must reuse the already-built plugin set under
        the single outer context instead.
        """
        import contextlib

        import agent_scan.redact as redact_mod

        real_transient_settings = redact_mod.transient_settings
        entries = 0

        @contextlib.contextmanager
        def counting_transient_settings(*args, **kwargs):
            nonlocal entries
            entries += 1
            with real_transient_settings(*args, **kwargs) as value:
                yield value

        monkeypatch.setattr(redact_mod, "transient_settings", counting_transient_settings)

        # Many whitespace tokens across several lines, including a real secret,
        # so the per-token detection pass runs repeatedly.
        text = "\n".join("alpha beta gamma delta epsilon zeta" for _ in range(20))
        text += f"\nthe secret is {FAKE_API_KEY}\n"

        result = redact_mod.redact_text(text)

        assert entries == 1
        # ...and detection still works under the single-context path.
        assert FAKE_API_KEY not in result
        assert "**REDACTED_SECRET_" in result

    @pytest.mark.parametrize(
        "wrapped",
        [
            'key: "the deploy value is {tok}"',  # token last word in a longer quoted string
            "use `{tok}` now",  # markdown code span
            "see ({tok}) here",  # parenthesised
            "see [{tok}] here",  # bracketed
            "token {tok}. done",  # trailing sentence period
            "token {tok}, done",  # trailing comma
        ],
    )
    def test_redact_text_redacts_wrapped_high_entropy_token(self, wrapped):
        """A high-entropy token wrapped in markup/punctuation is still redacted.

        Pass 2 splits on whitespace, so wrapping characters ride along with the
        token: a trailing ``"`` defeats the entropy plugin's quoted-literal
        regex, and a long low-entropy quoted string hides the secret from the
        raw-line scan. The edge-strip fallback recovers the bare core and
        redacts it. (Fully-quoted single-token forms like ``"<tok>"`` are
        already covered by the Pass-1 raw-line scan and are not retested here.)
        """
        text = wrapped.format(tok=FAKE_API_KEY)
        result = redact_text(text)
        assert FAKE_API_KEY not in result
        assert "**REDACTED_SECRET_" in result

    def test_redact_text_redacts_backtick_wrapped_format_token(self):
        r"""A boundary-anchored format token (Artifactory) in a markdown code span
        is redacted via the edge-strip fallback.

        ``ArtifactoryDetector`` requires the char before ``AKC`` to be one of
        ``\s = : " ^``; a backtick is not, so the raw backtick-wrapped token
        never matched. Stripping the backticks recovers a detectable core.
        """
        text = f"use the token `{FAKE_ARTIFACTORY_TOKEN}` to publish"
        result = redact_text(text)
        assert FAKE_ARTIFACTORY_TOKEN not in result
        assert "**REDACTED_SECRET_ARTIFACTORYDETECTOR**" in result

    def test_redact_text_preserves_wrapped_non_secret(self):
        """Edge-stripping must not over-redact: non-secret tokens wrapped in
        punctuation are returned unchanged."""
        text = "see (example) and `config` here, then stop."
        assert redact_text(text) == text


def _skill_signature(*, instructions="", prompts=None, resources=None, tools=None) -> ServerSignature:
    return ServerSignature(
        metadata=InitializeResult(
            protocolVersion="built-in",
            instructions=instructions,
            capabilities=ServerCapabilities(),
            serverInfo=Implementation(name="skill", version="skills"),
        ),
        prompts=prompts or [],
        resources=resources or [],
        tools=tools or [],
    )


class TestRedactSignature:
    """Unit tests for redact_signature (skill ServerSignature redaction)."""

    def test_redact_signature_redacts_instructions(self):
        sig = _skill_signature(instructions=f"Skill that uses {FAKE_API_KEY}")
        redact_signature(sig)
        assert FAKE_API_KEY not in sig.metadata.instructions

    def test_redact_signature_redacts_prompt_description(self):
        sig = _skill_signature(prompts=[Prompt(name="SKILL.md", description=f"key: {FAKE_API_KEY}")])
        redact_signature(sig)
        assert FAKE_API_KEY not in (sig.prompts[0].description or "")

    def test_redact_signature_redacts_resource_and_tool_descriptions(self):
        sig = _skill_signature(
            resources=[Resource(name="data", uri="skill://data", description=f"secret {FAKE_API_KEY}")],
            tools=[
                Tool(name="run.sh", description=f"Script: run.sh. Code:\nexport TOKEN={FAKE_API_KEY}", inputSchema={})
            ],
        )
        redact_signature(sig)
        assert FAKE_API_KEY not in (sig.resources[0].description or "")
        assert FAKE_API_KEY not in (sig.tools[0].description or "")
        # The non-secret structure around the secret is preserved.
        assert sig.tools[0].description.startswith("Script: run.sh. Code:")

    def test_redact_signature_preserves_clean_content(self):
        sig = _skill_signature(
            instructions="A helpful skill",
            prompts=[Prompt(name="SKILL.md", description="# Title\nDoes something useful.")],
        )
        redact_signature(sig)
        assert sig.metadata.instructions == "A helpful skill"
        assert sig.prompts[0].description == "# Title\nDoes something useful."

    def test_redact_signature_preserves_binary_file_hash(self):
        """The synthetic 'Binary file. Hash: <sha256>' marker is self-generated
        and secret-free, so redaction must leave the digest intact -- otherwise
        the 64-char hash trips the hex high-entropy detector and every binary
        collapses to an identical, useless description."""
        import hashlib

        digest = hashlib.sha256(b"\x00\x01\x02 binary blob \x80\x81").hexdigest()
        desc = f"Binary file. Hash: {digest}"
        sig = _skill_signature(resources=[Resource(name="logo.bin", uri="skill://logo.bin", description=desc)])
        redact_signature(sig)
        assert sig.resources[0].description == desc

    def test_redact_signature_still_redacts_text_resembling_binary_marker(self):
        """The exemption is an exact whole-string match: a description that only
        starts like the binary marker but carries extra (possibly secret) text
        is NOT exempt and is still redacted."""
        import hashlib

        digest = hashlib.sha256(b"blob").hexdigest()
        desc = f"Binary file. Hash: {digest} -- also token {FAKE_API_KEY}"
        sig = _skill_signature(resources=[Resource(name="logo.bin", uri="skill://logo.bin", description=desc)])
        redact_signature(sig)
        assert FAKE_API_KEY not in (sig.resources[0].description or "")


def test_redact_remote_url_query_and_headers():
    """
    Ensure RemoteServer headers are redacted and URL query parameter values are replaced with REDACTED.
    """
    result = ScanPathResult(
        path="/dummy/path",
        servers=[
            ServerScanResult(
                name="remote",
                server=RemoteServer(
                    url="https://api.example.com/endpoint?token=abc123&api_key=xyz",
                    type="http",
                    headers={"Authorization": "Bearer secret", "X-Custom": "value"},
                ),
            )
        ],
    )

    result = redact_scan_result(result)

    assert result.servers is not None and len(result.servers) == 1
    srv = result.servers[0]
    assert isinstance(srv.server, RemoteServer)
    assert srv.server.headers["Authorization"] == "**REDACTED**"
    assert srv.server.headers["X-Custom"] == "**REDACTED**"
    parts = urlsplit(srv.server.url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    assert qs.get("token") == "**REDACTED**"
    assert qs.get("api_key") == "**REDACTED**"


def test_redact_stdio_env_vars():
    """
    Ensure StdioServer environment variable values are redacted via redact_scan_result.
    """
    result = ScanPathResult(
        path="/dummy/path",
        servers=[
            ServerScanResult(
                name="stdio",
                server=StdioServer(
                    command="echo",
                    args=["hello"],
                    env={"SECRET": "shh", "API_TOKEN": "tok"},
                ),
            )
        ],
    )

    result = redact_scan_result(result)

    assert result.servers is not None and len(result.servers) == 1
    srv = result.servers[0]
    assert isinstance(srv.server, StdioServer)
    assert srv.server.env["SECRET"] == "**REDACTED**"
    assert srv.server.env["API_TOKEN"] == "**REDACTED**"


def test_redact_stdio_args():
    """
    Ensure StdioServer argument values are redacted via redact_scan_result.

    -y is a boolean flag; the package name is preserved; only high-entropy
    secret values are redacted (via detect-secrets).
    """
    result = ScanPathResult(
        path="/dummy/path",
        servers=[
            ServerScanResult(
                name="stdio",
                server=StdioServer(
                    command="npx",
                    args=["-y", "some-server", "--api-key", FAKE_API_KEY, f"--token={FAKE_API_KEY}"],
                    env={},
                ),
            )
        ],
    )

    result = redact_scan_result(result)

    assert result.servers is not None and len(result.servers) == 1
    srv = result.servers[0]
    assert isinstance(srv.server, StdioServer)
    assert srv.server.args is not None
    assert srv.server.args[:3] == ["-y", "some-server", "--api-key"]
    assert is_secret_marker(srv.server.args[3])
    flag, sep, value = srv.server.args[4].partition("=")
    assert (flag, sep) == ("--token", "=")
    assert is_secret_marker(value)
    assert FAKE_API_KEY not in " ".join(srv.server.args)


@pytest.mark.parametrize(
    "server,kind",
    [
        (
            ServerScanResult(
                name="Weather",
                server=StdioServer(
                    command="uv run python",
                    args=["tests/mcp_servers/weather_server.py"],
                    env={"API_KEY": FAKE_API_KEY},
                ),
            ),
            "env",
        ),
        (
            ServerScanResult(
                name="Math",
                server=StdioServer(
                    command="uv run python",
                    args=["tests/mcp_servers/math_server.py", f"--api-key={FAKE_API_KEY}"],
                ),
            ),
            "args",
        ),
    ],
)
def test_redact_scan_result_removes_api_key(server, kind):
    """
    Ensure redact_scan_result removes API keys from server configs.

    Env-var values use the legacy REDACTED constant (sibling-constant
    preservation); CLI arg values use the plugin-named REDACTED_SECRET
    marker.
    """
    result = ScanPathResult(path="/dummy/path", servers=[server])

    redacted = redact_scan_result(result)
    dump = redacted.model_dump_json()

    assert FAKE_API_KEY not in dump

    srv = redacted.servers[0]
    assert isinstance(srv.server, StdioServer)
    if kind == "env":
        assert srv.server.env is not None
        assert srv.server.env["API_KEY"] == "**REDACTED**"
    else:
        # args case: --api-key=<FAKE_API_KEY> becomes --api-key=<marker>.
        # FAKE_API_KEY absence is already asserted on the dump above.
        assert srv.server.args is not None
        flag, sep, value = srv.server.args[-1].partition("=")
        assert (flag, sep) == ("--api-key", "=")
        assert is_secret_marker(value)


# ---------------------------------------------------------------------------
# _is_uuid_like
# ---------------------------------------------------------------------------


class TestIsUuidLike:
    """Tests for the malformed-UUID detection helper."""

    def test_well_formed_uuid(self):
        assert _is_uuid_like("a1b2c3d4-e5f6-7890-abcd-ef1234567890") is True

    def test_uppercase_uuid(self):
        assert _is_uuid_like("A1B2C3D4-E5F6-7890-ABCD-EF1234567890") is True

    def test_no_dashes(self):
        assert _is_uuid_like("a1b2c3d4e5f67890abcdef1234567890") is True

    def test_extra_dashes(self):
        assert _is_uuid_like("a1b2c3d4--e5f6--7890--abcd--ef1234567890") is True

    def test_spaces_instead_of_dashes(self):
        assert _is_uuid_like("a1b2c3d4 e5f6 7890 abcd ef1234567890") is True

    def test_underscores_instead_of_dashes(self):
        assert _is_uuid_like("a1b2c3d4_e5f6_7890_abcd_ef1234567890") is True

    def test_dots_as_separators(self):
        assert _is_uuid_like("a1b2c3d4.e5f6.7890.abcd.ef1234567890") is True

    def test_mixed_noise_characters(self):
        assert _is_uuid_like("a1b2-c3d4 e5f6_7890.abcd-ef12 3456 7890") is True

    def test_one_extra_hex_digit(self):
        # 33 hex digits — recoverable by trying 33 combinations
        assert _is_uuid_like("a1b2c3d4-e5f6-7890-abcd-ef1234567890f") is True

    def test_two_extra_hex_digits(self):
        # 34 hex digits — C(34,2) = 561 attempts
        assert _is_uuid_like("a1b2c3d4-e5f6-7890-abcd-ef1234567890ff") is True

    def test_three_extra_hex_digits(self):
        # 35 hex digits — C(35,3) = 6545 attempts
        assert _is_uuid_like("a1b2c3d4-e5f6-7890-abcd-ef1234567890fff") is True

    def test_four_extra_hex_digits_rejected(self):
        # 36 hex digits — beyond the brute-force threshold
        assert _is_uuid_like("a1b2c3d4-e5f6-7890-abcd-ef1234567890ffff") is False

    def test_extra_hex_digits_with_noise(self):
        # 33 hex digits + noise separators
        assert _is_uuid_like("a1b2c3d4--e5f6-7890-abcd-ef12345678900") is True

    def test_extra_hex_scattered_with_noise(self):
        # 34 hex digits scattered among underscores
        assert _is_uuid_like("a1b2c3d4_e5f6_7890_abcd_ef1234567890_ab") is True

    def test_too_few_hex_digits(self):
        assert _is_uuid_like("a1b2c3d4-e5f6-7890-abcd") is False

    def test_empty_string(self):
        assert _is_uuid_like("") is False

    def test_plain_text(self):
        assert _is_uuid_like("hello-world") is False

    def test_short_hex(self):
        assert _is_uuid_like("abcdef12") is False


# ---------------------------------------------------------------------------
# redact_push_keys (string-level)
# ---------------------------------------------------------------------------


class TestRedactPushKeys:
    """Tests for redact_push_keys covering well-formed and malformed UUIDs."""

    VALID_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    def test_well_formed_push_key_env(self):
        text = f"PUSH_KEY='{self.VALID_UUID}' bash script.sh"
        result = redact_push_keys(text)
        assert self.VALID_UUID not in result
        assert "PUSH_KEY='**REDACTED**'" in result
        assert "bash script.sh" in result

    def test_well_formed_push_key_powershell(self):
        text = f"-PushKey '{self.VALID_UUID}'"
        result = redact_push_keys(text)
        assert self.VALID_UUID not in result
        assert "-PushKey '**REDACTED**'" in result

    def test_malformed_extra_dashes(self):
        malformed = "a1b2c3d4--e5f6--7890--abcd--ef1234567890"
        text = f"PUSH_KEY='{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_malformed_spaces(self):
        malformed = "a1b2c3d4 e5f6 7890 abcd ef1234567890"
        text = f"PUSH_KEY='{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_malformed_underscores(self):
        malformed = "a1b2c3d4_e5f6_7890_abcd_ef1234567890"
        text = f"PUSH_KEY='{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_malformed_dots(self):
        malformed = "a1b2c3d4.e5f6.7890.abcd.ef1234567890"
        text = f"PUSH_KEY='{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_malformed_no_separators(self):
        malformed = "a1b2c3d4e5f67890abcdef1234567890"
        text = f"PUSH_KEY='{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_malformed_mixed_noise(self):
        malformed = "a1b2-c3d4 e5f6_7890.abcd-ef12 3456 7890"
        text = f"PUSH_KEY='{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_malformed_powershell(self):
        malformed = "a1b2c3d4__e5f6__7890__abcd__ef1234567890"
        text = f"-PushKey  '{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_one_extra_hex_digit(self):
        malformed = "a1b2c3d4-e5f6-7890-abcd-ef1234567890a"
        text = f"PUSH_KEY='{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_two_extra_hex_digits(self):
        malformed = "a1b2c3d4-e5f6-7890-abcd-ef1234567890ab"
        text = f"PUSH_KEY='{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_three_extra_hex_digits(self):
        malformed = "a1b2c3d4-e5f6-7890-abcd-ef1234567890abc"
        text = f"PUSH_KEY='{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_four_extra_hex_digits_preserved(self):
        value = "a1b2c3d4-e5f6-7890-abcd-ef1234567890abcd"
        text = f"PUSH_KEY='{value}'"
        assert redact_push_keys(text) == text

    def test_extra_hex_with_noise_powershell(self):
        malformed = "a1b2c3d4__e5f6__7890__abcd__ef1234567890_ab"
        text = f"-PushKey '{malformed}'"
        result = redact_push_keys(text)
        assert malformed not in result
        assert "**REDACTED**" in result

    def test_non_uuid_value_preserved(self):
        text = "PUSH_KEY='not-a-uuid-at-all'"
        assert redact_push_keys(text) == text

    def test_short_value_preserved(self):
        text = "PUSH_KEY='abcd1234'"
        assert redact_push_keys(text) == text

    def test_no_push_key_context_preserved(self):
        text = f"OTHER_KEY='{self.VALID_UUID}'"
        assert redact_push_keys(text) == text

    def test_custom_replacement(self):
        text = f"PUSH_KEY='{self.VALID_UUID}'"
        result = redact_push_keys(text, "<PUSH_KEY>")
        assert self.VALID_UUID not in result
        assert "PUSH_KEY='<PUSH_KEY>'" in result

    def test_multiple_push_keys_in_same_string(self):
        uuid2 = "11111111-2222-3333-4444-555555555555"
        text = f"PUSH_KEY='{self.VALID_UUID}' then PUSH_KEY='{uuid2}'"
        result = redact_push_keys(text)
        assert self.VALID_UUID not in result
        assert uuid2 not in result
        assert result.count("**REDACTED**") == 2

    def test_case_insensitive_push_key(self):
        text = f"push_key='{self.VALID_UUID}'"
        result = redact_push_keys(text)
        assert self.VALID_UUID not in result
        assert "**REDACTED**" in result

    def test_surrounding_text_preserved(self):
        text = f"REMOTE_URL='https://api.snyk.io' PUSH_KEY='{self.VALID_UUID}' bash script.sh --client claude-code"
        result = redact_push_keys(text)
        assert "REMOTE_URL='https://api.snyk.io'" in result
        assert "bash script.sh --client claude-code" in result
        assert self.VALID_UUID not in result


# ---------------------------------------------------------------------------
# redact_push_keys_in_data (deep-traversal)
# ---------------------------------------------------------------------------


class TestRedactPushKeysInData:
    """Tests for redact_push_keys_in_data with malformed UUIDs in nested structures."""

    VALID_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

    def test_flat_dict(self):
        data = {"cmd": f"PUSH_KEY='{self.VALID_UUID}' bash script.sh"}
        redact_push_keys_in_data(data)
        assert self.VALID_UUID not in data["cmd"]
        assert "**REDACTED**" in data["cmd"]

    def test_nested_dict(self):
        data = {"outer": {"inner": f"PUSH_KEY='{self.VALID_UUID}'"}}
        redact_push_keys_in_data(data)
        assert self.VALID_UUID not in data["outer"]["inner"]

    def test_list_values(self):
        data = {"items": [f"PUSH_KEY='{self.VALID_UUID}'", "safe"]}
        redact_push_keys_in_data(data)
        assert self.VALID_UUID not in data["items"][0]
        assert data["items"][1] == "safe"

    def test_nested_list_of_dicts(self):
        malformed = "a1b2c3d4--e5f6--7890--abcd--ef1234567890"
        data = {"hooks": [{"command": f"PUSH_KEY='{malformed}' bash script.sh"}]}
        redact_push_keys_in_data(data)
        assert malformed not in data["hooks"][0]["command"]
        assert "bash script.sh" in data["hooks"][0]["command"]

    def test_mutates_in_place_and_returns(self):
        data = {"cmd": f"PUSH_KEY='{self.VALID_UUID}'"}
        result = redact_push_keys_in_data(data)
        assert result is data

    def test_non_string_values_ignored(self):
        data = {"count": 42, "flag": True, "empty": None}
        redact_push_keys_in_data(data)
        assert data == {"count": 42, "flag": True, "empty": None}

    def test_realistic_hooks_diff_with_malformed_uuid(self):
        malformed = "a1b2c3d4.e5f6.7890.abcd.ef1234567890"
        command = f"PUSH_KEY='{malformed}' REMOTE_HOOKS_BASE_URL='https://api.snyk.io' bash /path/to/script.sh"
        data = {
            "hook_event_name": "hooksConfigured",
            "session_id": "hooks-setup",
            "modified": {
                "PreToolUse": {
                    "expected_value": [{"hooks": [{"type": "command", "command": command}]}],
                },
            },
        }
        redact_push_keys_in_data(data)
        assert malformed not in str(data)
        assert (
            "REMOTE_HOOKS_BASE_URL='https://api.snyk.io'"
            in data["modified"]["PreToolUse"]["expected_value"][0]["hooks"][0]["command"]
        )
        assert data["session_id"] == "hooks-setup"
