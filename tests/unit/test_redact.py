"""Unit tests for the redaction module."""

import re
from urllib.parse import parse_qsl, urlsplit

import pytest

from agent_scan.models import RemoteServer, ScanPathResult, ServerScanResult, StdioServer
from agent_scan.redact import redact_absolute_paths, redact_args, redact_data, redact_scan_result

# High-entropy 40-char mixed-case+digit literal that should be flagged by
# detect-secrets' default high-entropy plugins. NOT a known-prefix token
# (the user explicitly forbade ghp_/sk-proj-/etc.). If during the red phase
# this exact string is not flagged by the default plugins, swap to another
# high-entropy random string of similar shape.
FAKE_API_KEY = "Xk9mPq2vNwBzRtY7Lc4hJfDsAe6uGiQoVpWbZxMr"

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
