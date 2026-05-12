"""Unit tests for the redaction module."""

import re
from urllib.parse import parse_qsl, urlsplit

import pytest

from agent_scan.models import RemoteServer, ScanPathResult, ServerScanResult, StdioServer
from agent_scan.redact import redact_absolute_paths, redact_args, redact_scan_result

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
