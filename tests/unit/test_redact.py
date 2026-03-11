"""Unit tests for the redaction module."""

from urllib.parse import parse_qsl, urlsplit

import pytest

from agent_scan.models import RemoteServer, ScanPathResult, ServerScanResult, StdioServer
from agent_scan.redact import redact_absolute_paths, redact_args, redact_scan_result


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
    """Unit tests for redact_args function."""

    def test_redact_args_none(self):
        """Test that None input returns None."""
        assert redact_args(None) is None

    def test_redact_args_empty(self):
        """Test that empty list returns empty list."""
        assert redact_args([]) == []

    def test_redact_args_positional_only(self):
        """Test that positional arguments are preserved."""
        args = ["script.js", "input.txt", "output.txt"]
        result = redact_args(args)
        assert result == ["script.js", "input.txt", "output.txt"]

    def test_redact_args_flag_with_value(self):
        """Test that flag values are redacted."""
        args = ["--api-key", "secret123"]
        result = redact_args(args)
        assert result == ["--api-key", "**REDACTED**"]

    def test_redact_args_short_flag_with_value(self):
        """Test that short flag values are redacted."""
        args = ["-k", "secret123"]
        result = redact_args(args)
        assert result == ["-k", "**REDACTED**"]

    def test_redact_args_equals_syntax(self):
        """Test that --flag=value syntax is handled."""
        args = ["--api-key=secret123", "--token=xyz"]
        result = redact_args(args)
        assert result == ["--api-key=**REDACTED**", "--token=**REDACTED**"]

    def test_redact_args_flag_without_value(self):
        """Test that flags without values are preserved."""
        args = ["--verbose", "--debug"]
        result = redact_args(args)
        assert result == ["--verbose", "--debug"]

    def test_redact_args_mixed(self):
        """Test mixed positional, flags, and flag-value pairs."""
        args = ["script.js", "--verbose", "--api-key", "secret", "-o", "output.txt"]
        result = redact_args(args)
        assert result == ["script.js", "--verbose", "--api-key", "**REDACTED**", "-o", "**REDACTED**"]

    def test_redact_args_complex_command(self):
        """Test a realistic MCP server command.
        Note: -y is treated as a boolean flag (like in npx -y), so the following arg is not its value.
        """
        args = ["-y", "some-mcp-server", "--token", "abc123", "--port", "3000"]
        result = redact_args(args)
        # -y is a boolean flag, so "some-mcp-server" is preserved as a positional arg
        assert result == ["-y", "some-mcp-server", "--token", "**REDACTED**", "--port", "**REDACTED**"]

    def test_redact_args_mixed_equals_and_space(self):
        """Test mix of equals and space-separated values."""
        args = ["--key=value1", "--secret", "value2", "--flag"]
        result = redact_args(args)
        assert result == ["--key=**REDACTED**", "--secret", "**REDACTED**", "--flag"]

    def test_redact_args_unix_paths(self):
        """Test that Unix absolute paths are redacted."""
        args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/developer/code"]
        result = redact_args(args)
        assert result == ["-y", "@modelcontextprotocol/server-filesystem", "**REDACTED**"]

    def test_redact_args_home_paths(self):
        """Test that home directory paths are redacted."""
        args = ["-y", "some-server", "~/Documents/projects"]
        result = redact_args(args)
        assert result == ["-y", "some-server", "**REDACTED**"]

    def test_redact_args_preserves_package_names(self):
        """Test that npm package names are not redacted."""
        args = ["-y", "@modelcontextprotocol/server-github", "--token", "secret"]
        result = redact_args(args)
        assert result == ["-y", "@modelcontextprotocol/server-github", "--token", "**REDACTED**"]


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
    Note: -y is treated as a boolean flag (like in npx -y), so the package name is preserved.
    """
    result = ScanPathResult(
        path="/dummy/path",
        servers=[
            ServerScanResult(
                name="stdio",
                server=StdioServer(
                    command="npx",
                    args=["-y", "some-server", "--api-key", "secret123", "--token=xyz"],
                    env={},
                ),
            )
        ],
    )

    result = redact_scan_result(result)

    assert result.servers is not None and len(result.servers) == 1
    srv = result.servers[0]
    assert isinstance(srv.server, StdioServer)
    assert srv.server.args == ["-y", "some-server", "--api-key", "**REDACTED**", "--token=**REDACTED**"]


FAKE_API_KEY = "sk-this-is-a-fake-api-key"


@pytest.mark.parametrize(
    "server",
    [
        ServerScanResult(
            name="Weather",
            server=StdioServer(
                command="uv run python",
                args=["tests/mcp_servers/weather_server.py"],
                env={"API_KEY": FAKE_API_KEY},
            ),
        ),
        ServerScanResult(
            name="Math",
            server=StdioServer(
                command="uv run python",
                args=["tests/mcp_servers/math_server.py", f"--api-key={FAKE_API_KEY}"],
            ),
        ),
    ],
)
def test_redact_scan_result_removes_api_key(server):
    """
    Ensure redact_scan_result removes API keys from server configs.
    """
    result = ScanPathResult(path="/dummy/path", servers=[server])

    redacted = redact_scan_result(result)

    dump = redacted.model_dump_json()
    assert FAKE_API_KEY not in dump
