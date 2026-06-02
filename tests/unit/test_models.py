import pytest
from pydantic import ValidationError

from agent_scan.models import CommandParsingError, RemoteServer, StdioServer


class TestRemoteServerUrlAlias:
    """Test that RemoteServer accepts both 'url' and 'serverUrl' field names."""

    def test_url_field_works(self):
        server = RemoteServer(url="https://mcp.example.com/mcp")
        assert server.url == "https://mcp.example.com/mcp"

    def test_server_url_alias_works(self):
        server = RemoteServer.model_validate({"serverUrl": "https://mcp.figma.com/mcp"})
        assert server.url == "https://mcp.figma.com/mcp"

    def test_server_url_alias_with_type(self):
        server = RemoteServer.model_validate({"serverUrl": "https://mcp.figma.com/mcp", "type": "http"})
        assert server.url == "https://mcp.figma.com/mcp"
        assert server.type == "http"

    def test_server_url_alias_with_headers(self):
        server = RemoteServer.model_validate(
            {
                "serverUrl": "https://mcp.example.com/mcp",
                "headers": {"Authorization": "Bearer token"},
            }
        )
        assert server.url == "https://mcp.example.com/mcp"
        assert server.headers == {"Authorization": "Bearer token"}

    def test_url_takes_precedence_when_both_present(self):
        # If both are somehow present, 'url' should win (it's first in AliasChoices)
        server = RemoteServer.model_validate(
            {"url": "https://primary.example.com/mcp", "serverUrl": "https://secondary.example.com/mcp"}
        )
        assert server.url == "https://primary.example.com/mcp"

    def test_http_url_alias_works(self):
        # Gemini CLI / Antigravity declare Streamable-HTTP remote servers with
        # an ``httpUrl`` key; it must map onto ``url`` like ``serverUrl`` does.
        server = RemoteServer.model_validate({"httpUrl": "https://mcp.gemini.example/mcp"})
        assert server.url == "https://mcp.gemini.example/mcp"

    def test_http_url_alias_with_headers(self):
        server = RemoteServer.model_validate(
            {
                "httpUrl": "https://mcp.gemini.example/mcp",
                "headers": {"Authorization": "Bearer token"},
            }
        )
        assert server.url == "https://mcp.gemini.example/mcp"
        assert server.headers == {"Authorization": "Bearer token"}

    def test_url_takes_precedence_over_http_url_when_both_present(self):
        # ``url`` is first in AliasChoices, so it wins over ``httpUrl``.
        server = RemoteServer.model_validate(
            {"url": "https://primary.example.com/mcp", "httpUrl": "https://secondary.example.com/mcp"}
        )
        assert server.url == "https://primary.example.com/mcp"


class TestRemoteServerTransportType:
    """``streamable-http`` folds onto ``http``; ``ws`` is not yet supported.

    ``type: "streamable-http"`` is a documented Claude Code spelling of the HTTP
    Streamable transport, so it normalizes to ``http``. ``type: "ws"`` is also a
    documented Claude Code transport but is intentionally rejected for now
    (TODO(ADS-384)) because the downstream backend/platform only accept
    ``{sse, http}``.
    """

    def test_existing_sse_type_unchanged(self):
        server = RemoteServer.model_validate({"url": "https://mcp.example.com/sse", "type": "sse"})
        assert server.type == "sse"

    def test_existing_http_type_unchanged(self):
        server = RemoteServer.model_validate({"url": "https://mcp.example.com/mcp", "type": "http"})
        assert server.type == "http"

    def test_type_omitted_stays_none(self):
        server = RemoteServer.model_validate({"url": "https://mcp.example.com/mcp"})
        assert server.type is None

    def test_streamable_http_normalized_to_http(self):
        # ``streamable-http`` is the same Streamable HTTP transport the client
        # already speaks under ``http`` -- fold it on so the connect path needs
        # no new branch.
        server = RemoteServer.model_validate({"url": "https://mcp.example.com/mcp", "type": "streamable-http"})
        assert server.type == "http"

    def test_streamable_https_normalized_to_http(self):
        server = RemoteServer.model_validate({"url": "https://mcp.example.com/mcp", "type": "streamable-https"})
        assert server.type == "http"

    def test_ws_type_rejected(self):
        # ``ws`` is a documented Claude Code transport, but it is intentionally
        # NOT accepted yet -- emitting it breaks the downstream backend/platform
        # (which validate against {sse, http} only). Re-add it end-to-end via
        # TODO(ADS-384): https://snyksec.atlassian.net/browse/ADS-384
        with pytest.raises(ValidationError):
            RemoteServer.model_validate({"url": "wss://mcp.example.com/ws", "type": "ws"})

    def test_type_is_case_insensitive(self):
        server = RemoteServer.model_validate({"url": "https://mcp.example.com/mcp", "type": "HTTP"})
        assert server.type == "http"


class TestStdioServerRebalance:
    """Test that StdioServer automatically rebalances command and args on creation."""

    @pytest.mark.parametrize(
        "input_command, input_args, expected_command, expected_args",
        [
            # NPX-based MCP servers
            (
                "npx -y @rf-d/motion-mcp",
                None,
                "npx",
                ["-y", "@rf-d/motion-mcp"],
            ),
            (
                "npx -y @modelcontextprotocol/server-filesystem /path/to/dir",
                None,
                "npx",
                ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/dir"],
            ),
            (
                "npx -y @modelcontextprotocol/server-github",
                ["--token", "abc123"],
                "npx",
                ["-y", "@modelcontextprotocol/server-github", "--token", "abc123"],
            ),
            # UVX-based MCP servers
            (
                "uvx agent-scan@latest --json",
                ["--control-server=something"],
                "uvx",
                ["agent-scan@latest", "--json", "--control-server=something"],
            ),
            (
                "uvx mcp-server-fetch",
                ["--timeout", "30"],
                "uvx",
                ["mcp-server-fetch", "--timeout", "30"],
            ),
            # Python module MCP servers
            (
                "python -m mcp_server_sqlite",
                ["--db", "test.db"],
                "python",
                ["-m", "mcp_server_sqlite", "--db", "test.db"],
            ),
            # Docker-based MCP servers
            (
                "docker run -i --rm mcp/filesystem",
                None,
                "docker",
                ["run", "-i", "--rm", "mcp/filesystem"],
            ),
            # Already balanced (single command)
            (
                "npx",
                ["-y", "@rf-d/motion-mcp"],
                "npx",
                ["-y", "@rf-d/motion-mcp"],
            ),
            # Command with quoted paths
            (
                'python "/path/with spaces/server.py"',
                None,
                "python",
                ['"/path/with spaces/server.py"'],
            ),
            # Node direct execution
            (
                "node /usr/local/lib/mcp-server/index.js",
                None,
                "node",
                ["/usr/local/lib/mcp-server/index.js"],
            ),
            # Extra whitespace handling
            (
                "npx   -y   @modelcontextprotocol/server-brave-search",
                None,
                "npx",
                ["-y", "@modelcontextprotocol/server-brave-search"],
            ),
        ],
    )
    def test_rebalance_on_creation(
        self,
        input_command: str,
        input_args: list[str] | None,
        expected_command: str,
        expected_args: list[str],
    ):
        """Test that command/args are rebalanced when StdioServer is created."""
        server = StdioServer(command=input_command, args=input_args)

        assert server.command == expected_command
        assert server.args == expected_args

    def test_rebalance_preserves_env(self):
        """Test that rebalancing doesn't affect other fields."""
        env = {"API_KEY": "secret", "DEBUG": "true"}
        server = StdioServer(
            command="npx -y @modelcontextprotocol/server-github",
            args=None,
            env=env,
        )

        assert server.command == "npx"
        assert server.args == ["-y", "@modelcontextprotocol/server-github"]
        assert server.env == env
        assert server.type == "stdio"

    def test_rebalance_with_malformed_command_raises(self):
        """Test that malformed commands (e.g., unterminated quotes) raise an error."""
        with pytest.raises(CommandParsingError):
            StdioServer(command='npx "unterminated', args=None)

    def test_rebalance_with_empty_command_raises(self):
        """Test that empty commands raise an error."""
        with pytest.raises(CommandParsingError):
            StdioServer(command="", args=None)

    def test_rebalance_with_whitespace_only_raises(self):
        """Test that whitespace-only commands raise an error."""
        with pytest.raises(CommandParsingError):
            StdioServer(command="   ", args=None)


class TestStdioServerArgsCoercion:
    """args=None / missing args must coerce to [] regardless of command shape."""

    def test_args_omitted(self):
        s = StdioServer.model_validate({"command": "npx"})
        assert s.args == []

    def test_args_explicit_null(self):
        s = StdioServer.model_validate({"command": "npx", "args": None})
        assert s.args == []

    def test_args_empty_list_preserved(self):
        s = StdioServer.model_validate({"command": "npx", "args": []})
        assert s.args == []

    def test_args_populated_preserved(self):
        s = StdioServer.model_validate({"command": "npx", "args": ["-y", "pkg"]})
        assert s.args == ["-y", "pkg"]

    def test_existing_absolute_path_with_no_args(self, tmp_path):
        """Reproduces the production failure mode: run.sh wrapper, no args."""
        script = tmp_path / "run.sh"
        script.write_text("#!/bin/sh\necho hi\n")
        script.chmod(0o755)
        s = StdioServer.model_validate({"command": str(script)})
        assert s.command == str(script)
        assert s.args == []

    def test_existing_absolute_path_with_explicit_null_args(self, tmp_path):
        """Explicit null args on an existing-path command must coerce to []."""
        script = tmp_path / "run.sh"
        script.write_text("#!/bin/sh\necho hi\n")
        script.chmod(0o755)
        s = StdioServer.model_validate({"command": str(script), "args": None})
        assert s.command == str(script)
        assert s.args == []

    def test_existing_absolute_path_with_populated_args_preserved(self, tmp_path):
        """Populated args on an existing-path command must be preserved verbatim."""
        script = tmp_path / "run.sh"
        script.write_text("#!/bin/sh\necho hi\n")
        script.chmod(0o755)
        s = StdioServer.model_validate({"command": str(script), "args": ["--foo", "bar"]})
        assert s.command == str(script)
        assert s.args == ["--foo", "bar"]


class TestMCPServerMap:
    """MCPServerMap is the agent-neutral model for an already-extracted
    ``{name: serverConfig}`` map (no wrapper key), used by ``_validate_servers``."""

    def test_validates_mixed_stdio_and_remote(self):
        from agent_scan.models import MCPServerMap

        m = MCPServerMap(servers={"a": {"command": "x"}, "b": {"url": "https://y"}})
        servers = m.get_servers()
        assert isinstance(servers["a"], StdioServer)
        assert isinstance(servers["b"], RemoteServer)
        assert servers["a"].command == "x"
        assert servers["b"].url == "https://y"

    def test_rejects_value_that_is_not_a_server_config(self):
        from pydantic import ValidationError

        from agent_scan.models import MCPServerMap

        with pytest.raises(ValidationError):
            MCPServerMap(servers={"bad": {"not_a": "server"}})
