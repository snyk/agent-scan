import pytest

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
