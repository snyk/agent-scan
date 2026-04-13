import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from agent_scan.models import CommandParsingError, FileTokenStorage, RemoteServer, StdioServer, TokenAndClientInfo


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


class TestInteractiveTokenStorage:
    """Tests for InteractiveTokenStorage persistence and path generation."""

    @pytest.fixture(autouse=True)
    def _import_interactive_token_storage(self):
        """Import InteractiveTokenStorage at test time so collection does not fail."""
        from agent_scan.models import InteractiveTokenStorage

        self.InteractiveTokenStorage = InteractiveTokenStorage

    @pytest.mark.asyncio
    async def test_interactive_token_storage_set_and_get_tokens(self, tmp_path):
        """Round-trip: set_tokens then get_tokens should return the same token."""
        storage = self.InteractiveTokenStorage(
            base_dir=str(tmp_path),
            server_url="https://mcp.example.com",
        )
        token = OAuthToken(access_token="access123", token_type="Bearer")
        await storage.set_tokens(token)
        result = await storage.get_tokens()
        assert result is not None
        assert result.access_token == "access123"
        assert result.token_type == "Bearer"

    @pytest.mark.asyncio
    async def test_interactive_token_storage_get_tokens_returns_none_when_no_file(self, tmp_path):
        """get_tokens should return None when no token file exists."""
        storage = self.InteractiveTokenStorage(
            base_dir=str(tmp_path),
            server_url="https://mcp.example.com",
        )
        result = await storage.get_tokens()
        assert result is None

    @pytest.mark.asyncio
    async def test_interactive_token_storage_set_and_get_client_info(self, tmp_path):
        """Round-trip for client_info persistence."""
        storage = self.InteractiveTokenStorage(
            base_dir=str(tmp_path),
            server_url="https://mcp.example.com",
        )
        client_info = OAuthClientInformationFull(
            client_id="my_client_id",
            redirect_uris=["http://localhost:3030/callback"],
        )
        await storage.set_client_info(client_info)
        result = await storage.get_client_info()
        assert result is not None
        assert result.client_id == "my_client_id"

    @pytest.mark.asyncio
    async def test_interactive_token_storage_get_client_info_returns_none_when_no_file(self, tmp_path):
        """get_client_info should return None when no client info file exists."""
        storage = self.InteractiveTokenStorage(
            base_dir=str(tmp_path),
            server_url="https://mcp.example.com",
        )
        result = await storage.get_client_info()
        assert result is None

    def test_interactive_token_storage_url_safe_filename(self, tmp_path):
        """_url_safe_filename should produce only URL-safe characters (no /, :, =)."""
        storage = self.InteractiveTokenStorage(
            base_dir=str(tmp_path),
            server_url="https://mcp.example.com:8080/path?query=1",
        )
        safe_name = storage._url_safe_filename(storage._server_url)
        assert "/" not in safe_name
        assert ":" not in safe_name
        assert "=" not in safe_name

    def test_interactive_token_storage_different_urls_different_dirs(self, tmp_path):
        """Different server URLs should produce different storage directory paths."""
        storage_a = self.InteractiveTokenStorage(
            base_dir=str(tmp_path),
            server_url="https://mcp-a.example.com",
        )
        storage_b = self.InteractiveTokenStorage(
            base_dir=str(tmp_path),
            server_url="https://mcp-b.example.com",
        )
        dir_a = storage_a._get_storage_dir()
        dir_b = storage_b._get_storage_dir()
        assert dir_a != dir_b

    def test_interactive_token_storage_creates_directory(self, tmp_path):
        """_get_storage_dir should create the directory if it does not exist."""
        storage = self.InteractiveTokenStorage(
            base_dir=str(tmp_path / "nonexistent_subdir"),
            server_url="https://mcp.example.com",
        )
        storage_dir = storage._get_storage_dir()
        assert storage_dir.exists()
        assert storage_dir.is_dir()


class TestFileTokenStorageUpdated:
    """Tests for updated FileTokenStorage that should no longer raise NotImplementedError."""

    @pytest.mark.asyncio
    async def test_file_token_storage_set_tokens_no_longer_raises(self):
        """Updated FileTokenStorage.set_tokens should not raise NotImplementedError."""
        data = TokenAndClientInfo(
            token=OAuthToken(access_token="tok", token_type="bearer"),
            server_name="test",
            client_id="cid",
            token_url="https://auth.example.com/token",
            mcp_server_url="https://mcp.example.com",
            updated_at=1000000,
        )
        storage = FileTokenStorage(data=data)
        new_token = OAuthToken(access_token="new_tok", token_type="bearer")
        # This should NOT raise NotImplementedError anymore
        await storage.set_tokens(new_token)
        assert storage.data.token.access_token == "new_tok"

    @pytest.mark.asyncio
    async def test_file_token_storage_set_client_info_no_longer_raises(self):
        """Updated FileTokenStorage.set_client_info should not raise NotImplementedError."""
        data = TokenAndClientInfo(
            token=OAuthToken(access_token="tok", token_type="bearer"),
            server_name="test",
            client_id="cid",
            token_url="https://auth.example.com/token",
            mcp_server_url="https://mcp.example.com",
            updated_at=1000000,
        )
        storage = FileTokenStorage(data=data)
        client_info = OAuthClientInformationFull(
            client_id="new_cid",
            redirect_uris=["http://localhost:3030/callback"],
        )
        # This should NOT raise NotImplementedError anymore
        await storage.set_client_info(client_info)
        assert storage.data.client_id == "new_cid"
