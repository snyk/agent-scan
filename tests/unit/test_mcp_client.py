"""Unit tests for the mcp_client module."""

import contextlib
from unittest.mock import AsyncMock, Mock, patch

import pytest
from mcp.types import (
    Implementation,
    InitializeResult,
    Prompt,
    PromptsCapability,
    Resource,
    ResourcesCapability,
    ServerCapabilities,
    Tool,
    ToolsCapability,
)
from pytest_lazy_fixtures import lf

from agent_scan.mcp_client import (
    _check_server_pass,
    check_server,
    get_client,
    scan_mcp_config_file,
)
from agent_scan.models import RemoteServer, StdioServer


@pytest.mark.parametrize(
    "sample_config_file", [lf("claudestyle_config_file"), lf("vscode_mcp_config_file"), lf("vscode_config_file")]
)
@pytest.mark.asyncio
async def test_scan_mcp_config(sample_config_file):
    await scan_mcp_config_file(sample_config_file)


@pytest.mark.asyncio
@patch("agent_scan.mcp_client.stdio_client")
async def test_check_server_mocked(mock_stdio_client):
    # Create mock objects
    mock_session = Mock()
    mock_read = AsyncMock()
    mock_write = AsyncMock()

    # Mock initialize response
    mock_metadata = InitializeResult(
        protocolVersion="1.0",
        capabilities=ServerCapabilities(
            prompts=PromptsCapability(),
            resources=ResourcesCapability(),
            tools=ToolsCapability(),
        ),
        serverInfo=Implementation(
            name="TestServer",
            version="1.0",
        ),
    )
    mock_session.initialize = AsyncMock(return_value=mock_metadata)

    # Mock list responses
    mock_prompts = Mock()
    mock_prompts.prompts = [
        Prompt(name="prompt1"),
        Prompt(name="prompt"),
    ]
    mock_session.list_prompts = AsyncMock(return_value=mock_prompts)

    mock_resources = Mock()
    mock_resources.resources = [Resource(name="resource1", uri="tel:+1234567890")]
    mock_session.list_resources = AsyncMock(return_value=mock_resources)

    mock_tools = Mock()
    mock_tools.tools = [
        Tool(name="tool1", inputSchema={}),
        Tool(name="tool2", inputSchema={}),
        Tool(name="tool3", inputSchema={}),
    ]
    mock_session.list_tools = AsyncMock(return_value=mock_tools)

    # Set up the mock stdio client to return our mocked read/write pair
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = (mock_read, mock_write)
    mock_stdio_client.return_value = mock_client

    # Mock ClientSession with proper async context manager protocol
    class MockClientSession:
        def __init__(self, read, write):
            self.read = read
            self.write = write

        async def __aenter__(self):
            return mock_session

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    # Test function with mocks
    with patch("agent_scan.mcp_client.ClientSession", MockClientSession):
        server = StdioServer(command="mcp", args=["run", "some_file.py"])
        signature = await _check_server_pass(server, 2, True)

    # Verify the results
    assert len(signature.prompts) == 2
    assert len(signature.resources) == 1
    assert len(signature.tools) == 3


@pytest.mark.asyncio
async def test_math_server():
    path = "tests/mcp_servers/configs_files/math_config.json"
    servers = (await scan_mcp_config_file(path)).get_servers()
    for name, server in servers.items():
        signature, _ = await check_server(server, 5, False)
        if name == "Math":
            assert len(signature.prompts) == 1
            assert len(signature.resources) == 0
            assert {t.name for t in signature.tools} == {
                "add",
                "subtract",
                "multiply",
                "store_value",  # This is the compromised tool
                "divide",
            }


@pytest.mark.asyncio
async def test_all_server():
    path = "tests/mcp_servers/configs_files/all_config.json"
    servers = (await scan_mcp_config_file(path)).get_servers()
    for name, server in servers.items():
        signature, _ = await check_server(server, 5, False)
        if name == "Math":
            assert len(signature.prompts) == 1
            assert len(signature.resources) == 0
            assert {t.name for t in signature.tools} == {
                "add",
                "subtract",
                "multiply",
                "store_value",  # This is the compromised tool
                "divide",
            }
        if name == "Weather":
            assert {t.name for t in signature.tools} == {"weather"}
            assert {p.name for p in signature.prompts} == {"good_morning"}
            assert {r.name for r in signature.resources} == {"weathers"}
            assert {rt.name for rt in signature.resource_templates} == {"weather_description"}


@pytest.mark.asyncio
async def test_weather_server():
    path = "tests/mcp_servers/configs_files/weather_config.json"
    servers = (await scan_mcp_config_file(path)).get_servers()
    for name, server in servers.items():
        signature, _ = await check_server(server, 5, False)
        if name == "Weather":
            assert {t.name for t in signature.tools} == {"weather"}
            assert {p.name for p in signature.prompts} == {"good_morning"}
            assert {r.name for r in signature.resources} == {"weathers"}
            assert {rt.name for rt in signature.resource_templates} == {"weather_description"}


@pytest.fixture
def remote_mcp_server_just_url():
    return """
    {
        "mcpServers": {
            "remote": {
                "url": "http://localhost:8000"
            }
        }
    }
    """


@pytest.mark.asyncio
async def test_parse_server():
    pass


class TestOAuthIntegrationInGetClient:
    """Tests for OAuth support in get_client and check_server."""

    @pytest.mark.asyncio
    async def test_get_client_sse_with_oauth_provider(self):
        """get_client should pass auth to sse_client when enable_oauth=True."""
        server = RemoteServer(url="https://mcp.example.com/sse", type="sse")

        with (
            patch("agent_scan.mcp_client.sse_client") as mock_sse,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
        ):
            mock_provider = Mock()
            mock_build.return_value = (mock_provider, Mock())

            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_sse.return_value = mock_cm

            async with get_client(server, timeout=10, enable_oauth=True) as _:
                pass

            # build_oauth_client_provider must have been called
            assert mock_build.called, "build_oauth_client_provider should have been called"
            # sse_client should have been called with an auth parameter
            call_kwargs = mock_sse.call_args
            assert call_kwargs is not None
            assert "auth" in (call_kwargs.kwargs or {}), "auth should have been passed to sse_client"

    @pytest.mark.asyncio
    async def test_get_client_sse_without_oauth_no_auth(self):
        """get_client should not pass auth when enable_oauth=False and no token."""
        server = RemoteServer(url="https://mcp.example.com/sse", type="sse")

        with patch("agent_scan.mcp_client.sse_client") as mock_sse:
            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_sse.return_value = mock_cm

            async with get_client(server, timeout=10, enable_oauth=False) as _:
                pass

            call_kwargs = mock_sse.call_args
            assert call_kwargs is not None
            # auth should not be passed or should be None
            auth_val = (call_kwargs.kwargs or {}).get("auth")
            assert auth_val is None

    @pytest.mark.asyncio
    async def test_get_client_http_with_enable_oauth_no_token(self):
        """HTTP path should construct OAuthClientProvider via InteractiveTokenStorage when enable_oauth=True."""
        server = RemoteServer(url="https://mcp.example.com/mcp", type="http")

        with (
            patch("agent_scan.mcp_client.streamablehttp_client_without_session") as mock_http,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
        ):
            mock_provider = Mock()
            mock_build.return_value = (mock_provider, Mock())

            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_http.return_value = mock_cm

            async with get_client(server, timeout=10, enable_oauth=True) as _:
                pass

            mock_build.assert_called()

    @pytest.mark.asyncio
    async def test_get_client_stdio_ignores_enable_oauth(self):
        """enable_oauth should have no effect on stdio servers."""
        server = StdioServer(command="echo", args=["hello"])

        with patch("agent_scan.mcp_client.stdio_client") as mock_stdio:
            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_stdio.return_value = mock_cm

            async with get_client(server, timeout=10, enable_oauth=True) as _:
                pass

            # stdio_client should have been called normally without OAuth params
            mock_stdio.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_server_passes_enable_oauth(self):
        """check_server should accept and forward enable_oauth to _check_server_pass."""
        import asyncio
        import inspect as inspect_mod

        # First, verify check_server actually accepts enable_oauth as a parameter
        sig = inspect_mod.signature(check_server)
        assert "enable_oauth" in sig.parameters, "check_server() does not have an 'enable_oauth' parameter"

        server = StdioServer(command="echo", args=["hello"])

        with patch("agent_scan.mcp_client._check_server_pass") as mock_check:
            mock_check.return_value = Mock()

            # Use asyncio.wait_for to wrap, matching the real implementation
            result_future = asyncio.ensure_future(check_server(server, timeout=5, enable_oauth=True))
            with contextlib.suppress(Exception):
                await asyncio.wait_for(result_future, timeout=2)

            # _check_server_pass should have been called with enable_oauth=True
            assert mock_check.called, "_check_server_pass was not called"
            call_kwargs = mock_check.call_args
            assert call_kwargs.kwargs.get("enable_oauth") is True or (
                len(call_kwargs.args) > 4 and call_kwargs.args[4] is True
            )

    @pytest.mark.asyncio
    async def test_get_client_with_oauth_client_id_prepopulates_storage(self):
        """get_client should prepopulate InteractiveTokenStorage with client_id when oauth_client_id is provided."""
        from agent_scan.models import InteractiveTokenStorage, OAuthClientInformationFull

        server = RemoteServer(url="https://mcp.example.com/sse", type="sse")

        with (
            patch("agent_scan.mcp_client.sse_client") as mock_sse,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
            patch.object(InteractiveTokenStorage, "set_client_info", new_callable=AsyncMock) as mock_set_client_info,
        ):
            mock_provider = Mock()
            mock_build.return_value = (mock_provider, Mock())

            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_sse.return_value = mock_cm

            async with get_client(
                server, timeout=10, enable_oauth=True, oauth_client_id="pre-reg-id", oauth_client_secret=None
            ) as _:
                pass

            # set_client_info should have been called with an OAuthClientInformationFull
            assert mock_set_client_info.called, "set_client_info was not called"
            client_info = mock_set_client_info.call_args[0][0]
            assert isinstance(client_info, OAuthClientInformationFull)
            assert client_info.client_id == "pre-reg-id"
            assert client_info.client_secret is None

    @pytest.mark.asyncio
    async def test_get_client_with_oauth_client_id_and_secret_prepopulates_storage(self):
        """get_client should prepopulate InteractiveTokenStorage with client_id and client_secret."""
        from agent_scan.models import InteractiveTokenStorage, OAuthClientInformationFull

        server = RemoteServer(url="https://mcp.example.com/sse", type="sse")

        with (
            patch("agent_scan.mcp_client.sse_client") as mock_sse,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
            patch.object(InteractiveTokenStorage, "set_client_info", new_callable=AsyncMock) as mock_set_client_info,
        ):
            mock_provider = Mock()
            mock_build.return_value = (mock_provider, Mock())

            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_sse.return_value = mock_cm

            async with get_client(
                server, timeout=10, enable_oauth=True, oauth_client_id="cid", oauth_client_secret="csec"
            ) as _:
                pass

            assert mock_set_client_info.called, "set_client_info was not called"
            client_info = mock_set_client_info.call_args[0][0]
            assert isinstance(client_info, OAuthClientInformationFull)
            assert client_info.client_id == "cid"
            assert client_info.client_secret == "csec"

    @pytest.mark.asyncio
    async def test_get_client_without_oauth_client_id_does_not_prepopulate(self):
        """get_client should NOT call set_client_info when oauth_client_id is None."""
        from agent_scan.models import InteractiveTokenStorage

        server = RemoteServer(url="https://mcp.example.com/sse", type="sse")

        with (
            patch("agent_scan.mcp_client.sse_client") as mock_sse,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
            patch.object(InteractiveTokenStorage, "set_client_info", new_callable=AsyncMock) as mock_set_client_info,
        ):
            mock_provider = Mock()
            mock_build.return_value = (mock_provider, Mock())

            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_sse.return_value = mock_cm

            async with get_client(server, timeout=10, enable_oauth=True, oauth_client_id=None) as _:
                pass

            assert not mock_set_client_info.called, "set_client_info should NOT have been called"

    @pytest.mark.asyncio
    async def test_get_client_passes_client_id_to_build_provider(self):
        """get_client should pass client_id and client_secret kwargs to build_oauth_client_provider."""
        server = RemoteServer(url="https://mcp.example.com/sse", type="sse")

        with (
            patch("agent_scan.mcp_client.sse_client") as mock_sse,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
        ):
            mock_provider = Mock()
            mock_build.return_value = (mock_provider, Mock())

            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_sse.return_value = mock_cm

            async with get_client(
                server, timeout=10, enable_oauth=True, oauth_client_id="cid", oauth_client_secret="csec"
            ) as _:
                pass

            assert mock_build.called, "build_oauth_client_provider was not called"
            call_kwargs = mock_build.call_args.kwargs
            assert call_kwargs.get("client_id") == "cid", "client_id not passed to build_oauth_client_provider"
            assert call_kwargs.get("client_secret") == "csec", "client_secret not passed to build_oauth_client_provider"

    @pytest.mark.asyncio
    async def test_check_server_forwards_oauth_client_id_and_secret(self):
        """check_server should forward oauth_client_id and oauth_client_secret to _check_server_pass."""
        import asyncio

        server = StdioServer(command="echo", args=["hello"])

        with patch("agent_scan.mcp_client._check_server_pass") as mock_check:
            mock_check.return_value = Mock()

            result_future = asyncio.ensure_future(
                check_server(server, timeout=5, oauth_client_id="cid", oauth_client_secret="csec")
            )
            with contextlib.suppress(Exception):
                await asyncio.wait_for(result_future, timeout=2)

            assert mock_check.called, "_check_server_pass was not called"
            call_kwargs = mock_check.call_args
            assert call_kwargs.kwargs.get("oauth_client_id") == "cid"
            assert call_kwargs.kwargs.get("oauth_client_secret") == "csec"
