"""Unit tests for the mcp_client module."""

import contextlib
import sys
from unittest.mock import AsyncMock, Mock, patch

if sys.version_info >= (3, 11):
    _ExceptionGroup = ExceptionGroup  # noqa: F821
else:
    _ExceptionGroup = BaseException  # broad fallback so pytest.raises still works on 3.10

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

            async with get_client(server, timeout=10, enable_oauth=True, oauth_client_id="pre-reg-id") as _:
                pass

            # set_client_info should have been called with an OAuthClientInformationFull
            assert mock_set_client_info.called, "set_client_info was not called"
            client_info = mock_set_client_info.call_args[0][0]
            assert isinstance(client_info, OAuthClientInformationFull)
            assert client_info.client_id == "pre-reg-id"

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
    async def test_get_client_passes_oauth_client_id_to_build_provider(self):
        """get_client should call build_oauth_client_provider when oauth_client_id is set."""
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

            async with get_client(server, timeout=10, enable_oauth=True, oauth_client_id="cid") as _:
                pass

            assert mock_build.called, "build_oauth_client_provider was not called"

    @pytest.mark.asyncio
    async def test_check_server_forwards_oauth_client_id(self):
        """check_server should forward oauth_client_id to _check_server_pass."""
        import asyncio

        server = StdioServer(command="echo", args=["hello"])

        with patch("agent_scan.mcp_client._check_server_pass") as mock_check:
            mock_check.return_value = Mock()

            result_future = asyncio.ensure_future(check_server(server, timeout=5, oauth_client_id="cid"))
            with contextlib.suppress(Exception):
                await asyncio.wait_for(result_future, timeout=2)

            assert mock_check.called, "_check_server_pass was not called"
            call_kwargs = mock_check.call_args
            assert call_kwargs.kwargs.get("oauth_client_id") == "cid"


class TestSharedOAuthProviderAcrossStrategies:
    """Tests for sharing a single OAuthClientProvider across all URL strategy attempts in check_server().

    The fix ensures DCR (Dynamic Client Registration) only runs once per scan by creating
    the provider in check_server() and forwarding it through _check_server_pass() and get_client().
    """

    @pytest.mark.asyncio
    async def test_shared_provider_created_once_for_oauth_across_strategy_attempts(self):
        """build_oauth_client_provider is called exactly once even when multiple strategy URLs are tried."""
        server = RemoteServer(url="https://mcp.example.com", type=None)

        with (
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
            patch("agent_scan.mcp_client._check_server_pass") as mock_check_pass,
        ):
            mock_provider = Mock()
            mock_build.return_value = (mock_provider, Mock())
            mock_check_pass.side_effect = Exception("connection failed")

            with pytest.raises((Exception, _ExceptionGroup)):
                await check_server(server, timeout=2, enable_oauth=True)

            # The provider must be constructed exactly once, not once per strategy attempt
            assert mock_build.call_count == 1, (
                f"build_oauth_client_provider should be called exactly once, "
                f"but was called {mock_build.call_count} times"
            )

    @pytest.mark.asyncio
    async def test_shared_provider_uses_original_url_not_mutated_url(self):
        """The provider is created with the original URL, not a strategy-mutated variant."""
        original_url = "https://mcp.example.com/custom-path"
        server = RemoteServer(url=original_url, type=None)

        with (
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
            patch("agent_scan.mcp_client._check_server_pass") as mock_check_pass,
        ):
            mock_build.return_value = (Mock(), Mock())
            mock_check_pass.side_effect = Exception("connection failed")

            with pytest.raises((Exception, _ExceptionGroup)):
                await check_server(server, timeout=2, enable_oauth=True)

            assert mock_build.called, "build_oauth_client_provider was not called"
            call_kwargs = mock_build.call_args
            # The server_url kwarg (or first positional arg) must be the original URL
            actual_url = call_kwargs.kwargs.get("server_url") or call_kwargs.args[0]
            assert actual_url == original_url, (
                f"Provider should be built with original URL '{original_url}', but got '{actual_url}'"
            )

    @pytest.mark.asyncio
    async def test_shared_provider_passed_to_check_server_pass(self):
        """The shared provider is forwarded to _check_server_pass() as oauth_client_provider."""
        from mcp.client.auth import OAuthClientProvider

        server = RemoteServer(url="https://mcp.example.com", type=None)

        with (
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
            patch("agent_scan.mcp_client._check_server_pass") as mock_check_pass,
        ):
            sentinel_provider = Mock(spec=OAuthClientProvider)
            mock_build.return_value = (sentinel_provider, Mock())
            mock_check_pass.side_effect = Exception("connection failed")

            with pytest.raises((Exception, _ExceptionGroup)):
                await check_server(server, timeout=2, enable_oauth=True)

            # Every call to _check_server_pass must include the shared provider
            assert mock_check_pass.call_count > 0, "_check_server_pass was never called"
            for call in mock_check_pass.call_args_list:
                provider_arg = call.kwargs.get("oauth_client_provider")
                assert provider_arg is sentinel_provider, (
                    f"_check_server_pass should receive the shared provider, "
                    f"but got oauth_client_provider={provider_arg!r}"
                )

    @pytest.mark.asyncio
    async def test_get_client_skips_provider_construction_when_provider_given(self):
        """When oauth_client_provider is passed to get_client(), it does NOT call build_oauth_client_provider internally."""
        from mcp.client.auth import OAuthClientProvider

        server = RemoteServer(url="https://mcp.example.com/sse", type="sse")
        prebuilt_provider = Mock(spec=OAuthClientProvider)

        with (
            patch("agent_scan.mcp_client.sse_client") as mock_sse,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
        ):
            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_sse.return_value = mock_cm

            async with get_client(
                server,
                timeout=10,
                enable_oauth=True,
                oauth_client_provider=prebuilt_provider,
            ) as _:
                pass

            # build_oauth_client_provider must NOT be called when provider is pre-supplied
            assert not mock_build.called, (
                "build_oauth_client_provider should not be called when oauth_client_provider is provided"
            )
            # The pre-built provider should be passed as auth to sse_client
            call_kwargs = mock_sse.call_args.kwargs or {}
            assert call_kwargs.get("auth") is prebuilt_provider, (
                "sse_client should receive the pre-built provider as auth"
            )

    @pytest.mark.asyncio
    async def test_get_client_constructs_provider_when_none_given(self):
        """Backward compat: when oauth_client_provider=None, get_client() constructs its own provider."""
        server = RemoteServer(url="https://mcp.example.com/sse", type="sse")

        with (
            patch("agent_scan.mcp_client.sse_client") as mock_sse,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
        ):
            mock_build.return_value = (Mock(), Mock())
            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_sse.return_value = mock_cm

            async with get_client(
                server,
                timeout=10,
                enable_oauth=True,
                oauth_client_provider=None,
            ) as _:
                pass

            assert mock_build.called, "build_oauth_client_provider should be called when oauth_client_provider is None"

    @pytest.mark.asyncio
    async def test_shared_provider_with_oauth_client_id_prepopulates_storage(self):
        """When oauth_client_id is provided, InteractiveTokenStorage.set_client_info is called before the strategy loop."""
        from agent_scan.models import InteractiveTokenStorage, OAuthClientInformationFull

        server = RemoteServer(url="https://mcp.example.com", type=None)

        with (
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
            patch("agent_scan.mcp_client._check_server_pass") as mock_check_pass,
            patch.object(InteractiveTokenStorage, "set_client_info", new_callable=AsyncMock) as mock_set_client_info,
        ):
            mock_build.return_value = (Mock(), Mock())
            mock_check_pass.side_effect = Exception("connection failed")

            with pytest.raises((Exception, _ExceptionGroup)):
                await check_server(server, timeout=2, enable_oauth=True, oauth_client_id="pre-reg-id")

            # set_client_info should have been called exactly once
            assert mock_set_client_info.call_count == 1, (
                f"set_client_info should be called once, but was called {mock_set_client_info.call_count} times"
            )
            client_info = mock_set_client_info.call_args[0][0]
            assert isinstance(client_info, OAuthClientInformationFull)
            assert client_info.client_id == "pre-reg-id"

    @pytest.mark.asyncio
    async def test_shared_provider_with_token_uses_file_token_storage(self):
        """When a token is provided, the shared provider uses FileTokenStorage, not InteractiveTokenStorage."""
        from mcp.shared.auth import OAuthToken

        from agent_scan.models import FileTokenStorage, TokenAndClientInfo

        mock_token = TokenAndClientInfo(
            token=OAuthToken(access_token="test-access", token_type="bearer"),
            server_name="test-server",
            client_id="test-client-id",
            token_url="https://auth.example.com/token",
            mcp_server_url="https://mcp.example.com",
            updated_at=1000000,
        )
        server = RemoteServer(url="https://mcp.example.com", type=None)

        with (
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
            patch("agent_scan.mcp_client._check_server_pass") as mock_check_pass,
        ):
            mock_build.return_value = (Mock(), Mock())
            mock_check_pass.side_effect = Exception("connection failed")

            with pytest.raises((Exception, _ExceptionGroup)):
                await check_server(server, timeout=2, token=mock_token)

            assert mock_build.called, "build_oauth_client_provider was not called"
            call_kwargs = mock_build.call_args
            # server_url should come from token, not from the server config
            actual_url = call_kwargs.kwargs.get("server_url") or call_kwargs.args[0]
            assert actual_url == mock_token.mcp_server_url, (
                f"Provider should be built with token's mcp_server_url '{mock_token.mcp_server_url}', "
                f"but got '{actual_url}'"
            )
            # storage should be a FileTokenStorage instance
            actual_storage = call_kwargs.kwargs.get("storage") or call_kwargs.args[1]
            assert isinstance(actual_storage, FileTokenStorage), (
                f"Storage should be FileTokenStorage when token is provided, got {type(actual_storage).__name__}"
            )

    @pytest.mark.asyncio
    async def test_no_shared_provider_when_oauth_disabled(self):
        """When enable_oauth=False and token=None, no provider is created and _check_server_pass gets oauth_client_provider=None explicitly."""
        server = RemoteServer(url="https://mcp.example.com", type=None)

        with (
            patch("agent_scan.mcp_client._check_server_pass") as mock_check_pass,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
        ):
            mock_check_pass.side_effect = Exception("connection failed")

            with pytest.raises((Exception, _ExceptionGroup)):
                await check_server(server, timeout=2, enable_oauth=False)

            assert not mock_build.called, "build_oauth_client_provider should not be called when OAuth is disabled"
            # Every call to _check_server_pass must explicitly include the oauth_client_provider keyword
            assert mock_check_pass.call_count > 0, "_check_server_pass was never called"
            for call in mock_check_pass.call_args_list:
                assert "oauth_client_provider" in call.kwargs, (
                    "check_server must explicitly pass oauth_client_provider kwarg to _check_server_pass, "
                    f"but the kwarg was not present. Got kwargs: {list(call.kwargs.keys())}"
                )
                assert call.kwargs["oauth_client_provider"] is None, (
                    f"_check_server_pass should receive oauth_client_provider=None, "
                    f"got {call.kwargs['oauth_client_provider']!r}"
                )

    @pytest.mark.asyncio
    async def test_stdio_server_path_unaffected(self):
        """StdioServer path doesn't create any shared provider; _check_server_pass accepts oauth_client_provider param."""
        import inspect as inspect_mod

        # First, verify _check_server_pass has the oauth_client_provider parameter
        # (required by the shared-provider refactor, even though stdio won't use it)
        sig = inspect_mod.signature(_check_server_pass)
        assert "oauth_client_provider" in sig.parameters, (
            "_check_server_pass() must accept 'oauth_client_provider' parameter"
        )

        server = StdioServer(command="echo", args=["hello"])

        with (
            patch("agent_scan.mcp_client._check_server_pass") as mock_check_pass,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
        ):
            mock_check_pass.return_value = Mock()

            import asyncio

            with contextlib.suppress(Exception):
                await asyncio.wait_for(
                    check_server(server, timeout=5, enable_oauth=True),
                    timeout=2,
                )

            assert not mock_build.called, "build_oauth_client_provider should not be called for StdioServer"

    @pytest.mark.asyncio
    async def test_get_client_http_with_prebuilt_provider(self):
        """When oauth_client_provider is passed and server type is http, streamablehttp_client receives it."""
        from mcp.client.auth import OAuthClientProvider

        server = RemoteServer(url="https://mcp.example.com/mcp", type="http")
        prebuilt_provider = Mock(spec=OAuthClientProvider)

        with (
            patch("agent_scan.mcp_client.streamablehttp_client_without_session") as mock_http,
            patch("agent_scan.mcp_client.build_oauth_client_provider") as mock_build,
        ):
            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_http.return_value = mock_cm

            async with get_client(
                server,
                timeout=10,
                oauth_client_provider=prebuilt_provider,
            ) as _:
                pass

            # build_oauth_client_provider must NOT be called
            assert not mock_build.called, (
                "build_oauth_client_provider should not be called when oauth_client_provider is provided"
            )
            # The provider must be passed to streamablehttp_client_without_session
            call_kwargs = mock_http.call_args.kwargs or {}
            assert call_kwargs.get("oauth_client_provider") is prebuilt_provider, (
                "streamablehttp_client_without_session should receive the pre-built provider"
            )
