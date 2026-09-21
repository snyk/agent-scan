"""Unit tests for the mcp_client module."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, Mock, patch

import pytest
from mcp import StdioServerParameters
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

from agent_scan import mcp_client as mcp_client_module
from agent_scan import oauth_store
from agent_scan.mcp_client import (
    _check_server_pass,
    check_server,
    get_client,
    scan_mcp_config_file,
    streamablehttp_client_without_session,
)
from agent_scan.models import RemoteServer, StdioServer
from agent_scan.utils import resolve_command_and_args


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
@patch("agent_scan.mcp_client.stdio_client")
async def test_get_client_expands_env_placeholders_for_stdio_server(mock_stdio_client, monkeypatch):
    """get_client() must pass the EXPANDED env to StdioServerParameters, not
    the literal ${VAR} placeholder from the parsed config."""
    monkeypatch.setenv("AUTH_HEADER", "Bearer real-secret-value")

    mock_read = AsyncMock()
    mock_write = AsyncMock()
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = (mock_read, mock_write)
    mock_stdio_client.return_value = mock_client

    server = StdioServer(
        command="npx",
        args=["-y", "mcp-remote@0.3.0", "https://example.com/mcp", "--header", "Authorization:${AUTH_HEADER}"],
        env={"AUTH_HEADER": "${AUTH_HEADER}"},
    )

    async with get_client(server, timeout=5):
        pass

    assert mock_stdio_client.call_count == 1
    called_params = mock_stdio_client.call_args.args[0]
    assert called_params.env == {"AUTH_HEADER": "Bearer real-secret-value"}
    assert called_params.args == server.args
    # The parsed model itself must be untouched -- still the literal placeholder.
    assert server.env == {"AUTH_HEADER": "${AUTH_HEADER}"}


@pytest.mark.asyncio
@patch("agent_scan.mcp_client.streamablehttp_client_without_session")
async def test_get_client_expands_env_placeholders_for_remote_http_server(mock_streamable_client, monkeypatch):
    """get_client() must pass the EXPANDED headers to the HTTP transport, not
    the literal ${VAR} placeholder from the parsed config."""
    monkeypatch.setenv("LINEAR_API_TOKEN", "real-secret-value")

    mock_read = AsyncMock()
    mock_write = AsyncMock()
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = (mock_read, mock_write)
    mock_streamable_client.return_value = mock_client

    server = RemoteServer(
        url="https://example.com/mcp",
        type="http",
        headers={"Authorization": "Bearer ${LINEAR_API_TOKEN}"},
    )

    async with get_client(server, timeout=5):
        pass

    assert mock_streamable_client.call_count == 1
    called_kwargs = mock_streamable_client.call_args.kwargs
    assert called_kwargs["headers"] == {"Authorization": "Bearer real-secret-value"}
    # The parsed model itself must be untouched -- still the literal placeholder.
    assert server.headers == {"Authorization": "Bearer ${LINEAR_API_TOKEN}"}


@pytest.mark.asyncio
@patch("agent_scan.mcp_client.sse_client")
async def test_get_client_expands_env_placeholders_for_remote_sse_server(mock_sse_client, monkeypatch):
    """get_client() must pass the EXPANDED headers to the SSE transport, not
    the literal ${VAR} placeholder from the parsed config."""
    monkeypatch.setenv("LINEAR_API_TOKEN", "real-secret-value")

    mock_read = AsyncMock()
    mock_write = AsyncMock()
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = (mock_read, mock_write)
    mock_sse_client.return_value = mock_client

    server = RemoteServer(
        url="https://example.com/sse",
        type="sse",
        headers={"Authorization": "Bearer ${LINEAR_API_TOKEN}"},
    )

    async with get_client(server, timeout=5):
        pass

    assert mock_sse_client.call_count == 1
    called_kwargs = mock_sse_client.call_args.kwargs
    assert called_kwargs["headers"] == {"Authorization": "Bearer real-secret-value"}
    # The parsed model itself must be untouched -- still the literal placeholder.
    assert server.headers == {"Authorization": "Bearer ${LINEAR_API_TOKEN}"}


@pytest.mark.asyncio
async def test_streamablehttp_client_without_session_wires_redirect_guard(monkeypatch):
    """Integration: the HTTP scan-path client must carry the token-exchange
    redirect guard, since the MCP SDK's OAuthClientProvider can trigger its
    own internal refresh through this same client on a 401 -- a path the
    proactive ensure_fresh_token guard in oauth_store.py never sees."""
    captured = {}

    class _FakeAsyncClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    @asynccontextmanager
    async def fake_streamable_http_client(url, http_client):
        yield (None, None, None)

    monkeypatch.setattr(mcp_client_module.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(mcp_client_module, "streamable_http_client", fake_streamable_http_client)

    async with streamablehttp_client_without_session(url="https://example.test/mcp", headers={}, timeout=5):
        pass

    hooks = captured["event_hooks"]["response"]
    assert oauth_store._reject_redirected_token_exchange in hooks


@pytest.mark.asyncio
@patch("agent_scan.mcp_client.sse_client")
async def test_get_client_sse_wires_redirect_guard(mock_sse_client):
    """Integration: the SSE scan-path client must carry the same guard."""
    mock_read = AsyncMock()
    mock_write = AsyncMock()
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = (mock_read, mock_write)
    mock_sse_client.return_value = mock_client

    server = RemoteServer(url="https://example.com/sse", type="sse")

    async with get_client(server, timeout=5):
        pass

    called_kwargs = mock_sse_client.call_args.kwargs
    factory = called_kwargs["httpx_client_factory"]
    client = factory(headers=None, timeout=None, auth=None)
    try:
        assert oauth_store._reject_redirected_token_exchange in client.event_hooks["response"]
    finally:
        await client.aclose()


@pytest.mark.parametrize(
    "input_url",
    [
        "https://example.com",
        "https://example.com/",
        "https://example.com/mcp",
        "https://example.com/mcp/",
        "https://example.com/sse",
        "https://example.com/sse/",
        "https://example.com/api/",
        "https://example.com/api/mcp/",
    ],
)
@pytest.mark.asyncio
async def test_remote_url_candidates_have_no_double_slash_and_include_clean(input_url):
    """Regression: trailing slashes or pre-existing /mcp,/sse suffixes used to
    produce candidate URLs like //mcp or /mcp/mcp, and never fell back to a
    clean URL stripped of the suffix."""
    tried: list[str] = []

    async def fake_check(server_config, *args, **kwargs):
        tried.append(server_config.url)
        raise RuntimeError("boom")

    server = RemoteServer(url=input_url)
    with patch("agent_scan.mcp_client._check_server_pass", side_effect=fake_check):
        with pytest.raises(Exception, match="(?i)could not connect|boom"):
            await check_server(server, 1, False)

    assert tried, "expected the strategy to try at least one URL"
    for url in tried:
        scheme, _, rest = url.partition("://")
        assert "//" not in rest, f"double slash leaked into candidate URL: {url}"
        assert "/mcp/mcp" not in url, f"duplicated /mcp suffix in candidate URL: {url}"
        assert "/sse/sse" not in url, f"duplicated /sse suffix in candidate URL: {url}"

    # Clean fallback (no /mcp or /sse suffix) must be among the candidates.
    expected_clean = input_url.rstrip("/")
    for suffix in ("/mcp", "/sse"):
        if expected_clean.endswith(suffix):
            expected_clean = expected_clean[: -len(suffix)]
            break
    assert expected_clean in tried, f"clean URL {expected_clean!r} not tried; tried={tried}"

    # After all strategies fail, server_config must be reset to the URL the
    # user originally configured (trailing slash stripped) and the original
    # type — not left on whatever the last attempt mutated it to.
    assert server.url == input_url.rstrip("/"), f"server.url not reset to original: {server.url!r}"
    assert server.type is None


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


class TestResolveCommandAndArgsRegression:
    """Regression: resolve_command_and_args must return list[str] for omitted args."""

    def test_resolve_returns_list_for_omitted_args_and_stdio_params_accepts_it(self, tmp_path):
        script = tmp_path / "run.sh"
        script.write_text("#!/bin/sh\necho hi\n")
        script.chmod(0o755)

        server = StdioServer.model_validate({"command": str(script)})
        command, args = resolve_command_and_args(server)
        params = StdioServerParameters(command=command, args=args)

        assert isinstance(args, list) is True
        assert args == []
        assert command == str(script)
        assert params.args == []


class TestTransportProbing:
    """check_server probes six transport/URL combinations unless probing is disabled."""

    @staticmethod
    def _failing_pass():
        return AsyncMock(side_effect=RuntimeError("connect failed"))

    @pytest.mark.asyncio
    async def test_probing_tries_six_combinations_and_groups_errors(self):
        config = RemoteServer(url="https://example.test/mcp-server/mcp", type="http")

        with patch("agent_scan.mcp_client._check_server_pass", new=self._failing_pass()) as attempt:
            with pytest.raises(ExceptionGroup):  # noqa: F821
                await check_server(config, 5)

        assert attempt.await_count == 6

    @pytest.mark.asyncio
    async def test_strict_mode_makes_exactly_one_attempt(self):
        config = RemoteServer(url="https://example.test/mcp-server/mcp", type="http")

        with patch("agent_scan.mcp_client._check_server_pass", new=self._failing_pass()) as attempt:
            with pytest.raises(RuntimeError):
                await check_server(config, 5, probe_transports=False)

        assert attempt.await_count == 1

    @pytest.mark.asyncio
    async def test_strict_mode_raises_the_real_error_not_a_group(self):
        """A single failure must surface its own exception, not ExceptionGroup(1 sub-exception)."""
        config = RemoteServer(url="https://example.test/mcp-server/mcp", type="http")

        with patch("agent_scan.mcp_client._check_server_pass", new=self._failing_pass()):
            with pytest.raises(RuntimeError, match="connect failed"):
                await check_server(config, 5, probe_transports=False)

    @pytest.mark.asyncio
    async def test_strict_mode_contacts_the_exact_url_without_suffix_rewriting(self):
        """No /mcp or /sse appending: the caller said what this server is."""
        config = RemoteServer(url="https://example.test/mcp-server/custom", type="sse")
        seen: list[tuple[str, str]] = []

        async def record(server_config, *args, **kwargs):
            seen.append((server_config.type, server_config.url))
            raise RuntimeError("connect failed")

        with patch("agent_scan.mcp_client._check_server_pass", new=record):
            with pytest.raises(RuntimeError):
                await check_server(config, 5, probe_transports=False)

        assert seen == [("sse", "https://example.test/mcp-server/custom")]

    @pytest.mark.asyncio
    async def test_strict_mode_without_a_type_falls_back_to_probing(self):
        config = RemoteServer(url="https://example.test/mcp-server/mcp")

        with patch("agent_scan.mcp_client._check_server_pass", new=self._failing_pass()) as attempt:
            with pytest.raises(ExceptionGroup):  # noqa: F821
                await check_server(config, 5, probe_transports=False)

        assert attempt.await_count == 6
