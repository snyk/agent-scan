"""Unit tests for the mcp_client module."""

from contextlib import asynccontextmanager
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
    scan_mcp_config_file,
    streamablehttp_client_without_session,
    with_default_json_content_type,
)
from agent_scan.models import StdioServer


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


def test_with_default_json_content_type_adds_header_when_missing():
    headers = with_default_json_content_type({"Authorization": "Bearer token"})

    assert headers["Content-Type"] == "application/json"
    assert headers["Authorization"] == "Bearer token"


def test_with_default_json_content_type_preserves_existing_header():
    headers = with_default_json_content_type({"content-type": "application/custom+json"})

    assert "Content-Type" not in headers
    assert headers["content-type"] == "application/custom+json"


@pytest.mark.asyncio
async def test_streamable_http_client_sets_default_json_content_type():
    async_client_cm = AsyncMock()
    async_client_instance = AsyncMock()
    async_client_cm.__aenter__.return_value = async_client_instance
    async_client_cm.__aexit__.return_value = None

    @asynccontextmanager
    async def mock_streamable_http_client(*args, **kwargs):
        yield AsyncMock(), AsyncMock(), None

    with (
        patch("agent_scan.mcp_client.httpx.AsyncClient", return_value=async_client_cm) as mock_async_client,
        patch("agent_scan.mcp_client.streamable_http_client", new=mock_streamable_http_client),
    ):
        async with streamablehttp_client_without_session(
            url="https://example.com/mcp",
            headers={"Authorization": "Bearer token"},
            timeout=30,
        ):
            pass

    headers = mock_async_client.call_args.kwargs["headers"]
    assert headers["Content-Type"] == "application/json"
    assert headers["Authorization"] == "Bearer token"


@pytest.mark.asyncio
async def test_streamable_http_client_preserves_existing_content_type():
    async_client_cm = AsyncMock()
    async_client_instance = AsyncMock()
    async_client_cm.__aenter__.return_value = async_client_instance
    async_client_cm.__aexit__.return_value = None

    @asynccontextmanager
    async def mock_streamable_http_client(*args, **kwargs):
        yield AsyncMock(), AsyncMock(), None

    with (
        patch("agent_scan.mcp_client.httpx.AsyncClient", return_value=async_client_cm) as mock_async_client,
        patch("agent_scan.mcp_client.streamable_http_client", new=mock_streamable_http_client),
    ):
        async with streamablehttp_client_without_session(
            url="https://example.com/mcp",
            headers={"content-type": "application/custom+json"},
            timeout=30,
        ):
            pass

    headers = mock_async_client.call_args.kwargs["headers"]
    assert "Content-Type" not in headers
    assert headers["content-type"] == "application/custom+json"
