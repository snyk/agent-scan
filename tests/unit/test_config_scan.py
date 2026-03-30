"""Test scanning/parsing and connecting to MCP servers."""

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

from agent_scan.mcp_client import check_server, scan_mcp_config_file
from agent_scan.models import StdioServer, UnknownMCPConfig, ConfigWithoutMCP


@pytest.mark.parametrize(
    "sample_config_file",
    [
        lf("claudestyle_config_file"),
        lf("vscode_mcp_config_file"),
        lf("vscode_config_file"),
        lf("vscode_settings_file_with_empty_mcp"),
        lf("vscode_settings_file_without_mcp"),
    ],
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
        signature, _ = await check_server(server, 2, True)

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


@pytest.mark.asyncio
async def test_vscode_settings_file_without_mcp():
    path = "tests/mcp_servers/configs_files/vs_code_settings_file_without_mcp.json"
    mcp_config = await scan_mcp_config_file(path)
    assert isinstance(mcp_config, ConfigWithoutMCP)
    servers = mcp_config.get_servers()
    assert len(servers) == 0


@pytest.mark.asyncio
async def test_vscode_settings_file_with_empty_mcp():
    path = "tests/mcp_servers/configs_files/vs_code_settings_file_with_empty_mcp.json"
    mcp_config = await scan_mcp_config_file(path)
    assert isinstance(mcp_config, UnknownMCPConfig)
    servers = mcp_config.get_servers()
    assert len(servers) == 0
