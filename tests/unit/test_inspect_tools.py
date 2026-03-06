import json

import pytest

from agent_scan.direct_scanner import direct_scan
from agent_scan.models import StaticToolsServer


@pytest.mark.asyncio
async def test_inspect_with_direct_tools_json():
    tools = [
        {
            "name": "search",
            "description": "Search something",
            "inputSchema": {
                "type": "object",
                "required": ["query"],
                "properties": {"query": {"type": "string"}},
            },
            "outputSchema": {
                "type": "object",
                "required": ["result"],
                "properties": {"result": {"type": "string"}},
            },
        },
        {
            "name": "fetch_content",
            "description": "Fetch URL content",
            "inputSchema": {
                "type": "object",
                "required": ["url"],
                "properties": {"url": {"type": "string"}},
            },
            "outputSchema": {
                "type": "object",
                "required": ["result"],
                "properties": {"result": {"type": "string"}},
            },
        },
    ]

    path = "tools:" + json.dumps(tools)

    config = await direct_scan(path)
    servers = config.get_servers()

    assert len(servers) == 1
    server_name, server = next(iter(servers.items()))

    assert isinstance(server, StaticToolsServer)
    assert server.type == "tools"
