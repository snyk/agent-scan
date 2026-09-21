import asyncio
import socket
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from agent_scan.inspect import inspect_client
from agent_scan.mcp_client import (
    UnsafeMCPDestination,
    _check_server_pass,
    _create_mcp_http_client_without_redirects,
    _find_unsafe_destination,
)
from agent_scan.models import ClientToInspect, RemoteServer, StdioServer
from agent_scan.models.errors import FAILURE_CATEGORY_TO_CODE


def resolved(*addresses):
    return [
        (socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))
        for address in addresses
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["sse", "http"])
@pytest.mark.parametrize(
    "address",
    ["169.254.169.254", "169.254.0.1", "fe80::1", "febf::1", "fd00:ec2::254", "100.100.100.200"],
)
@pytest.mark.parametrize("hostname", [False, True])
async def test_both_transports_refuse_blocked_destinations(transport, address, hostname):
    host = "metadata.example" if hostname else (f"[{address}]" if ":" in address else address)
    with (
        patch.object(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=resolved(address))),
        patch.object(httpx.AsyncHTTPTransport, "handle_async_request", new_callable=AsyncMock) as send,
    ):
        with pytest.raises(Exception) as error:
            await _check_server_pass(RemoteServer(type=transport, url=f"http://{host}/mcp"), timeout=5)

        assert _find_unsafe_destination(error.value) is not None
        send.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["169.254.169.254", "2852039166", "025177524776", "[::ffff:169.254.169.254]"])
async def test_system_resolver_catches_literal_and_encoded_metadata(host):
    with patch.object(httpx.AsyncHTTPTransport, "handle_async_request", new_callable=AsyncMock) as send:
        async with _create_mcp_http_client_without_redirects() as client:
            with pytest.raises(UnsafeMCPDestination, match="Connection refused"):
                await client.get(f"http://{host}/mcp")
        send.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "127.255.255.254", "::1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "fc00::1", "fd00::1", "8.8.8.8"],
)
async def test_loopback_private_and_public_addresses_remain_allowed(address):
    with (
        patch.object(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=resolved(address))),
        patch.object(
            httpx.AsyncHTTPTransport, "handle_async_request", AsyncMock(return_value=httpx.Response(200))
        ) as send,
    ):
        async with _create_mcp_http_client_without_redirects() as client:
            assert (await client.get("http://mcp.example/mcp")).status_code == 200
        send.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("addresses", [("127.0.0.1", "169.254.169.254"), ("fe80::1", "::1")])
async def test_any_blocked_answer_refuses_entire_destination(addresses):
    with (
        patch.object(asyncio.get_running_loop(), "getaddrinfo", AsyncMock(return_value=resolved(*addresses))),
        patch.object(httpx.AsyncHTTPTransport, "handle_async_request", new_callable=AsyncMock) as send,
    ):
        async with _create_mcp_http_client_without_redirects() as client:
            with pytest.raises(UnsafeMCPDestination):
                await client.get("http://mcp.example/mcp")
        send.assert_not_called()


@pytest.mark.asyncio
async def test_every_request_is_guarded():
    with (
        patch.object(
            asyncio.get_running_loop(),
            "getaddrinfo",
            AsyncMock(side_effect=[resolved("127.0.0.1"), resolved("169.254.169.254")]),
        ),
        patch.object(
            httpx.AsyncHTTPTransport, "handle_async_request", AsyncMock(return_value=httpx.Response(200))
        ) as send,
    ):
        async with _create_mcp_http_client_without_redirects() as client:
            await client.get("http://mcp.example/mcp")
            with pytest.raises(UnsafeMCPDestination):
                await client.post("http://mcp.example/mcp", json={})
        send.assert_awaited_once()


@pytest.mark.asyncio
async def test_refusal_is_actionable_per_server_error_and_inspection_continues():
    client = ClientToInspect(
        name="test-client",
        client_path="/proj",
        mcp_configs={
            "/proj/mcp.json": [
                ("metadata-server", RemoteServer(url="http://169.254.169.254/mcp")),
                ("local-server", StdioServer(command="local-mcp")),
            ]
        },
        skills_dirs={},
    )
    with patch.object(httpx.AsyncHTTPTransport, "handle_async_request", new_callable=AsyncMock) as send:
        result = await inspect_client(client, timeout=5, tokens=[], scan_skills=False, do_stdio_handshake=False)
        send.assert_not_called()
    servers = {server.name: server for server in result.servers}
    error = servers["metadata-server"].error
    assert FAILURE_CATEGORY_TO_CODE[error.category] == "X001"
    assert "metadata-server" in error.message
    assert "169.254.169.254" in error.message
    assert "Connection refused" in error.message
    assert "Configure this MCP server" in error.message
    assert servers["local-server"].error is None
