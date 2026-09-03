"""Tests for the ``mcp-auth`` command's exit status.

``mcp_auth`` must return a status that reflects whether every requested
target actually authenticated, since ``cli.py`` propagates it via
``sys.exit`` and scripts rely on the exit code to detect failure.
"""

from argparse import Namespace
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import mcp_auth
from agent_scan.models import RemoteServer
from agent_scan.oauth_flow import AuthResult


def _args(**kwargs):
    defaults = {
        "url": None,
        "server": None,
        "all_servers": False,
        "server_timeout": 10,
        "scan_all_users": False,
    }
    defaults.update(kwargs)
    return Namespace(**defaults)


@pytest.mark.asyncio
async def test_returns_zero_when_url_target_succeeds():
    with patch(
        "agent_scan.oauth_flow.authenticate_server",
        AsyncMock(return_value=AuthResult(ok=True, server_url="https://example.test")),
    ):
        assert await mcp_auth(_args(url="https://example.test/mcp")) == 0


@pytest.mark.asyncio
async def test_returns_one_when_url_target_fails():
    with patch(
        "agent_scan.oauth_flow.authenticate_server",
        AsyncMock(return_value=AuthResult(ok=False, server_url="https://example.test", message="boom")),
    ):
        assert await mcp_auth(_args(url="https://example.test/mcp")) == 1


@pytest.mark.asyncio
async def test_returns_one_for_unknown_server_name():
    with patch("agent_scan.cli.discover_servers_by_name", AsyncMock(return_value={})):
        assert await mcp_auth(_args(server="does-not-exist")) == 1


@pytest.mark.asyncio
async def test_returns_one_when_no_target_specified():
    with patch("agent_scan.cli.discover_servers_by_name", AsyncMock(return_value={})):
        assert await mcp_auth(_args()) == 1


@pytest.mark.asyncio
async def test_returns_one_when_any_of_several_targets_fails():
    discovered = {
        "good": RemoteServer(url="https://good.test/mcp"),
        "bad": RemoteServer(url="https://bad.test/mcp"),
    }
    results = {
        "https://good.test/mcp": AuthResult(ok=True, server_url="https://good.test"),
        "https://bad.test/mcp": AuthResult(ok=False, server_url="https://bad.test", message="boom"),
    }

    async def fake_authenticate_server(url, name, store, **kwargs):
        return results[url]

    with (
        patch("agent_scan.cli.discover_servers_by_name", AsyncMock(return_value=discovered)),
        patch("agent_scan.oauth_flow.authenticate_server", fake_authenticate_server),
    ):
        assert await mcp_auth(_args(all_servers=True)) == 1
