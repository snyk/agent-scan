"""Unit tests for the interactive OAuth flow (M2)."""

import urllib.request

import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from agent_scan.oauth_flow import (
    _AuthFlowTokenStorage,
    _LoopbackCallbackServer,
    _transport_strategy,
)
from agent_scan.oauth_store import OAuthTokenStore


def _tok(access="a", refresh="r", expires_in=3600):
    fields = {"access_token": access, "token_type": "Bearer", "expires_in": expires_in, "refresh_token": refresh}
    return OAuthToken(**fields)


def test_transport_strategy_sse_url():
    attempts = _transport_strategy("https://mcp.atlassian.com/v1/sse")
    # Base is reduced to /v1, and both transports are tried across suffixes.
    assert ("http", "https://mcp.atlassian.com/v1/mcp") in attempts
    assert ("sse", "https://mcp.atlassian.com/v1/sse") in attempts
    assert ("sse", "https://mcp.atlassian.com/v1") in attempts
    # No duplicate attempts.
    assert len(attempts) == len(set(attempts))


def test_transport_strategy_mcp_url_prefers_http_first():
    attempts = _transport_strategy("https://mcp.linear.app/mcp")
    assert attempts[0] == ("http", "https://mcp.linear.app/mcp")
    assert ("sse", "https://mcp.linear.app/sse") in attempts


@pytest.mark.asyncio
async def test_loopback_callback_success():
    server = _LoopbackCallbackServer(port=0)
    server.start()
    try:
        # Simulate the browser redirect hitting the loopback listener.
        urllib.request.urlopen(f"{server.redirect_uri}?code=the-code&state=the-state", timeout=5).read()
        code, state = await server.callback_handler()
        assert code == "the-code"
        assert state == "the-state"
    finally:
        server.close()


@pytest.mark.asyncio
async def test_loopback_callback_error_raises():
    server = _LoopbackCallbackServer(port=0)
    server.start()
    try:
        urllib.request.urlopen(f"{server.redirect_uri}?error=access_denied&error_description=nope", timeout=5).read()
        with pytest.raises(RuntimeError, match="access_denied"):
            await server.callback_handler()
    finally:
        server.close()


def test_loopback_redirect_uri_is_127_0_0_1():
    server = _LoopbackCallbackServer(port=0)
    try:
        assert server.redirect_uri.startswith("http://127.0.0.1:")
        assert server.redirect_uri.endswith("/callback")
    finally:
        server.close()


@pytest.mark.asyncio
async def test_auth_flow_storage_creates_entry(tmp_path):
    store = OAuthTokenStore(path=tmp_path / "store.json")
    storage = _AuthFlowTokenStorage(store, "https://mcp.linear.app/mcp", "linear")
    assert await storage.get_tokens() is None

    # The SDK reports the registered client first, then the token.
    client_info = OAuthClientInformationFull(client_id="cid-1", redirect_uris=["http://127.0.0.1:5000/callback"])
    await storage.set_client_info(client_info)
    await storage.set_tokens(_tok(access="access-value", refresh="refresh-value"))

    # A full entry is created, keyed by the normalized URL (note: /sse suffix here).
    entry = store.get("https://mcp.linear.app/sse")
    assert entry is not None
    assert entry.client_id == "cid-1"
    assert entry.token.access_token == "access-value"
    assert entry.token.refresh_token == "refresh-value"
    assert entry.expires_at is not None
    assert entry.redirect_uris == ["http://127.0.0.1:5000/callback"]
