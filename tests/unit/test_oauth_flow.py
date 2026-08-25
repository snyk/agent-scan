"""Unit tests for the interactive OAuth flow (M2)."""

import urllib.request
from types import SimpleNamespace

import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from agent_scan import oauth_flow as oauth_flow_module
from agent_scan.oauth_flow import (
    _AuthFlowTokenStorage,
    _LoopbackCallbackServer,
    _transport_strategy,
    authenticate_server,
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


def test_transport_strategy_preserves_query_string():
    # A query string must survive suffix stripping/rewriting, not be sliced off
    # or land after the wrong path segment.
    attempts = _transport_strategy("https://host/mcp?tenant=acme")
    assert ("http", "https://host/mcp?tenant=acme") in attempts
    assert ("http", "https://host?tenant=acme") in attempts
    assert ("sse", "https://host/sse?tenant=acme") in attempts


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


@pytest.mark.asyncio
async def test_authenticate_server_success_persists_token_endpoint(tmp_path, monkeypatch):
    store = OAuthTokenStore(path=tmp_path / "store.json")

    async def fake_connect_once(kind, attempt_url, provider, timeout):
        # Simulate the SDK completing the auth-code exchange during the real
        # connect: it registers the client, stores the token, and discovers
        # the token endpoint that authenticate_server later finalizes.
        await provider.context.storage.set_client_info(
            OAuthClientInformationFull(client_id="cid-1", redirect_uris=["http://127.0.0.1:0/callback"])
        )
        await provider.context.storage.set_tokens(_tok(access="access-value", refresh="refresh-value"))
        provider.context.oauth_metadata = SimpleNamespace(token_endpoint="https://example.test/token")

    monkeypatch.setattr(oauth_flow_module, "_connect_once", fake_connect_once)

    result = await authenticate_server("https://example.test/mcp", "example", store, timeout=1.0)

    assert result.ok is True
    assert result.server_url == "https://example.test"
    entry = store.get("https://example.test/mcp")
    assert entry is not None
    assert entry.token.access_token == "access-value"
    assert entry.token_url == "https://example.test/token"


@pytest.mark.asyncio
async def test_authenticate_server_reports_generic_failure_after_exhausting_transports(tmp_path, monkeypatch):
    store = OAuthTokenStore(path=tmp_path / "store.json")

    async def fake_connect_once(kind, attempt_url, provider, timeout):
        raise ConnectionRefusedError("nobody home")

    monkeypatch.setattr(oauth_flow_module, "_connect_once", fake_connect_once)

    result = await authenticate_server("https://example.test/mcp", "example", store, timeout=1.0)

    assert result.ok is False
    assert result.server_url == "https://example.test"
    assert "ConnectionRefusedError" in result.message
    # Nothing was persisted for a fully failed attempt.
    assert store.get("https://example.test/mcp") is None


@pytest.mark.asyncio
async def test_authenticate_server_warns_on_insecure_token_endpoint(tmp_path, monkeypatch):
    store = OAuthTokenStore(path=tmp_path / "store.json")

    async def fake_connect_once(kind, attempt_url, provider, timeout):
        await provider.context.storage.set_client_info(
            OAuthClientInformationFull(client_id="cid-1", redirect_uris=["http://127.0.0.1:0/callback"])
        )
        await provider.context.storage.set_tokens(_tok(access="access-value", refresh="refresh-value"))
        provider.context.oauth_metadata = SimpleNamespace(token_endpoint="http://not-secure.example/token")

    monkeypatch.setattr(oauth_flow_module, "_connect_once", fake_connect_once)

    result = await authenticate_server("https://example.test/mcp", "example", store, timeout=1.0)

    # The connection itself still succeeded -- only automatic refresh is disabled.
    assert result.ok is True
    entry = store.get("https://example.test/mcp")
    assert entry is not None
    assert entry.token_url == ""
