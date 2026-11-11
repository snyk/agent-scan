"""Unit tests for the interactive OAuth flow (M2)."""

import threading
import urllib.request
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import httpx
import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from agent_scan import oauth_flow as oauth_flow_module
from agent_scan import oauth_store
from agent_scan.mcp_client import UnsafeMCPDestination
from agent_scan.oauth_flow import (
    _AuthFlowTokenStorage,
    _connect_once,
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


class _FakeSession:
    """Stands in for ClientSession so _connect_once's real MCP handshake
    (which the fake streams below can't actually service) never runs."""

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def initialize(self):
        return None


@pytest.mark.asyncio
async def test_connect_once_http_wires_redirect_guard(monkeypatch):
    """Integration: mcp-auth's HTTP connection attempt must carry the
    token-exchange redirect guard, since the OAuthClientProvider it's given
    can trigger its own internal refresh/auth-code exchange through this same
    client on a 401 -- a path this module's own no-redirect refresh guard
    (ensure_fresh_token, in oauth_store.py) never sees."""
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

    monkeypatch.setattr(oauth_flow_module.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(oauth_flow_module, "streamable_http_client", fake_streamable_http_client)
    monkeypatch.setattr(oauth_flow_module, "ClientSession", _FakeSession)

    await _connect_once("http", "https://example.test/mcp", provider=object(), timeout=5.0)

    hooks = captured["event_hooks"]["response"]
    assert oauth_store._reject_redirected_token_exchange in hooks


@pytest.mark.asyncio
async def test_connect_once_sse_wires_redirect_guard(monkeypatch):
    """Integration: mcp-auth's SSE connection attempt must carry the same guard."""
    captured = {}

    @asynccontextmanager
    async def fake_sse_client(**kwargs):
        captured.update(kwargs)
        yield (None, None)

    monkeypatch.setattr(oauth_flow_module, "sse_client", fake_sse_client)
    monkeypatch.setattr(oauth_flow_module, "ClientSession", _FakeSession)

    await _connect_once("sse", "https://example.test/sse", provider=object(), timeout=5.0)

    factory = captured["httpx_client_factory"]
    client = factory(headers=None, timeout=None, auth=None)
    try:
        assert oauth_store._reject_redirected_token_exchange in client.event_hooks["response"]
    finally:
        await client.aclose()


_METADATA_URL = "http://169.254.169.254/latest/meta-data/"


class _RedirectHandler(BaseHTTPRequestHandler):
    """Loopback server: /hop -> /ok (a legitimate redirect), /to-metadata -> cloud metadata address."""

    def do_GET(self):
        if self.path == "/ok":
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(302)
        self.send_header("Location", "/ok" if self.path == "/hop" else _METADATA_URL)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def redirect_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


async def _probe_destination_guard(client: httpx.AsyncClient, base_url: str) -> dict[str, object]:
    """What a client does with a direct metadata request, a redirect *to* metadata, and a normal redirect."""
    outcomes: dict[str, object] = {}
    for label, url in {
        "metadata": _METADATA_URL,
        "redirect_to_metadata": f"{base_url}/to-metadata",
        "legitimate_redirect": f"{base_url}/hop",
    }.items():
        try:
            outcomes[label] = (await client.get(url)).status_code
        except UnsafeMCPDestination:
            outcomes[label] = "blocked"
    return outcomes


_EXPECTED_GUARD_OUTCOMES = {"metadata": "blocked", "redirect_to_metadata": "blocked", "legitimate_redirect": 200}


@pytest.mark.asyncio
async def test_connect_once_http_client_applies_destination_guard_and_keeps_redirects(monkeypatch, redirect_server):
    """mcp-auth must refuse metadata destinations at every hop (as scans do) without giving up redirects."""
    outcomes: dict[str, object] = {}

    @asynccontextmanager
    async def probing_streamable_http_client(url, http_client):
        outcomes.update(await _probe_destination_guard(http_client, redirect_server))
        yield (None, None, None)

    class _NoOpAuth(httpx.Auth):
        def auth_flow(self, request):
            yield request

    monkeypatch.setattr(oauth_flow_module, "streamable_http_client", probing_streamable_http_client)
    monkeypatch.setattr(oauth_flow_module, "ClientSession", _FakeSession)

    await _connect_once("http", f"{redirect_server}/mcp", provider=_NoOpAuth(), timeout=2.0)

    assert outcomes == _EXPECTED_GUARD_OUTCOMES


@pytest.mark.asyncio
async def test_connect_once_sse_client_applies_destination_guard(monkeypatch, redirect_server):
    """The SDK's own client (mcp 1.30) leaves redirects off -- its transport follows same-origin ones itself --
    so here the redirect is simply not followed; what must hold is that metadata is never reached."""
    captured = {}

    @asynccontextmanager
    async def fake_sse_client(**kwargs):
        captured.update(kwargs)
        yield (None, None)

    monkeypatch.setattr(oauth_flow_module, "sse_client", fake_sse_client)
    monkeypatch.setattr(oauth_flow_module, "ClientSession", _FakeSession)

    await _connect_once("sse", f"{redirect_server}/sse", provider=object(), timeout=2.0)

    client = captured["httpx_client_factory"](headers=None, timeout=httpx.Timeout(2.0), auth=None)
    try:
        outcomes = await _probe_destination_guard(client, redirect_server)
    finally:
        await client.aclose()

    assert outcomes["metadata"] == "blocked"
    assert outcomes["redirect_to_metadata"] in ("blocked", 302)  # refused, or returned unfollowed -- never fetched


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

    # A full entry is created, keyed by the exact URL passed at construction.
    entry = store.get("https://mcp.linear.app/mcp")
    assert entry is not None
    assert entry.client_id == "cid-1"
    assert entry.token.access_token == "access-value"
    assert entry.token.refresh_token == "refresh-value"
    assert entry.expires_at is not None
    assert entry.redirect_uris == ["http://127.0.0.1:5000/callback"]
    # A different suffix on the same origin must not see this credential.
    assert store.get("https://mcp.linear.app/sse") is None


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
    assert result.server_url == "https://example.test/mcp"
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
    assert result.server_url == "https://example.test/mcp"
    assert "ConnectionRefusedError" in result.message
    # Nothing was persisted for a fully failed attempt.
    assert store.get("https://example.test/mcp") is None


@pytest.mark.asyncio
async def test_authenticate_server_names_a_blocked_destination_instead_of_an_exception_group(tmp_path, monkeypatch):
    """The transports run in anyio task groups, so a refused destination arrives wrapped in an ExceptionGroup."""
    store = OAuthTokenStore(path=tmp_path / "store.json")
    request = httpx.Request("GET", _METADATA_URL)

    async def fake_connect_once(kind, attempt_url, provider, timeout):
        refused = UnsafeMCPDestination(
            "Connection refused: blocked link-local or cloud-metadata address", request=request
        )
        raise ExceptionGroup("unhandled errors in a TaskGroup", [refused])  # noqa: F821

    monkeypatch.setattr(oauth_flow_module, "_connect_once", fake_connect_once)

    result = await authenticate_server("https://example.test/mcp", "example", store, timeout=1.0)

    assert result.ok is False
    assert "UnsafeMCPDestination" in result.message
    assert "cloud-metadata" in result.message
    assert "TaskGroup" not in result.message


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


@pytest.mark.asyncio
async def test_authenticate_server_reports_failure_when_no_token_is_obtained(tmp_path, monkeypatch):
    """A server that needs no OAuth at all must not be reported as authenticated.

    ``_connect_once`` succeeds (the session just initializes) without the SDK
    ever calling ``set_tokens``/``set_client_info`` on the storage, so nothing
    is persisted. Success must be gated on a token actually having been
    written, not merely on the connection succeeding.
    """
    store = OAuthTokenStore(path=tmp_path / "store.json")

    async def fake_connect_once(kind, attempt_url, provider, timeout):
        return None

    monkeypatch.setattr(oauth_flow_module, "_connect_once", fake_connect_once)

    result = await authenticate_server("https://example.test/mcp", "example", store, timeout=1.0)

    assert result.ok is False
    assert store.get("https://example.test/mcp") is None
