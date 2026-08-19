"""Unit tests for the persistent OAuth token store (M1)."""

import json
import stat
import time

import pytest
from mcp.shared.auth import OAuthToken

from agent_scan import oauth_store
from agent_scan.models import TokenAndClientInfo
from agent_scan.oauth_store import (
    OAuthTokenStore,
    PersistentTokenStorage,
    StoredServerAuth,
    ensure_fresh_token,
    normalize_server_url,
)


def _token(access="a1", refresh="r1", expires_in=3600):
    # Build from a dict so tests never assign literals directly to token fields.
    fields = {"access_token": access, "token_type": "Bearer", "expires_in": expires_in, "refresh_token": refresh}
    return OAuthToken(**fields)


def _entry(url="https://mcp.linear.app", token=None, expires_at=None):
    return StoredServerAuth(
        server_name="linear",
        client_id="client-123",
        token_url="https://mcp.linear.app/token",
        mcp_server_url=url,
        updated_at=time.time(),
        expires_at=expires_at,
        token=token or _token(),
    )


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://mcp.linear.app/mcp", "https://mcp.linear.app"),
        ("https://mcp.linear.app/sse", "https://mcp.linear.app"),
        ("https://mcp.linear.app/mcp/", "https://mcp.linear.app"),
        ("https://mcp.linear.app/", "https://mcp.linear.app"),
        ("https://mcp.linear.app", "https://mcp.linear.app"),
        ("https://cf.mcp.atlassian.com/v1/mcp", "https://cf.mcp.atlassian.com/v1"),
    ],
)
def test_normalize_server_url(url, expected):
    assert normalize_server_url(url) == expected


def test_transport_suffixes_key_to_one_entry(tmp_path):
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry())
    # The /sse form and the bare form must resolve to the same stored entry.
    assert store.get("https://mcp.linear.app/sse") is not None
    assert store.get("https://mcp.linear.app") is not None


def test_from_token_and_client_info_computes_expiry():
    tci = TokenAndClientInfo(
        token=_token(expires_in=100),
        server_name="linear",
        client_id="c1",
        token_url="https://mcp.linear.app/token",
        mcp_server_url="https://mcp.linear.app/mcp",
        updated_at=1000,
    )
    entry = StoredServerAuth.from_token_and_client_info(tci)
    assert entry.expires_at == 1100.0
    assert entry.token.refresh_token == "r1"


def test_is_access_token_expired_skew_and_unknown():
    now = 10_000.0
    fresh = _entry(expires_at=now + 3600)
    stale = _entry(expires_at=now + 30)  # within the 60s skew -> treated as expired
    unknown = _entry(expires_at=None)
    assert fresh.is_access_token_expired(now=now) is False
    assert stale.is_access_token_expired(now=now) is True
    assert unknown.is_access_token_expired(now=now) is False


def test_store_roundtrip_and_permissions(tmp_path):
    path = tmp_path / "store.json"
    store = OAuthTokenStore(path=path)
    assert store.get("https://mcp.linear.app/mcp") is None  # missing file -> None
    store.put("https://mcp.linear.app/mcp", _entry())
    got = store.get("https://mcp.linear.app/mcp")
    assert got is not None and got.client_id == "client-123"
    # File is written 0600.
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # It is valid JSON keyed by the normalized URL.
    data = json.loads(path.read_text())
    assert list(data.keys()) == ["https://mcp.linear.app"]


def test_update_token_preserves_refresh_when_omitted(tmp_path):
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry(token=_token(access="old", refresh="orig")))
    # Server returned a new access token but no refresh token (non-rotating).
    rotated = _token(access="new", refresh=None)
    store.update_token("https://mcp.linear.app/mcp", rotated, expires_at=time.time() + 3600)
    got = store.get("https://mcp.linear.app/mcp")
    assert got.token.access_token == "new"
    assert got.token.refresh_token == "orig"  # preserved


@pytest.mark.asyncio
async def test_persistent_storage_roundtrip(tmp_path):
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry())
    storage = PersistentTokenStorage(store, "https://mcp.linear.app/sse")  # different suffix, same server
    tokens = await storage.get_tokens()
    assert tokens is not None and tokens.access_token == "a1"
    client_info = await storage.get_client_info()
    assert client_info.client_id == "client-123"
    # set_tokens persists a rotation back to disk.
    await storage.set_tokens(_token(access="rotated", refresh="r2"))
    assert store.get("https://mcp.linear.app/mcp").token.access_token == "rotated"


class _FakeResponse:
    def __init__(self, status_code, content):
        self.status_code = status_code
        self.content = content


class _FakeAsyncClient:
    """Minimal stand-in for httpx.AsyncClient capturing the refresh POST."""

    last_post = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, data=None, headers=None):
        type(self).last_post = {"url": url, "data": data}
        body = json.dumps(
            {"access_token": "refreshed", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "r2"}
        ).encode()
        return _FakeResponse(200, body)


@pytest.mark.asyncio
async def test_ensure_fresh_token_refreshes_expired(tmp_path, monkeypatch):
    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _FakeAsyncClient)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry(expires_at=time.time() - 10))  # expired

    await ensure_fresh_token(store, "https://mcp.linear.app/sse")

    got = store.get("https://mcp.linear.app/mcp")
    assert got.token.access_token == "refreshed"
    assert got.token.refresh_token == "r2"
    # Correct refresh request was made to the stored token endpoint.
    assert _FakeAsyncClient.last_post["url"] == "https://mcp.linear.app/token"
    assert _FakeAsyncClient.last_post["data"]["grant_type"] == "refresh_token"
    assert _FakeAsyncClient.last_post["data"]["refresh_token"] == "r1"
    assert _FakeAsyncClient.last_post["data"]["client_id"] == "client-123"


@pytest.mark.asyncio
async def test_ensure_fresh_token_noop_when_valid(tmp_path, monkeypatch):
    called = {"post": False}

    class _NoPost(_FakeAsyncClient):
        async def post(self, *a, **k):
            called["post"] = True
            return _FakeResponse(200, b"{}")

    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _NoPost)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry(expires_at=time.time() + 3600))  # valid

    await ensure_fresh_token(store, "https://mcp.linear.app/mcp")
    assert called["post"] is False  # no refresh attempted


@pytest.mark.asyncio
async def test_ensure_fresh_token_noop_without_refresh_token(tmp_path, monkeypatch):
    called = {"post": False}

    class _NoPost(_FakeAsyncClient):
        async def post(self, *a, **k):
            called["post"] = True
            return _FakeResponse(200, b"{}")

    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _NoPost)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put(
        "https://mcp.linear.app/mcp",
        _entry(token=_token(refresh=None), expires_at=time.time() - 10),  # expired, no refresh token
    )

    await ensure_fresh_token(store, "https://mcp.linear.app/mcp")
    assert called["post"] is False  # cannot refresh -> left for the auth_failed path


@pytest.mark.asyncio
async def test_ensure_fresh_token_swallows_failure(tmp_path, monkeypatch):
    class _Failing(_FakeAsyncClient):
        async def post(self, *a, **k):
            raise RuntimeError("network down")

    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _Failing)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry(token=_token(access="stale"), expires_at=time.time() - 10))

    # Must not raise; the stale token is left in place for the connection to try.
    await ensure_fresh_token(store, "https://mcp.linear.app/mcp")
    assert store.get("https://mcp.linear.app/mcp").token.access_token == "stale"
