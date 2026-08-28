"""Unit tests for the persistent OAuth token store (M1)."""

import json
import os
import stat
import sys
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
    is_secure_token_url,
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


@pytest.fixture
def permissive_umask():
    """Pin a permissive umask for the duration of a test.

    Without this, a developer running with ``umask 077`` would see the
    permission tests pass even against the unfixed code, because the ambient
    umask — not the code — would be what tightened the file.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://mcp.linear.app/mcp", "https://mcp.linear.app"),
        ("https://mcp.linear.app/sse", "https://mcp.linear.app"),
        ("https://mcp.linear.app/mcp/", "https://mcp.linear.app"),
        ("https://mcp.linear.app/", "https://mcp.linear.app"),
        ("https://mcp.linear.app", "https://mcp.linear.app"),
        ("https://cf.mcp.atlassian.com/v1/mcp", "https://cf.mcp.atlassian.com/v1"),
        # A query string is preserved, not sliced off along with the /mcp suffix.
        ("https://host/mcp?tenant=acme", "https://host?tenant=acme"),
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
    if sys.platform != "win32":
        # File is written 0600. POSIX file modes are not meaningful on Windows.
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # It is valid JSON keyed by the normalized URL.
    data = json.loads(path.read_text())
    assert list(data.keys()) == ["https://mcp.linear.app"]


def test_store_encrypts_secrets_at_rest(tmp_path):
    """The access/refresh tokens and client secret must not appear in
    plaintext in the on-disk file, but a round trip through get() must still
    return the original values."""
    path = tmp_path / "store.json"
    store = OAuthTokenStore(path=path)
    entry = _entry(token=_token(access="SECRETACCESS", refresh="SECRETREFRESH"))
    entry.client_secret = "SECRETCLIENT"
    store.put("https://mcp.linear.app/mcp", entry)

    raw_bytes = path.read_bytes()
    assert b"SECRETACCESS" not in raw_bytes
    assert b"SECRETREFRESH" not in raw_bytes
    assert b"SECRETCLIENT" not in raw_bytes

    got = store.get("https://mcp.linear.app/mcp")
    assert got.token.access_token == "SECRETACCESS"
    assert got.token.refresh_token == "SECRETREFRESH"
    assert got.client_secret == "SECRETCLIENT"


def test_store_reads_legacy_plaintext_entries(tmp_path):
    """An entry written before encryption-at-rest was added (plain strings,
    no encryption tag) must still be read correctly."""
    path = tmp_path / "store.json"
    entry = _entry(token=_token(access="PLAINACCESS", refresh="PLAINREFRESH"))
    path.write_text(json.dumps({"https://mcp.linear.app": json.loads(entry.model_dump_json())}))

    store = OAuthTokenStore(path=path)
    got = store.get("https://mcp.linear.app/mcp")
    assert got.token.access_token == "PLAINACCESS"
    assert got.token.refresh_token == "PLAINREFRESH"


def test_store_migrates_legacy_entry_to_encrypted_on_next_write(tmp_path):
    """A legacy plaintext entry gets encrypted the next time it is written."""
    path = tmp_path / "store.json"
    entry = _entry(token=_token(access="PLAINACCESS", refresh="PLAINREFRESH"))
    path.write_text(json.dumps({"https://mcp.linear.app": json.loads(entry.model_dump_json())}))

    store = OAuthTokenStore(path=path)
    store.update_token(
        "https://mcp.linear.app/mcp", _token(access="PLAINACCESS", refresh="PLAINREFRESH"), expires_at=None
    )

    assert b"PLAINACCESS" not in path.read_bytes()
    assert store.get("https://mcp.linear.app/mcp").token.access_token == "PLAINACCESS"


def test_store_get_returns_none_when_encryption_key_is_lost(tmp_path):
    """If the key file is lost/rotated, an undecryptable access token must not
    be handed back as if it were a real credential."""
    path = tmp_path / "store.json"
    store = OAuthTokenStore(path=path)
    store.put("https://mcp.linear.app/mcp", _entry(token=_token(access="SECRETACCESS")))

    key_path = path.parent / "store.key"
    key_path.write_bytes(oauth_store.Fernet.generate_key())  # simulate a lost/rotated key

    assert store.get("https://mcp.linear.app/mcp") is None


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


@pytest.mark.asyncio
async def test_persistent_storage_withholds_refresh_credentials_for_insecure_endpoint(tmp_path):
    """The SDK provider must not receive a usable refresh token/secret when the
    stored token endpoint fails ``is_secure_token_url`` -- otherwise it would
    perform its own unguarded refresh against that endpoint on a 401, bypassing
    ``ensure_fresh_token``'s HTTPS/loopback and no-redirect protections.
    """
    store = OAuthTokenStore(path=tmp_path / "store.json")
    entry = _entry(token=_token(access="live", refresh="refresh-token"))
    entry.token_url = "http://attacker.example/token"  # not HTTPS, not loopback
    entry.client_secret = "shh"
    store.put("https://mcp.linear.app/mcp", entry)

    storage = PersistentTokenStorage(store, "https://mcp.linear.app/mcp")
    tokens = await storage.get_tokens()
    client_info = await storage.get_client_info()

    assert tokens is not None
    assert tokens.access_token == "live"  # the (possibly stale) access token still flows through
    assert tokens.refresh_token is None
    assert client_info.client_secret is None
    assert client_info.token_endpoint_auth_method == "none"


class _FakeResponse:
    def __init__(self, status_code, content, headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}


class _FakeAsyncClient:
    """Minimal stand-in for httpx.AsyncClient capturing the refresh POST."""

    last_post = None
    last_init_kwargs: dict | None = None

    def __init__(self, *args, **kwargs):
        # Recorded on the base class so subclass instances report here too.
        _FakeAsyncClient.last_init_kwargs = kwargs

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


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are not meaningful on Windows")
def test_temp_file_is_owner_only_while_being_written(tmp_path, monkeypatch, permissive_umask):
    """The temp file must be 0600 before any token bytes reach it.

    Regression test: creating it with builtin ``open()`` yields ``0o666 & ~umask``
    (0o644 here) and only tightens it after the write, so the fully-written
    credential file is world-readable for the length of the write.
    """
    path = tmp_path / "store.json"
    tmp_file = tmp_path / "store.json.tmp"
    observed: dict[str, int] = {}

    real_dump = oauth_store.json.dump

    def spy_dump(obj, fp, **kwargs):
        # Sampled at the moment the credentials are being serialized — the exact
        # window the unfixed code leaves open.
        observed["mode"] = stat.S_IMODE(tmp_file.stat().st_mode)
        return real_dump(obj, fp, **kwargs)

    monkeypatch.setattr(oauth_store.json, "dump", spy_dump)
    OAuthTokenStore(path=path).put("https://mcp.linear.app/mcp", _entry())

    assert observed["mode"] == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes are not meaningful on Windows")
def test_store_directory_is_owner_only(tmp_path, permissive_umask):
    """Characterization test: the store directory is 0700, including when created.

    Passes before and after the temp-file fix. It exists so that the directory
    tightening cannot be removed without a test failing.
    """
    store_dir = tmp_path / "nested" / ".mcp-scan"
    OAuthTokenStore(path=store_dir / "store.json").put("https://mcp.linear.app/mcp", _entry())

    assert stat.S_IMODE(store_dir.stat().st_mode) == 0o700


def test_safe_summary_omits_secrets():
    entry = _entry(token=_token(access="SECRETACCESS", refresh="SECRETREFRESH"))
    entry.client_secret = "SECRETCLIENT"

    summary = entry.safe_summary()
    rendered = json.dumps(summary)

    assert "SECRETACCESS" not in rendered
    assert "SECRETREFRESH" not in rendered
    assert "SECRETCLIENT" not in rendered
    # Presence is still reportable without disclosing the values.
    assert summary["has_refresh_token"] is True
    assert summary["has_client_secret"] is True
    # Non-secret identifiers stay useful for diagnostics.
    assert summary["client_id"] == "client-123"
    assert summary["token_url"] == "https://mcp.linear.app/token"


@pytest.mark.asyncio
async def test_refresh_disables_redirect_following(tmp_path, monkeypatch):
    """The token exchange must not follow redirects.

    token_url comes from server-controlled discovery metadata, and httpx
    re-sends the body on 307/308 — so following a redirect would hand the
    refresh token and client secret to a host the server chose.
    """
    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _FakeAsyncClient)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry(expires_at=time.time() - 10))

    await ensure_fresh_token(store, "https://mcp.linear.app/mcp")

    assert _FakeAsyncClient.last_init_kwargs["follow_redirects"] is False


@pytest.mark.asyncio
async def test_refresh_ignores_a_redirect_response(tmp_path, monkeypatch, caplog):
    class _Redirecting(_FakeAsyncClient):
        async def post(self, url, data=None, headers=None):
            _FakeAsyncClient.last_post = {"url": url, "data": data}
            return _FakeResponse(307, b"", {"location": "https://attacker.example/token"})

    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _Redirecting)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry(token=_token(access="stale"), expires_at=time.time() - 10))

    with caplog.at_level("WARNING", logger="agent_scan.oauth_store"):
        await ensure_fresh_token(store, "https://mcp.linear.app/mcp")

    # The stale token is left for the connection to try, and the only request
    # made went to the configured endpoint.
    assert store.get("https://mcp.linear.app/mcp").token.access_token == "stale"
    assert _FakeAsyncClient.last_post["url"] == "https://mcp.linear.app/token"
    # This branch's only observable behaviour distinct from a plain non-200 is
    # its warning log — assert it fires and names the redirect target, so
    # deleting the 3xx branch (which would fall through to the generic
    # status_code != 200 return, producing identical stored-token state) fails
    # this test.
    redirect_warnings = [r for r in caplog.records if "redirect" in r.getMessage()]
    assert len(redirect_warnings) == 1
    assert "307" in redirect_warnings[0].getMessage()
    assert "https://attacker.example/token" in redirect_warnings[0].getMessage()


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://mcp.linear.app/token", True),
        ("https://auth.atlassian.com/oauth/token", True),
        # Loopback http never leaves the host, and local servers use it.
        ("http://127.0.0.1:8080/token", True),
        ("http://localhost:8080/token", True),
        ("http://[::1]:8080/token", True),
        # Anything else must be TLS (RFC 6749 s3.2).
        ("http://mcp.linear.app/token", False),
        ("http://attacker.example/token", False),
        # Empty (an entry whose endpoint was never finalized) and malformed.
        ("", False),
        ("not a url", False),
    ],
)
def test_is_secure_token_url(url, expected):
    assert is_secure_token_url(url) is expected


@pytest.mark.asyncio
async def test_refresh_refuses_a_plaintext_token_endpoint(tmp_path, monkeypatch):
    called = {"post": False}

    class _NoPost(_FakeAsyncClient):
        async def post(self, *a, **k):
            called["post"] = True
            return _FakeResponse(200, b"{}")

    monkeypatch.setattr(oauth_store.httpx, "AsyncClient", _NoPost)
    store = OAuthTokenStore(path=tmp_path / "store.json")
    entry = _entry(expires_at=time.time() - 10)
    entry.token_url = "http://mcp.linear.app/token"
    store.put("https://mcp.linear.app/mcp", entry)

    await ensure_fresh_token(store, "https://mcp.linear.app/mcp")

    assert called["post"] is False  # the refresh token was never sent in cleartext


def test_set_token_url_rejects_plaintext(tmp_path):
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry())

    result = store.set_token_url("https://mcp.linear.app/mcp", "http://attacker.example/token")

    # The original endpoint is retained; the insecure one is never persisted.
    assert store.get("https://mcp.linear.app/mcp").token_url == "https://mcp.linear.app/token"
    # Callers (e.g. authenticate_server) need to know the endpoint was refused
    # so they can warn the user that automatic refresh is disabled.
    assert result is False


def test_set_token_url_accepts_https(tmp_path):
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry())

    result = store.set_token_url("https://mcp.linear.app/mcp", "https://auth.atlassian.com/oauth/token")

    assert store.get("https://mcp.linear.app/mcp").token_url == "https://auth.atlassian.com/oauth/token"
    assert result is True


def test_set_token_url_return_value_distinguishes_accepted_from_refused(tmp_path):
    """set_token_url's bool return is what lets a caller warn the user.

    Without it, authenticate_server cannot tell a stored endpoint from a
    silently-refused one, so mcp-auth would print "authenticated" even though
    the entry's token_url stayed unset and can never be refreshed.
    """
    store = OAuthTokenStore(path=tmp_path / "store.json")
    store.put("https://mcp.linear.app/mcp", _entry())

    accepted = store.set_token_url("https://mcp.linear.app/mcp", "https://mcp.linear.app/oauth/token")
    refused = store.set_token_url("https://mcp.linear.app/mcp", "http://attacker.example/token")

    assert accepted is True
    assert refused is False
