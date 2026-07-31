"""Persistent, cross-invocation OAuth token storage for remote MCP servers.

Agent Scan runs unattended (e.g. re-invoked by MDM), so a token obtained once
must survive across separate process runs and be refreshed silently on each
run. This module provides that persistence:

* ``OAuthTokenStore`` — a file-backed store under ``~/.mcp-scan`` keyed by the
  *normalized* server URL, so the same server discovered under different config
  names or transport suffixes (``/mcp`` vs ``/sse``) maps to one entry.
* ``PersistentTokenStorage`` — a ``mcp.client.auth.TokenStorage`` bound to one
  server, so the MCP SDK reads and writes tokens through the store.
* ``ensure_fresh_token`` — proactively refreshes an expired access token
  *before* the scan connects, using the stored token endpoint.

Why the proactive refresh: the MCP SDK only tracks token expiry in-memory for
the lifetime of one provider. On a fresh process it treats a loaded token as
valid regardless of age, sends it, gets a 401, and then falls into the full
(browser) authorization flow — which the unattended scan cannot perform. It
also derives the refresh token endpoint as ``<base>/token`` when no discovery
has run, which is wrong for servers like Sentry (``/oauth/token``) and
Atlassian (a different host). Refreshing here, using the token endpoint we
persisted at authentication time, sidesteps both problems and works uniformly
across providers. Pinned against ``mcp==1.27.0``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx
from mcp.client.auth import TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from agent_scan.models import TokenAndClientInfo

logger = logging.getLogger(__name__)

# Refresh this many seconds *before* the access token's nominal expiry, to
# avoid using a token that expires mid-request.
_EXPIRY_SKEW_SECONDS = 60

# Default callback used only to satisfy the SDK's client-info shape on the scan
# path; the scan never performs an interactive authorization, so nothing binds
# to it. The interactive command (M2) supplies a real ``127.0.0.1`` callback.
_PLACEHOLDER_REDIRECT_URI = "http://127.0.0.1:33418/callback"


def normalize_server_url(url: str) -> str:
    """Reduce a remote MCP server URL to a stable identity key.

    Mirrors the reduction ``check_server`` applies while probing transports
    (``mcp_client.py``): strip a trailing slash, then a trailing ``/mcp`` or
    ``/sse`` path segment. This ensures the same server keys to one store entry
    whether it is reached via ``.../mcp``, ``.../sse``, or the bare base URL.
    """
    base = url.rstrip("/")
    path = urlparse(base).path
    if path.endswith("/sse"):
        base = base[: -len("/sse")]
    elif path.endswith("/mcp"):
        base = base[: -len("/mcp")]
    return base.rstrip("/")


def _store_path() -> Path:
    """Location of the token store.

    ``~/.mcp-scan/oauth-tokens.json`` — the same working directory the MDM
    deployment already runs the scan from, so the unattended scan (as the
    logged-in user) reads what the user authenticated. Tests point elsewhere by
    passing ``path=`` to ``OAuthTokenStore`` directly.
    """
    return Path("~/.mcp-scan/oauth-tokens.json").expanduser()


class StoredServerAuth(BaseModel):
    """One server's persisted OAuth material.

    ``expires_at`` is the absolute wall-clock time (``time.time()`` domain) the
    access token expires, so validity can be judged after a process restart —
    which the raw ``OAuthToken`` (carrying only relative ``expires_in``) cannot
    express on its own.
    """

    model_config = ConfigDict()
    server_name: str
    client_id: str
    client_secret: str | None = None
    token_url: str
    mcp_server_url: str
    redirect_uris: list[str] | None = None
    updated_at: float
    expires_at: float | None = None
    token: OAuthToken

    @classmethod
    def from_token_and_client_info(cls, tci: TokenAndClientInfo) -> StoredServerAuth:
        """Build a store entry from the legacy ``--mcp-oauth-tokens-path`` shape."""
        expires_at: float | None = None
        if tci.token.expires_in is not None:
            expires_at = float(tci.updated_at) + float(tci.token.expires_in)
        return cls(
            server_name=tci.server_name,
            client_id=tci.client_id,
            token_url=tci.token_url,
            mcp_server_url=tci.mcp_server_url,
            updated_at=float(tci.updated_at),
            expires_at=expires_at,
            token=tci.token,
        )

    def is_access_token_expired(self, *, now: float | None = None) -> bool:
        """True if the access token is at/near expiry (with a safety skew).

        Unknown expiry (``expires_at is None``) is treated as *not* expired: we
        cannot prove it is stale, so we let the connection try it and fall back
        to the ``auth_failed`` path if the server rejects it.
        """
        if self.expires_at is None:
            return False
        current = time.time() if now is None else now
        return current >= (self.expires_at - _EXPIRY_SKEW_SECONDS)


class OAuthTokenStore:
    """File-backed map of ``normalized server URL -> StoredServerAuth``.

    Reads and writes the whole JSON document under a best-effort POSIX file
    lock, and writes atomically via ``os.replace`` so a concurrent reader never
    sees a partial file. Concurrency is low in the MDM (single-writer) model;
    this is cheap insurance against an overlapping run.
    """

    def __init__(self, path: Path | None = None):
        self.path = path or _store_path()

    # -- disk I/O -----------------------------------------------------------

    def _read_raw(self) -> dict[str, dict]:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        except (json.JSONDecodeError, OSError):
            logger.warning("OAuth token store at %s is unreadable; treating as empty", self.path)
            return {}
        return data if isinstance(data, dict) else {}

    def _write_raw(self, data: dict[str, dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(self.path.parent, 0o700)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def _locked(self):
        """Context manager holding an exclusive lock file next to the store.

        Uses ``fcntl`` where available (POSIX; macOS/Linux). On platforms
        without it (Windows, a fast-follow target) it degrades to no lock —
        atomic ``os.replace`` still prevents a torn read.
        """
        return _FileLock(self.path.with_suffix(self.path.suffix + ".lock"))

    # -- public API ---------------------------------------------------------

    def get(self, server_url: str) -> StoredServerAuth | None:
        key = normalize_server_url(server_url)
        raw = self._read_raw().get(key)
        if raw is None:
            return None
        try:
            return StoredServerAuth.model_validate(raw)
        except Exception:
            logger.warning("Malformed OAuth store entry for %s; ignoring", key)
            return None

    def put(self, server_url: str, entry: StoredServerAuth) -> None:
        key = normalize_server_url(server_url)
        with self._locked():
            data = self._read_raw()
            data[key] = json.loads(entry.model_dump_json())
            self._write_raw(data)

    def update_token(self, server_url: str, token: OAuthToken, *, expires_at: float | None) -> None:
        """Persist a rotated token, preserving a refresh token the server omitted."""
        key = normalize_server_url(server_url)
        with self._locked():
            data = self._read_raw()
            raw = data.get(key)
            if raw is None:
                return
            entry = StoredServerAuth.model_validate(raw)
            # Servers that do not rotate refresh tokens omit it on refresh; keep
            # the one we already hold rather than dropping to None.
            if token.refresh_token is None and entry.token.refresh_token is not None:
                token = token.model_copy(update={"refresh_token": entry.token.refresh_token})
            entry.token = token
            entry.expires_at = expires_at
            entry.updated_at = time.time()
            data[key] = json.loads(entry.model_dump_json())
            self._write_raw(data)

    def set_token_url(self, server_url: str, token_url: str) -> None:
        """Record the discovered token endpoint for an entry.

        The interactive auth command captures the token endpoint from OAuth
        discovery and stores it here so ``ensure_fresh_token`` refreshes against
        the correct URL — important for servers (e.g. Atlassian) whose token
        endpoint is on a different host than ``<base>/token``.
        """
        key = normalize_server_url(server_url)
        with self._locked():
            data = self._read_raw()
            raw = data.get(key)
            if raw is None:
                return
            entry = StoredServerAuth.model_validate(raw)
            entry.token_url = token_url
            entry.updated_at = time.time()
            data[key] = json.loads(entry.model_dump_json())
            self._write_raw(data)


class _FileLock:
    """Minimal exclusive file lock; no-op where ``fcntl`` is unavailable."""

    def __init__(self, path: Path):
        self.path = path
        self._fd: int | None = None

    def __enter__(self) -> _FileLock:
        try:
            import fcntl

            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except (ImportError, OSError):
            # Best-effort: proceed without a lock. Atomic os.replace still
            # guarantees readers never observe a partial write.
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
        return self

    def __exit__(self, *exc) -> None:
        if self._fd is not None:
            try:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass
            os.close(self._fd)
            self._fd = None


class PersistentTokenStorage(TokenStorage):
    """``TokenStorage`` bound to one server, backed by ``OAuthTokenStore``.

    Unlike the read-only ``FileTokenStorage`` it replaces on the scan path,
    this persists refreshed tokens (``set_tokens``) and registered client info
    (``set_client_info``) back to disk, so the next process run reuses them.
    """

    def __init__(self, store: OAuthTokenStore, server_url: str):
        self._store = store
        self._server_url = server_url

    async def get_tokens(self) -> OAuthToken | None:
        entry = self._store.get(self._server_url)
        return entry.token if entry else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        expires_at: float | None = None
        if tokens.expires_in is not None:
            expires_at = time.time() + float(tokens.expires_in)
        self._store.update_token(self._server_url, tokens, expires_at=expires_at)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        entry = self._store.get(self._server_url)
        if entry is None:
            return None
        return OAuthClientInformationFull(
            client_id=entry.client_id,
            client_secret=entry.client_secret,
            redirect_uris=entry.redirect_uris or [_PLACEHOLDER_REDIRECT_URI],
            token_endpoint_auth_method="client_secret_post" if entry.client_secret else "none",
        )

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        entry = self._store.get(self._server_url)
        if entry is None:
            return
        if client_info.client_id is not None:
            entry.client_id = client_info.client_id
        entry.client_secret = client_info.client_secret
        if client_info.redirect_uris:
            entry.redirect_uris = [str(u) for u in client_info.redirect_uris]
        self._store.put(self._server_url, entry)


# Per-server in-process locks so concurrent scans of the same server (e.g. the
# transport-probing matrix, or parallel server inspection) don't each fire a
# refresh and double-spend a single-use rotating refresh token.
_refresh_locks: dict[str, asyncio.Lock] = {}


def _refresh_lock(server_url: str) -> asyncio.Lock:
    key = normalize_server_url(server_url)
    lock = _refresh_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _refresh_locks[key] = lock
    return lock


async def ensure_fresh_token(store: OAuthTokenStore, server_url: str, *, timeout: float = 30.0) -> None:
    """Refresh a stored access token before connecting, if it is expired.

    Best-effort and non-fatal: any failure (network, dead refresh token,
    non-rotating server) is logged and swallowed. The scan then attempts the
    stale token; if the server rejects it, the existing ``auth_failed`` path
    records that, and the user re-authenticates. Never raises.
    """
    entry = store.get(server_url)
    if entry is None or not entry.is_access_token_expired():
        return

    async with _refresh_lock(server_url):
        # Re-read under the lock: a concurrent refresh may have already produced
        # a fresh token (and rotated the refresh token), so use that rather than
        # spending a now-invalid one.
        entry = store.get(server_url)
        if entry is None or not entry.is_access_token_expired():
            return
        if entry.token.refresh_token is None:
            # Nothing to refresh with; let the connection fail to auth_failed.
            logger.debug("Stored token for %s expired and has no refresh token", server_url)
            return

        data = {
            "grant_type": "refresh_token",
            "refresh_token": entry.token.refresh_token,
            "client_id": entry.client_id,
        }
        if entry.client_secret:
            data["client_secret"] = entry.client_secret
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.post(entry.token_url, data=data, headers=headers)
            if resp.status_code != 200:
                logger.info("Refresh for %s failed with status %s; leaving stored token", server_url, resp.status_code)
                return
            new_token = OAuthToken.model_validate_json(resp.content)
        except Exception:
            logger.info("Refresh for %s errored; leaving stored token", server_url, exc_info=True)
            return

        expires_at: float | None = None
        if new_token.expires_in is not None:
            expires_at = time.time() + float(new_token.expires_in)
        store.update_token(server_url, new_token, expires_at=expires_at)
        logger.debug("Refreshed and persisted access token for %s", server_url)
