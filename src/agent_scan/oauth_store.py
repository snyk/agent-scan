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
import ipaddress
import json
import logging
import os
import time
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlsplit, urlunsplit

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


def _is_loopback_host(host: str) -> bool:
    """True for ``localhost`` and any address in 127.0.0.0/8 or ::1."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_secure_token_url(url: str) -> bool:
    """True if a refresh token and client secret may be sent to ``url``.

    RFC 6749 s3.2 requires TLS on the token endpoint. The endpoint we persist is
    taken from server-controlled OAuth discovery metadata, so it is validated
    before use rather than trusted. Plain ``http`` is accepted only for loopback
    hosts: local MCP servers legitimately use it, and the credential never
    reaches a network. An empty or unparseable URL is rejected, which is also
    what makes an entry whose endpoint was never finalized fail closed.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme == "https":
        return True
    return parsed.scheme == "http" and _is_loopback_host((parsed.hostname or "").lower())


def normalize_server_url(url: str) -> str:
    """Reduce a remote MCP server URL to a stable identity key.

    Similar in spirit to the reduction ``check_server`` applies while probing
    transports (``mcp_client.py``): strip a trailing slash, then a trailing
    ``/mcp`` or ``/sse`` path segment. This ensures the same server keys to one
    store entry whether it is reached via ``.../mcp``, ``.../sse``, or the bare
    base URL. Unlike that helper, the suffix is stripped from the parsed
    *path* only, so a query string or fragment (e.g. ``?tenant=acme``) is
    preserved rather than sliced off along with the suffix.
    """
    split = urlsplit(url)
    path = split.path.rstrip("/")
    if path.endswith("/sse"):
        path = path[: -len("/sse")]
    elif path.endswith("/mcp"):
        path = path[: -len("/mcp")]
    return urlunsplit((split.scheme, split.netloc, path.rstrip("/"), split.query, split.fragment))


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
        cannot prove it is stale, so we let the connection try it; if the server
        rejects it, the connection attempt fails and the scan reports a
        connection error for that server.
        """
        if self.expires_at is None:
            return False
        current = time.time() if now is None else now
        return current >= (self.expires_at - _EXPIRY_SKEW_SECONDS)

    def safe_summary(self) -> dict[str, object]:
        """Non-secret description of this entry, for diagnostics and logs.

        Deliberately omits ``access_token``, ``refresh_token`` and
        ``client_secret``. Anything that prints or logs an entry must go through
        here — ``model_dump()`` returns the live credentials verbatim.
        """
        return {
            "server_name": self.server_name,
            "mcp_server_url": self.mcp_server_url,
            "client_id": self.client_id,
            "token_url": self.token_url,
            "redirect_uris": self.redirect_uris,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "has_client_secret": self.client_secret is not None,
            "has_refresh_token": self.token.refresh_token is not None,
            "access_token_expired": self.is_access_token_expired(),
        }


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
        # Create the directory owner-only from the start; the chmod covers the
        # case where it already existed with looser permissions.
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(OSError):
            os.chmod(self.path.parent, 0o700)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        # Open at 0o600 *before* any token bytes are written. Builtin open()
        # would create the file at 0o666 & ~umask (0o644 under the usual
        # umask 022) and only tighten it afterwards, leaving a fully-written
        # credential file readable by every local user for the length of the
        # write.
        # O_NOFOLLOW (POSIX-only, absent on Windows) refuses to open the path if
        # it is a symlink, so a symlink planted at the ``.tmp`` path beforehand
        # cannot redirect the write to an arbitrary target. getattr(...) makes
        # this a no-op flag bit on platforms without it.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            # os.open's mode argument is masked by umask; fchmod is not, so this
            # pins 0o600 regardless of the umask the caller runs with. Guarded
            # because os.fchmod is POSIX-only and absent on Windows before
            # Python 3.13 (this repo's floor is 3.10 and CI includes
            # windows-latest); POSIX file modes are meaningless there anyway.
            if hasattr(os, "fchmod"):
                os.fchmod(f.fileno(), 0o600)
            json.dump(data, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
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

    def set_token_url(self, server_url: str, token_url: str) -> bool:
        """Record the discovered token endpoint for an entry.

        The interactive auth command captures the token endpoint from OAuth
        discovery and stores it here so ``ensure_fresh_token`` refreshes against
        the correct URL — important for servers (e.g. Atlassian) whose token
        endpoint is on a different host than ``<base>/token``.

        Declines to store an endpoint that is neither HTTPS nor loopback, so a
        discovery document cannot arrange for the refresh token to be sent in
        cleartext later. The entry keeps whatever endpoint it already had.

        Returns ``True`` if the endpoint was stored, ``False`` if it was refused
        (non-HTTPS/non-loopback) or there was no existing entry to update. Never
        raises; callers that need the user to know about a refusal must check
        the return value themselves.
        """
        if not is_secure_token_url(token_url):
            logger.warning("Refusing to store a non-HTTPS token endpoint for %s: %r", server_url, token_url)
            return False
        key = normalize_server_url(server_url)
        with self._locked():
            data = self._read_raw()
            raw = data.get(key)
            if raw is None:
                return False
            entry = StoredServerAuth.model_validate(raw)
            entry.token_url = token_url
            entry.updated_at = time.time()
            data[key] = json.loads(entry.model_dump_json())
            self._write_raw(data)
            return True


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

    When the entry's token endpoint fails ``is_secure_token_url`` -- the same
    check ``ensure_fresh_token`` uses before its own guarded refresh -- the
    refresh token and client secret are withheld from what is handed to the
    SDK's ``OAuthClientProvider``. Without that, the provider still holds a
    live refresh token and would perform its *own* unguarded refresh against
    that endpoint on a 401, bypassing the HTTPS/loopback and no-redirect
    protections entirely. The (possibly stale) access token is still returned,
    so the connection attempt itself is unaffected.
    """

    def __init__(self, store: OAuthTokenStore, server_url: str):
        self._store = store
        self._server_url = server_url

    async def get_tokens(self) -> OAuthToken | None:
        entry = self._store.get(self._server_url)
        if entry is None:
            return None
        if entry.token.refresh_token is not None and not is_secure_token_url(entry.token_url):
            return entry.token.model_copy(update={"refresh_token": None})
        return entry.token

    async def set_tokens(self, tokens: OAuthToken) -> None:
        expires_at: float | None = None
        if tokens.expires_in is not None:
            expires_at = time.time() + float(tokens.expires_in)
        self._store.update_token(self._server_url, tokens, expires_at=expires_at)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        entry = self._store.get(self._server_url)
        if entry is None:
            return None
        client_secret = entry.client_secret
        if client_secret is not None and not is_secure_token_url(entry.token_url):
            client_secret = None
        return OAuthClientInformationFull(
            client_id=entry.client_id,
            client_secret=client_secret,
            redirect_uris=entry.redirect_uris or [_PLACEHOLDER_REDIRECT_URI],
            token_endpoint_auth_method="client_secret_post" if client_secret else "none",
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
    stale token; if the server rejects it, the connection attempt fails and the
    scan reports a connection error for that server, and the user
    re-authenticates. Never raises.

    This function guards only its own proactive refresh: ``follow_redirects``
    and ``is_secure_token_url`` below cover this module's HTTP POST to the
    stored token endpoint, not the MCP SDK's own refresh. When that guard
    declines, the stale token is instead handed to the SDK's
    ``OAuthClientProvider``, which performs its own refresh
    (``mcp/client/auth/oauth2.py``) against a ``token_endpoint`` taken from
    discovery with no scheme check, through an ``httpx`` client built with
    ``follow_redirects=True`` (see ``mcp_client.py`` and ``oauth_flow.py``).
    That path is not covered here and is tracked as a follow-up.
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
            # Nothing to refresh with; let the connection attempt fail on its own,
            # which the scan reports as a connection error for this server.
            logger.debug("Stored token for %s expired and has no refresh token", server_url)
            return

        if not is_secure_token_url(entry.token_url):
            # Fail closed rather than send the credential in cleartext through
            # this module's own refresh POST below. This does not stop the MCP
            # SDK's own refresh (see the docstring above) — only this proactive
            # path. The scan then tries the stale token; if the server rejects
            # it, the connection attempt fails and the scan reports a connection
            # error, prompting the user to re-run mcp-auth.
            logger.warning(
                "Refusing to refresh %s: stored token endpoint %r is neither HTTPS nor loopback",
                server_url,
                entry.token_url,
            )
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
            # follow_redirects=False is deliberate and security-relevant for this
            # module's own refresh POST: httpx preserves the method and re-sends
            # the body on 307/308, and entry.token_url comes from
            # server-controlled discovery metadata. Following a redirect would
            # deliver the refresh token and client secret to a host the remote
            # server picked. This protects only this proactive-refresh path, not
            # the MCP SDK's own refresh (see the docstring above); that path is
            # not covered here and is tracked as a follow-up.
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                resp = await client.post(entry.token_url, data=data, headers=headers)
            if resp.status_code in (301, 302, 303, 307, 308):
                logger.warning(
                    "Token endpoint for %s returned a %s redirect to %s; not resending the refresh token",
                    server_url,
                    resp.status_code,
                    resp.headers.get("location", "<no location header>"),
                )
                return
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
