"""Interactive OAuth authorization for remote MCP servers (the ``mcp-auth`` command).

This is the one place Agent Scan performs a *browser* OAuth flow. A developer
(or a security-team member with credentials) runs it once, in advance, to
authenticate a server; the resulting token is written to the persistent store
that the unattended scan later consumes. The scan path itself never runs this.

The flow reuses the MCP SDK's ``OAuthClientProvider`` — which performs discovery,
Dynamic Client Registration, the authorization-code exchange, and refresh — and
supplies the two pieces the scan path deliberately leaves unimplemented:

* ``redirect_handler`` — opens the system browser to the authorization URL.
* ``callback_handler`` — a short-lived ``127.0.0.1`` loopback HTTP listener that
  receives the ``?code=…`` redirect.

Per RFC 8252 the callback binds the ``127.0.0.1`` literal on an ephemeral port
and registers that exact URI via DCR, so no server-side port wildcarding is
needed. Pinned against ``mcp==1.27.0``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import httpx
import rich
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.sse import sse_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from agent_scan.oauth_store import OAuthTokenStore, StoredServerAuth, normalize_server_url

logger = logging.getLogger(__name__)

# How long to wait for the user to complete the browser authorization.
_CALLBACK_TIMEOUT_SECONDS = 300

_SUCCESS_HTML = (
    b"<html><body style='font-family:sans-serif'>"
    b"<h2>Authentication complete</h2>"
    b"<p>You can close this tab and return to the terminal.</p>"
    b"</body></html>"
)
_ERROR_HTML = (
    b"<html><body style='font-family:sans-serif'>"
    b"<h2>Authentication failed</h2>"
    b"<p>Return to the terminal for details.</p>"
    b"</body></html>"
)


@dataclass
class AuthResult:
    ok: bool
    server_url: str
    message: str = ""


class _CallbackRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.rstrip("/") != "/callback":
            # Ignore stray requests (e.g. /favicon.ico) without completing the flow.
            self.send_response(404)
            self.end_headers()
            return
        params = parse_qs(parsed.query)
        result = {
            "code": params.get("code", [None])[0],
            "state": params.get("state", [None])[0],
            "error": params.get("error", [None])[0],
            "error_description": params.get("error_description", [None])[0],
        }
        self.server.oauth_result = result  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(_ERROR_HTML if result["error"] else _SUCCESS_HTML)
        self.server.callback_received.set()  # type: ignore[attr-defined]

    def log_message(self, *args) -> None:  # silence the default stderr logging
        return


class _LoopbackCallbackServer:
    """A one-shot loopback HTTP server that captures the OAuth redirect."""

    def __init__(self, port: int = 0):
        self._server = HTTPServer(("127.0.0.1", port), _CallbackRequestHandler)
        self._server.oauth_result = None  # type: ignore[attr-defined]
        self._server.callback_received = threading.Event()  # type: ignore[attr-defined]
        self.port = self._server.server_address[1]
        self.redirect_uri = f"http://127.0.0.1:{self.port}/callback"
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    async def redirect_handler(self, authorization_url: str) -> None:
        rich.print(
            f"\n[bold]Opening your browser to authorize.[/bold] If it does not open, visit:\n  {authorization_url}\n"
        )
        try:
            webbrowser.open(authorization_url)
        except Exception:
            logger.debug("webbrowser.open failed; user must open the URL manually", exc_info=True)

    async def callback_handler(self) -> tuple[str, str | None]:
        loop = asyncio.get_event_loop()
        received = await loop.run_in_executor(None, self._server.callback_received.wait, _CALLBACK_TIMEOUT_SECONDS)
        if not received:
            raise TimeoutError("Timed out waiting for the OAuth callback")
        result = self._server.oauth_result or {}  # type: ignore[attr-defined]
        if result.get("error"):
            raise RuntimeError(
                f"Authorization failed: {result['error']} {result.get('error_description') or ''}".strip()
            )
        code = result.get("code")
        if not code:
            raise RuntimeError("No authorization code in the OAuth callback")
        return code, result.get("state")

    def close(self) -> None:
        # shutdown() blocks until serve_forever() stops, and deadlocks if it was
        # never started — so only call it when the serving thread is running.
        if self._thread is not None:
            try:
                self._server.shutdown()
            except Exception:
                logger.debug("callback server shutdown error", exc_info=True)
        self._server.server_close()


class _AuthFlowTokenStorage(TokenStorage):
    """Create-capable ``TokenStorage`` for the interactive flow.

    Unlike ``PersistentTokenStorage`` (which only updates an existing entry),
    this writes a *new* store entry once the flow yields a token. It holds the
    DCR client info in memory until then, so the entry is written atomically
    with both the client id and the token. The token endpoint is filled in by
    the caller afterward from discovery metadata.
    """

    def __init__(self, store: OAuthTokenStore, server_url: str, server_name: str):
        self._store = store
        self._server_url = server_url
        self._server_name = server_name
        self._client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        entry = self._store.get(self._server_url)
        return entry.token if entry else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        import time

        expires_at = time.time() + float(tokens.expires_in) if tokens.expires_in is not None else None
        redirect_uris = None
        client_id = ""
        client_secret = None
        if self._client_info is not None:
            client_id = self._client_info.client_id or ""
            client_secret = self._client_info.client_secret
            if self._client_info.redirect_uris:
                redirect_uris = [str(u) for u in self._client_info.redirect_uris]
        entry = StoredServerAuth(
            server_name=self._server_name,
            client_id=client_id,
            client_secret=client_secret,
            token_url="",  # finalized by authenticate_server from discovery metadata
            mcp_server_url=self._server_url,
            redirect_uris=redirect_uris,
            updated_at=time.time(),
            expires_at=expires_at,
            token=tokens,
        )
        self._store.put(self._server_url, entry)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info


def _transport_strategy(url: str) -> list[tuple[str, str]]:
    """Ordered (transport, url) attempts, mirroring ``check_server``'s probing.

    The OAuth flow triggers on the 401 from whichever transport/URL the server
    actually answers on, so we try the common shapes until one connects.
    """
    base = url.rstrip("/")
    path = urlparse(base).path
    if path.endswith("/sse"):
        base = base[: -len("/sse")]
    elif path.endswith("/mcp"):
        base = base[: -len("/mcp")]
    base = base.rstrip("/")
    with_mcp, with_sse = base + "/mcp", base + "/sse"
    ordered = [
        ("http", with_mcp),
        ("http", base),
        ("sse", with_sse),
        ("sse", base),
        ("http", with_sse),
        ("sse", with_mcp),
    ]
    # De-duplicate while preserving order.
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for attempt in ordered:
        if attempt not in seen:
            seen.add(attempt)
            out.append(attempt)
    return out


async def _connect_once(kind: str, attempt_url: str, provider: OAuthClientProvider, timeout: float) -> None:
    """Open one MCP session through the auth provider, triggering the flow on 401."""
    if kind == "sse":
        async with sse_client(url=attempt_url, auth=provider, timeout=timeout) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
    else:
        async with httpx.AsyncClient(auth=provider, follow_redirects=True, timeout=timeout) as client:
            async with streamable_http_client(url=attempt_url, http_client=client) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()


async def authenticate_server(
    url: str,
    server_name: str,
    store: OAuthTokenStore,
    *,
    port: int = 0,
    timeout: float = float(_CALLBACK_TIMEOUT_SECONDS),
) -> AuthResult:
    """Run the interactive OAuth flow for one server and persist the token.

    Returns an ``AuthResult``; never raises for expected failures (connection or
    authorization errors are reported via ``AuthResult.message``).
    """
    loopback = _LoopbackCallbackServer(port=port)
    loopback.start()
    storage = _AuthFlowTokenStorage(store, url, server_name)
    provider = OAuthClientProvider(
        server_url=url,
        client_metadata=OAuthClientMetadata(
            client_name="snyk-agent-scan",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            redirect_uris=[loopback.redirect_uri],
        ),
        storage=storage,
        redirect_handler=loopback.redirect_handler,
        callback_handler=loopback.callback_handler,
        timeout=timeout,
    )

    last_error: str = "could not connect to the server on any known transport"
    try:
        for kind, attempt_url in _transport_strategy(url):
            logger.debug("mcp-auth trying %s %s", kind, attempt_url)
            try:
                await _connect_once(kind, attempt_url, provider, timeout)
            except Exception as e:
                last_error = f"{type(e).__name__}: {e}"
                logger.debug("mcp-auth attempt failed (%s %s): %s", kind, attempt_url, last_error)
                continue
            # Connected and initialized -> auth succeeded. Persist the token
            # endpoint discovered by the SDK so refreshes hit the right URL.
            metadata = getattr(provider.context, "oauth_metadata", None)
            token_endpoint = getattr(metadata, "token_endpoint", None) if metadata else None
            if token_endpoint:
                store.set_token_url(url, str(token_endpoint))
            else:
                logger.warning("Authenticated %s but no token endpoint was discovered", url)
            return AuthResult(ok=True, server_url=normalize_server_url(url))
    finally:
        loopback.close()

    return AuthResult(ok=False, server_url=normalize_server_url(url), message=last_error)
