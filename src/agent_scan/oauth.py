"""OAuth support utilities for interactive MCP server authentication."""

import asyncio
import logging
import threading
import webbrowser
from collections.abc import Awaitable, Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientMetadata

logger = logging.getLogger(__name__)


class OAuthCallbackError(Exception):
    """Raised when the OAuth callback is missing required parameters (e.g. code)."""


async def open_browser_to_authorize(authorization_url: str) -> None:
    """Open the authorization URL in the user's default browser.

    Args:
        authorization_url: The OAuth authorization URL to open.
    """
    logger.info("Opening browser for OAuth authorization: %s", authorization_url)
    webbrowser.open(authorization_url)


async def wait_for_oauth_callback(
    host: str = "localhost",
    port: int = 3030,
    timeout: float = 300.0,
) -> tuple[str, str | None]:
    """Start a temporary HTTP server and wait for the OAuth callback.

    Uses a threaded HTTP server so that synchronous callers (e.g.
    ``urllib.request.urlopen``) do not block the async event loop.

    Args:
        host: The hostname to bind the callback server to.
        port: The port to bind the callback server to.
        timeout: Maximum seconds to wait for the callback before raising TimeoutError.

    Returns:
        A tuple of (code, state). state may be None if not provided.

    Raises:
        OAuthCallbackError: If the callback request is missing the ``code`` parameter.
        TimeoutError: If no callback is received within the timeout period.
    """
    loop = asyncio.get_running_loop()
    result_future: asyncio.Future[tuple[str, str | None]] = loop.create_future()

    class _CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return

            params = parse_qs(parsed.query)
            code_list = params.get("code")
            state_list = params.get("state")

            code = code_list[0] if code_list else None
            state = state_list[0] if state_list else None

            if code is None:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Missing 'code' parameter")
                if not result_future.done():
                    loop.call_soon_threadsafe(
                        result_future.set_exception,
                        OAuthCallbackError("OAuth callback missing required 'code' parameter"),
                    )
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Authorization successful. You can close this window.")
            if not result_future.done():
                loop.call_soon_threadsafe(result_future.set_result, (code, state))

        def log_message(self, format: str, *args: object) -> None:
            """Suppress default stderr logging from BaseHTTPRequestHandler."""
            pass

    server = HTTPServer((host, port), _CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        return await asyncio.wait_for(asyncio.shield(result_future), timeout=timeout)
    except asyncio.TimeoutError:
        raise TimeoutError(f"OAuth callback was not received within {timeout} seconds") from None
    finally:
        server.shutdown()
        server_thread.join(timeout=2)


def make_redirect_handler() -> Callable[[str], Awaitable[None]]:
    """Return a closure that opens the browser for OAuth authorization.

    Returns:
        An async callable that accepts an authorization URL string.
    """

    async def redirect_handler(authorization_url: str) -> None:
        await open_browser_to_authorize(authorization_url)

    return redirect_handler


def make_callback_handler(
    port: int = 3030,
    timeout: float = 300.0,
) -> Callable[[], Awaitable[tuple[str, str | None]]]:
    """Return a closure that waits for the OAuth callback.

    Args:
        port: The port on which to listen for the callback.
        timeout: Maximum seconds to wait.

    Returns:
        An async callable that returns (code, state).
    """

    async def callback_handler() -> tuple[str, str | None]:
        return await wait_for_oauth_callback(port=port, timeout=timeout)

    return callback_handler


def build_oauth_client_provider(
    server_url: str,
    storage: TokenStorage,
    port: int = 3030,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> tuple[OAuthClientProvider, OAuthClientMetadata]:
    """Construct an OAuthClientProvider with interactive browser-based handlers.

    Args:
        server_url: The MCP server URL to authenticate against.
        storage: A TokenStorage instance for persisting tokens and client info.
        port: The local port for the OAuth redirect callback server.
        client_id: Pre-registered OAuth client ID (optional).
        client_secret: OAuth client secret for confidential clients (optional).

    Returns:
        A tuple of (provider, client_metadata) where provider is a configured
        OAuthClientProvider instance and client_metadata is the OAuthClientMetadata
        used to construct it.
    """
    metadata_kwargs: dict = {
        "client_name": "mcp-scan",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": [f"http://localhost:{port}/callback"],
    }
    if client_secret:
        metadata_kwargs["token_endpoint_auth_method"] = "client_secret_post"

    client_metadata = OAuthClientMetadata(**metadata_kwargs)

    provider = OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=make_redirect_handler(),
        callback_handler=make_callback_handler(port=port),
    )

    return provider, client_metadata
