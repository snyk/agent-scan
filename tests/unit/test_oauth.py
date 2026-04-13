"""Unit tests for the OAuth module (agent_scan.oauth)."""

import asyncio
import contextlib
from unittest.mock import patch

import pytest

from agent_scan.oauth import (
    OAuthCallbackError,
    build_oauth_client_provider,
    make_callback_handler,
    make_redirect_handler,
    open_browser_to_authorize,
    wait_for_oauth_callback,
)


class TestOpenBrowserToAuthorize:
    """Tests for the open_browser_to_authorize function."""

    @pytest.mark.asyncio
    async def test_open_browser_to_authorize_calls_webbrowser(self):
        """open_browser_to_authorize should call webbrowser.open with the given URL."""
        url = "https://auth.example.com/authorize?client_id=abc"
        with patch("agent_scan.oauth.webbrowser.open") as mock_open:
            await open_browser_to_authorize(url)
            mock_open.assert_called_once_with(url)


class TestWaitForOAuthCallback:
    """Tests for the wait_for_oauth_callback function."""

    @pytest.mark.asyncio
    async def test_wait_for_oauth_callback_returns_code_and_state(self):
        """The callback server should extract code and state from the request."""
        import urllib.request

        port = 13199  # ephemeral port for testing

        async def send_callback():
            await asyncio.sleep(0.3)
            url = f"http://localhost:{port}/callback?code=test_auth_code&state=test_state"
            urllib.request.urlopen(url, timeout=5)

        task = asyncio.create_task(send_callback())
        code, state = await wait_for_oauth_callback(port=port, timeout=5)
        await task

        assert code == "test_auth_code"
        assert state == "test_state"

    @pytest.mark.asyncio
    async def test_wait_for_oauth_callback_returns_none_state_when_absent(self):
        """State should be None when not present in the callback URL."""
        import urllib.request

        port = 13200

        async def send_callback():
            await asyncio.sleep(0.3)
            url = f"http://localhost:{port}/callback?code=test_auth_code"
            urllib.request.urlopen(url, timeout=5)

        task = asyncio.create_task(send_callback())
        code, state = await wait_for_oauth_callback(port=port, timeout=5)
        await task

        assert code == "test_auth_code"
        assert state is None

    @pytest.mark.asyncio
    async def test_wait_for_oauth_callback_raises_on_missing_code(self):
        """OAuthCallbackError should be raised when code is missing from the callback."""
        import urllib.request

        port = 13201

        async def send_callback():
            await asyncio.sleep(0.3)
            url = f"http://localhost:{port}/callback?state=test_state"
            with contextlib.suppress(Exception):
                urllib.request.urlopen(url, timeout=5)

        task = asyncio.create_task(send_callback())
        with pytest.raises(OAuthCallbackError):
            await wait_for_oauth_callback(port=port, timeout=5)
        await task

    @pytest.mark.asyncio
    async def test_wait_for_oauth_callback_timeout(self):
        """TimeoutError should be raised if no callback is received within the timeout."""
        with pytest.raises((TimeoutError, asyncio.TimeoutError)):
            await wait_for_oauth_callback(port=13202, timeout=0.5)


class TestHandlerFactories:
    """Tests for make_redirect_handler and make_callback_handler."""

    def test_make_redirect_handler_returns_callable(self):
        """make_redirect_handler should return a callable."""
        handler = make_redirect_handler()
        assert callable(handler)

    def test_make_callback_handler_returns_callable(self):
        """make_callback_handler should return a callable."""
        handler = make_callback_handler(port=13031)
        assert callable(handler)


class TestBuildOAuthClientProvider:
    """Tests for build_oauth_client_provider."""

    def test_build_oauth_client_provider_returns_provider_instance(self, tmp_path):
        """build_oauth_client_provider should return an OAuthClientProvider instance."""
        from mcp.client.auth import OAuthClientProvider

        from agent_scan.models import InteractiveTokenStorage

        storage = InteractiveTokenStorage(base_dir=str(tmp_path), server_url="https://mcp.example.com")
        provider, metadata = build_oauth_client_provider(
            server_url="https://mcp.example.com",
            storage=storage,
        )
        assert isinstance(provider, OAuthClientProvider)

    def test_build_oauth_client_provider_custom_port(self, tmp_path):
        """Custom port should be reflected in the redirect URIs."""
        from agent_scan.models import InteractiveTokenStorage

        storage = InteractiveTokenStorage(base_dir=str(tmp_path), server_url="https://mcp.example.com")
        provider, metadata = build_oauth_client_provider(
            server_url="https://mcp.example.com",
            storage=storage,
            port=4040,
        )
        # The returned metadata should contain the custom redirect URI
        redirect_uris = [str(u) for u in metadata.redirect_uris]
        assert "http://localhost:4040/callback" in redirect_uris

    def test_build_oauth_client_provider_metadata_does_not_set_auth_method(self, tmp_path):
        """build_oauth_client_provider should not set token_endpoint_auth_method to 'client_secret_post'."""
        from agent_scan.models import InteractiveTokenStorage

        storage = InteractiveTokenStorage(base_dir=str(tmp_path), server_url="https://mcp.example.com")
        provider, metadata = build_oauth_client_provider(
            server_url="https://mcp.example.com",
            storage=storage,
        )
        assert metadata.token_endpoint_auth_method != "client_secret_post"
