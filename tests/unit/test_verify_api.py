"""Unit tests for the verify_api module, including HTTP proxy support."""

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agent_scan.models import ScanPathResult
from agent_scan.verify_api import analyze_machine, setup_tcp_connector


class TestProxySupport:
    """Test cases for HTTP proxy support in verify_api."""

    @pytest.mark.asyncio
    async def test_analyze_machine_honors_http_proxy_env(self):
        """Test that analyze_machine respects HTTP_PROXY environment variable."""
        scan_paths = [ScanPathResult(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        # Mock the aiohttp.ClientSession to capture how it was called
        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(
                return_value='{"scan_path_results": [{"path": "/test/path", "issues": [], "labels": []}], "scan_user_info": {}}'
            )
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            # Set proxy environment variable
            with patch.dict(os.environ, {"HTTP_PROXY": "http://proxy.example.com:8080"}):
                result = await analyze_machine(
                    scan_paths=scan_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                )

            # Verify ClientSession was called with trust_env=True
            mock_session_class.assert_called_once()
            call_kwargs = mock_session_class.call_args[1]
            assert call_kwargs["trust_env"] is True, "ClientSession should be called with trust_env=True"

            assert len(result) == 1
            assert result[0].path == "/test/path"

    @pytest.mark.asyncio
    async def test_analyze_machine_honors_https_proxy_env(self):
        """Test that analyze_machine respects HTTPS_PROXY environment variable."""
        scan_paths = [ScanPathResult(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(
                return_value='{"scan_path_results": [{"path": "/test/path", "issues": [], "labels": []}], "scan_user_info": {}}'
            )
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            # Set HTTPS proxy environment variable
            with patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy.example.com:8443"}):
                result = await analyze_machine(
                    scan_paths=scan_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                )

            # Verify ClientSession was called with trust_env=True
            mock_session_class.assert_called_once()
            call_kwargs = mock_session_class.call_args[1]
            assert call_kwargs["trust_env"] is True, "ClientSession should be called with trust_env=True"

            assert len(result) == 1

    @pytest.mark.asyncio
    async def test_analyze_machine_works_without_proxy(self):
        """Test that analyze_machine works normally when no proxy is configured."""
        scan_paths = [ScanPathResult(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(
                return_value='{"scan_path_results": [{"path": "/test/path", "issues": [], "labels": []}], "scan_user_info": {}}'
            )
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            # Ensure no proxy env vars are set
            env_without_proxy = {k: v for k, v in os.environ.items() if "PROXY" not in k.upper()}
            with patch.dict(os.environ, env_without_proxy, clear=True):
                result = await analyze_machine(
                    scan_paths=scan_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                )

            # Verify ClientSession was still called with trust_env=True
            # (it just won't find any proxy to use)
            mock_session_class.assert_called_once()
            call_kwargs = mock_session_class.call_args[1]
            assert call_kwargs["trust_env"] is True

            assert len(result) == 1
            assert result[0].path == "/test/path"

    @pytest.mark.asyncio
    async def test_analyze_machine_with_skip_ssl_verify_and_proxy(self):
        """Test that skip_ssl_verify works correctly with proxy support."""
        scan_paths = [ScanPathResult(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(
                return_value='{"scan_path_results": [{"path": "/test/path", "issues": [], "labels": []}], "scan_user_info": {}}'
            )
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            with patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy.example.com:8443"}):
                result = await analyze_machine(
                    scan_paths=scan_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                    skip_ssl_verify=True,
                )

            # Verify both trust_env and connector are set
            mock_session_class.assert_called_once()
            call_kwargs = mock_session_class.call_args[1]
            assert call_kwargs["trust_env"] is True
            assert "connector" in call_kwargs

            assert len(result) == 1

    def test_setup_tcp_connector_with_ssl_verify(self):
        """Test that setup_tcp_connector creates proper SSL context."""
        with patch("agent_scan.verify_api.aiohttp.TCPConnector") as mock_connector:
            mock_instance = MagicMock()
            mock_connector.return_value = mock_instance

            setup_tcp_connector(skip_ssl_verify=False)

            # Verify TCPConnector was called with SSL context (not False)
            mock_connector.assert_called_once()
            call_kwargs = mock_connector.call_args[1]
            assert "ssl" in call_kwargs
            assert call_kwargs["ssl"] is not False  # Should have SSL context
            assert call_kwargs["enable_cleanup_closed"] is True

    def test_setup_tcp_connector_without_ssl_verify(self):
        """Test that setup_tcp_connector disables SSL when requested."""
        with patch("agent_scan.verify_api.aiohttp.TCPConnector") as mock_connector:
            mock_instance = MagicMock()
            mock_connector.return_value = mock_instance

            setup_tcp_connector(skip_ssl_verify=True)

            # Verify TCPConnector was called with ssl=False
            mock_connector.assert_called_once()
            call_kwargs = mock_connector.call_args[1]
            assert call_kwargs["ssl"] is False  # SSL verification disabled
            assert call_kwargs["enable_cleanup_closed"] is True


class TestAnalyzeMachineRetries:
    """Test retry logic in analyze_machine."""

    @pytest.mark.asyncio
    async def test_analyze_machine_retries_on_timeout(self):
        """Test that analyze_machine retries on timeout errors."""
        scan_paths = [ScanPathResult(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()

            # First two attempts timeout, third succeeds
            mock_response_success = AsyncMock()
            mock_response_success.status = 200
            mock_response_success.text = AsyncMock(
                return_value='{"scan_path_results": [{"path": "/test/path", "issues": [], "labels": []}], "scan_user_info": {}}'
            )
            mock_response_success.raise_for_status = MagicMock()

            call_count = 0

            def post_side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1

                if call_count <= 2:
                    # First two calls timeout
                    mock_post_timeout = MagicMock()
                    mock_post_timeout.__aenter__ = AsyncMock(side_effect=TimeoutError("Connection timeout"))
                    mock_post_timeout.__aexit__ = AsyncMock(return_value=None)
                    return mock_post_timeout
                else:
                    # Third call succeeds
                    mock_post_success = MagicMock()
                    mock_post_success.__aenter__ = AsyncMock(return_value=mock_response_success)
                    mock_post_success.__aexit__ = AsyncMock(return_value=None)
                    return mock_post_success

            mock_session.post = MagicMock(side_effect=post_side_effect)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            with patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock):
                result = await analyze_machine(
                    scan_paths=scan_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                    max_retries=3,
                )

            # Should have retried 3 times
            assert call_count == 3
            assert len(result) == 1
            assert result[0].path == "/test/path"


class TestAnalyzeMachineHeaders:
    """Test header handling in analyze_machine."""

    @pytest.mark.asyncio
    async def test_analyze_machine_includes_additional_headers(self):
        """Test that additional headers are included in the request."""
        scan_paths = [ScanPathResult(path="/test/path")]
        analysis_url = "https://test.example.com/api"
        additional_headers = {"X-Custom-Header": "custom-value"}

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(
                return_value='{"scan_path_results": [{"path": "/test/path", "issues": [], "labels": []}], "scan_user_info": {}}'
            )
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = await analyze_machine(
                scan_paths=scan_paths,
                analysis_url=analysis_url,
                identifier=None,
                additional_headers=additional_headers,
            )

            # Verify post was called with the additional headers
            mock_session.post.assert_called_once()
            call_kwargs = mock_session.post.call_args[1]
            headers = call_kwargs["headers"]

            assert "X-Custom-Header" in headers
            # Snyk token is included in the Authorization header
            assert "Authorization" in headers
            assert headers["X-Custom-Header"] == "custom-value"
            assert headers["Content-Type"] == "application/json"

            assert len(result) == 1


class TestAnalyzeMachineScanMetadata:
    """Test that analyze_machine includes scan_metadata in the request payload."""

    @pytest.mark.asyncio
    async def test_analyze_machine_includes_scan_metadata_when_scan_context_provided(self):
        """When scan_context is passed, the request payload includes scan_metadata."""
        scan_paths = [ScanPathResult(path="/test/path")]
        analysis_url = "https://test.example.com/api"
        scan_context = {"cli_version": "1.2.3", "source": "pipeline"}

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(
                return_value='{"scan_path_results": [{"path": "/test/path", "issues": [], "labels": []}], "scan_user_info": {}}'
            )
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            await analyze_machine(
                scan_paths=scan_paths,
                analysis_url=analysis_url,
                identifier=None,
                scan_context=scan_context,
            )

            mock_session.post.assert_called_once()
            call_kwargs = mock_session.post.call_args[1]
            payload = json.loads(call_kwargs["data"])
            assert payload.get("scan_metadata") == scan_context

    @pytest.mark.asyncio
    async def test_analyze_machine_omits_scan_metadata_when_scan_context_not_provided(self):
        """When scan_context is not passed, the request payload has no scan_metadata or null."""
        scan_paths = [ScanPathResult(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(
                return_value='{"scan_path_results": [{"path": "/test/path", "issues": [], "labels": []}], "scan_user_info": {}}'
            )
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            await analyze_machine(
                scan_paths=scan_paths,
                analysis_url=analysis_url,
                identifier=None,
            )

            mock_session.post.assert_called_once()
            call_kwargs = mock_session.post.call_args[1]
            payload = json.loads(call_kwargs["data"])
            # scan_metadata may be absent or null when not provided
            assert payload.get("scan_metadata") is None
