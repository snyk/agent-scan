"""Unit tests for the verify_api module, including HTTP proxy support."""

import gzip
import json
import os
import ssl
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from mcp.types import Implementation, InitializeResult, ServerCapabilities, Tool

from agent_scan.models.api.common import ScanUserInfo
from agent_scan.models.api.v20260710 import (
    McpServerRequest,
    ScanPathRequest,
    ScanPathResponse,
    ScanRequest,
    ScanResponse,
    SkillRequest,
)
from agent_scan.models.errors import ErrorCategory, ScanError
from agent_scan.models.inspect import InspectedPath, InspectedServer, InspectedSkill
from agent_scan.models.mcp import RemoteServer, ServerSignature, StdioServer
from agent_scan.models.skill import SkillFile
from agent_scan.verify_api import (
    _async_analysis_enabled,
    _submit_async_analysis,
    analyze_machine,
    build_scan_request,
    load_extra_ca_certs,
    setup_tcp_connector,
)


def _mock_session(response_json: dict) -> MagicMock:
    session = MagicMock()
    response = AsyncMock()
    response.status = 200
    response.text = AsyncMock(return_value=json.dumps(response_json))
    response.raise_for_status = MagicMock()

    post = MagicMock()
    post.__aenter__ = AsyncMock(return_value=response)
    post.__aexit__ = AsyncMock(return_value=None)
    session.post = MagicMock(return_value=post)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    return session


class TestProxySupport:
    """Test cases for HTTP proxy support in verify_api."""

    @pytest.mark.asyncio
    async def test_analyze_machine_honors_http_proxy_env(self):
        """Test that analyze_machine respects HTTP_PROXY environment variable."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        # Mock the aiohttp.ClientSession to capture how it was called
        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
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
                    inspected_paths=inspected_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                )

            # Verify ClientSession was called with trust_env=True
            mock_session_class.assert_called_once()
            call_kwargs = mock_session_class.call_args[1]
            assert call_kwargs["trust_env"] is True, "ClientSession should be called with trust_env=True"

            assert len(result.scan_path_responses) == 1
            assert result.scan_path_responses[0].path == "/test/path"

    @pytest.mark.asyncio
    async def test_analyze_machine_honors_https_proxy_env(self):
        """Test that analyze_machine respects HTTPS_PROXY environment variable."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
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
                    inspected_paths=inspected_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                )

            # Verify ClientSession was called with trust_env=True
            mock_session_class.assert_called_once()
            call_kwargs = mock_session_class.call_args[1]
            assert call_kwargs["trust_env"] is True, "ClientSession should be called with trust_env=True"

            assert len(result.scan_path_responses) == 1

    @pytest.mark.asyncio
    async def test_analyze_machine_works_without_proxy(self):
        """Test that analyze_machine works normally when no proxy is configured."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
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
                    inspected_paths=inspected_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                )

            # Verify ClientSession was still called with trust_env=True
            # (it just won't find any proxy to use)
            mock_session_class.assert_called_once()
            call_kwargs = mock_session_class.call_args[1]
            assert call_kwargs["trust_env"] is True

            assert len(result.scan_path_responses) == 1
            assert result.scan_path_responses[0].path == "/test/path"

    @pytest.mark.asyncio
    async def test_analyze_machine_with_skip_ssl_verify_and_proxy(self):
        """Test that skip_ssl_verify works correctly with proxy support."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
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
                    inspected_paths=inspected_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                    skip_ssl_verify=True,
                )

            # Verify both trust_env and connector are set
            mock_session_class.assert_called_once()
            call_kwargs = mock_session_class.call_args[1]
            assert call_kwargs["trust_env"] is True
            assert "connector" in call_kwargs

            assert len(result.scan_path_responses) == 1

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

    def test_setup_tcp_connector_loads_extra_ca_certs(self):
        """When verifying, setup_tcp_connector augments the context with env CA certs."""
        with (
            patch("agent_scan.verify_api.aiohttp.TCPConnector"),
            patch("agent_scan.verify_api.load_extra_ca_certs") as mock_load,
        ):
            setup_tcp_connector(skip_ssl_verify=False)
            mock_load.assert_called_once()
            assert isinstance(mock_load.call_args[0][0], ssl.SSLContext)

    def test_setup_tcp_connector_skips_extra_ca_certs_when_insecure(self):
        """When skip_ssl_verify is True, there is no context to augment."""
        with (
            patch("agent_scan.verify_api.aiohttp.TCPConnector"),
            patch("agent_scan.verify_api.load_extra_ca_certs") as mock_load,
        ):
            setup_tcp_connector(skip_ssl_verify=True)
            mock_load.assert_not_called()


class TestLoadExtraCaCerts:
    """The Snyk CLI proxy exports SSL_CERT_FILE / REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS
    pointing at its self-signed certificate; these must be trusted additively."""

    _CERT_ENV_VARS = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")

    def _clear_cert_env(self):
        for var in self._CERT_ENV_VARS:
            os.environ.pop(var, None)

    @pytest.mark.parametrize("env_var", _CERT_ENV_VARS)
    def test_loads_cert_from_each_env_var(self, tmp_path, env_var):
        cert = tmp_path / "proxy.pem"
        cert.write_text("dummy")
        ctx = MagicMock(spec=ssl.SSLContext)

        with patch.dict(os.environ, {}, clear=False):
            self._clear_cert_env()
            os.environ[env_var] = str(cert)
            load_extra_ca_certs(ctx)

        ctx.load_verify_locations.assert_called_once_with(cafile=os.path.realpath(str(cert)))

    def test_deduplicates_when_vars_point_to_same_file(self, tmp_path):
        cert = tmp_path / "proxy.pem"
        cert.write_text("dummy")
        ctx = MagicMock(spec=ssl.SSLContext)

        with patch.dict(os.environ, {var: str(cert) for var in self._CERT_ENV_VARS}, clear=False):
            load_extra_ca_certs(ctx)

        ctx.load_verify_locations.assert_called_once()

    def test_missing_file_is_skipped(self, tmp_path):
        ctx = MagicMock(spec=ssl.SSLContext)

        with patch.dict(os.environ, {}, clear=False):
            self._clear_cert_env()
            os.environ["SSL_CERT_FILE"] = str(tmp_path / "does-not-exist.pem")
            load_extra_ca_certs(ctx)

        ctx.load_verify_locations.assert_not_called()

    def test_no_env_vars_is_noop(self):
        ctx = MagicMock(spec=ssl.SSLContext)

        with patch.dict(os.environ, {}, clear=False):
            self._clear_cert_env()
            load_extra_ca_certs(ctx)

        ctx.load_verify_locations.assert_not_called()

    @pytest.mark.parametrize(
        "error",
        [
            ssl.SSLError("bad certificate"),
            OSError("permission denied"),
            PermissionError("EACCES"),
            FileNotFoundError("removed after isfile check"),
        ],
        ids=["ssl_error", "os_error", "permission_error", "file_not_found"],
    )
    def test_load_failure_is_logged_not_raised(self, tmp_path, error):
        """load_verify_locations failures (bad cert or runtime OS errors) must be
        swallowed so the connector still gets built and falls back to certifi/OS trust."""
        cert = tmp_path / "bad.pem"
        cert.write_text("not a certificate")
        ctx = MagicMock(spec=ssl.SSLContext)
        ctx.load_verify_locations.side_effect = error

        with patch.dict(os.environ, {}, clear=False):
            self._clear_cert_env()
            os.environ["SSL_CERT_FILE"] = str(cert)
            load_extra_ca_certs(ctx)  # must not raise

        ctx.load_verify_locations.assert_called_once()


class TestAnalyzeMachineRetries:
    """Test retry logic in analyze_machine."""

    @pytest.mark.asyncio
    async def test_analyze_machine_retries_on_timeout(self):
        """Test that analyze_machine retries on timeout errors."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()

            # First two attempts timeout, third succeeds
            mock_response_success = AsyncMock()
            mock_response_success.status = 200
            mock_response_success.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
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
                    inspected_paths=inspected_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                    max_retries=3,
                )

            # Should have retried 3 times
            assert call_count == 3
            assert len(result.scan_path_responses) == 1
            assert result.scan_path_responses[0].path == "/test/path"


class TestAnalyzeMachineHeaders:
    """Test header handling in analyze_machine."""

    @pytest.mark.asyncio
    async def test_analyze_machine_includes_additional_headers(self):
        """Test that additional headers are included in the request."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"
        additional_headers = {"X-Custom-Header": "custom-value"}

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            result = await analyze_machine(
                inspected_paths=inspected_paths,
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

            assert len(result.scan_path_responses) == 1


class TestAnalyzeMachineScanMetadata:
    """Test that analyze_machine includes scan_metadata in the request payload."""

    @pytest.mark.asyncio
    async def test_analyze_machine_includes_scan_metadata_when_scan_context_provided(self):
        """When scan_context is passed, the request payload includes scan_metadata."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"
        scan_context = {"cli_version": "1.2.3", "source": "pipeline"}

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            await analyze_machine(
                inspected_paths=inspected_paths,
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
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
            mock_response.raise_for_status = MagicMock()

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            await analyze_machine(
                inspected_paths=inspected_paths,
                analysis_url=analysis_url,
                identifier=None,
            )

            mock_session.post.assert_called_once()
            call_kwargs = mock_session.post.call_args[1]
            payload = json.loads(call_kwargs["data"])
            # scan_metadata may be absent or null when not provided
            assert payload.get("scan_metadata") is None


class TestAnalyzeMachineUserInfo:
    """Test that analyze_machine populates scan_user_info correctly."""

    @staticmethod
    def _make_mock_session():
        mock_session = MagicMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
        mock_response.raise_for_status = MagicMock()

        mock_post = MagicMock()
        mock_post.__aenter__ = AsyncMock(return_value=mock_response)
        mock_post.__aexit__ = AsyncMock(return_value=None)

        mock_session.post = MagicMock(return_value=mock_post)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        return mock_session

    @pytest.mark.asyncio
    async def test_uses_scanned_usernames_when_provided(self):
        """When scanned_usernames is passed, the payload's username is that list."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"
        scanned_usernames = ["alice", "bob"]

        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class,
            patch("agent_scan.verify_api.get_username", return_value="local-user"),
            patch("agent_scan.verify_api.get_hostname", return_value="test-host"),
            patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}),
        ):
            mock_session_class.return_value = self._make_mock_session()

            await analyze_machine(
                inspected_paths=inspected_paths,
                analysis_url=analysis_url,
                identifier=None,
                scanned_usernames=scanned_usernames,
            )

            mock_session_class.return_value.post.assert_called_once()
            call_kwargs = mock_session_class.return_value.post.call_args[1]
            payload = json.loads(call_kwargs["data"])
            assert payload["scan_user_info"]["username"] == scanned_usernames
            assert payload["scan_user_info"]["hostname"] == "test-host"

    @pytest.mark.asyncio
    async def test_falls_back_to_local_username_when_scanned_usernames_not_provided(self):
        """When scanned_usernames is not provided, username falls back to [get_username()]."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class,
            patch("agent_scan.verify_api.get_username", return_value="local-user"),
            patch("agent_scan.verify_api.get_hostname", return_value="test-host"),
            patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}),
        ):
            mock_session_class.return_value = self._make_mock_session()

            await analyze_machine(
                inspected_paths=inspected_paths,
                analysis_url=analysis_url,
                identifier=None,
            )

            mock_session_class.return_value.post.assert_called_once()
            call_kwargs = mock_session_class.return_value.post.call_args[1]
            payload = json.loads(call_kwargs["data"])
            assert payload["scan_user_info"]["username"] == ["local-user"]
            assert payload["scan_user_info"]["hostname"] == "test-host"

    @pytest.mark.asyncio
    async def test_falls_back_to_local_username_when_scanned_usernames_empty(self):
        """When scanned_usernames is an empty list, username falls back to [get_username()]."""
        inspected_paths = [InspectedPath(path="/test/path")]
        analysis_url = "https://test.example.com/api"

        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class,
            patch("agent_scan.verify_api.get_username", return_value="local-user"),
            patch("agent_scan.verify_api.get_hostname", return_value="test-host"),
            patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}),
        ):
            mock_session_class.return_value = self._make_mock_session()

            await analyze_machine(
                inspected_paths=inspected_paths,
                analysis_url=analysis_url,
                identifier=None,
                scanned_usernames=[],
            )

            mock_session_class.return_value.post.assert_called_once()
            call_kwargs = mock_session_class.return_value.post.call_args[1]
            payload = json.loads(call_kwargs["data"])
            assert payload["scan_user_info"]["username"] == ["local-user"]


class TestAnalyzeMachineAuthPrecedence:
    """
    Auth selection in ``analyze_machine`` follows an explicit precedence:

    1. ``push_key`` (from ``--control-server-H x-client-id:...``) wins
       — explicit CLI args beat implicit env state, and split-auth
       (push-key for upload + SNYK_TOKEN for analysis) caused
       hard-to-debug routing issues for users with both set.
    2. ``SNYK_TOKEN`` env var.
    3. ``SNYK_CLI_USE`` env var (proxy mode).
    4. Otherwise → error.

    These tests pin that exact ordering.
    """

    _ANALYSIS_URL = "https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10"

    @staticmethod
    def _make_mock_session():
        mock_session = MagicMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
        mock_response.raise_for_status = MagicMock()

        mock_post = MagicMock()
        mock_post.__aenter__ = AsyncMock(return_value=mock_response)
        mock_post.__aexit__ = AsyncMock(return_value=None)

        mock_session.post = MagicMock(return_value=mock_post)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        return mock_session

    async def _run(
        self,
        *,
        push_key: str | None,
        env: dict[str, str],
        analysis_url: str | None = None,
    ):
        inspected_paths = [InspectedPath(path="/test/path")]
        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class,
            patch("agent_scan.verify_api.get_username", return_value="local-user"),
            patch("agent_scan.verify_api.get_hostname", return_value="test-host"),
            patch.dict(os.environ, env, clear=False),
        ):
            mock_session_class.return_value = self._make_mock_session()
            await analyze_machine(
                inspected_paths=inspected_paths,
                analysis_url=analysis_url or self._ANALYSIS_URL,
                identifier=None,
                push_key=push_key,
            )
            mock_session_class.return_value.post.assert_called_once()
            call_args = mock_session_class.return_value.post.call_args
            posted_url = call_args[0][0]
            posted_headers = call_args[1]["headers"]
        return posted_url, posted_headers

    @pytest.mark.asyncio
    async def test_push_key_forces_v20260710_when_analysis_url_requests_legacy_version(self):
        os.environ.pop("SNYK_TOKEN", None)
        posted_url, _ = await self._run(
            push_key="push-abc",
            env={},
            analysis_url=("https://api.snyk.io/hidden/mcp-scan/analysis-machine?region=us&version=2025-09-02"),
        )

        assert posted_url == ("https://api.snyk.io/hidden/mcp-scan/analysis-machine?region=us&version=2026-07-10")

    @pytest.mark.asyncio
    async def test_push_key_only_uses_x_push_key_header_on_unrewritten_url(self):
        # SNYK_TOKEN must not leak from a real test environment; drop it.
        os.environ.pop("SNYK_TOKEN", None)
        posted_url, posted_headers = await self._run(push_key="push-abc", env={})

        assert posted_headers.get("X-Push-Key") == "push-abc"
        assert "Authorization" not in posted_headers
        assert posted_url == self._ANALYSIS_URL  # not rewritten

    @pytest.mark.asyncio
    async def test_snyk_token_only_uses_authorization_header_on_cli_url(self):
        posted_url, posted_headers = await self._run(push_key=None, env={"SNYK_TOKEN": "snyk-tok-123"})

        assert posted_headers.get("Authorization") == "token snyk-tok-123"
        assert "X-Push-Key" not in posted_headers
        assert "/cli/analysis-machine" in posted_url

    @pytest.mark.asyncio
    async def test_both_present_push_key_wins(self):
        """
        Load-bearing precedence: when both a push key and SNYK_TOKEN are
        set, the push key wins. Explicit CLI args beat implicit env state.
        The analysis URL is *not* rewritten to /cli/analysis-machine and
        Authorization is *not* set — every byte of the call matches the
        push-key-only case.
        """
        posted_url, posted_headers = await self._run(push_key="push-abc", env={"SNYK_TOKEN": "snyk-tok-123"})

        assert posted_headers.get("X-Push-Key") == "push-abc"
        assert "Authorization" not in posted_headers
        assert posted_url == self._ANALYSIS_URL


class TestAnalyzeMachineHttpErrors:
    """Test that analyze_machine handles various HTTP error status codes correctly."""

    @staticmethod
    def _make_inspected_paths() -> list[InspectedPath]:
        """Build a realistic InspectedPath modelled on a real claude code inspect."""
        return [
            InspectedPath(
                path="/Users/test/.claude",
                client="claude code",
                servers=[
                    InspectedServer(
                        name="figma",
                        server=RemoteServer(url="https://mcp.figma.com/mcp", type="http"),
                        signature=None,
                        error=ScanError(
                            message="could not start server",
                            category="server_startup",
                        ),
                    ),
                    InspectedServer(
                        name="Playwright",
                        server=StdioServer(command="npx", args=["@playwright/mcp@latest"]),
                        signature=ServerSignature(
                            metadata=InitializeResult(
                                protocolVersion="2025-11-25",
                                capabilities=ServerCapabilities(),
                                serverInfo=Implementation(name="Playwright", version="0.0.68"),
                            ),
                            tools=[
                                Tool(
                                    name="browser_close",
                                    description="Close the page",
                                    inputSchema={"type": "object", "properties": {}},
                                ),
                            ],
                        ),
                    ),
                ],
            ),
            InspectedPath(
                path="/Users/test/.vscode",
                client="vscode",
                servers=[],
                error=ScanError(
                    message="Unknown MCP config: /Users/test/.vscode/settings.json",
                    exception=None,
                    traceback=None,
                    is_failure=True,
                    category="unknown_config",
                    server_output=None,
                ),
            ),
            InspectedPath(
                path="/Users/test/.cursor",
                client="cursor",
                servers=[],
            ),
        ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "status_code, status_message, expected_error_substring",
        [
            (400, "Bad Request", "The analysis server returned an error for your request: 400 - Bad Request"),
            (401, "Unauthorized", "Unauthorized. Please check your SNYK_TOKEN environment variable or your push key."),
            (403, "Forbidden", "The analysis server returned an error for your request: 403 - Forbidden"),
            (
                413,
                "Payload Too Large",
                "Analysis scope too large (e.g. too many or very large MCP servers/skills)",
            ),
            (
                422,
                "Unprocessable Entity",
                "The analysis server returned an error for your request: 422 - Unprocessable Entity",
            ),
            (
                429,
                "Too Many Requests",
                "Daily usage limit reached for the public version of Agent-Scan",
            ),
            (500, "Internal Server Error", "Could not reach analysis server: 500 - Internal Server Error"),
            (502, "Bad Gateway", "Could not reach analysis server: 502 - Bad Gateway"),
            (503, "Service Unavailable", "Could not reach analysis server: 503 - Service Unavailable"),
            (504, "Gateway Timeout", "Could not reach analysis server: 504 - Gateway Timeout"),
        ],
        ids=["400", "401", "403", "413", "422", "429", "500", "502", "503", "504"],
    )
    async def test_analyze_machine_http_error_responses(self, status_code, status_message, expected_error_substring):
        """Test that each HTTP error status code produces the correct error message on inspected_paths."""
        inspected_paths = self._make_inspected_paths()
        analysis_url = "https://test.example.com/api"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class:
            mock_session = MagicMock()

            mock_request_info = MagicMock()
            mock_request_info.real_url = analysis_url

            error = aiohttp.ClientResponseError(
                request_info=mock_request_info,
                history=(),
                status=status_code,
                message=status_message,
            )

            mock_response = AsyncMock()
            mock_response.status = status_code
            mock_response.raise_for_status = MagicMock(side_effect=error)

            mock_post = MagicMock()
            mock_post.__aenter__ = AsyncMock(return_value=mock_response)
            mock_post.__aexit__ = AsyncMock(return_value=None)

            mock_session.post = MagicMock(return_value=mock_post)
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=None)

            mock_session_class.return_value = mock_session

            with patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}):
                result = await analyze_machine(
                    inspected_paths=inspected_paths,
                    analysis_url=analysis_url,
                    identifier=None,
                    max_retries=1,
                )

        assert len(result.scan_path_responses) == 3
        assert [path.path for path in result.scan_path_responses] == [path.path for path in inspected_paths]
        for path in result.scan_path_responses:
            assert path.error is not None
            assert path.error.category == "analysis_error"
            assert expected_error_substring in path.error.message
            assert path.server_risks == []
            assert path.skill_risks == []


def _make_get_session(*, status, json_data=None, get_exc=None):
    """A mock ClientSession whose ``.get(...)`` yields a response with the given status/json."""
    mock_session = MagicMock()
    mock_response = AsyncMock()
    mock_response.status = status
    mock_response.json = AsyncMock(return_value=json_data)

    mock_get = MagicMock()
    if get_exc is not None:
        mock_get.__aenter__ = AsyncMock(side_effect=get_exc)
    else:
        mock_get.__aenter__ = AsyncMock(return_value=mock_response)
    mock_get.__aexit__ = AsyncMock(return_value=None)

    mock_session.get = MagicMock(return_value=mock_get)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


def _get_cm(*, status=None, json_data=None, exc=None):
    """A single ``session.get(...)`` async context manager yielding a status/json or raising."""
    cm = MagicMock()
    if exc is not None:
        cm.__aenter__ = AsyncMock(side_effect=exc)
    else:
        response = AsyncMock()
        response.status = status
        response.json = AsyncMock(return_value=json_data)
        cm.__aenter__ = AsyncMock(return_value=response)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm


def _make_get_session_seq(get_cms):
    """A mock ClientSession whose successive ``.get(...)`` calls return the given
    context managers in order (one per retry attempt)."""
    mock_session = MagicMock()
    mock_session.get = MagicMock(side_effect=list(get_cms))
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


def _make_post_session(*, status=202, post_exc=None):
    """A mock ClientSession whose ``.post(...)`` yields a response with the given status."""
    mock_session = MagicMock()
    mock_response = AsyncMock()
    mock_response.status = status

    mock_post = MagicMock()
    if post_exc is not None:
        mock_post.__aenter__ = AsyncMock(side_effect=post_exc)
    else:
        mock_post.__aenter__ = AsyncMock(return_value=mock_response)
    mock_post.__aexit__ = AsyncMock(return_value=None)

    mock_session.post = MagicMock(return_value=mock_post)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


def _post_cm(*, status=None, exc=None):
    """A single ``session.post(...)`` async context manager yielding a status or raising."""
    cm = MagicMock()
    if exc is not None:
        cm.__aenter__ = AsyncMock(side_effect=exc)
    else:
        response = AsyncMock()
        response.status = status
        cm.__aenter__ = AsyncMock(return_value=response)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm


def _make_post_session_seq(post_cms):
    """A mock ClientSession whose successive ``.post(...)`` calls return the given
    context managers in order (one per retry attempt)."""
    mock_session = MagicMock()
    mock_session.post = MagicMock(side_effect=list(post_cms))
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


def _make_sync_ok_session():
    """A mock ClientSession for the synchronous analysis POST returning a 200 with empty results."""
    mock_session = MagicMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text = AsyncMock(return_value='{"scan_path_responses": [{"path": "/test/path"}]}')
    mock_response.raise_for_status = MagicMock()

    mock_post = MagicMock()
    mock_post.__aenter__ = AsyncMock(return_value=mock_response)
    mock_post.__aexit__ = AsyncMock(return_value=None)

    mock_session.post = MagicMock(return_value=mock_post)
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=None)
    return mock_session


class TestAsyncAnalysisEnabled:
    """The push-key config lookup that decides sync vs async analysis per tenant."""

    _CONFIG_URL = "https://api.snyk.io/hidden/agent-scan/config?version=2026-07-10"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "json_data, expected",
        [
            ({"async_analysis_enabled": True}, True),
            ({"async_analysis_enabled": False}, False),
            ({}, False),
        ],
        ids=["enabled", "disabled", "missing_key"],
    )
    async def test_parses_flag_from_config_response(self, json_data, expected):
        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls:
            mock_cls.return_value = _make_get_session(status=200, json_data=json_data)
            result = await _async_analysis_enabled(self._CONFIG_URL, "push-abc", None, False)
        assert result is expected

    @pytest.mark.asyncio
    async def test_sends_push_key_header_to_config_url(self):
        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls:
            session = _make_get_session(status=200, json_data={"async_analysis_enabled": True})
            mock_cls.return_value = session
            await _async_analysis_enabled(self._CONFIG_URL, "push-abc", None, False)

        session.get.assert_called_once()
        assert session.get.call_args[0][0] == self._CONFIG_URL
        assert session.get.call_args[1]["headers"]["X-Push-Key"] == "push-abc"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [400, 401, 403, 404])
    async def test_4xx_returns_false_without_retry(self, status):
        """Deterministic client errors fall back to sync immediately, no retry."""
        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_get_session(status=status, json_data={"async_analysis_enabled": True})
            mock_cls.return_value = session
            assert await _async_analysis_enabled(self._CONFIG_URL, "push-abc", None, False) is False

        session.get.assert_called_once()
        mock_sleep.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [500, 502, 503])
    async def test_5xx_retries_then_returns_false(self, status):
        """A persistent 5xx is retried (default max_retries=2) then falls back to sync."""
        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_get_session(status=status, json_data={"async_analysis_enabled": True})
            mock_cls.return_value = session
            assert await _async_analysis_enabled(self._CONFIG_URL, "push-abc", None, False) is False

        assert session.get.call_count == 2
        mock_sleep.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_5xx_retries_then_succeeds(self):
        """A transient 5xx followed by a 200 honors the tenant's async preference."""
        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_get_session_seq(
                [_get_cm(status=503), _get_cm(status=200, json_data={"async_analysis_enabled": True})]
            )
            mock_cls.return_value = session
            assert await _async_analysis_enabled(self._CONFIG_URL, "push-abc", None, False) is True

        assert session.get.call_count == 2
        mock_sleep.assert_awaited_once()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "exc",
        [
            aiohttp.ServerDisconnectedError("dropped"),
            aiohttp.ClientOSError("connection reset"),
            aiohttp.ClientPayloadError("truncated"),
            TimeoutError("slow"),
        ],
        ids=["server_disconnected", "os_error", "payload_error", "timeout"],
    )
    async def test_transient_exception_retries_then_returns_false(self, exc):
        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_get_session(status=200, get_exc=exc)
            mock_cls.return_value = session
            assert await _async_analysis_enabled(self._CONFIG_URL, "push-abc", None, False) is False

        assert session.get.call_count == 2
        mock_sleep.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_transient_exception_retries_then_succeeds(self):
        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_get_session_seq(
                [_get_cm(exc=TimeoutError("slow")), _get_cm(status=200, json_data={"async_analysis_enabled": True})]
            )
            mock_cls.return_value = session
            assert await _async_analysis_enabled(self._CONFIG_URL, "push-abc", None, False) is True

        assert session.get.call_count == 2
        mock_sleep.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_transient_client_error_returns_false_without_retry(self):
        """A bare aiohttp.ClientError outside the transient set falls back to sync, no retry."""
        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_get_session(status=200, get_exc=aiohttp.ClientError("boom"))
            mock_cls.return_value = session
            assert await _async_analysis_enabled(self._CONFIG_URL, "push-abc", None, False) is False

        session.get.assert_called_once()
        mock_sleep.assert_not_awaited()


class TestSubmitAsyncAnalysis:
    """The fire-and-forget async submission: gzipped body, headers, and no-raise on failure."""

    _ASYNC_URL = "https://api.snyk.io/hidden/agent-scan/async/analysis?version=2026-07-10"

    @pytest.mark.asyncio
    async def test_gzips_payload_and_sets_headers(self):
        payload = MagicMock()
        payload.model_dump_json.return_value = '{"scan_path_results": []}'

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls:
            session = _make_post_session(status=202)
            mock_cls.return_value = session
            await _submit_async_analysis(
                self._ASYNC_URL,
                payload,
                {"X-Push-Key": "pk", "X-Environment": "test"},
                "user-1",
                None,
                False,
            )

        session.post.assert_called_once()
        call = session.post.call_args
        assert call[0][0] == self._ASYNC_URL
        headers = call[1]["headers"]
        assert headers["Content-Encoding"] == "gzip"
        assert headers["X-Push-Key"] == "pk"
        assert headers["X-Scan-User-Id"] == "user-1"
        assert gzip.decompress(call[1]["data"]) == b'{"scan_path_results": []}'

    @pytest.mark.asyncio
    async def test_omits_scan_user_id_without_identifier(self):
        payload = MagicMock()
        payload.model_dump_json.return_value = "{}"

        with patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls:
            session = _make_post_session(status=202)
            mock_cls.return_value = session
            await _submit_async_analysis(self._ASYNC_URL, payload, {"X-Push-Key": "pk"}, None, None, False)

        assert "X-Scan-User-Id" not in session.post.call_args[1]["headers"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [400, 401, 403, 413])
    async def test_4xx_does_not_retry(self, status):
        """4xx is deterministic: return after a single attempt without retrying."""
        payload = MagicMock()
        payload.model_dump_json.return_value = "{}"

        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_post_session(status=status)
            mock_cls.return_value = session
            assert await _submit_async_analysis(self._ASYNC_URL, payload, {}, None, None, False) is None

        session.post.assert_called_once()
        mock_sleep.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_202_first_try_does_not_retry(self):
        payload = MagicMock()
        payload.model_dump_json.return_value = "{}"

        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_post_session(status=202)
            mock_cls.return_value = session
            assert await _submit_async_analysis(self._ASYNC_URL, payload, {}, None, None, False) is None

        session.post.assert_called_once()
        mock_sleep.assert_not_awaited()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [500, 502, 503])
    async def test_5xx_retries_then_succeeds(self, status):
        """A 5xx is transient (server asks to retry later); the next 202 succeeds."""
        payload = MagicMock()
        payload.model_dump_json.return_value = "{}"

        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_post_session_seq([_post_cm(status=status), _post_cm(status=202)])
            mock_cls.return_value = session
            assert await _submit_async_analysis(self._ASYNC_URL, payload, {}, None, None, False, 3) is None

        assert session.post.call_count == 2
        mock_sleep.assert_awaited_once()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "exc",
        [
            aiohttp.ServerDisconnectedError("dropped"),
            aiohttp.ClientOSError("connection reset"),
            aiohttp.ClientPayloadError("truncated"),
            TimeoutError("slow"),
        ],
        ids=["server_disconnected", "os_error", "payload_error", "timeout"],
    )
    async def test_transient_exception_retries_then_succeeds(self, exc):
        """The client-side manifestations of a server ClientDisconnect are retried."""
        payload = MagicMock()
        payload.model_dump_json.return_value = "{}"

        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_post_session_seq([_post_cm(exc=exc), _post_cm(status=202)])
            mock_cls.return_value = session
            assert await _submit_async_analysis(self._ASYNC_URL, payload, {}, None, None, False, 3) is None

        assert session.post.call_count == 2
        mock_sleep.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_transient_exception_gives_up_after_max_retries(self):
        """Exhausting retries returns None (fire-and-forget) after max_retries attempts."""
        payload = MagicMock()
        payload.model_dump_json.return_value = "{}"

        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_post_session(post_exc=TimeoutError("slow"))
            mock_cls.return_value = session
            assert await _submit_async_analysis(self._ASYNC_URL, payload, {}, None, None, False, 3) is None

        assert session.post.call_count == 3
        assert mock_sleep.await_count == 2  # backoff between the 3 attempts

    @pytest.mark.asyncio
    async def test_non_transient_client_error_does_not_retry(self):
        """A bare aiohttp.ClientError outside the transient set is swallowed, not retried."""
        payload = MagicMock()
        payload.model_dump_json.return_value = "{}"

        with (
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_cls,
            patch("agent_scan.verify_api.asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        ):
            session = _make_post_session(post_exc=aiohttp.ClientError("boom"))
            mock_cls.return_value = session
            assert await _submit_async_analysis(self._ASYNC_URL, payload, {}, None, None, False, 3) is None

        session.post.assert_called_once()
        mock_sleep.assert_not_awaited()


class TestAnalyzeMachineAsyncRouting:
    """analyze_machine's push-key routing: async when the tenant is flagged, sync otherwise, no fallback."""

    _ANALYSIS_URL = "https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10"

    @pytest.mark.asyncio
    async def test_async_enabled_submits_async_and_skips_sync(self):
        inspected_paths = [
            InspectedPath(
                client="cursor",
                path="/test/path",
                servers=[
                    InspectedServer(
                        name="server",
                        server=StdioServer(command="server"),
                        signature=ServerSignature(
                            metadata=InitializeResult(
                                protocolVersion="2024-11-05",
                                capabilities=ServerCapabilities(),
                                serverInfo=Implementation(name="server", version="1"),
                            ),
                            tools=[Tool(name="search", inputSchema={})],
                        ),
                    )
                ],
                skills=[
                    InspectedSkill(
                        name="skill",
                        installation_path="/test/skill",
                        files=[SkillFile(path="SKILL.md", content="instructions")],
                    )
                ],
            )
        ]

        with (
            patch(
                "agent_scan.verify_api._async_analysis_enabled", new_callable=AsyncMock, return_value=True
            ) as mock_enabled,
            patch("agent_scan.verify_api._submit_async_analysis", new_callable=AsyncMock) as mock_submit,
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class,
        ):
            result = await analyze_machine(
                inspected_paths=inspected_paths,
                analysis_url=self._ANALYSIS_URL,
                identifier="id-1",
                push_key="push-abc",
            )

        mock_enabled.assert_awaited_once()
        mock_submit.assert_awaited_once()
        # No synchronous analysis session is ever opened once async is chosen.
        mock_session_class.assert_not_called()
        response_path = result.scan_path_responses[0]
        assert response_path.client == "cursor"
        assert response_path.path == "/test/path"
        assert response_path.server_risks[0].name == "server"
        assert response_path.server_risks[0].entities[0].name == "search"
        assert response_path.server_risks[0].entities[0].type == "tool"
        assert response_path.skill_risks[0].name == "skill"
        assert response_path.skill_risks[0].files[0].name == "SKILL.md"
        assert response_path.skill_risks[0].files[0].type == "instruction"
        assert isinstance(mock_submit.call_args.args[1], ScanRequest)
        # Config + async URLs are derived from the sync analysis URL, preserving the version query.
        assert mock_enabled.call_args.args[0] == "https://api.snyk.io/hidden/agent-scan/config?version=2026-07-10"
        assert (
            mock_submit.call_args.args[0] == "https://api.snyk.io/hidden/agent-scan/async/analysis?version=2026-07-10"
        )

    @pytest.mark.asyncio
    async def test_async_disabled_falls_through_to_sync(self):
        inspected_paths = [InspectedPath(path="/test/path")]

        with (
            patch(
                "agent_scan.verify_api._async_analysis_enabled", new_callable=AsyncMock, return_value=False
            ) as mock_enabled,
            patch("agent_scan.verify_api._submit_async_analysis", new_callable=AsyncMock) as mock_submit,
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class,
        ):
            mock_session_class.return_value = _make_sync_ok_session()
            result = await analyze_machine(
                inspected_paths=inspected_paths,
                analysis_url=self._ANALYSIS_URL,
                identifier=None,
                push_key="push-abc",
            )

        mock_enabled.assert_awaited_once()
        mock_submit.assert_not_awaited()
        mock_session_class.assert_called_once()
        # The sync request keeps the push-key auth and the un-rewritten analysis URL.
        call = mock_session_class.return_value.post.call_args
        assert call[0][0] == self._ANALYSIS_URL
        assert call[1]["headers"]["X-Push-Key"] == "push-abc"
        assert result == ScanResponse(scan_path_responses=[ScanPathResponse(path="/test/path")])

    @pytest.mark.asyncio
    async def test_show_analysis_results_skips_async_check_even_with_push_key(self):
        """show_analysis_results=True must go straight to sync without ever probing the async-enabled
        config endpoint, even for a push-key tenant that would otherwise route to async."""
        inspected_paths = [InspectedPath(path="/test/path")]

        with (
            patch(
                "agent_scan.verify_api._async_analysis_enabled", new_callable=AsyncMock, return_value=True
            ) as mock_enabled,
            patch("agent_scan.verify_api._submit_async_analysis", new_callable=AsyncMock) as mock_submit,
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class,
        ):
            mock_session_class.return_value = _make_sync_ok_session()
            result = await analyze_machine(
                inspected_paths=inspected_paths,
                analysis_url=self._ANALYSIS_URL,
                identifier=None,
                push_key="push-abc",
                show_analysis_results=True,
            )

        # The async gate is never consulted and no async submission happens.
        mock_enabled.assert_not_awaited()
        mock_submit.assert_not_awaited()
        # A synchronous request is made, keeping push-key auth and the un-rewritten analysis URL.
        mock_session_class.assert_called_once()
        call = mock_session_class.return_value.post.call_args
        assert call[0][0] == self._ANALYSIS_URL
        assert call[1]["headers"]["X-Push-Key"] == "push-abc"
        assert result == ScanResponse(scan_path_responses=[ScanPathResponse(path="/test/path")])

    @pytest.mark.asyncio
    async def test_snyk_token_always_sync_never_probes_async(self):
        """SNYK_TOKEN auth (no push key) must always go synchronous: the async gate is reserved for
        the push-key branch, so it is never consulted and no async submission happens."""
        inspected_paths = [InspectedPath(path="/test/path")]

        with (
            patch(
                "agent_scan.verify_api._async_analysis_enabled", new_callable=AsyncMock, return_value=True
            ) as mock_enabled,
            patch("agent_scan.verify_api._submit_async_analysis", new_callable=AsyncMock) as mock_submit,
            patch("agent_scan.verify_api.aiohttp.ClientSession") as mock_session_class,
            patch.dict(os.environ, {"SNYK_TOKEN": "snyk-tok-123"}, clear=False),
        ):
            mock_session_class.return_value = _make_sync_ok_session()
            result = await analyze_machine(
                inspected_paths=inspected_paths,
                analysis_url=self._ANALYSIS_URL,
                identifier=None,
                push_key=None,
            )

        # The async gate is never consulted and no async submission happens for token auth.
        mock_enabled.assert_not_awaited()
        mock_submit.assert_not_awaited()
        # A synchronous request is made against the /cli/ URL with token Authorization (no push key).
        mock_session_class.assert_called_once()
        call = mock_session_class.return_value.post.call_args
        assert "/cli/analysis-machine" in call[0][0]
        assert call[1]["headers"]["Authorization"] == "token snyk-tok-123"
        assert "X-Push-Key" not in call[1]["headers"]
        assert result == ScanResponse(scan_path_responses=[ScanPathResponse(path="/test/path")])


class TestBuildScanRequest:
    """The API boundary turns inspection-domain results into v2026-07-10 wire models."""

    def test_maps_mcp_servers_and_skills(self):
        inspected = InspectedPath(
            client="cursor",
            path="/tmp/project",
            servers=[
                InspectedServer(
                    name="sqlite",
                    config_path="/tmp/project/.mcp.json",
                    server=StdioServer(command="uvx", args=["sqlite-mcp"], type="stdio"),
                ),
                InspectedServer(
                    name="remote",
                    config_path="/tmp/project/.mcp.json",
                    server=RemoteServer(url="https://example.com/mcp", type="http"),
                ),
            ],
            skills=[
                InspectedSkill(
                    name="my-skill",
                    installation_path="/tmp/project/.skills/my-skill",
                    files=[SkillFile(path="SKILL.md", content="---\nname: my-skill\n---\ndo things")],
                ),
            ],
        )

        req = build_scan_request([inspected])

        assert len(req.scan_path_requests) == 1
        spr = req.scan_path_requests[0]
        assert type(spr) is ScanPathRequest
        assert type(spr.servers[0]) is McpServerRequest
        assert type(spr.skills[0]) is SkillRequest
        assert spr.client == "cursor"
        assert [s.name for s in spr.servers] == ["sqlite", "remote"]
        assert [s.name for s in spr.skills] == ["my-skill"]
        # mcp fields carried across
        assert spr.servers[0].config_path == "/tmp/project/.mcp.json"
        assert isinstance(spr.servers[0].server, StdioServer)
        assert isinstance(spr.servers[1].server, RemoteServer)
        # skill request carries installation_path + files verbatim
        assert spr.skills[0].installation_path == "/tmp/project/.skills/my-skill"
        assert [f.path for f in spr.skills[0].files] == ["SKILL.md"]

    def test_top_level_path_is_home_relativized(self):
        absolute_path = os.path.expanduser("~/project/.mcp.json")
        inspected = InspectedPath(client=None, path=absolute_path)
        req = build_scan_request([inspected])

        assert req.scan_path_requests[0].path == "~/project/.mcp.json"
        assert inspected.path == absolute_path

    def test_passes_through_error_and_empty_name(self):
        server_error = ScanError(message="boom", category="server_startup")
        inspected = InspectedPath(
            client=None,
            path="/tmp/p",
            error=ScanError(message="path error", category="parse_error"),
            servers=[
                InspectedServer(name="", server=StdioServer(command="x", type="stdio"), error=server_error),
            ],
        )

        spr = build_scan_request([inspected]).scan_path_requests[0]

        assert spr.error is not None and spr.error.message == "path error"
        assert spr.servers[0].name == ""
        assert spr.servers[0].error == server_error
        assert spr.servers[0].error is not server_error

    def test_sanitizes_error_diagnostics_without_mutating_local_errors(self):
        private_path = "/Users/alice/private/diagnostics/error.log"
        secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"

        def local_error(message: str, category: ErrorCategory) -> ScanError:
            return ScanError(
                message=f"{message}: {private_path}",
                exception=f"permission denied for {private_path}; token={secret}",
                traceback=f'File "{private_path}", line 7, in inspect\nValueError: token={secret}',
                server_output=f"failed to open {private_path}; token={secret}",
                category=category,
            )

        path_error = local_error("path failed", "parse_error")
        server_error = local_error("server failed", "server_startup")
        skill_error = local_error("skill failed", "skill_scan_error")
        inspected = InspectedPath(
            client="cursor",
            path="/tmp/project",
            error=path_error,
            servers=[
                InspectedServer(
                    name="server",
                    server=StdioServer(command="server", type="stdio"),
                    error=server_error,
                )
            ],
            skills=[InspectedSkill(name="skill", installation_path="/tmp/project/skill", error=skill_error)],
        )

        request = build_scan_request([inspected])

        request_json = request.model_dump_json()
        assert private_path not in request_json
        assert secret not in request_json
        wire_errors = [
            request.scan_path_requests[0].error,
            request.scan_path_requests[0].servers[0].error,
            request.scan_path_requests[0].skills[0].error,
        ]
        assert all(error is not None and error.traceback is None for error in wire_errors)
        assert wire_errors[0] is not None and wire_errors[0].message.startswith("path failed:")
        assert wire_errors[1] is not None and wire_errors[1].category == "server_startup"
        assert wire_errors[2] is not None and wire_errors[2].category == "skill_scan_error"

        # Local inspect output retains full diagnostics for --print-errors.
        assert path_error.traceback is not None and private_path in path_error.traceback
        assert server_error.exception is not None and secret in str(server_error.exception)
        assert skill_error.server_output is not None and secret in skill_error.server_output

    def test_redacts_stdio_server_config_without_mutating_local_result(self):
        secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        local_server = StdioServer(
            command="server",
            args=["--token", secret, "--mode", "safe"],
            env={"API_TOKEN": secret, "MODE": "development"},
            type="stdio",
        )
        inspected = InspectedPath(
            path="/tmp/project",
            servers=[InspectedServer(name="server", server=local_server)],
        )

        request_server = build_scan_request([inspected]).scan_path_requests[0].servers[0].server

        assert isinstance(request_server, StdioServer)
        assert request_server.command == "server"
        assert request_server.args is not None
        assert secret not in request_server.args
        assert request_server.args[-2:] == ["--mode", "safe"]
        assert request_server.env == {"API_TOKEN": "**REDACTED**", "MODE": "**REDACTED**"}
        assert local_server.args == ["--token", secret, "--mode", "safe"]
        assert local_server.env == {"API_TOKEN": secret, "MODE": "development"}

    def test_redacts_remote_server_config_without_mutating_local_result(self):
        local_server = RemoteServer(
            url="https://example.com/mcp?token=private-token&mode=development",
            headers={"Authorization": "Bearer private-token", "X-Mode": "development"},
            type="http",
        )
        inspected = InspectedPath(
            path="/tmp/project",
            servers=[InspectedServer(name="server", server=local_server)],
        )

        request_server = build_scan_request([inspected]).scan_path_requests[0].servers[0].server

        assert isinstance(request_server, RemoteServer)
        assert request_server.url == ("https://example.com/mcp?token=%2A%2AREDACTED%2A%2A&mode=%2A%2AREDACTED%2A%2A")
        assert request_server.headers == {"Authorization": "**REDACTED**", "X-Mode": "**REDACTED**"}
        assert local_server.url == "https://example.com/mcp?token=private-token&mode=development"
        assert local_server.headers == {"Authorization": "Bearer private-token", "X-Mode": "development"}

    def test_signature_passed_through_for_mcp_server(self):
        signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="server", version="1"),
            )
        )
        server = InspectedServer(
            name="s",
            server=StdioServer(command="x", type="stdio"),
            signature=signature,
        )

        req = build_scan_request([InspectedPath(client=None, path="/tmp/p", servers=[server])])

        converted_signature = req.scan_path_requests[0].servers[0].signature
        assert converted_signature == signature
        assert converted_signature is not signature

    def test_serializes_server_key_not_component(self):
        inspected = InspectedPath(
            client=None,
            path="/tmp/p",
            servers=[InspectedServer(name="s", server=StdioServer(command="x", type="stdio"))],
        )

        req = build_scan_request(
            [inspected], scan_user_info=ScanUserInfo(identifier="u"), scan_metadata={"cli_version": "0.6.0"}
        )
        server_dump = req.model_dump()["scan_path_requests"][0]["servers"][0]

        assert "server" in server_dump
        assert "component" not in server_dump
        assert '"server"' in req.model_dump_json()
        assert req.scan_metadata == {"cli_version": "0.6.0"}

    def test_maps_each_path_independently_preserving_order(self):
        inspected = [
            InspectedPath(
                client="cursor",
                path="/tmp/a",
                servers=[InspectedServer(name="a-srv", server=StdioServer(command="a", type="stdio"))],
            ),
            InspectedPath(
                client="vscode",
                path="/tmp/b",
                skills=[InspectedSkill(name="b-skill", installation_path="/tmp/b/skill")],
            ),
        ]

        req = build_scan_request(inspected)

        # order preserved, and each path's servers/skills stay independent
        assert [p.path for p in req.scan_path_requests] == ["/tmp/a", "/tmp/b"]
        assert [p.client for p in req.scan_path_requests] == ["cursor", "vscode"]
        assert [s.name for s in req.scan_path_requests[0].servers] == ["a-srv"]
        assert req.scan_path_requests[0].skills == []
        assert req.scan_path_requests[1].servers == []
        assert [s.name for s in req.scan_path_requests[1].skills] == ["b-skill"]

    def test_empty_inspected_paths(self):
        req = build_scan_request([])
        assert req.scan_path_requests == []


@pytest.mark.asyncio
async def test_analyze_machine_posts_v2026_inspection_results_and_parses_scan_response():
    config_path = str(Path.home() / "project/.cursor/mcp.json")
    inspected = InspectedPath(
        client="cursor",
        path=config_path,
        servers=[
            InspectedServer(
                name="remote",
                config_path=config_path,
                server=RemoteServer(url="https://example.test/mcp?token=secret", headers={"Authorization": "secret"}),
            )
        ],
        skills=[InspectedSkill(name="review", installation_path="/skills/review")],
    )
    response_json = {
        "scan_path_responses": [
            {
                "client": "cursor",
                "path": "/Users/alice/project/.cursor/mcp.json",
                "server_risks": [
                    {
                        "name": "remote",
                        "risk_indexes": {
                            "private_data": {"score": 750, "evidence": "Reads private data", "affected_tools": [0]}
                        },
                    }
                ],
                "skill_risks": [],
            }
        ]
    }

    with (
        patch("agent_scan.verify_api.aiohttp.ClientSession") as session_cls,
        patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}),
    ):
        session_cls.return_value = _mock_session(response_json)
        result = await analyze_machine(
            inspected_paths=[inspected],
            analysis_url="https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10",
            identifier=None,
        )

    assert result == ScanResponse.model_validate(response_json)
    payload = json.loads(session_cls.return_value.post.call_args.kwargs["data"])
    assert list(payload) == ["scan_path_requests", "scan_user_info", "scan_metadata"]
    path_request = payload["scan_path_requests"][0]
    assert path_request["path"] == "~/project/.cursor/mcp.json"
    assert path_request["servers"][0]["server"]["headers"]["Authorization"] == "**REDACTED**"
    assert path_request["servers"][0]["server"]["url"] == "https://example.test/mcp?token=%2A%2AREDACTED%2A%2A"
    assert path_request["skills"][0]["name"] == "review"


@pytest.mark.asyncio
async def test_analyze_machine_http_failure_returns_one_analysis_error_per_path():
    inspected = [
        InspectedPath(client="cursor", path="/one"),
        InspectedPath(client="claude", path="/two"),
    ]
    request_info = MagicMock()
    request_info.real_url = "https://test.example/api"
    http_error = aiohttp.ClientResponseError(
        request_info=request_info,
        history=(),
        status=503,
        message="Service Unavailable",
    )
    session = _mock_session({})
    post_response = await session.post.return_value.__aenter__()
    post_response.status = 503
    post_response.raise_for_status = MagicMock(side_effect=http_error)

    with (
        patch("agent_scan.verify_api.aiohttp.ClientSession", return_value=session),
        patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}),
    ):
        result = await analyze_machine(
            inspected_paths=inspected,
            analysis_url="https://test.example/api",
            identifier=None,
            max_retries=1,
        )

    assert [(path.client, path.path) for path in result.scan_path_responses] == [
        ("cursor", "/one"),
        ("claude", "/two"),
    ]
    assert all(path.error and path.error.category == "analysis_error" for path in result.scan_path_responses)
    assert all(not path.server_risks and not path.skill_risks for path in result.scan_path_responses)
    assert "Service Unavailable" in result.model_dump_json()


@pytest.mark.asyncio
async def test_analyze_machine_failure_uses_the_same_relative_path_as_the_request():
    inspected_path = InspectedPath(client="cursor", path=str(Path.home() / ".cursor/mcp.json"))
    request_info = MagicMock()
    request_info.real_url = "https://test.example/api"
    http_error = aiohttp.ClientResponseError(
        request_info=request_info,
        history=(),
        status=503,
        message="Service Unavailable",
    )
    session = _mock_session({})
    response = await session.post.return_value.__aenter__()
    response.status = 503
    response.raise_for_status = MagicMock(side_effect=http_error)

    with (
        patch("agent_scan.verify_api.aiohttp.ClientSession", return_value=session),
        patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}),
    ):
        result = await analyze_machine(
            inspected_paths=[inspected_path],
            analysis_url="https://test.example/api",
            identifier=None,
            max_retries=1,
        )

    assert result.scan_path_responses[0].path == "~/.cursor/mcp.json"


@pytest.mark.asyncio
async def test_analyze_machine_preserves_raise_on_retry_exhaustion():
    session = MagicMock()
    post = MagicMock()
    post.__aenter__ = AsyncMock(side_effect=TimeoutError("timed out"))
    post.__aexit__ = AsyncMock(return_value=None)
    session.post = MagicMock(return_value=post)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("agent_scan.verify_api.aiohttp.ClientSession", return_value=session),
        patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}),
    ):
        with pytest.raises(RuntimeError, match="Tried calling verification api 1 times"):
            await analyze_machine(
                inspected_paths=[InspectedPath(path="/config")],
                analysis_url="https://test.example/api",
                identifier=None,
                max_retries=1,
                raise_on_error=True,
            )


@pytest.mark.asyncio
async def test_analyze_machine_preserves_runtime_error_from_upload():
    upload_error = RuntimeError("connection pool closed")
    session = MagicMock()
    post = MagicMock()
    post.__aenter__ = AsyncMock(side_effect=upload_error)
    post.__aexit__ = AsyncMock(return_value=None)
    session.post = MagicMock(return_value=post)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("agent_scan.verify_api.aiohttp.ClientSession", return_value=session),
        patch.dict(os.environ, {"SNYK_TOKEN": "test-token"}),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            await analyze_machine(
                inspected_paths=[InspectedPath(path="/config")],
                analysis_url="https://test.example/api",
                identifier=None,
                max_retries=1,
            )

    assert exc_info.value is upload_error
