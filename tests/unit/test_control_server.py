import json
from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from agent_scan.models import (
    ScanError,
    ScanPathResult,
    ServerScanResult,
    StdioServer,
)
from agent_scan.upload import (
    upload,
)


@pytest.mark.asyncio
async def test_upload_payload_excludes_hostname_and_username():
    """
    Test that the upload payload does include hostname or username in scan_user_info.
    """
    mock_result = ScanPathResult(path="/test/path")

    mock_http_response = AsyncMock(status=200)
    mock_http_response.json.return_value = []
    mock_http_response.text.return_value = ""

    mock_post_context_manager = AsyncMock()
    mock_post_context_manager.__aenter__.return_value = mock_http_response

    with (
        patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method,
    ):
        mock_post_method.return_value = mock_post_context_manager

        await upload([mock_result], "https://control.mcp.scan", "email")

        mock_post_method.assert_called_once()
        sent_kwargs = mock_post_method.call_args.kwargs
        payload = json.loads(sent_kwargs["data"])

        user_info = payload["scan_user_info"]
        assert user_info["hostname"] is not None
        assert user_info["username"] is not None


@pytest.mark.asyncio
async def test_upload_includes_scan_error_in_payload():
    """
    Ensure that when a ScanPathResult has an error, it is serialized
    and included in the payload sent by upload().
    """

    # Prepare a ScanPathResult with at least one server (so it isn't skipped) and an error
    server = ServerScanResult(name="server1", server=StdioServer(command="echo"))
    scan_error_message = "something went wrong"
    exception_message = "could not start server"
    traceback = "traceback"
    path_result_with_error = ScanPathResult(
        path="/test/path",
        servers=[server],
        error=ScanError(
            message=scan_error_message,
            exception=Exception(exception_message),
            traceback=traceback,
            is_failure=True,
            category="server_startup",
        ),
    )
    # Mock HTTP response
    mock_http_response = AsyncMock(status=200)
    mock_http_response.json.return_value = []
    mock_http_response.text.return_value = ""

    # Async context manager for session.post
    mock_post_context_manager = AsyncMock()
    mock_post_context_manager.__aenter__.return_value = mock_http_response

    # Patch aiohttp ClientSession.post
    with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
        mock_post_method.return_value = mock_post_context_manager

        # Execute upload
        await upload([path_result_with_error], "https://control.mcp.scan", "email", False)

        # Capture payload
        assert mock_post_method.call_args is not None, "upload did not call ClientSession.post"
        sent_kwargs = mock_post_method.call_args.kwargs
        assert "data" in sent_kwargs, "upload did not send JSON payload in 'data'"

        payload = json.loads(sent_kwargs["data"])
        # Validate structure and error propagation
        assert "scan_path_results" in payload and isinstance(payload["scan_path_results"], list)
        assert len(payload["scan_path_results"]) == 1
        sent_result = payload["scan_path_results"][0]

        # Error must be present and correctly serialized
        assert "error" in sent_result and sent_result["error"] is not None
        assert scan_error_message in sent_result["error"].get("message")
        assert exception_message in sent_result["error"].get("exception")
        assert sent_result["error"]["is_failure"] is True
        assert sent_result["error"]["traceback"] == traceback


@pytest.mark.asyncio
async def test_upload_file_not_found_error_in_payload():
    """
    Ensure a ScanPathResult with a file-not-found error is correctly serialized and uploaded.
    """
    result = ScanPathResult(
        path="/nonexistent/path",
        servers=None,
        error=ScanError(
            message="file /nonexistent/path does not exist",
            exception=FileNotFoundError("missing"),
            is_failure=False,
            category="file_not_found",
        ),
    )

    mock_http_response = AsyncMock(status=200)
    mock_http_response.json.return_value = []
    mock_http_response.text.return_value = ""

    mock_post_context_manager = AsyncMock()
    mock_post_context_manager.__aenter__.return_value = mock_http_response

    with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
        mock_post_method.return_value = mock_post_context_manager

        await upload([result], "https://control.mcp.scan", None, False)

        payload = json.loads(mock_post_method.call_args.kwargs["data"])
        sent_result = payload["scan_path_results"][0]
        assert sent_result["servers"] is None
        assert sent_result["path"] == "/nonexistent/path"
        assert sent_result["error"]["message"] == "file /nonexistent/path does not exist"
        assert sent_result["error"]["is_failure"] is False
        assert "missing" in (sent_result["error"].get("exception") or "")


@pytest.mark.asyncio
async def test_upload_parse_error_in_payload():
    """
    Ensure a ScanPathResult with a parse error is correctly serialized and uploaded.
    """
    result = ScanPathResult(
        path="/bad/config",
        servers=None,
        error=ScanError(
            message="could not parse file /bad/config",
            exception=Exception("parse failure"),
            is_failure=True,
            category="parse_error",
        ),
    )

    mock_http_response = AsyncMock(status=200)
    mock_http_response.json.return_value = []
    mock_http_response.text.return_value = ""

    mock_post_context_manager = AsyncMock()
    mock_post_context_manager.__aenter__.return_value = mock_http_response

    with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
        mock_post_method.return_value = mock_post_context_manager

        await upload([result], "https://control.mcp.scan", None, False)

        payload = json.loads(mock_post_method.call_args.kwargs["data"])
        sent_result = payload["scan_path_results"][0]
        assert sent_result["servers"] is None
        assert sent_result["path"] == "/bad/config"
        assert sent_result["error"]["message"] == "could not parse file /bad/config"
        assert sent_result["error"]["is_failure"] is True
        assert "parse failure" in (sent_result["error"].get("exception") or "")


@pytest.mark.asyncio
async def test_upload_server_http_error_in_payload():
    """
    Ensure a server-level HTTP status error is correctly serialized and uploaded.
    """
    result = ScanPathResult(
        path="/ok/path",
        servers=[
            ServerScanResult(
                name="srv",
                server=StdioServer(command="echo"),
                error=ScanError(
                    message="server returned HTTP status code",
                    is_failure=True,
                    category="server_http_error",
                ),
            )
        ],
    )

    mock_http_response = AsyncMock(status=200)
    mock_http_response.json.return_value = []
    mock_http_response.text.return_value = ""

    mock_post_context_manager = AsyncMock()
    mock_post_context_manager.__aenter__.return_value = mock_http_response

    with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
        mock_post_method.return_value = mock_post_context_manager

        await upload([result], "https://control.mcp.scan", None, False)

        payload = json.loads(mock_post_method.call_args.kwargs["data"])
        assert payload["scan_path_results"][0]["servers"] is not None
        sent_result = payload["scan_path_results"][0]
        assert sent_result["servers"][0]["error"]["message"] == "server returned HTTP status code"
        assert sent_result["servers"][0]["error"]["is_failure"] is True


@pytest.mark.asyncio
async def test_upload_server_startup_error_in_payload():
    """
    Ensure a server-level startup error is correctly serialized and uploaded.
    """
    result = ScanPathResult(
        path="/ok/path",
        servers=[
            ServerScanResult(
                name="srv",
                server=StdioServer(command="echo"),
                error=ScanError(
                    message="could not start server",
                    is_failure=True,
                    category="server_startup",
                ),
            )
        ],
    )

    mock_http_response = AsyncMock(status=200)
    mock_http_response.json.return_value = []
    mock_http_response.text.return_value = ""

    mock_post_context_manager = AsyncMock()
    mock_post_context_manager.__aenter__.return_value = mock_http_response

    with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
        mock_post_method.return_value = mock_post_context_manager

        await upload([result], "https://control.mcp.scan", None, False)

        payload = json.loads(mock_post_method.call_args.kwargs["data"])
        assert payload["scan_path_results"][0]["servers"] is not None
        sent_result = payload["scan_path_results"][0]
        assert sent_result["servers"][0]["error"]["message"] == "could not start server"
        assert sent_result["servers"][0]["error"]["is_failure"] is True


@pytest.mark.asyncio
async def test_upload_retries_on_network_error():
    """
    Test that upload retries up to 3 times on network errors.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("agent_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_sleep.return_value = None  # Speed up tests by not actually sleeping

        # Mock HTTP response to always fail with network error
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.side_effect = aiohttp.ClientError("Connection refused")

        with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted 3 times
            assert mock_post_method.call_count == 3

            # Verify that sleep was called between retries (2 times for 3 attempts)
            assert mock_sleep.call_count == 2
            # Verify exponential backoff: 1s, 2s
            mock_sleep.assert_any_call(1)
            mock_sleep.assert_any_call(2)


@pytest.mark.asyncio
async def test_upload_retries_on_server_error():
    """
    Test that upload retries on 5xx server errors but not on 4xx client errors.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("agent_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_sleep.return_value = None

        # Mock HTTP response with 503 Service Unavailable
        mock_http_response = AsyncMock(status=503)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = "Service Unavailable"

        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted 3 times
            assert mock_post_method.call_count == 3

            # Verify that sleep was called between retries
            assert mock_sleep.call_count == 2


@pytest.mark.asyncio
async def test_upload_does_not_retry_on_client_error():
    """
    Test that upload does NOT retry on 4xx client errors (like 400, 404).
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("agent_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_sleep.return_value = None

        # Mock HTTP response with 400 Bad Request
        mock_http_response = AsyncMock(status=400)
        mock_http_response.json.return_value = []
        mock_http_response.text.return_value = "Bad Request"

        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.return_value = mock_http_response

        with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted only once (no retries on 4xx)
            assert mock_post_method.call_count == 1

            # Verify that sleep was NOT called
            mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_upload_succeeds_on_second_attempt():
    """
    Test that upload succeeds if it fails first but succeeds on retry.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("agent_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_sleep.return_value = None

        # First attempt fails, second succeeds
        mock_error_context = AsyncMock()
        mock_error_context.__aenter__.side_effect = aiohttp.ClientError("Connection refused")

        mock_success_response = AsyncMock(status=200)
        mock_success_response.json.return_value = []
        mock_success_context = AsyncMock()
        mock_success_context.__aenter__.return_value = mock_success_response

        with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            # First call fails, second succeeds
            mock_post_method.side_effect = [mock_error_context, mock_success_context]

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted twice (failed once, succeeded on retry)
            assert mock_post_method.call_count == 2

            # Verify that sleep was called once
            assert mock_sleep.call_count == 1
            mock_sleep.assert_called_once_with(1)  # First backoff is 1 second


@pytest.mark.asyncio
async def test_upload_custom_max_retries():
    """
    Test that upload respects custom max_retries parameter.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("agent_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_sleep.return_value = None

        # Mock to always fail
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.side_effect = aiohttp.ClientError("Connection refused")

        with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload with custom max_retries=5
            await upload([mock_result], "https://control.mcp.scan", "email", False, max_retries=5)

            # Verify that post was attempted 5 times
            assert mock_post_method.call_count == 5

            # Verify that sleep was called 4 times (between 5 attempts)
            assert mock_sleep.call_count == 4


@pytest.mark.asyncio
async def test_upload_exponential_backoff():
    """
    Test that upload uses exponential backoff between retries.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("agent_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_sleep.return_value = None

        # Mock to always fail
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.side_effect = aiohttp.ClientError("Connection refused")

        with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload
            await upload([mock_result], "https://control.mcp.scan", "email", False, max_retries=3)

            # Verify exponential backoff: 2^0=1, 2^1=2
            assert mock_sleep.call_count == 2
            sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
            assert sleep_calls == [1, 2]  # Exponential: 1s, 2s


@pytest.mark.asyncio
async def test_upload_does_not_retry_on_unexpected_error():
    """
    Test that upload does NOT retry on unexpected (non-network) errors and re-raises them.
    """
    mock_result = ScanPathResult(path="/test/path")

    with (
        patch("agent_scan.upload.asyncio.sleep") as mock_sleep,
    ):
        mock_sleep.return_value = None

        # Mock to raise unexpected error
        mock_post_context_manager = AsyncMock()
        mock_post_context_manager.__aenter__.side_effect = ValueError("Unexpected error")

        with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
            mock_post_method.return_value = mock_post_context_manager

            # Execute upload and expect ValueError to be raised
            with pytest.raises(ValueError, match="Unexpected error"):
                await upload([mock_result], "https://control.mcp.scan", "email", False)

            # Verify that post was attempted only once (no retry on unexpected errors)
            assert mock_post_method.call_count == 1

            # Verify that sleep was NOT called
            mock_sleep.assert_not_called()


@pytest.mark.asyncio
async def test_upload_unknown_mcp_config_error_in_payload():
    """
    Ensure a ScanPathResult with an unknown MCP config error is correctly serialized and uploaded
    with empty servers list.
    """
    result = ScanPathResult(
        path="/unknown.cfg",
        servers=[],
        error=ScanError(
            message="Unknown MCP config: /unknown.cfg",
            is_failure=False,
            category="unknown_config",
        ),
    )

    mock_http_response = AsyncMock(status=200)
    mock_http_response.json.return_value = []
    mock_http_response.text.return_value = ""

    mock_post_context_manager = AsyncMock()
    mock_post_context_manager.__aenter__.return_value = mock_http_response

    with patch("agent_scan.upload.aiohttp.ClientSession.post") as mock_post_method:
        mock_post_method.return_value = mock_post_context_manager

        await upload([result], "https://control.mcp.scan", None, False)

        payload = json.loads(mock_post_method.call_args.kwargs["data"])
        sent_result = payload["scan_path_results"][0]
        assert sent_result["servers"] == []
        assert sent_result["path"] == "/unknown.cfg"
        assert sent_result["error"]["message"] == "Unknown MCP config: /unknown.cfg"
        assert sent_result["error"]["is_failure"] is False
