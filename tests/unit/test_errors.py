from unittest.mock import patch

import httpx
import pytest

from agent_scan.inspect import inspect_extension, inspected_client_to_scan_path_result
from agent_scan.models import (
    InspectedClient,
    RemoteServer,
    ScanError,
    ServerHTTPError,
)


def make_http_status_error(status_code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://example.com/mcp")
    response = httpx.Response(status_code, request=request)
    return httpx.HTTPStatusError(
        message=f"{status_code} Error",
        request=request,
        response=response,
    )


class TestServerHTTPErrorStatusCode:
    def test_status_code_field_exists(self):
        err = ServerHTTPError(message="server returned HTTP status code", category="server_http_error", status_code=401)
        assert err.status_code == 401

    def test_status_code_defaults_to_none(self):
        err = ServerHTTPError(message="server returned HTTP status code", category="server_http_error")
        assert err.status_code is None

    def test_status_code_serializes(self):
        err = ServerHTTPError(message="server returned HTTP status code", category="server_http_error", status_code=404)
        data = err.model_dump()
        assert data["status_code"] == 404


class TestScanErrorStatusCode:
    def test_status_code_field_exists(self):
        err = ScanError(message="oops", status_code=403)
        assert err.status_code == 403

    def test_status_code_defaults_to_none(self):
        err = ScanError(message="oops")
        assert err.status_code is None

    def test_clone_preserves_status_code(self):
        err = ScanError(message="oops", status_code=503)
        cloned = err.clone()
        assert cloned.status_code == 503

    def test_clone_preserves_none_status_code(self):
        err = ScanError(message="oops")
        cloned = err.clone()
        assert cloned.status_code is None

    def test_status_code_serializes_in_json(self):
        err = ScanError(message="oops", status_code=401)
        data = err.model_dump()
        assert data["status_code"] == 401


class TestInspectExtensionHTTPStatusCode:
    @pytest.mark.asyncio
    async def test_401_is_captured_as_status_code(self):
        config = RemoteServer(url="https://example.com/mcp")
        with patch("agent_scan.inspect.check_server", side_effect=make_http_status_error(401)):
            result = await inspect_extension("my-server", config, timeout=5)

        assert isinstance(result.signature_or_error, ServerHTTPError)
        assert result.signature_or_error.status_code == 401

    @pytest.mark.asyncio
    async def test_404_is_captured_as_status_code(self):
        config = RemoteServer(url="https://example.com/mcp")
        with patch("agent_scan.inspect.check_server", side_effect=make_http_status_error(404)):
            result = await inspect_extension("my-server", config, timeout=5)

        assert isinstance(result.signature_or_error, ServerHTTPError)
        assert result.signature_or_error.status_code == 404

    @pytest.mark.asyncio
    async def test_status_code_propagates_to_scan_error(self):
        config = RemoteServer(url="https://example.com/mcp")
        with patch("agent_scan.inspect.check_server", side_effect=make_http_status_error(401)):
            inspected = await inspect_extension("my-server", config, timeout=5)

        client = InspectedClient(
            name="test",
            client_path="/test",
            extensions={"/test/mcp.json": [inspected]},
        )
        result = inspected_client_to_scan_path_result(client)

        assert result.servers is not None
        assert len(result.servers) == 1
        error = result.servers[0].error
        assert error is not None
        assert error.status_code == 401
        assert error.category == "server_http_error"
