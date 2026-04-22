"""Tests for agent_scan.pushkeys HTTP helpers."""

import http.client
from io import BytesIO
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

import pytest

from agent_scan.hook_version import HOOK_VERSION
from agent_scan.pushkeys import (
    GuardEnabledAccessDeniedError,
    _build_guard_enabled_url,
    fetch_guard_enabled,
)


def _http_error(url: str, code: int, body: bytes = b"") -> HTTPError:
    return HTTPError(url, code, "msg", http.client.HTTPMessage(), BytesIO(body))


class TestFetchGuardEnabled:
    def test_returns_true_when_api_enables(self):
        payload = b'{"tenant_id": "tid", "enabled": true}'
        mock_resp = MagicMock()
        mock_resp.read.return_value = payload
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_resp
        mock_cm.__exit__.return_value = None

        with patch("agent_scan.pushkeys.urlopen", return_value=mock_cm) as mock_urlopen:
            assert fetch_guard_enabled("https://api.snyk.io", "tid", "tok") is True

        request_obj = mock_urlopen.call_args[0][0]
        assert request_obj.get_full_url() == _build_guard_enabled_url("https://api.snyk.io", "tid")
        assert request_obj.get_header("Authorization") == "token tok"

    def test_returns_false_when_api_disables(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"tenant_id": "tid", "enabled": false}'
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_resp
        mock_cm.__exit__.return_value = None

        with patch("agent_scan.pushkeys.urlopen", return_value=mock_cm):
            assert fetch_guard_enabled("https://api.snyk.io", "tid", "tok") is False

    def test_skips_auth_on_localhost(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"tenant_id": "x", "enabled": true}'
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_resp
        mock_cm.__exit__.return_value = None

        with patch("agent_scan.pushkeys.urlopen", return_value=mock_cm) as mock_urlopen:
            fetch_guard_enabled("http://127.0.0.1:9", "tid", "")

        request_obj = mock_urlopen.call_args[0][0]
        assert request_obj.get_header("Authorization") is None

    def test_raises_on_bad_json_shape(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"tenant_id": "tid"}'
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_resp
        mock_cm.__exit__.return_value = None

        with patch("agent_scan.pushkeys.urlopen", return_value=mock_cm):
            with pytest.raises(RuntimeError, match="Unexpected guard-enabled"):
                fetch_guard_enabled("https://api.snyk.io", "tid", "tok")

    def test_raises_access_denied_on_403(self):
        url = _build_guard_enabled_url("https://api.snyk.io", "tid")

        def boom(*args, **kwargs):
            raise _http_error(url, 403, b'{"detail":"Forbidden"}')

        with patch("agent_scan.pushkeys.urlopen", side_effect=boom):
            with pytest.raises(GuardEnabledAccessDeniedError) as exc_info:
                fetch_guard_enabled("https://api.snyk.io", "tid", "tok")
        assert '{"detail"' in str(exc_info.value)

    def test_non_403_http_error_message_omits_response_body(self):
        url = _build_guard_enabled_url("https://api.snyk.io", "tid")
        secret_body = b'{"internal":"do-not-leak","stack":"..."}'

        def boom(*args, **kwargs):
            raise _http_error(url, 500, secret_body)

        with patch("agent_scan.pushkeys.urlopen", side_effect=boom):
            with pytest.raises(RuntimeError, match="HTTP 500") as exc_info:
                fetch_guard_enabled("https://api.snyk.io", "tid", "tok")
        err = str(exc_info.value)
        assert "internal" not in err
        assert "do-not-leak" not in err


class TestMintPushKeyUrl:
    """Smoke test for shared URL normalization (guard-enabled matches push-key style)."""

    def test_builds_hidden_tenants_path(self):
        assert _build_guard_enabled_url("https://api.snyk.io", "tid-1") == (
            f"https://api.snyk.io/hidden/tenants/tid-1/agent-monitor/guard-enabled"
            f"?version={HOOK_VERSION}"
        )
