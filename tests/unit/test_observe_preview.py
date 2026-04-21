"""Tests for observe-preview evaluation used by Agent Guard install."""

from unittest.mock import patch

import pytest

from agent_scan.observe_preview import is_observe_preview_enabled


def test_local_env_skips_flipt(monkeypatch):
    monkeypatch.setenv("AGENT_SCAN_ENVIRONMENT", "local")
    assert is_observe_preview_enabled("550e8400-e29b-41d4-a716-446655440000") is True


def test_empty_tenant_false():
    assert is_observe_preview_enabled("") is False


@pytest.mark.parametrize("enabled", [True, False])
def test_production_reads_flipt_body(monkeypatch, enabled):
    monkeypatch.delenv("MCP_SCAN_ENVIRONMENT", raising=False)
    monkeypatch.setenv("AGENT_SCAN_ENVIRONMENT", "production")

    class Resp:
        status = 200

        def read(self):
            import json

            return json.dumps({"enabled": enabled}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        return Resp()

    with patch("agent_scan.observe_preview.urllib.request.urlopen", fake_urlopen):
        assert is_observe_preview_enabled("550e8400-e29b-41d4-a716-446655440000") is enabled
