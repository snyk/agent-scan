"""Tests for direct Agent Monitor hook-event delivery."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from agent_scan.hook_events import _HOOK_REQUEST_TIMEOUT_SECONDS, send_hook_event
from agent_scan.hook_version import HOOK_VERSION


@pytest.mark.parametrize("client", ["claude-code", "cursor", "codex"])
def test_sends_existing_hook_wire_contract(client):
    response = MagicMock()
    response.__enter__.return_value = SimpleNamespace(status=200)
    payload = '{"hook_event_name":"serversDiscovered"}'

    with (
        patch("agent_scan.hook_events.get_hostname", return_value="host-1"),
        patch("agent_scan.hook_events.get_username", return_value="user-1"),
        patch("agent_scan.hook_events.urlopen", return_value=response) as urlopen,
    ):
        result = send_hook_event("https://api.snyk.io/", client, "push-key", payload, "machine-1")

    assert result == (True, "")
    request = urlopen.call_args.args[0]
    assert request.full_url == f"https://api.snyk.io/hidden/agent-monitor/hooks/{client}?version={HOOK_VERSION}"
    assert urlopen.call_args.kwargs["timeout"] == _HOOK_REQUEST_TIMEOUT_SECONDS
    assert base64.b64decode(request.data.decode().removeprefix("base64:")).decode() == payload
    assert request.get_header("Content-type") == "text/plain"
    assert request.get_header("X-client-id") == "push-key"
    assert "Agent Scan v" in request.get_header("User-agent")
    assert json.loads(request.get_header("X-user")) == {
        "hostname": "host-1",
        "username": "user-1",
        "identifier": "machine-1",
    }


def test_rejects_missing_machine_identifier_without_request():
    with patch("agent_scan.hook_events.urlopen") as urlopen:
        result = send_hook_event("https://api.snyk.io", "claude-code", "push-key", "{}", "  ")

    assert result == (False, "machine ID is required")
    urlopen.assert_not_called()


@pytest.mark.parametrize(
    "error, expected",
    [
        (HTTPError("https://api.snyk.io", 403, "Forbidden", None, None), "HTTP 403"),
        (URLError("offline"), "offline"),
        (TimeoutError("timed out"), "timed out"),
    ],
)
def test_reports_http_and_network_failures(error, expected):
    with patch("agent_scan.hook_events.urlopen", side_effect=error):
        ok, detail = send_hook_event("https://api.snyk.io", "claude-code", "push-key", "{}", "machine-1")

    assert ok is False
    assert expected in detail


def test_rejects_unknown_client_without_request():
    with patch("agent_scan.hook_events.urlopen") as urlopen:
        result = send_hook_event("https://api.snyk.io", "unknown", "push-key", "{}", "machine-1")

    assert result == (False, "unknown client: unknown")
    urlopen.assert_not_called()
