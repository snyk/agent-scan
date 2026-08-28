"""Tests for direct Agent Monitor hook-event delivery."""

from __future__ import annotations

import base64
import json
from unittest.mock import patch

import aiohttp
import pytest

from agent_scan.hook_events import _HOOK_REQUEST_TIMEOUT_SECONDS, send_hook_event
from agent_scan.hook_version import HOOK_VERSION
from agent_scan.version import version_info


class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    """Stand-in for the aiohttp session the shared backend factory builds."""

    def __init__(self, status: int = 200, error: BaseException | None = None) -> None:
        self.status = status
        self.error = error
        self.posts: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def post(self, url, **kwargs):
        self.posts.append({"url": url, **kwargs})
        if self.error is not None:
            raise self.error
        return _FakeResponse(self.status)


def _patch_session(session: _FakeSession):
    """Patch the shared factory, so a test failure here means the TLS posture was bypassed."""
    return patch("agent_scan.hook_events.backend_client_session", return_value=session)


@pytest.mark.parametrize("client", ["claude-code", "cursor", "codex"])
def test_sends_existing_hook_wire_contract(client):
    session = _FakeSession()
    payload = '{"hook_event_name":"hooksConfiguredServerDiscovery"}'

    with (
        patch("agent_scan.hook_events.get_hostname", return_value="host-1"),
        patch("agent_scan.hook_events.get_username", return_value="user-1"),
        _patch_session(session),
    ):
        result = send_hook_event("https://api.snyk.io/", client, "push-key", payload, "machine-1")

    assert result == (True, "")
    assert len(session.posts) == 1
    post = session.posts[0]
    assert post["url"] == f"https://api.snyk.io/hidden/agent-monitor/hooks/{client}?version={HOOK_VERSION}"
    assert post["timeout"] == aiohttp.ClientTimeout(total=_HOOK_REQUEST_TIMEOUT_SECONDS)
    assert base64.b64decode(post["data"].decode().removeprefix("base64:")).decode() == payload
    headers = post["headers"]
    assert headers["Content-Type"] == "text/plain"
    assert headers["X-Client-Id"] == "push-key"
    assert headers["User-Agent"] == f"snyk/agent-scan Agent Scan v{version_info}"
    assert json.loads(headers["X-User"]) == {
        "hostname": "host-1",
        "username": "user-1",
        "identifier": "machine-1",
    }


@pytest.mark.parametrize(
    "base_url, expected_base_url",
    [
        ("localhost", "http://localhost"),
        ("localhost:8000/", "http://localhost:8000"),
        ("127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("localhost:8000/proxy/https://upstream", "http://localhost:8000/proxy/https://upstream"),
    ],
)
def test_send_hook_event_defaults_scheme_less_base_url_to_http(base_url, expected_base_url):
    session = _FakeSession()

    with _patch_session(session):
        result = send_hook_event(base_url, "claude-code", "push-key", "{}", "machine-1")

    assert result == (True, "")
    assert session.posts[0]["url"] == (
        f"{expected_base_url}/hidden/agent-monitor/hooks/claude-code?version={HOOK_VERSION}"
    )


def test_uses_the_shared_backend_session_factory():
    """Hook events must ride the same connector as the analysis path (certifi + extra CAs)."""
    session = _FakeSession()

    with _patch_session(session) as factory:
        send_hook_event("https://api.snyk.io", "claude-code", "push-key", "{}", "machine-1")

    factory.assert_called_once()


def test_rejects_missing_machine_identifier_without_request():
    session = _FakeSession()

    with _patch_session(session) as factory:
        result = send_hook_event("https://api.snyk.io", "claude-code", "push-key", "{}", "  ")

    assert result == (False, "machine ID is required")
    factory.assert_not_called()


def test_rejects_unknown_client_without_request():
    session = _FakeSession()

    with _patch_session(session) as factory:
        result = send_hook_event("https://api.snyk.io", "unknown", "push-key", "{}", "machine-1")

    assert result == (False, "unknown client: unknown")
    factory.assert_not_called()


@pytest.mark.parametrize("status, expected", [(403, "HTTP 403"), (404, "HTTP 404"), (500, "HTTP 500")])
def test_reports_http_failures(status, expected):
    session = _FakeSession(status=status)

    with _patch_session(session):
        result = send_hook_event("https://api.snyk.io", "claude-code", "push-key", "{}", "machine-1")

    assert result == (False, expected)


@pytest.mark.parametrize(
    "error, expected",
    [
        (aiohttp.ClientConnectionError("offline"), "offline"),
        (TimeoutError("timed out"), "timed out"),
    ],
)
def test_reports_transport_failures(error, expected):
    session = _FakeSession(error=error)

    with _patch_session(session):
        ok, detail = send_hook_event("https://api.snyk.io", "claude-code", "push-key", "{}", "machine-1")

    assert ok is False
    assert expected in detail


def test_transport_failures_are_retried_when_requested():
    session = _FakeSession(error=aiohttp.ClientConnectionError("offline"))

    with _patch_session(session), patch("agent_scan.hook_events.asyncio.sleep") as sleep:
        ok, _ = send_hook_event("https://api.snyk.io", "claude-code", "push-key", "{}", "machine-1", max_retries=3)

    assert ok is False
    assert len(session.posts) == 3
    assert sleep.await_count == 2


def test_single_attempt_by_default():
    """SessionStart discovery runs inside a hook budget, so retries are opt-in."""
    session = _FakeSession(error=aiohttp.ClientConnectionError("offline"))

    with _patch_session(session):
        send_hook_event("https://api.snyk.io", "claude-code", "push-key", "{}", "machine-1")

    assert len(session.posts) == 1


def test_http_errors_are_not_retried():
    session = _FakeSession(status=403)

    with _patch_session(session):
        send_hook_event("https://api.snyk.io", "claude-code", "push-key", "{}", "machine-1", max_retries=3)

    assert len(session.posts) == 1
