import asyncio
import json
import logging
import time
from pathlib import Path
from uuid import uuid4

import pytest
from aiohttp import web

from agent_scan import bootstrap as bootstrap_module
from agent_scan.bootstrap import bootstrap_first_control_server
from agent_scan.models import ControlServer

REAL_ASYNCIO_SLEEP = asyncio.sleep


class _BootstrapServer:
    def __init__(self, responses: list[tuple[int, object, float]] | None = None) -> None:
        self.responses = responses or [(200, {"scan_event_id": str(uuid4()), "runtime_config": {}}, 0)]
        self.requests: list[dict] = []
        self.runner: web.AppRunner | None = None
        self.url = ""

    async def __aenter__(self):
        app = web.Application()
        app.router.add_post("/{tail:.*}", self._handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        socket = site._server.sockets[0]
        self.url = f"http://127.0.0.1:{socket.getsockname()[1]}"
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.runner is not None:
            await self.runner.cleanup()

    async def _handle(self, request: web.Request) -> web.Response:
        self.requests.append(
            {
                "path": request.path,
                "query_string": request.query_string,
                "headers": dict(request.headers),
                "body": None,
            }
        )
        raw_body = await request.text()
        self.requests[-1]["body"] = json.loads(raw_body) if raw_body else None
        idx = min(len(self.requests) - 1, len(self.responses) - 1)
        status, body, delay = self.responses[idx]
        if delay:
            await REAL_ASYNCIO_SLEEP(delay)
        if isinstance(body, str):
            return web.Response(status=status, text=body)
        return web.json_response(body, status=status)


def _control_server(url: str) -> ControlServer:
    return ControlServer(url=url, headers={"x-client-id": str(uuid4())}, identifier="machine-1")


@pytest.fixture(autouse=True)
def _mock_home_dirs(monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path("/home/alice"), "alice")],
    )


@pytest.mark.asyncio
async def test_no_control_servers_returns_default():
    cfg = await bootstrap_first_control_server([], "scan", None, None, [], False)

    assert cfg.source == "default"
    assert cfg.scan_event_id is None


@pytest.mark.asyncio
async def test_no_bootstrap_flag_returns_default_without_http():
    async with _BootstrapServer() as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], True)

    assert cfg.source == "default"
    assert server.requests == []


@pytest.mark.asyncio
async def test_single_control_server_posts_to_bootstrap_endpoint():
    scan_event_id = uuid4()
    async with _BootstrapServer([(200, {"scan_event_id": str(scan_event_id), "runtime_config": {}}, 0)]) as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.source == "bootstrap"
    assert cfg.scan_event_id == scan_event_id
    assert len(server.requests) == 1
    assert server.requests[0]["path"] == "/mcp-scan/client-bootstrap"


@pytest.mark.asyncio
async def test_push_url_is_rewritten_to_sibling_bootstrap_endpoint():
    async with _BootstrapServer() as server:
        await bootstrap_first_control_server(
            [_control_server(f"{server.url}/hidden/mcp-scan/push?version=2025-08-28")],
            "scan",
            None,
            "machine-1",
            [],
            False,
        )

    assert server.requests[0]["path"] == "/hidden/mcp-scan/client-bootstrap"
    assert server.requests[0]["query_string"] == "version=2025-08-28"


@pytest.mark.asyncio
async def test_multiple_control_servers_only_posts_to_first_and_warns(caplog):
    scan_event_id = uuid4()
    with caplog.at_level(logging.WARNING, logger="agent_scan.bootstrap"):
        async with (
            _BootstrapServer([(200, {"scan_event_id": str(scan_event_id), "runtime_config": {}}, 0)]) as first,
            _BootstrapServer([(500, {"error": "should not be called"}, 0)]) as second,
        ):
            cfg = await bootstrap_first_control_server(
                [_control_server(first.url), _control_server(second.url)],
                "scan",
                None,
                "machine-1",
                [],
                False,
            )

    assert cfg.scan_event_id == scan_event_id
    assert len(first.requests) == 1
    assert second.requests == []
    assert "bootstrap sent only to" in caplog.text


@pytest.mark.asyncio
async def test_runtime_config_dict_round_trips():
    scan_event_id = uuid4()
    async with _BootstrapServer([(200, {"scan_event_id": str(scan_event_id), "runtime_config": {"a": 1}}, 0)]) as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.source == "bootstrap"
    assert cfg.config == {"a": 1}


@pytest.mark.asyncio
async def test_500_once_then_200_succeeds(monkeypatch):
    scan_event_id = uuid4()
    monkeypatch.setattr(bootstrap_module.asyncio, "sleep", lambda delay: REAL_ASYNCIO_SLEEP(0))
    async with _BootstrapServer(
        [
            (500, {"error": "temporary"}, 0),
            (200, {"scan_event_id": str(scan_event_id), "runtime_config": {}}, 0),
        ]
    ) as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.scan_event_id == scan_event_id
    assert len(server.requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 404])
async def test_definitive_4xx_does_not_retry(status):
    async with _BootstrapServer([(status, {"error": "no"}, 0)]) as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.source == "default"
    assert len(server.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [408, 429])
async def test_retryable_4xx_retries(monkeypatch, status):
    scan_event_id = uuid4()
    monkeypatch.setattr(bootstrap_module.asyncio, "sleep", lambda delay: REAL_ASYNCIO_SLEEP(0))
    async with _BootstrapServer(
        [
            (status, {"error": "retry"}, 0),
            (200, {"scan_event_id": str(scan_event_id), "runtime_config": {}}, 0),
        ]
    ) as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.scan_event_id == scan_event_id
    assert len(server.requests) == 2


@pytest.mark.asyncio
async def test_timeout_retries_three_times(monkeypatch):
    monkeypatch.setattr(bootstrap_module.asyncio, "sleep", lambda delay: REAL_ASYNCIO_SLEEP(0))
    async with _BootstrapServer([(200, {"scan_event_id": str(uuid4()), "runtime_config": {}}, 0.1)]) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)], "scan", None, "machine-1", [], False, timeout_seconds=0.02
        )

    assert cfg.source == "default"
    assert len(server.requests) == 3


@pytest.mark.asyncio
async def test_malformed_json_returns_default_without_retry():
    async with _BootstrapServer([(200, "not-json", 0)]) as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.source == "default"
    assert len(server.requests) == 1


@pytest.mark.asyncio
async def test_response_missing_scan_event_id_returns_default():
    async with _BootstrapServer([(200, {"runtime_config": {}}, 0)]) as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.source == "default"
    assert len(server.requests) == 1


@pytest.mark.asyncio
async def test_slow_home_enumeration_is_outside_http_timeout(monkeypatch):
    def slow_home_dirs(all_users=False):
        time.sleep(0.05)
        return [(Path("/home/alice"), "alice")]

    monkeypatch.setattr(bootstrap_module, "get_readable_home_directories", slow_home_dirs)
    scan_event_id = uuid4()
    async with _BootstrapServer([(200, {"scan_event_id": str(scan_event_id), "runtime_config": {}}, 0)]) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)], "scan", None, "machine-1", [], False, timeout_seconds=0.5
        )

    assert cfg.scan_event_id == scan_event_id


@pytest.mark.asyncio
async def test_home_enumeration_failure_returns_default(monkeypatch):
    def fail_home_dirs(all_users=False):
        raise RuntimeError("boom")

    monkeypatch.setattr(bootstrap_module, "get_readable_home_directories", fail_home_dirs)
    async with _BootstrapServer() as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.source == "default"
    assert server.requests == []


@pytest.mark.asyncio
async def test_home_directories_are_capped_at_1000(monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path(f"/home/user-{i}"), f"user-{i}") for i in range(1500)],
    )
    async with _BootstrapServer() as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.source == "bootstrap"
    paths = server.requests[0]["body"]["paths"]
    assert len(paths["home_directories"]) == 1000
    assert paths["home_directories_truncated"] is True


@pytest.mark.asyncio
async def test_home_directory_enumeration_uses_to_thread(monkeypatch):
    called = False

    async def fake_to_thread(func, *args, **kwargs):
        nonlocal called
        called = True
        return func(*args, **kwargs)

    monkeypatch.setattr(bootstrap_module.asyncio, "to_thread", fake_to_thread)
    async with _BootstrapServer() as server:
        cfg = await bootstrap_first_control_server([_control_server(server.url)], "scan", None, "machine-1", [], False)

    assert cfg.source == "bootstrap"
    assert called is True
