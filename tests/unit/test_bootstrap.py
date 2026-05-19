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
from agent_scan.runtime_config import get_runtime_config, set_runtime_config

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
    if "/mcp-scan/push" not in url:
        url = f"{url.rstrip('/')}/mcp-scan/push"
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
async def test_non_canonical_url_skips_bootstrap(caplog):
    async with _BootstrapServer() as server:
        cs = ControlServer(
            url=f"{server.url}/push",
            headers={"x-client-id": str(uuid4())},
            identifier="machine-1",
        )
        with caplog.at_level(logging.WARNING, logger="agent_scan.bootstrap"):
            cfg = await bootstrap_first_control_server([cs], "scan", None, "machine-1", [], False)

    assert cfg.source == "default"
    assert server.requests == []
    assert "does not end in /mcp-scan/push" in caplog.text


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


@pytest.mark.asyncio
async def test_control_server_headers_forwarded_to_bootstrap_request():
    """Custom headers configured on ControlServer (e.g. auth) must be sent on the bootstrap POST."""
    async with _BootstrapServer() as server:
        cs = ControlServer(
            url=f"{server.url}/mcp-scan/push",
            headers={
                "x-client-id": "client-abc",
                "Authorization": "Bearer secret-token",
                "X-Custom-Trace": "trace-42",
            },
            identifier="machine-1",
        )
        await bootstrap_first_control_server([cs], "scan", None, "machine-1", [], False)

    assert len(server.requests) == 1
    sent_headers = server.requests[0]["headers"]
    assert sent_headers["x-client-id"] == "client-abc"
    assert sent_headers["Authorization"] == "Bearer secret-token"
    assert sent_headers["X-Custom-Trace"] == "trace-42"
    # The bootstrap layer must default the content type when the caller has
    # not supplied one, but never overwrite a caller-supplied value.
    assert sent_headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_caller_supplied_content_type_header_is_not_overwritten():
    async with _BootstrapServer() as server:
        cs = ControlServer(
            url=f"{server.url}/mcp-scan/push",
            headers={"x-client-id": "client-abc", "Content-Type": "application/vnd.snyk+json"},
            identifier="machine-1",
        )
        await bootstrap_first_control_server([cs], "scan", None, "machine-1", [], False)

    assert server.requests[0]["headers"]["Content-Type"] == "application/vnd.snyk+json"


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_payload_reaches_singleton():
    """The runtime_config dict from the bootstrap response must reach get_runtime_config().config."""
    scan_event_id = uuid4()
    server_config = {"feature_x": True, "scan_limit": 100, "nested": {"k": "v"}}
    async with _BootstrapServer(
        [(200, {"scan_event_id": str(scan_event_id), "runtime_config": server_config}, 0)]
    ) as server:
        result = await bootstrap_first_control_server(
            [_control_server(server.url)], "scan", None, "machine-1", [], False
        )

    # The helper returns a RuntimeConfig holding the response's runtime_config.
    assert result.scan_event_id == scan_event_id
    assert result.config == server_config

    # And once the caller stores it, get_runtime_config() reflects the same dict.
    set_runtime_config(result)
    assert get_runtime_config().config == server_config
    assert get_runtime_config().scan_event_id == scan_event_id


@pytest.mark.asyncio
async def test_concurrent_bootstrap_calls_do_not_interleave():
    """Two bootstrap calls running concurrently must each return their own coherent
    RuntimeConfig — no field mixing between the two responses — and the singleton
    plumbing must stay atomic per ``set_runtime_config`` call."""
    event_id_a = uuid4()
    event_id_b = uuid4()
    config_a = {"who": "A", "shared_key": "value-from-A"}
    config_b = {"who": "B", "shared_key": "value-from-B"}

    async with (
        _BootstrapServer([(200, {"scan_event_id": str(event_id_a), "runtime_config": config_a}, 0.05)]) as server_a,
        _BootstrapServer([(200, {"scan_event_id": str(event_id_b), "runtime_config": config_b}, 0.05)]) as server_b,
    ):
        cfg_a, cfg_b = await asyncio.gather(
            bootstrap_first_control_server(
                [_control_server(server_a.url)], "scan", None, "machine-a", [], False
            ),
            bootstrap_first_control_server(
                [_control_server(server_b.url)], "scan", None, "machine-b", [], False
            ),
        )

    # Each result must be coherent: scan_event_id and config from the same server,
    # never mixed.
    assert cfg_a.scan_event_id == event_id_a
    assert cfg_a.config == config_a
    assert cfg_b.scan_event_id == event_id_b
    assert cfg_b.config == config_b

    # Atomicity check on the singleton: setting A then reading must yield A whole;
    # then setting B and reading must yield B whole — no field bleed between
    # consecutive writes.
    set_runtime_config(cfg_a)
    snapshot_a = get_runtime_config()
    assert snapshot_a.scan_event_id == event_id_a
    assert snapshot_a.config == config_a

    set_runtime_config(cfg_b)
    snapshot_b = get_runtime_config()
    assert snapshot_b.scan_event_id == event_id_b
    assert snapshot_b.config == config_b

    # The earlier snapshot must still hold its own value — the singleton's deep
    # copy on get prevents the second write from rewriting earlier readers.
    assert snapshot_a.scan_event_id == event_id_a
    assert snapshot_a.config == config_a
