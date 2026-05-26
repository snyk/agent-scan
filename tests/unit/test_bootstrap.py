import asyncio
import json
import logging
import time
from pathlib import Path
from uuid import uuid4

import pytest
from aiohttp import test_utils, web

from agent_scan import bootstrap as bootstrap_module
from agent_scan.bootstrap import bootstrap_first_control_server
from agent_scan.models import ControlServer
from agent_scan.runtime_config import get_runtime_config, set_runtime_config
from agent_scan.utils import parse_headers

REAL_ASYNCIO_SLEEP = asyncio.sleep


class _BootstrapServer:
    def __init__(self, responses: list[tuple[int, object, float]] | None = None) -> None:
        self.responses = responses or [(200, {"bootstrap_event_id": str(uuid4()), "runtime_config": {}}, 0)]
        self.requests: list[dict] = []
        self.runner: web.AppRunner | None = None
        self.url = ""

    async def __aenter__(self):
        app = web.Application()
        app.router.add_post("/{tail:.*}", self._handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        sock = test_utils.get_unused_port_socket("127.0.0.1")
        host, port = sock.getsockname()[:2]
        site = web.SockSite(self.runner, sock)
        await site.start()
        self.url = f"http://{host}:{port}"
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
    cfg = await bootstrap_first_control_server(
        [],
        command="scan",
        subcommand=None,
        control_identifier=None,
        argv=[],
        no_bootstrap=False,
    )

    assert cfg.source == "default"
    assert cfg.bootstrap_event_id is None


@pytest.mark.asyncio
async def test_no_bootstrap_flag_returns_default_without_http():
    async with _BootstrapServer() as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=True,
        )

    assert cfg.source == "default"
    assert server.requests == []


@pytest.mark.asyncio
async def test_single_control_server_posts_to_bootstrap_endpoint():
    bootstrap_event_id = uuid4()
    async with _BootstrapServer(
        [(200, {"bootstrap_event_id": str(bootstrap_event_id), "runtime_config": {}}, 0)]
    ) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert cfg.source == "bootstrap"
    assert cfg.bootstrap_event_id == bootstrap_event_id
    assert len(server.requests) == 1
    assert server.requests[0]["path"] == "/mcp-scan/client-bootstrap"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 201, 202])
async def test_any_2xx_response_is_accepted(status):
    """The control server returns 201 for a freshly-created bootstrap event;
    the client must accept the whole 2xx range so a future server change
    (200 for idempotent retries, 202 for async-ish acceptance) is non-breaking.
    """
    bootstrap_event_id = uuid4()
    async with _BootstrapServer(
        [(status, {"bootstrap_event_id": str(bootstrap_event_id), "runtime_config": {}}, 0)]
    ) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert cfg.source == "bootstrap"
    assert cfg.bootstrap_event_id == bootstrap_event_id
    assert len(server.requests) == 1


@pytest.mark.asyncio
async def test_non_canonical_url_skips_bootstrap(caplog):
    async with _BootstrapServer() as server:
        cs = ControlServer(
            url=f"{server.url}/push",
            headers={"x-client-id": str(uuid4())},
            identifier="machine-1",
        )
        with caplog.at_level(logging.WARNING, logger="agent_scan.bootstrap"):
            cfg = await bootstrap_first_control_server(
                [cs],
                command="scan",
                subcommand=None,
                control_identifier="machine-1",
                argv=[],
                no_bootstrap=False,
            )

    assert cfg.source == "default"
    assert server.requests == []
    assert "does not end in /mcp-scan/push" in caplog.text


@pytest.mark.asyncio
async def test_push_url_is_rewritten_to_sibling_bootstrap_endpoint():
    async with _BootstrapServer() as server:
        await bootstrap_first_control_server(
            [_control_server(f"{server.url}/hidden/mcp-scan/push?version=2025-08-28")],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert server.requests[0]["path"] == "/hidden/mcp-scan/client-bootstrap"
    assert server.requests[0]["query_string"] == "version=2025-08-28"


@pytest.mark.asyncio
async def test_multiple_control_servers_only_posts_to_first_and_warns(caplog):
    bootstrap_event_id = uuid4()
    with caplog.at_level(logging.WARNING, logger="agent_scan.bootstrap"):
        async with (
            _BootstrapServer(
                [(200, {"bootstrap_event_id": str(bootstrap_event_id), "runtime_config": {}}, 0)]
            ) as first,
            _BootstrapServer([(500, {"error": "should not be called"}, 0)]) as second,
        ):
            cfg = await bootstrap_first_control_server(
                [_control_server(first.url), _control_server(second.url)],
                command="scan",
                subcommand=None,
                control_identifier="machine-1",
                argv=[],
                no_bootstrap=False,
            )

    assert cfg.bootstrap_event_id == bootstrap_event_id
    assert len(first.requests) == 1
    assert second.requests == []
    assert "bootstrap sent only to" in caplog.text


@pytest.mark.asyncio
async def test_runtime_config_dict_round_trips():
    bootstrap_event_id = uuid4()
    async with _BootstrapServer(
        [(200, {"bootstrap_event_id": str(bootstrap_event_id), "runtime_config": {"a": 1}}, 0)]
    ) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert cfg.source == "bootstrap"
    assert cfg.config == {"a": 1}


@pytest.mark.asyncio
async def test_500_once_then_200_succeeds(monkeypatch):
    bootstrap_event_id = uuid4()
    monkeypatch.setattr(bootstrap_module.asyncio, "sleep", lambda delay: REAL_ASYNCIO_SLEEP(0))
    async with _BootstrapServer(
        [
            (500, {"error": "temporary"}, 0),
            (200, {"bootstrap_event_id": str(bootstrap_event_id), "runtime_config": {}}, 0),
        ]
    ) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert cfg.bootstrap_event_id == bootstrap_event_id
    assert len(server.requests) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 404])
async def test_definitive_4xx_does_not_retry(status):
    async with _BootstrapServer([(status, {"error": "no"}, 0)]) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert cfg.source == "default"
    assert len(server.requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 500])
async def test_non_2xx_response_body_is_not_logged(monkeypatch, caplog, status):
    """On a non-2xx the server body may carry internal detail (stack snippets,
    query fragments, IDs). We must NOT pull `response.text()` into the client
    logs. The bootstrap log line carries only the HTTP status code; debugging
    the actual failure happens on the server side, keyed by tenant.

    This guards against a regression that re-introduces the body for
    "debuggability" — it's a privacy/leakage contract, not a logging style.
    """
    monkeypatch.setattr(bootstrap_module.asyncio, "sleep", lambda delay: REAL_ASYNCIO_SLEEP(0))
    secret_body = 'DETAIL: relation "push_keys" violates RLS policy SECRET-INTERNAL-XYZ'
    async with _BootstrapServer([(status, secret_body, 0)]) as server:
        with caplog.at_level(logging.WARNING, logger="agent_scan.bootstrap"):
            cfg = await bootstrap_first_control_server(
                [_control_server(server.url)],
                command="scan",
                subcommand=None,
                control_identifier="machine-1",
                argv=[],
                no_bootstrap=False,
            )

    assert cfg.source == "default"
    assert "SECRET-INTERNAL-XYZ" not in caplog.text, f"server response body leaked into client log: {caplog.text!r}"
    assert 'relation "push_keys"' not in caplog.text
    # Status code itself IS allowed in logs — it drives retry logic and isn't
    # a leak channel. Pin its presence so a future overcorrection doesn't
    # strip it too.
    assert f"HTTP {status}" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [408, 429])
async def test_retryable_4xx_retries(monkeypatch, status):
    bootstrap_event_id = uuid4()
    monkeypatch.setattr(bootstrap_module.asyncio, "sleep", lambda delay: REAL_ASYNCIO_SLEEP(0))
    async with _BootstrapServer(
        [
            (status, {"error": "retry"}, 0),
            (200, {"bootstrap_event_id": str(bootstrap_event_id), "runtime_config": {}}, 0),
        ]
    ) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert cfg.bootstrap_event_id == bootstrap_event_id
    assert len(server.requests) == 2


@pytest.mark.asyncio
async def test_timeout_retries_three_times(monkeypatch):
    monkeypatch.setattr(bootstrap_module.asyncio, "sleep", lambda delay: REAL_ASYNCIO_SLEEP(0))
    async with _BootstrapServer([(200, {"bootstrap_event_id": str(uuid4()), "runtime_config": {}}, 0.1)]) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
            timeout_seconds=0.02,
        )

    assert cfg.source == "default"
    assert len(server.requests) == 3


@pytest.mark.asyncio
async def test_malformed_json_returns_default_without_retry():
    async with _BootstrapServer([(200, "not-json", 0)]) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert cfg.source == "default"
    assert len(server.requests) == 1


@pytest.mark.asyncio
async def test_response_missing_bootstrap_event_id_returns_default():
    async with _BootstrapServer([(200, {"runtime_config": {}}, 0)]) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert cfg.source == "default"
    assert len(server.requests) == 1


@pytest.mark.asyncio
async def test_slow_home_enumeration_is_outside_http_timeout(monkeypatch):
    def slow_home_dirs(all_users=False):
        time.sleep(0.05)
        return [(Path("/home/alice"), "alice")]

    monkeypatch.setattr(bootstrap_module, "get_readable_home_directories", slow_home_dirs)
    bootstrap_event_id = uuid4()
    async with _BootstrapServer(
        [(200, {"bootstrap_event_id": str(bootstrap_event_id), "runtime_config": {}}, 0)]
    ) as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
            timeout_seconds=0.5,
        )

    assert cfg.bootstrap_event_id == bootstrap_event_id


@pytest.mark.asyncio
async def test_home_enumeration_failure_returns_default(monkeypatch):
    def fail_home_dirs(all_users=False):
        raise RuntimeError("boom")

    monkeypatch.setattr(bootstrap_module, "get_readable_home_directories", fail_home_dirs)
    async with _BootstrapServer() as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert cfg.source == "default"
    assert server.requests == []


@pytest.mark.asyncio
async def test_home_directory_enumeration_uses_to_thread(monkeypatch):
    called = False

    async def fake_to_thread(func, *args, **kwargs):
        nonlocal called
        called = True
        return func(*args, **kwargs)

    monkeypatch.setattr(bootstrap_module.asyncio, "to_thread", fake_to_thread)
    async with _BootstrapServer() as server:
        cfg = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

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
        await bootstrap_first_control_server(
            [cs],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert len(server.requests) == 1
    sent_headers = server.requests[0]["headers"]
    assert sent_headers["x-client-id"] == "client-abc"
    assert sent_headers["Authorization"] == "Bearer secret-token"
    assert sent_headers["X-Custom-Trace"] == "trace-42"
    # The bootstrap layer must default the content type when the caller has
    # not supplied one, but never overwrite a caller-supplied value.
    assert sent_headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_cli_parsed_headers_reach_bootstrap_post_intact():
    """Headers that flow through `utils.parse_headers` (the real CLI path) must reach the bootstrap POST with their semantic value intact.

    `parse_headers` splits each `name:value` token on the first colon without
    trimming the value half, so the canonical CLI form `--control-server-H
    "Authorization: Bearer x"` produces a dict value with a leading space.
    The sibling test above constructs `ControlServer.headers` directly with
    pre-trimmed values; this regression covers the post-`parse_headers` flow
    end-to-end so a future change anywhere in the chain (parse_headers
    trimming, bootstrap overwriting, aiohttp behavior) can't silently
    corrupt what the CLI actually produces.
    """
    cli_tokens = [
        "x-client-id:client-abc",
        "Authorization: Bearer secret-token",
        "X-Custom-Trace:trace-42",
    ]
    parsed = parse_headers(cli_tokens)
    # Document the exact post-parse shape so a future change to parse_headers
    # (e.g. trimming the value half) is caught here rather than only at the
    # downstream assertions, where the failure mode is less obvious.
    assert parsed == {
        "x-client-id": "client-abc",
        "Authorization": " Bearer secret-token",
        "X-Custom-Trace": "trace-42",
    }

    async with _BootstrapServer() as server:
        cs = ControlServer(
            url=f"{server.url}/mcp-scan/push",
            headers=parsed,
            identifier="machine-1",
        )
        await bootstrap_first_control_server(
            [cs],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    sent = server.requests[0]["headers"]
    assert sent["x-client-id"] == "client-abc"
    assert sent["X-Custom-Trace"] == "trace-42"
    # aiohttp strips leading/trailing whitespace from header values during
    # transport (RFC 7230 §3.2.4: OWS around field-value is not part of the
    # value). The dict carries " Bearer secret-token" but the wire value is
    # "Bearer secret-token" — and that's exactly what the control server
    # parses, so it's the semantically-meaningful value to pin.
    assert sent["Authorization"] == "Bearer secret-token"
    assert sent["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_caller_supplied_content_type_header_is_not_overwritten():
    async with _BootstrapServer() as server:
        cs = ControlServer(
            url=f"{server.url}/mcp-scan/push",
            headers={"x-client-id": "client-abc", "Content-Type": "application/vnd.snyk+json"},
            identifier="machine-1",
        )
        await bootstrap_first_control_server(
            [cs],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert server.requests[0]["headers"]["Content-Type"] == "application/vnd.snyk+json"


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_payload_reaches_singleton():
    """The runtime_config dict from the bootstrap response must reach get_runtime_config().config."""
    bootstrap_event_id = uuid4()
    server_config = {"feature_x": True, "scan_limit": 100, "nested": {"k": "v"}}
    async with _BootstrapServer(
        [(200, {"bootstrap_event_id": str(bootstrap_event_id), "runtime_config": server_config}, 0)]
    ) as server:
        result = await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    # The helper returns a RuntimeConfig holding the response's runtime_config.
    assert result.bootstrap_event_id == bootstrap_event_id
    assert result.config == server_config

    # And once the caller stores it, get_runtime_config() reflects the same dict.
    set_runtime_config(result)
    assert get_runtime_config().config == server_config
    assert get_runtime_config().bootstrap_event_id == bootstrap_event_id


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
        _BootstrapServer(
            [(200, {"bootstrap_event_id": str(event_id_a), "runtime_config": config_a}, 0.05)]
        ) as server_a,
        _BootstrapServer(
            [(200, {"bootstrap_event_id": str(event_id_b), "runtime_config": config_b}, 0.05)]
        ) as server_b,
    ):
        cfg_a, cfg_b = await asyncio.gather(
            bootstrap_first_control_server(
                [_control_server(server_a.url)],
                command="scan",
                subcommand=None,
                control_identifier="machine-a",
                argv=[],
                no_bootstrap=False,
            ),
            bootstrap_first_control_server(
                [_control_server(server_b.url)],
                command="scan",
                subcommand=None,
                control_identifier="machine-b",
                argv=[],
                no_bootstrap=False,
            ),
        )

    # Each result must be coherent: bootstrap_event_id and config from the same server,
    # never mixed.
    assert cfg_a.bootstrap_event_id == event_id_a
    assert cfg_a.config == config_a
    assert cfg_b.bootstrap_event_id == event_id_b
    assert cfg_b.config == config_b

    # Atomicity check on the singleton: setting A then reading must yield A whole;
    # then setting B and reading must yield B whole — no field bleed between
    # consecutive writes.
    set_runtime_config(cfg_a)
    snapshot_a = get_runtime_config()
    assert snapshot_a.bootstrap_event_id == event_id_a
    assert snapshot_a.config == config_a

    set_runtime_config(cfg_b)
    snapshot_b = get_runtime_config()
    assert snapshot_b.bootstrap_event_id == event_id_b
    assert snapshot_b.config == config_b

    # The earlier snapshot must still hold its own value — the singleton's deep
    # copy on get prevents the second write from rewriting earlier readers.
    assert snapshot_a.bootstrap_event_id == event_id_a
    assert snapshot_a.config == config_a


# Outer safety-net tests: anything weird that escapes the inner retry loop
# (OSError from connector setup, AttributeError from a bad lib, an unrelated
# Exception subclass) must be caught and turned into a default RuntimeConfig.
# Without this guard, a scan would crash on startup rather than fall back.
@pytest.mark.asyncio
async def test_outer_guard_catches_oserror_from_connector(monkeypatch, caplog):
    def boom_connector(**_kwargs):
        raise OSError("too many open files")

    monkeypatch.setattr(bootstrap_module, "setup_tcp_connector", boom_connector)

    async with _BootstrapServer() as server:
        with caplog.at_level(logging.WARNING, logger="agent_scan.bootstrap"):
            cfg = await bootstrap_first_control_server(
                [_control_server(server.url)],
                command="scan",
                subcommand=None,
                control_identifier="machine-1",
                argv=[],
                no_bootstrap=False,
            )

    assert cfg.source == "default"
    assert cfg.bootstrap_event_id is None
    assert "crashed" in caplog.text or "failed" in caplog.text


@pytest.mark.asyncio
async def test_outer_guard_catches_unexpected_exception_type(monkeypatch, caplog):
    """An exception class outside the inner handler's (TimeoutError, ClientError,
    ValidationError, ValueError, TypeError) families must NOT propagate."""

    class WeirdLibraryError(Exception):
        pass

    def boom_connector(**_kwargs):
        raise WeirdLibraryError("library invariant violated")

    monkeypatch.setattr(bootstrap_module, "setup_tcp_connector", boom_connector)

    async with _BootstrapServer() as server:
        with caplog.at_level(logging.WARNING, logger="agent_scan.bootstrap"):
            cfg = await bootstrap_first_control_server(
                [_control_server(server.url)],
                command="scan",
                subcommand=None,
                control_identifier="machine-1",
                argv=[],
                no_bootstrap=False,
            )

    assert cfg.source == "default"


@pytest.mark.asyncio
async def test_outer_guard_lets_keyboard_interrupt_propagate(monkeypatch):
    """Ctrl-C during bootstrap must kill the command, not silently fall through.

    The outer guard intentionally re-raises KeyboardInterrupt and SystemExit
    so the user's exit signal still works.
    """

    def interrupt_connector(**_kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(bootstrap_module, "setup_tcp_connector", interrupt_connector)

    async with _BootstrapServer() as server:
        with pytest.raises(KeyboardInterrupt):
            await bootstrap_first_control_server(
                [_control_server(server.url)],
                command="scan",
                subcommand=None,
                control_identifier="machine-1",
                argv=[],
                no_bootstrap=False,
            )


@pytest.mark.asyncio
async def test_outer_guard_lets_system_exit_propagate(monkeypatch):
    """sys.exit() during bootstrap must propagate so explicit exits still work."""

    def exit_connector(**_kwargs):
        raise SystemExit(1)

    monkeypatch.setattr(bootstrap_module, "setup_tcp_connector", exit_connector)

    async with _BootstrapServer() as server:
        with pytest.raises(SystemExit):
            await bootstrap_first_control_server(
                [_control_server(server.url)],
                command="scan",
                subcommand=None,
                control_identifier="machine-1",
                argv=[],
                no_bootstrap=False,
            )


@pytest.mark.asyncio
async def test_outer_guard_lets_cancelled_error_propagate(monkeypatch):
    """asyncio.CancelledError during bootstrap must propagate so structured
    concurrency stays intact.

    Since Python 3.8, asyncio.CancelledError inherits from BaseException
    (not Exception). A bare `except BaseException` would silently swallow
    a sibling-triggered cancellation in a `gather()` and return a default
    RuntimeConfig instead of unwinding — breaking the caller's contract
    that "this task is no longer needed, stop now." Mirrors the
    KeyboardInterrupt/SystemExit propagation tests above.
    """

    def cancel_connector(**_kwargs):
        raise asyncio.CancelledError()

    monkeypatch.setattr(bootstrap_module, "setup_tcp_connector", cancel_connector)

    async with _BootstrapServer() as server:
        with pytest.raises(asyncio.CancelledError):
            await bootstrap_first_control_server(
                [_control_server(server.url)],
                command="scan",
                subcommand=None,
                control_identifier="machine-1",
                argv=[],
                no_bootstrap=False,
            )


@pytest.mark.asyncio
async def test_skip_ssl_verify_is_forwarded_to_tcp_connector(monkeypatch):
    """If the user disables SSL verification on the CLI, bootstrap must use the
    same setting as the eventual push — otherwise on a host with a self-signed
    control-server cert, the upload succeeds (because `--skip-ssl-verify` is
    plumbed through `upload()`) but the bootstrap silently fails its TLS
    handshake, defaulting `RuntimeConfig` and stripping the X-Bootstrap-Event-Id
    correlation from every push for the run.
    """
    captured_kwargs: dict = {}
    real_connector_factory = bootstrap_module.setup_tcp_connector

    def fake_connector(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return real_connector_factory(**kwargs)

    monkeypatch.setattr(bootstrap_module, "setup_tcp_connector", fake_connector)

    async with _BootstrapServer() as server:
        await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
            skip_ssl_verify=True,
        )

    assert captured_kwargs.get("skip_ssl_verify") is True, (
        f"expected skip_ssl_verify=True to reach setup_tcp_connector; got kwargs={captured_kwargs}"
    )


@pytest.mark.asyncio
async def test_skip_ssl_verify_defaults_false_when_unset(monkeypatch):
    """Default path: callers that don't pass skip_ssl_verify must get a verifying connector."""
    captured_kwargs: dict = {}
    real_connector_factory = bootstrap_module.setup_tcp_connector

    def fake_connector(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return real_connector_factory(**kwargs)

    monkeypatch.setattr(bootstrap_module, "setup_tcp_connector", fake_connector)

    async with _BootstrapServer() as server:
        await bootstrap_first_control_server(
            [_control_server(server.url)],
            command="scan",
            subcommand=None,
            control_identifier="machine-1",
            argv=[],
            no_bootstrap=False,
        )

    assert captured_kwargs.get("skip_ssl_verify") is False
