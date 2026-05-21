"""Tests for the `cli.bootstrap_runtime_config` wrapper.

The wrapper itself does not short-circuit -- it always calls
`bootstrap_first_control_server` and the helper short-circuits when
`no_bootstrap=True`. These tests pin the wrapper's pass-through contract
(args.no_bootstrap -> helper kwarg) and the end-to-end effect (no HTTP,
runtime config left at defaults) so neither layer can drift independently.
"""

from argparse import Namespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from aiohttp import test_utils, web

from agent_scan import cli
from agent_scan.models import ControlServer
from agent_scan.runtime_config import RuntimeConfig, get_runtime_config


def _control_server(url: str) -> ControlServer:
    if "/mcp-scan/push" not in url:
        url = f"{url.rstrip('/')}/mcp-scan/push"
    return ControlServer(url=url, headers={"x-client-id": str(uuid4())}, identifier="machine-1")


class _CountingServer:
    """Records every POST it receives so a test can assert zero hits."""

    def __init__(self) -> None:
        self.requests: list[str] = []
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
        self.requests.append(request.path)
        return web.json_response({"bootstrap_event_id": str(uuid4()), "runtime_config": {}})


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_passes_no_bootstrap_true_to_helper():
    """Wrapper forwards `args.no_bootstrap=True` to `bootstrap_first_control_server`.

    Mocks the helper to inspect the kwargs. This is the pure pass-through
    contract; the helper's short-circuit behavior is tested separately in
    test_bootstrap.py::test_no_bootstrap_flag_returns_default_without_http.
    """
    fake_helper = AsyncMock(return_value=RuntimeConfig())
    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=True,
    )

    with patch("agent_scan.cli.bootstrap_first_control_server", fake_helper):
        await cli.bootstrap_runtime_config(args, command="scan")

    assert fake_helper.call_count == 1
    assert fake_helper.call_args.kwargs["no_bootstrap"] is True


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_passes_no_bootstrap_false_when_flag_unset():
    """When `args.no_bootstrap` is False, the wrapper forwards False (not True)."""
    fake_helper = AsyncMock(return_value=RuntimeConfig())
    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=False,
    )

    with patch("agent_scan.cli.bootstrap_first_control_server", fake_helper):
        await cli.bootstrap_runtime_config(args, command="scan")

    assert fake_helper.call_args.kwargs["no_bootstrap"] is False


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_defaults_no_bootstrap_to_false_when_attr_missing():
    """`getattr(args, 'no_bootstrap', False)` defends against subparsers that did not register the flag.

    `scan` and `inspect` register the flag via `add_bootstrap_argument`, but
    a future subcommand could forget. The wrapper must not crash; it must
    default to running bootstrap, matching the documented opt-out semantics.
    """
    fake_helper = AsyncMock(return_value=RuntimeConfig())
    args = Namespace(control_servers=[_control_server("http://example/mcp-scan/push")])
    # Deliberately no `no_bootstrap` attribute on args.

    with patch("agent_scan.cli.bootstrap_first_control_server", fake_helper):
        await cli.bootstrap_runtime_config(args, command="scan")

    assert fake_helper.call_args.kwargs["no_bootstrap"] is False


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_with_no_bootstrap_makes_zero_http_calls():
    """End-to-end: `no_bootstrap=True` reaches the helper and no HTTP fires.

    Verifies the wrapper + helper combination delivers the user-visible
    effect of `--no-bootstrap`, not just that a kwarg was passed.
    """
    async with _CountingServer() as server:
        args = Namespace(
            control_servers=[_control_server(server.url)],
            no_bootstrap=True,
        )

        await cli.bootstrap_runtime_config(args, command="scan")

        assert server.requests == []
        # Runtime config is left at defaults when bootstrap is skipped.
        cfg = get_runtime_config()
        assert cfg.source == "default"
        assert cfg.bootstrap_event_id is None


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_forwards_scan_all_users():
    """args.scan_all_users must reach bootstrap_first_control_server unchanged.

    The bootstrap payload's home-directory enumeration mirrors the scan: when
    --scan-all-users is set, both touch every readable home; otherwise both
    stay limited to the current user. The wrapper is the only place that maps
    args -> helper kwarg, so a regression here would silently widen what gets
    sent to the control server.
    """
    fake_helper = AsyncMock(return_value=RuntimeConfig())
    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=False,
        scan_all_users=True,
    )

    with patch("agent_scan.cli.bootstrap_first_control_server", fake_helper):
        await cli.bootstrap_runtime_config(args, command="scan")

    assert fake_helper.call_args.kwargs["scan_all_users"] is True


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_defaults_scan_all_users_to_false_when_attr_missing():
    """Subparsers that omit --scan-all-users (e.g. guard) must not crash the wrapper.

    Default is False so the bootstrap payload stays narrow when the flag was
    never registered on the parser.
    """
    fake_helper = AsyncMock(return_value=RuntimeConfig())
    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=False,
    )
    # Deliberately no `scan_all_users` attribute on args.

    with patch("agent_scan.cli.bootstrap_first_control_server", fake_helper):
        await cli.bootstrap_runtime_config(args, command="scan")

    assert fake_helper.call_args.kwargs["scan_all_users"] is False


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_stores_helper_result_in_runtime_config():
    """The wrapper must call `set_runtime_config` with whatever the helper returns.

    Without this, the bootstrap response would be discarded and uploads
    would never carry the `X-Bootstrap-Event-Id` correlation header.
    """
    expected_event_id = uuid4()
    fake_helper = AsyncMock(
        return_value=RuntimeConfig(bootstrap_event_id=expected_event_id, source="bootstrap"),
    )
    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=False,
    )

    with patch("agent_scan.cli.bootstrap_first_control_server", fake_helper):
        await cli.bootstrap_runtime_config(args, command="scan")

    cfg = get_runtime_config()
    assert cfg.bootstrap_event_id == expected_event_id
    assert cfg.source == "bootstrap"


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_outer_guard_catches_unexpected_exception():
    """If the helper itself raises (defeating its own inner guard via some
    future regression), the wrapper must still leave the runtime config at
    defaults rather than aborting the scan."""

    async def boom(*args, **kwargs):
        raise RuntimeError("inner guard was bypassed somehow")

    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=False,
    )

    with patch("agent_scan.cli.bootstrap_first_control_server", side_effect=boom):
        # Must not raise — the wrapper catches BaseException-minus-(KI, SE).
        await cli.bootstrap_runtime_config(args, command="scan")

    cfg = get_runtime_config()
    assert cfg.source == "default"
    assert cfg.bootstrap_event_id is None


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_lets_keyboard_interrupt_propagate():
    """Ctrl-C during the helper must still kill the command."""

    async def interrupt(*args, **kwargs):
        raise KeyboardInterrupt()

    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=False,
    )

    with patch("agent_scan.cli.bootstrap_first_control_server", side_effect=interrupt):
        with pytest.raises(KeyboardInterrupt):
            await cli.bootstrap_runtime_config(args, command="scan")


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_lets_cancelled_error_propagate():
    """asyncio.CancelledError raised inside the helper must propagate, not be
    swallowed by the wrapper.

    asyncio.CancelledError inherits from BaseException (Py 3.8+), so a bare
    `except BaseException` would silently turn a structured-cancellation
    signal into a default RuntimeConfig — the surrounding event loop would
    then think the task completed normally and skip the cancellation it had
    asked for. Pinning re-raise behavior keeps `gather()` and timeout cancels
    correct even when bootstrap is the first thing to notice the cancel.
    """
    import asyncio

    async def cancel(*args, **kwargs):
        raise asyncio.CancelledError()

    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=False,
    )

    with patch("agent_scan.cli.bootstrap_first_control_server", side_effect=cancel):
        with pytest.raises(asyncio.CancelledError):
            await cli.bootstrap_runtime_config(args, command="scan")


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_forwards_skip_ssl_verify():
    """args.skip_ssl_verify must reach bootstrap_first_control_server unchanged.

    Without this, bootstrap uses a verifying TCPConnector while the subsequent
    upload uses a non-verifying one — so on hosts with self-signed control
    server certs the upload succeeds but bootstrap silently fails its TLS
    handshake, stripping the X-Bootstrap-Event-Id correlation off every push.
    """
    fake_helper = AsyncMock(return_value=RuntimeConfig())
    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=False,
        skip_ssl_verify=True,
    )

    with patch("agent_scan.cli.bootstrap_first_control_server", fake_helper):
        await cli.bootstrap_runtime_config(args, command="scan")

    assert fake_helper.call_args.kwargs["skip_ssl_verify"] is True


@pytest.mark.asyncio
async def test_bootstrap_runtime_config_defaults_skip_ssl_verify_to_false_when_attr_missing():
    """Subparsers that omit --skip-ssl-verify must not crash the wrapper.

    Default is False so bootstrap stays verifying when the flag was never
    registered on the parser — matching the safe default everywhere else.
    """
    fake_helper = AsyncMock(return_value=RuntimeConfig())
    args = Namespace(
        control_servers=[_control_server("http://example/mcp-scan/push")],
        no_bootstrap=False,
    )
    # Deliberately no `skip_ssl_verify` attribute on args.

    with patch("agent_scan.cli.bootstrap_first_control_server", fake_helper):
        await cli.bootstrap_runtime_config(args, command="scan")

    assert fake_helper.call_args.kwargs["skip_ssl_verify"] is False
