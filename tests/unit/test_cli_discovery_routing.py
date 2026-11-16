"""run_scan fetches the Agent Scan config once, then uses it to pick discovery and analysis paths."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import run_scan
from agent_scan.models import ClientToInspect, InspectedPath, ScanResponse
from agent_scan.verify_api import AgentScanConfig
from tests.unit.test_cli_control_server_no_consent import _push_key_scan_args

_Discovered = tuple[list[ClientToInspect], list[InspectedPath], list[str]]

_REMOTE: _Discovered = (
    [ClientToInspect(name="remote", client_path="/r", mcp_configs={}, skills_dirs={})],
    [],
    ["alice"],
)
_LOCAL: _Discovered = ([ClientToInspect(name="local", client_path="/l", mcp_configs={}, skills_dirs={})], [], ["alice"])


async def _run(args, config: AgentScanConfig, remote_result=_REMOTE):
    with (
        patch("agent_scan.cli.fetch_agent_scan_config", new=AsyncMock(return_value=config)) as fetch,
        patch("agent_scan.cli.discover_clients_remotely", new=AsyncMock(return_value=remote_result)) as remote,
        patch("agent_scan.cli.discover_clients_to_inspect", new=AsyncMock(return_value=_LOCAL)) as local,
        patch("agent_scan.pipelines.inspect_pipeline", new=AsyncMock(return_value=([], []))) as inspect,
        patch(
            "agent_scan.pipelines.analyze_machine", new=AsyncMock(return_value=ScanResponse(scan_path_responses=[]))
        ) as analyze,
    ):
        await run_scan(args, mode="scan")
    return fetch, remote, local, inspect, analyze


@pytest.mark.asyncio
async def test_remote_discovery_enabled_uses_backend_and_reuses_config():
    config = AgentScanConfig(remote_discovery_enabled=True, async_analysis_enabled=True)
    fetch, remote, local, inspect, analyze = await _run(_push_key_scan_args(), config)

    fetch.assert_awaited_once()
    assert fetch.await_args.args[1] == "some-user-push-key"
    remote.assert_awaited_once()
    assert remote.await_args.args[1] == "https://some.analysis.endpoint.com"
    local.assert_not_awaited()
    assert [c.name for c in inspect.await_args.kwargs["clients_to_inspect"]] == ["remote"]
    assert analyze.await_args.kwargs["agent_scan_config"] == config


@pytest.mark.asyncio
async def test_remote_discovery_disabled_uses_local():
    _fetch, remote, local, inspect, _analyze = await _run(_push_key_scan_args(), AgentScanConfig())

    remote.assert_not_awaited()
    local.assert_awaited_once()
    assert [c.name for c in inspect.await_args.kwargs["clients_to_inspect"]] == ["local"]


@pytest.mark.asyncio
async def test_remote_discovery_failure_falls_back_to_local():
    config = AgentScanConfig(remote_discovery_enabled=True)
    _fetch, remote, local, inspect, _analyze = await _run(_push_key_scan_args(), config, remote_result=None)

    remote.assert_awaited_once()
    local.assert_awaited_once()
    assert [c.name for c in inspect.await_args.kwargs["clients_to_inspect"]] == ["local"]


@pytest.mark.asyncio
async def test_explicit_paths_always_use_local():
    config = AgentScanConfig(remote_discovery_enabled=True)
    _fetch, remote, local, _inspect, _analyze = await _run(_push_key_scan_args(files=["/x/mcp.json"]), config)

    remote.assert_not_awaited()
    local.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "env, overrides",
    [
        ({}, {"control_servers": []}),
        ({"SNYK_TOKEN": "snyk-tok"}, {"control_servers": []}),
        ({"SNYK_CLI_USE": "true"}, {"control_servers": []}),
        ({"SNYK_TOKEN": "snyk-tok"}, {"control_servers": [], "push_key": ""}),
    ],
    ids=["no_auth", "snyk_token", "snyk_cli_proxy", "snyk_token_empty_push_key"],
)
async def test_without_push_key_skips_config_and_uses_local(env, overrides):
    """The config API is push-key authed, so token users never fetch it or use remote discovery."""
    with patch.dict(os.environ, env, clear=False):
        fetch, remote, local, _inspect, analyze = await _run(
            _push_key_scan_args(**overrides), AgentScanConfig(remote_discovery_enabled=True)
        )

    fetch.assert_not_awaited()
    remote.assert_not_awaited()
    local.assert_awaited_once()
    assert not analyze.await_args.kwargs["push_key"]
    assert analyze.await_args.kwargs["agent_scan_config"] == AgentScanConfig()


@pytest.mark.asyncio
async def test_push_key_wins_over_snyk_token():
    with patch.dict(os.environ, {"SNYK_TOKEN": "snyk-tok"}, clear=False):
        fetch, remote, local, _inspect, _analyze = await _run(
            _push_key_scan_args(), AgentScanConfig(remote_discovery_enabled=True)
        )

    assert fetch.await_args.args[1] == "some-user-push-key"
    assert remote.await_args.args[2] == "some-user-push-key"
    local.assert_not_awaited()
