"""run_scan fetches the Agent Scan config once, then uses it to pick discovery and analysis paths."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import run_scan
from agent_scan.machine_auth import MachineAuth, MachineAuthError
from agent_scan.models import ClientToInspect, InspectedPath, ScanResponse
from agent_scan.pipelines import RemoteOutcome
from agent_scan.verify_api import AgentScanConfig
from tests.unit.test_cli_control_server_no_consent import _push_key_scan_args

_Discovered = tuple[list[ClientToInspect], list[InspectedPath], list[str]]

_REMOTE: _Discovered = (
    [ClientToInspect(name="remote", client_path="/r", mcp_configs={}, skills_dirs={})],
    [],
    ["alice"],
)
_LOCAL: _Discovered = ([ClientToInspect(name="local", client_path="/l", mcp_configs={}, skills_dirs={})], [], ["alice"])
_HOMES = [(Path("/home/alice"), "alice")]
_SCANNED = {"homes_count": 1, "wsl_homes_count": 0}


async def _run(args, config: AgentScanConfig, remote_result: RemoteOutcome | None = None, homes=_HOMES):
    remote_result = remote_result or RemoteOutcome(_REMOTE, supported_agents=["remote", "local"])
    with (
        patch("agent_scan.cli.fetch_agent_scan_config", new=AsyncMock(return_value=config)) as fetch,
        patch("agent_scan.pipelines.get_readable_home_directories", return_value=homes),
        patch("agent_scan.pipelines.discover_clients_remotely", new=AsyncMock(return_value=remote_result)) as remote,
        patch("agent_scan.pipelines.discover_clients_to_inspect", new=AsyncMock(return_value=_LOCAL)) as local,
        patch("agent_scan.pipelines.inspect_pipeline", new=AsyncMock(return_value=([], []))) as inspect,
        patch(
            "agent_scan.pipelines.analyze_machine", new=AsyncMock(return_value=ScanResponse(scan_path_responses=[]))
        ) as analyze,
    ):
        await run_scan(args, mode="scan")
    return fetch, remote, local, inspect, analyze


def _inspected(inspect) -> list[str]:
    return [c.name for c in inspect.await_args.kwargs["clients_to_inspect"]]


def _discovery(analyze) -> dict:
    return analyze.await_args.kwargs["scan_context"]["discovery"]


_COUNTS = {"clients": 1, "mcp_configs": 0, "mcp_servers": 0, "skills_dirs": 0}


@pytest.mark.asyncio
async def test_on_uses_remote_only_and_reuses_config():
    config = AgentScanConfig(remote_discovery_mode="on", async_analysis_enabled=True)
    fetch, remote, local, inspect, analyze = await _run(_push_key_scan_args(), config)

    fetch.assert_awaited_once()
    assert fetch.await_args.args[1] == "some-user-push-key"
    remote.assert_awaited_once()
    assert remote.await_args.args[1] == "https://some.analysis.endpoint.com"
    assert remote.await_args.kwargs["identifier"] == "some-machine-id-dh7g62dyug7d"
    local.assert_not_awaited()
    assert _inspected(inspect) == ["remote"]
    assert analyze.await_args.kwargs["agent_scan_config"] == config
    assert _discovery(analyze) == {"mode": "on", "source": "remote", **_SCANNED, "remote": _COUNTS}


@pytest.mark.asyncio
async def test_on_failure_pushes_only_local_only_pieces():
    config = AgentScanConfig(remote_discovery_mode="on")
    _fetch, _remote, local, inspect, analyze = await _run(
        _push_key_scan_args(), config, remote_result=RemoteOutcome(None, "http_503"), homes=[]
    )

    local.assert_not_awaited()
    assert _inspected(inspect) == []
    assert _discovery(analyze) == {
        "mode": "on",
        "source": "remote",
        "homes_count": 0,
        "wsl_homes_count": 0,
        "remote": {"clients": 0, "mcp_configs": 0, "mcp_servers": 0, "skills_dirs": 0},
        "remote_error_reason": "http_503",
    }


@pytest.mark.asyncio
async def test_on_partial_pushes_what_was_found():
    config = AgentScanConfig(remote_discovery_mode="on")
    _fetch, _remote, _local, inspect, analyze = await _run(
        _push_key_scan_args(), config, remote_result=RemoteOutcome(_REMOTE, partial=True)
    )

    assert _inspected(inspect) == ["remote"]
    assert _discovery(analyze) == {"mode": "on", "source": "remote", **_SCANNED, "remote": _COUNTS, "partial": True}


@pytest.mark.asyncio
async def test_shadow_ignores_partial_remote():
    config = AgentScanConfig(remote_discovery_mode="shadow")
    _fetch, _remote, _local, inspect, analyze = await _run(
        _push_key_scan_args(), config, remote_result=RemoteOutcome(_REMOTE, partial=True)
    )

    assert _inspected(inspect) == ["local"]
    assert _discovery(analyze)["remote_error_reason"] == "partial"


@pytest.mark.asyncio
async def test_off_uses_local():
    _fetch, remote, local, inspect, analyze = await _run(_push_key_scan_args(), AgentScanConfig())

    remote.assert_not_awaited()
    local.assert_awaited_once()
    assert _inspected(inspect) == ["local"]
    assert _discovery(analyze) == {"mode": "off", "source": "local", "local": _COUNTS}


@pytest.mark.asyncio
async def test_shadow_uses_local_and_reports_diff():
    config = AgentScanConfig(remote_discovery_mode="shadow")
    _fetch, remote, local, inspect, analyze = await _run(_push_key_scan_args(), config)

    remote.assert_awaited_once()
    local.assert_awaited_once()
    assert _inspected(inspect) == ["local"]
    discovery = _discovery(analyze)
    assert discovery["mode"] == "shadow" and discovery["source"] == "local"
    assert discovery["local"] == discovery["remote"] == _COUNTS
    # Clients without configs have no keys to compare.
    assert discovery["comparison"] == "identical"


@pytest.mark.asyncio
async def test_shadow_remote_failure_keeps_local():
    config = AgentScanConfig(remote_discovery_mode="shadow")
    _fetch, _remote, _local, inspect, analyze = await _run(
        _push_key_scan_args(), config, remote_result=RemoteOutcome(None, "http_503")
    )

    assert _inspected(inspect) == ["local"]
    assert _discovery(analyze) == {
        "mode": "shadow",
        "source": "local",
        **_SCANNED,
        "local": _COUNTS,
        "comparison": "failed",
        "remote_error_reason": "http_503",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["shadow", "on"])
async def test_explicit_paths_always_use_local(mode):
    config = AgentScanConfig(remote_discovery_mode=mode)
    _fetch, remote, local, _inspect, analyze = await _run(_push_key_scan_args(files=["/x/mcp.json"]), config)

    remote.assert_not_awaited()
    local.assert_awaited_once()
    assert _discovery(analyze)["remote_skipped"] == "not_eligible"


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
            _push_key_scan_args(**overrides), AgentScanConfig(remote_discovery_mode="on")
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
            _push_key_scan_args(), AgentScanConfig(remote_discovery_mode="on")
        )

    assert fetch.await_args.args[1] == "some-user-push-key"
    assert remote.await_args.args[2] == "some-user-push-key"
    local.assert_not_awaited()


# Absolute on every platform: machine mode refuses a token command that is not an absolute path.
_TOKEN_COMMAND = os.path.abspath("/opt/ads/installer")
_MACHINE_ARGS = {"token_command": _TOKEN_COMMAND, "tenant_id": "tenant-1"}
# Scheme and host of the analysis URL in _push_key_scan_args.
_API = "https://some.analysis.endpoint.com"


@pytest.mark.asyncio
async def test_machine_auth_runs_token_command_once_and_reaches_every_tenant_call():
    config = AgentScanConfig(remote_discovery_mode="on", async_analysis_enabled=True)
    with patch("agent_scan.machine_auth.fetch_access_token", return_value="machine-token") as fetch_token:
        fetch, remote, _local, _inspect, analyze = await _run(_push_key_scan_args(**_MACHINE_ARGS), config)

    expected = MachineAuth(_API, "tenant-1", "machine-token")
    fetch_token.assert_called_once_with(_TOKEN_COMMAND, _API)
    assert fetch.await_args.kwargs["machine_auth"] == expected
    assert remote.await_args.kwargs["machine_auth"] == expected
    assert analyze.await_args.kwargs["machine_auth"] == expected
    # A push key on the command line is forwarded as before; machine mode never sends it.
    assert analyze.await_args.kwargs["push_key"] == "some-user-push-key"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {**_MACHINE_ARGS, "command": "evo"},
        {"token_command": _TOKEN_COMMAND},
        {"tenant_id": "tenant-1"},
        # An installer that still writes base_url without the other two values.
        {"base_url": "https://api.snyk.io"},
    ],
    ids=["no_machine_values", "evo", "token_command_only", "tenant_id_only", "base_url_only"],
)
async def test_push_key_mode_keeps_push_key(overrides):
    config = AgentScanConfig(remote_discovery_mode="on")
    with patch("agent_scan.machine_auth.fetch_access_token") as fetch_token:
        fetch, remote, _local, _inspect, analyze = await _run(_push_key_scan_args(**overrides), config)

    fetch_token.assert_not_called()
    assert fetch.await_args.args[1] == "some-user-push-key"
    assert fetch.await_args.kwargs["machine_auth"] is None
    assert remote.await_args.args[2] == "some-user-push-key"
    assert remote.await_args.kwargs["machine_auth"] is None
    assert analyze.await_args.kwargs["machine_auth"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides, fetch_token_kwargs",
    [
        (_MACHINE_ARGS, {"side_effect": MachineAuthError("The token command exited with 1.")}),
        ({**_MACHINE_ARGS, "token_command": "ads-installer"}, {"return_value": "machine-token"}),
    ],
    ids=["token_command_fails", "relative_token_command"],
)
async def test_machine_auth_failure_stops_the_scan_before_any_call(overrides, fetch_token_kwargs):
    """No push-key fallback: nothing is fetched, discovered or analyzed."""
    config = AgentScanConfig(remote_discovery_mode="on")
    with (
        patch("agent_scan.machine_auth.fetch_access_token", **fetch_token_kwargs),
        patch("agent_scan.cli.fetch_agent_scan_config", new=AsyncMock(return_value=config)) as fetch,
        patch("agent_scan.pipelines.discover_clients_remotely", new=AsyncMock()) as remote,
        patch("agent_scan.pipelines.analyze_machine", new=AsyncMock()) as analyze,
        pytest.raises(MachineAuthError),
    ):
        await run_scan(_push_key_scan_args(**overrides), mode="scan")

    fetch.assert_not_awaited()
    remote.assert_not_awaited()
    analyze.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config, overrides",
    [
        (AgentScanConfig(async_analysis_enabled=False), {}),
        (AgentScanConfig(async_analysis_enabled=True), {"show_analysis_results": True}),
        (AgentScanConfig(async_analysis_enabled=True), {"ci": True}),
    ],
    ids=["async_disabled", "show_results", "ci"],
)
async def test_machine_auth_sync_analysis_stops_the_scan_before_discovery(config, overrides):
    """Sync analysis has no tenant route: the scan fails right after the config read."""
    with (
        patch("agent_scan.machine_auth.fetch_access_token", return_value="machine-token"),
        patch("agent_scan.cli.fetch_agent_scan_config", new=AsyncMock(return_value=config)) as fetch,
        patch("agent_scan.pipelines.discover_clients_remotely", new=AsyncMock()) as remote,
        patch("agent_scan.pipelines.discover_clients_to_inspect", new=AsyncMock()) as local,
        patch("agent_scan.pipelines.analyze_machine", new=AsyncMock()) as analyze,
        pytest.raises(MachineAuthError, match="no machine identity route"),
    ):
        await run_scan(_push_key_scan_args(**_MACHINE_ARGS, **overrides), mode="scan")

    fetch.assert_awaited_once()
    remote.assert_not_awaited()
    local.assert_not_awaited()
    analyze.assert_not_awaited()


@pytest.mark.asyncio
async def test_machine_auth_ignores_base_url_and_uses_the_analysis_url_api():
    config = AgentScanConfig(remote_discovery_mode="on", async_analysis_enabled=True)
    args = _push_key_scan_args(**_MACHINE_ARGS, base_url="https://other.example.io")
    with patch("agent_scan.machine_auth.fetch_access_token", return_value="machine-token") as fetch_token:
        _fetch, _remote, _local, _inspect, analyze = await _run(args, config)

    fetch_token.assert_called_once_with(_TOKEN_COMMAND, _API)
    assert analyze.await_args.kwargs["machine_auth"].base_url == _API


@pytest.mark.asyncio
async def test_machine_auth_without_machine_id_sends_the_hostname():
    """The tenant analysis route requires X-Scan-User-Id."""
    config = AgentScanConfig(remote_discovery_mode="on", async_analysis_enabled=True)
    args = _push_key_scan_args(**_MACHINE_ARGS, control_servers=[], machine_id=None)
    with (
        patch("agent_scan.machine_auth.fetch_access_token", return_value="machine-token"),
        patch("agent_scan.cli.get_hostname", return_value="host-1"),
    ):
        _fetch, remote, _local, _inspect, analyze = await _run(args, config)

    assert analyze.await_args.kwargs["identifier"] == "host-1"
    assert remote.await_args.kwargs["identifier"] == "host-1"
