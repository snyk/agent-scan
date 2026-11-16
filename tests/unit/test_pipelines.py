from unittest.mock import AsyncMock, patch

import aiohttp
import pytest

from agent_scan.agents import DiscoveryScope
from agent_scan.models import ClientToInspect, ControlServer, InspectedPath
from agent_scan.models.api.v20260710 import ScanPathResponse, ScanResponse
from agent_scan.pipelines import (
    AnalyzeArgs,
    InspectArgs,
    PushArgs,
    discover_clients_remotely,
    inspect_analyze_push_pipeline,
    supports_remote_discovery,
)
from agent_scan.remote_discovery.client import RemoteDiscoveryError, RemoteResult
from agent_scan.verify_api import AgentScanConfig


@pytest.mark.asyncio
async def test_scan_pipeline_returns_api_response():
    inspected_paths = [InspectedPath(client="cursor", path="/config")]
    response = ScanResponse(scan_path_responses=[ScanPathResponse(client="cursor", path="/config")])

    with (
        patch(
            "agent_scan.pipelines.inspect_pipeline",
            new_callable=AsyncMock,
            return_value=(inspected_paths, ["alice"]),
        ) as inspect_pipeline,
        patch("agent_scan.pipelines.analyze_machine", new_callable=AsyncMock, return_value=response) as analyze,
    ):
        result = await inspect_analyze_push_pipeline(
            InspectArgs(timeout=10, tokens=[], paths=[]),
            AnalyzeArgs(analysis_url="https://test.example/api"),
            PushArgs(control_servers=[], version="0.6.0"),
        )

    assert result is response
    inspect_pipeline.assert_awaited_once()
    assert analyze.await_args.args[0] is inspected_paths


@pytest.mark.asyncio
async def test_push_args_push_key_passed_through_verbatim():
    """PushArgs.push_key is forwarded to analyze_machine exactly as given;
    precedence between --push-key and the deprecated --control-server-H
    x-client-id header is resolved upstream by the caller (cli.py's
    _effective_push_key), not by this pipeline."""
    inspected_paths = [InspectedPath(client="cursor", path="/config")]
    response = ScanResponse(scan_path_responses=[ScanPathResponse(client="cursor", path="/config")])

    with (
        patch(
            "agent_scan.pipelines.inspect_pipeline",
            new_callable=AsyncMock,
            return_value=(inspected_paths, ["alice"]),
        ),
        patch("agent_scan.pipelines.analyze_machine", new_callable=AsyncMock, return_value=response) as analyze,
    ):
        await inspect_analyze_push_pipeline(
            InspectArgs(timeout=10, tokens=[], paths=[]),
            AnalyzeArgs(analysis_url="https://test.example/api"),
            PushArgs(
                control_servers=[
                    ControlServer(url="https://server1.com", headers={"x-client-id": "old-key"}, identifier="old-id")
                ],
                push_key="new-key",
                version="0.6.0",
            ),
        )

    assert analyze.await_args.kwargs["push_key"] == "new-key"


@pytest.mark.asyncio
async def test_push_args_push_key_none_is_not_derived_from_control_server_header():
    """If the caller passes push_key=None, this pipeline does NOT fall back
    to deriving it from the control_servers x-client-id header itself —
    that resolution is the caller's responsibility (see cli.py's
    _effective_push_key). A caller that skips resolving it gets None
    forwarded, not a silently-derived value."""
    inspected_paths = [InspectedPath(client="cursor", path="/config")]
    response = ScanResponse(scan_path_responses=[ScanPathResponse(client="cursor", path="/config")])

    with (
        patch(
            "agent_scan.pipelines.inspect_pipeline",
            new_callable=AsyncMock,
            return_value=(inspected_paths, ["alice"]),
        ),
        patch("agent_scan.pipelines.analyze_machine", new_callable=AsyncMock, return_value=response) as analyze,
    ):
        await inspect_analyze_push_pipeline(
            InspectArgs(timeout=10, tokens=[], paths=[]),
            AnalyzeArgs(analysis_url="https://test.example/api"),
            PushArgs(
                control_servers=[
                    ControlServer(url="https://server1.com", headers={"x-client-id": "old-key"}, identifier="old-id")
                ],
                version="0.6.0",
            ),
        )

    assert analyze.await_args.kwargs["push_key"] is None


@pytest.mark.asyncio
async def test_skip_pushing_true_when_push_key_set_without_control_servers():
    """--push-key alone (no --control-server) must still suppress the
    default push behavior via X-Push: skip, matching the header-derived
    push-key flow where control_servers was always non-empty."""
    inspected_paths = [InspectedPath(client="cursor", path="/config")]
    response = ScanResponse(scan_path_responses=[ScanPathResponse(client="cursor", path="/config")])

    with (
        patch(
            "agent_scan.pipelines.inspect_pipeline",
            new_callable=AsyncMock,
            return_value=(inspected_paths, ["alice"]),
        ),
        patch("agent_scan.pipelines.analyze_machine", new_callable=AsyncMock, return_value=response) as analyze,
    ):
        await inspect_analyze_push_pipeline(
            InspectArgs(timeout=10, tokens=[], paths=[]),
            AnalyzeArgs(analysis_url="https://test.example/api"),
            PushArgs(control_servers=[], push_key="direct-push-key", version="0.6.0"),
        )

    assert analyze.await_args.kwargs["skip_pushing"] is True


@pytest.mark.asyncio
async def test_skip_pushing_false_when_neither_control_servers_nor_push_key_set():
    """A plain scan with no control servers and no push key must not set
    X-Push: skip."""
    inspected_paths = [InspectedPath(client="cursor", path="/config")]
    response = ScanResponse(scan_path_responses=[ScanPathResponse(client="cursor", path="/config")])

    with (
        patch(
            "agent_scan.pipelines.inspect_pipeline",
            new_callable=AsyncMock,
            return_value=(inspected_paths, ["alice"]),
        ),
        patch("agent_scan.pipelines.analyze_machine", new_callable=AsyncMock, return_value=response) as analyze,
    ):
        await inspect_analyze_push_pipeline(
            InspectArgs(timeout=10, tokens=[], paths=[]),
            AnalyzeArgs(analysis_url="https://test.example/api"),
            PushArgs(control_servers=[], version="0.6.0"),
        )

    assert analyze.await_args.kwargs["skip_pushing"] is False


@pytest.mark.asyncio
async def test_skip_pushing_false_when_push_key_explicitly_empty_string():
    """An explicit empty-string --push-key (used only to override a legacy
    header without adopting it, see cli._effective_push_key's ``is not None``
    resolution) is not a real push key: it must be treated as falsy/unset for
    skip_pushing, consistent with every other consumer of the resolved push
    key (analyze_machine's own ``if push_key:`` header guard, and cli.py's
    is_interactive_run / decide_handshake, both of which use ``bool(...)``).
    The ``is not None`` check belongs only to source-precedence resolution
    inside _effective_push_key itself, not to behavior driven by the
    resolved value."""
    inspected_paths = [InspectedPath(client="cursor", path="/config")]
    response = ScanResponse(scan_path_responses=[ScanPathResponse(client="cursor", path="/config")])

    with (
        patch(
            "agent_scan.pipelines.inspect_pipeline",
            new_callable=AsyncMock,
            return_value=(inspected_paths, ["alice"]),
        ),
        patch("agent_scan.pipelines.analyze_machine", new_callable=AsyncMock, return_value=response) as analyze,
    ):
        await inspect_analyze_push_pipeline(
            InspectArgs(timeout=10, tokens=[], paths=[]),
            AnalyzeArgs(analysis_url="https://test.example/api"),
            PushArgs(control_servers=[], push_key="", version="0.6.0"),
        )

    assert analyze.await_args.kwargs["skip_pushing"] is False


@pytest.mark.asyncio
async def test_agent_scan_config_passed_to_analyze_machine():
    config = AgentScanConfig(async_analysis_enabled=True)
    with (
        patch("agent_scan.pipelines.inspect_pipeline", new_callable=AsyncMock, return_value=([], [])),
        patch("agent_scan.pipelines.analyze_machine", new_callable=AsyncMock) as analyze,
    ):
        await inspect_analyze_push_pipeline(
            InspectArgs(timeout=10, tokens=[], paths=[]),
            AnalyzeArgs(analysis_url="https://test.example/api", agent_scan_config=config),
            PushArgs(control_servers=[], push_key="k", version="0.6.0"),
        )

    assert analyze.await_args.kwargs["agent_scan_config"] == config


@pytest.mark.parametrize(
    "kwargs, expected",
    [({}, True), ({"paths": ["/x/mcp.json"]}, False), ({"target_folders": ["/repo"]}, False)],
    ids=["machine", "explicit_paths", "target_folders"],
)
def test_supports_remote_discovery(kwargs, expected):
    args = {"timeout": 10, "tokens": [], "paths": [], **kwargs}
    assert supports_remote_discovery(InspectArgs(**args)) is expected


@pytest.mark.asyncio
async def test_discover_clients_remotely_builds_clients():
    remote = RemoteResult(
        found={
            "clients": [{"name": "cursor", "client_path": "~/.cursor", "username": "alice"}],
            "mcp_configs": [],
            "skills_dirs": [],
        }
    )
    with (
        patch("agent_scan.pipelines.run_remote_discovery", new_callable=AsyncMock, return_value=remote) as run,
        patch("agent_scan.pipelines.get_readable_home_directories", return_value=[]),
    ):
        result = await discover_clients_remotely(
            InspectArgs(timeout=10, tokens=[], paths=[], discovery_scope=DiscoveryScope.ALL),
            "https://api.snyk.io",
            "push-abc",
            cli_version="1.0",
            skip_ssl_verify=True,
        )

    assert result is not None
    clients, unresolved, usernames = result
    assert [(c.name, c.username) for c in clients] == [("cursor", "alice")]
    assert unresolved == []
    assert usernames == ["alice"]
    assert run.await_args.args == ("https://api.snyk.io",)
    assert run.await_args.kwargs == {
        "scope": "all",
        "push_key": "push-abc",
        "cli_version": "1.0",
        "all_users": False,
        "skip_ssl_verify": True,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [RemoteDiscoveryError("503"), aiohttp.ClientConnectionError("down"), TimeoutError(), KeyError("found")],
    ids=["backend_error", "connection", "timeout", "malformed_response"],
)
async def test_discover_clients_remotely_returns_none_on_failure(error):
    with patch("agent_scan.pipelines.run_remote_discovery", new_callable=AsyncMock, side_effect=error):
        result = await discover_clients_remotely(InspectArgs(timeout=10, tokens=[], paths=[]), "https://x", "k")
    assert result is None


class _FakeDiscoverer:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.scopes = result, error, []

    def discover_local_only(self, scope):
        self.scopes.append(scope)
        if self.error:
            raise self.error
        return self.result


@pytest.mark.asyncio
async def test_discover_clients_remotely_merges_local_only_sources(tmp_path):
    remote = RemoteResult(
        found={
            "clients": [{"name": "vscode", "client_path": "~/.vscode", "username": "alice"}],
            "mcp_configs": [],
            "skills_dirs": [],
        }
    )
    vscode = _FakeDiscoverer(
        ClientToInspect(name="vscode", client_path="~/.vscode", mcp_configs={"/ext.js": []}, skills_dirs={})
    )
    opencode = _FakeDiscoverer(
        ClientToInspect(name="opencode", client_path="~/.config/opencode", mcp_configs={}, skills_dirs={"/p": []})
    )
    empty = _FakeDiscoverer(ClientToInspect(name="cursor", client_path="~/.cursor", mcp_configs={}, skills_dirs={}))
    broken = _FakeDiscoverer(error=RuntimeError("boom"))
    with (
        patch("agent_scan.pipelines.run_remote_discovery", new_callable=AsyncMock, return_value=remote),
        patch("agent_scan.pipelines.get_readable_home_directories", return_value=[(tmp_path, "alice")]),
        patch("agent_scan.pipelines.find_discoverers", return_value=[broken, vscode, opencode, empty]) as find,
    ):
        result = await discover_clients_remotely(
            InspectArgs(timeout=10, tokens=[], paths=[], discovery_scope=DiscoveryScope.SERVERS), "https://x", "k"
        )

    assert result is not None
    clients = {(c.name, c.username): c for c in result[0]}
    assert set(clients) == {("vscode", "alice"), ("opencode", "alice")}
    assert clients[("vscode", "alice")].mcp_configs == {"/ext.js": []}
    assert clients[("opencode", "alice")].skills_dirs == {"/p": []}
    find.assert_called_once_with(tmp_path)
    assert vscode.scopes == [DiscoveryScope.SERVERS]


@pytest.mark.asyncio
async def test_discover_clients_remotely_skips_local_only_when_backend_fails():
    with (
        patch(
            "agent_scan.pipelines.run_remote_discovery", new_callable=AsyncMock, side_effect=RemoteDiscoveryError("x")
        ),
        patch("agent_scan.pipelines.find_discoverers") as find,
    ):
        assert await discover_clients_remotely(InspectArgs(timeout=10, tokens=[], paths=[]), "https://x", "k") is None
    find.assert_not_called()
