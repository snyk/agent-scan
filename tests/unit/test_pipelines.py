from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.models import ControlServer, InspectedPath
from agent_scan.models.api.v20260710 import ScanPathResponse, ScanResponse
from agent_scan.pipelines import AnalyzeArgs, InspectArgs, PushArgs, inspect_analyze_push_pipeline


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
