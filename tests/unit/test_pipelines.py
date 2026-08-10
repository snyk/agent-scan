from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.models import InspectedPath
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
