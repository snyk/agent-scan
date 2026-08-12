import argparse
import json
from argparse import Namespace
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import _handle_ci_exit, print_scan_inspect, setup_scan_parser
from agent_scan.models import ScanError
from agent_scan.models.api.v20260710 import (
    McpServerRiskIndexes,
    McpServerRiskResponse,
    RiskScore,
    ScanPathResponse,
    ScanResponse,
    SkillRiskIndexes,
    SkillRiskResponse,
    SkillRiskScore,
)


def _cli_args(*, json_output: bool, ci: bool) -> Namespace:
    return Namespace(
        json=json_output,
        print_errors=False,
        print_full_descriptions=False,
        verbose=False,
        ci=ci,
        skills=True,
    )


def test_scan_parser_defaults_to_v20260710_and_rejects_removed_issue_flag():
    parser = argparse.ArgumentParser()
    setup_scan_parser(parser)

    assert parser.parse_args([]).analysis_url.endswith("?version=2026-07-10")
    with pytest.raises(SystemExit, match="2"):
        parser.parse_args(["--ignore-issues-codes", "W001"])


@pytest.mark.asyncio
async def test_scan_json_emits_scan_response_shape(capsys):
    response = ScanResponse(scan_path_responses=[ScanPathResponse(client="cursor", path="/config")])

    async def noisy_scan(*args, **kwargs):
        print("inspection noise that must not corrupt JSON")
        return response

    with patch("agent_scan.cli.run_scan", side_effect=noisy_scan):
        await print_scan_inspect(mode="scan", args=_cli_args(json_output=True, ci=False))

    output = capsys.readouterr().out
    assert "inspection noise" not in output
    assert json.loads(output) == {
        "scan_path_responses": [{"client": "cursor", "path": "/config", "server_risks": [], "skill_risks": []}]
    }


@pytest.mark.asyncio
async def test_scan_ci_exits_for_server_or_skill_risk():
    responses = [
        ScanResponse(
            scan_path_responses=[
                ScanPathResponse(
                    path="/config",
                    server_risks=[
                        McpServerRiskResponse(
                            name="server",
                            risk_indexes=McpServerRiskIndexes(
                                dangerous_words=RiskScore(score=200, evidence="dangerous word")
                            ),
                        )
                    ],
                )
            ]
        ),
        ScanResponse(
            scan_path_responses=[
                ScanPathResponse(
                    path="/config",
                    skill_risks=[
                        SkillRiskResponse(
                            name="skill",
                            risk_indexes=SkillRiskIndexes(
                                malicious_code=SkillRiskScore(score=900, evidence="executes payload")
                            ),
                        )
                    ],
                )
            ]
        ),
    ]

    for response in responses:
        with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response):
            with pytest.raises(SystemExit, match="1"):
                await print_scan_inspect(mode="scan", args=_cli_args(json_output=True, ci=True))


@pytest.mark.asyncio
async def test_scan_ci_exits_for_runtime_failure_but_not_clean_result():
    failed_response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                client="cursor",
                path="/config",
                error=ScanError(message="parse failed", category="parse_error", is_failure=True),
            )
        ]
    )
    clean_response = ScanResponse(scan_path_responses=[ScanPathResponse(client="cursor", path="/config")])

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=failed_response):
        with pytest.raises(SystemExit, match="1"):
            await print_scan_inspect(mode="scan", args=_cli_args(json_output=True, ci=True))

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=clean_response):
        await print_scan_inspect(mode="scan", args=_cli_args(json_output=True, ci=True))


@pytest.mark.asyncio
async def test_scan_ci_exits_for_analysis_response_failure():
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                client="cursor",
                path="/config",
                error=ScanError(message="backend unavailable", category="analysis_error", is_failure=True),
            )
        ]
    )

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response):
        with pytest.raises(SystemExit, match="1"):
            await print_scan_inspect(mode="scan", args=_cli_args(json_output=True, ci=True))


@pytest.mark.parametrize(
    ("response", "expected_reason", "unexpected_reason"),
    [
        (
            ScanResponse(
                scan_path_responses=[
                    ScanPathResponse(
                        path="/config",
                        server_risks=[
                            McpServerRiskResponse(
                                name="server",
                                risk_indexes=McpServerRiskIndexes(
                                    dangerous_words=RiskScore(score=100, evidence="dangerous word")
                                ),
                            )
                        ],
                    )
                ]
            ),
            "risks found",
            "runtime failure codes",
        ),
        (
            ScanResponse(
                scan_path_responses=[
                    ScanPathResponse(
                        path="/config",
                        error=ScanError(message="parse failed", category="parse_error", is_failure=True),
                    )
                ]
            ),
            "runtime failure codes: X005",
            "risks found",
        ),
        (
            ScanResponse(
                scan_path_responses=[
                    ScanPathResponse(
                        path="/config",
                        error=ScanError(message="parse failed", category="parse_error", is_failure=True),
                        skill_risks=[
                            SkillRiskResponse(
                                name="skill",
                                risk_indexes=SkillRiskIndexes(
                                    malicious_code=SkillRiskScore(score=600, evidence="runs code")
                                ),
                            )
                        ],
                    )
                ]
            ),
            "risks found; runtime failure codes: X005",
            "runtime failure codes: none",
        ),
    ],
)
def test_scan_ci_message_reports_the_actual_failure_reasons(response, expected_reason, unexpected_reason, capsys):
    with pytest.raises(SystemExit, match="1"):
        _handle_ci_exit(response, json_output=False)

    message = capsys.readouterr().err
    assert expected_reason in message
    assert unexpected_reason not in message
