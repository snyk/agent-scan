import argparse
import json
from argparse import Namespace
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import (
    _handle_ci_exit,
    _parse_sandbox_env_args,
    _should_show_analysis_results,
    print_scan_inspect,
    setup_scan_parser,
)
from agent_scan.models import InspectedPath, ScanError
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


def _cli_args(
    *,
    json_output: bool,
    ci: bool,
    ignore_risks: str | None = None,
    ignore_failure_codes: str | None = None,
    show_full_discovery: bool = False,
) -> Namespace:
    return Namespace(
        json=json_output,
        print_errors=False,
        print_full_descriptions=False,
        verbose=False,
        ci=ci,
        ignore_risks=ignore_risks,
        ignore_failure_codes=ignore_failure_codes,
        skills=True,
        show_full_discovery=show_full_discovery,
    )


def test_scan_parser_defaults_to_v20260710_and_rejects_removed_issue_flag():
    parser = argparse.ArgumentParser()
    setup_scan_parser(parser)

    assert parser.parse_args([]).analysis_url.endswith("?version=2026-07-10")
    with pytest.raises(SystemExit, match="2"):
        parser.parse_args(["--ignore-issues-codes", "W001"])


def test_scan_parser_describes_print_full_descriptions_flag():
    parser = argparse.ArgumentParser()
    setup_scan_parser(parser)

    action = next(action for action in parser._actions if "--print-full-descriptions" in action.option_strings)
    assert action.help == "Show full entity and skill-file descriptions without truncation"


def test_scan_parser_accepts_ignore_risks():
    parser = argparse.ArgumentParser()
    setup_scan_parser(parser)

    args = parser.parse_args(["--ignore-risks", "private_data,malicious_code"])

    assert args.ignore_risks == "private_data,malicious_code"


def test_scan_parser_accepts_ignore_failure_codes():
    parser = argparse.ArgumentParser()
    setup_scan_parser(parser)

    args = parser.parse_args(["--ignore-failure-codes", "X001,X007"])

    assert args.ignore_failure_codes == "X001,X007"


def test_scan_parser_accepts_show_full_discovery():
    parser = argparse.ArgumentParser()
    setup_scan_parser(parser)

    assert parser.parse_args([]).show_full_discovery is False
    assert parser.parse_args(["--show-full-discovery"]).show_full_discovery is True


def test_scan_parser_accepts_show_analysis_results():
    parser = argparse.ArgumentParser()
    setup_scan_parser(parser)

    assert parser.parse_args([]).show_analysis_results is False
    assert parser.parse_args(["--show-analysis-results"]).show_analysis_results is True


@pytest.mark.parametrize(
    "command, ci, show_analysis_results, expected",
    [
        (None, False, False, False),
        ("scan", False, False, False),
        ("evo", False, False, True),
        ("scan", True, False, True),
        ("scan", False, True, True),
        # evo wins even if the other triggers are off; any single trigger forces sync.
        ("evo", True, True, True),
    ],
)
def test_should_show_analysis_results(command, ci, show_analysis_results, expected):
    args = Namespace(command=command, ci=ci, show_analysis_results=show_analysis_results)

    assert _should_show_analysis_results(args) is expected


def test_should_show_analysis_results_tolerates_missing_attributes():
    """run_scan is shared by scan/inspect; the helper must not blow up when flags are absent."""
    assert _should_show_analysis_results(Namespace()) is False


@pytest.mark.asyncio
async def test_show_full_discovery_is_forwarded_to_plain_printer():
    response = ScanResponse(scan_path_responses=[])
    args = _cli_args(json_output=False, ci=False, show_full_discovery=True)

    with (
        patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response),
        patch("agent_scan.cli.print_scan_response") as print_response,
    ):
        await print_scan_inspect(mode="scan", args=args)

    print_response.assert_called_once_with(response, False, args, show_all=True)


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


@pytest.mark.asyncio
async def test_ignore_risks_requires_ci(capsys):
    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock) as run_scan:
        with pytest.raises(SystemExit, match="2"):
            await print_scan_inspect(
                mode="scan",
                args=_cli_args(json_output=False, ci=False, ignore_risks="private_data"),
            )

    assert "--ignore-risks can only be used with --ci" in capsys.readouterr().err
    run_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_ignore_failure_codes_requires_ci(capsys):
    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock) as run_scan:
        with pytest.raises(SystemExit, match="2"):
            await print_scan_inspect(
                mode="scan",
                args=_cli_args(json_output=False, ci=False, ignore_failure_codes="X001"),
            )

    assert "--ignore-failure-codes can only be used with --ci" in capsys.readouterr().err
    run_scan.assert_not_awaited()


@pytest.mark.asyncio
async def test_ignored_risk_is_removed_from_json_and_ci_exit(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                server_risks=[
                    McpServerRiskResponse(
                        name="server",
                        risk_indexes=McpServerRiskIndexes(
                            private_data=RiskScore(score=300, evidence="reads private data")
                        ),
                    )
                ],
                skill_risks=[
                    SkillRiskResponse(
                        name="skill",
                        risk_indexes=SkillRiskIndexes(malicious_code=SkillRiskScore(score=600, evidence="runs code")),
                    )
                ],
            )
        ]
    )

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response):
        await print_scan_inspect(
            mode="scan",
            args=_cli_args(json_output=True, ci=True, ignore_risks="private_data,malicious_code"),
        )

    output = json.loads(capsys.readouterr().out)
    path = output["scan_path_responses"][0]
    assert "private_data" not in path["server_risks"][0]["risk_indexes"]
    assert "malicious_code" not in path["skill_risks"][0]["risk_indexes"]


@pytest.mark.asyncio
async def test_non_ignored_risk_still_prints_and_fails_ci(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                server_risks=[
                    McpServerRiskResponse(
                        name="server",
                        risk_indexes=McpServerRiskIndexes(
                            dangerous_words=RiskScore(score=100, evidence="dangerous word"),
                            private_data=RiskScore(score=300, evidence="reads private data"),
                        ),
                    )
                ],
            )
        ]
    )

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response):
        with pytest.raises(SystemExit, match="1"):
            await print_scan_inspect(
                mode="scan",
                args=_cli_args(json_output=False, ci=True, ignore_risks="private_data"),
            )

    captured = capsys.readouterr()
    assert "Private data" not in captured.out
    assert "Dangerous words" in captured.out
    assert "risks found" in captured.err


@pytest.mark.asyncio
async def test_ignored_risk_does_not_suppress_runtime_failure(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                server_risks=[
                    McpServerRiskResponse(
                        name="server",
                        error=ScanError(message="could not start server", category="server_startup", is_failure=True),
                        risk_indexes=McpServerRiskIndexes(
                            private_data=RiskScore(score=300, evidence="reads private data")
                        ),
                    )
                ],
            )
        ]
    )

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response):
        with pytest.raises(SystemExit, match="1"):
            await print_scan_inspect(
                mode="scan",
                args=_cli_args(json_output=False, ci=True, ignore_risks="private_data"),
            )

    captured = capsys.readouterr()
    assert "Private data" not in captured.out
    assert "runtime failure codes: X001" in captured.err
    assert "risks found" not in captured.err


@pytest.mark.asyncio
async def test_ignored_failure_code_remains_visible_but_does_not_fail_scan_ci(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                server_risks=[
                    McpServerRiskResponse(
                        name="server",
                        error=ScanError(message="could not start server", category="server_startup", is_failure=True),
                    )
                ],
            )
        ]
    )

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response):
        await print_scan_inspect(
            mode="scan",
            args=_cli_args(json_output=False, ci=True, ignore_failure_codes="X001"),
        )

    captured = capsys.readouterr()
    assert "[X001 info]" in captured.out
    assert "could not start server" in captured.out
    assert "exiting with code 1" not in captured.err


@pytest.mark.asyncio
async def test_ignored_failure_code_applies_to_inspect_ci(capsys):
    inspected_paths = [
        InspectedPath(
            path="/config",
            error=ScanError(message="could not parse config", category="parse_error", is_failure=True),
        )
    ]

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=inspected_paths):
        await print_scan_inspect(
            mode="inspect",
            args=_cli_args(json_output=False, ci=True, ignore_failure_codes="X005"),
        )

    captured = capsys.readouterr()
    assert "X005" in captured.out
    assert "could not parse config" in captured.out
    assert "exiting with code 1" not in captured.err


@pytest.mark.asyncio
async def test_unknown_ignore_risk_warns_and_is_tolerated(capsys):
    response = ScanResponse(scan_path_responses=[ScanPathResponse(path="/config")])

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response):
        await print_scan_inspect(
            mode="scan",
            args=_cli_args(json_output=False, ci=True, ignore_risks="future_risk"),
        )

    assert "unknown risk name: future_risk" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_ignore_failure_codes_warns_for_unknown_codes(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                error=ScanError(message="could not start server", category="server_startup", is_failure=True),
            )
        ]
    )

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response):
        await print_scan_inspect(
            mode="scan",
            args=_cli_args(json_output=False, ci=True, ignore_failure_codes="X001,X999"),
        )

    captured = capsys.readouterr()
    assert "could not start server" in captured.out
    assert "unknown failure code: X999" in captured.err
    assert "exiting with code 1" not in captured.err


@pytest.mark.asyncio
async def test_ignore_failure_codes_is_case_sensitive(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                error=ScanError(message="could not start server", category="server_startup", is_failure=True),
            )
        ]
    )

    with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=response):
        with pytest.raises(SystemExit, match="1"):
            await print_scan_inspect(
                mode="scan",
                args=_cli_args(json_output=False, ci=True, ignore_failure_codes="x001"),
            )

    captured = capsys.readouterr()
    assert "unknown failure code: x001" in captured.err
    assert "runtime failure codes: X001" in captured.err


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


class TestParseSandboxEnvArgs:
    """Tests for sandbox-scan's --env KEY=VALUE parsing."""

    def test_none_returns_empty_dict(self):
        assert _parse_sandbox_env_args(None) == {}

    def test_single_entry(self):
        assert _parse_sandbox_env_args(["API_TOKEN=secret"]) == {"API_TOKEN": "secret"}

    def test_multiple_entries(self):
        assert _parse_sandbox_env_args(["A=1", "B=2"]) == {"A": "1", "B": "2"}

    def test_value_may_contain_equals_signs(self):
        assert _parse_sandbox_env_args(["JWT=header.payload=x.sig=y"]) == {"JWT": "header.payload=x.sig=y"}

    def test_value_may_be_empty(self):
        assert _parse_sandbox_env_args(["EMPTY="]) == {"EMPTY": ""}

    @pytest.mark.parametrize("entry", ["no-equals-sign", "=no-key"])
    def test_malformed_entry_raises_clear_error(self, entry):
        with pytest.raises(ValueError, match="KEY=VALUE"):
            _parse_sandbox_env_args([entry])
