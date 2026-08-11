import types

import pytest
from mcp.types import Implementation, InitializeResult, Tool

from agent_scan.models import (
    InspectedPath,
    InspectedServer,
    InspectedSkill,
    ScanError,
    ServerSignature,
    SkillFile,
    StdioServer,
)
from agent_scan.models.api.v20260710 import (
    MaliciousURLSkillRiskScore,
    McpEntitySummary,
    McpServerRiskIndexes,
    McpServerRiskResponse,
    Occurrence,
    Region,
    RiskScore,
    ScanPathResponse,
    ScanResponse,
    SkillFileSummary,
    SkillRiskIndexes,
    SkillRiskResponse,
    SkillRiskScore,
    UnverifiableURLSkillRiskScore,
)
from agent_scan.printer import (
    _format_component_line,
    _format_risk,
    _risk_score_color,
    format_skill_file_line,
    print_inspected_machine,
    print_scan_response,
)


@pytest.mark.parametrize(
    ("score", "color"),
    [
        (100, "#e2d2f4"),
        (299, "#e2d2f4"),
        (300, "#cbabee"),
        (599, "#cbabee"),
        (600, "#9456d2"),
        (999, "#9456d2"),
        (1000, "#8446c4"),
    ],
)
def test_risk_score_color_matches_maverick_bands(score, color):
    assert _risk_score_color(score) == color


def test_scan_component_line_uses_highest_risk_score_color():
    result = _format_component_line("my-server", [300, 600, 100])

    assert result.plain == "my-server 3 risks"
    assert any("#9456d2" in str(span.style) for span in result.spans)
    assert not any("green" in str(span.style) for span in result.spans)


def test_scan_component_line_uses_clean_and_error_colors():
    clean = _format_component_line("clean-server", [])
    failed = _format_component_line("failed-server", [], has_error=True)

    assert any("green" in str(span.style) for span in clean.spans)
    assert any("blue" in str(span.style) for span in failed.spans)


def test_format_risk_uses_score_color_and_explicit_metadata_labels():
    malicious = _format_risk(
        "suspicious_download_url",
        MaliciousURLSkillRiskScore(
            score=600,
            evidence="Downloads executable content",
            malicious_urls=["https://malicious.example/payload"],
        ),
        affected_tools=["download", "execute"],
    )
    unverifiable = _format_risk(
        "unverifiable_dependencies",
        UnverifiableURLSkillRiskScore(
            score=300,
            evidence="Uses an unverified dependency",
            unverifiable_urls=["https://unknown.example/package"],
        ),
    )

    assert "Suspicious download URL (600/1000)" in malicious.plain
    assert "Affected tools: download, execute" in malicious.plain
    assert "Malicious URLs: https://malicious.example/payload" in malicious.plain
    assert "Unverifiable URLs: https://unknown.example/package" in unverifiable.plain
    assert any("#9456d2" in str(span.style) for span in malicious.spans)
    assert not malicious.style
    for unstyled_text in (
        "Downloads executable content",
        "download, execute",
        "https://malicious.example/payload",
    ):
        offset = malicious.plain.index(unstyled_text)
        assert not any(span.start <= offset < span.end for span in malicious.spans)
    for metadata_label in ("Affected tools:", "Malicious URLs:"):
        offset = malicious.plain.index(metadata_label)
        assert any(span.start <= offset < span.end and "gray62" in str(span.style) for span in malicious.spans)


class TestPrintInspectedMachine:
    """The `inspect` command's InspectedPath renderer: MCP servers with their
    entities, and skills with their files."""

    def test_renders_servers_and_skills(self, capsys):
        signature = ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities={},
                serverInfo=Implementation(name="github", version="1"),
            ),
            tools=[Tool(name="create_pull_request", description="d", inputSchema={})],
        )
        path = InspectedPath(
            client="cursor",
            path="/proj",
            servers=[
                InspectedServer(
                    name="github",
                    server=StdioServer(command="uvx", args=["gh"], type="stdio"),
                    signature=signature,
                )
            ],
            skills=[
                InspectedSkill(
                    name="my-skill",
                    installation_path="/proj/.skills/my-skill",
                    files=[SkillFile(path="SKILL.md", content="x"), SkillFile(path="run.py", content="y")],
                )
            ],
        )

        print_inspected_machine([path], args=types.SimpleNamespace(skills=True))
        out = capsys.readouterr().out

        assert "found 1 mcp server and 1 skill" in out
        assert "github" in out
        assert "create_pull_request" in out  # server entity from the signature
        assert "my-skill" in out
        assert "SKILL.md" in out and "run.py" in out  # skill files

    def test_skill_file_name_is_rendered_as_plain_text(self):
        line = format_skill_file_line(SkillFile(path="[bold]not-markup[/bold].md", content="x"))
        assert "[bold]not-markup[/bold].md" in line.plain

    def test_error_without_public_message_does_not_render_exception_details(self, capsys):
        path = InspectedPath(
            path="/proj",
            servers=[
                InspectedServer(
                    name="failed",
                    server=StdioServer(command="failed"),
                    error=ScanError(
                        exception="credential in /Users/alice/private/config.json",
                        category="server_startup",
                    ),
                )
            ],
        )

        print_inspected_machine([path], args=types.SimpleNamespace(skills=False))
        out = capsys.readouterr().out

        assert "could not complete inspection" in out
        assert "credential" not in out
        assert "/Users/alice" not in out

    def test_empty_machine(self, capsys):
        print_inspected_machine([], args=types.SimpleNamespace(skills=True))
        assert "No MCP client configurations found" in capsys.readouterr().out


def test_plain_scan_output_includes_complete_server_and_skill_risk_details(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                client="cursor",
                path="/config",
                server_risks=[
                    McpServerRiskResponse(
                        name="server",
                        entities=[McpEntitySummary(name="catalog_tool", type="tool")],
                        risk_indexes=McpServerRiskIndexes(
                            private_data=RiskScore(
                                score=750,
                                evidence="Reads private records",
                                affected_tools=[0],
                            )
                        ),
                    )
                ],
                skill_risks=[
                    SkillRiskResponse(
                        name="skill",
                        risk_indexes=SkillRiskIndexes(
                            suspicious_download_url=MaliciousURLSkillRiskScore(
                                score=900,
                                evidence="Downloads an untrusted executable",
                                locations=[Region(start=Occurrence(path="SKILL.md", line=12, offset=3))],
                                malicious_urls=["https://malware.example/payload"],
                            )
                        ),
                    )
                ],
            )
        ]
    )

    print_scan_response(response)

    output = capsys.readouterr().out
    assert "Private data (750/1000)" in output
    assert "Reads private records" in output
    assert "Affected tools: catalog_tool" in output
    assert "Suspicious download URL (900/1000)" in output
    assert "SKILL.md:12:3" in output
    assert "Malicious URLs:" in output
    assert "https://malware.example/payload" in output


def test_plain_scan_output_renders_external_strings_literally(capsys):
    markup = "[/red]"
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path=f"/config/{markup}",
                error=ScanError(
                    message=f"path error {markup}",
                    traceback=f"traceback {markup}",
                    category="analysis_error",
                ),
                server_risks=[
                    McpServerRiskResponse(
                        name=f"server {markup}",
                        entities=[McpEntitySummary(name=f"tool {markup}", type="tool")],
                        risk_indexes=McpServerRiskIndexes(
                            private_data=RiskScore(
                                score=300,
                                evidence=f"evidence {markup}",
                                affected_tools=[0],
                            )
                        ),
                    )
                ],
                skill_risks=[
                    SkillRiskResponse(
                        name=f"skill {markup}",
                        files=[SkillFileSummary(name=f"SKILL {markup}.md", type="instruction")],
                        risk_indexes=SkillRiskIndexes(
                            suspicious_download_url=MaliciousURLSkillRiskScore(
                                score=600,
                                evidence=f"skill evidence {markup}",
                                locations=[Region(start=Occurrence(path=f"SKILL {markup}.md", line=2))],
                                malicious_urls=[f"https://example.test/{markup}"],
                            )
                        ),
                    )
                ],
            )
        ]
    )

    print_scan_response(response, print_errors=True)

    output = capsys.readouterr().out
    assert f"/config/{markup}" in output
    assert f"path error {markup}" in output
    assert f"server {markup}" in output
    assert f"Affected tools: tool {markup}" in output
    assert f"evidence {markup}" in output
    assert f"SKILL {markup}.md:2" in output
    assert f"https://example.test/{markup}" in output
    assert f"traceback {markup}" in output


def test_plain_scan_output_summarizes_clean_components_and_only_lists_risk_connected_items(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                client="cursor",
                path="~/.cursor",
                server_risks=[
                    McpServerRiskResponse(
                        name="clean-server",
                        entities=[
                            McpEntitySummary(name="clean_tool", type="tool"),
                            McpEntitySummary(name="clean_prompt", type="prompt"),
                        ],
                    ),
                    McpServerRiskResponse(
                        name="risky-server",
                        entities=[
                            McpEntitySummary(name="risky_tool", type="tool"),
                            McpEntitySummary(name="unaffected_tool", type="tool"),
                            McpEntitySummary(name="unaffected_prompt", type="prompt"),
                            McpEntitySummary(name="affected_resource", type="resource"),
                            McpEntitySummary(name="unaffected_resource", type="resource"),
                            McpEntitySummary(name="unaffected_template", type="resource_template"),
                        ],
                        risk_indexes=McpServerRiskIndexes(
                            private_data=RiskScore(
                                score=300,
                                evidence="Reads private records",
                                affected_tools=[0, 3],
                            )
                        ),
                    ),
                ],
                skill_risks=[
                    SkillRiskResponse(
                        name="clean-skill",
                        files=[
                            SkillFileSummary(name="SKILL.md", type="instruction"),
                            SkillFileSummary(name="logo.png", type="asset"),
                        ],
                    ),
                    SkillRiskResponse(
                        name="risky-skill",
                        files=[
                            SkillFileSummary(name="scripts/run.py", type="script"),
                            SkillFileSummary(name="scripts/helper.py", type="script"),
                            SkillFileSummary(name="notes.txt", type="asset"),
                        ],
                        risk_indexes=SkillRiskIndexes(
                            malicious_code=SkillRiskScore(
                                score=600,
                                evidence="Runs untrusted code",
                                locations=[Region(start=Occurrence(path="scripts/run.py", line=3))],
                            )
                        ),
                    ),
                ],
            )
        ]
    )

    print_scan_response(response)

    output = capsys.readouterr().out
    assert "Scanning " in output
    assert "found 2 mcp servers and 2 skills" in output
    assert "clean-server" in output
    assert "1 tool, 1 prompt" in output
    assert "clean_tool" not in output
    assert "clean_prompt" not in output
    assert "clean-skill" in output
    assert "1 instruction, 1 asset" in output
    assert "SKILL.md" not in output
    assert "logo.png" not in output
    assert "risky-server" in output
    assert "risky_tool" in output
    assert "affected_resource" in output
    assert "unaffected_tool" not in output
    assert "unaffected_prompt" not in output
    assert "unaffected_resource" not in output
    assert "unaffected_template" not in output
    assert "and 1 more tool, 1 prompt, 1 more resource, 1 resource template" in output
    assert "Private data (300/1000)" in output
    assert "risky-skill" in output
    assert "scripts/run.py" in output
    assert "scripts/helper.py" not in output
    assert "notes.txt" not in output
    assert "and 1 more script, 1 asset" in output
    assert "Malicious code (600/1000)" in output

    # Keep each risk after its owner and before
    # the next sibling component, rather than in a separate flat risk report.
    assert output.index("risky-server") < output.index("Private data") < output.index("clean-skill")
    assert output.index("risky-skill") < output.index("Malicious code") < output.index("scripts/run.py")

    # Risks are continuation lines in the
    # component label, not child nodes with their own tree connectors.
    private_data_line = next(line for line in output.splitlines() if "Private data" in line)
    malicious_code_line = next(line for line in output.splitlines() if "Malicious code" in line)
    assert "├── ●" not in private_data_line and "└── ●" not in private_data_line
    assert "├── ●" not in malicious_code_line and "└── ●" not in malicious_code_line


def test_plain_scan_output_show_all_restores_complete_item_lists(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                server_risks=[
                    McpServerRiskResponse(
                        name="server",
                        entities=[
                            McpEntitySummary(name="affected", type="tool"),
                            McpEntitySummary(name="unaffected", type="resource"),
                        ],
                        risk_indexes=McpServerRiskIndexes(
                            private_data=RiskScore(score=600, evidence="reads data", affected_tools=[0])
                        ),
                    )
                ],
                skill_risks=[
                    SkillRiskResponse(
                        name="skill",
                        files=[
                            SkillFileSummary(name="SKILL.md", type="instruction"),
                            SkillFileSummary(name="run.py", type="script"),
                        ],
                    )
                ],
            )
        ]
    )

    print_scan_response(response, show_all=True)

    output = capsys.readouterr().out
    for name in ("affected", "unaffected", "SKILL.md", "run.py"):
        assert name in output
    assert "and 1 resource" not in output


def test_plain_scan_output_uses_contains_when_risk_has_no_affected_items(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                server_risks=[
                    McpServerRiskResponse(
                        name="server-wide-risk",
                        entities=[McpEntitySummary(name="tool", type="tool")],
                        risk_indexes=McpServerRiskIndexes(
                            private_data=RiskScore(score=300, evidence="Server-wide evidence")
                        ),
                    )
                ],
                skill_risks=[
                    SkillRiskResponse(
                        name="locationless-risk",
                        files=[
                            SkillFileSummary(name="SKILL.md", type="instruction"),
                            SkillFileSummary(name="run.py", type="script"),
                        ],
                        risk_indexes=SkillRiskIndexes(
                            missing_skill_md=SkillRiskScore(score=1000, evidence="Manifest is missing")
                        ),
                    )
                ],
            )
        ]
    )

    print_scan_response(response)

    output = capsys.readouterr().out
    assert "contains 1 tool" in output
    assert "contains 1 instruction, 1 script" in output
    assert "and 1 tool" not in output
    assert "and 1 instruction, 1 script" not in output


def test_plain_scan_output_sorts_only_risks_by_descending_score(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                server_risks=[
                    McpServerRiskResponse(
                        name="server",
                        entities=[
                            McpEntitySummary(name="first-tool", type="tool"),
                            McpEntitySummary(name="second-tool", type="tool"),
                        ],
                        risk_indexes=McpServerRiskIndexes(
                            dangerous_words=RiskScore(score=100, evidence="low risk"),
                            private_data=RiskScore(score=600, evidence="high risk"),
                        ),
                    )
                ],
                skill_risks=[
                    SkillRiskResponse(
                        name="skill",
                        files=[
                            SkillFileSummary(name="first-file.md", type="instruction"),
                            SkillFileSummary(name="second-file.py", type="script"),
                        ],
                        risk_indexes=SkillRiskIndexes(
                            malicious_code=SkillRiskScore(score=100, evidence="low skill risk"),
                            secret_detection=SkillRiskScore(score=600, evidence="high skill risk"),
                        ),
                    )
                ],
            )
        ]
    )

    print_scan_response(response, show_all=True)

    output = capsys.readouterr().out
    assert output.index("Private data") < output.index("Dangerous words")
    assert output.index("Secret detection") < output.index("Malicious code")
    assert output.index("first-tool") < output.index("second-tool")
    assert output.index("first-file.md") < output.index("second-file.py")


def test_plain_scan_output_prints_every_component_and_analysis_error(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                error=ScanError(message="partial analysis failure", category="analysis_error", is_failure=True),
                server_risks=[
                    McpServerRiskResponse(
                        name=name,
                        risk_indexes=McpServerRiskIndexes(
                            dangerous_words=RiskScore(score=100, evidence=f"evidence for {name}")
                        ),
                    )
                    for name in ("first-server", "second-server")
                ],
                skill_risks=[
                    SkillRiskResponse(
                        name=name,
                        risk_indexes=SkillRiskIndexes(
                            malicious_code=SkillRiskScore(score=500, evidence=f"evidence for {name}")
                        ),
                    )
                    for name in ("first-skill", "second-skill")
                ]
                + [
                    SkillRiskResponse(
                        name="failed-skill",
                        error=ScanError(message="skill analysis failed", category="analysis_error", is_failure=True),
                    )
                ],
            )
        ]
    )

    print_scan_response(response)

    output = capsys.readouterr().out
    for name in ("first-server", "second-server", "first-skill", "second-skill"):
        assert name in output
    assert "partial analysis failure" in output
    assert "skill analysis failed" in output


def test_plain_scan_output_reports_clean_analysis(capsys):
    print_scan_response(
        ScanResponse(scan_path_responses=[ScanPathResponse(path="/config")]),
    )

    output = capsys.readouterr().out
    assert "Scanning /config" in output
    assert "no mcp servers found" in output


def test_plain_scan_output_uses_backend_enriched_entities(capsys):
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                path="/config",
                server_risks=[
                    McpServerRiskResponse(
                        name="server",
                        entities=[McpEntitySummary(name="catalog_tool", type="tool")],
                        risk_indexes=McpServerRiskIndexes(
                            private_data=RiskScore(score=750, evidence="reads data", affected_tools=[0])
                        ),
                    )
                ],
            )
        ]
    )

    print_scan_response(response)

    assert "Affected tools: catalog_tool" in capsys.readouterr().out
