import types

from mcp.types import Implementation, InitializeResult, Prompt, Tool

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
)
from agent_scan.printer import (
    _format_component_line,
    format_entity_line,
    format_servers_line,
    format_skill_file_line,
    print_inspected_machine,
    print_scan_response,
)


class TestFormatServersLine:
    def test_no_severities(self):
        result = format_servers_line("my-server")
        assert "my-server" in result.plain
        assert "finding" not in result.plain
        assert any(str(span.style) == "green" for span in result.spans)

    def test_only_info_severities_are_ignored(self):
        result = format_servers_line("my-server", severities=["info", "info"]).plain
        assert "finding" not in result
        assert "(" not in result

    def test_single_finding_uses_singular_form(self):
        result = format_servers_line("my-server", severities=["medium"]).plain
        assert "1 medium finding" in result
        assert "findings" not in result
        assert "(" not in result

    def test_single_finding_critical(self):
        result = format_servers_line("my-server", severities=["critical"]).plain
        assert "1 critical finding" in result

    def test_multiple_findings_show_total_and_breakdown(self):
        result = format_servers_line("my-server", severities=["medium", "medium", "medium", "low"]).plain
        assert "4 findings" in result
        assert "(3 medium, 1 low)" in result

    def test_multiple_findings_ignores_info(self):
        result = format_servers_line("my-server", severities=["medium", "low", "info", "info"]).plain
        assert "2 findings" in result
        assert "(1 medium, 1 low)" in result

    def test_multiple_findings_orders_by_severity(self):
        result = format_servers_line("my-server", severities=["low", "critical", "medium", "high"]).plain
        assert "4 findings" in result
        assert "(1 critical, 1 high, 1 medium, 1 low)" in result

    def test_server_name_is_included(self):
        result = format_servers_line("my-server", severities=["high"]).plain
        assert "my-server" in result


def test_scan_component_line_preserves_legacy_green_style():
    result = _format_component_line("my-server", risk_count=1)

    assert result.plain == "my-server 1 risk"
    assert any("green" in str(span.style) for span in result.spans)


class TestFormatEntityLine:
    def test_skill_instruction_has_space_before_name(self):
        entity = Prompt(name="SKILL.md", description=None)
        result = format_entity_line(entity, issues=[], is_skill=True).plain
        assert "instruction SKILL.md" in result
        assert "instructionSKILL.md" not in result

    def test_skill_script_has_space_before_name(self):
        entity = Tool(name="run.sh", description=None, inputSchema={"type": "object"})
        result = format_entity_line(entity, issues=[], is_skill=True).plain
        assert "script" in result
        assert "run.sh" in result
        assert "scriptrun.sh" not in result

    def test_non_skill_tool_has_space_before_name(self):
        entity = Tool(name="my_tool", description=None, inputSchema={"type": "object"})
        result = format_entity_line(entity, issues=[], is_skill=False).plain
        assert "tool" in result
        assert "my_tool" in result
        assert "toolmy_tool" not in result

    def test_non_skill_prompt_has_space_before_name(self):
        entity = Prompt(name="my_prompt", description=None)
        result = format_entity_line(entity, issues=[], is_skill=False).plain
        assert "prompt" in result
        assert "my_prompt" in result
        assert "promptmy_prompt" not in result

    def test_full_description_skill_still_has_space(self):
        # With full_description=True the name isn't right-padded, so the type
        # padding is the only thing keeping it separated from the name.
        entity = Prompt(name="SKILL.md", description=None)
        result = format_entity_line(entity, issues=[], is_skill=True, full_description=True).plain
        assert "instruction SKILL.md" in result
        assert "instructionSKILL.md" not in result


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
    assert "Private data (score: 750)" in output
    assert "Reads private records" in output
    assert "Affected tools: catalog_tool" in output
    assert "Suspicious download URL (score: 900)" in output
    assert "SKILL.md:12:3" in output
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


def test_plain_scan_output_preserves_components_and_nests_risks(capsys):
    """Dropping clean components or flattening risks away from their owner is a scan-output regression."""
    response = ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                client="cursor",
                path="~/.cursor",
                server_risks=[
                    McpServerRiskResponse(
                        name="clean-server",
                        entities=[McpEntitySummary(name="clean_tool", type="tool")],
                    ),
                    McpServerRiskResponse(
                        name="risky-server",
                        entities=[McpEntitySummary(name="risky_tool", type="tool")],
                        risk_indexes=McpServerRiskIndexes(
                            private_data=RiskScore(
                                score=300,
                                evidence="Reads private records",
                                affected_tools=[0],
                            )
                        ),
                    ),
                ],
                skill_risks=[
                    SkillRiskResponse(
                        name="clean-skill",
                        files=[SkillFileSummary(name="SKILL.md", type="instruction")],
                    ),
                    SkillRiskResponse(
                        name="risky-skill",
                        files=[SkillFileSummary(name="scripts/run.py", type="script")],
                        risk_indexes=SkillRiskIndexes(
                            malicious_code=SkillRiskScore(score=600, evidence="Runs untrusted code")
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
    assert "clean_tool" in output
    assert "clean-skill" in output
    assert "SKILL.md" in output
    assert "risky-server" in output
    assert "risky_tool" in output
    assert "Private data (score: 300)" in output
    assert "risky-skill" in output
    assert "scripts/run.py" in output
    assert "Malicious code (score: 600)" in output

    # Preserve the old hierarchy: each risk appears after its owner and before
    # the next sibling component, rather than in a separate flat risk report.
    assert output.index("risky-server") < output.index("Private data") < output.index("clean-skill")
    assert output.index("risky-skill") < output.index("Malicious code") < output.index("scripts/run.py")

    # Match the legacy issue layout: findings are continuation lines in the
    # component label, not child nodes with their own tree connectors.
    private_data_line = next(line for line in output.splitlines() if "Private data" in line)
    malicious_code_line = next(line for line in output.splitlines() if "Malicious code" in line)
    assert "├── ●" not in private_data_line and "└── ●" not in private_data_line
    assert "├── ●" not in malicious_code_line and "└── ●" not in malicious_code_line


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
