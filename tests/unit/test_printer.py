from mcp.types import Implementation, InitializeResult, Prompt, ServerCapabilities, Tool

from agent_scan.models import Issue, ScanPathResult, ServerScanResult, ServerSignature, StdioServer
from agent_scan.printer import format_entity_line, format_servers_line, print_scan_result


class TestFormatServersLine:
    def test_no_severities(self):
        result = format_servers_line("my-server").plain
        assert "my-server" in result
        assert "finding" not in result

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


def _result_with_findings() -> ScanPathResult:
    """A scan result with a server, one tool entity, and both an entity-level
    and a server-level security finding."""
    server = ServerScanResult(
        name="github",
        server=StdioServer(command="run"),
        signature=ServerSignature(
            metadata=InitializeResult(
                protocolVersion="2024-11-05",
                capabilities=ServerCapabilities(),
                serverInfo=Implementation(name="github", version="1.0"),
            ),
            tools=[Tool(name="create_issue", description="dangerous tool", inputSchema={"type": "object"})],
        ),
    )
    return ScanPathResult(
        path="/test/path",
        servers=[server],
        issues=[
            Issue(code="E001", message="entity finding", reference=(0, 0), extra_data={"severity": "high"}),
            Issue(code="W001", message="server finding", reference=(0, None), extra_data={"severity": "medium"}),
        ],
    )


class TestPrintScanResultShowFindings:
    """--no-findings hides security findings while keeping the discovery tree."""

    def test_findings_shown_by_default(self, capsys):
        print_scan_result([_result_with_findings()])
        out = capsys.readouterr().out
        # discovery + findings both present
        assert "github" in out
        assert "create_issue" in out
        assert "E001" in out
        assert "entity finding" in out
        assert "finding" in out  # severity summary line

    def test_show_findings_true_prints_issue(self, capsys):
        print_scan_result([_result_with_findings()], show_findings=True)
        out = capsys.readouterr().out
        assert "E001" in out
        assert "entity finding" in out

    def test_no_findings_hides_issues_keeps_discovery(self, capsys):
        result = _result_with_findings()
        print_scan_result([result], show_findings=False)
        out = capsys.readouterr().out
        # discovery is preserved
        assert "github" in out
        assert "create_issue" in out
        # findings are suppressed
        assert "E001" not in out
        assert "W001" not in out
        assert "entity finding" not in out
        assert "server finding" not in out
        assert "finding" not in out  # severity summary gone
        # the live result object is not mutated (guards --ci / push behavior)
        assert sorted(i.code for i in result.issues) == ["E001", "W001"]
