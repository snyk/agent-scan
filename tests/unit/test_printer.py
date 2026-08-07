import types

from mcp.types import Implementation, InitializeResult, Prompt, Tool

from agent_scan.models import InspectedPath, InspectedServer, InspectedSkill, ServerSignature, SkillFile, StdioServer
from agent_scan.printer import format_entity_line, format_servers_line, format_skill_file_line, print_inspected_machine


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
