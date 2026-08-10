import builtins
import os
from typing import Literal, cast, overload

import rich
from mcp.types import Prompt, Resource, ResourceTemplate, Tool
from rich.text import Text
from rich.traceback import Traceback as rTraceback
from rich.tree import Tree

from agent_scan.models import (
    FAILURE_CATEGORY_TO_CODE,
    Entity,
    InspectedPath,
    Issue,
    ScanError,
    ScanPathResult,
    ScanResponse,
    SkillFile,
    ToxicFlowExtraData,
)
from agent_scan.models.api.v20260710 import (
    RISK_DISPLAY_NAMES,
    RISK_SCORE_MAX,
    MaliciousURLSkillRiskScore,
    McpEntitySummary,
    McpServerRiskIndexes,
    McpServerRiskResponse,
    Region,
    RiskScore,
    ScanPathResponse,
    SkillFileSummary,
    SkillRiskIndexes,
    SkillRiskResponse,
    SkillRiskScore,
    UnverifiableURLSkillRiskScore,
)

MAX_ENTITY_NAME_LENGTH = 25
MAX_ENTITY_NAME_LENGTH_SKILL = 35
MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH = 30

RISK_SCORE_BANDS = (
    (299, "#e2d2f4"),
    (599, "#cbabee"),
    (999, "#9456d2"),
    (RISK_SCORE_MAX, "#8446c4"),
)


SEVERITY_COLOR_MAP = {
    None: "[green]",
    "info": "[blue]",
    "low": "[white]",
    "medium": "[yellow]",
    "high": "[orange_red1]",
    "critical": "[bold][red]",
}


def format_exception(e: Exception | str | None) -> tuple[str, rTraceback | None]:
    if e is None:
        return "", None
    if isinstance(e, str):
        return e, None
    name = builtins.type(e).__name__
    message = str(e).strip()
    cause = getattr(e, "__cause__", None)
    context = getattr(e, "__context__", None)
    parts = [f"{name}: {message}"]
    if cause is not None:
        parts.append(f"Caused by: {format_exception(cause)[0]}")
    if context is not None:
        parts.append(f"Context: {format_exception(context)[0]}")
    text = "\n".join(parts)
    tb = rTraceback.from_exception(builtins.type(e), e, getattr(e, "__traceback__", None))
    return text, tb


def format_error(
    e: ScanError, server_idx: int | None = None, entity_idx: int | None = None
) -> tuple[Issue, rTraceback | None]:
    status, traceback = format_exception(e.exception)
    if e.message:
        status = e.message
    if e.traceback:
        traceback = e.traceback
    return Issue(
        code=FAILURE_CATEGORY_TO_CODE[e.category],
        message=status,
        extra_data={
            "severity": "info",
        },
        reference=(server_idx, entity_idx) if server_idx is not None else None,
    ), traceback


def format_path_line(
    path: str, message: str | None = None, issues: list[Issue] | None = None, operation: str = "Scanning"
) -> Text:
    text = f"● {operation} [bold]{path}[/bold]"
    if issues:
        text += " " + format_issues(issues, new_line=False)
    if message is not None:
        text += f" [gray62]{message}[/gray62]"
    return Text.from_markup(text)


def format_servers_line(
    server: str,
    severities: list[Literal["info", "low", "medium", "high", "critical"]] | None = None,
    issues: list[Issue] | None = None,
) -> Text:
    max_severity = get_max_severity(severities) if severities is not None else None
    color = SEVERITY_COLOR_MAP[max_severity]
    text = f"{color}[bold]{server}[/bold]{color.replace('[', '[/')}"
    gap = 27
    text += " " * (max(0, gap - len(text)))

    # criticalities summary
    severity_levels: list[Literal["critical", "high", "medium", "low"]] = ["critical", "high", "medium", "low"]
    if severities is not None and len([s for s in severities if s != "info"]) > 0:
        severity_summary: list[str] = []
        total_findings = 0
        single_severity: Literal["critical", "high", "medium", "low"] | None = None
        for k in severity_levels:
            count = severities.count(k)
            if count == 0:
                continue
            total_findings += count
            single_severity = k
            severity_summary.append(f"{SEVERITY_COLOR_MAP[k]}{count} {k}{SEVERITY_COLOR_MAP[k].replace('[', '[/')}")
        if total_findings == 1 and single_severity is not None:
            color = SEVERITY_COLOR_MAP[single_severity]
            text += f" {color}1 {single_severity} finding{color.replace('[', '[/')}"
        else:
            text += f" {total_findings} findings ({', '.join(severity_summary)})"

    if issues:
        text += format_issues(issues, new_line=True)
    return Text.from_markup(text)


def get_severity(issue: Issue) -> Literal["info", "low", "medium", "high", "critical"]:
    if issue.code.startswith("X"):
        return "info"
    issue_severity = issue.extra_data.get("severity", None) if issue.extra_data is not None else None
    if issue_severity is None:
        if issue.code.startswith("W"):
            return "medium"
        elif issue.code.startswith("E"):
            return "high"
        else:
            return "info"
    if not isinstance(issue_severity, str):
        raise ValueError(f"Invalid severity type: {type(issue_severity)}")
    if issue_severity not in ["info", "low", "medium", "high", "critical"]:
        raise ValueError(
            f"Invalid severity: {issue_severity}. Expected one of: {['info', 'low', 'medium', 'high', 'critical']}"
        )
    return cast("Literal['info', 'low', 'medium', 'high', 'critical']", issue_severity)


def get_serverity_score(severity: Literal["info", "low", "medium", "high", "critical"]) -> int:
    return {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }[severity]


def get_max_severity(
    severities: list[Literal["info", "low", "medium", "high", "critical"]],
) -> Literal["info", "low", "medium", "high", "critical"] | None:
    max_severity = max([get_serverity_score(severity) for severity in severities], default=None)
    severity_levels: list[Literal["info", "low", "medium", "high", "critical"]] = [
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]
    return severity_levels[max_severity] if max_severity is not None else None


def format_issue(issue: Issue) -> str:
    severity = get_severity(issue)
    color_open = SEVERITY_COLOR_MAP[severity]
    color_close = color_open.replace("[", "[/")

    prefix = rf"● \[{issue.code} {severity}]:"

    if issue.code in ["W015", "W016", "W017", "W018"] and issue.extra_data is not None and "reason" in issue.extra_data:
        body = f"{issue.message} Reason: {issue.extra_data['reason']}"
    elif issue.code == "W001" and issue.extra_data is not None and "words" in issue.extra_data:
        words = ",".join([f'"{w}"' for w in issue.extra_data["words"]])
        body = f"Found the word{'s' if len(issue.extra_data['words']) > 1 else ''} {words} in the tool description. It is a common word used in prompt injection attacks."
    else:
        body = issue.message

    # Only color the severity prefix; keep the message body in the default
    # color so long descriptions remain readable.
    return f"{color_open}{prefix}{color_close} {body}"


def format_issues(issues: list[Issue], new_line: bool = False) -> str:
    # sort issues by severity
    issues.sort(key=lambda x: get_serverity_score(get_severity(x)), reverse=True)
    separator = "\n" if new_line else " "
    status_text = separator.join([format_issue(issue) for issue in issues])
    if new_line:
        status_text = "\n" + status_text
    return status_text


def format_entity_type(entity: Entity, is_skill: bool = False) -> str:
    if isinstance(entity, Prompt):
        return "prompt" if not is_skill else "instruction"
    elif isinstance(entity, Tool):
        return "tool" if not is_skill else "script"
    elif isinstance(entity, Resource):
        return "resource" if not is_skill else "asset"
    elif isinstance(entity, ResourceTemplate):
        return "res. temp." if not is_skill else "asset"
    else:
        raise ValueError(f"Unknown entity type: {type(entity)}")


def format_entity_line(
    entity: Entity,
    issues: list[Issue],
    inspect_mode: bool = False,
    is_skill: bool = False,
    full_description: bool = False,
) -> Text:
    include_description = len(issues) > 0

    # right-pad name
    name = entity.name
    if not full_description:
        max_name_length = MAX_ENTITY_NAME_LENGTH_SKILL if is_skill else MAX_ENTITY_NAME_LENGTH
        name = name + " " * max(0, max_name_length - len(name))

    # right-pad type (with at least one trailing space so it never abuts the name)
    type_str = format_entity_type(entity, is_skill)
    type_str = type_str + " " * (len("instruction") + 1 - len(type_str))
    # prompt     / instruction
    # tool       / script
    # resouce    / asset
    # res. temp. / asset

    status_text = format_issues(issues)
    text = f"{type_str}[bold]{name}[/bold]  {status_text}"

    if include_description:
        if hasattr(entity, "description") and entity.description is not None:
            description = entity.description
        else:
            description = "<no description available>"
        if not full_description and len(description) > 200:
            description = (
                description[:200]
                + f"... {len(description) - 200} characters truncated. Use --print-full-descriptions to see the full description."
            )
        # escape markdown in the description
        description = description.replace("[", r"\[").replace("]", r"\]")
        text += f"\n[gray62][bold]Description:[/bold]\n{description}[/gray62]"

    formatted_text = Text.from_markup(text)
    return formatted_text


def format_global_issue(result: ScanPathResult, issue: Issue, show_all: bool = False) -> Tree:
    """
    Format issues about the whole scan.
    """
    assert issue.reference is None, "Global issues should not have a reference"
    tree = Tree(f"[yellow]\n⚠️ [{issue.code}]: {issue.message}[/yellow]")

    def _format_tool_kind_name(tool_kind_name: str) -> str:
        return " ".join(tool_kind_name.split("_")).title()

    def _format_tool_name(server_name: str, tool_name: str, value: float) -> str:
        tool_string = f"{server_name}/{tool_name}"
        tool_string = tool_string + " " * max(0, MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH - len(tool_string))
        if value <= 1.5:
            severity = "[yellow]Low[/yellow]"
        elif value <= 2.5:
            severity = "[red]High[/red]"
        else:
            severity = "[bold][red]Critical[/red][/bold]"
        return f"{tool_string} {severity}"

    if not issue.code.startswith("TF"):
        return tree

    try:
        extra_data = ToxicFlowExtraData.model_validate(issue.extra_data)
    except Exception:
        tree.add("[gray62]Invalid extra data format[/gray62]")
        return tree

    for tool_kind_name, tool_references in extra_data.root.items():
        tool_references.sort(key=lambda x: x.label_value, reverse=True)
        tool_tree = tree.add(f"[bold]{_format_tool_kind_name(tool_kind_name)}[/bold]")
        for tool_reference in tool_references[: 3 if not show_all else None]:
            tool_tree.add(
                _format_tool_name(
                    result.servers[tool_reference.reference[0]].name if result.servers is not None else "",
                    result.servers[tool_reference.reference[0]].signature.entities[tool_reference.reference[1]].name
                    if result.servers is not None
                    else "",
                    tool_reference.label_value,
                )
            )
        if len(tool_references) > 3 and not show_all:
            tool_tree.add(
                f"[gray62]... and {len(tool_references) - 3} more tools (to see all, use --full-toxic-flows)[/gray62]"
            )
    return tree


def print_scan_path_result(
    result: ScanPathResult,
    print_errors: bool = False,
    inspect_mode: bool = False,
    full_description: bool = False,
    args=None,
) -> None:
    issues = []
    if result.error is not None:
        error_issue, traceback = format_error(result.error)
        issues.append(error_issue)
        if print_errors and traceback is not None:
            console = rich.console.Console()
            console.print(traceback)

    server_count = 0
    skill_count = 0
    for server in result.servers or []:
        if server.server.type == "skill":
            skill_count += 1
        else:
            server_count += 1

    report_skills = hasattr(args, "skills") and args.skills
    if server_count > 0 and skill_count > 0:
        message = f"found {server_count} mcp server{'' if server_count == 1 else 's'} and {skill_count} skill{'' if skill_count == 1 else 's'}"
    elif server_count > 0:
        message = f"found {server_count} mcp server{'' if server_count == 1 else 's'}"
    elif skill_count > 0:
        message = f"found {skill_count} skill{'' if skill_count == 1 else 's'}"
    elif report_skills:
        message = "no mcp servers or skills found"
    else:
        message = "no mcp servers found"
    rich.print(format_path_line(result.path, message, issues))
    path_print_tree = Tree("│")
    server_tracebacks = []
    for server_idx, server in enumerate(result.servers or []):
        server_issues = [issue for issue in result.issues if issue.reference == (server_idx, None)]
        severities = [
            get_severity(issue)
            for issue in result.issues
            if issue.reference is not None and issue.reference[0] == server_idx
        ]
        if server.error is not None:
            error_issue, traceback = format_error(server.error, server_idx)
            server_issues.append(error_issue)
            if traceback is not None:
                server_tracebacks.append((server, traceback))
            severities.append("info")
        server_print = path_print_tree.add(format_servers_line(server.name or "", severities, server_issues))
        for entity_idx, entity in enumerate(server.entities):
            issues = [issue for issue in result.issues if issue.reference == (server_idx, entity_idx)]
            server_print.add(
                format_entity_line(
                    entity,
                    issues,
                    inspect_mode,
                    is_skill=server.server.type == "skill",
                    full_description=full_description,
                )
            )

    if result.servers is not None and len(result.servers) > 0:
        rich.print(path_print_tree)

    # print global issues
    for issue in result.issues:
        if issue.reference is None:
            rich.print(format_global_issue(result, issue, True))

    if print_errors and len(server_tracebacks) > 0:
        console = rich.console.Console()
        for server, traceback in server_tracebacks:
            console.print()
            console.print("[bold]Exception when scanning " + (server.name or "") + "[/bold]")
            console.print(traceback)
    print(end="", flush=True)


def print_scan_result(
    result: list[ScanPathResult],
    print_errors: bool = False,
    inspect_mode: bool = False,
    internal_issues: bool = False,
    full_description: bool = False,
    args=None,
) -> None:
    if not result:
        rich.print("No MCP client configurations found on this machine.")
        return
    if not internal_issues:
        for res in result:
            res.issues = [issue for issue in res.issues if issue.code not in ["W003", "W004", "W005", "W006"]]
    for i, path_result in enumerate(result):
        print_scan_path_result(path_result, print_errors, inspect_mode, full_description, args)
        if i < len(result) - 1:
            rich.print()


# ---------------------------------------------------------------------------
# InspectedPath rendering for the `inspect` command.
# `inspect` never analyzes, so there are no risks/issues here - just the
# discovered MCP servers (with their tool/prompt/resource entities) and skills
# (with their files).
# ---------------------------------------------------------------------------


def _skill_file_type(path: str) -> str:
    """Human label for a skill file, mirroring ``format_entity_type``'s skill names."""
    lowered = path.lower()
    if lowered.endswith(".md"):
        return "instruction"
    if lowered.rsplit(".", 1)[-1] in ("py", "js", "ts", "sh"):
        return "script"
    return "asset"


def format_skill_file_line(skill_file: SkillFile, full_description: bool = False) -> Text:
    name = skill_file.path
    if not full_description:
        name = name + " " * max(0, MAX_ENTITY_NAME_LENGTH_SKILL - len(name))
    type_str = _skill_file_type(skill_file.path)
    type_str = type_str + " " * (len("instruction") + 1 - len(type_str))
    result = Text(type_str)
    result.append(name, style="bold")
    return result


def print_inspected_path(
    path: InspectedPath,
    print_errors: bool = False,
    full_description: bool = False,
    args=None,
) -> None:
    issues = []
    if path.error is not None:
        error_issue, traceback = format_error(path.error)
        issues.append(error_issue)
        if print_errors and traceback is not None:
            rich.console.Console().print(traceback)

    server_count = len(path.servers)
    skill_count = len(path.skills)
    report_skills = hasattr(args, "skills") and args.skills
    if server_count > 0 and skill_count > 0:
        message = f"found {server_count} mcp server{'' if server_count == 1 else 's'} and {skill_count} skill{'' if skill_count == 1 else 's'}"
    elif server_count > 0:
        message = f"found {server_count} mcp server{'' if server_count == 1 else 's'}"
    elif skill_count > 0:
        message = f"found {skill_count} skill{'' if skill_count == 1 else 's'}"
    elif report_skills:
        message = "no mcp servers or skills found"
    else:
        message = "no mcp servers found"
    rich.print(format_path_line(path.path, message, issues))

    tree = Tree("│")
    tracebacks: list[tuple[str, rTraceback]] = []
    for server in path.servers:
        server_issues = []
        severities: list[Literal["info", "low", "medium", "high", "critical"]] | None = None
        if server.error is not None:
            error_issue, traceback = format_error(server.error)
            server_issues.append(error_issue)
            severities = ["info"]
            if traceback is not None:
                tracebacks.append((server.name, traceback))
        server_print = tree.add(format_servers_line(server.name, severities, server_issues))
        entities = server.signature.entities if server.signature is not None else []
        for entity in entities:
            server_print.add(
                format_entity_line(entity, [], inspect_mode=True, is_skill=False, full_description=full_description)
            )
    for skill in path.skills:
        skill_issues = []
        severities = None
        if skill.error is not None:
            error_issue, traceback = format_error(skill.error)
            skill_issues.append(error_issue)
            severities = ["info"]
            if traceback is not None:
                tracebacks.append((skill.name, traceback))
        skill_print = tree.add(format_servers_line(skill.name, severities, skill_issues))
        for skill_file in skill.files:
            skill_print.add(format_skill_file_line(skill_file, full_description))

    if server_count > 0 or skill_count > 0:
        rich.print(tree)

    if print_errors and tracebacks:
        console = rich.console.Console()
        for name, traceback in tracebacks:
            console.print()
            console.print(f"[bold]Exception when scanning {name}[/bold]")
            console.print(traceback)
    print(end="", flush=True)


def print_inspected_machine(
    paths: list[InspectedPath],
    print_errors: bool = False,
    full_description: bool = False,
    args=None,
) -> None:
    if not paths:
        rich.print("No MCP client configurations found on this machine.")
        return
    for i, path in enumerate(paths):
        print_inspected_path(path, print_errors, full_description, args)
        if i < len(paths) - 1:
            rich.print()
    print(end="", flush=True)


def _format_region(region: Region) -> str:
    start = region.start
    location = start.path
    if start.line is not None:
        location += f":{start.line}"
        if start.offset is not None:
            location += f":{start.offset}"
    if region.end is not None:
        location += f"-{_format_region(Region(start=region.end))}"
    return location


def _format_response_entity_line(entity: McpEntitySummary) -> Text:
    type_names = {
        "prompt": "prompt",
        "resource": "resource",
        "resource_template": "res. temp.",
        "tool": "tool",
    }
    type_str = type_names[entity.type]
    type_str += " " * (len("instruction") + 1 - len(type_str))
    name = entity.name + " " * max(0, MAX_ENTITY_NAME_LENGTH - len(entity.name))
    result = Text(type_str)
    result.append(name, style="bold")
    return result


def _format_response_skill_file_line(skill_file: SkillFileSummary) -> Text:
    type_str = skill_file.type + " " * (len("instruction") + 1 - len(skill_file.type))
    name = skill_file.name + " " * max(0, MAX_ENTITY_NAME_LENGTH_SKILL - len(skill_file.name))
    result = Text(type_str)
    result.append(name, style="bold")
    return result


def _risk_score_color(score: int) -> str:
    """Map an Agent Scan score to the same risk bands used by Maverick."""
    for upper_bound, color in RISK_SCORE_BANDS:
        if score <= upper_bound:
            return color
    return RISK_SCORE_BANDS[-1][1]


@overload
def _sorted_risks(risk_indexes: McpServerRiskIndexes) -> list[tuple[str, RiskScore]]: ...


@overload
def _sorted_risks(risk_indexes: SkillRiskIndexes) -> list[tuple[str, SkillRiskScore]]: ...


def _sorted_risks(
    risk_indexes: McpServerRiskIndexes | SkillRiskIndexes,
) -> list[tuple[str, RiskScore | SkillRiskScore]]:
    """Return detected risks highest-first, preserving model order for ties."""
    risks = [(name, risk) for name, risk in risk_indexes if risk is not None]
    return sorted(risks, key=lambda item: item[1].score, reverse=True)


def _format_component_line(name: str, risk_scores: list[int], *, has_error: bool = False) -> Text:
    result = Text()
    if risk_scores:
        color = _risk_score_color(max(risk_scores))
    elif has_error:
        color = "blue"
    else:
        color = "green"
    result.append(name, style=f"bold {color}")
    if risk_scores:
        risk_count = len(risk_scores)
        result.append(f" {risk_count} risk{'' if risk_count == 1 else 's'}")
    return result


def _format_response_error(error: ScanError) -> Text:
    code = FAILURE_CATEGORY_TO_CODE[error.category]
    result = Text(f"● [{code} info]: ", style="blue")
    result.append(error.message or str(error.exception or "unknown error"))
    return result


def _format_scan_path_line(path: str, message: str, error: ScanError | None) -> Text:
    result = Text("● Scanning ")
    result.append(path, style="bold")
    if error is not None:
        result.append(" ")
        result.append(_format_response_error(error))
    result.append(f" {message}", style="gray62")
    return result


def _format_risk(
    name: str,
    risk: RiskScore | SkillRiskScore,
    *,
    affected_tools: list[str] | None = None,
) -> Text:
    color = _risk_score_color(risk.score)
    line = Text()
    line.append("● ", style=color)
    line.append(RISK_DISPLAY_NAMES[name], style=f"bold {color}")
    line.append(f" ({risk.score}/{RISK_SCORE_MAX})", style=f"bold {color}")
    line.append(f": {risk.evidence}")
    if affected_tools:
        line.append("\n  Affected tools: ", style="bold gray62")
        line.append(", ".join(affected_tools))
    locations = getattr(risk, "locations", None)
    if locations:
        line.append("\n  Locations: ", style="bold gray62")
        line.append(", ".join(_format_region(region) for region in locations))
    if isinstance(risk, MaliciousURLSkillRiskScore):
        if risk.malicious_urls:
            line.append("\n  Malicious URLs: ", style="bold gray62")
            line.append(", ".join(risk.malicious_urls))
    elif isinstance(risk, UnverifiableURLSkillRiskScore) and risk.unverifiable_urls:
        line.append("\n  Unverifiable URLs: ", style="bold gray62")
        line.append(", ".join(risk.unverifiable_urls))
    return line


def _append_component_detail(component: Text, detail: Text) -> None:
    component.append("\n")
    component.append(detail)


def _add_server(parent: Tree, server: McpServerRiskResponse) -> None:
    risks = _sorted_risks(server.risk_indexes)
    component = _format_component_line(
        server.name,
        [risk.score for _, risk in risks],
        has_error=server.error is not None,
    )
    for name, risk in risks:
        tools = []
        for index in risk.affected_tools or []:
            if 0 <= index < len(server.entities):
                tools.append(server.entities[index].name)
            else:
                tools.append(str(index))
        _append_component_detail(component, _format_risk(name, risk, affected_tools=tools))
    if server.error is not None:
        _append_component_detail(component, _format_response_error(server.error))
    server_tree = parent.add(component)
    for entity in server.entities:
        server_tree.add(_format_response_entity_line(entity))


def _add_skill(parent: Tree, skill: SkillRiskResponse) -> None:
    risks = _sorted_risks(skill.risk_indexes)
    component = _format_component_line(
        skill.name,
        [risk.score for _, risk in risks],
        has_error=skill.error is not None,
    )
    for name, risk in risks:
        _append_component_detail(component, _format_risk(name, risk))
    if skill.error is not None:
        _append_component_detail(component, _format_response_error(skill.error))
    skill_tree = parent.add(component)
    for skill_file in skill.files:
        skill_tree.add(_format_response_skill_file_line(skill_file))


def _scan_path_message(path: ScanPathResponse, report_skills: bool) -> str:
    server_count = len(path.server_risks)
    skill_count = len(path.skill_risks)
    if server_count and skill_count:
        return f"found {server_count} mcp server{'' if server_count == 1 else 's'} and {skill_count} skill{'' if skill_count == 1 else 's'}"
    if server_count:
        return f"found {server_count} mcp server{'' if server_count == 1 else 's'}"
    if skill_count:
        return f"found {skill_count} skill{'' if skill_count == 1 else 's'}"
    return "no mcp servers or skills found" if report_skills else "no mcp servers found"


def _print_scan_path_response(
    path: ScanPathResponse,
    *,
    print_errors: bool,
    report_skills: bool,
) -> None:
    rich.print(
        _format_scan_path_line(
            os.path.expanduser(path.path),
            _scan_path_message(path, report_skills),
            path.error,
        )
    )

    tree = Tree("│")
    for server in path.server_risks:
        _add_server(tree, server)
    for skill in path.skill_risks:
        _add_skill(tree, skill)
    if path.server_risks or path.skill_risks:
        rich.print(tree)

    if print_errors:
        errors = [path.error]
        errors.extend(server.error for server in path.server_risks)
        errors.extend(skill.error for skill in path.skill_risks)
        for error in errors:
            if error is not None and error.traceback:
                rich.print(Text(error.traceback))


def print_scan_response(
    response: ScanResponse,
    print_errors: bool = False,
    args=None,
) -> None:
    """Render the complete backend-enriched results, with risks under each component."""
    if not response.scan_path_responses:
        rich.print("No MCP client configurations found on this machine.")
        return
    report_skills = hasattr(args, "skills") and args.skills
    for index, path in enumerate(response.scan_path_responses):
        _print_scan_path_response(path, print_errors=print_errors, report_skills=report_skills)
        if index < len(response.scan_path_responses) - 1:
            rich.print()
