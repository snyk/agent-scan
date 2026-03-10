import builtins
from typing import Literal, cast

import rich
from mcp.types import Prompt, Resource, ResourceTemplate, Tool
from rich.text import Text
from rich.traceback import Traceback as rTraceback
from rich.tree import Tree

from agent_scan.models import (
    Entity,
    Issue,
    ScanError,
    ScanPathResult,
    ToxicFlowExtraData,
)

MAX_ENTITY_NAME_LENGTH = 25
MAX_ENTITY_NAME_LENGTH_SKILL = 35
MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH = 30

ISSUE_COLOR_MAP = {
    "successful": "[green]",
    "issue": "[red]",
    "analysis_error": "[gray62]",
    "warning": "[yellow]",
    "inspect_mode": "[white]",
}

SEVERITY_COLOR_MAP = {
    None: "[green]",
    "info": "[blue]",
    "low": "[white]",
    "medium": "[yellow]",
    "high": "[orange_red1]",
    "critical": "[bold][red]",
}
ICON_MAP = {
    "ok": ":white_heavy_check_mark:",
    "error": ":cross_mark:",
    "analysis_error": "",
    "warning": "⚠️ ",
    "whitelisted": ":white_heavy_check_mark:",
    "inspect_mode": "  ",
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
    e: ScanError, server_idx: int | None = None, entity_idx: int | None = None, code: str = "X001"
) -> tuple[Issue, rTraceback | None]:
    status, traceback = format_exception(e.exception)
    if e.message:
        status = e.message
    if e.traceback:
        traceback = e.traceback
    return Issue(
        code=code,
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
        for k in severity_levels:
            count = severities.count(k)
            if count == 0:
                continue
            severity_summary.append(f"{SEVERITY_COLOR_MAP[k]}{count} {k}{SEVERITY_COLOR_MAP[k].replace('[', '[/')}")
        text += f" ({', '.join(severity_summary)})"

    if issues:
        text += format_issues(issues, new_line=True)
    return Text.from_markup(text)


def append_status(status: str, new_status: str) -> str:
    if status == "":
        return new_status
    return f"{new_status}, {status}"


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
    issue_str = rf"● \[{issue.code} {get_severity(issue)}]: "

    if issue.code in ["W015", "W016", "W017", "W018"] and issue.extra_data is not None and "reason" in issue.extra_data:
        issue_str += f"{issue.message} Reason: {issue.extra_data['reason']}"
    elif issue.code == "W001" and issue.extra_data is not None and "words" in issue.extra_data:
        words = ",".join([f'"{w}"' for w in issue.extra_data["words"]])
        issue_str += f"Found the word{'s' if len(issue.extra_data['words']) > 1 else ''} {words} in the tool description. It is a common word used in prompt injection attacks."
    else:
        issue_str += f"{issue.message}"
    return (
        SEVERITY_COLOR_MAP[get_severity(issue)] + issue_str + SEVERITY_COLOR_MAP[get_severity(issue)].replace("[", "[/")
    )


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
    # is_verified = verified.value
    # if is_verified is not None and changed.value is not None:
    #     is_verified = is_verified and not changed.value
    include_description = len(issues) > 0

    # right-pad & truncate name
    name = entity.name
    if not full_description:
        max_name_length = MAX_ENTITY_NAME_LENGTH_SKILL if is_skill else MAX_ENTITY_NAME_LENGTH
        if len(name) > max_name_length:
            name = name[: (max_name_length - 3)] + "..."
        name = name + " " * (max_name_length - len(name))

    # right-pad type
    type_str = format_entity_type(entity, is_skill)
    type_str = type_str + " " * (len("instruction") - len(type_str))
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


def format_tool_flow(tool_name: str, server_name: str, value: float) -> Text:
    text = "{tool_name} {risk}"
    tool_name = f"{server_name}/{tool_name}"
    if len(tool_name) > MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH:
        tool_name = tool_name[: (MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH - 3)] + "..."
    tool_name = tool_name + " " * (MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH - len(tool_name))

    risk = "[yellow]Low[/yellow]" if value <= 1.5 else "[red]High[/red]"
    return Text.from_markup(text.format(tool_name=tool_name, risk=risk))


def format_global_issue(result: ScanPathResult, issue: Issue, show_all: bool = False) -> Tree:
    """
    Format issues about the whole scan.
    """
    assert issue.reference is None, "Global issues should not have a reference"
    # assert issue.code in ["TF001", "TF002", "W002"] , (
    #     f"Only issues with code TF001, TF002 or W002 can be global issues. {issue.code}"
    # )
    tree = Tree(f"[yellow]\n⚠️ [{issue.code}]: {issue.message}[/yellow]")

    def _format_tool_kind_name(tool_kind_name: str) -> str:
        return " ".join(tool_kind_name.split("_")).title()

    def _format_tool_name(server_name: str, tool_name: str, value: float) -> str:
        tool_string = f"{server_name}/{tool_name}"
        if len(tool_string) > MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH:
            tool_string = tool_string[: (MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH - 3)] + "..."
        tool_string = tool_string + " " * (MAX_ENTITY_NAME_TOXIC_FLOW_LENGTH - len(tool_string))
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
) -> None:
    if result.error is not None:
        error_issue, traceback = format_error(result.error, None, None)
        rich.print(format_path_line(result.path, issues=[error_issue]))
        if print_errors and traceback is not None:
            console = rich.console.Console()
            console.print(traceback)
        return

    server_count = 0
    skill_count = 0
    for server in result.servers or []:
        if server.server.type == "skill":
            skill_count += 1
        else:
            server_count += 1
    if server_count > 0 and skill_count > 0:
        message = f"found {server_count} mcp server{'' if server_count == 1 else 's'} and {skill_count} skill{'' if skill_count == 1 else 's'}"
    elif server_count > 0:
        message = f"found {server_count} mcp server{'' if server_count == 1 else 's'}"
    elif skill_count > 0:
        message = f"found {skill_count} skill{'' if skill_count == 1 else 's'}"
    else:
        message = "no servers or skills found"
    rich.print(format_path_line(result.path, message))
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
            error_issue, traceback = format_error(server.error, server_idx, code="X003")
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
) -> None:
    if not internal_issues:
        for res in result:
            res.issues = [issue for issue in res.issues if issue.code not in ["W003", "W004", "W005", "W006"]]
    for i, path_result in enumerate(result):
        print_scan_path_result(path_result, print_errors, inspect_mode, full_description)
        if i < len(result) - 1:
            rich.print()
    print(end="", flush=True)
