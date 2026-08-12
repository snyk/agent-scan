import os
from collections import Counter
from collections.abc import Sequence
from typing import overload

import rich
from mcp.types import Prompt, Resource, ResourceTemplate, Tool
from rich.text import Text
from rich.tree import Tree

from agent_scan.models import (
    FAILURE_CATEGORY_TO_CODE,
    Entity,
    InspectedPath,
    ScanError,
    ScanResponse,
    SkillFile,
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
INSPECTED_COMPONENT_NAME_COLUMN_WIDTH = 14
INSPECTION_ERROR_MESSAGE_FALLBACK = "could not complete inspection"
SCAN_ERROR_MESSAGE_FALLBACK = "could not complete scan"

RISK_SCORE_BANDS = (
    (299, "#e2d2f4"),
    (599, "#cbabee"),
    (999, "#9456d2"),
    (RISK_SCORE_MAX, "#8446c4"),
)

MCP_ENTITY_TYPE_ORDER = ("tool", "prompt", "resource", "resource_template")
MCP_ENTITY_TYPE_LABELS = {
    "tool": "tool",
    "prompt": "prompt",
    "resource": "resource",
    "resource_template": "resource template",
}
SKILL_FILE_TYPE_ORDER = ("instruction", "script", "asset")


def _format_entity_type(entity: Entity) -> str:
    if isinstance(entity, Prompt):
        return "prompt"
    elif isinstance(entity, Tool):
        return "tool"
    elif isinstance(entity, Resource):
        return "resource"
    elif isinstance(entity, ResourceTemplate):
        return "res. temp."
    else:
        raise ValueError(f"Unknown entity type: {type(entity)}")


# ---------------------------------------------------------------------------
# InspectedPath rendering for the `inspect` command.
# `inspect` never analyzes, so there are no risks/issues here - just the
# discovered MCP servers (with their tool/prompt/resource entities) and skills
# (with their files).
# ---------------------------------------------------------------------------


def _skill_file_type(path: str) -> str:
    """Return the human-readable type used for a collected skill file."""
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


def _format_inspected_entity_line(entity: Entity, full_description: bool = False) -> Text:
    name = entity.name
    if not full_description:
        name += " " * max(0, MAX_ENTITY_NAME_LENGTH - len(name))
    type_str = _format_entity_type(entity)
    type_str += " " * (len("instruction") + 1 - len(type_str))
    result = Text(type_str)
    result.append(name, style="bold")
    result.append("  ")
    return result


def _format_inspection_error(error: ScanError) -> Text:
    code = FAILURE_CATEGORY_TO_CODE[error.category]
    result = Text(f"● [{code} info]:", style="blue")
    result.append(f" {error.message or INSPECTION_ERROR_MESSAGE_FALLBACK}")
    return result


def _format_inspected_path_line(path: str, message: str, error: ScanError | None) -> Text:
    result = Text("● Scanning ")
    result.append(path, style="bold")
    if error is not None:
        result.append(" ")
        result.append(_format_inspection_error(error))
    result.append(f" {message}", style="gray62")
    return result


def _format_inspected_component_header(name: str, error: ScanError | None) -> Text:
    result = Text(name, style=f"bold {'blue' if error is not None else 'green'}")
    result.append(" " * max(0, INSPECTED_COMPONENT_NAME_COLUMN_WIDTH - len(name)))
    if error is not None:
        result.append("\n")
        result.append(_format_inspection_error(error))
    return result


def print_inspected_path(
    path: InspectedPath,
    print_errors: bool = False,
    full_description: bool = False,
    args=None,
) -> None:
    if path.error is not None and print_errors and path.error.traceback:
        rich.console.Console().print(path.error.traceback)

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
    rich.print(_format_inspected_path_line(path.path, message, path.error))

    tree = Tree("│")
    tracebacks: list[tuple[str, str]] = []
    for server in path.servers:
        if server.error is not None and server.error.traceback:
            tracebacks.append((server.name, server.error.traceback))
        server_node = tree.add(_format_inspected_component_header(server.name, server.error))
        entities = server.signature.entities if server.signature is not None else []
        for entity in entities:
            server_node.add(_format_inspected_entity_line(entity, full_description))
    for skill in path.skills:
        if skill.error is not None and skill.error.traceback:
            tracebacks.append((skill.name, skill.error.traceback))
        skill_node = tree.add(_format_inspected_component_header(skill.name, skill.error))
        for skill_file in skill.files:
            skill_node.add(format_skill_file_line(skill_file, full_description))

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


def _format_type_counts(
    types: Sequence[str],
    order: tuple[str, ...],
    labels: dict[str, str] | None = None,
    *,
    count_suffix: str = "",
    count_suffix_by_type: dict[str, str] | None = None,
) -> str:
    labels = labels or {}
    count_suffix_by_type = count_suffix_by_type or {}
    counts = Counter(types)
    parts = []
    for item_type in order:
        count = counts[item_type]
        if count:
            label = labels.get(item_type, item_type)
            suffix = count_suffix_by_type.get(item_type, count_suffix)
            parts.append(f"{count}{suffix} {label}{'' if count == 1 else 's'}")
    return ", ".join(parts)


def _append_compact_counts_to_header(component: Text, summary: str) -> None:
    if summary:
        component.append(f"  {summary}", style="gray62")


def _add_undisplayed_item_counts(parent: Tree, summary: str, *, follows_visible_items: bool) -> None:
    if summary:
        prefix = "and" if follows_visible_items else "contains"
        parent.add(Text(f"{prefix} {summary}", style="gray62"))


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
    result.append(error.message or SCAN_ERROR_MESSAGE_FALLBACK)
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


def _collect_risk_affected_entity_indexes(
    server: McpServerRiskResponse,
    risks: list[tuple[str, RiskScore]],
) -> set[int]:
    return {index for _, risk in risks for index in (risk.affected_tools or []) if 0 <= index < len(server.entities)}


def _add_server_entities(
    parent: Tree,
    server: McpServerRiskResponse,
    affected_entity_indexes: set[int],
    *,
    has_risks: bool,
    show_all: bool,
) -> None:
    visible_indexes = set(range(len(server.entities))) if show_all else affected_entity_indexes
    for index, entity in enumerate(server.entities):
        if index in visible_indexes:
            parent.add(_format_response_entity_line(entity))

    if not has_risks or show_all:
        return
    remaining = [entity.type for index, entity in enumerate(server.entities) if index not in affected_entity_indexes]
    affected_types = {server.entities[index].type for index in affected_entity_indexes}
    _add_undisplayed_item_counts(
        parent,
        _format_type_counts(
            remaining,
            MCP_ENTITY_TYPE_ORDER,
            MCP_ENTITY_TYPE_LABELS,
            count_suffix_by_type=dict.fromkeys(affected_types, " more"),
        ),
        follows_visible_items=bool(affected_entity_indexes),
    )


def _add_server(parent: Tree, server: McpServerRiskResponse, *, show_all: bool) -> None:
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

    affected_entity_indexes = _collect_risk_affected_entity_indexes(server, risks)
    if not risks and not show_all:
        _append_compact_counts_to_header(
            component,
            _format_type_counts(
                [entity.type for entity in server.entities],
                MCP_ENTITY_TYPE_ORDER,
                MCP_ENTITY_TYPE_LABELS,
            ),
        )
    server_tree = parent.add(component)
    _add_server_entities(
        server_tree,
        server,
        affected_entity_indexes,
        has_risks=bool(risks),
        show_all=show_all,
    )


def _add_skill(parent: Tree, skill: SkillRiskResponse, *, show_all: bool) -> None:
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

    affected_paths = {
        occurrence.path.removeprefix("./").replace("\\", "/")
        for _, risk in risks
        for region in (getattr(risk, "locations", None) or [])
        for occurrence in (region.start, region.end)
        if occurrence is not None
    }
    if not risks and not show_all:
        _append_compact_counts_to_header(
            component,
            _format_type_counts([skill_file.type for skill_file in skill.files], SKILL_FILE_TYPE_ORDER),
        )
    skill_tree = parent.add(component)
    for skill_file in skill.files:
        if not show_all and skill_file.name.removeprefix("./").replace("\\", "/") not in affected_paths:
            continue
        skill_tree.add(_format_response_skill_file_line(skill_file))
    if risks and not show_all:
        remaining = [
            skill_file.type
            for skill_file in skill.files
            if skill_file.name.removeprefix("./").replace("\\", "/") not in affected_paths
        ]
        affected_types = {
            skill_file.type
            for skill_file in skill.files
            if skill_file.name.removeprefix("./").replace("\\", "/") in affected_paths
        }
        _add_undisplayed_item_counts(
            skill_tree,
            _format_type_counts(
                remaining,
                SKILL_FILE_TYPE_ORDER,
                count_suffix_by_type=dict.fromkeys(affected_types, " more"),
            ),
            follows_visible_items=bool(affected_types),
        )


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
    show_all: bool,
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
        _add_server(tree, server, show_all=show_all)
    for skill in path.skill_risks:
        _add_skill(tree, skill, show_all=show_all)
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
    *,
    show_all: bool = False,
) -> None:
    """Render backend-enriched scan results.

    By default, clean components show type counts and risky components show
    only risk-connected entities or files. ``show_all`` expands every
    component's complete entity and file list.
    """
    if not response.scan_path_responses:
        rich.print("No MCP client configurations found on this machine.")
        return
    report_skills = hasattr(args, "skills") and args.skills
    for index, path in enumerate(response.scan_path_responses):
        _print_scan_path_response(
            path,
            print_errors=print_errors,
            report_skills=report_skills,
            show_all=show_all,
        )
        if index < len(response.scan_path_responses) - 1:
            rich.print()
