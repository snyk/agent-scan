import hashlib
import os
from pathlib import Path
from typing import Any

from agent_scan.models import FAILURE_CATEGORY_TO_CODE, Issue, ScanError, ScanPathResult, ServerScanResult
from agent_scan.version import version_info


def scan_results_to_sarif(results: list[ScanPathResult], base_dir: str | Path | None = None) -> dict[str, Any]:
    """Convert Agent Scan results to SARIF 2.1.0 for GitHub code scanning."""
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    root = Path(base_dir or os.getcwd()).resolve()

    for scan_result in results:
        for issue in scan_result.issues:
            rule = _rule_for_issue(issue)
            rules[rule["id"]] = rule
            sarif_results.append(_result_for_issue(scan_result, issue, root))

        if scan_result.error:
            rule = _rule_for_error(scan_result.error)
            rules[rule["id"]] = rule
            sarif_results.append(_result_for_path_error(scan_result, scan_result.error, root))

        for server_index, server in enumerate(scan_result.servers or []):
            if server.error:
                rule = _rule_for_error(server.error)
                rules[rule["id"]] = rule
                sarif_results.append(_result_for_server_error(scan_result, server, server_index, server.error, root))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Snyk Agent Scan",
                        "semanticVersion": version_info,
                        "informationUri": "https://github.com/snyk/agent-scan",
                        "rules": sorted(rules.values(), key=lambda rule: rule["id"]),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def _rule_for_issue(issue: Issue) -> dict[str, Any]:
    return {
        "id": issue.code,
        "name": issue.code,
        "shortDescription": {"text": _rule_title(issue.code)},
        "fullDescription": {"text": issue.message},
        "helpUri": f"https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md#{issue.code.lower()}",
        "properties": {
            "tags": ["security", "agent-scan", "ai-agent"],
            "precision": "medium",
            "security-severity": _security_severity(issue.code),
        },
    }


def _rule_for_error(error: ScanError) -> dict[str, Any]:
    code = FAILURE_CATEGORY_TO_CODE.get(error.category, FAILURE_CATEGORY_TO_CODE[None])
    return {
        "id": code,
        "name": code,
        "shortDescription": {"text": _rule_title(code)},
        "fullDescription": {"text": error.text or "Agent Scan runtime error"},
        "helpUri": "https://github.com/snyk/agent-scan/blob/main/docs/json-output.md#1-checking-for-execution-failures",
        "properties": {
            "tags": ["security", "agent-scan", "runtime"],
            "precision": "medium",
            "security-severity": "6.0" if error.is_failure else "3.0",
        },
    }


def _result_for_issue(scan_result: ScanPathResult, issue: Issue, root: Path) -> dict[str, Any]:
    server_name, entity_name = _referenced_names(scan_result, issue.reference)
    message_parts = [f"[{issue.code}] {issue.message}"]
    if server_name:
        message_parts.append(f"Server: {server_name}")
    if entity_name:
        message_parts.append(f"Component: {entity_name}")

    return {
        "ruleId": issue.code,
        "level": _level_for_code(issue.code),
        "message": {"text": " ".join(message_parts)},
        "locations": [_location(scan_result.path, root)],
        "partialFingerprints": {
            "agentScanIssue": _fingerprint(scan_result.path, issue.code, issue.message, issue.reference, server_name, entity_name)
        },
        "properties": {
            "reference": list(issue.reference) if issue.reference is not None else None,
            "extraData": issue.extra_data,
        },
    }


def _result_for_path_error(scan_result: ScanPathResult, error: ScanError, root: Path) -> dict[str, Any]:
    code = FAILURE_CATEGORY_TO_CODE.get(error.category, FAILURE_CATEGORY_TO_CODE[None])
    return {
        "ruleId": code,
        "level": "error" if error.is_failure else "note",
        "message": {"text": f"[{code}] Failed to scan {scan_result.path}: {error.text}"},
        "locations": [_location(scan_result.path, root)],
        "partialFingerprints": {"agentScanIssue": _fingerprint(scan_result.path, code, error.text)},
    }


def _result_for_server_error(
    scan_result: ScanPathResult,
    server: ServerScanResult,
    server_index: int,
    error: ScanError,
    root: Path,
) -> dict[str, Any]:
    code = FAILURE_CATEGORY_TO_CODE.get(error.category, FAILURE_CATEGORY_TO_CODE[None])
    server_name = server.name or f"server[{server_index}]"
    return {
        "ruleId": code,
        "level": "error" if error.is_failure else "note",
        "message": {"text": f"[{code}] Failed to scan {server_name} in {scan_result.path}: {error.text}"},
        "locations": [_location(scan_result.path, root)],
        "partialFingerprints": {"agentScanIssue": _fingerprint(scan_result.path, code, error.text, server_index, server_name)},
        "properties": {"reference": [server_index, None]},
    }


def _location(path: str, root: Path) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {
                "uri": _artifact_uri(path, root),
            },
            "region": {"startLine": 1},
        }
    }


def _artifact_uri(path: str, root: Path) -> str:
    artifact_path = Path(path).expanduser()
    try:
        resolved = artifact_path.resolve()
        relative = resolved.relative_to(root)
        return relative.as_posix()
    except (OSError, ValueError):
        return artifact_path.as_posix()


def _referenced_names(scan_result: ScanPathResult, reference: tuple[int, int | None] | None) -> tuple[str | None, str | None]:
    if reference is None or scan_result.servers is None:
        return None, None

    server_index, entity_index = reference
    if server_index < 0 or server_index >= len(scan_result.servers):
        return None, None

    server = scan_result.servers[server_index]
    server_name = server.name
    if entity_index is None:
        return server_name, None
    if entity_index < 0 or entity_index >= len(server.entities):
        return server_name, None
    return server_name, getattr(server.entities[entity_index], "name", None)


def _level_for_code(code: str) -> str:
    if code.startswith("E"):
        return "error"
    if code.startswith("W"):
        return "warning"
    return "note"


def _security_severity(code: str) -> str:
    if code.startswith("E"):
        return "8.0"
    if code.startswith("W"):
        return "5.0"
    return "3.0"


def _rule_title(code: str) -> str:
    if code.startswith("E"):
        return "Agent security error"
    if code.startswith("W"):
        return "Agent security warning"
    return "Agent Scan runtime or analysis notice"


def _fingerprint(*parts: object) -> str:
    text = "\x1f".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
