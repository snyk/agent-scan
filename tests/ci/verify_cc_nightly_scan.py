"""Verify agent-scan discovered every Claude Code artefact the nightly job seeded.

Used by the nightly CircleCI workflow (`.circleci/config.yml`). The job runs
`agent-scan inspect --json > scan.json` after seeding a global MCP server, a
project MCP server, a plugin (which ships its own MCP + skill), a global
skill, and a project skill via real `claude` CLI commands. This script asserts
each of those names appears in the discovery output for the right path scope;
non-zero exit means upstream Claude Code changed something agent-scan no
longer recognises.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass(frozen=True)
class ExpectedArtifact:
    """One thing the nightly job seeded that we expect to find in the scan.

    ``path_pattern`` may contain ``~`` (expanded against the supplied home) and
    ``*`` / ``**`` glob wildcards — plugin scopes live under unpredictable
    hashed subdirectories so glob matching is required.
    """

    label: str
    path_pattern: str
    server_name: str


def _normalize(path: str) -> str:
    """Match the POSIX form that ClaudeCodeDiscoverer emits via ``as_posix()``."""
    return path.replace("\\", "/")


def _expand(pattern: str, home: str) -> str:
    pattern = _normalize(pattern)
    home_posix = _normalize(home)
    if pattern.startswith("~/"):
        return f"{home_posix}/{pattern[2:]}"
    if pattern == "~":
        return home_posix
    return pattern


def _matches(pattern: str, candidate: str, home: str) -> bool:
    # fnmatch's ``*`` greedily matches ``/`` too, so a single ``*`` already
    # spans multiple path components and ``**`` (used in the plugin-scope
    # patterns) is equivalent to ``*`` here. Do not "fix" this to
    # ``pathlib.PurePath.match`` — that one is stricter about ``/`` and would
    # break plugin-cache discovery.
    expanded = _expand(pattern, home)
    candidate_norm = _normalize(candidate)
    if "*" in expanded:
        return fnmatch.fnmatchcase(candidate_norm, expanded)
    return expanded == candidate_norm


def _server_names(scan_entry: dict[str, Any]) -> set[str]:
    servers = scan_entry.get("servers") or []
    names: set[str] = set()
    for s in servers:
        if isinstance(s, dict):
            name = s.get("name")
            if isinstance(name, str):
                names.add(name)
    return names


def check_scan(
    scan: dict[str, Any],
    expected: Iterable[ExpectedArtifact],
    home: str | None = None,
) -> list[ExpectedArtifact]:
    """Return the artefacts that are NOT present in the scan dict.

    An artefact is considered present when at least one scan key matches its
    ``path_pattern`` *and* that entry's ``servers`` list contains a server with
    the expected ``name``.
    """
    home_str = home if home is not None else str(Path.home())
    missing: list[ExpectedArtifact] = []
    for artefact in expected:
        found = False
        for key, entry in scan.items():
            if not isinstance(entry, dict):
                continue
            if not _matches(artefact.path_pattern, key, home_str):
                continue
            if artefact.server_name in _server_names(entry):
                found = True
                break
        if not found:
            missing.append(artefact)
    return missing


def default_expected(workspace: str) -> list[ExpectedArtifact]:
    """The six artefacts the nightly CircleCI job is responsible for seeding —
    two (one MCP server + one skill) at each of the three scopes the user
    asked about: global, project, plugin."""
    ws = _normalize(workspace)
    return [
        ExpectedArtifact("global-mcp", "~/.claude.json", "nightly-global-mcp"),
        ExpectedArtifact("project-mcp", f"{ws}/.mcp.json", "nightly-project-mcp"),
        ExpectedArtifact("plugin-mcp", "~/.claude/plugins/cache/**/.mcp.json", "nightly-plugin-mcp"),
        ExpectedArtifact("global-skill", "~/.claude/skills", "nightly-global-skill"),
        ExpectedArtifact("project-skill", f"{ws}/.claude/skills", "nightly-project-skill"),
        ExpectedArtifact("plugin-skill", "~/.claude/plugins/cache/**/skills", "nightly-plugin-skill"),
    ]


def _format_report(missing: list[ExpectedArtifact], scan: dict[str, Any]) -> str:
    lines = [f"Claude Code nightly discovery check FAILED — {len(missing)} missing artefact(s):", ""]
    for art in missing:
        lines.append(
            f"  - [{art.label}] expected server/skill '{art.server_name}' under path matching '{art.path_pattern}'"
        )
    lines.append("")
    lines.append("Observed scan keys:")
    for key in sorted(scan):
        names = sorted(n for n in _server_names(scan[key]) if n)
        lines.append(f"  {key}  -> {names or '(no servers)'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scan_file", help="Path to scan.json (output of `agent-scan inspect --json`).")
    parser.add_argument(
        "--workspace",
        default=os.getcwd(),
        help="Workspace directory the job seeded (used for project-scope path keys). Defaults to cwd.",
    )
    parser.add_argument(
        "--home",
        default=str(Path.home()),
        help="Home directory to expand ~ against. Defaults to current user's home.",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.scan_file, encoding="utf-8") as f:
            scan = json.load(f)
    except FileNotFoundError:
        print(f"scan file not found: {args.scan_file}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"scan file is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if not isinstance(scan, dict):
        print("scan file root must be a JSON object keyed by scan path", file=sys.stderr)
        return 2

    expected = default_expected(args.workspace)
    missing = check_scan(scan, expected, home=args.home)
    if not missing:
        print(f"OK — all {len(expected)} expected Claude Code artefacts discovered.")
        return 0

    print(_format_report(missing, scan))
    return 1


if __name__ == "__main__":
    sys.exit(main())
