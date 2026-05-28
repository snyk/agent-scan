"""Tests for the Claude Code nightly CircleCI discovery verifier.

The verifier parses ``agent-scan inspect --json`` output and asserts that every
expected MCP server / skill (global, project, plugin scope) appears in the
discovery result. Used by the nightly CircleCI workflow to catch upstream
Claude Code layout regressions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.ci.verify_cc_nightly_scan import (
    ExpectedArtifact,
    check_scan,
    main,
)


HOME = Path.home().as_posix()


def _server(name: str, kind: str = "stdio") -> dict:
    """Build a minimal ServerScanResult dict for fixtures."""
    if kind == "skill":
        return {"name": name, "server": {"type": "skill", "path": f"/whatever/{name}"}}
    return {
        "name": name,
        "server": {"type": "stdio", "command": "echo", "args": []},
    }


def _scan_path(path: str, servers: list[dict]) -> dict:
    return {"path": path, "client": "claude code", "servers": servers, "issues": [], "labels": []}


def _full_passing_scan(workspace: str) -> dict:
    """Build a JSON dict where every expected artefact is discovered."""
    return {
        f"{HOME}/.claude.json": _scan_path(
            f"{HOME}/.claude.json", [_server("nightly-global-mcp")]
        ),
        f"{workspace}/.mcp.json": _scan_path(
            f"{workspace}/.mcp.json", [_server("nightly-project-mcp")]
        ),
        f"{HOME}/.claude/plugins/cache/cc-nightly/nightly-test-plugin/.mcp.json": _scan_path(
            f"{HOME}/.claude/plugins/cache/cc-nightly/nightly-test-plugin/.mcp.json",
            [_server("nightly-plugin-mcp")],
        ),
        f"{HOME}/.claude/skills": _scan_path(
            f"{HOME}/.claude/skills", [_server("nightly-global-skill", kind="skill")]
        ),
        f"{workspace}/.claude/skills": _scan_path(
            f"{workspace}/.claude/skills",
            [_server("nightly-project-skill", kind="skill")],
        ),
        f"{HOME}/.claude/plugins/cache/cc-nightly/nightly-test-plugin/skills": _scan_path(
            f"{HOME}/.claude/plugins/cache/cc-nightly/nightly-test-plugin/skills",
            [_server("nightly-plugin-skill", kind="skill")],
        ),
    }


def _default_expected(workspace: str) -> list[ExpectedArtifact]:
    return [
        ExpectedArtifact("global-mcp", "~/.claude.json", "nightly-global-mcp"),
        ExpectedArtifact(
            "project-mcp", f"{workspace}/.mcp.json", "nightly-project-mcp"
        ),
        ExpectedArtifact(
            "plugin-mcp",
            "~/.claude/plugins/cache/**/.mcp.json",
            "nightly-plugin-mcp",
        ),
        ExpectedArtifact("global-skill", "~/.claude/skills", "nightly-global-skill"),
        ExpectedArtifact(
            "project-skill", f"{workspace}/.claude/skills", "nightly-project-skill"
        ),
        ExpectedArtifact(
            "plugin-skill",
            "~/.claude/plugins/cache/**/skills",
            "nightly-plugin-skill",
        ),
    ]


class TestCheckScan:
    def test_returns_empty_list_when_all_expected_present(self, tmp_path):
        workspace = (tmp_path / "repo").as_posix()
        scan = _full_passing_scan(workspace)

        missing = check_scan(scan, _default_expected(workspace))

        assert missing == []

    def test_reports_missing_path_key(self, tmp_path):
        workspace = (tmp_path / "repo").as_posix()
        scan = _full_passing_scan(workspace)
        del scan[f"{HOME}/.claude.json"]

        missing = check_scan(scan, _default_expected(workspace))

        assert len(missing) == 1
        assert missing[0].label == "global-mcp"

    def test_reports_present_path_but_missing_server_name(self, tmp_path):
        workspace = (tmp_path / "repo").as_posix()
        scan = _full_passing_scan(workspace)
        scan[f"{HOME}/.claude.json"]["servers"] = [_server("some-other-server")]

        missing = check_scan(scan, _default_expected(workspace))

        assert len(missing) == 1
        assert missing[0].label == "global-mcp"

    def test_reports_multiple_missing(self, tmp_path):
        workspace = (tmp_path / "repo").as_posix()
        scan = _full_passing_scan(workspace)
        del scan[f"{HOME}/.claude.json"]
        del scan[f"{workspace}/.claude/skills"]

        missing = check_scan(scan, _default_expected(workspace))

        labels = {m.label for m in missing}
        assert labels == {"global-mcp", "project-skill"}

    def test_matches_glob_for_plugin_paths(self, tmp_path):
        """Plugin keys live under unpredictable subdirectories, so the matcher
        must accept ``**`` globs."""
        workspace = (tmp_path / "repo").as_posix()
        scan = _full_passing_scan(workspace)
        # Replace the canned plugin path with a deeper one.
        plugin_path = scan.pop(
            f"{HOME}/.claude/plugins/cache/cc-nightly/nightly-test-plugin/.mcp.json"
        )
        new_key = f"{HOME}/.claude/plugins/cache/marketplace-abc/another/deeper/.mcp.json"
        plugin_path["path"] = new_key
        scan[new_key] = plugin_path

        missing = check_scan(scan, _default_expected(workspace))

        labels = {m.label for m in missing}
        assert "plugin-mcp" not in labels

    def test_expands_tilde_against_provided_home(self, tmp_path):
        """The path-matcher must expand ``~`` to the supplied home directory,
        not the current process's home (so the verifier can run on a CI machine
        that scanned from a different home)."""
        custom_home = (tmp_path / "fake-home").as_posix()
        workspace = (tmp_path / "repo").as_posix()
        scan = {
            f"{custom_home}/.claude.json": _scan_path(
                f"{custom_home}/.claude.json", [_server("nightly-global-mcp")]
            ),
        }
        expected = [
            ExpectedArtifact("global-mcp", "~/.claude.json", "nightly-global-mcp"),
        ]

        missing = check_scan(scan, expected, home=custom_home)

        assert missing == []

    def test_windows_path_separators_are_normalized(self, tmp_path):
        """Discovery emits POSIX paths via ``as_posix()``, but a workspace
        passed in from a CircleCI Windows job can arrive with backslashes — the
        matcher must normalize."""
        workspace_win = r"C:\Users\circleci\project"
        workspace_posix = "C:/Users/circleci/project"
        scan = {
            f"{workspace_posix}/.mcp.json": _scan_path(
                f"{workspace_posix}/.mcp.json", [_server("nightly-project-mcp")]
            ),
        }
        expected = [
            ExpectedArtifact(
                "project-mcp",
                f"{workspace_win}/.mcp.json",
                "nightly-project-mcp",
            ),
        ]

        missing = check_scan(scan, expected)

        assert missing == []

    def test_servers_can_be_none_without_crashing(self, tmp_path):
        """When agent-scan fails to parse a config it sets ``servers: None``
        — the matcher should treat that as 'name not found' rather than raise."""
        workspace = (tmp_path / "repo").as_posix()
        scan = {
            f"{HOME}/.claude.json": {
                "path": f"{HOME}/.claude.json",
                "client": "claude code",
                "servers": None,
                "issues": [],
                "labels": [],
            },
        }
        expected = [
            ExpectedArtifact("global-mcp", "~/.claude.json", "nightly-global-mcp"),
        ]

        missing = check_scan(scan, expected)

        assert len(missing) == 1
        assert missing[0].label == "global-mcp"


class TestCliMain:
    def test_exits_zero_on_full_match(self, tmp_path, capsys, monkeypatch):
        workspace = tmp_path / "repo"
        workspace.mkdir()
        scan_file = tmp_path / "scan.json"
        scan_file.write_text(json.dumps(_full_passing_scan(workspace.as_posix())))

        rc = main([str(scan_file), "--workspace", str(workspace)])

        assert rc == 0

    def test_exits_nonzero_and_prints_missing(self, tmp_path, capsys):
        workspace = tmp_path / "repo"
        workspace.mkdir()
        scan = _full_passing_scan(workspace.as_posix())
        del scan[f"{HOME}/.claude.json"]
        scan_file = tmp_path / "scan.json"
        scan_file.write_text(json.dumps(scan))

        rc = main([str(scan_file), "--workspace", str(workspace)])

        out = capsys.readouterr().out + capsys.readouterr().err
        assert rc != 0
        # The missing label appears somewhere in the report.
        assert "global-mcp" in (out + capsys.readouterr().out)

    def test_missing_scan_file_exits_nonzero(self, tmp_path):
        rc = main([str(tmp_path / "does-not-exist.json"), "--workspace", str(tmp_path)])
        assert rc != 0
