"""Shape tests for the canary specs: derived expectations, seed commands, fixtures, gaps."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from agent_scan.canary import CANARIES, CanaryContext
from agent_scan.canary.base import ExpectedItem, FixtureScope, Gap, McpScope, PluginScope
from agent_scan.canary.claude_code import ClaudeCodeCanary

CTX = CanaryContext(home=Path("/home"), project=Path("/home/proj"), bin="claude")

EXPECTED_ITEMS = [
    ExpectedItem("mcp", "canary-global-mcp", "mcp/global"),
    ExpectedItem("mcp", "canary-project-inline-mcp", "mcp/project-inline"),
    ExpectedItem("mcp", "canary-project-file-mcp", "mcp/project-file"),
    ExpectedItem("mcp", "discord", "mcp/plugin"),
    ExpectedItem("skill", "access", "skill/plugin", ("$HOME/.claude/plugins/", "skills/access")),
    ExpectedItem("skill", "configure", "skill/plugin", ("$HOME/.claude/plugins/", "skills/configure")),
    ExpectedItem("skill", "commit", "command/plugin", ("$HOME/.claude/plugins/", "commands/commit")),
    ExpectedItem(
        "skill", "canary-project-skill", "skill/project", ("$PROJECT/.claude/skills/", "canary-project-skill")
    ),
    ExpectedItem(
        "skill", "canary-project-command", "command/project", ("$PROJECT/.claude/commands/", "canary-project-command")
    ),
    ExpectedItem("mcp", "canary-project-fixture-mcp", "mcp/project-file-fixture"),
]


def test_registry_keys_on_discoverer_name():
    assert "claude code" in CANARIES
    assert isinstance(CANARIES["claude code"], ClaudeCodeCanary)


def test_expected_items_in_order():
    assert ClaudeCodeCanary().expected() == EXPECTED_ITEMS


def test_scope_order_live_then_fixtures_then_gaps():
    scopes = ClaudeCodeCanary().scopes
    labels = [s.label for s in scopes]
    assert labels[:6] == [
        "mcp/global",
        "mcp/project-inline",
        "mcp/project-file",
        "lifecycle/trust",
        "mcp+skill/plugin",
        "command/plugin",
    ]
    assert all(isinstance(s, PluginScope) for s in scopes[4:6])  # both plugins are live installs
    assert labels[6:9] == ["skill/project", "command/project", "mcp/project-file-fixture"]
    assert all(isinstance(s, FixtureScope) for s in scopes[6:9])
    assert all(isinstance(s, Gap) for s in scopes[9:])


def test_mcp_scope_emits_claude_mcp_add():
    scope = next(s for s in ClaudeCodeCanary().scopes if isinstance(s, McpScope) and s.label == "mcp/project-file")
    (cmd,) = scope.commands(CTX)
    assert cmd.argv == ("claude", "mcp", "add", "-s", "project", "canary-project-file-mcp", "--", "echo", "file")
    assert cmd.run_in_project is True


def _plugin_scope(label):
    return next(s for s in ClaudeCodeCanary().scopes if isinstance(s, PluginScope) and s.label == label)


def test_plugin_scope_marketplace_pin_then_installs_narrow_to_broad():
    scope = _plugin_scope("mcp+skill/plugin")
    argvs = [" ".join(c.argv) for c in scope.commands(CTX)]
    # Build the clone path the same way the code does, so the assertion holds on Windows too (backslashes).
    clone = str(CTX.home / ".claude" / "plugins" / "marketplaces" / "claude-plugins-official")
    assert argvs == [
        "claude plugin marketplace add anthropics/claude-plugins-official",
        f"git -C {clone} fetch --depth 1 origin {scope.pin_sha}",
        f"git -C {clone} checkout --detach {scope.pin_sha}",
        "claude plugin install discord@claude-plugins-official --scope local",
        "claude plugin install discord@claude-plugins-official --scope project",
        "claude plugin install discord@claude-plugins-official --scope user",
    ]
    assert all(c.non_fatal for c in scope.commands(CTX))


def test_command_plugin_scope_installs_commit_commands_and_expects_the_command():
    # command/plugin is filled by installing a SECOND pinned plugin (commit-commands) from the same
    # official marketplace — discord ships no commands. One `--scope user` install populates the shared
    # plugin cache that _discover_plugin_commands scans; detection ignores enablement.
    scope = _plugin_scope("command/plugin")
    argvs = [" ".join(c.argv) for c in scope.commands(CTX)]
    assert "claude plugin marketplace add anthropics/claude-plugins-official" in argvs
    assert argvs[-1] == "claude plugin install commit-commands@claude-plugins-official --scope user"
    assert all(c.non_fatal for c in scope.commands(CTX))
    assert scope.expected() == [
        ExpectedItem("skill", "commit", "command/plugin", ("$HOME/.claude/plugins/", "commands/commit"))
    ]
    assert scope.mirrors == (ClaudeCodeCanary.discoverer._discover_plugin_commands,)


def test_gaps_are_inert():
    for gap in ClaudeCodeCanary().gaps():
        assert gap.commands(CTX) == []
        assert gap.files() == []
        assert gap.expected() == []
        assert gap.enforced is False
        assert gap.mirrors  # still references its discoverer method


def test_fixture_scopes_declare_files_and_assert_items_but_run_no_command():
    fixtures = {s.label: s for s in ClaudeCodeCanary().scopes if isinstance(s, FixtureScope)}
    assert set(fixtures) == {"skill/project", "command/project", "mcp/project-file-fixture"}

    skill = fixtures["skill/project"]
    assert skill.commands(CTX) == []  # no CLI can write a project skill
    (sf,) = skill.files()
    assert (sf.src, sf.dest) == (
        "test_projects/proj/.claude/skills/canary-project-skill",
        ".claude/skills/canary-project-skill",
    )
    assert skill.expected() == [
        ExpectedItem(
            "skill", "canary-project-skill", "skill/project", ("$PROJECT/.claude/skills/", "canary-project-skill")
        )
    ]
    assert skill.enforced is True

    server = fixtures["mcp/project-file-fixture"]
    (mf,) = server.files()
    assert (mf.src, mf.dest) == ("test_projects/proj/.mcp.json", ".mcp.json")
    assert server.expected() == [ExpectedItem("mcp", "canary-project-fixture-mcp", "mcp/project-file-fixture")]


def test_project_skill_and_command_are_no_longer_gaps():
    gap_labels = {g.label for g in ClaudeCodeCanary().gaps()}
    assert "skill/project" not in gap_labels
    assert "command/project" not in gap_labels


def test_committed_fixtures_are_packaged_and_locatable():
    # Mirrors how the executor finds fixtures: importlib.resources over the agent_scan.canary package
    # (works for a dev checkout AND the wheel built with the force-include). A miss here means the
    # backoffice would copy nothing and the scope would fail MISSING in CI.
    root = files("agent_scan.canary")
    for canary in CANARIES.values():
        for scope in canary.scopes:
            for f in scope.files():
                src = root / f.src
                assert src.is_dir() or src.is_file(), f"fixture not packaged: {f.src}"
