"""Shape tests for the canary specs: derived expectations, seed commands, gaps."""

from __future__ import annotations

from pathlib import Path

from agent_scan.canary import CANARIES, CanaryContext
from agent_scan.canary.base import ExpectedItem, Gap, McpScope, PluginScope
from agent_scan.canary.claude_code import ClaudeCodeCanary

CTX = CanaryContext(home=Path("/home"), project=Path("/home/proj"), bin="claude")

EXPECTED_SIX = [
    ExpectedItem("mcp", "canary-global-mcp", "mcp/global"),
    ExpectedItem("mcp", "canary-project-inline-mcp", "mcp/project-inline"),
    ExpectedItem("mcp", "canary-project-file-mcp", "mcp/project-file"),
    ExpectedItem("mcp", "discord", "mcp/plugin"),
    ExpectedItem("skill", "access", "skill/plugin", ("$HOME/.claude/plugins/", "skills/access")),
    ExpectedItem("skill", "configure", "skill/plugin", ("$HOME/.claude/plugins/", "skills/configure")),
]


def test_registry_keys_on_discoverer_name():
    assert "claude code" in CANARIES
    assert isinstance(CANARIES["claude code"], ClaudeCodeCanary)


def test_expected_is_the_six_enforced_items_in_order():
    assert ClaudeCodeCanary().expected() == EXPECTED_SIX


def test_scope_order_is_mcp_then_trust_then_plugin_then_gaps():
    labels = [s.label for s in ClaudeCodeCanary().scopes]
    assert labels[:5] == ["mcp/global", "mcp/project-inline", "mcp/project-file", "lifecycle/trust", "mcp+skill/plugin"]
    assert all(isinstance(s, Gap) for s in ClaudeCodeCanary().scopes[5:])


def test_mcp_scope_emits_claude_mcp_add():
    scope = next(s for s in ClaudeCodeCanary().scopes if isinstance(s, McpScope) and s.label == "mcp/project-file")
    (cmd,) = scope.commands(CTX)
    assert cmd.argv == ("claude", "mcp", "add", "-s", "project", "canary-project-file-mcp", "--", "echo", "file")
    assert cmd.run_in_project is True


def test_plugin_scope_marketplace_pin_then_installs_narrow_to_broad():
    scope = next(s for s in ClaudeCodeCanary().scopes if isinstance(s, PluginScope))
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


def test_gaps_are_inert():
    for gap in ClaudeCodeCanary().gaps():
        assert gap.commands(CTX) == []
        assert gap.expected() == []
        assert gap.enforced is False
        assert gap.mirrors  # still references its discoverer method
