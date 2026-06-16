"""ClaudeCodeCanary — the live-test counterpart of :class:`ClaudeCodeDiscoverer`.

One :class:`Scope` per scope-producing ``_discover_*`` method (``mirrors`` references the method object
itself). The scopes a real ``claude`` can write are enforced (the three ``claude mcp add`` MCP scopes +
the pinned plugin's MCP/skills); the rest are :class:`Gap` s — represented for fidelity (so the coverage
test sees them covered) but never seeded or asserted, because no ``claude`` CLI creates them.
"""

from __future__ import annotations

from agent_scan.agents.claude_code import ClaudeCodeDiscoverer
from agent_scan.canary.base import (
    AgentCanary,
    ExpectedItem,
    Gap,
    LifecycleStep,
    McpScope,
    PluginScope,
    Scope,
)

# The live plugin canary installs a real plugin from Anthropic's official marketplace so the on-disk
# plugin cache (the format-fragile, undocumented `~/.claude/plugins/cache/...` layout) is written by the
# real binary. `discord` is vendored in the marketplace repo and bundles BOTH an MCP server (`discord`)
# and skills (`access`, `configure`). The marketplace clone is pinned to a fixed commit for a
# deterministic baseline; bump PIN_SHA deliberately when intentionally tracking a newer plugin.
CLAUDE_PLUGIN_MARKETPLACE = "claude-plugins-official"
CLAUDE_PLUGIN_MARKETPLACE_REPO = "anthropics/claude-plugins-official"
CLAUDE_PLUGIN = "discord"
CLAUDE_PLUGIN_PIN_SHA = "66bca6b6f62e5023673feff699d9d99451ae9919"

_D = ClaudeCodeDiscoverer  # the scope methods this canary mirrors, by object reference


class ClaudeCodeCanary(AgentCanary):
    discoverer = ClaudeCodeDiscoverer

    @property
    def scopes(self) -> list[Scope]:
        # Ordered: the three `claude mcp add` scopes → trust the project → install the pinned plugin
        # last (its cache is the final on-disk write before the scan) → the no-live-writer Gaps.
        return [
            McpScope("mcp/global", (_D._discover_global_mcp_servers,), "canary-global-mcp", "user", ("echo", "global")),
            McpScope(
                "mcp/project-inline",
                (_D._discover_project_mcp_servers,),
                "canary-project-inline-mcp",
                "local",
                ("echo", "inline"),
                run_in_project=True,
            ),
            McpScope(
                "mcp/project-file",
                (_D._discover_project_mcp_servers,),
                "canary-project-file-mcp",
                "project",
                ("echo", "file"),
                run_in_project=True,
            ),
            LifecycleStep(),  # trust/register the project so the local-scope server resolves
            PluginScope(
                "mcp+skill/plugin",
                (_D._discover_plugin_mcp_servers, _D._discover_plugin_skills),
                marketplace=CLAUDE_PLUGIN_MARKETPLACE,
                marketplace_repo=CLAUDE_PLUGIN_MARKETPLACE_REPO,
                plugin=CLAUDE_PLUGIN,
                pin_sha=CLAUDE_PLUGIN_PIN_SHA,
                expected_items=(
                    ExpectedItem("mcp", "discord", "mcp/plugin"),
                    ExpectedItem("skill", "access", "skill/plugin", ("$HOME/.claude/plugins/", "skills/access")),
                    ExpectedItem("skill", "configure", "skill/plugin", ("$HOME/.claude/plugins/", "skills/configure")),
                ),
            ),
            # --- Gaps: real discoverer scopes with no live writer (no claude CLI creates them); seeding
            #     them would need a synthetic fixture, which this canary refuses. Mirrored so the coverage
            #     test counts their method as covered; surfaced in the report as known coverage gaps.
            Gap("skill/global", (_D._discover_global_skill,), "no claude CLI creates a standalone personal skill"),
            Gap("skill/project", (_D._discover_project_skills,), "no claude CLI creates a standalone project skill"),
            Gap("command/global", (_D._discover_global_commands,), "no claude CLI creates a slash command"),
            Gap("command/project", (_D._discover_project_commands,), "no claude CLI creates a slash command"),
            Gap("command/plugin", (_D._discover_plugin_commands,), "the pinned discord plugin bundles no commands"),
            Gap("mcp/managed", (_D._discover_managed_mcp_servers,), "enterprise system path; no CLI writer"),
            Gap(
                "mcp/plugin-manifest",
                (_D._discover_plugin_manifest_mcp_servers,),
                "needs a plugin with inline plugin.json mcpServers",
            ),
            Gap(
                "skill/plugin-manifest",
                (_D._discover_plugin_manifest_skills,),
                "needs a plugin with inline plugin.json skills",
            ),
        ]
