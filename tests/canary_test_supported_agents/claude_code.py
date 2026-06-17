"""ClaudeCodeCanary — the live-test counterpart of :class:`ClaudeCodeDiscoverer`.

One :class:`Scope` per scope-producing ``_discover_*`` method (``mirrors`` references the method object
itself). Three tiers: the scopes a real ``claude`` can write are driven live (the three ``claude mcp add``
MCP scopes + two pinned marketplace plugins — ``discord`` for MCP/skills, ``commit-commands`` for plugin
commands); the project-local skill/command/server scopes that no CLI writes are :class:`FixtureScope` s
(the executor copies a committed fixture into the project, then inspect must detect it); the rest are
:class:`Gap` s — mirrored for fidelity (so the coverage test sees them covered) but never seeded or
asserted, because neither a CLI nor a sensible fixture can drive them.
"""

from __future__ import annotations

from agent_scan.agents.claude_code import ClaudeCodeDiscoverer

from .base import (
    AgentCanary,
    ExpectedItem,
    FixtureFile,
    FixtureScope,
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

# `discord` ships no slash commands, so the plugin-command scope needs a second real plugin. `commit-commands`
# is a pure command plugin in the SAME official marketplace (and present at PIN_SHA), bundling
# `commands/commit.md` etc. — installing it lands a `commands/` dir in the plugin cache that
# `_discover_plugin_commands` detects. Same marketplace + pin as `discord`, so still deterministic.
CLAUDE_COMMAND_PLUGIN = "commit-commands"

# Committed project fixtures, copied into the (registered) dummy project so inspect can detect the
# project-local skill/command/server scopes no `claude` CLI writes. The src paths are relative to the
# `canary_test_supported_agents` package dir on disk; the executor resolves them against that dir (the
# cloned source tree it puts on PYTHONPATH — these fixtures are test support, not shipped in the wheel)
# and copies them in.
_FIXTURE_ROOT = "test_projects/proj"

_D = ClaudeCodeDiscoverer  # the scope methods this canary mirrors, by object reference


class ClaudeCodeCanary(AgentCanary):
    discoverer = ClaudeCodeDiscoverer
    bin_candidates = ("claude",)

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
            PluginScope(
                "command/plugin",
                (_D._discover_plugin_commands,),
                marketplace=CLAUDE_PLUGIN_MARKETPLACE,
                marketplace_repo=CLAUDE_PLUGIN_MARKETPLACE_REPO,
                plugin=CLAUDE_COMMAND_PLUGIN,
                pin_sha=CLAUDE_PLUGIN_PIN_SHA,
                # commit-commands ships exactly these three commands at PIN_SHA — assert all of them so the
                # report stays clean (no informational EXTRA) and a future command add/remove on a pin bump
                # surfaces as drift.
                expected_items=(
                    ExpectedItem("skill", "commit", "command/plugin", ("$HOME/.claude/plugins/", "commands/commit.md")),
                    ExpectedItem(
                        "skill", "clean_gone", "command/plugin", ("$HOME/.claude/plugins/", "commands/clean_gone.md")
                    ),
                    ExpectedItem(
                        "skill",
                        "commit-push-pr",
                        "command/plugin",
                        ("$HOME/.claude/plugins/", "commands/commit-push-pr.md"),
                    ),
                ),
                scopes=("user",),  # one install populates the shared cache; command detection ignores enablement
            ),
            # --- Fixture scopes: project-local skill/command/server that no `claude` CLI writes. The
            #     executor copies the committed fixture into the (registered) project, then inspect must
            #     detect it. Project skills/commands surface as skill-type items (path distinguishes the
            #     scope). The server fixture shares <project>/.mcp.json with the mcp/project-file CLI write
            #     — `claude mcp add` merges into the pre-written file, so both servers are detected.
            FixtureScope(
                "skill/project",
                (_D._discover_project_skills,),
                (
                    FixtureFile(
                        f"{_FIXTURE_ROOT}/.claude/skills/canary-project-skill", ".claude/skills/canary-project-skill"
                    ),
                ),
                (
                    ExpectedItem(
                        "skill",
                        "canary-project-skill",
                        "skill/project",
                        ("$PROJECT/.claude/skills/", "canary-project-skill"),
                    ),
                ),
            ),
            FixtureScope(
                "command/project",
                (_D._discover_project_commands,),
                (
                    FixtureFile(
                        f"{_FIXTURE_ROOT}/.claude/commands/canary-project-command.md",
                        ".claude/commands/canary-project-command.md",
                    ),
                ),
                (
                    ExpectedItem(
                        "skill",
                        "canary-project-command",
                        "command/project",
                        ("$PROJECT/.claude/commands/", "canary-project-command"),
                    ),
                ),
            ),
            FixtureScope(
                "mcp/project-file-fixture",
                (_D._discover_project_mcp_servers,),
                (FixtureFile(f"{_FIXTURE_ROOT}/.mcp.json", ".mcp.json"),),
                (ExpectedItem("mcp", "canary-project-fixture-mcp", "mcp/project-file-fixture"),),
            ),
            # --- Gaps: real discoverer scopes with no live writer (no claude CLI creates them) and no
            #     sensible fixture. Mirrored so the coverage test counts their method as covered; surfaced
            #     in the report as known coverage gaps.
            Gap("skill/global", (_D._discover_global_skill,), "no claude CLI creates a standalone personal skill"),
            Gap("command/global", (_D._discover_global_commands,), "no claude CLI creates a slash command"),
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
