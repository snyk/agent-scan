"""Canaries for the VS Code-family discoverers (vscode, cursor, kiro, windsurf, antigravity).

All five share ``VSCodeFamilyDiscoverer``'s scope-producing ``_discover_*`` methods. Only VS Code has a
real binary writer — ``code --add-mcp`` writes the user ``mcp.json`` (the one enforced scope) — so VS
Code's canary drives that live and Gaps the rest. The forks (cursor/kiro/windsurf/antigravity) have no
CLI that writes a detectable MCP scope yet (their config is hand-authored or GUI-only), so their canary
is a headless :class:`LifecycleStep` plus Gaps: it exercises the real installed CLI and asserts nothing,
matching the old empty-baseline legs. Every scope-producing method is still mirrored (as a Gap) so
``test_canary_covers_scopes`` enforces coverage for these discoverers too.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agent_scan.agents.vscode.antigravity import AntigravityDiscoverer
from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer
from agent_scan.agents.vscode.cursor import CursorDiscoverer
from agent_scan.agents.vscode.kiro import KiroDiscoverer
from agent_scan.agents.vscode.vscode import VSCodeDiscoverer
from agent_scan.agents.vscode.windsurf import WindsurfDiscoverer

from .base import AgentCanary, CommandScope, ExpectedItem, Gap, LifecycleStep, Scope

if TYPE_CHECKING:
    from collections.abc import Callable

    from .base import CanaryContext

_B = VSCodeFamilyDiscoverer  # the shared scope methods every family discoverer inherits, by reference

# The user-level ``mcp.json`` server `code --add-mcp` writes (a stdio echo server, like the claude scopes).
_VSCODE_USER_MCP_NAME = "canary-vscode-user-mcp"


def _vscode_add_mcp_argv(ctx: CanaryContext) -> tuple[str, ...]:
    """``code [--user-data-dir <userdata>] --add-mcp <json>`` — the only VS Code MCP scope a real binary
    writes (the user ``mcp.json`` under ``<userdata>/User/``).

    ``--user-data-dir`` is taken from the discoverer's OWN path logic (``VSCodeDiscoverer(home)._user_data_dir()``,
    the first ``Code`` userdata candidate), so the seed location provably matches where the discoverer
    scans — no duplicated per-OS path table to drift. It's omitted on an unsupported platform (None), where
    ``code`` falls back to its default userdata dir under HOME.
    """
    server = json.dumps({"name": _VSCODE_USER_MCP_NAME, "command": "echo", "args": ["usermcp"], "type": "stdio"})
    userdata = VSCodeDiscoverer(ctx.home)._user_data_dir()
    argv: tuple[str, ...] = (ctx.bin,)
    if userdata is not None:
        argv += ("--user-data-dir", str(userdata))
    return (*argv, "--add-mcp", server)


# Every scope-producing _discover_* method shared by the VS Code family, as (method, label, why-a-gap).
# None has a `claude mcp add`-style writer: the user mcp.json is the lone exception (written live by
# `code --add-mcp` — enforced in VSCodeCanary; a Gap everywhere else). The rest are hand-authored config,
# workspace files, or extension state with no CLI writer — mirrored for anti-drift coverage, never seeded.
_FAMILY_GAPS: tuple[tuple[Callable[..., object], str, str], ...] = (
    (_B._discover_home_skills_dirs, "skill/home", "user-authored home skills dir; no CLI writer"),
    (_B._discover_system_skills_dirs, "skill/system", "machine-wide skills dir; no CLI writer"),
    (
        _B._discover_user_mcp_files,
        "mcp/user-mcp-json",
        "user mcp.json — written live by `code --add-mcp` (VSCodeCanary); a Gap for forks whose CLI can't write it",
    ),
    (_B._discover_profile_mcp_files, "mcp/profile", "per-profile mcp.json; no CLI writer"),
    (_B._discover_user_settings_mcp, "mcp/user-settings", "mcp.servers in user settings.json; no CLI writer"),
    (_B._discover_workspace_mcp, "mcp/workspace", "workspace .vscode/mcp.json; no CLI writer"),
    (_B._discover_agent_config_mcp, "mcp/agent-config", "agent-config mcp; no CLI writer"),
    (_B._discover_workspace_skills, "skill/workspace", "workspace skills dir; no CLI writer"),
    (_B._discover_extension_mcp_servers, "mcp/extension", "extension-contributed mcp; no CLI writer"),
    (_B._discover_extension_skills, "skill/extension", "extension-bundled skills; no CLI writer"),
    (_B._discover_settings_skill_locations, "skill/settings-locations", "skill dirs from settings; no CLI writer"),
    (_B._discover_gated_home_settings_mcp, "mcp/home-settings", "gated home settings.json mcp; no CLI writer"),
    (_B._discover_devcontainer_mcp, "mcp/devcontainer", "devcontainer.json mcp; no CLI writer"),
    (_B._discover_code_workspace_mcp, "mcp/code-workspace", ".code-workspace mcp; no CLI writer"),
    (_B._discover_code_workspace_skills, "skill/code-workspace", ".code-workspace skills; no CLI writer"),
)


def _family_gaps(exclude: frozenset = frozenset()) -> list[Scope]:
    """The shared family Gaps, minus any method already covered by a live scope in a given canary."""
    return [Gap(label, (method,), why) for method, label, why in _FAMILY_GAPS if method not in exclude]


class VSCodeCanary(AgentCanary):
    discoverer = VSCodeDiscoverer
    bin_candidates = ("code",)

    @property
    def scopes(self) -> list[Scope]:
        return [
            # The one VS Code MCP scope its real binary writes live (the user mcp.json). Required: if
            # `code --add-mcp` fails, the scope is genuinely absent and the leg should fail (like the
            # claude McpScopes), not silently pass.
            CommandScope(
                "mcp/user-mcp-json",
                (_B._discover_user_mcp_files,),
                _vscode_add_mcp_argv,
                expected_items=(ExpectedItem("mcp", _VSCODE_USER_MCP_NAME, "mcp/user-mcp-json"),),
            ),
            *_family_gaps(exclude=frozenset({_B._discover_user_mcp_files})),
        ]


class _ForkCanary(AgentCanary):
    """A VS Code fork with no CLI MCP writer yet: a headless run + all family scopes as Gaps."""

    _headless_args: tuple[str, ...] = ("-p", "List the files in this directory.")

    @property
    def scopes(self) -> list[Scope]:
        return [LifecycleStep(label="lifecycle/headless", args=self._headless_args), *_family_gaps()]


class KiroCanary(_ForkCanary):
    discoverer = KiroDiscoverer
    bin_candidates = ("kiro-cli",)
    # Kiro has no `-p`; its headless entrypoint is `chat --no-interactive`.
    _headless_args = ("chat", "--no-interactive", "--trust-all-tools", "List the files in this directory.")


class WindsurfCanary(_ForkCanary):
    # The Windsurf leg drives Cognition's Devin CLI (the CLI bundled with Windsurf), run headless.
    discoverer = WindsurfDiscoverer
    bin_candidates = ("devin",)


class AntigravityCanary(_ForkCanary):
    discoverer = AntigravityDiscoverer
    bin_candidates = ("agy",)


class CursorCanary(_ForkCanary):
    discoverer = CursorDiscoverer
    # The official Cursor CLI was renamed `cursor-agent` -> `agent`; probe both.
    bin_candidates = ("cursor-agent", "agent")

    @property
    def scopes(self) -> list[Scope]:
        # Cursor adds one own scope method (`_discover_builtin_skills`) on top of the shared family set.
        return [
            *super().scopes,
            Gap(
                "skill/builtin",
                (CursorDiscoverer._discover_builtin_skills,),
                "Cursor's synced built-in/managed skills dir (~/.cursor/skills-cursor); no CLI writer",
            ),
        ]
