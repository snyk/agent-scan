"""Windsurf discoverer."""

import sys
from pathlib import Path

from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer


class WindsurfDiscoverer(VSCodeFamilyDiscoverer):
    name = "windsurf"
    _user_data_dir_names = ("Windsurf",)
    # ``~/.codeium`` alone is the Codeium VSCode *plugin*; the IDE proper
    # lives under ``~/.codeium/windsurf``. Use the deeper path so we don't
    # report Windsurf as installed for plugin-only users.
    _install_paths = ("~/.codeium/windsurf",)
    _user_mcp_file_paths = ("~/.codeium/windsurf/mcp_config.json",)
    _user_settings_file = "User/settings.json"
    _workspace_mcp_relative = (".windsurf/mcp.json",)
    # Windsurf docs: workspace skills at ``.windsurf/skills`` plus cross-agent
    # compatibility for ``.agents/skills`` and ``.claude/skills``.
    # https://docs.windsurf.com/windsurf/cascade/skills
    _workspace_skills_relative = (
        ".windsurf/skills",
        ".agents/skills",
        ".claude/skills",
    )
    # Windsurf docs list cross-agent compat at the user/home level too: skills
    # placed at ``~/.agents/skills`` and ``~/.claude/skills`` are honored
    # alongside the canonical ``~/.codeium/windsurf/skills``.
    _skills_dir_paths = (
        "~/.codeium/windsurf/skills",
        "~/.agents/skills",
        "~/.claude/skills",
    )
    _extension_paths = ("~/.codeium/windsurf/extensions",)

    def _platform_system_skills_dirs(self) -> list[Path]:
        """Machine-wide skills dirs documented at
        https://docs.windsurf.com/windsurf/cascade/skills (system, not per-home)."""
        if sys.platform == "darwin":
            return [Path("/Library/Application Support/Windsurf/skills")]
        if sys.platform in ("linux", "linux2"):
            return [Path("/etc/windsurf/skills")]
        if sys.platform == "win32":
            return [Path(r"C:\ProgramData\Windsurf\skills")]
        return []
