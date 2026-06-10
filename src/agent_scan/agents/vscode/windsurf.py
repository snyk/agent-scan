"""Windsurf discoverer."""

import sys
from pathlib import Path
from typing import ClassVar

from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer


class WindsurfDiscoverer(VSCodeFamilyDiscoverer):
    name = "windsurf"
    _user_data_dir_names = ("Windsurf",)
    # Windsurf (the IDE) keeps its state under ``~/.codeium/windsurf``; the
    # broader ``~/.codeium`` is the Codeium root, shared with the Codeium editor
    # plugin. Both count as an install signal — the deeper path is listed first
    # so a full IDE install reports it as the client path, while ``~/.codeium``
    # keeps parity with legacy well-known-client detection. The windsurf-scoped
    # MCP/skill paths below are unaffected either way.
    _install_paths = ("~/.codeium/windsurf", "~/.codeium")
    _user_mcp_file_paths = ("~/.codeium/windsurf/mcp_config.json",)
    # Windsurf *documents* MCP at exactly one location — the global
    # ``~/.codeium/windsurf/mcp_config.json`` above. The remaining paths are
    # NOT Codeium-documented:
    #   * ``User/settings.json`` — inherited VSCode-family fallback, presence-
    #     gated so harmless.
    #   * ``.mcp.json`` — project-root MCP; VERIFIED EMPIRICALLY that Windsurf
    #     loads it (the docs list only the global path, so this is undocumented).
    #   * ``.windsurf/mcp.json`` — speculative workspace fallback, belt-and-
    #     suspenders alongside the verified ``.mcp.json``.
    _user_settings_file = "User/settings.json"
    _workspace_mcp_relative = (".mcp.json", ".windsurf/mcp.json")
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
    # Windsurf keeps Codeium *engine* state under ``~/.codeium/windsurf`` (the
    # MCP/skill paths above), but its VSCode-fork *user data* — extensions and
    # ``argv.json`` — lives under ``~/.windsurf``. VERIFIED on disk:
    # ``~/.windsurf/extensions/extensions.json`` plus the installed dirs are there,
    # while ``~/.codeium/windsurf`` has no ``extensions`` subdir. Standard
    # ``extensions.json`` tree, so it is manifest-gated like upstream VSCode.
    _extension_paths = ("~/.windsurf/extensions",)
    # Built-in (bundled) extensions shipped inside the Windsurf application.
    _builtin_extension_dir_templates: ClassVar[dict[str, tuple[str, ...]]] = {
        "darwin": (
            "/Applications/Windsurf.app/Contents/Resources/app/extensions",  # VERIFIED on disk
            "~/Applications/Windsurf.app/Contents/Resources/app/extensions",  # inferred — verify (user-local install)
        ),
        # inferred — verify: per-user install; Windsurf docs give no path.
        "win32": ("~/AppData/Local/Programs/Windsurf/resources/app/extensions",),
        # linux: NO STABLE PATH — Windsurf ships a .tar.gz the user extracts to
        # an arbitrary location (no deb/rpm), so there is no fixed install root
        # to scan. Intentionally omitted; revisit if a packaged build ships.
    }

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
