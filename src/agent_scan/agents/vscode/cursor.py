"""Cursor discoverer."""

from pathlib import Path
from typing import ClassVar

from agent_scan.agents.vscode.base import SkillsDirsResult, VSCodeFamilyDiscoverer
from agent_scan.well_known_clients import expand_path


class CursorDiscoverer(VSCodeFamilyDiscoverer):
    name = "cursor"
    _user_data_dir_names = ("Cursor",)
    _install_paths = ("~/.cursor",)
    _user_mcp_file_paths = ("~/.cursor/mcp.json",)
    # Inherited VSCode-family fallbacks, NOT documented for Cursor — its docs
    # define MCP only at ``~/.cursor/mcp.json`` (user) and ``.cursor/mcp.json``
    # (workspace, below). Kept as harmless belt-and-suspenders: absent on a
    # normal Cursor install, and the ``settings.json`` scan is presence-gated so
    # it never surfaces a false parse failure.
    _userdata_user_mcp_file = "User/mcp.json"
    _user_settings_file = "User/settings.json"
    # ``.cursor/mcp.json`` is the documented workspace MCP file. ``.mcp.json``
    # at the project root is undocumented (the Cursor docs list only
    # ``.cursor/mcp.json`` and the global ``~/.cursor/mcp.json``) but verified
    # empirically that Cursor loads it — same cross-tool project-root convention
    # the VS Code/Windsurf/Kiro siblings already carry.
    _workspace_mcp_relative = (".cursor/mcp.json", ".mcp.json")
    # Cursor's docs list two primary workspace skill paths and two legacy
    # compatibility paths (Claude Code and Codex). See cursor.com/docs/skills.
    _workspace_skills_relative = (
        ".cursor/skills",
        ".agents/skills",
        ".claude/skills",
        ".codex/skills",
    )
    # Per cursor.com/docs/skills the same four paths apply at the user/home level
    # for skills available across all workspaces. (Cursor's own synced built-in /
    # managed skills live separately at ``~/.cursor/skills-cursor`` — scanned via
    # ``_builtin_skills_dir_paths`` below, kept out of this tuple to avoid a
    # double scan.)
    _skills_dir_paths = (
        "~/.cursor/skills",
        "~/.agents/skills",
        "~/.claude/skills",
        "~/.codex/skills",
    )
    _extension_paths = ("~/.cursor/extensions",)
    # Built-in (bundled) extensions shipped inside the Cursor application.
    _builtin_extension_dir_templates: ClassVar[dict[str, tuple[str, ...]]] = {
        "darwin": (
            "/Applications/Cursor.app/Contents/Resources/app/extensions",  # VERIFIED on disk
            "~/Applications/Cursor.app/Contents/Resources/app/extensions",  # inferred — verify (user-local install)
        ),
        # inferred — verify: per-user NSIS install; Cursor docs give no path.
        "win32": ("~/AppData/Local/Programs/Cursor/resources/app/extensions",),
        # inferred — verify: deb install root. The Linux AppImage build has no
        # stable filesystem path (extensions live inside the mounted image) and
        # is omitted.
        "linux": ("/usr/share/cursor/resources/app/extensions",),
    }
    # Cursor's own built-in / managed skills (``migrate-to-skills``, ``loop``,
    # ``review``, …) are not user-authored: Cursor *syncs* them into
    # ``~/.cursor/skills-cursor`` at the user level (alongside
    # ``.cursor-managed-skills-manifest.json`` / ``.sync-manifest.json``),
    # distinct from the user-authored ``~/.cursor/skills``. Home-relative and the
    # same on every OS (Cursor's user dir is ``~/.cursor`` everywhere), so this is
    # a flat tuple rather than the per-OS map ``_builtin_extension_dir_templates``
    # above needs. Kept out of ``_skills_dir_paths`` so the dir is scanned once,
    # not twice. No other VSCode-family fork ships such a dir. See
    # cursor.com/docs/skills.
    _builtin_skills_dir_paths: ClassVar[tuple[str, ...]] = ("~/.cursor/skills-cursor",)

    def _builtin_skills_dirs(self) -> list[Path]:
        """Resolve the home-relative built-in / managed skills directories."""
        return [expand_path(Path(raw), self.home_directory) for raw in self._builtin_skills_dir_paths]

    def _discover_builtin_skills(self) -> SkillsDirsResult:
        """Scan Cursor's synced built-in / managed skills dir(s) (``~/.cursor/skills-cursor``)."""
        result: SkillsDirsResult = {}
        for skills_dir in self._builtin_skills_dirs():
            entries = self._scan_skills_dir(skills_dir)
            if entries is not None:
                result[skills_dir.as_posix()] = entries
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result = super().discover_skills()
        result.update(self._discover_builtin_skills())
        return result
