"""Cursor discoverer."""

from typing import ClassVar

from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer


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
    # for skills available across all workspaces.
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
