"""Cursor discoverer."""

from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer


class CursorDiscoverer(VSCodeFamilyDiscoverer):
    name = "cursor"
    _user_data_dir_names = ("Cursor",)
    _install_paths = ("~/.cursor",)
    _user_mcp_file_paths = ("~/.cursor/mcp.json",)
    _userdata_user_mcp_file = "User/mcp.json"
    _user_settings_file = "User/settings.json"
    _workspace_mcp_relative = (".cursor/mcp.json",)
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
