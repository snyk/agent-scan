"""VSCode (stable + Insiders) discoverer."""

from typing import ClassVar

from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer


class VSCodeDiscoverer(VSCodeFamilyDiscoverer):
    name = "vscode"
    # ``Code`` is stable VS Code; ``Code - Insiders`` is the Insiders channel,
    # which uses a separate userdata tree and extensions dir.
    _user_data_dir_names = ("Code", "Code - Insiders")
    _install_paths = ("~/.vscode", "~/.vscode-insiders")
    _user_mcp_file_paths = ("~/.vscode/mcp.json",)
    _userdata_user_mcp_file = "User/mcp.json"
    _user_settings_file = "User/settings.json"
    _workspace_mcp_relative = (".vscode/mcp.json",)
    # Per the official VS Code Agent Skills docs
    # (https://code.visualstudio.com/docs/copilot/customization/agent-skills):
    # user-level skills live at ``~/.copilot/skills`` (Copilot's canonical
    # location) plus ``~/.claude/skills`` and ``~/.agents/skills`` for
    # cross-agent compatibility. Custom paths declared via the
    # ``chat.agentSkillsLocations`` setting are picked up by
    # ``_settings_skill_locations_enabled`` below.
    _skills_dir_paths = (
        "~/.copilot/skills",
        "~/.claude/skills",
        "~/.agents/skills",
    )
    # Workspace skills, per the same docs: ``.github/skills`` is VS Code's
    # canonical location; ``.claude/skills`` and ``.agents/skills`` are
    # documented cross-agent compatibility paths.
    _workspace_skills_relative = (
        ".github/skills",
        ".claude/skills",
        ".agents/skills",
    )
    _extension_paths = ("~/.vscode/extensions", "~/.vscode-insiders/extensions")
    # Built-in (bundled) extensions shipped inside the VS Code application — the
    # location Copilot Chat moved to once it became a built-in (its skills live
    # at ``…/extensions/copilot/assets/prompts/skills``).
    _builtin_extension_dir_templates: ClassVar[dict[str, tuple[str, ...]]] = {
        "darwin": (
            # VERIFIED on disk (macOS app bundle).
            "/Applications/Visual Studio Code.app/Contents/Resources/app/extensions",
            # inferred — verify: user-local /Applications install (standard macOS).
            "~/Applications/Visual Studio Code.app/Contents/Resources/app/extensions",
            # inferred — verify: Insiders channel mirrors the stable layout.
            "/Applications/Visual Studio Code - Insiders.app/Contents/Resources/app/extensions",
            "~/Applications/Visual Studio Code - Insiders.app/Contents/Resources/app/extensions",
        ),
        "win32": (
            # Documented install roots — code.visualstudio.com/docs/setup/windows
            # (per-user setup under %LOCALAPPDATA%\Programs, system setup under Program Files).
            "~/AppData/Local/Programs/Microsoft VS Code/resources/app/extensions",
            "C:/Program Files/Microsoft VS Code/resources/app/extensions",
            # inferred — verify: Insiders program-dir name mirrors stable.
            "~/AppData/Local/Programs/Microsoft VS Code Insiders/resources/app/extensions",
            "C:/Program Files/Microsoft VS Code Insiders/resources/app/extensions",
        ),
        "linux": (
            # inferred — verify: deb/rpm install root. snap/flatpak live under
            # versioned sandbox mounts with no stable path and are omitted.
            "/usr/share/code/resources/app/extensions",
            "/usr/share/code-insiders/resources/app/extensions",
        ),
    }
    # VSCode/Copilot-specific features (not assumed for forks).
    _settings_skill_locations_enabled = True
    _devcontainer_mcp_enabled = True
    _code_workspace_enabled = True
    _portable_env_var = "VSCODE_PORTABLE"
