"""Antigravity discoverer."""

from pathlib import Path
from typing import ClassVar

from agent_scan.agents.vscode.base import (
    VSCodeFamilyDiscoverer,
    _file_uri_to_path,
    _nested_dict_get,
)
from agent_scan.well_known_clients import expand_path


class AntigravityDiscoverer(VSCodeFamilyDiscoverer):
    name = "antigravity"
    # Same rationale as Windsurf: ``~/.gemini`` alone is the Gemini CLI.
    # v1.x writes to ``Antigravity``, v2.0 writes to ``Antigravity IDE`` —
    # scan both so users on either version surface. v1.x first so that
    # ``_user_data_dir()`` (the single-path accessor) preserves prior behavior.
    _user_data_dir_names = ("Antigravity", "Antigravity IDE")
    _install_paths = ("~/.gemini/antigravity",)
    # IDE-specific MCP plus the unified config that Antigravity CLI + IDE both
    # consult (``~/.gemini/config/mcp_config.json``) per the Google Cloud
    # Community docs on configuring MCP across the Antigravity stack.
    _user_mcp_file_paths = (
        "~/.gemini/antigravity/mcp_config.json",
        "~/.gemini/config/mcp_config.json",
    )
    # Antigravity is a VSCode fork, so its per-user ``settings.json`` follows
    # VSCode's nested ``mcp.servers`` shape. Users who configure MCP through
    # the editor settings UI (rather than the dotfile ``mcp_config.json``) would
    # slip past discovery without this. The gate in
    # :meth:`_discover_user_settings_mcp` keeps an editor-only settings.json
    # (no ``mcp`` key) from being flagged as a parse failure.
    _user_settings_file = "User/settings.json"
    # The shared ``~/.gemini/settings.json`` (used by the Gemini CLI + Antigravity)
    # can carry MCP under a top-level ``mcpServers`` key. Parsed with the
    # presence-gate so an editor-only settings file is not flagged as malformed.
    # Gemini's remote servers use the ``httpUrl`` key (Streamable HTTP), which
    # ``RemoteServer`` accepts as a URL alias (see its ``AliasChoices``).
    _gated_home_settings_files = ("~/.gemini/settings.json",)
    # User-global skill dirs the Antigravity IDE reads, most-reliable first:
    #   * ``~/.gemini/skills`` — shared across all Antigravity tools (CLI+IDE);
    #     the location skills reliably load from in practice.
    #   * ``~/.agents/skills`` (PLURAL) — Antigravity 2.0's default global dir
    #     and the ``npx`` skills-installer target (its ``.skill-lock.json`` lists
    #     ``antigravity``).
    #   * ``~/.gemini/antigravity/skills`` — the officially documented global
    #     path (Google codelab); kept even though its real-world pickup is
    #     unreliable.
    #   * ``~/.agent/skills`` (SINGULAR) — the v1-era path, still read by 2.0 for
    #     backward compatibility. Kept as a harmless fallback.
    # NOT included: ``~/.gemini/antigravity-ide/skills`` (no first-party source
    # documents it) and ``~/.gemini/antigravity-cli/skills`` (CLI-only, not read
    # by the IDE). Workspace ``.agent``/``.agents`` paths are below.
    _skills_dir_paths = (
        "~/.gemini/skills",
        "~/.agents/skills",
        "~/.gemini/antigravity/skills",
        "~/.agent/skills",
    )
    _workspace_skills_relative = (".agent/skills", ".agents/skills")
    # Per-workspace MCP paths. NONE is Google-official: the Antigravity docs site
    # (``antigravity.google/docs/*``) is a client-rendered SPA that discloses no
    # workspace ``mcp.json`` path, and its sitemap lists none — the only documented
    # MCP file is the user-global ``~/.gemini/antigravity/mcp_config.json`` (in
    # ``_user_mcp_file_paths`` above). All three below are SPECULATIVE, added at
    # user request as best-effort catches and individually tagged ``inferred —
    # verify``. Each opened workspace and its ancestors are scanned for these (see
    # :meth:`_discover_workspace_mcp` + :meth:`_gemini_project_folders`); a path
    # that never exists is a harmless no-op. Reconcile if Google publishes one.
    _workspace_mcp_relative = (
        # Cross-tool project-root convention (Claude Code / Cline); mirrors the
        # speculative entry on KiroDiscoverer.
        ".mcp.json",  # inferred — verify (undocumented for Antigravity)
        # Matches Antigravity's ``mcp_config.json`` naming + ``.agents/`` workspace
        # dir (its workspace skills live under ``.agents/skills``); community-floated.
        ".agents/mcp_config.json",  # inferred — verify (undocumented for Antigravity)
        # Workspace mirror of the user-global ``~/.gemini/config/mcp_config.json``.
        ".gemini/mcp_config.json",  # inferred — verify (undocumented for Antigravity)
    )
    # Installed extensions live under ``~/.gemini/extensions/`` (shared with
    # the Gemini CLI; not under the ``antigravity/`` subdir).
    _extension_paths = ("~/.gemini/extensions",)
    # Built-in (bundled) extensions shipped inside the Antigravity application.
    # ENTIRELY INFERRED — verify: Antigravity was not available to verify on
    # disk, and Google has not published install paths. The macOS bundle name is
    # assumed to follow the product name; Google states the Windows installer is
    # user-level (%LOCALAPPDATA%) but not the exact folder; the Linux installer
    # currently extracts to /opt/antigravity (community-reported, version-
    # dependent) and may pack extensions inside app.asar, in which case the dir
    # below is absent. Re-check each entry against a real install.
    _builtin_extension_dir_templates: ClassVar[dict[str, tuple[str, ...]]] = {
        "darwin": (
            "/Applications/Antigravity.app/Contents/Resources/app/extensions",  # inferred — verify
            "~/Applications/Antigravity.app/Contents/Resources/app/extensions",  # inferred — verify
        ),
        "win32": (
            # inferred — verify: user-level install confirmed by Google, exact folder name NOT.
            "~/AppData/Local/Programs/Antigravity/resources/app/extensions",
        ),
        "linux": (
            "/opt/antigravity/resources/app/extensions",  # inferred — verify (may be packed in app.asar)
        ),
    }
    # Antigravity's own opened-workspace registry. Each opened folder is recorded
    # as a ``<id>.json`` file here, with the root under
    # ``projectResources.resources[].folderUri`` (a ``file://`` URI). Shared by the
    # Antigravity CLI + IDE (``~/.gemini/config`` is the unified config root).
    _gemini_projects_dir = "~/.gemini/config/projects"

    def _discover_project_folders(self) -> list[Path]:
        """Opened-workspace roots for Antigravity.

        Antigravity does NOT use the VSCode ``<userdata>/User/workspaceStorage``
        tree the rest of the family relies on — its userdata dir is a bare
        Chromium profile with no ``User/`` subtree, so the inherited walk finds
        nothing on a real install. The IDE instead records each opened workspace
        in its own registry at ``~/.gemini/config/projects/<id>.json``, under
        ``projectResources.resources[].folderUri``. Without reading those, every
        workspace-scoped scan (skills today, any workspace MCP later) comes up
        empty even with a project open.

        ``super()`` (the ``workspaceStorage`` walk) is still consulted so that if
        a future Antigravity build does populate it, those workspaces surface too;
        in practice it returns nothing today. Duplicates across the two sources are
        collapsed downstream by :meth:`_project_paths_with_ancestors`.
        """
        folders = super()._discover_project_folders()
        folders.extend(self._gemini_project_folders())
        return folders

    def _gemini_project_folders(self) -> list[Path]:
        """Workspace roots from the ``~/.gemini/config/projects/*.json`` registry.

        Each project file lists its opened root(s) under
        ``projectResources.resources[].folderUri``. Files that are missing,
        unreadable, malformed, or carry a non-``file://`` URI are skipped silently
        — these are IDE-internal state, not user config, so a stray one must not
        surface as a discovery error (mirrors how the base skips a malformed
        ``workspace.json``).
        """
        projects_dir = expand_path(Path(self._gemini_projects_dir), self.home_directory)
        try:
            project_files = sorted(projects_dir.glob("*.json"))
        except (PermissionError, OSError):
            return []
        folders: list[Path] = []
        for project_file in project_files:
            data = self._load_json_file(project_file)
            if not isinstance(data, dict):
                continue
            resources = _nested_dict_get(data, "projectResources", "resources")
            if not isinstance(resources, list):
                continue
            for resource in resources:
                if not isinstance(resource, dict):
                    continue
                folder = _file_uri_to_path(resource.get("folderUri"))
                if folder is not None:
                    folders.append(folder)
        return folders
