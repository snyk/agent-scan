"""Shared base for VSCode and its forks (Cursor, Windsurf, Kiro, Antigravity).

``VSCodeFamilyDiscoverer`` encodes the layout common to VSCode-based IDEs:
user-scope and per-workspace MCP files, ``settings.json`` with nested/dotted
``mcp.servers``, named profiles, a ``workspaceStorage`` tree that points at
opened workspaces, extension bundles, and skill directories. Concrete forks in
``discoverers.py`` override only path constants and feature flags.
"""

import logging
import os
import sys
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse
from urllib.request import url2pathname

if TYPE_CHECKING:
    from collections.abc import Callable

from agent_scan.agents.base import (
    _MAX_PLUGIN_RGLOB_DEPTH,
    AgentDiscoverer,
    McpConfigsResult,
    McpScanResult,
    SkillsDirsResult,
    _walk_under_depth,
)
from agent_scan.models import (
    ClaudeConfigFile,
    CouldNotParseMCPConfig,
    MCPConfig,
    PluginMCPConfigFile,
    RemoteServer,
    StdioServer,
    VSCodeConfigFile,
    VSCodeMCPConfig,
)
from agent_scan.skill_client import inspect_skills_dir
from agent_scan.well_known_clients import expand_path

logger = logging.getLogger(__name__)
# Cap traversal into ``<userdata>/User/workspaceStorage/``. Layout is
# ``<workspaceStorage>/<hash>/workspace.json`` so depth 2 is sufficient.
_MAX_WORKSPACE_STORAGE_DEPTH = 2

# Format-detection order for VSCode-family ``mcp.json`` / ``settings.json``
# files. First model whose ``model_validate`` succeeds wins. Order matters:
# ``ClaudeConfigFile`` (wrapped ``mcpServers``) is the most common across forks
# and must be tried before ``PluginMCPConfigFile`` (fully flat), which is the
# most permissive and would otherwise greedily match any ``{name: ...}`` map.
_VSCODE_FAMILY_FORMATS: tuple[type[MCPConfig], ...] = (
    ClaudeConfigFile,
    VSCodeConfigFile,
    VSCodeMCPConfig,
    PluginMCPConfigFile,
)


def _claude_desktop_config_path(home_directory: Path | None) -> Path | None:
    """Per-OS path to Claude Desktop's ``claude_desktop_config.json``.

    VSCode can import these servers when ``chat.mcp.discovery.enabled`` is on.
    Returns ``None`` on unsupported platforms.
    """
    if sys.platform == "darwin":
        rel = "~/Library/Application Support/Claude/claude_desktop_config.json"
    elif sys.platform in ("linux", "linux2"):
        rel = "~/.config/Claude/claude_desktop_config.json"
    elif sys.platform == "win32":
        rel = "~/AppData/Roaming/Claude/claude_desktop_config.json"
    else:
        return None
    return expand_path(Path(rel), home_directory)


def _file_uri_to_path(uri: object) -> Path | None:
    """Convert a ``file://`` URI to a ``Path``, or ``None`` for a non-string or
    non-``file://`` value (e.g. ``vscode-remote://`` points at a filesystem we
    can't scan from this process).

    ``url2pathname`` decodes percent-encoding (VSCode stores e.g. ``My%20Projects``
    for paths with spaces) and is platform-aware: on POSIX ``file:///home/u/repo``
    becomes ``/home/u/repo``; on Windows ``file:///C:/Users/me/repo`` becomes
    ``C:\\Users\\me\\repo`` (dropping the URL artifact slash before the drive
    letter). Naïve ``file://`` stripping would leave ``/C:/Users/me/repo`` on
    Windows, which ``Path`` won't resolve correctly.
    """
    if not isinstance(uri, str) or not uri.startswith("file://"):
        return None
    return Path(url2pathname(urlparse(uri).path))


def _nested_dict_get(data: object, *keys: str) -> object:
    """Walk ``keys`` through nested dicts, returning ``None`` if any level is
    missing or not a dict. Safe alternative to chained ``.get(k, {}).get(...)``,
    which raises ``AttributeError`` when an intermediate value is a non-dict."""
    node: object = data
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


def _read_chat_setting(settings: dict, key: str) -> object:
    """Read a ``chat.<key>`` setting in either dotted (``"chat.<key>"``) or
    nested (``{"chat": {"<key>": ...}}``) form. Returns ``None`` if absent."""
    dotted = settings.get(f"chat.{key}")
    if dotted is not None:
        return dotted
    chat = settings.get("chat")
    if isinstance(chat, dict):
        return chat.get(key)
    return None


class VSCodeFamilyDiscoverer(AgentDiscoverer, abstract=True):
    """Shared layout for VSCode and its forks (Cursor, Windsurf, Kiro, Antigravity).

    Subclasses override path constants only — the discovery logic is identical
    across the family:

    * ``_install_paths`` — any one existing means the agent is installed.
    * ``_user_data_dir_names`` — tuple of per-platform userdata folder names
      to look for under ``~/Library/Application Support/`` (macOS),
      ``~/.config/`` (Linux), or ``~/AppData/Roaming/`` (Windows). A tuple so
      we can scan multiple folders for the same IDE — e.g. Antigravity v1.x
      writes to ``Antigravity`` and v2.0 to ``Antigravity IDE``. Empty means
      no userdata tree to scan.
    * ``_user_mcp_file_paths`` — home-relative paths to standalone MCP config
      files (e.g. ``~/.vscode/mcp.json``).
    * ``_user_settings_file`` — userdata-relative path of a ``settings.json``
      file that carries MCP under a nested ``mcp.servers`` key (resolved
      against the platform-specific userdata dir, not the home dir).
    * ``_userdata_user_mcp_file`` — userdata-relative path of a standalone
      ``mcp.json`` under ``<userdata>/User/`` (set on subclasses that ship one).
    * ``_workspace_mcp_relative`` — paths *inside* an opened workspace that
      hold per-workspace MCP config (e.g. ``.vscode/mcp.json``).
    * ``_workspace_skills_relative`` — paths *inside* an opened workspace
      that hold per-workspace skill directories (e.g. ``.cursor/skills``).
    * ``_skills_dir_paths`` — home-relative paths to skill directories.
    * ``_extension_paths`` — home-relative roots holding installed
      extensions (e.g. ``~/.vscode/extensions``). Each tree is walked
      recursively for bundled ``mcp.json`` / ``skills/`` — mirrors Claude
      Code's plugin walk so extension-shipped MCP/skills don't slip past
      discovery.

    Format detection across all MCP files in the family is via
    :attr:`_VSCODE_FAMILY_FORMATS` (passed to :meth:`_parse_mcp_file`), so a
    single subclass can mix wrapped and flat config files without special
    casing.
    """

    name: str = ""

    # Subclass overrides.
    _install_paths: tuple[str, ...] = ()
    _user_data_dir_names: tuple[str, ...] = ()
    _user_mcp_file_paths: tuple[str, ...] = ()
    _userdata_user_mcp_file: str = ""  # e.g. "User/mcp.json"
    _user_settings_file: str = ""  # e.g. "User/settings.json"
    _workspace_mcp_relative: tuple[str, ...] = ()
    _workspace_skills_relative: tuple[str, ...] = ()
    _skills_dir_paths: tuple[str, ...] = ()
    _extension_paths: tuple[str, ...] = ()
    # Home-relative ``settings.json`` files that may carry MCP under a top-level
    # ``mcpServers``/``mcp`` key (e.g. Antigravity's ``~/.gemini/settings.json``).
    # Parsed with the same presence-gate as ``_discover_user_settings_mcp``.
    _gated_home_settings_files: tuple[str, ...] = ()
    # Feature flags (opt-in per concrete subclass).
    _settings_skill_locations_enabled: bool = False  # honor chat.agentSkillsLocations
    _devcontainer_mcp_enabled: bool = False  # honor .devcontainer/devcontainer.json
    _code_workspace_enabled: bool = False  # honor .code-workspace settings block
    _claude_desktop_import_enabled: bool = False  # honor chat.mcp.discovery.enabled
    # Path under $VSCODE_PORTABLE that holds the relocated userdata tree.
    _portable_env_var: str = ""

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        for raw in self._install_paths:
            path = expand_path(Path(raw), self.home_directory)
            try:
                if path.exists():
                    return path.as_posix()
            except PermissionError:
                logger.warning("Permission error for path %s", path.as_posix())
        # The platform-specific userdata dirs are a secondary signal — if no
        # explicit ``_install_paths`` matched but any of the IDE's userdata
        # trees is present, the IDE has run at least once on this machine.
        for userdata in self._user_data_dirs():
            try:
                if userdata.exists():
                    return userdata.as_posix()
            except PermissionError:
                logger.warning("Permission error for path %s", userdata.as_posix())
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        result.update(self._discover_user_mcp_files())
        result.update(self._discover_user_settings_mcp())
        result.update(self._discover_gated_home_settings_mcp())
        result.update(self._discover_profile_mcp_files())
        result.update(self._discover_workspace_mcp())
        result.update(self._discover_extension_mcp_servers())
        result.update(self._discover_devcontainer_mcp())
        result.update(self._discover_code_workspace_mcp())
        result.update(self._discover_claude_desktop_import())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        for raw in self._skills_dir_paths:
            path = expand_path(Path(raw), self.home_directory)
            entries = self._scan_skills_dir(path)
            if entries is not None:
                result[path.as_posix()] = entries
        for path in self._platform_system_skills_dirs():
            entries = self._scan_skills_dir(path)
            if entries is not None:
                result[path.as_posix()] = entries
        result.update(self._discover_workspace_skills())
        result.update(self._discover_extension_skills())
        result.update(self._discover_settings_skill_locations())
        result.update(self._discover_code_workspace_skills())
        return result

    # --- system-level (machine-wide) skills hook ---

    def _platform_system_skills_dirs(self) -> list[Path]:
        """Per-OS machine-wide skill directories (outside any home). Empty by
        default; subclasses (e.g. Windsurf) override with their system paths."""
        return []

    # --- platform-aware userdata helpers ---

    def _user_data_dirs(self) -> list[Path]:
        """Resolve every entry in ``_user_data_dir_names`` for the current platform.

        Returns an empty list if the subclass declares no userdata names or
        the platform is unsupported. Each name maps to one platform path
        (``~/Library/Application Support/<name>`` on macOS, ``~/.config/<name>``
        on Linux, ``~/AppData/Roaming/<name>`` on Windows). Order is preserved
        so callers that pick the "first one" get the v1.x folder before any
        newer variants (e.g. Antigravity ``Antigravity`` before
        ``Antigravity IDE``).
        """
        if not self._user_data_dir_names:
            return []
        if sys.platform == "darwin":
            template = "~/Library/Application Support/{name}"
        elif sys.platform in ("linux", "linux2"):
            template = "~/.config/{name}"
        elif sys.platform == "win32":
            template = "~/AppData/Roaming/{name}"
        else:
            return []
        dirs = [
            expand_path(Path(template.format(name=name)), self.home_directory) for name in self._user_data_dir_names
        ]
        portable = self._portable_user_data_dir()
        if portable is not None:
            # Portable mode relocates the whole userdata tree; prepend it so it
            # is scanned alongside the default locations.
            dirs = [portable, *dirs]
        return dirs

    def _portable_user_data_dir(self) -> Path | None:
        """Userdata dir under ``$VSCODE_PORTABLE`` (``<portable>/user-data``).

        Best-effort: the env var reflects the scanning process, so it is honored
        only when scanning the process's own home (see :meth:`_scans_own_home`);
        a no-op otherwise.
        """
        if not self._portable_env_var or not self._scans_own_home():
            return None
        portable = os.environ.get(self._portable_env_var)
        if not portable:
            return None
        return Path(portable) / "user-data"

    def _user_data_dir(self) -> Path | None:
        """First candidate userdata path (or ``None`` if none declared).

        A single-path convenience for tests that want one deterministic
        ``<userdata>`` directory. Production discovery scans every candidate via
        :meth:`_user_data_dirs`; it does not use this accessor.
        """
        dirs = self._user_data_dirs()
        return dirs[0] if dirs else None

    def _profile_dirs(self, userdata: Path) -> list[Path]:
        """Named-profile directories under ``<userdata>/User/profiles`` (empty if
        the directory is absent or unreadable).

        VSCode and its forks store each named profile as its own subdir there,
        each able to ship its own ``mcp.json`` / ``settings.json``. Used by the
        profile MCP, skill-locations, and Claude-Desktop-discovery scans, which
        all enumerate these the same way.
        """
        profiles_dir = userdata / "User" / "profiles"
        try:
            return [p for p in profiles_dir.iterdir() if p.is_dir()]
        except (PermissionError, FileNotFoundError):
            return []

    # --- private: MCP discovery ---

    def _discover_user_mcp_files(self) -> McpConfigsResult:
        """Parse every file in ``_user_mcp_file_paths`` plus the userdata standalone ``mcp.json``."""
        result: McpConfigsResult = {}
        paths: list[Path] = [expand_path(Path(raw), self.home_directory) for raw in self._user_mcp_file_paths]
        if self._userdata_user_mcp_file:
            paths.extend(userdata / self._userdata_user_mcp_file for userdata in self._user_data_dirs())

        for path in paths:
            parsed = self._parse_mcp_file(path, formats=_VSCODE_FAMILY_FORMATS)
            if parsed is None:
                continue
            result[path.as_posix()] = parsed
        return result

    def _discover_profile_mcp_files(self) -> McpConfigsResult:
        """Walk every per-user profile directory and parse profile-scoped MCP files.

        VSCode (and forks) stores named profiles at ``<userdata>/User/profiles/<id>/``
        where each profile can ship its own ``mcp.json`` and ``settings.json``
        (with nested ``mcp.servers``). A power user with multiple profiles can
        have wildly different MCP server sets per profile — surface all of them.

        The default profile lives at ``<userdata>/User/`` directly and is already
        handled by :meth:`_discover_user_mcp_files` (via ``_userdata_user_mcp_file``)
        and :meth:`_discover_user_settings_mcp` (via ``_user_settings_file``); this
        walk only covers the *named* profiles under ``profiles/``.

        ``settings.json`` is parsed via the presence-gated
        :meth:`_parse_settings_mcp_gated` (it is multi-purpose, so an editor-only
        profile settings file must not surface as a parse failure), while the
        standalone ``mcp.json`` is parsed directly — matching how the default
        profile's two files are each handled.
        """
        # (filename, parser) pairs, each gated on the subclass actually shipping
        # that file type. The standalone mcp.json uses the direct MCP parser; the
        # multi-purpose settings.json uses the presence-gated parser so ordinary
        # editor settings aren't misreported as malformed MCP.
        parsers: list[tuple[str, Callable[[Path], McpScanResult]]] = []
        if self._userdata_user_mcp_file:
            parsers.append(("mcp.json", lambda p: self._parse_mcp_file(p, formats=_VSCODE_FAMILY_FORMATS)))
        if self._user_settings_file:
            parsers.append(("settings.json", self._parse_settings_mcp_gated))
        if not parsers:
            return {}
        result: McpConfigsResult = {}
        for userdata in self._user_data_dirs():
            for profile in self._profile_dirs(userdata):
                for filename, parse in parsers:
                    candidate = profile / filename
                    parsed = parse(candidate)
                    if parsed is None:
                        continue
                    result[candidate.as_posix()] = parsed
        return result

    def _parse_settings_mcp_gated(
        self, path: Path
    ) -> list[tuple[str, StdioServer | RemoteServer]] | CouldNotParseMCPConfig | None:
        """Parse a multi-purpose ``settings.json`` for MCP, gated on a top-level
        ``mcp``/``mcpServers`` key.

        ``settings.json`` carries far more than MCP, so most files have neither
        key — those return ``None`` (no entry) rather than a
        ``CouldNotParseMCPConfig`` parse failure (the file isn't malformed MCP,
        it just isn't MCP). Without this gate the full format tuple is tried and
        the last format's ``ValidationError`` is surfaced as a false positive. A
        genuinely malformed file is returned as ``CouldNotParseMCPConfig``
        (consistent with how malformed standalone ``mcp.json`` files are
        treated). When the gate passes, the full family format tuple is used so a
        nested ``mcp.servers`` (VSCode), bare ``mcpServers`` (a fork that
        diverges), or any other recognized shape still parses.

        The flattened dotted ``"mcp.servers"`` key is handled up front via
        :meth:`_settings_mcp_server_map` (the same extractor the ``.code-workspace``
        scan uses), because none of the format models recognize a dotted key —
        without this a dotted-form ``settings.json`` would slip past discovery.

        Shared by :meth:`_discover_user_settings_mcp` (userdata-relative paths)
        and :meth:`_discover_gated_home_settings_mcp` (home-relative paths).
        """
        data = self._load_json_file(path)
        if isinstance(data, CouldNotParseMCPConfig):
            return data
        if not isinstance(data, dict):
            return None
        # Dotted/nested ``mcp.servers`` (the shape VSCode settings actually use)
        # is extracted explicitly — the format models below only match nested-
        # object, bare ``mcpServers``, or flat shapes, not a dotted key.
        servers = self._settings_mcp_server_map(data)
        if servers:
            return self._validate_servers(servers, source=f"mcp.servers in {path.as_posix()}")
        if "mcp" not in data and "mcpServers" not in data:
            return None
        return self._parse_mcp_file(path, formats=_VSCODE_FAMILY_FORMATS)

    def _discover_user_settings_mcp(self) -> McpConfigsResult:
        """Parse ``<userdata>/<_user_settings_file>`` (e.g. ``User/settings.json``)
        from every candidate userdata folder, gated via
        :meth:`_parse_settings_mcp_gated`.
        """
        if not self._user_settings_file:
            return {}
        result: McpConfigsResult = {}
        for userdata in self._user_data_dirs():
            path = userdata / self._user_settings_file
            entry = self._parse_settings_mcp_gated(path)
            if entry is not None:
                result[path.as_posix()] = entry
        return result

    @cached_property
    def _workspace_json_files(self) -> list[tuple[Path, dict]]:
        """``(workspace_file, parsed_dict)`` for every ``workspace.json`` under
        ``<userdata>/User/workspaceStorage`` across all candidate userdata dirs.

        Walked and loaded once and cached for the discoverer's lifetime. Both the
        single-root project-folder resolution (``folder`` field) and the
        multi-root ``.code-workspace`` scan (``workspace`` field) read from this,
        so the tree is walked once and each file parsed once. Files are collected
        across *every* candidate userdata dir, so an IDE whose userdata path was
        renamed across versions (Antigravity v1.x → v2.0) still surfaces
        workspaces opened under either. Malformed / non-dict files are skipped.
        """
        results: list[tuple[Path, dict]] = []
        for userdata in self._user_data_dirs():
            workspace_storage = userdata / "User" / "workspaceStorage"
            if not workspace_storage.exists():
                continue
            for workspace_file in _walk_under_depth(
                workspace_storage, "workspace.json", _MAX_WORKSPACE_STORAGE_DEPTH, want_file=True
            ):
                data = self._load_json_file(workspace_file)
                if isinstance(data, dict):
                    results.append((workspace_file, data))
        return results

    def _discover_project_folders(self) -> list[Path]:
        """Resolve each opened workspace's single-root ``folder`` from
        ``workspaceStorage`` (see :attr:`_workspace_json_files`).

        The ``folder`` field is a ``file://`` URI pointing at the workspace root.
        Entries that are malformed, lack ``folder`` (e.g. multi-root workspaces
        using ``workspace``/``configuration``), or use a non-``file://`` scheme
        are skipped silently — IDE-internal state, not user config.
        """
        folders: list[Path] = []
        for _workspace_file, data in self._workspace_json_files:
            workspace_root = _file_uri_to_path(data.get("folder"))
            if workspace_root is not None:
                folders.append(workspace_root)
        return folders

    def _discover_workspace_mcp(self) -> McpConfigsResult:
        """For each opened workspace (and every ancestor up to filesystem root),
        scan the workspace-relative MCP paths.

        Walking ancestors mirrors Claude Code's behavior and lets a monorepo
        keep its MCP config at the repo root even when Cursor/VSCode opens a
        subdirectory.
        """
        result: McpConfigsResult = {}
        if not self._workspace_mcp_relative:
            return result
        for path in self._project_paths_with_ancestors():
            for rel in self._workspace_mcp_relative:
                mcp_path = path / rel
                parsed = self._parse_mcp_file(mcp_path, formats=_VSCODE_FAMILY_FORMATS)
                if parsed is None:
                    continue
                result[mcp_path.as_posix()] = parsed
        return result

    # --- private: workspace skills discovery ---

    def _discover_workspace_skills(self) -> SkillsDirsResult:
        """For each opened workspace (and every ancestor), scan each entry in
        ``_workspace_skills_relative`` and surface any skill dirs found.
        """
        result: SkillsDirsResult = {}
        if not self._workspace_skills_relative:
            return result
        for path in self._project_paths_with_ancestors():
            for rel in self._workspace_skills_relative:
                skills_path = path / rel
                entries = self._scan_skills_dir(skills_path)
                if entries is None:
                    continue
                result[skills_path.as_posix()] = entries
        return result

    # --- private: extension walks (parity with Claude Code plugin walks) ---

    def _extension_base_dirs(self) -> list[Path]:
        """Resolve every entry in ``_extension_paths`` against this discoverer's
        home, plus the portable-mode extensions dir when active."""
        dirs = [expand_path(Path(raw), self.home_directory) for raw in self._extension_paths]
        portable = self._portable_user_data_dir()
        if portable is not None:
            # Portable layout: ``<portable>/extensions`` is a sibling of ``user-data``.
            dirs.append(portable.parent / "extensions")
        return dirs

    def _discover_extension_mcp_servers(self) -> McpConfigsResult:
        """Walk each extension root for ``mcp.json`` (no leading dot — matches the
        VSCode-family file-name convention). Mirrors
        :meth:`ClaudeCodeDiscoverer._discover_plugin_mcp_servers` but uses
        :attr:`_VSCODE_FAMILY_FORMATS` so wrapped, VSCode-flat ``servers``, and
        fully flat shapes all parse.
        """
        result: McpConfigsResult = {}
        for base in self._extension_base_dirs():
            if not base.exists():
                continue
            for mcp_file in _walk_under_depth(base, "mcp.json", _MAX_PLUGIN_RGLOB_DEPTH, want_file=True):
                if not mcp_file.is_file():
                    continue
                parsed = self._parse_mcp_file(mcp_file, formats=_VSCODE_FAMILY_FORMATS)
                if parsed is None:
                    continue
                result[mcp_file.as_posix()] = parsed
        return result

    def _discover_extension_skills(self) -> SkillsDirsResult:
        """Walk each extension root for ``skills/`` subdirectories."""
        return self._discover_dirs_under(self._extension_base_dirs(), "skills", inspect_skills_dir)

    # --- private: chat.agentSkillsLocations ---

    def _skill_locations_from_settings(self, settings: dict, base_dir: Path | None) -> SkillsDirsResult:
        """Scan each dir listed in a settings object's ``chat.agentSkillsLocations``.

        Entries may be absolute, ``~``-prefixed, or relative (resolved against
        ``base_dir``, the workspace root for workspace-scoped settings). Only
        existing directories are surfaced.
        """
        result: SkillsDirsResult = {}
        if not self._settings_skill_locations_enabled or not isinstance(settings, dict):
            return result
        locations = _read_chat_setting(settings, "agentSkillsLocations")
        if not isinstance(locations, list):
            return result
        for raw in locations:
            if not isinstance(raw, str) or not raw:
                continue
            if raw.startswith("~"):
                path = expand_path(Path(raw), self.home_directory)
            elif Path(raw).is_absolute():
                path = Path(raw)
            elif base_dir is not None:
                path = base_dir / raw
            else:
                continue
            entries = self._scan_skills_dir(path)
            if entries is not None:
                result[path.as_posix()] = entries
        return result

    def _settings_files_for_skill_locations(self) -> list[tuple[Path, Path | None]]:
        """``(settings.json path, base_dir)`` pairs to scan for skill locations:
        userdata + profile settings (base ``None``) and per-workspace
        ``.vscode/settings.json`` (base = workspace root)."""
        pairs: list[tuple[Path, Path | None]] = []
        if self._user_settings_file:
            for userdata in self._user_data_dirs():
                pairs.append((userdata / self._user_settings_file, None))
                for profile in self._profile_dirs(userdata):
                    pairs.append((profile / "settings.json", None))
        for path in self._project_paths_with_ancestors():
            pairs.append((path / ".vscode" / "settings.json", path))
        return pairs

    def _discover_settings_skill_locations(self) -> SkillsDirsResult:
        """Aggregate ``chat.agentSkillsLocations`` skill dirs across all settings sources."""
        result: SkillsDirsResult = {}
        if not self._settings_skill_locations_enabled:
            return result
        for path, base_dir in self._settings_files_for_skill_locations():
            data = self._load_json_file(path)
            if not isinstance(data, dict):
                continue
            result.update(self._skill_locations_from_settings(data, base_dir))
        return result

    # --- private: home-relative gated settings.json (e.g. ~/.gemini/settings.json) ---

    def _discover_gated_home_settings_mcp(self) -> McpConfigsResult:
        """Parse each ``_gated_home_settings_files`` entry (home-relative settings
        files such as ``~/.gemini/settings.json``) for MCP, gated via
        :meth:`_parse_settings_mcp_gated` so editor-only settings files don't
        surface as parse failures."""
        result: McpConfigsResult = {}
        for raw in self._gated_home_settings_files:
            path = expand_path(Path(raw), self.home_directory)
            entry = self._parse_settings_mcp_gated(path)
            if entry is not None:
                result[path.as_posix()] = entry
        return result

    # --- private: devcontainer.json MCP ---

    def _discover_devcontainer_mcp(self) -> McpConfigsResult:
        """Scan each opened workspace (and ancestors) for
        ``.devcontainer/devcontainer.json`` and ``.devcontainer.json``, surfacing
        ``customizations.vscode.mcp.servers`` via :meth:`_validate_servers`."""
        result: McpConfigsResult = {}
        if not self._devcontainer_mcp_enabled:
            return result
        for root in self._project_paths_with_ancestors():
            for rel in (".devcontainer/devcontainer.json", ".devcontainer.json"):
                path = root / rel
                data = self._load_json_file(path)
                if not isinstance(data, dict):
                    continue
                servers = _nested_dict_get(data, "customizations", "vscode", "mcp", "servers")
                if not isinstance(servers, dict) or not servers:
                    continue
                result[path.as_posix()] = self._validate_servers(
                    servers, source=f"customizations.vscode.mcp.servers in {path.as_posix()}"
                )
        return result

    # --- private: .code-workspace multi-root files ---

    def _code_workspace_files(self) -> list[Path]:
        """``.code-workspace`` files referenced by the ``workspace`` field of any
        ``workspaceStorage/*/workspace.json`` (the multi-root counterpart of the
        single-root ``folder`` field). Reads from the shared
        :attr:`_workspace_json_files` cache, so it does not re-walk the tree."""
        files: list[Path] = []
        for _workspace_file, data in self._workspace_json_files:
            ref = _file_uri_to_path(data.get("workspace"))
            if ref is not None:
                files.append(ref)
        return files

    def _settings_mcp_server_map(self, settings: dict) -> dict | None:
        """Extract the MCP server map from a settings-shaped dict, accepting either
        the nested ``{"mcp": {"servers": {...}}}`` object or the flattened dotted
        ``{"mcp.servers": {...}}`` key.

        VSCode (and forks) persist settings in either form — the settings UI writes
        the nested object, but a hand-edited or programmatically-written
        ``settings.json`` / ``.code-workspace`` may use the dotted key. Shared by
        the ``.code-workspace`` scan (:meth:`_discover_code_workspace_mcp`) and the
        user/profile ``settings.json`` gate (:meth:`_parse_settings_mcp_gated`) so
        both honor the dotted form identically (rather than one path silently
        dropping it).
        """
        mcp = settings.get("mcp")
        if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
            return mcp["servers"]
        dotted = settings.get("mcp.servers")
        if isinstance(dotted, dict):
            return dotted
        return None

    def _discover_code_workspace_mcp(self) -> McpConfigsResult:
        """Surface ``settings.mcp.servers`` from each opened ``.code-workspace`` file."""
        result: McpConfigsResult = {}
        if not self._code_workspace_enabled:
            return result
        for ws_file in self._code_workspace_files():
            data = self._load_json_file(ws_file)
            if not isinstance(data, dict):
                continue
            settings = data.get("settings")
            if not isinstance(settings, dict):
                continue
            servers = self._settings_mcp_server_map(settings)
            if not servers:
                continue
            result[ws_file.as_posix()] = self._validate_servers(
                servers, source=f"settings mcp servers in {ws_file.as_posix()}"
            )
        return result

    def _discover_code_workspace_skills(self) -> SkillsDirsResult:
        """Surface ``chat.agentSkillsLocations`` from each ``.code-workspace``'s
        ``settings`` block, resolving relative entries against the workspace file's
        directory."""
        result: SkillsDirsResult = {}
        if not self._code_workspace_enabled or not self._settings_skill_locations_enabled:
            return result
        for ws_file in self._code_workspace_files():
            data = self._load_json_file(ws_file)
            if not isinstance(data, dict):
                continue
            settings = data.get("settings")
            if not isinstance(settings, dict):
                continue
            result.update(self._skill_locations_from_settings(settings, ws_file.parent))
        return result

    # --- private: Claude Desktop config import (chat.mcp.discovery.enabled) ---

    def _claude_desktop_discovery_enabled(self) -> bool:
        """True if any scanned ``settings.json`` enables ``chat.mcp.discovery.enabled``."""
        if not self._user_settings_file:
            return False
        for userdata in self._user_data_dirs():
            candidates = [userdata / self._user_settings_file]
            candidates.extend(profile / "settings.json" for profile in self._profile_dirs(userdata))
            for path in candidates:
                data = self._load_json_file(path)
                if isinstance(data, dict) and _read_chat_setting(data, "mcp.discovery.enabled") is True:
                    return True
        return False

    def _discover_claude_desktop_import(self) -> McpConfigsResult:
        """Parse Claude Desktop's ``claude_desktop_config.json`` when VSCode's
        ``chat.mcp.discovery.enabled`` is on (servers are reused by VSCode)."""
        if not self._claude_desktop_import_enabled or not self._claude_desktop_discovery_enabled():
            return {}
        path = _claude_desktop_config_path(self.home_directory)
        if path is None:
            return {}
        parsed = self._parse_mcp_file(path, formats=_VSCODE_FAMILY_FORMATS)
        if parsed is None:
            return {}
        return {path.as_posix(): parsed}

    def _workspace_root_from(self, workspace_json: Path) -> Path | None:
        """Read a ``workspace.json`` and return its ``folder`` field as a Path.

        Returns ``None`` for malformed JSON, a missing ``folder`` (e.g. multi-root
        workspaces using ``workspace``/``configuration``), or any non-``file://``
        scheme. ``file://`` URI decoding (percent-encoding + platform-aware drive
        handling) is delegated to :func:`_file_uri_to_path`.
        """
        data = self._load_json_file(workspace_json)
        if not isinstance(data, dict):
            return None
        return _file_uri_to_path(data.get("folder"))
