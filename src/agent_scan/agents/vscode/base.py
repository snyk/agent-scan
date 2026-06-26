"""Shared base for VSCode and its forks (Cursor, Windsurf, Kiro, Antigravity).

``VSCodeFamilyDiscoverer`` encodes the layout common to VSCode-based IDEs:
user-scope and per-workspace MCP files, ``settings.json`` with nested/dotted
``mcp.servers``, named profiles, a ``workspaceStorage`` tree that points at
opened workspaces, extension bundles, and skill directories. Concrete forks in
sibling modules (``cursor.py``, ``windsurf.py``, ``kiro.py``, ``antigravity.py``,
``vscode.py``) override only path constants and feature flags.
"""

import logging
import os
import sys
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar
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

    A non-empty host denotes a UNC/network share (``file://server/share`` ->
    ``\\\\server\\share``). ``urlparse`` peels the host into ``netloc`` and leaves
    only ``/share/...`` in ``path``, so the host is re-attached as a UNC root
    rather than dropped — otherwise the share would be silently rewritten to a
    bogus local ``/share/...`` path. The empty host and the explicit
    ``localhost`` host both denote a plain local path (RFC 8089). A share that
    isn't mounted on the scanning host simply fails the downstream existence
    check and is skipped.
    """
    if not isinstance(uri, str) or not uri.startswith("file://"):
        return None
    parsed = urlparse(uri)
    local_path = url2pathname(parsed.path)
    host = parsed.netloc
    if not host or host.lower() == "localhost":
        # A path-less local URI (``file://`` / ``file://localhost``) leaves
        # ``local_path`` empty, and ``Path("")`` is ``Path(".")`` — the scanner's
        # CWD, whose ancestors every workspace-relative scan would then walk
        # (``.vscode/mcp.json``, ``.cursor/skills``, …). VSCode never writes a
        # path-less folder URI; treat such a degenerate value as unresolvable.
        if not local_path:
            return None
        return Path(local_path)
    # ``os.sep`` keeps the UNC prefix correct per platform: ``\\server\share`` on
    # Windows, ``//server/share`` on POSIX.
    return Path(f"{os.sep}{os.sep}{host}{local_path}")


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


def _setting_flag_enabled(value: object) -> bool:
    """True if a VS Code boolean-ish setting value is "on".

    VS Code's ``asBoolean`` helper accepts a real bool or the case-insensitive
    strings ``"true"``/``"false"``, so a hand-edited string flag still resolves.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _enabled_skill_location_paths(locations: object) -> list[str]:
    """Non-empty path strings from a ``chat.agentSkillsLocations`` value.

    VS Code registers this setting as an *object* mapping each location
    (``~``/relative path string — not a glob) to a boolean, e.g.
    ``{".github/skills": true, "old-skills": false}``; its ``getLocationsValue``
    parser ignores the array form entirely. We honor the object form (keeping
    only entries whose flag is truthy) and *also* tolerate a bare list of path
    strings as a defensive fallback for hand-edited / legacy files. Resolution of
    each returned path (``~`` / absolute / relative) is left to the caller.
    """
    if isinstance(locations, dict):
        return [k for k, v in locations.items() if isinstance(k, str) and k and _setting_flag_enabled(v)]
    if isinstance(locations, list):
        return [k for k in locations if isinstance(k, str) and k]
    return []


def _resolve_code_workspace_folder(entry: object, base_dir: Path) -> Path | None:
    """Resolve one ``.code-workspace`` ``folders[]`` entry to a Path.

    A multi-root workspace lists its roots as ``{"path": "frontend"}`` (relative
    to the ``.code-workspace`` file's directory — often ``../``-relative — or
    absolute) or, for explicit/remote roots, ``{"uri": "file:///abs/repo"}``.

    Prefers ``uri`` (decoded via :func:`_file_uri_to_path`, so a non-``file://``
    scheme yields ``None``); otherwise resolves ``path`` against ``base_dir`` and
    normalizes lexically (``os.path.normpath``) to collapse ``..`` segments so the
    result dedups cleanly against other discovered roots. Returns ``None`` for a
    non-dict entry or one carrying neither a usable ``uri`` nor ``path``.
    """
    if not isinstance(entry, dict):
        return None
    uri = entry.get("uri")
    if isinstance(uri, str):
        return _file_uri_to_path(uri)
    rel = entry.get("path")
    if not isinstance(rel, str) or not rel:
        return None
    candidate = Path(rel)
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    return Path(os.path.normpath(candidate))


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

    TODO (not yet supported, applies family-wide) — two VS Code "discovery"
    toggles that import config from *other* tools. We should add support for
    both:

    * ``chat.mcp.discovery.enabled`` — auto-discovers and reuses MCP servers
      from other apps (e.g. Claude Desktop). Documented under "Automatically
      discover MCP servers":
      https://code.visualstudio.com/docs/copilot/customization/mcp-servers
    * ``chat.skills.discovery.enabled`` — the skills analogue (auto-discover
      skills from other tools). NOTE: this exact setting name could NOT be
      confirmed in the current VS Code docs; the closest documented surface is
      the Agent Skills page (``chat.agentSkillsLocations`` + auto-detection):
      https://code.visualstudio.com/docs/copilot/customization/agent-skills
      Verify the real setting name and value shape before implementing.

    Which forks actually honor these (and which source keys apply) may vary per
    fork — verify per subclass when implementing.

    Follow-up: ADS-367.
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
    # Directories holding custom-agent / subagent definitions, one file per
    # agent (e.g. Kiro's ``~/.kiro/agents/<agent>.json``). The CLI agent format
    # is JSON and may declare MCP servers *inline* via an ``mcpServers`` block,
    # so each such file is a potential standalone MCP source. Files are named
    # per-agent (not ``mcp.json``), so the whole dir is scanned for ``*.json``
    # and gated on MCP shape (see ``_discover_agent_config_mcp``). Empty by
    # default so only forks that ship this layout opt in.
    _agent_config_dir_paths: tuple[str, ...] = ()  # home-relative, e.g. "~/.kiro/agents"
    _workspace_agent_config_relative: tuple[str, ...] = ()  # workspace-relative, e.g. ".kiro/agents"
    # Per-OS templates for the editor's *built-in* (bundled) extensions dir — the
    # ``extensions`` folder shipped inside the application install, NOT the
    # user-installed ``_extension_paths`` tree. Keyed by the normalized platform
    # ("darwin"/"win32"/"linux"); ``~``-prefixed entries expand against the
    # scanned user's home, absolute entries are used as-is. Empty by default so
    # each fork opts in; a platform absent from a fork's map is a documented
    # coverage gap. Only macOS ``/Applications/<app>.app`` paths for VS Code,
    # Cursor and Windsurf are verified on disk — every other entry is INFERRED
    # and tagged ``inferred — verify`` at its definition. See ADS-367.
    _builtin_extension_dir_templates: ClassVar[dict[str, tuple[str, ...]]] = {}
    # Home-relative ``settings.json`` files that may carry MCP under a top-level
    # ``mcpServers``/``mcp`` key (e.g. Antigravity's ``~/.gemini/settings.json``).
    # Parsed with the same presence-gate as ``_discover_user_settings_mcp``.
    _gated_home_settings_files: tuple[str, ...] = ()
    # Feature flags (opt-in per concrete subclass).
    _settings_skill_locations_enabled: bool = False  # honor chat.agentSkillsLocations
    _devcontainer_mcp_enabled: bool = False  # honor .devcontainer/devcontainer.json
    _code_workspace_enabled: bool = False  # honor .code-workspace settings block
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
        result.update(self._discover_agent_config_mcp())
        result.update(self._discover_extension_mcp_servers())
        result.update(self._discover_devcontainer_mcp())
        result.update(self._discover_code_workspace_mcp())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        result.update(self._discover_home_skills_dirs())
        result.update(self._discover_system_skills_dirs())
        result.update(self._discover_workspace_skills())
        result.update(self._discover_extension_skills())
        result.update(self._discover_settings_skill_locations())
        result.update(self._discover_code_workspace_skills())
        return result

    def _discover_home_skills_dirs(self) -> SkillsDirsResult:
        """Scan the home-relative skill directories declared in ``_skills_dir_paths``."""
        result: SkillsDirsResult = {}
        for raw in self._skills_dir_paths:
            path = expand_path(Path(raw), self.home_directory)
            entries = self._scan_skills_dir(path)
            if entries is not None:
                result[path.as_posix()] = entries
        return result

    def _discover_system_skills_dirs(self) -> SkillsDirsResult:
        """Scan the machine-wide system skill directories from
        :meth:`_platform_system_skills_dirs` (empty unless a subclass overrides)."""
        result: SkillsDirsResult = {}
        for path in self._platform_system_skills_dirs():
            entries = self._scan_skills_dir(path)
            if entries is not None:
                result[path.as_posix()] = entries
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
        profile MCP and skill-locations scans, which all enumerate these the
        same way.
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
        """Parse a multi-purpose ``settings.json`` for MCP, gated on the presence
        of actual MCP servers (a top-level ``mcpServers`` or an ``mcp.servers``).

        ``settings.json`` carries far more than MCP, so most files have no servers
        — those return ``None`` (no entry) rather than a ``CouldNotParseMCPConfig``
        parse failure (the file isn't malformed MCP, it just isn't MCP). A
        top-level ``mcp`` object that carries no ``servers`` (e.g. only ``inputs``
        or ``discovery``) likewise returns ``None``: it holds nothing to surface,
        so handing it to the format tuple would only produce a false-positive
        parse error. Without this gate the full format tuple is tried and
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
        # ``_settings_mcp_server_map`` already covers nested/dotted ``mcp.servers``
        # in its valid dict shape (the shapes VSCode actually writes). The only
        # remaining cases worth handing to the format tuple are a bare top-level
        # ``mcpServers`` (a fork that diverges) or an ``mcp.servers`` in a
        # *malformed* (non-dict) shape we still want flagged. Two cases must NOT
        # fall through, or every format fails / coerces to a bogus entry:
        #   * an ``mcp`` object with no ``servers`` at all (e.g. only ``inputs``
        #     or ``discovery``) — nothing to surface; and
        #   * an ``mcp.servers`` that is present but an *empty* dict — already
        #     seen (and found empty) above, and ``VSCodeConfigFile`` would
        #     validate it to a zero-server ``[]`` entry, surfacing an ordinary
        #     editor settings file as an empty MCP config.
        # Both return ``None`` instead.
        mcp = data.get("mcp")
        mcp_servers_malformed = isinstance(mcp, dict) and "servers" in mcp and not isinstance(mcp.get("servers"), dict)
        if "mcpServers" not in data and not mcp_servers_malformed:
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
            # ``_walk_under_depth`` skips an unreadable userdata tree rather than
            # letting it abort the discoverer — the routine ``--scan-all-users``
            # case where ``Path.exists()`` re-raises ``PermissionError`` on Python
            # 3.12+ for another user's home (see its docstring).
            for workspace_file in _walk_under_depth(
                workspace_storage, "workspace.json", _MAX_WORKSPACE_STORAGE_DEPTH, want_file=True
            ):
                data = self._load_json_file(workspace_file)
                if isinstance(data, dict):
                    results.append((workspace_file, data))
        return results

    def _discover_project_folders(self) -> list[Path]:
        """Resolve opened-workspace roots from ``workspaceStorage`` (see
        :attr:`_workspace_json_files`).

        Single-root windows store a ``folder`` ``file://`` URI pointing directly
        at the workspace root. Multi-root windows instead store a ``workspace``
        URI pointing at a ``.code-workspace`` file whose ``folders[]`` array lists
        the constituent roots; those are expanded here — when this agent honors
        ``.code-workspace`` files (:attr:`_code_workspace_enabled`) — so each
        folder's own workspace-scoped config (``.vscode/mcp.json``, skills,
        ``.devcontainer``, …) is discovered exactly as single-root folders are.
        These roots flow into :meth:`_project_paths_with_ancestors`, which every
        workspace-relative scan consumes.

        Entries that are malformed, lack a resolvable root, or use a non-``file://``
        scheme are skipped silently — IDE-internal state, not user config.
        """
        folders: list[Path] = []
        for _workspace_file, data in self._workspace_json_files:
            workspace_root = _file_uri_to_path(data.get("folder"))
            if workspace_root is not None:
                folders.append(workspace_root)
        if self._code_workspace_enabled:
            folders.extend(self._code_workspace_folder_roots())
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

    def _discover_agent_config_mcp(self) -> McpConfigsResult:
        """Scan custom-agent / subagent definition files for *inline* ``mcpServers``.

        Some forks store agents one-file-per-agent under a dedicated directory —
        Kiro: ``~/.kiro/agents/`` (home-global, ``_agent_config_dir_paths``) and
        ``<workspace>/.kiro/agents/`` (per-workspace,
        ``_workspace_agent_config_relative``). The CLI agent format is JSON and
        may declare MCP servers inline via an ``mcpServers`` block — documented
        as the highest-priority MCP source (kiro.dev/docs/cli/mcp/configuration/)
        — so a server can be defined here and nowhere else.

        Agent files are named ``<agent-name>.json`` (not ``mcp.json``), so the
        whole directory is globbed for ``*.json`` and each file parsed with
        ``skip_unrecognized=True``: an agent file with no inline ``mcpServers``
        (the common case — most only *reference* servers defined elsewhere)
        returns ``None`` and is skipped rather than surfaced as a
        ``CouldNotParseMCPConfig`` false positive. ``ClaudeConfigFile`` (first in
        the family format tuple) lifts the ``mcpServers`` block while ignoring the
        file's non-MCP keys (``name``/``description``/``tools``/…) via the models'
        default ``extra="ignore"``.

        The workspace dirs are resolved against every opened project root *and its
        ancestors* (like :meth:`_discover_workspace_mcp`) so a monorepo root's
        ``.kiro/agents`` is found even when a subdirectory is the opened folder.
        The scan is flat (non-recursive), matching the documented one-file-per-
        agent layout. IDE agents are markdown (``.md``) whose frontmatter only
        *references* servers, defining none, so they are intentionally not read.
        """
        if not self._agent_config_dir_paths and not self._workspace_agent_config_relative:
            return {}
        dirs: list[Path] = [expand_path(Path(raw), self.home_directory) for raw in self._agent_config_dir_paths]
        for root in self._project_paths_with_ancestors():
            dirs.extend(root / rel for rel in self._workspace_agent_config_relative)
        result: McpConfigsResult = {}
        for base in dirs:
            try:
                json_files = list(base.glob("*.json"))
            except (PermissionError, OSError):
                continue
            for json_file in json_files:
                if not json_file.is_file():
                    continue
                parsed = self._parse_mcp_file(json_file, formats=_VSCODE_FAMILY_FORMATS, skip_unrecognized=True)
                if parsed is None:
                    continue
                result[json_file.as_posix()] = parsed
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
        home, plus the portable-mode extensions dir when active and the
        application's built-in (bundled) extensions dir(s) (see
        :meth:`_builtin_extension_dirs`)."""
        dirs = [expand_path(Path(raw), self.home_directory) for raw in self._extension_paths]
        portable = self._portable_user_data_dir()
        if portable is not None:
            # Portable layout: ``<portable>/extensions`` is a sibling of ``user-data``.
            dirs.append(portable.parent / "extensions")
        # Built-in (bundled) extensions shipped inside the application install.
        # Appended here so both the extension-MCP and extension-skills walks
        # cover them with no further wiring.
        dirs.extend(self._builtin_extension_dirs())
        return dirs

    def _builtin_extension_dirs(self) -> list[Path]:
        """Absolute paths to the editor's *built-in* (bundled) extensions dir(s).

        These live inside the application install (macOS
        ``…/Contents/Resources/app/extensions``; ``…/resources/app/extensions``
        elsewhere), so they are machine-global rather than home-relative — though
        the per-user install variants (e.g. macOS ``~/Applications``, Windows
        ``%LOCALAPPDATA%``) are expressed ``~``-relative and expand against the
        scanned user's home. Resolved from :attr:`_builtin_extension_dir_templates`
        for the current platform; empty when the fork declares nothing for it
        (a documented coverage gap, e.g. Linux tarball/AppImage installs).
        """
        key = "linux" if sys.platform in ("linux", "linux2") else sys.platform
        return [
            expand_path(Path(raw), self.home_directory) for raw in self._builtin_extension_dir_templates.get(key, ())
        ]

    # --- private: install-manifest gating (don't scan uninstalled extensions) ---

    @staticmethod
    def _immediate_subdirs(base: Path) -> list[Path]:
        """Immediate subdirectories of ``base`` (empty if absent/unreadable).

        Used for *unmanaged* extension roots that ship no ``extensions.json`` —
        every present subdir is an installed extension, so they are the dirs to
        scan. Errors fail soft (empty list) so one unreadable root cannot drop the
        whole discoverer; mirrors the tolerance in :func:`_walk_under_depth`.
        """
        try:
            return [p for p in base.iterdir() if p.is_dir()]
        except (PermissionError, OSError):
            return []

    def _installed_extension_dirs(self, base: Path) -> list[Path]:
        """The dirs of the extensions *installed* under ``base`` — always a list,
        the directories to walk for bundled ``mcp.json`` / ``skills/``.

        Two kinds of root, both resolved here to a concrete list of dirs:

        * *Manifest-managed* — gated by ``<base>/extensions.json``, VSCode's
          authoritative install manifest. Each entry's ``relativeLocation`` is the
          on-disk dir name; some manifest shapes omit it, so fall back to the
          basename of ``location.path``. The name is resolved against ``base`` and
          confined to it (see :meth:`_confine_to_base`) so an attacker-influenceable
          manifest (under ``--scan-all-users``) cannot redirect the scan outside the
          extension root. Returns exactly the dirs the manifest names, or ``[]``
          when it is missing, unreadable, or unparseable — a managed root **fails
          closed**: an extension is installed iff the manifest lists it, and the
          editor itself loads nothing from such a dir, so there is nothing live to
          scan (a present-but-empty manifest ``[]`` is the same: nothing installed).
        * *Unmanaged* — roots that ship no ``extensions.json`` *by design*: the
          built-in (bundled) extension roots, detected here, and the fork-declared
          unmanaged trees (Kiro Powers, Antigravity's Gemini dir) whose subclasses
          override this. Every present subdir is an installed extension, so this
          returns all of them via :meth:`_immediate_subdirs`.

        Uninstalled leftovers and upgraded-away versions linger on disk but are
        absent from a managed root's manifest, so they are never reached — no
        separate ``.obsolete`` denylist is needed (an obsolete dir is never in the
        manifest).
        """
        # Built-in/bundled roots ship no manifest by design — they are not
        # manifest-managed, so scan every installed (present) subdir rather than
        # failing closed.
        if base in set(self._builtin_extension_dirs()):
            return self._immediate_subdirs(base)
        data = self._load_json_file(base / "extensions.json")
        if not isinstance(data, list):
            return []
        dirs: list[Path] = []
        seen: set[str] = set()
        for entry in data:
            if not isinstance(entry, dict):
                continue
            rel = entry.get("relativeLocation")
            if not (isinstance(rel, str) and rel):
                location = entry.get("location")
                path = location.get("path") if isinstance(location, dict) else None
                rel = Path(path).name if isinstance(path, str) and path else None
            if not rel or rel in seen:
                continue
            seen.add(rel)
            confined = self._confine_to_base(base, rel)
            if confined is not None:
                dirs.append(confined)
        return dirs

    @staticmethod
    def _confine_to_base(base: Path, relative_location: str) -> Path | None:
        """Resolve a manifest dir name against ``base``, confined to it.

        ``relativeLocation`` is normally a single dir name (e.g.
        ``pub.ext-1.0.0``), but the manifest is attacker-influenceable under
        ``--scan-all-users``; a value carrying ``..`` or an absolute path must not
        redirect the walk outside the extension root. Returns the resolved dir, or
        ``None`` for anything that escapes (or equals) ``base``. Normalized
        lexically — no filesystem access, so it cannot be defeated by symlinks
        planted between this check and the walk.
        """
        candidate = Path(os.path.normpath(base / relative_location))
        if candidate != base and candidate.is_relative_to(base):
            return candidate
        return None

    def _extension_scan_roots(self) -> list[Path]:
        """The directories to walk for bundled ``mcp.json`` / ``skills/``: each
        extension root from :meth:`_extension_base_dirs` contributes its installed
        extension dirs (see :meth:`_installed_extension_dirs`). The actual walking
        is the shared :func:`_walk_under_depth`."""
        roots: list[Path] = []
        for base in self._extension_base_dirs():
            roots.extend(self._installed_extension_dirs(base))
        return roots

    def _discover_extension_mcp_servers(self) -> McpConfigsResult:
        """Scan ``mcp.json`` under each *installed* extension (no leading dot — the
        VSCode-family file-name convention) via the shared
        :meth:`_discover_plugin_mcp_files`, the same opportunistic walk the Claude
        Code / Codex / Cursor plugin trees use. Roots are install-manifest gated
        (see :meth:`_extension_scan_roots`) so uninstalled extensions left on disk
        are not scanned. Uses :attr:`_VSCODE_FAMILY_FORMATS` so wrapped, VSCode-flat
        ``servers``, and fully flat shapes all parse.

        ``skip_unrecognized=True``: this walk matches every file merely *named*
        ``mcp.json``, and extensions ship unrelated files under that name (JSON
        schemas, fixtures). Those are skipped rather than surfaced as
        ``CouldNotParseMCPConfig`` false positives; a file with a real MCP shape
        that fails to validate is still reported as malformed.
        """
        return self._discover_plugin_mcp_files(
            self._extension_scan_roots(),
            ("mcp.json",),
            lambda f: self._parse_mcp_file(f, formats=_VSCODE_FAMILY_FORMATS, skip_unrecognized=True),
        )

    def _discover_extension_skills(self) -> SkillsDirsResult:
        """Scan ``skills/`` subdirs under each *installed* extension (roots are
        install-manifest gated, see :meth:`_extension_scan_roots`)."""
        result: SkillsDirsResult = {}
        for root in self._extension_scan_roots():
            for skills_dir in _walk_under_depth(root, "skills", _MAX_PLUGIN_RGLOB_DEPTH, want_file=False):
                if skills_dir.is_dir():
                    result[skills_dir.as_posix()] = inspect_skills_dir(str(skills_dir))
        return result

    # --- private: chat.agentSkillsLocations ---

    def _skill_locations_from_settings(self, settings: dict, base_dir: Path | None) -> SkillsDirsResult:
        """Scan each dir listed in a settings object's ``chat.agentSkillsLocations``.

        The setting is a VS Code object map (``{path: bool}``); a bare list is a
        defensive fallback (see :func:`_enabled_skill_location_paths`). Entries may
        be absolute, ``~``-prefixed, or relative (resolved against ``base_dir``, the
        workspace root for workspace-scoped settings). Only existing directories
        are surfaced.
        """
        result: SkillsDirsResult = {}
        if not self._settings_skill_locations_enabled or not isinstance(settings, dict):
            return result
        locations = _read_chat_setting(settings, "agentSkillsLocations")
        for raw in _enabled_skill_location_paths(locations):
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

    @cached_property
    def _code_workspace_json_files(self) -> list[tuple[Path, dict]]:
        """``(code_workspace_file, parsed_dict)`` for every opened ``.code-workspace``.

        Each file is loaded once and cached for the discoverer's lifetime; the
        inline-settings MCP scan, the skill-locations scan, and the multi-root
        folder-roots expansion all read from here, so a ``.code-workspace`` is
        parsed once rather than re-read per consumer. Malformed / non-dict files
        are skipped.
        """
        results: list[tuple[Path, dict]] = []
        for ws_file in self._code_workspace_files():
            data = self._load_json_file(ws_file)
            if isinstance(data, dict):
                results.append((ws_file, data))
        return results

    def _code_workspace_folder_roots(self) -> list[Path]:
        """Constituent root folders of every opened multi-root ``.code-workspace``.

        Each entry in the file's ``folders`` array names a root via ``path`` or
        ``uri`` (see :func:`_resolve_code_workspace_folder`). Surfacing these lets
        each folder's own workspace-scoped config be discovered for multi-root
        workspaces, mirroring the single-root ``folder`` path.
        """
        roots: list[Path] = []
        for ws_file, data in self._code_workspace_json_files:
            folders = data.get("folders")
            if not isinstance(folders, list):
                continue
            for entry in folders:
                root = _resolve_code_workspace_folder(entry, ws_file.parent)
                if root is not None:
                    roots.append(root)
        return roots

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
        for ws_file, data in self._code_workspace_json_files:
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
        for ws_file, data in self._code_workspace_json_files:
            settings = data.get("settings")
            if not isinstance(settings, dict):
                continue
            result.update(self._skill_locations_from_settings(settings, ws_file.parent))
        return result
