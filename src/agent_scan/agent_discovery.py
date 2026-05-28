"""Per-agent abstraction for discovering MCP servers and skills.

This module sits alongside the existing data-driven discovery pipeline
(`well_known_clients.py` + `inspect.py`). Each subclass of `AgentDiscoverer`
owns the agent-specific knowledge of where to look for config files and
skills directories. The legacy `inspect.get_mcp_config_per_client()` path
remains the fallback for agents that don't have a subclass yet.
"""

import logging
import os
import sys
import traceback
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

import pyjson5

from agent_scan.models import (
    ClaudeConfigFile,
    ClientToInspect,
    CouldNotParseMCPConfig,
    FileNotFoundConfig,
    MCPConfig,
    PluginMCPConfigFile,
    RemoteServer,
    SkillServer,
    StdioServer,
    UnknownConfigFormat,
    VSCodeConfigFile,
    VSCodeMCPConfig,
)
from agent_scan.signed_binary import check_server_signature
from agent_scan.skill_client import inspect_skills_dir
from agent_scan.well_known_clients import CLAUDE_CODE_NAME, expand_path

logger = logging.getLogger(__name__)


McpConfigsResult = dict[
    str,
    list[tuple[str, StdioServer | RemoteServer]] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig,
]
SkillsDirsResult = dict[str, list[tuple[str, SkillServer]] | FileNotFoundConfig]

# Cap traversal into ``~/.claude/plugins/{cache,repos}`` to mirror the legacy
# glob-based discovery, which uses ``CandidateClient.max_glob_depth=6``. We pick
# a slightly larger budget here because plugin install layouts vary.
_MAX_PLUGIN_RGLOB_DEPTH = 10

# Top-level keys that only ever appear on a single server config (StdioServer.command,
# RemoteServer.url/serverUrl). Used to disambiguate wrapped vs flat .mcp.json payloads.
_SERVER_CONFIG_DISCRIMINATOR_KEYS = frozenset({"command", "url", "serverUrl"})


def _walk_under_depth(base: Path, name: str, max_path_depth: int, *, want_file: bool) -> Iterator[Path]:
    """Yield paths named ``name`` under ``base``, pruning traversal so each yielded
    path's relative parts count is at most ``max_path_depth``.

    Unlike ``Path.rglob`` + post-hoc filtering, traversal stops at the cap rather
    than walking the full subtree first — so a pathologically deep plugin layout
    cannot blow up the walk. When ``want_file`` is True, only file entries are
    yielded; otherwise directory entries.
    """
    for root_str, dirs, files in os.walk(base):
        root = Path(root_str)
        dir_depth = len(root.relative_to(base).parts)
        candidates = files if want_file else dirs
        if name in candidates:
            yield root / name
        # The dir we're in is at depth `dir_depth`; an entry inside it sits at
        # depth+1. Prune once depth+1 reaches the cap so we don't descend further.
        if dir_depth + 1 >= max_path_depth:
            dirs.clear()


def _select_servers_payload(file_data: dict) -> dict:
    """Pick the server-map payload from a ``.mcp.json`` file (plugin or project scope).

    Files come in two shapes:

    * Wrapped: ``{"mcpServers": {<name>: <server-config>, ...}}``
    * Flat:    ``{<name>: <server-config>, ...}``

    Disambiguation by *value type*, not just key presence: ``file_data["mcpServers"]``
    is treated as a flat-format server config only if one of the discriminator keys
    (``command``/``url``/``serverUrl``) is present with a string value — those are
    always strings on a real server config. A wrapped server *named* "command" maps
    to a dict (the server's own config), so it correctly stays wrapped.

    Note: only applied to plugin and per-project ``.mcp.json`` files. The global
    ``~/.claude.json`` is machine-managed by Claude Code and never flat; its
    parser short-circuits on a missing top-level ``mcpServers`` key.
    """
    candidate = file_data.get("mcpServers")
    if isinstance(candidate, dict) and not any(
        isinstance(candidate.get(key), str) for key in _SERVER_CONFIG_DISCRIMINATOR_KEYS
    ):
        return candidate
    return file_data


class AgentDiscoverer(ABC):
    """Abstract per-agent discoverer.

    Concrete subclasses encapsulate one agent's filesystem layout: where the
    install lives, which JSON file(s) hold its MCP servers, and which directory
    holds its skills. Subclasses MUST set the ``name`` class attribute to the
    canonical agent name used in ``well_known_clients``; this is enforced in
    ``__init_subclass__``.

    A discoverer is bound to a single user's ``home_directory`` at construction;
    the multi-user (`--scan-all-users`) loop in ``pipelines`` constructs one
    discoverer per home directory.

    Note: this abstraction intentionally does NOT consult the corresponding
    ``CandidateClient`` row's ``mcp_config_globs`` / ``skills_dir_globs``
    fields. Subclasses encode their layout directly. If a future agent
    genuinely needs glob-based discovery, override ``discover_mcp_servers`` /
    ``discover_skills`` to handle it explicitly.
    """

    name: str = ""

    def __init__(self, home_directory: Path | None) -> None:
        self.home_directory = home_directory

    def __init_subclass__(cls, *, abstract: bool = False, **kwargs: object) -> None:
        """Enforce a non-empty ``name`` on concrete subclasses.

        Pass ``abstract=True`` (e.g. ``class VSCodeFamilyDiscoverer(AgentDiscoverer, abstract=True)``)
        for intermediate base classes that exist only to share implementation
        with their own concrete subclasses; those don't need a ``name`` of
        their own and won't ever be registered.
        """
        super().__init_subclass__(**kwargs)
        if abstract:
            return
        if not cls.name:
            raise TypeError(f"{cls.__name__} must set a non-empty 'name' class attribute")

    @abstractmethod
    def client_exists(self) -> str | None:
        """Return the resolved install path if the agent is present, else None."""

    @abstractmethod
    def discover_mcp_servers(self) -> McpConfigsResult:
        """Parse the agent's MCP config file(s) and return them keyed by absolute path."""

    @abstractmethod
    def discover_skills(self) -> SkillsDirsResult:
        """List the agent's skills, keyed by absolute skills-dir path."""

    def discover(self) -> ClientToInspect | None:
        """Assemble a ClientToInspect, or None when the agent isn't installed."""
        client_path = self.client_exists()
        if client_path is None:
            return None
        mcp_configs = self.discover_mcp_servers()
        skills_dirs = self.discover_skills()
        return ClientToInspect(
            name=self.name,
            client_path=client_path,
            mcp_configs=mcp_configs,
            skills_dirs=skills_dirs,
        )

    # --- shared helpers (inherited by every concrete subclass) ---

    def _load_json_file(self, path: Path) -> dict | CouldNotParseMCPConfig | None:
        """JSON-decode an arbitrary file. ``None`` if missing or unreadable due to
        permissions, parsed dict on success, ``CouldNotParseMCPConfig`` on
        malformed JSON.

        Uses ``pyjson5`` to match the legacy ``mcp_client.scan_mcp_config_file``
        path, which tolerates ``//`` comments and trailing commas. An empty or
        whitespace-only file is treated as an empty config (also matching legacy).

        ``PermissionError`` is treated like a missing file — under
        ``--scan-all-users`` an unprivileged process routinely hits homes it
        can't read, and surfacing those as ``CouldNotParseMCPConfig`` would
        misclassify access-control denials as malformed-config errors.
        """
        try:
            if not path.exists():
                return None
            content = path.read_text(encoding="utf-8")
            if content.strip() == "":
                return {}
            return pyjson5.loads(content)
        except PermissionError:
            logger.warning("Permission denied reading %s", path.as_posix())
            return None
        except Exception as e:
            logger.exception("Error reading %s: %s", path.as_posix(), e)
            return CouldNotParseMCPConfig(
                message=f"could not parse file {path.as_posix()}",
                traceback=traceback.format_exc(),
                is_failure=True,
            )

    def _validate_servers(
        self, raw: dict, source: str
    ) -> list[tuple[str, StdioServer | RemoteServer]] | CouldNotParseMCPConfig:
        """Validate a raw ``mcpServers`` mapping into typed Stdio/Remote server entries.

        Input is the *already-extracted* server map (e.g. the value of
        ``mcpServers``). For format-aware whole-file parsing (where the wrapper
        layout differs across agents), use :meth:`_parse_mcp_file` instead.
        """
        try:
            validated = ClaudeConfigFile(mcpServers=raw)
        except Exception as e:
            logger.exception("Invalid %s: %s", source, e)
            return CouldNotParseMCPConfig(
                message=f"could not parse {source}",
                traceback=traceback.format_exc(),
                is_failure=True,
            )
        servers = validated.get_servers()
        for name, server_config in servers.items():
            if isinstance(server_config, StdioServer):
                servers[name] = check_server_signature(server_config)
        return list(servers.items())

    def _parse_mcp_file(
        self,
        path: Path,
        *,
        formats: tuple[type[MCPConfig], ...] = (ClaudeConfigFile,),
    ) -> list[tuple[str, StdioServer | RemoteServer]] | CouldNotParseMCPConfig | None:
        """Load ``path``, try each ``MCPConfig`` subclass in order, return the first
        that validates.

        Returns:
          * ``None`` if the file is missing, empty, or unreadable due to permissions
            (matches ``_load_json_file`` semantics).
          * A list of ``(name, server)`` tuples if any of ``formats`` validates the file.
          * ``CouldNotParseMCPConfig`` if the JSON is malformed, or if none of
            ``formats`` validates the file.

        ``formats`` order matters: the first model whose ``model_validate``
        succeeds wins. This mirrors the strategy in
        ``mcp_client.scan_mcp_config_file``.
        """
        data = self._load_json_file(path)
        if data is None:
            return None
        if isinstance(data, CouldNotParseMCPConfig):
            return data
        if not isinstance(data, dict) or not data:
            return None

        last_error: Exception | None = None
        for model in formats:
            try:
                validated = model.model_validate(data)
            except Exception as e:
                last_error = e
                continue
            servers = validated.get_servers()
            for name, server_config in servers.items():
                if isinstance(server_config, StdioServer):
                    servers[name] = check_server_signature(server_config)
            return list(servers.items())

        # None of the formats validated — record as parse failure.
        logger.exception("No MCP format matched %s; last error: %s", path.as_posix(), last_error)
        return CouldNotParseMCPConfig(
            message=f"could not parse {path.as_posix()} as any of {[m.__name__ for m in formats]}",
            traceback="".join(traceback.format_exception(type(last_error), last_error, last_error.__traceback__))
            if last_error is not None
            else "",
            is_failure=True,
        )

    def _scan_skills_dir(self, path: Path) -> list[tuple[str, SkillServer]] | None:
        """Return the parsed skill list for ``path`` if it's an existing directory,
        else ``None``. Thin wrapper that hides the existence check from callers.
        """
        try:
            if not path.exists() or not path.is_dir():
                return None
        except PermissionError:
            return None
        return inspect_skills_dir(str(path))


class ClaudeCodeDiscoverer(AgentDiscoverer):
    """Claude Code discovery: ``~/.claude.json`` + ``~/.claude/skills/`` + per-project scopes.

    The public ``discover_mcp_servers`` / ``discover_skills`` methods orchestrate six
    private helpers split by scope:

    * ``_discover_global_folders`` / ``_discover_project_folders`` enumerate where to look.
    * ``_discover_global_mcp_servers`` reads the top-level ``mcpServers`` key in
      ``~/.claude.json``; ``_discover_project_mcp_servers`` reads each
      ``projects.<path>.mcpServers`` block.
    * ``_discover_global_skill`` reads ``~/.claude/skills``;
      ``_discover_project_skills`` reads ``<project>/.claude/skills`` for every
      project listed in ``~/.claude.json``.
    """

    name = CLAUDE_CODE_NAME

    _install_path = "~/.claude"
    _mcp_config_path = "~/.claude.json"
    _skills_subdir = "skills"
    _project_dotclaude_subdir = ".claude"
    _plugin_subdirs: tuple[str, ...] = ("plugins/cache", "plugins/repos")

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        path = expand_path(Path(self._install_path), self.home_directory)
        try:
            if path.exists():
                return path.as_posix()
        except PermissionError:
            logger.warning("Permission error for path %s", path.as_posix())
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        result.update(self._discover_global_mcp_servers())
        result.update(self._discover_project_mcp_servers())
        result.update(self._discover_plugin_mcp_servers())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        result.update(self._discover_global_skill())
        result.update(self._discover_project_skills())
        result.update(self._discover_plugin_skills())
        return result

    # --- private: folder enumeration ---

    def _discover_global_folders(self) -> list[Path]:
        """Folders that hold user-global Claude Code state (currently just ``~/.claude``)."""
        return [expand_path(Path(self._install_path), self.home_directory)]

    def _discover_project_folders(self) -> list[Path]:
        """Project root paths recorded under ``projects`` in ``~/.claude.json``."""
        data = self._load_config_raw()
        if not isinstance(data, dict):
            return []
        projects = data.get("projects")
        if not isinstance(projects, dict):
            return []
        return [Path(p) for p in projects if isinstance(p, str)]

    def _project_paths_with_ancestors(self) -> list[Path]:
        """Project roots plus every ancestor up to filesystem root, deduplicated.

        Walking up lets project-scope MCP and skills discovery pick up
        ``.mcp.json`` or ``.claude/skills`` directories living in any
        parent folder of a registered project (e.g. a monorepo root that
        contains many project subdirectories).
        """
        seen: set[Path] = set()
        result: list[Path] = []
        for project_path in self._discover_project_folders():
            cur = project_path
            while True:
                if cur not in seen:
                    seen.add(cur)
                    result.append(cur)
                parent = cur.parent
                if parent == cur:
                    break
                cur = parent
        return result

    # --- private: MCP discovery ---

    def _discover_global_mcp_servers(self) -> McpConfigsResult:
        """Parse top-level ``mcpServers`` from ``~/.claude.json`` — the user-global scope."""
        config_path = expand_path(Path(self._mcp_config_path), self.home_directory)
        if not config_path.exists():
            return {}
        data = self._load_config_raw()
        if isinstance(data, CouldNotParseMCPConfig):
            return {config_path.as_posix(): data}
        if not isinstance(data, dict):
            return {}
        top = data.get("mcpServers")
        if not isinstance(top, dict) or not top:
            return {}
        entries = self._validate_servers(top, source=f"global mcpServers in {config_path.as_posix()}")
        return {config_path.as_posix(): entries}

    def _discover_project_mcp_servers(self) -> McpConfigsResult:
        """Per-project MCP discovery for each path in ``_project_paths_with_ancestors``.

        Two sources are checked at every path:

        1. ``projects.<path>.mcpServers`` in ``~/.claude.json`` — keyed by the project path.
        2. ``<path>/.mcp.json`` on disk — keyed by the absolute file path.

        A malformed ``.mcp.json`` becomes a ``CouldNotParseMCPConfig`` entry.
        """
        config_path = expand_path(Path(self._mcp_config_path), self.home_directory)
        data = self._load_config_raw()
        if isinstance(data, CouldNotParseMCPConfig):
            return {config_path.as_posix(): data}
        projects = data.get("projects") if isinstance(data, dict) else None
        if not isinstance(projects, dict):
            projects = {}

        result: McpConfigsResult = {}
        for path in self._project_paths_with_ancestors():
            key = path.as_posix()
            project_config = projects.get(key)
            if isinstance(project_config, dict):
                project_mcp = project_config.get("mcpServers")
                if isinstance(project_mcp, dict) and project_mcp:
                    result[key] = self._validate_servers(
                        project_mcp, source=f"projects.{key}.mcpServers in {config_path.as_posix()}"
                    )

            mcp_file = path / ".mcp.json"
            file_data = self._load_json_file(mcp_file)
            if file_data is None:
                continue
            if isinstance(file_data, CouldNotParseMCPConfig):
                result[mcp_file.as_posix()] = file_data
                continue
            if not isinstance(file_data, dict) or not file_data:
                continue
            file_mcp = _select_servers_payload(file_data)
            if not isinstance(file_mcp, dict) or not file_mcp:
                continue
            result[mcp_file.as_posix()] = self._validate_servers(
                file_mcp, source=f"mcpServers in {mcp_file.as_posix()}"
            )
        return result

    # --- private: skills discovery ---

    def _discover_global_skill(self) -> SkillsDirsResult:
        """Scan ``<install>/skills`` under each user-global folder for skills."""
        result: SkillsDirsResult = {}
        for folder in self._discover_global_folders():
            skills_dir = folder / self._skills_subdir
            if skills_dir.exists():
                result[skills_dir.as_posix()] = inspect_skills_dir(str(skills_dir))
        return result

    def _discover_project_skills(self) -> SkillsDirsResult:
        """For each project (and every ancestor up to root), scan ``<path>/.claude/skills`` if present."""
        result: SkillsDirsResult = {}
        for path in self._project_paths_with_ancestors():
            skills_dir = path / self._project_dotclaude_subdir / self._skills_subdir
            if skills_dir.exists():
                result[skills_dir.as_posix()] = inspect_skills_dir(str(skills_dir))
        return result

    # --- private: plugin discovery ---

    def _plugin_base_dirs(self) -> list[Path]:
        """Roots where Claude Code stages installed plugins: ``cache/`` (hydrated)
        and ``repos/`` (git-cloned source). Both can host MCP servers and skills."""
        return [folder / sub for folder in self._discover_global_folders() for sub in self._plugin_subdirs]

    def _discover_plugin_mcp_servers(self) -> McpConfigsResult:
        """Scan plugin ``.mcp.json`` files under every plugin base dir.

        Plugin ``.mcp.json`` files use the flat ``{name: serverConfig}`` format
        (no ``mcpServers`` wrapper). A top-level ``mcpServers`` key is also
        tolerated for plugins that ship the wrapped format.
        """
        result: McpConfigsResult = {}
        for base in self._plugin_base_dirs():
            if not base.exists():
                continue
            for mcp_file in _walk_under_depth(base, ".mcp.json", _MAX_PLUGIN_RGLOB_DEPTH, want_file=True):
                if not mcp_file.is_file():
                    continue
                file_data = self._load_json_file(mcp_file)
                if file_data is None:
                    continue
                if isinstance(file_data, CouldNotParseMCPConfig):
                    result[mcp_file.as_posix()] = file_data
                    continue
                if not isinstance(file_data, dict) or not file_data:
                    continue
                raw_servers = _select_servers_payload(file_data)
                if not isinstance(raw_servers, dict) or not raw_servers:
                    continue
                result[mcp_file.as_posix()] = self._validate_servers(
                    raw_servers, source=f"plugin {mcp_file.as_posix()}"
                )
        return result

    def _discover_plugin_skills(self) -> SkillsDirsResult:
        """Scan ``skills/`` subdirs under every plugin base dir."""
        result: SkillsDirsResult = {}
        for base in self._plugin_base_dirs():
            if not base.exists():
                continue
            for skills_dir in _walk_under_depth(base, "skills", _MAX_PLUGIN_RGLOB_DEPTH, want_file=False):
                if skills_dir.is_dir():
                    result[skills_dir.as_posix()] = inspect_skills_dir(str(skills_dir))
        return result

    # --- internal helpers ---

    def _load_config_raw(self) -> dict | CouldNotParseMCPConfig | None:
        """Read and JSON-decode ``~/.claude.json``. Returns ``None`` if missing,
        a dict on success, or a ``CouldNotParseMCPConfig`` on malformed JSON.
        """
        return self._load_json_file(expand_path(Path(self._mcp_config_path), self.home_directory))


# --- VSCode family ----------------------------------------------------------

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


class VSCodeFamilyDiscoverer(AgentDiscoverer, abstract=True):
    """Shared layout for VSCode and its forks (Cursor, Windsurf, Kiro, Antigravity).

    Subclasses override path constants only — the discovery logic is identical
    across the family:

    * ``_install_paths`` — any one existing means the agent is installed.
    * ``_user_data_dir_name`` — name of the per-platform userdata folder under
      ``~/Library/Application Support/`` (macOS), ``~/.config/`` (Linux), or
      ``~/AppData/Roaming/`` (Windows). Empty means the agent has no userdata
      tree (Kiro, Antigravity).
    * ``_user_mcp_file_paths`` — home-relative paths to standalone MCP config
      files (e.g. ``~/.vscode/mcp.json``).
    * ``_user_settings_file`` — userdata-relative path of a ``settings.json``
      file that carries MCP under a nested ``mcp.servers`` key (resolved
      against the platform-specific userdata dir, not the home dir).
    * ``_userdata_user_mcp_file`` — userdata-relative path of a standalone
      ``mcp.json`` under ``<userdata>/User/`` (set on subclasses that ship one).
    * ``_workspace_mcp_relative`` — paths *inside* an opened workspace that
      hold per-workspace MCP config (e.g. ``.vscode/mcp.json``).
    * ``_skills_dir_paths`` — home-relative paths to skill directories.

    Format detection across all MCP files in the family is via
    :attr:`_VSCODE_FAMILY_FORMATS` (passed to :meth:`_parse_mcp_file`), so a
    single subclass can mix wrapped and flat config files without special
    casing.
    """

    name: str = ""

    # Subclass overrides.
    _install_paths: tuple[str, ...] = ()
    _user_data_dir_name: str = ""
    _user_mcp_file_paths: tuple[str, ...] = ()
    _userdata_user_mcp_file: str = ""  # e.g. "User/mcp.json"
    _user_settings_file: str = ""  # e.g. "User/settings.json"
    _workspace_mcp_relative: tuple[str, ...] = ()
    _skills_dir_paths: tuple[str, ...] = ()

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        for raw in self._install_paths:
            path = expand_path(Path(raw), self.home_directory)
            try:
                if path.exists():
                    return path.as_posix()
            except PermissionError:
                logger.warning("Permission error for path %s", path.as_posix())
        # The platform-specific userdata dir is a secondary signal — if the
        # explicit ``_install_paths`` didn't match but the IDE's userdata tree
        # is present, the IDE has run at least once on this machine.
        userdata = self._user_data_dir()
        if userdata is not None:
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
        result.update(self._discover_workspace_mcp())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        for raw in self._skills_dir_paths:
            path = expand_path(Path(raw), self.home_directory)
            entries = self._scan_skills_dir(path)
            if entries is not None:
                result[path.as_posix()] = entries
        return result

    # --- platform-aware userdata helper ---

    def _user_data_dir(self) -> Path | None:
        """Resolve ``<userdata>/<_user_data_dir_name>`` for the current platform.

        Returns ``None`` if the subclass doesn't ship a userdata folder
        (Kiro, Antigravity) or the platform is unsupported.
        """
        if not self._user_data_dir_name:
            return None
        if sys.platform == "darwin":
            base = Path(f"~/Library/Application Support/{self._user_data_dir_name}")
        elif sys.platform in ("linux", "linux2"):
            base = Path(f"~/.config/{self._user_data_dir_name}")
        elif sys.platform == "win32":
            base = Path(f"~/AppData/Roaming/{self._user_data_dir_name}")
        else:
            return None
        return expand_path(base, self.home_directory)

    # --- private: MCP discovery ---

    def _discover_user_mcp_files(self) -> McpConfigsResult:
        """Parse every file in ``_user_mcp_file_paths`` plus the userdata standalone ``mcp.json``."""
        result: McpConfigsResult = {}
        paths: list[Path] = [expand_path(Path(raw), self.home_directory) for raw in self._user_mcp_file_paths]
        if self._userdata_user_mcp_file:
            userdata = self._user_data_dir()
            if userdata is not None:
                paths.append(userdata / self._userdata_user_mcp_file)

        for path in paths:
            parsed = self._parse_mcp_file(path, formats=_VSCODE_FAMILY_FORMATS)
            if parsed is None:
                continue
            result[path.as_posix()] = parsed
        return result

    def _discover_user_settings_mcp(self) -> McpConfigsResult:
        """Parse ``<userdata>/<_user_settings_file>`` (e.g. ``User/settings.json``).

        ``settings.json`` carries MCP under a nested ``mcp.servers`` key — the
        ``VSCodeConfigFile`` model handles that shape. We still pass the full
        family format tuple so a settings file with only ``mcpServers`` (e.g.
        from a fork that diverges) is still recognized.
        """
        if not self._user_settings_file:
            return {}
        userdata = self._user_data_dir()
        if userdata is None:
            return {}
        path = userdata / self._user_settings_file
        parsed = self._parse_mcp_file(path, formats=_VSCODE_FAMILY_FORMATS)
        if parsed is None:
            return {}
        return {path.as_posix(): parsed}

    def _discover_workspace_mcp(self) -> McpConfigsResult:
        """Walk ``<userdata>/User/workspaceStorage/<hash>/workspace.json``, follow
        each ``folder`` URL to an opened workspace, then look for per-workspace
        MCP files (e.g. ``<workspace>/.vscode/mcp.json``).

        Failures inside the workspaceStorage tree (malformed ``workspace.json``,
        unreadable hash dirs) are logged and skipped — they're VSCode-internal
        state, not user-authored MCP files, so they must NOT surface as
        ``CouldNotParseMCPConfig``.
        """
        result: McpConfigsResult = {}
        userdata = self._user_data_dir()
        if userdata is None or not self._workspace_mcp_relative:
            return result
        workspace_storage = userdata / "User" / "workspaceStorage"
        if not workspace_storage.exists():
            return result

        for workspace_file in _walk_under_depth(
            workspace_storage, "workspace.json", _MAX_WORKSPACE_STORAGE_DEPTH, want_file=True
        ):
            workspace_root = self._workspace_root_from(workspace_file)
            if workspace_root is None:
                continue
            for rel in self._workspace_mcp_relative:
                mcp_path = workspace_root / rel
                parsed = self._parse_mcp_file(mcp_path, formats=_VSCODE_FAMILY_FORMATS)
                if parsed is None:
                    continue
                result[mcp_path.as_posix()] = parsed
        return result

    def _workspace_root_from(self, workspace_json: Path) -> Path | None:
        """Read a ``workspace.json`` and return its ``folder`` field as a Path.

        Returns ``None`` for malformed JSON, missing ``folder`` (e.g. multi-root
        workspaces using ``configuration``), or unparseable file URIs. The
        ``folder`` field is a ``file://`` URI where path segments are
        percent-encoded (VSCode stores e.g. ``My%20Projects`` for paths with
        spaces) — we must decode before constructing the ``Path``, otherwise
        the per-workspace MCP lookup would silently miss any workspace whose
        path contains a special character.
        """
        from urllib.parse import unquote

        data = self._load_json_file(workspace_json)
        if not isinstance(data, dict):
            return None
        folder = data.get("folder")
        if not isinstance(folder, str):
            return None
        if folder.startswith("file://"):
            folder = folder[len("file://") :]
        return Path(unquote(folder))


# --- VSCode family: concrete subclasses ---


class VSCodeDiscoverer(VSCodeFamilyDiscoverer):
    name = "vscode"
    _user_data_dir_name = "Code"
    _install_paths = ("~/.vscode",)
    _user_mcp_file_paths = ("~/.vscode/mcp.json",)
    _userdata_user_mcp_file = "User/mcp.json"
    _user_settings_file = "User/settings.json"
    _workspace_mcp_relative = (".vscode/mcp.json",)
    _skills_dir_paths = ("~/.copilot/skills",)


class CursorDiscoverer(VSCodeFamilyDiscoverer):
    name = "cursor"
    _user_data_dir_name = "Cursor"
    _install_paths = ("~/.cursor",)
    _user_mcp_file_paths = ("~/.cursor/mcp.json",)
    _userdata_user_mcp_file = "User/mcp.json"
    _user_settings_file = "User/settings.json"
    _workspace_mcp_relative = (".cursor/mcp.json",)
    _skills_dir_paths = ("~/.cursor/skills",)


class WindsurfDiscoverer(VSCodeFamilyDiscoverer):
    name = "windsurf"
    _user_data_dir_name = "Windsurf"
    # ``~/.codeium`` alone is the Codeium VSCode *plugin*; the IDE proper
    # lives under ``~/.codeium/windsurf``. Use the deeper path so we don't
    # report Windsurf as installed for plugin-only users.
    _install_paths = ("~/.codeium/windsurf",)
    _user_mcp_file_paths = ("~/.codeium/windsurf/mcp_config.json",)
    _user_settings_file = "User/settings.json"
    _workspace_mcp_relative = (".windsurf/mcp.json",)
    _skills_dir_paths = ("~/.codeium/windsurf/skills",)


class KiroDiscoverer(VSCodeFamilyDiscoverer):
    name = "kiro"
    # Kiro doesn't follow the platform-specific userdata layout (no
    # ``~/Library/Application Support/Kiro`` observed); everything lives
    # under ``~/.kiro``.
    _user_data_dir_name = ""
    _install_paths = ("~/.kiro",)
    _user_mcp_file_paths = ("~/.kiro/settings/mcp.json",)


class AntigravityDiscoverer(VSCodeFamilyDiscoverer):
    name = "antigravity"
    # Same rationale as Windsurf: ``~/.gemini`` alone is the Gemini CLI.
    _user_data_dir_name = ""
    _install_paths = ("~/.gemini/antigravity",)
    _user_mcp_file_paths = ("~/.gemini/antigravity/mcp_config.json",)


DISCOVERERS: dict[str, type[AgentDiscoverer]] = {
    ClaudeCodeDiscoverer.name: ClaudeCodeDiscoverer,
    VSCodeDiscoverer.name: VSCodeDiscoverer,
    CursorDiscoverer.name: CursorDiscoverer,
    WindsurfDiscoverer.name: WindsurfDiscoverer,
    KiroDiscoverer.name: KiroDiscoverer,
    AntigravityDiscoverer.name: AntigravityDiscoverer,
}


def find_discoverers(home_directory: Path | None) -> list[AgentDiscoverer]:
    """Construct one instance per registered discoverer with the given home, and
    return only those whose ``client_exists()`` confirms the agent is installed.
    Each returned instance is home-bound; the caller just runs
    ``d.discover()`` on each.

    A discoverer whose ``client_exists()`` raises is skipped (and logged) so a
    single buggy subclass cannot abort discovery for the whole machine.
    """
    found: list[AgentDiscoverer] = []
    for cls in DISCOVERERS.values():
        discoverer = cls(home_directory)
        try:
            exists = discoverer.client_exists() is not None
        except Exception:
            logger.exception("Discoverer %s.client_exists() raised; skipping", cls.__name__)
            continue
        if exists:
            found.append(discoverer)
    return found
