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
from collections.abc import Callable, Iterator
from functools import cached_property
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import url2pathname

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
from agent_scan.skill_client import inspect_commands_dir, inspect_skills_dir
from agent_scan.well_known_clients import CLAUDE_CODE_NAME, expand_path

logger = logging.getLogger(__name__)


McpConfigsResult = dict[
    str,
    list[tuple[str, StdioServer | RemoteServer]] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig,
]
SkillsDirsResult = dict[str, list[tuple[str, SkillServer]] | FileNotFoundConfig]
# Return type of the per-file MCP parsers (``_parse_mcp_file`` /
# ``_parse_settings_mcp_gated``): parsed servers, a parse failure, or ``None``
# when the file is absent/empty/not-MCP.
McpScanResult = list[tuple[str, StdioServer | RemoteServer]] | CouldNotParseMCPConfig | None

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
        # Lazily-populated cache for _project_paths_with_ancestors. A discoverer
        # is constructed once per home and used for a single scan (see
        # find_discoverers), so the project list is stable for its lifetime and
        # the several discovery methods that consult it need not re-walk the
        # workspaceStorage tree / re-read ~/.claude.json each time.
        self._project_paths_cache: list[Path] | None = None

    def _scans_own_home(self) -> bool:
        """True when this discoverer targets the scanning process's own user.

        Env-var-relocated config paths (``CLAUDE_CONFIG_DIR``, ``VSCODE_PORTABLE``)
        reflect the *scanning process's* environment, so they may only be honored
        when the home being scanned is that same user's. ``home_directory is None``
        is the explicit own-home sentinel, but production never passes it: for the
        current user ``get_readable_home_directories`` returns ``Path.home()`` (see
        ``pipelines.discover_clients_to_inspect``), so an equal ``Path.home()`` must
        also count as own-home — otherwise those env paths never activate in a real
        scan. Other users' homes under ``--scan-all-users`` compare unequal and are
        correctly excluded (the scanner can't know their env).
        """
        return self.home_directory is None or self.home_directory == Path.home()

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

    def _servers_to_signed_list(self, validated: MCPConfig) -> list[tuple[str, StdioServer | RemoteServer]]:
        """Materialize a validated config's servers into ``(name, server)`` tuples,
        replacing each Stdio entry with its signature-checked form.

        Shared by :meth:`_validate_servers` and :meth:`_parse_mcp_file` so the
        signature-check step stays in one place.
        """
        servers = validated.get_servers()
        for name, server_config in servers.items():
            if isinstance(server_config, StdioServer):
                servers[name] = check_server_signature(server_config)
        return list(servers.items())

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
        return self._servers_to_signed_list(validated)

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
            return self._servers_to_signed_list(validated)

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

    def _discover_dirs_under(
        self,
        bases: list[Path],
        subdir_name: str,
        inspect_fn: Callable[[str], list[tuple[str, SkillServer]]],
    ) -> SkillsDirsResult:
        """Walk each base dir for ``subdir_name`` directories and inspect each hit.

        Shared by the Claude Code plugin ``skills``/``commands`` walks and the
        VSCode-family extension ``skills`` walk — all iterate identically: for
        each existing base, ``_walk_under_depth`` for the named directory, then
        run ``inspect_fn`` (``inspect_skills_dir`` or ``inspect_commands_dir``)
        on each match.
        """
        result: SkillsDirsResult = {}
        for base in bases:
            if not base.exists():
                continue
            for found in _walk_under_depth(base, subdir_name, _MAX_PLUGIN_RGLOB_DEPTH, want_file=False):
                if found.is_dir():
                    result[found.as_posix()] = inspect_fn(str(found))
        return result

    # --- shared project-folder enumeration (used by both Claude Code and the VSCode family) ---

    def _discover_project_folders(self) -> list[Path]:
        """Return the project roots this agent has opened.

        Each subclass surfaces them from its own source of truth: Claude Code
        reads the ``projects`` map in ``~/.claude.json``; the VSCode family
        walks ``<userdata>/User/workspaceStorage``. Discoverers without a
        project concept return ``[]`` so the ancestor walk is a no-op.
        """
        return []

    def _project_paths_with_ancestors(self) -> list[Path]:
        """Project roots plus every ancestor up to filesystem root, deduplicated.

        Walking up lets project-scope MCP and skills discovery pick up config
        living in any parent folder of an opened project (e.g. a monorepo root
        that contains many project subdirectories).

        The result is cached for the discoverer's lifetime — every project-scope
        discovery method calls this, and recomputing would re-walk
        workspaceStorage (VSCode family) or re-read ``~/.claude.json`` (Claude
        Code) on each call.
        """
        if self._project_paths_cache is not None:
            return self._project_paths_cache
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
        self._project_paths_cache = result
        return result


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
        path = self._claude_base_dir()
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
        result.update(self._discover_plugin_manifest_mcp_servers())
        result.update(self._discover_managed_mcp_servers())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        result.update(self._discover_global_skill())
        result.update(self._discover_project_skills())
        result.update(self._discover_plugin_skills())
        result.update(self._discover_global_commands())
        result.update(self._discover_project_commands())
        result.update(self._discover_plugin_commands())
        result.update(self._discover_plugin_manifest_skills())
        return result

    # --- config-dir resolution (CLAUDE_CONFIG_DIR) ---

    def _claude_base_dir(self) -> Path:
        """The base directory holding Claude Code state (``~/.claude`` by default).

        ``CLAUDE_CONFIG_DIR`` relocates this directory. The env var reflects the
        *scanning process's* environment, so it is honored only when scanning the
        process's own home (see :meth:`_scans_own_home`); under ``--scan-all-users``
        the scanner can't know each *other* target user's env, so the per-home
        default is used instead.
        """
        if self._scans_own_home():
            config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
            if config_dir:
                return Path(config_dir)
        return expand_path(Path(self._install_path), self.home_directory)

    def _config_json_path(self) -> Path:
        """Path to the global ``.claude.json``.

        When ``CLAUDE_CONFIG_DIR`` is active (own-home scan), the config lives at
        ``<base>/.claude.json``; falls back to the legacy ``~/.claude.json`` when
        that relocated file does not exist.
        """
        if self._scans_own_home() and os.environ.get("CLAUDE_CONFIG_DIR"):
            relocated = self._claude_base_dir() / ".claude.json"
            if relocated.exists():
                return relocated
        return expand_path(Path(self._mcp_config_path), self.home_directory)

    # --- private: folder enumeration ---

    def _discover_global_folders(self) -> list[Path]:
        """Folders that hold user-global Claude Code state (``~/.claude``, or the
        ``CLAUDE_CONFIG_DIR`` override on own-home scans)."""
        return [self._claude_base_dir()]

    def _discover_project_folders(self) -> list[Path]:
        """Project root paths recorded under ``projects`` in ``~/.claude.json``."""
        data = self._load_config_raw()
        if not isinstance(data, dict):
            return []
        projects = data.get("projects")
        if not isinstance(projects, dict):
            return []
        return [Path(p) for p in projects if isinstance(p, str)]

    # --- private: MCP discovery ---

    def _discover_global_mcp_servers(self) -> McpConfigsResult:
        """Parse top-level ``mcpServers`` from ``~/.claude.json`` — the user-global scope."""
        config_path = self._config_json_path()
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
        config_path = self._config_json_path()
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
        return self._discover_dirs_under(self._plugin_base_dirs(), "skills", inspect_skills_dir)

    # --- private: commands discovery (commands are skills per current docs) ---

    def _discover_global_commands(self) -> SkillsDirsResult:
        """Scan ``<install>/commands`` for command files under each global folder."""
        result: SkillsDirsResult = {}
        for folder in self._discover_global_folders():
            commands_dir = folder / "commands"
            if commands_dir.exists():
                result[commands_dir.as_posix()] = inspect_commands_dir(str(commands_dir))
        return result

    def _discover_project_commands(self) -> SkillsDirsResult:
        """For each project (and ancestor), scan ``<path>/.claude/commands`` if present."""
        result: SkillsDirsResult = {}
        for path in self._project_paths_with_ancestors():
            commands_dir = path / self._project_dotclaude_subdir / "commands"
            if commands_dir.exists():
                result[commands_dir.as_posix()] = inspect_commands_dir(str(commands_dir))
        return result

    def _discover_plugin_commands(self) -> SkillsDirsResult:
        """Scan ``commands/`` subdirs under every plugin base dir."""
        return self._discover_dirs_under(self._plugin_base_dirs(), "commands", inspect_commands_dir)

    # --- private: enterprise/managed MCP discovery ---

    def _managed_mcp_path(self) -> Path | None:
        """Per-OS absolute path to the enterprise ``managed-mcp.json``, or ``None``
        on unsupported platforms. See
        https://code.claude.com/docs/en/managed-mcp."""
        if sys.platform == "darwin":
            return Path("/Library/Application Support/ClaudeCode/managed-mcp.json")
        if sys.platform in ("linux", "linux2"):
            return Path("/etc/claude-code/managed-mcp.json")
        if sys.platform == "win32":
            # ``Program Files`` may live on a non-C: drive or be relocated, so
            # resolve it from the machine-level env var instead of hardcoding the
            # drive. ``PROGRAMW6432`` always points at the 64-bit root (even from a
            # 32-bit process); fall back to ``PROGRAMFILES`` then the conventional
            # default. This is a machine-global path (not per-user), so honoring
            # the scanning process's env is correct even under ``--scan-all-users``.
            # (Python uppercases ``os.environ`` keys on Windows, so the canonical
            # mixed-case ``ProgramW6432``/``ProgramFiles`` vars resolve here.)
            program_files = os.environ.get("PROGRAMW6432") or os.environ.get("PROGRAMFILES") or r"C:\Program Files"
            return Path(program_files) / "ClaudeCode" / "managed-mcp.json"
        return None

    def _discover_managed_mcp_servers(self) -> McpConfigsResult:
        """Parse the system-wide ``managed-mcp.json`` (wrapped ``mcpServers``).

        This is a machine-level file at an absolute system path, not a per-home
        path, so it is identical across every home scanned on one machine;
        downstream keying is by absolute path so duplicates collapse.
        """
        path = self._managed_mcp_path()
        if path is None:
            return {}
        parsed = self._parse_mcp_file(path)
        if parsed is None:
            return {}
        return {path.as_posix(): parsed}

    # --- private: inline plugin manifest discovery ---

    @cached_property
    def _plugin_manifests(self) -> list[tuple[Path, dict]]:
        """``(manifest_path, parsed_dict)`` for every readable ``plugin.json`` under
        the plugin base dirs.

        Walked and loaded once and cached for the discoverer's lifetime — the
        inline-MCP and skills manifest scans both consume it, so neither the walk
        nor the JSON read is repeated. Malformed or non-dict manifests are
        skipped (so a bad ``plugin.json`` is silently ignored, as before).
        """
        manifests: list[tuple[Path, dict]] = []
        for base in self._plugin_base_dirs():
            if not base.exists():
                continue
            for manifest in _walk_under_depth(base, "plugin.json", _MAX_PLUGIN_RGLOB_DEPTH, want_file=True):
                if not manifest.is_file():
                    continue
                data = self._load_json_file(manifest)
                if isinstance(data, dict):
                    manifests.append((manifest, data))
        return manifests

    def _discover_plugin_manifest_mcp_servers(self) -> McpConfigsResult:
        """Parse inline ``mcpServers`` from each plugin's
        ``.claude-plugin/plugin.json`` manifest.

        A plugin can declare its MCP servers inline in the manifest instead of a
        standalone ``.mcp.json``. The ``mcpServers`` value may also be a *string*
        path referencing a separate file — those are already covered by the
        ``.mcp.json`` walk, so only the inline dict form is handled here.
        """
        result: McpConfigsResult = {}
        for manifest, data in self._plugin_manifests:
            inline = data.get("mcpServers")
            if not isinstance(inline, dict) or not inline:
                continue
            result[manifest.as_posix()] = self._validate_servers(
                inline, source=f"plugin manifest {manifest.as_posix()}"
            )
        return result

    def _discover_plugin_manifest_skills(self) -> SkillsDirsResult:
        """Scan skill dirs listed in each plugin's ``.claude-plugin/plugin.json``
        ``skills`` array. Paths are resolved relative to the plugin root (the
        parent of the ``.claude-plugin`` dir). Only string entries are honored.
        """
        result: SkillsDirsResult = {}
        for manifest, data in self._plugin_manifests:
            skills = data.get("skills")
            if not isinstance(skills, list):
                continue
            plugin_root = manifest.parent.parent
            for rel in skills:
                if not isinstance(rel, str):
                    continue
                skills_dir = plugin_root / rel
                if skills_dir.is_dir():
                    result[skills_dir.as_posix()] = inspect_skills_dir(str(skills_dir))
        return result

    # --- internal helpers ---

    def _load_config_raw(self) -> dict | CouldNotParseMCPConfig | None:
        """Read and JSON-decode the global ``.claude.json`` (honoring
        ``CLAUDE_CONFIG_DIR`` on own-home scans). Returns ``None`` if missing,
        a dict on success, or a ``CouldNotParseMCPConfig`` on malformed JSON.
        """
        return self._load_json_file(self._config_json_path())


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


# --- VSCode family: concrete subclasses ---


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
    # VSCode/Copilot-specific features (not assumed for forks).
    _settings_skill_locations_enabled = True
    _devcontainer_mcp_enabled = True
    _code_workspace_enabled = True
    _claude_desktop_import_enabled = True
    _portable_env_var = "VSCODE_PORTABLE"


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


class KiroDiscoverer(VSCodeFamilyDiscoverer):
    name = "kiro"
    # Kiro stores chat history and globalStorage under
    # ``~/Library/Application Support/kiro/`` (lowercase, observed in the IDE
    # at ``…/kiro/User/globalStorage/kiro.kiroagent``), so it does follow the
    # VSCode userdata convention — necessary for workspaceStorage walks that
    # power per-workspace skill discovery.
    _user_data_dir_names = ("kiro",)
    _install_paths = ("~/.kiro",)
    # User-global MCP plus the auto-generated merged Powers config that Kiro
    # writes at install time — see kirodotdev/powers and the install flow at
    # kiro.dev/docs/powers/installation/.
    _user_mcp_file_paths = (
        "~/.kiro/settings/mcp.json",
        "~/.kiro/powers.mcp.json",
    )
    # Per kiro.dev/docs/mcp/configuration/: workspace MCP at
    # ``<root>/.kiro/settings/mcp.json`` mirrors the user-global path.
    _workspace_mcp_relative = (".kiro/settings/mcp.json",)
    # Per Kiro docs (https://kiro.dev/docs/skills/): user-global at
    # ``~/.kiro/skills/`` and workspace at ``<root>/.kiro/skills/``.
    _skills_dir_paths = ("~/.kiro/skills",)
    _workspace_skills_relative = (".kiro/skills",)
    # Kiro is a VSCode fork using OpenVSX — installed extensions live under
    # ``~/.kiro/extensions/`` and can contribute ``mcp.json`` / ``skills/``.
    # Installed Kiro Powers live under ``~/.kiro/powers/installed/<name>/``
    # and each carries its own ``mcp.json`` (the bundled MCP server for that
    # Power). Walking that tree the same way as extensions picks them up.
    # Per kiro.dev/docs/powers/ Powers are user-global only — no documented
    # project-scoped equivalent.
    _extension_paths = (
        "~/.kiro/extensions",
        "~/.kiro/powers/installed",
    )


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
    # NOTE: Gemini's remote ``httpUrl`` server shape is not covered by
    # ``RemoteServer`` (``url``/``serverUrl`` only) — out of scope here.
    _gated_home_settings_files = ("~/.gemini/settings.json",)
    # Per Antigravity docs / Google codelabs: user-global at
    # ``~/.gemini/antigravity/skills/`` and workspace at ``.agent/skills``
    # (singular ``.agent``). The plural ``.agents/skills`` is the newer reported
    # default; ``~/.agent/skills`` (singular, HOME) is a tool-agnostic location
    # Antigravity also reads. ``~/.gemini/skills/`` is shared CLI+IDE.
    _skills_dir_paths = (
        "~/.gemini/antigravity/skills",
        "~/.gemini/skills",
        "~/.agent/skills",
    )
    _workspace_skills_relative = (".agent/skills", ".agents/skills")
    # No per-workspace MCP path configured. Antigravity's official documentation
    # site (``antigravity.google/docs/*``) is a client-rendered SPA whose pages
    # don't disclose a workspace-scoped ``mcp.json`` file path. The official
    # sitemap (``antigravity.google/sitemap.xml``) lists only
    # ``/docs/{agent-features,editor-features,faq,features,get-started,rest-api}``
    # and the ``/docs/mcp`` page that search engines index documents the
    # user-global ``~/.gemini/antigravity/mcp_config.json`` (already in
    # ``_user_mcp_file_paths`` above). Community write-ups float candidates
    # like ``.agents/mcp_config.json``, but those are not Google-official.
    # Leaving ``_workspace_mcp_relative`` empty is the conservative call:
    # adding a guessed path would let a user-controlled file on disk feed
    # parse failures into every scan and falsely advertise coverage we don't
    # actually have. Revisit once Google publishes a path we can cite.
    # Installed extensions live under ``~/.gemini/extensions/`` (shared with
    # the Gemini CLI; not under the ``antigravity/`` subdir).
    _extension_paths = ("~/.gemini/extensions",)


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
