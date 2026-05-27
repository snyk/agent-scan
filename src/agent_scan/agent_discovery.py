"""Per-agent abstraction for discovering MCP servers and skills.

This module sits alongside the existing data-driven discovery pipeline
(`well_known_clients.py` + `inspect.py`). Each subclass of `AgentDiscoverer`
owns the agent-specific knowledge of where to look for config files and
skills directories. The legacy `inspect.get_mcp_config_per_client()` path
remains the fallback for agents that don't have a subclass yet.
"""

import logging
import os
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
    RemoteServer,
    SkillServer,
    StdioServer,
    UnknownConfigFormat,
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

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
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
        """Validate a raw ``mcpServers`` mapping into typed Stdio/Remote server entries."""
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


DISCOVERERS: dict[str, type[AgentDiscoverer]] = {
    ClaudeCodeDiscoverer.name: ClaudeCodeDiscoverer,
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
