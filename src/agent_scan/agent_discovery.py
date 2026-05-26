"""Per-agent abstraction for discovering MCP servers and skills.

This module sits alongside the existing data-driven discovery pipeline
(`well_known_clients.py` + `inspect.py`). Each subclass of `AgentDiscoverer`
owns the agent-specific knowledge of where to look for config files and
skills directories. The legacy `inspect.get_mcp_config_per_client()` path
remains the fallback for agents that don't have a subclass yet.
"""

import json
import logging
import traceback
from abc import ABC, abstractmethod
from pathlib import Path

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
from agent_scan.well_known_clients import expand_path

logger = logging.getLogger(__name__)


McpConfigsResult = dict[
    str,
    list[tuple[str, StdioServer | RemoteServer]] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig,
]
SkillsDirsResult = dict[str, list[tuple[str, SkillServer]] | FileNotFoundConfig]


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
    async def discover_mcp_servers(self) -> McpConfigsResult:
        """Parse the agent's MCP config file(s) and return them keyed by absolute path."""

    @abstractmethod
    def discover_skills(self) -> SkillsDirsResult:
        """List the agent's skills, keyed by absolute skills-dir path."""

    async def discover(self) -> ClientToInspect | None:
        """Assemble a ClientToInspect, or None when the agent isn't installed."""
        client_path = self.client_exists()
        if client_path is None:
            return None
        mcp_configs = await self.discover_mcp_servers()
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

    name = "claude code"

    _install_path = "~/.claude"
    _mcp_config_path = "~/.claude.json"
    _skills_subdir = "skills"
    _project_dotclaude_subdir = ".claude"

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        path = expand_path(Path(self._install_path), self.home_directory)
        try:
            if path.exists():
                return path.as_posix()
        except PermissionError:
            logger.warning("Permission error for path %s", path.as_posix())
        return None

    async def discover_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        result.update(await self._discover_global_mcp_servers())
        result.update(await self._discover_project_mcp_servers())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        result.update(self._discover_global_skill())
        result.update(self._discover_project_skills())
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

    # --- private: MCP discovery ---

    async def _discover_global_mcp_servers(self) -> McpConfigsResult:
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
        if isinstance(entries, CouldNotParseMCPConfig):
            return {config_path.as_posix(): entries}
        return {config_path.as_posix(): entries}

    async def _discover_project_mcp_servers(self) -> McpConfigsResult:
        """Parse ``projects.<path>.mcpServers`` from ``~/.claude.json`` — per-project scope.

        Each project contributes one entry keyed by its absolute project path.
        """
        config_path = expand_path(Path(self._mcp_config_path), self.home_directory)
        if not config_path.exists():
            return {}
        data = self._load_config_raw()
        if isinstance(data, CouldNotParseMCPConfig):
            return {config_path.as_posix(): data}
        if not isinstance(data, dict):
            return {}
        projects = data.get("projects")
        if not isinstance(projects, dict):
            return {}

        result: McpConfigsResult = {}
        for project_path, project_config in projects.items():
            if not isinstance(project_path, str) or not isinstance(project_config, dict):
                continue
            project_mcp = project_config.get("mcpServers")
            if not isinstance(project_mcp, dict) or not project_mcp:
                continue
            entries = self._validate_servers(
                project_mcp, source=f"projects.{project_path}.mcpServers in {config_path.as_posix()}"
            )
            result[project_path] = entries
        return result

    # --- private: skills discovery ---

    def _discover_global_skill(self) -> SkillsDirsResult:
        """Scan ``~/.claude/skills`` for user-global skills."""
        skills_dir = expand_path(Path(self._install_path), self.home_directory) / self._skills_subdir
        if not skills_dir.exists():
            return {}
        return {skills_dir.as_posix(): inspect_skills_dir(str(skills_dir))}

    def _discover_project_skills(self) -> SkillsDirsResult:
        """For each project, scan ``<project>/.claude/skills`` if present."""
        result: SkillsDirsResult = {}
        for project_path in self._discover_project_folders():
            skills_dir = project_path / self._project_dotclaude_subdir / self._skills_subdir
            if skills_dir.exists():
                result[skills_dir.as_posix()] = inspect_skills_dir(str(skills_dir))
        return result

    # --- internal helpers ---

    def _load_config_raw(self) -> dict | CouldNotParseMCPConfig | None:
        """Read and JSON-decode ``~/.claude.json``. Returns ``None`` if missing,
        a dict on success, or a ``CouldNotParseMCPConfig`` on malformed JSON.
        """
        config_path = expand_path(Path(self._mcp_config_path), self.home_directory)
        if not config_path.exists():
            return None
        try:
            return json.loads(config_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.exception("Error reading %s: %s", config_path.as_posix(), e)
            return CouldNotParseMCPConfig(
                message=f"could not parse file {config_path.as_posix()}",
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
        for server_config in servers.values():
            if isinstance(server_config, StdioServer):
                server_config = check_server_signature(server_config)
        return [(name, server) for name, server in servers.items()]


_DISCOVERERS: dict[str, type[AgentDiscoverer]] = {
    ClaudeCodeDiscoverer.name: ClaudeCodeDiscoverer,
}


def get_discoverer_class(name: str) -> type[AgentDiscoverer]:
    """Return the discoverer class for an agent name, or raise NotImplementedError.

    Callers instantiate the class with the target ``home_directory``. Looking
    up the class (rather than a constructed instance) lets one well-known
    client be scanned across multiple home directories without re-checking
    NotImplementedError per user.
    """
    cls = _DISCOVERERS.get(name)
    if cls is None:
        raise NotImplementedError(f"No AgentDiscoverer implemented for agent {name!r}")
    return cls
