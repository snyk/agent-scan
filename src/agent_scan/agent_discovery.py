"""Per-agent abstraction for discovering MCP servers and skills.

This module sits alongside the existing data-driven discovery pipeline
(`well_known_clients.py` + `inspect.py`). Each subclass of `AgentDiscoverer`
owns the agent-specific knowledge of where to look for config files and
skills directories. The legacy `inspect.get_mcp_config_per_client()` path
remains the fallback for agents that don't have a subclass yet.
"""

import logging
import traceback
from abc import ABC, abstractmethod
from pathlib import Path

from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import (
    ClientToInspect,
    CouldNotParseMCPConfig,
    FileNotFoundConfig,
    RemoteServer,
    SkillServer,
    StdioServer,
    UnknownConfigFormat,
    UnknownMCPConfig,
)
from agent_scan.signed_binary import check_server_signature
from agent_scan.skill_client import inspect_skills_dir
from agent_scan.well_known_clients import expand_path

logger = logging.getLogger(__name__)


McpConfigsResult = dict[
    str,
    list[tuple[str, StdioServer | RemoteServer]]
    | FileNotFoundConfig
    | UnknownConfigFormat
    | CouldNotParseMCPConfig,
]
SkillsDirsResult = dict[str, list[tuple[str, SkillServer]] | FileNotFoundConfig]


class AgentDiscoverer(ABC):
    """Abstract per-agent discoverer.

    Concrete subclasses encapsulate one agent's filesystem layout: where the
    install lives, which JSON file(s) hold its MCP servers, and which directory
    holds its skills.
    """

    name: str

    @abstractmethod
    def client_exists(self, home_directory: Path | None) -> str | None:
        """Return the resolved install path if the agent is present, else None."""

    @abstractmethod
    async def discover_mcp_servers(self, home_directory: Path | None) -> McpConfigsResult:
        """Parse the agent's MCP config file(s) and return them keyed by absolute path."""

    @abstractmethod
    def discover_skills(self, home_directory: Path | None) -> SkillsDirsResult:
        """List the agent's skills, keyed by absolute skills-dir path."""

    async def discover(self, home_directory: Path | None) -> ClientToInspect | None:
        """Assemble a ClientToInspect, or None when the agent isn't installed."""
        client_path = self.client_exists(home_directory)
        if client_path is None:
            return None
        mcp_configs = await self.discover_mcp_servers(home_directory)
        skills_dirs = self.discover_skills(home_directory)
        return ClientToInspect(
            name=self.name,
            client_path=client_path,
            mcp_configs=mcp_configs,
            skills_dirs=skills_dirs,
        )


class ClaudeCodeDiscoverer(AgentDiscoverer):
    name = "claude code"

    _install_path = "~/.claude"
    _mcp_config_path = "~/.claude.json"
    _skills_dir_path = "~/.claude/skills"

    def client_exists(self, home_directory: Path | None) -> str | None:
        path = expand_path(Path(self._install_path), home_directory)
        try:
            if path.exists():
                return path.as_posix()
        except PermissionError:
            logger.warning("Permission error for path %s", path.as_posix())
        return None

    async def discover_mcp_servers(self, home_directory: Path | None) -> McpConfigsResult:
        mcp_configs: McpConfigsResult = {}
        mcp_config_path = expand_path(Path(self._mcp_config_path), home_directory)
        if not mcp_config_path.exists():
            return mcp_configs
        try:
            mcp_config = await scan_mcp_config_file(str(mcp_config_path))
            if isinstance(mcp_config, UnknownMCPConfig):
                mcp_configs[mcp_config_path.as_posix()] = UnknownConfigFormat(
                    message=f"Unknown MCP config: {mcp_config_path.as_posix()}",
                    is_failure=False,
                )
                return mcp_configs

            server_configs_by_name = mcp_config.get_servers()
            for server_config in server_configs_by_name.values():
                if isinstance(server_config, StdioServer):
                    server_config = check_server_signature(server_config)
            mcp_configs[mcp_config_path.as_posix()] = [
                (server_name, server) for server_name, server in server_configs_by_name.items()
            ]
        except Exception as e:
            logger.exception("Error parsing MCP config file %s: %s", mcp_config_path.as_posix(), e)
            mcp_configs[mcp_config_path.as_posix()] = CouldNotParseMCPConfig(
                message=f"could not parse file {mcp_config_path.as_posix()}",
                traceback=traceback.format_exc(),
                is_failure=True,
            )
        return mcp_configs

    def discover_skills(self, home_directory: Path | None) -> SkillsDirsResult:
        skills_dirs: SkillsDirsResult = {}
        skills_dir_path = expand_path(Path(self._skills_dir_path), home_directory)
        if skills_dir_path.exists():
            skills_dirs[skills_dir_path.as_posix()] = inspect_skills_dir(str(skills_dir_path))
        return skills_dirs


_DISCOVERERS: dict[str, type[AgentDiscoverer]] = {
    ClaudeCodeDiscoverer.name: ClaudeCodeDiscoverer,
}


def get_discoverer(name: str) -> AgentDiscoverer:
    """Return a discoverer for the agent name, or raise NotImplementedError."""
    cls = _DISCOVERERS.get(name)
    if cls is None:
        raise NotImplementedError(f"No AgentDiscoverer implemented for agent {name!r}")
    return cls()
