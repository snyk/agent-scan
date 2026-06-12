"""Shared base for ``partial`` discoverers.

The ``partial/`` package holds discoverers for agents with a simple, statically
known config layout -- a handful of documented files/directories, with no project,
plugin, extension, or managed scopes. Each agent declares its documented paths as
class-attribute tuples and inherits the three :class:`AgentDiscoverer` outputs from
this base, which turns those paths into MCP-server / skills results using the
parse helpers inherited from ``AgentDiscoverer``.

This mirrors how ``VSCodeFamilyDiscoverer`` shares implementation across the VSCode
forks: every partial agent is still its own registered discoverer with its own
``name`` (so it produces a distinct client in scan output) -- this base only
removes the per-agent boilerplate. Richer or undocumented scopes are deliberately
not covered here; an agent that grows one should graduate to its own dedicated
discoverer.
"""

import logging
from pathlib import Path

from agent_scan.agents.base import (
    AgentDiscoverer,
    McpConfigsResult,
    McpScanResult,
    SkillsDirsResult,
)
from agent_scan.models import CouldNotParseMCPConfig
from agent_scan.utils import expand_path

logger = logging.getLogger(__name__)


class PartialDiscoverer(AgentDiscoverer, abstract=True):
    """Base for agents whose layout is fully described by three path lists.

    Subclasses set ``name`` and any of the path tuples below; ``~`` is expanded
    against the discoverer's bound home (so it resolves correctly per-home under
    ``--scan-all-users``), while non-``~`` paths (e.g. ``.amp/skills``) are
    cwd-relative and pass through unchanged.
    """

    # Any one existing path confirms the agent is installed.
    _client_exists_paths: tuple[str, ...] = ()
    # MCP config files in the wrapped ``{"mcpServers": {...}}`` shape.
    _mcp_config_paths: tuple[str, ...] = ()
    # Skills directories (``<dir>/<skill>/SKILL.md``).
    _skills_dir_paths: tuple[str, ...] = ()

    def client_exists(self) -> str | None:
        for raw in self._client_exists_paths:
            path = expand_path(Path(raw), self.home_directory)
            try:
                if path.exists():
                    return path.as_posix()
            except PermissionError:
                logger.warning("Permission error for path %s", path.as_posix())
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        for raw in self._mcp_config_paths:
            path = expand_path(Path(raw), self.home_directory)
            entry = self._discover_mcpservers_table(path)
            if entry is not None:
                result[path.as_posix()] = entry
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        for raw in self._skills_dir_paths:
            path = expand_path(Path(raw), self.home_directory)
            scanned = self._scan_skills_dir(path)
            if scanned is not None:
                result[path.as_posix()] = scanned
        return result

    def static_mcp_config_paths(self) -> list[str]:
        return [expand_path(Path(raw), self.home_directory).as_posix() for raw in self._mcp_config_paths]

    def _discover_mcpservers_table(self, path: Path) -> McpScanResult:
        """Parse a wrapped ``{"mcpServers": {...}}`` config at ``path``.

        Mirrors ``ClaudeDesktopDiscoverer.discover_mcp_servers``: a missing/empty
        file, a non-object root, or one without a non-empty ``mcpServers`` table
        yields ``None`` (no entry, not a failure -- these files are multi-purpose);
        malformed JSON becomes ``CouldNotParseMCPConfig``; a valid table is
        validated into typed servers.
        """
        data = self._load_json_file(path)
        if data is None:
            return None
        if isinstance(data, CouldNotParseMCPConfig):
            return data
        if not isinstance(data, dict):
            return None
        servers = data.get("mcpServers")
        if not isinstance(servers, dict) or not servers:
            return None
        return self._validate_servers(servers, source=f"mcpServers in {path.as_posix()}")
