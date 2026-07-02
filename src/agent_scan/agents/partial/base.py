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

from pathlib import Path

from agent_scan.agents.base import (
    AgentDiscoverer,
    McpConfigsResult,
    SkillsDirsResult,
)


class PartialDiscoverer(AgentDiscoverer, abstract=True):
    """Base for agents whose layout is fully described by three path lists.

    Subclasses set ``name`` and any of the path tuples below — plus the inherited
    ``AgentDiscoverer._skills_dir_paths`` for skills directories; ``~`` is expanded
    against the discoverer's bound home (so it resolves correctly per-home under
    ``--scan-all-users``), while non-``~`` paths (e.g. ``.amp/skills``) are
    cwd-relative and pass through unchanged.
    """

    # Any one existing path confirms the agent is installed.
    _client_exists_paths: tuple[str, ...] = ()
    # MCP config files, documented as the wrapped ``{"mcpServers": {...}}`` shape
    # but parsed leniently (``mcp.servers``/``servers`` wrappers and flat server
    # maps are also accepted -- legacy ``well_known_clients`` scan parity).
    _mcp_config_paths: tuple[str, ...] = ()

    def client_exists(self) -> str | None:
        return self._first_existing_path([self._expand_path(Path(raw)) for raw in self._client_exists_paths])

    def discover_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        for raw in self._mcp_config_paths:
            path = self._expand_path(Path(raw))
            entry = self._discover_mcpservers_table(path)
            if entry is not None:
                result[path.as_posix()] = entry
        return result

    def discover_skills(self) -> SkillsDirsResult:
        return self._discover_home_skills_dirs()

    def static_mcp_config_paths(self) -> list[str]:
        return [self._expand_path(Path(raw)).as_posix() for raw in self._mcp_config_paths]
