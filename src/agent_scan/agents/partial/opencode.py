"""Opencode discoverer."""

from agent_scan.agents.partial.base import PartialDiscoverer


class OpencodeDiscoverer(PartialDiscoverer):
    """Opencode: detected by the presence of ``~/.config/opencode``.

    No MCP-config or skills filesystem path is documented, so only installation is
    reported (``discover_mcp_servers`` / ``discover_skills`` return ``{}``).
    """

    name = "opencode"
    _client_exists_paths = ("~/.config/opencode",)
