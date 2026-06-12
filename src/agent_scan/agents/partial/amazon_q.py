"""Amazon Q discoverer."""

import sys

from agent_scan.agents.partial.base import PartialDiscoverer


class AmazonQDiscoverer(PartialDiscoverer):
    """Amazon Q Developer CLI: installed at ``~/.aws/amazonq``, with MCP servers in
    the wrapped ``mcpServers`` tables of ``agents/default.json``, ``agents/mcp.json``
    and ``mcp.json``. No skills path is documented.

    macOS/Linux only: Amazon Q has no documented Windows install (the legacy Windows
    client list omitted it), so ``client_exists`` returns ``None`` on ``win32`` even
    if a same-named directory happens to exist.
    """

    name = "amazon_q"
    _client_exists_paths = ("~/.aws/amazonq",)
    _mcp_config_paths = (
        "~/.aws/amazonq/agents/default.json",
        "~/.aws/amazonq/agents/mcp.json",
        "~/.aws/amazonq/mcp.json",
    )

    def client_exists(self) -> str | None:
        # Branches on the scanning machine's OS (shared by every home on it).
        if sys.platform == "win32":
            return None
        return super().client_exists()
