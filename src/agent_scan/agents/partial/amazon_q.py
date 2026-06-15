"""Amazon Q discoverer."""

from agent_scan.agents.partial.base import PartialDiscoverer


class AmazonQDiscoverer(PartialDiscoverer):
    """Amazon Q Developer CLI: installed at ``~/.aws/amazonq``, with MCP servers in
    the wrapped ``mcpServers`` tables of ``agents/default.json``, ``agents/mcp.json``
    and ``mcp.json``. No skills path is documented.

    The ``~/.aws/amazonq`` path is platform-identical and probed on every platform:
    a Windows ``--scan-all-users`` run reaches WSL homes (``utils.get_wsl_home_directories``),
    so detection must not be gated on the scanning machine's OS.
    """

    name = "amazon_q"
    _client_exists_paths = ("~/.aws/amazonq",)
    _mcp_config_paths = (
        "~/.aws/amazonq/agents/default.json",
        "~/.aws/amazonq/agents/mcp.json",
        "~/.aws/amazonq/mcp.json",
    )
