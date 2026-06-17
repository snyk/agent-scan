"""Gemini CLI discoverer."""

from agent_scan.agents.partial.base import PartialDiscoverer


class GeminiCliDiscoverer(PartialDiscoverer):
    """Gemini CLI: installed at ``~/.gemini``, with MCP servers in the wrapped
    ``mcpServers`` table of ``~/.gemini/settings.json`` and skills under
    ``~/.gemini/skills``. Paths are identical across macOS/Linux/Windows.

    ``~/.gemini/antigravity`` (the Antigravity IDE, which nests under the same
    ``~/.gemini`` tree) is a separate agent covered by ``AntigravityDiscoverer``.
    """

    name = "gemini cli"
    _client_exists_paths = ("~/.gemini",)
    _mcp_config_paths = ("~/.gemini/settings.json",)
    _skills_dir_paths = ("~/.gemini/skills",)
