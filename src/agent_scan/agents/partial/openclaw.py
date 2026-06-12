"""Openclaw discoverer."""

from agent_scan.agents.partial.base import PartialDiscoverer


class OpenclawDiscoverer(PartialDiscoverer):
    """Openclaw: installed at ``~/.clawdbot`` or ``~/.openclaw``.

    Skills only -- no documented MCP config file. Includes a project-local
    ``.openclaw/skills`` path (cwd-relative, passed through ``_expand_path``
    unchanged) alongside the home-relative skills directories.
    """

    name = "openclaw"
    _client_exists_paths = ("~/.clawdbot", "~/.openclaw")
    _skills_dir_paths = (
        "~/.clawdbot/skills",
        "~/.openclaw/skills",
        "~/.openclaw/workspace/skills",
        ".openclaw/skills",
    )
