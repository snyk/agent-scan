"""Amp discoverer."""

from agent_scan.agents.partial.base import PartialDiscoverer


class AmpDiscoverer(PartialDiscoverer):
    """Amp: installed at ``~/.config/agents`` (global) or a project-local ``.amp``.

    Skills only -- no documented MCP config file. The ``.amp`` paths are
    project-relative (resolved against the current working directory), not
    home-relative, so they are passed through ``expand_path`` unchanged.
    """

    name = "amp"
    _client_exists_paths = ("~/.config/agents", ".amp")
    _skills_dir_paths = ("~/.config/agents/skills", ".amp/skills")
