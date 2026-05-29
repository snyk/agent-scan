"""Kiro discoverer."""

from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer


class KiroDiscoverer(VSCodeFamilyDiscoverer):
    name = "kiro"
    # Kiro stores chat history and globalStorage under
    # ``~/Library/Application Support/kiro/`` (lowercase, observed in the IDE
    # at ``…/kiro/User/globalStorage/kiro.kiroagent``), so it does follow the
    # VSCode userdata convention — necessary for workspaceStorage walks that
    # power per-workspace skill discovery.
    _user_data_dir_names = ("kiro",)
    _install_paths = ("~/.kiro",)
    # User-global MCP plus the auto-generated merged Powers config that Kiro
    # writes at install time — see kirodotdev/powers and the install flow at
    # kiro.dev/docs/powers/installation/.
    _user_mcp_file_paths = (
        "~/.kiro/settings/mcp.json",
        "~/.kiro/powers.mcp.json",
    )
    # Per kiro.dev/docs/mcp/configuration/: workspace MCP at
    # ``<root>/.kiro/settings/mcp.json`` mirrors the user-global path.
    _workspace_mcp_relative = (".kiro/settings/mcp.json",)
    # Per Kiro docs (https://kiro.dev/docs/skills/): user-global at
    # ``~/.kiro/skills/`` and workspace at ``<root>/.kiro/skills/``.
    _skills_dir_paths = ("~/.kiro/skills",)
    _workspace_skills_relative = (".kiro/skills",)
    # Kiro is a VSCode fork using OpenVSX — installed extensions live under
    # ``~/.kiro/extensions/`` and can contribute ``mcp.json`` / ``skills/``.
    # Installed Kiro Powers live under ``~/.kiro/powers/installed/<name>/``
    # and each carries its own ``mcp.json`` (the bundled MCP server for that
    # Power). Walking that tree the same way as extensions picks them up.
    # Per kiro.dev/docs/powers/ Powers are user-global only — no documented
    # project-scoped equivalent.
    _extension_paths = (
        "~/.kiro/extensions",
        "~/.kiro/powers/installed",
    )
