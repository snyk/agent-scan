"""Kiro discoverer."""

from typing import ClassVar

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
    # User-global MCP. Powers do not write a separate merged file: on install
    # Kiro namespaces each Power's servers into a ``powers.mcpServers`` block
    # inside ``~/.kiro/settings/mcp.json`` (kiro.dev/docs/powers/installation/),
    # and the Power's as-shipped ``mcp.json`` also lands under
    # ``~/.kiro/powers/installed/<name>/`` (walked via ``_extension_paths``).
    _user_mcp_file_paths = ("~/.kiro/settings/mcp.json",)
    # Per kiro.dev/docs/mcp/configuration/: workspace MCP at
    # ``<root>/.kiro/settings/mcp.json`` mirrors the user-global path.
    _workspace_mcp_relative = (".kiro/settings/mcp.json",)
    # Per Kiro docs (https://kiro.dev/docs/skills/): user-global at
    # ``~/.kiro/skills/`` and workspace at ``<root>/.kiro/skills/``.
    _skills_dir_paths = ("~/.kiro/skills",)
    _workspace_skills_relative = (".kiro/skills",)
    # Kiro is a VSCode fork using OpenVSX — installed extensions live under
    # ``~/.kiro/extensions/`` and can contribute ``mcp.json`` / ``skills/``.
    # Installed Kiro Powers live under ``~/.kiro/powers/installed/<name>/``,
    # each shipping its as-authored ``mcp.json`` + ``steering/`` (the official
    # kirodotdev/powers repo documents this layout, e.g. databricks/POWER.md).
    # Walking that tree the same way as extensions picks them up. Powers are
    # user-global only — no documented project-scoped equivalent.
    _extension_paths = (
        "~/.kiro/extensions",
        "~/.kiro/powers/installed",
    )
    # Built-in (bundled) extensions shipped inside the Kiro application.
    # ENTIRELY INFERRED — verify: Kiro was not available to verify on disk and
    # its docs only say "follow the installer". The macOS bundle name and the
    # Windows per-user Programs folder follow the VS Code-fork convention.
    _builtin_extension_dir_templates: ClassVar[dict[str, tuple[str, ...]]] = {
        "darwin": (
            "/Applications/Kiro.app/Contents/Resources/app/extensions",  # inferred — verify
            "~/Applications/Kiro.app/Contents/Resources/app/extensions",  # inferred — verify
        ),
        "win32": (
            "~/AppData/Local/Programs/Kiro/resources/app/extensions",  # inferred — verify
        ),
        # linux: NO STABLE PATH — Kiro distributes an AppImage/tarball with no
        # documented fixed install root, so Linux built-in discovery is omitted.
    }
