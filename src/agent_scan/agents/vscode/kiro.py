"""Kiro discoverer."""

from pathlib import Path
from typing import ClassVar

from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer
from agent_scan.well_known_clients import expand_path


class KiroDiscoverer(VSCodeFamilyDiscoverer):
    name = "kiro"
    # Kiro stores its userdata tree under ``~/Library/Application Support/Kiro/``
    # (capital K, verified on disk at ``…/Kiro/User/workspaceStorage/``), matching
    # the rest of the VSCode family (``Code``/``Cursor``/``Windsurf``). The
    # lowercase ``kiro.kiroagent`` seen under ``…/User/globalStorage/`` is the
    # extension id, NOT the userdata folder. The case is load-bearing: the
    # workspaceStorage walk that powers per-workspace (project) MCP/skill
    # discovery hangs off this name, so a lowercase ``kiro`` would miss the tree
    # on case-sensitive filesystems and under ``--scan-all-users``.
    _user_data_dir_names = ("Kiro",)
    _install_paths = ("~/.kiro",)
    # User-global MCP. Powers do not write a separate merged file: on install
    # Kiro namespaces each Power's servers into a ``powers.mcpServers`` block
    # inside ``~/.kiro/settings/mcp.json`` (kiro.dev/docs/powers/installation/),
    # and the Power's as-shipped ``mcp.json`` also lands under
    # ``~/.kiro/powers/installed/<name>/`` (walked via ``_extension_paths``).
    _user_mcp_file_paths = ("~/.kiro/settings/mcp.json",)
    # Per kiro.dev/docs/mcp/configuration/: workspace MCP at
    # ``<root>/.kiro/settings/mcp.json`` mirrors the user-global path.
    # The second entry, ``<root>/.mcp.json``, is SPECULATIVE — NOT documented for
    # Kiro (its only documented MCP files are the ``.kiro/settings/mcp.json``
    # pair); added at user request as a best-effort catch for the cross-tool
    # project-root convention (Claude Code / Cline). If Kiro never ships one the
    # path is a harmless no-op (the file simply won't exist).
    _workspace_mcp_relative = (
        ".kiro/settings/mcp.json",
        ".mcp.json",  # inferred — verify (undocumented for Kiro)
    )
    # Kiro custom agents / subagents live one file per agent under
    # ``~/.kiro/agents/`` (global) and ``<root>/.kiro/agents/`` (workspace).
    # CLI agents are JSON and may define MCP servers inline via an ``mcpServers``
    # block — the highest-priority MCP source per kiro.dev/docs/cli/mcp/configuration/
    # — so those files are scanned for inline servers (see
    # ``_discover_agent_config_mcp``). IDE agents are markdown that only reference
    # servers defined elsewhere, so they contribute no new server definitions.
    _agent_config_dir_paths = ("~/.kiro/agents",)
    _workspace_agent_config_relative = (".kiro/agents",)
    # Per Kiro docs (https://kiro.dev/docs/skills/): user-global at
    # ``~/.kiro/skills/`` and workspace at ``<root>/.kiro/skills/``.
    # The second workspace entry, ``.agents/skills``, is INFERRED — NOT documented
    # for Kiro; added as a best-effort catch for the cross-tool project-root skills
    # convention its VSCode-family siblings (Cursor/VSCode/Windsurf) already honor.
    # If Kiro never uses it the path is a harmless no-op (the dir simply won't exist).
    _skills_dir_paths = ("~/.kiro/skills",)
    _workspace_skills_relative = (
        ".kiro/skills",
        ".agents/skills",  # inferred — verify (undocumented for Kiro)
    )
    # Kiro is a VSCode fork using OpenVSX — installed extensions live under
    # ``~/.kiro/extensions/``, tracked by that dir's ``extensions.json`` install
    # manifest, so it is scanned manifest-gated like any VSCode-family extensions
    # dir. Installed Kiro Powers live under ``~/.kiro/powers/installed/<name>/``,
    # each shipping its as-authored ``mcp.json`` + ``steering/`` (the official
    # kirodotdev/powers repo documents this layout, e.g. databricks/POWER.md).
    # Powers use NO ``extensions.json`` manifest — the ``installed/`` segment is
    # itself the install marker — so that tree is scanned wholesale via
    # ``_unmanaged_extension_paths`` (see ``_installed_extension_dirs`` below).
    # Powers are user-global only.
    _extension_paths = (
        "~/.kiro/extensions",
        "~/.kiro/powers/installed",
    )
    # Subset of ``_extension_paths`` with no ``extensions.json`` install manifest.
    _unmanaged_extension_paths: ClassVar[tuple[str, ...]] = ("~/.kiro/powers/installed",)
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

    def _installed_extension_dirs(self, base: Path) -> list[Path]:
        """Roots in ``_unmanaged_extension_paths`` ship no ``extensions.json``
        manifest — each installed Power is just a present subdir — so those roots
        return their immediate subdirs (every Power is scanned). All other roots
        (e.g. ``~/.kiro/extensions``) stay manifest-gated via ``super()``."""
        unmanaged = {expand_path(Path(raw), self.home_directory) for raw in self._unmanaged_extension_paths}
        if base in unmanaged:
            return self._immediate_subdirs(base)
        return super()._installed_extension_dirs(base)
