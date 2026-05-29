"""Antigravity discoverer."""

from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer


class AntigravityDiscoverer(VSCodeFamilyDiscoverer):
    name = "antigravity"
    # Same rationale as Windsurf: ``~/.gemini`` alone is the Gemini CLI.
    # v1.x writes to ``Antigravity``, v2.0 writes to ``Antigravity IDE`` —
    # scan both so users on either version surface. v1.x first so that
    # ``_user_data_dir()`` (the single-path accessor) preserves prior behavior.
    _user_data_dir_names = ("Antigravity", "Antigravity IDE")
    _install_paths = ("~/.gemini/antigravity",)
    # IDE-specific MCP plus the unified config that Antigravity CLI + IDE both
    # consult (``~/.gemini/config/mcp_config.json``) per the Google Cloud
    # Community docs on configuring MCP across the Antigravity stack.
    _user_mcp_file_paths = (
        "~/.gemini/antigravity/mcp_config.json",
        "~/.gemini/config/mcp_config.json",
    )
    # Antigravity is a VSCode fork, so its per-user ``settings.json`` follows
    # VSCode's nested ``mcp.servers`` shape. Users who configure MCP through
    # the editor settings UI (rather than the dotfile ``mcp_config.json``) would
    # slip past discovery without this. The gate in
    # :meth:`_discover_user_settings_mcp` keeps an editor-only settings.json
    # (no ``mcp`` key) from being flagged as a parse failure.
    _user_settings_file = "User/settings.json"
    # The shared ``~/.gemini/settings.json`` (used by the Gemini CLI + Antigravity)
    # can carry MCP under a top-level ``mcpServers`` key. Parsed with the
    # presence-gate so an editor-only settings file is not flagged as malformed.
    # Gemini's remote servers use the ``httpUrl`` key (Streamable HTTP), which
    # ``RemoteServer`` accepts as a URL alias (see its ``AliasChoices``).
    _gated_home_settings_files = ("~/.gemini/settings.json",)
    # User-global skill dirs the Antigravity IDE reads, most-reliable first:
    #   * ``~/.gemini/skills`` — shared across all Antigravity tools (CLI+IDE);
    #     the location skills reliably load from in practice.
    #   * ``~/.agents/skills`` (PLURAL) — Antigravity 2.0's default global dir
    #     and the ``npx`` skills-installer target (its ``.skill-lock.json`` lists
    #     ``antigravity``).
    #   * ``~/.gemini/antigravity/skills`` — the officially documented global
    #     path (Google codelab); kept even though its real-world pickup is
    #     unreliable.
    #   * ``~/.agent/skills`` (SINGULAR) — the v1-era path, still read by 2.0 for
    #     backward compatibility. Kept as a harmless fallback.
    # NOT included: ``~/.gemini/antigravity-ide/skills`` (no first-party source
    # documents it) and ``~/.gemini/antigravity-cli/skills`` (CLI-only, not read
    # by the IDE). Workspace ``.agent``/``.agents`` paths are below.
    _skills_dir_paths = (
        "~/.gemini/skills",
        "~/.agents/skills",
        "~/.gemini/antigravity/skills",
        "~/.agent/skills",
    )
    _workspace_skills_relative = (".agent/skills", ".agents/skills")
    # No per-workspace MCP path configured. Antigravity's official documentation
    # site (``antigravity.google/docs/*``) is a client-rendered SPA whose pages
    # don't disclose a workspace-scoped ``mcp.json`` file path. The official
    # sitemap (``antigravity.google/sitemap.xml``) lists only
    # ``/docs/{agent-features,editor-features,faq,features,get-started,rest-api}``
    # and the ``/docs/mcp`` page that search engines index documents the
    # user-global ``~/.gemini/antigravity/mcp_config.json`` (already in
    # ``_user_mcp_file_paths`` above). Community write-ups float candidates
    # like ``.agents/mcp_config.json``, but those are not Google-official.
    # Leaving ``_workspace_mcp_relative`` empty is the conservative call:
    # adding a guessed path would let a user-controlled file on disk feed
    # parse failures into every scan and falsely advertise coverage we don't
    # actually have. Revisit once Google publishes a path we can cite.
    # Installed extensions live under ``~/.gemini/extensions/`` (shared with
    # the Gemini CLI; not under the ``antigravity/`` subdir).
    _extension_paths = ("~/.gemini/extensions",)
