"""Claude Desktop discoverer: the single per-OS ``claude_desktop_config.json``.

Claude Desktop (the Anthropic desktop app, distinct from Claude Code the CLI)
stores its MCP servers in one JSON file per OS, in the documented wrapped form
``{"mcpServers": {...}}``:

  * macOS:   ``~/Library/Application Support/Claude/claude_desktop_config.json``
  * Windows: ``%APPDATA%\\Claude\\claude_desktop_config.json``
    (``~/AppData/Roaming/Claude/claude_desktop_config.json``)

See https://modelcontextprotocol.io/docs/develop/connect-local-servers.

``claude_desktop_config.json`` is a config distinct from Claude Code's
``~/.claude.json`` (handled by ``ClaudeCodeDiscoverer``): the standalone Claude
Code CLI does not read it. The unified desktop app's Code tab *does* surface these
servers into its sessions, alongside ``~/.claude.json`` / ``.mcp.json``, but the
file itself belongs to the Claude Desktop chat surface and is only discovered
here -- which is why this is a separate discoverer rather than part of
``ClaudeCodeDiscoverer``. See https://code.claude.com/docs/en/desktop.

Deliberately not covered (no officially-documented filesystem path -- not guessed
by convention):

  * **Skills** -- Claude Desktop (the claude.ai app surface) *does* support custom
    Skills, but they are uploaded through Settings (Features / Customize > Skills)
    as zip files and stored per-account in the cloud; Anthropic documents no local
    filesystem path for them, so there is nothing on disk to scan. This is distinct
    from Claude Code's filesystem skills (``~/.claude/skills/`` and project
    ``.claude/skills/``), which ``ClaudeCodeDiscoverer`` already covers -- attributing
    those to Claude Desktop would double-count and mis-attribute them.
  * **Connectors (remote MCP)** -- added via Settings > Connectors (or org settings)
    through an OAuth flow; cloud/account-managed, with sensitive values held in OS
    secure storage (Keychain / Credential Manager), so there is no documented local
    config file to read.
  * **Extensions / ``.mcpb`` (Desktop Extensions / DXT)** -- installed via
    Settings > Extensions, but the installed-extension directory is not documented
    anywhere.
  * **Enterprise/MDM managed config** -- the macOS defaults domain
    ``com.anthropic.claudefordesktop``, the Windows registry key
    ``HKLM\\SOFTWARE\\Policies\\Claude``, and ``.../Claude/org-plugins/`` are
    non-filesystem mechanisms or have no documented internal MCP structure.
  * **Config-relocation env var** -- Claude Desktop documents none (unlike Claude
    Code's ``CLAUDE_CONFIG_DIR``), so there is nothing to honor.
  * **Linux** -- not an officially supported Claude Desktop platform.
"""

import logging
import sys
from pathlib import Path

from agent_scan.agents.base import (
    AgentDiscoverer,
    McpConfigsResult,
    SkillsDirsResult,
)
from agent_scan.models import CouldNotParseMCPConfig

logger = logging.getLogger(__name__)


class ClaudeDesktopDiscoverer(AgentDiscoverer):
    """Claude Desktop discovery: the single per-OS ``claude_desktop_config.json``.

    Only one documented scope exists -- a single user-global config file -- so this
    discoverer is intentionally small: no project, plugin, skills, or managed scopes
    (see the module docstring for the deliberately-uncovered, undocumented ones).
    The config is the wrapped ``{"mcpServers": {...}}`` shape, so MCP discovery
    mirrors ``ClaudeCodeDiscoverer._discover_global_mcp_servers``: extract the
    top-level ``mcpServers`` map and route it through the inherited
    :meth:`AgentDiscoverer._validate_servers`. Gating on the presence of
    ``mcpServers`` (rather than format-union parsing the whole file) avoids
    misreporting a config that carries only UI settings as a parse failure -- the
    file is multi-purpose (e.g. ``globalShortcut``).
    """

    # Canonical agent name: this discoverer's key in ``agents.DISCOVERERS`` and the
    # ``name`` on every ``ClientToInspect`` it produces.
    name = "claude desktop"

    _config_filename = "claude_desktop_config.json"
    # Documented per-OS install/config directories. ``~`` is expanded against the
    # discoverer's bound home, so it resolves correctly per-home under
    # ``--scan-all-users``.
    _macos_dir = "~/Library/Application Support/Claude"
    _windows_dir = "~/AppData/Roaming/Claude"

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        install_dir = self._install_dir()
        if install_dir is None:
            return None
        try:
            if install_dir.exists():
                return install_dir.as_posix()
        except PermissionError:
            logger.warning("Permission error for path %s", install_dir.as_posix())
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        """Parse the top-level ``mcpServers`` map from ``claude_desktop_config.json``.

        Mirrors ``ClaudeCodeDiscoverer._discover_global_mcp_servers``: a missing
        file or one without a non-empty ``mcpServers`` table yields no entry (not a
        parse failure), malformed JSON is surfaced as ``CouldNotParseMCPConfig``
        keyed by the file, and a valid table is validated into typed servers.
        """
        config_path = self._config_path()
        if config_path is None or not config_path.exists():
            return {}
        data = self._load_json_file(config_path)
        if isinstance(data, CouldNotParseMCPConfig):
            return {config_path.as_posix(): data}
        if not isinstance(data, dict):
            return {}
        servers = data.get("mcpServers")
        if not isinstance(servers, dict) or not servers:
            return {}
        entries = self._validate_servers(servers, source=f"mcpServers in {config_path.as_posix()}")
        return {config_path.as_posix(): entries}

    def discover_skills(self) -> SkillsDirsResult:
        """Claude Desktop's custom Skills are uploaded through Settings and stored
        per-account in the cloud, with no documented local filesystem path -- so
        there is nothing on disk to discover. (The filesystem ``~/.claude/skills/``
        path belongs to Claude Code, covered by ``ClaudeCodeDiscoverer``.) See the
        module docstring."""
        return {}

    def static_mcp_config_paths(self) -> list[str]:
        config_path = self._config_path()
        return [config_path.as_posix()] if config_path is not None else []

    # --- private: per-OS path resolution ---

    def _install_dir(self) -> Path | None:
        """The documented Claude Desktop config dir for the current OS, or ``None``
        on platforms where Claude Desktop isn't officially supported (Linux/other).

        Branches on ``sys.platform`` (the scanning machine's OS -- shared by every
        home on it). The Windows path also covers WSL-exposed Windows homes when
        scanning from Windows; Linux has no documented Claude Desktop install.
        """
        if sys.platform == "darwin":
            return self._expand_path(Path(self._macos_dir))
        if sys.platform == "win32":
            return self._expand_path(Path(self._windows_dir))
        return None

    def _config_path(self) -> Path | None:
        """Absolute path to ``claude_desktop_config.json``, or ``None`` on an
        unsupported platform."""
        install_dir = self._install_dir()
        if install_dir is None:
            return None
        return install_dir / self._config_filename
