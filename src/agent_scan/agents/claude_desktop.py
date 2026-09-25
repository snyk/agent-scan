"""Claude Desktop's MCP config, local macOS plugins and logged connectors.

Desktop plugins are listed in
``local-agent-mode-sessions/*/*/rpm/manifest.json`` beneath the Desktop base.
Only listed plugin directories are scanned. Guard discovery also reads connector
metadata from Claude Code and Cowork session files on macOS and Windows; the
Windows session layout is assumed to match macOS and has not been verified.
Plugin discovery is macOS-only. Cloud skills, extensions and MDM settings remain
out of scope. Claude Code's separate configuration belongs to its own discoverer.
"""

import logging
import math
import sys
from pathlib import Path

from agent_scan import redact
from agent_scan.agents.base import McpConfigsResult, SkillsDirsResult, _canonicalize_keys, _escapes_plugin_root
from agent_scan.agents.claude_plugins import ClaudePluginDiscoverer
from agent_scan.models import CouldNotParseMCPConfig, RemoteServer
from agent_scan.well_known_clients import expand_path

logger = logging.getLogger(__name__)

# Allowlist, not passthrough: new or credential-bearing keys (e.g. headers) never leave the machine.
_LOGGED_CONNECTOR_FIELDS = ("uuid", "name", "url", "tools", "instructions")


class ClaudeDesktopDiscoverer(ClaudePluginDiscoverer):
    """Discover Desktop configuration, manifest-listed plugins and logged connectors."""

    name = "claude desktop"
    _config_filename = "claude_desktop_config.json"
    _macos_dir = "~/Library/Application Support/Claude"
    _windows_dir = "~/AppData/Roaming/Claude"
    _plugin_manifest_dirs = (".claude-plugin",)
    _confine_plugin_paths = True

    def __init__(self, home_directory: Path | None, target_folders: list[Path] | None = None) -> None:
        super().__init__(home_directory, target_folders)
        self._plugin_base_dirs_cache: list[Path] | None = None

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
        result = self._discover_global_mcp_servers()
        result.update(self._discover_plugin_mcp_servers())
        result.update(self._discover_plugin_manifest_mcp_servers())
        return _canonicalize_keys(result)

    def _discover_global_mcp_servers(self) -> McpConfigsResult:
        config_path = self._config_path()
        if config_path is None:
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
        result = self._discover_plugin_skills()
        result.update(self._discover_plugin_manifest_skills())
        return _canonicalize_keys(result)

    def discover_logged_mcp_servers(self) -> dict[str, list[dict]]:
        """Collect the newest connector metadata per org/UUID from Desktop sessions."""
        install_dir = self._install_dir()
        if install_dir is None:
            return {}
        newest: dict[str, dict[str, tuple[tuple[float, float, float], dict]]] = {}
        for directory in ("claude-code-sessions", "local-agent-mode-sessions"):
            try:
                sessions = sorted(install_dir.glob(f"{directory}/*/*/local_*.json"))
            except (OSError, RuntimeError, ValueError):
                continue
            for session in sessions:
                try:
                    relative = session.relative_to(install_dir)
                    if any(
                        (install_dir / Path(*relative.parts[:i])).is_symlink()
                        for i in range(1, len(relative.parts) + 1)
                    ):
                        continue
                    data = self._load_json_file(session, log_parse_errors=False)
                    if not isinstance(data, dict):
                        continue
                    entries = data.get("remoteMcpServersConfig")
                    if not isinstance(entries, list) or not entries:
                        continue
                    # Desktop rewrites old files too, so mtime is only a tie-breaker.
                    timestamps = [data.get("lastActivityAt"), data.get("createdAt")]
                    activity, created = (
                        value
                        if isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)
                        else 0
                        for value in timestamps
                    )
                    rank = (activity, created, session.stat().st_mtime)
                    org = relative.parts[2]
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        uuid, url = entry.get("uuid"), entry.get("url")
                        if not isinstance(uuid, str) or not isinstance(url, str):
                            continue
                        by_uuid = newest.setdefault(org, {})
                        if uuid in by_uuid and by_uuid[uuid][0] >= rank:
                            continue
                        server = RemoteServer(url=url, type="http")
                        redact.redact_server_config(server)
                        fields = {key: entry[key] for key in _LOGGED_CONNECTOR_FIELDS if key in entry}
                        by_uuid[uuid] = (rank, {**fields, "url": server.url})
                except (OSError, RuntimeError, ValueError):
                    continue
        return {org: [entry for _, entry in by_uuid.values()] for org, by_uuid in newest.items()}

    def _plugin_base_dirs(self) -> list[Path]:
        if self._plugin_base_dirs_cache is not None:
            return self._plugin_base_dirs_cache
        self._plugin_base_dirs_cache = []
        install_dir = self._install_dir()
        if sys.platform != "darwin" or install_dir is None:
            return self._plugin_base_dirs_cache
        try:
            manifests = list(install_dir.glob("local-agent-mode-sessions/*/*/rpm/manifest.json"))
        except (OSError, ValueError):
            return self._plugin_base_dirs_cache
        for manifest in manifests:
            try:
                relative = manifest.relative_to(install_dir)
                if any(
                    (install_dir / Path(*relative.parts[:i])).is_symlink() for i in range(1, len(relative.parts) + 1)
                ):
                    continue
                data = self._load_json_file(manifest, log_parse_errors=False)
                plugins = data.get("plugins") if isinstance(data, dict) else None
                if not isinstance(plugins, list):
                    continue
                for plugin in plugins:
                    plugin_id = plugin.get("id") if isinstance(plugin, dict) else None
                    if (
                        not isinstance(plugin_id, str)
                        or not plugin_id.strip()
                        or plugin_id in (".", "..")
                        or any(char in plugin_id for char in ("/", "\\", "\x00"))
                        or _escapes_plugin_root(plugin_id)
                    ):
                        continue
                    root = manifest.parent / plugin_id
                    if root.is_symlink() or not root.is_dir():
                        continue
                    if root not in self._plugin_base_dirs_cache:
                        self._plugin_base_dirs_cache.append(root)
            except (OSError, RuntimeError, ValueError):
                continue
        return self._plugin_base_dirs_cache

    def _install_dir(self) -> Path | None:
        if sys.platform == "darwin":
            return expand_path(Path(self._macos_dir), self.home_directory)
        if sys.platform == "win32":
            return expand_path(Path(self._windows_dir), self.home_directory)
        return None

    def _config_path(self) -> Path | None:
        install_dir = self._install_dir()
        return install_dir / self._config_filename if install_dir is not None else None
