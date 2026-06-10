"""Codex CLI discoverer: ``config.toml`` MCP servers (TOML) + skill directories.

Codex keeps MCP servers in a TOML ``[mcp_servers.<name>]`` table that the
JSON-only data-driven pipeline can't parse, so they're invisible to it; this
discoverer closes that gap. Paths follow developers.openai.com/codex.
"""

import logging
import os
import sys
import traceback
from pathlib import Path

# ``tomllib`` is stdlib from 3.11; fall back to the ``tomli`` backport on 3.10,
# else degrade to a no-op (TOML scans skipped) rather than failing import.
try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 lacks stdlib TOML
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

from agent_scan.agents.base import (
    _MAX_CONFIG_FILE_BYTES,
    _MAX_PLUGIN_RGLOB_DEPTH,
    AgentDiscoverer,
    McpConfigsResult,
    McpScanResult,
    SkillsDirsResult,
    _walk_under_depth,
)
from agent_scan.models import (
    ClaudeConfigFile,
    CouldNotParseMCPConfig,
    PluginMCPConfigFile,
)
from agent_scan.skill_client import inspect_skills_dir
from agent_scan.well_known_clients import expand_path

logger = logging.getLogger(__name__)


class CodexDiscoverer(AgentDiscoverer):
    """OpenAI Codex CLI discovery: ``config.toml`` MCP servers (TOML) + skills.

    MCP servers live in a flat ``[mcp_servers.<name>]`` table (stdio or HTTP),
    routed through the inherited :meth:`AgentDiscoverer._validate_servers`.

    Scopes covered:

    * **User** — ``<codex_home>/config.toml`` + profile overlays
      ``<codex_home>/<name>.config.toml``; skills in ``~/.agents/skills``, the
      deprecated-but-still-loaded ``<codex_home>/skills``, and the OpenAI-embedded
      ``<codex_home>/skills/.system`` cache.
    * **System** — the machine-wide ``config.toml`` (``/etc/codex`` on Unix,
      ``%ProgramData%\\OpenAI\\Codex`` on Windows) and ``/etc/codex/skills``.
    * **Plugins** — ``<codex_home>/plugins`` walked for ``.mcp.json`` + ``skills/``. A
      plugin manifest (``.codex-plugin/plugin.json``, or the ``.claude-plugin`` fallback)
      may relocate its MCP config (``mcpServers``) or add a skills root (``skills``);
      those ``./``-relative overrides are honored additively.
    * **Project** — each ``[projects]`` entry and its ancestors, scanned for
      ``.codex/config.toml`` servers and ``.agents/skills``. ``trust_level`` is
      never read — every listed project is scanned regardless of trust.

    Not covered: ``requirements.toml`` / legacy ``managed_config.toml`` (admin
    allowlists, not server definitions); the enterprise *cloud* bundle
    (``cloud-config-bundle-cache.json`` — HMAC-signed, short-TTL, identity-scoped, not a
    stable parseable on-disk config); ``enabled = false`` flags (disabled entries are
    still inventoried).

    TODO(ADS-422): the macOS MDM ``com.openai.codex`` managed-preferences layer DOES
    land on disk (``/Library/Managed Preferences/com.openai.codex.plist``) and its
    ``config_toml_base64`` key carries a full ``[mcp_servers]`` table — currently
    unscanned. https://snyksec.atlassian.net/browse/ADS-422
    """

    # MUST match the Codex entry in ``well_known_clients.py`` so the Phase-A /
    # Phase-B merge in ``pipelines`` lines up on one client.
    name = "codex"

    _install_path = "~/.codex"
    _config_filename = "config.toml"
    # Plugin manifest dirs Codex reads, in precedence order: the native
    # ``.codex-plugin`` then the Claude-compat ``.claude-plugin`` fallback. The
    # manifest file inside each is ``plugin.json``.
    _plugin_manifest_dirs = (".codex-plugin", ".claude-plugin")
    _plugin_manifest_filename = "plugin.json"
    # Documented skill dirs (developers.openai.com/codex/skills): user (home-relative,
    # cross-agent convention) + admin (absolute, machine-wide).
    _user_skills_relative = "~/.agents/skills"
    _admin_skills_dir = "/etc/codex/skills"

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        path = self._codex_home()
        try:
            if path.exists():
                return path.as_posix()
        except PermissionError:
            logger.warning("Permission error for path %s", path.as_posix())
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        """MCP servers across every on-disk layer: user + profile + system config,
        plugins, and each registered project."""
        result: McpConfigsResult = {}
        result.update(self._discover_user_mcp_servers())
        result.update(self._discover_profile_mcp_servers())
        result.update(self._discover_system_mcp_servers())
        result.update(self._discover_plugin_mcp_servers())
        result.update(self._discover_plugin_manifest_mcp_servers())
        result.update(self._discover_project_mcp_servers())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        """Skills from the documented user/admin dirs, installed plugins, and every
        registered project."""
        result: SkillsDirsResult = {}
        result.update(self._discover_global_skills())
        result.update(self._discover_plugin_skills())
        result.update(self._discover_plugin_manifest_skills())
        result.update(self._discover_project_skills())
        return result

    # --- private: MCP discovery ---

    def _discover_user_mcp_servers(self) -> McpConfigsResult:
        """Parse the ``mcp_servers`` table in ``<codex_home>/config.toml``."""
        config_path = self._codex_home() / self._config_filename
        return self._mcp_servers_from_data(self._user_config_toml(), config_path)

    def _discover_profile_mcp_servers(self) -> McpConfigsResult:
        """Parse ``mcp_servers`` from profile overlays ``<codex_home>/<name>.config.toml``
        (selected with ``--profile``). The main ``config.toml`` is excluded; an
        unreadable home is skipped.
        """
        result: McpConfigsResult = {}
        codex_home = self._codex_home()
        try:
            profile_files = sorted(codex_home.glob("*.config.toml"))
        except (PermissionError, OSError):
            return result
        for profile_file in profile_files:
            if profile_file.name == self._config_filename:
                continue
            result.update(self._mcp_servers_from_data(self._load_toml_file(profile_file), profile_file))
        return result

    def _discover_system_mcp_servers(self) -> McpConfigsResult:
        """Parse ``mcp_servers`` from the machine-wide system ``config.toml`` (same
        shape as the user config). Fixed absolute path, keyed by it so it dedups
        across homes under ``--scan-all-users``.
        """
        path = self._system_config_path()
        if path is None:
            return {}
        return self._mcp_servers_from_data(self._load_toml_file(path), path)

    def _system_config_path(self) -> Path | None:
        """Per-OS path to the system ``config.toml``: ``/etc/codex/config.toml`` on
        Unix, ``%ProgramData%\\OpenAI\\Codex\\config.toml`` on Windows (ProgramData from
        the env — machine-global, so honoring it under ``--scan-all-users`` is correct).
        """
        if sys.platform in ("darwin", "linux", "linux2"):
            return Path("/etc/codex/config.toml")
        if sys.platform == "win32":
            # Codex resolves ProgramData via the ``FOLDERID_ProgramData`` known-folder
            # API; reading ``%PROGRAMDATA%`` is a safe approximation (it's machine-global
            # and kept in sync with the env var) and matches the managed-path convention
            # in ``claude_code.py``. (Windows uppercases ``os.environ`` keys:
            # ``ProgramData`` -> ``PROGRAMDATA``.)
            program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
            return Path(program_data) / "OpenAI" / "Codex" / "config.toml"
        return None

    # --- private: plugin discovery (mirrors ClaudeCodeDiscoverer's plugin walk) ---

    def _plugin_base_dirs(self) -> list[Path]:
        """The Codex plugins root ``<codex_home>/plugins`` (Codex installs under
        ``plugins/cache/<marketplace>/<plugin>/<version>/``), walked recursively by the
        plugin scans. A missing root is skipped by :func:`_walk_under_depth`."""
        return [self._codex_home() / "plugins"]

    def _discover_plugin_mcp_servers(self) -> McpConfigsResult:
        """Scan every plugin tree for ``.mcp.json`` files."""
        result: McpConfigsResult = {}
        for base in self._plugin_base_dirs():
            for mcp_file in _walk_under_depth(base, ".mcp.json", _MAX_PLUGIN_RGLOB_DEPTH, want_file=True):
                if not mcp_file.is_file():
                    continue
                parsed = self._parse_plugin_mcp_json(mcp_file)
                if not parsed:
                    continue
                result[mcp_file.as_posix()] = parsed
        return result

    def _discover_plugin_skills(self) -> SkillsDirsResult:
        """Scan ``skills/`` subdirs under every plugin tree (the default location). A
        manifest may declare an *additional* skills root; see
        :meth:`_discover_plugin_manifest_skills`."""
        return self._discover_skill_and_command_dirs(self._plugin_base_dirs(), "skills", inspect_skills_dir)

    def _plugin_manifests(self) -> list[tuple[Path, dict]]:
        """Locate installed plugin manifests under the plugins root, returning
        ``(plugin_root, manifest_data)`` for each.

        A manifest lives at ``<plugin_root>/.codex-plugin/plugin.json`` (preferred) or
        ``<plugin_root>/.claude-plugin/plugin.json`` (Claude-compat fallback). We walk
        for ``plugin.json`` files, keep those whose parent dir is one of the manifest
        dirs, and prefer the higher-precedence dir when a plugin root has both.
        Unparseable / non-dict manifests are skipped.
        """
        precedence = self._plugin_manifest_dirs
        by_root: dict[Path, Path] = {}
        for base in self._plugin_base_dirs():
            for manifest_path in _walk_under_depth(
                base, self._plugin_manifest_filename, _MAX_PLUGIN_RGLOB_DEPTH, want_file=True
            ):
                dir_name = manifest_path.parent.name
                if dir_name not in precedence:
                    continue
                plugin_root = manifest_path.parent.parent
                existing = by_root.get(plugin_root)
                if existing is None or precedence.index(dir_name) < precedence.index(existing.parent.name):
                    by_root[plugin_root] = manifest_path
        result: list[tuple[Path, dict]] = []
        for plugin_root, manifest_path in by_root.items():
            data = self._load_json_file(manifest_path)
            if isinstance(data, dict):
                result.append((plugin_root, data))
        return result

    def _resolve_manifest_relative_path(self, plugin_root: Path, value: object) -> Path | None:
        """Resolve a manifest path value (``mcpServers`` / ``skills``) to an absolute
        path under ``plugin_root``, mirroring Codex's rules: the value must be a string
        starting with ``./`` and must not be absolute or contain a ``..`` component.
        Anything else returns ``None`` (the override is ignored).
        """
        if not isinstance(value, str) or not value.startswith("./"):
            return None
        relative = value[2:].strip()
        if not relative:
            return None
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            return None
        return plugin_root / candidate

    def _discover_plugin_manifest_mcp_servers(self) -> McpConfigsResult:
        """Honor a plugin manifest's ``mcpServers`` path override: when a manifest
        relocates its MCP config to a ``./``-relative file, parse that file too.
        Additive to the default ``.mcp.json`` walk (keyed by path, so an override
        pointing back at ``.mcp.json`` dedups with it).
        """
        result: McpConfigsResult = {}
        for plugin_root, manifest in self._plugin_manifests():
            resolved = self._resolve_manifest_relative_path(plugin_root, manifest.get("mcpServers"))
            if resolved is None:
                continue
            parsed = self._parse_plugin_mcp_json(resolved)
            if not parsed:
                continue
            result[resolved.as_posix()] = parsed
        return result

    def _discover_plugin_manifest_skills(self) -> SkillsDirsResult:
        """Honor a plugin manifest's ``skills`` path override: scan an extra
        ``./``-relative skills root declared in the manifest. Additive to the default
        ``skills/`` walk (keyed by path, so an override naming ``./skills`` dedups).
        """
        result: SkillsDirsResult = {}
        for plugin_root, manifest in self._plugin_manifests():
            resolved = self._resolve_manifest_relative_path(plugin_root, manifest.get("skills"))
            if resolved is None:
                continue
            entries = self._scan_skills_dir(resolved)
            if entries is not None:
                result[resolved.as_posix()] = entries
        return result

    def _parse_plugin_mcp_json(self, path: Path) -> McpScanResult:
        """Parse a plugin ``.mcp.json`` (JSON) in any of the three shapes Codex accepts:

        * the camelCase-wrapped ``{"mcpServers": {...}}`` form (``ClaudeConfigFile``) — the
          shape Codex's plugin loader actually deserializes (its ``PluginMcpServersFile``
          struct is ``#[serde(rename_all = "camelCase")]``; see openai/codex#22105);
        * the flat ``{name: serverConfig}`` map (``PluginMCPConfigFile``);
        * the snake_case-wrapped ``{"mcp_servers": {...}}`` form (handled first — no shared
          ``MCPConfig`` model knows that snake-case key). Codex's docs show this shape even
          though the loader expects camelCase, so it is accepted as a deliberate superset.

        ``None`` if missing/empty/unrecognized, ``CouldNotParseMCPConfig`` if malformed.
        """
        data = self._load_json_file(path)
        if data is None or isinstance(data, CouldNotParseMCPConfig):
            return data
        if isinstance(data, dict) and isinstance(data.get("mcp_servers"), dict):
            servers = data["mcp_servers"]
            if not servers:
                return None
            return self._validate_servers(servers, source=f"mcp_servers in {path.as_posix()}")
        return self._parse_mcp_file(path, formats=(ClaudeConfigFile, PluginMCPConfigFile), skip_unrecognized=True)

    def _discover_project_mcp_servers(self) -> McpConfigsResult:
        """Parse ``<project>/.codex/config.toml`` servers for every registered project
        and its ancestors (so a monorepo root is found from a sub-package). Keyed by
        absolute path, so an ancestor equal to ``codex_home`` dedups in the merge.
        """
        result: McpConfigsResult = {}
        for path in self._project_paths_with_ancestors():
            config_path = path / ".codex" / self._config_filename
            result.update(self._mcp_servers_from_data(self._load_toml_file(config_path), config_path))
        return result

    def _mcp_servers_from_data(self, data: dict | CouldNotParseMCPConfig | None, config_path: Path) -> McpConfigsResult:
        """Turn a loaded ``config.toml`` into a ``{path: result}`` map, gated on a
        non-empty ``mcp_servers`` table (the multi-purpose config without one is not a
        parse failure). ``None`` -> ``{}``; malformed TOML is surfaced keyed by file.
        """
        if data is None:
            return {}
        if isinstance(data, CouldNotParseMCPConfig):
            return {config_path.as_posix(): data}
        servers = data.get("mcp_servers")
        if not isinstance(servers, dict) or not servers:
            return {}
        entries = self._validate_servers(servers, source=f"mcp_servers in {config_path.as_posix()}")
        return {config_path.as_posix(): entries}

    # --- private: project enumeration ---

    def _discover_project_folders(self) -> list[Path]:
        """Project roots from the ``[projects]`` table. ``trust_level`` is intentionally
        not read — every listed project is returned regardless of trust.
        """
        data = self._user_config_toml()
        if not isinstance(data, dict):
            return []
        projects = data.get("projects")
        if not isinstance(projects, dict):
            return []
        return [Path(p) for p in projects if isinstance(p, str)]

    # --- private: skills discovery ---

    def _discover_global_skills(self) -> SkillsDirsResult:
        """Scan the user (``~/.agents/skills``), the deprecated-but-still-loaded
        ``<codex_home>/skills`` (kept by Codex for backward compatibility), the
        OpenAI-embedded ``<codex_home>/skills/.system`` cache, and admin
        (``/etc/codex/skills``) skill dirs; missing/non-dir/unreadable paths are skipped.
        These ``<codex_home>``-rooted dirs follow ``CODEX_HOME``, so a relocated home is
        covered where the legacy pipeline only scans the literal ``~/.codex/skills``.

        ``.system`` is scanned in its own right because its skills nest one level inside it
        (``.system/<name>/SKILL.md``, e.g. ``imagegen``), below the one-level
        ``<codex_home>/skills`` scan that would otherwise skip the dot-dir.
        """
        result: SkillsDirsResult = {}
        skills_dirs = (
            self._codex_home() / "skills",
            self._codex_home() / "skills" / ".system",
            expand_path(Path(self._user_skills_relative), self.home_directory),
            Path(self._admin_skills_dir),
        )
        for skills_dir in skills_dirs:
            entries = self._scan_skills_dir(skills_dir)
            if entries is not None:
                result[skills_dir.as_posix()] = entries
        return result

    def _discover_project_skills(self) -> SkillsDirsResult:
        """Scan ``<project>/.agents/skills`` for every registered project and ancestor."""
        result: SkillsDirsResult = {}
        for path in self._project_paths_with_ancestors():
            skills_dir = path / ".agents" / "skills"
            entries = self._scan_skills_dir(skills_dir)
            if entries is not None:
                result[skills_dir.as_posix()] = entries
        return result

    # --- CODEX_HOME resolution ---

    def _codex_home(self) -> Path:
        """Codex state dir (``~/.codex`` by default). ``CODEX_HOME`` relocates it, but
        only on an own-home scan — under ``--scan-all-users`` the scanner can't know
        another user's env. Mirrors ``ClaudeCodeDiscoverer``'s ``CLAUDE_CONFIG_DIR``.
        """
        if self._scans_own_home():
            codex_home = os.environ.get("CODEX_HOME")
            if codex_home:
                return Path(codex_home)
        return expand_path(Path(self._install_path), self.home_directory)

    def _user_config_toml(self) -> dict | CouldNotParseMCPConfig | None:
        """Read and TOML-decode ``<codex_home>/config.toml`` (``None`` if missing/empty,
        ``CouldNotParseMCPConfig`` if malformed). Re-read on each call rather than
        cached, matching the uncached ``ClaudeCodeDiscoverer._load_config_raw``.
        """
        return self._load_toml_file(self._codex_home() / self._config_filename)

    # --- TOML loader (mirrors AgentDiscoverer._load_json_file semantics) ---

    def _load_toml_file(self, path: Path) -> dict | CouldNotParseMCPConfig | None:
        """TOML-decode ``path``: ``None`` if missing/empty/unreadable, parsed dict on
        success, ``CouldNotParseMCPConfig`` on malformed TOML. Mirrors
        :meth:`AgentDiscoverer._load_json_file` (same size cap + permission tolerance).
        """
        if tomllib is None:  # pragma: no cover - Python 3.10 without the tomli backport
            logger.warning("TOML support unavailable (Python < 3.11, no tomli); skipping %s", path.as_posix())
            return None
        try:
            if not path.exists():
                return None
            size = path.stat().st_size
            if size > _MAX_CONFIG_FILE_BYTES:
                logger.warning(
                    "Skipping oversized config %s (%d bytes > %d-byte cap)",
                    path.as_posix(),
                    size,
                    _MAX_CONFIG_FILE_BYTES,
                )
                return None
            content = path.read_text(encoding="utf-8")
            if content.strip() == "":
                return {}
            return tomllib.loads(content)
        except PermissionError:
            logger.warning("Permission denied reading %s", path.as_posix())
            return None
        except Exception as e:
            logger.exception("Error reading %s: %s", path.as_posix(), e)
            return CouldNotParseMCPConfig(
                message=f"could not parse file {path.as_posix()}",
                traceback=traceback.format_exc(),
                is_failure=True,
            )
