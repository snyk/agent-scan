"""GitHub Copilot discoverer: ``~/.copilot`` MCP config, skills, and installed plugins.

Copilot's home is shared by the CLI, the desktop app and Copilot inside VS Code, and
is reachable without VS Code at all. The ``vscode`` discoverer reads the same user-level
files, but only when VS Code itself is installed; this discoverer is gated on the Copilot
home instead, so a Copilot-only machine is scanned too — and it adds the project- and
plugin-scope sources that are Copilot's own rather than VS Code's.

Paths follow the Copilot CLI reference:
https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference
"""

import logging
import os
from pathlib import Path, PurePosixPath, PureWindowsPath

from agent_scan.agents.base import (
    _MAX_PLUGIN_RGLOB_DEPTH,
    AgentDiscoverer,
    McpConfigsResult,
    McpScanResult,
    SkillsDirsResult,
    _canonicalize_keys,
    _walk_manifest_candidates,
)
from agent_scan.models import (
    ClaudeConfigFile,
    MCPConfig,
    PluginMCPConfigFile,
    VSCodeMCPConfig,
)
from agent_scan.skill_client import inspect_skills_dir
from agent_scan.well_known_clients import GITHUB_COPILOT_NAME, expand_path

logger = logging.getLogger(__name__)

# ``{"mcpServers": {...}}`` is the shape Copilot documents for every one of its MCP
# files. ``servers`` (VS Code's spelling) and the wrapper-less flat map are accepted too
# because repository-level ``.mcp.json`` is a shared, cross-tool file: a server declared
# there in a neighbouring tool's shape is still a server this machine can run.
_COPILOT_MCP_FORMATS: tuple[type[MCPConfig], ...] = (
    ClaudeConfigFile,
    VSCodeMCPConfig,
    PluginMCPConfigFile,
)


# Legacy plugin manifest locations, in the order Copilot searches them — the first hit
# for a plugin wins. Agent Plugins 1.0 uses the bare ``plugin.json`` at the root. Paths
# declared *inside* a manifest resolve against the plugin root, so the root is the
# manifest path with its location suffix stripped rather than simply its parent: for
# ``<root>/.claude-plugin/plugin.json`` the parent is the manifest's own directory.
_PLUGIN_MANIFEST_LOCATIONS: tuple[tuple[str, ...], ...] = (
    (".plugin", "plugin.json"),
    ("plugin.json",),
    (".github", "plugin", "plugin.json"),
    (".claude-plugin", "plugin.json"),
)
# Matched longest-first so ``.github/plugin/plugin.json`` is not mistaken for a bare
# ``plugin.json`` sitting in a directory called ``plugin``; the documented search order
# above is kept separately as the precedence value.
_PLUGIN_MANIFEST_MATCH_ORDER: tuple[tuple[int, tuple[str, ...]], ...] = tuple(
    sorted(enumerate(_PLUGIN_MANIFEST_LOCATIONS), key=lambda item: len(item[1]), reverse=True)
)


def _plugin_root_for(manifest_path: Path) -> tuple[Path, int] | None:
    """The plugin root a manifest belongs to, with its location's search precedence.

    ``None`` when the file is not at one of the documented manifest locations, so a
    stray ``plugin.json`` nested somewhere unrelated is not treated as a plugin.
    """
    parts = manifest_path.parts
    for precedence, location in _PLUGIN_MANIFEST_MATCH_ORDER:
        if len(parts) > len(location) and parts[-len(location) :] == location:
            return manifest_path.parents[len(location) - 1], precedence
    return None


def _escapes_plugin_root(value: str) -> bool:
    r"""True when a manifest path value would resolve outside the plugin that declared it."""
    for flavour in (PurePosixPath, PureWindowsPath):
        candidate = flavour(value)
        if candidate.is_absolute() or candidate.root or candidate.drive or ".." in candidate.parts:
            return True
    return False


class GitHubCopilotDiscoverer(AgentDiscoverer):
    """GitHub Copilot discovery: user, project and plugin MCP servers + skills.

    Scopes covered:

    * **User** — ``<copilot_home>/mcp-config.json``; skills in ``<copilot_home>/skills``
      and the cross-agent ``~/.agents/skills``.
    * **Project** — for every recorded and explicitly targeted root (and its ancestors):
      ``.mcp.json`` and ``.github/mcp.json``; skills in ``.github/skills`` plus the
      documented ``.claude/skills`` / ``.agents/skills`` compatibility paths.
    * **Plugins** — ``<copilot_home>/installed-plugins`` walked for ``skills/`` and the
      default MCP files (``.mcp.json`` for a legacy plugin, ``mcp.json`` for an Agent
      Plugins 1.0 one). A legacy ``plugin.json`` manifest may relocate ``mcpServers`` /
      ``skills`` inside the plugin, or define its MCP servers inline; both forms are
      honored additively.

    Recorded project roots come from the ``locations`` map in
    ``<copilot_home>/permissions-config.json``, which Copilot keys by absolute project
    path. As with Codex's ``[projects]`` table, the saved approvals themselves are never
    read — every listed location is scanned.

    Not covered: ``<copilot_home>/session-state/<id>/workspace.yaml``, whose ``cwd``
    records one more project root per session (YAML, one file per session); LSP servers
    (``lsp-config.json``) and custom agents (``agents/``), neither of which declares MCP
    servers; and ``COPILOT_HOME`` for other users' homes, which this process cannot know.
    """

    # MUST match the GitHub Copilot entry in ``well_known_clients.py`` so the Phase-A /
    # Phase-B merge in ``pipelines`` lines up on one client.
    name = GITHUB_COPILOT_NAME

    _install_path = "~/.copilot"
    _user_mcp_filename = "mcp-config.json"
    _permissions_filename = "permissions-config.json"
    _plugins_dir_name = "installed-plugins"
    _plugin_manifest_filename = "plugin.json"
    # Cross-agent user skills dir Copilot reads outside its own home.
    _user_skills_relative = "~/.agents/skills"
    # Repo-relative MCP files, per the Copilot CLI MCP docs: Copilot walks from the
    # working directory up to the repository root loading each one.
    _workspace_mcp_relative = (".mcp.json", ".github/mcp.json")
    # Repo-relative skills dirs: ``.github/skills`` is Copilot's own; the other two are
    # documented cross-agent compatibility paths.
    _workspace_skills_relative = (".github/skills", ".claude/skills", ".agents/skills")

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        path = self._copilot_home()
        try:
            if path.exists():
                return path.as_posix()
        except PermissionError:
            logger.warning("Permission error for path %s", path.as_posix())
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        result.update(self._discover_user_mcp_servers())
        result.update(self._discover_project_mcp_servers())
        result.update(self._discover_plugin_mcp_servers())
        result.update(self._discover_plugin_manifest_mcp_servers())
        return _canonicalize_keys(result)

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        result.update(self._discover_global_skills())
        result.update(self._discover_project_skills())
        result.update(self._discover_plugin_skills())
        result.update(self._discover_plugin_manifest_skills())
        return _canonicalize_keys(result)

    # --- private: MCP discovery ---

    def _discover_user_mcp_servers(self) -> McpConfigsResult:
        """Parse ``<copilot_home>/mcp-config.json``, Copilot's user-level MCP file."""
        path = self._copilot_home() / self._user_mcp_filename
        parsed = self._parse_mcp_file(path, formats=_COPILOT_MCP_FORMATS)
        return {path.as_posix(): parsed} if parsed is not None else {}

    def _discover_project_mcp_servers(self) -> McpConfigsResult:
        """Scan the repo-relative MCP files for every discovery root and ancestor."""
        result: McpConfigsResult = {}
        for folder in self._discovery_paths_with_ancestors():
            for relative in self._workspace_mcp_relative:
                path = folder / relative
                parsed = self._parse_mcp_file(path, formats=_COPILOT_MCP_FORMATS)
                if parsed is not None:
                    result[path.as_posix()] = parsed
        return result

    def _discover_plugin_mcp_servers(self) -> McpConfigsResult:
        """Walk installed plugins for their default MCP files: ``.mcp.json`` for a legacy
        plugin, and ``mcp.json`` for an Agent Plugins 1.0 one, whose component locations
        are fixed and cannot be redeclared in the manifest."""
        return self._discover_plugin_mcp_files(
            self._plugin_base_dirs(), (".mcp.json", "mcp.json"), self._parse_plugin_mcp_json
        )

    def _parse_plugin_mcp_json(self, path: Path) -> McpScanResult:
        """Parse a plugin MCP file opportunistically: the walk matches every file named
        ``.mcp.json`` under a plugin tree, so one with no MCP shape is skipped rather
        than reported as malformed."""
        return self._parse_mcp_file(path, formats=_COPILOT_MCP_FORMATS, skip_unrecognized=True)

    def _discover_plugin_manifest_mcp_servers(self) -> McpConfigsResult:
        """Honor a manifest's ``mcpServers``, documented as a path *or* inline server
        definitions.

        A path names another file to parse; an inline map is the definition itself, so it
        is keyed on the manifest that carries it — there is no other file to point at.
        Additive to the default walk, and keyed by path, so a manifest naming
        ``.mcp.json`` dedups with it.
        """
        result: McpConfigsResult = {}
        for plugin_root, manifest_path, manifest in self._plugin_manifests():
            servers = manifest.get("mcpServers")
            if isinstance(servers, dict):
                if servers:
                    result[manifest_path.as_posix()] = self._validate_servers(
                        servers, source=f"mcpServers in {manifest_path.as_posix()}"
                    )
                continue
            for resolved in self._manifest_relative_paths(plugin_root, servers):
                parsed = self._parse_plugin_mcp_json(resolved)
                if parsed:
                    result[resolved.as_posix()] = parsed
        return result

    # --- private: skills discovery ---

    def _discover_global_skills(self) -> SkillsDirsResult:
        """Scan the user skills dirs: ``<copilot_home>/skills`` (Copilot's own, so it
        follows ``COPILOT_HOME``) and the cross-agent ``~/.agents/skills``."""
        result: SkillsDirsResult = {}
        skills_dirs = (
            self._copilot_home() / "skills",
            expand_path(Path(self._user_skills_relative), self.home_directory),
        )
        for skills_dir in skills_dirs:
            entries = self._scan_skills_dir(skills_dir)
            if entries is not None:
                result[skills_dir.as_posix()] = entries
        return result

    def _discover_project_skills(self) -> SkillsDirsResult:
        """Scan the repo-relative skills dirs for every discovery root and ancestor."""
        result: SkillsDirsResult = {}
        for folder in self._discovery_paths_with_ancestors():
            for relative in self._workspace_skills_relative:
                skills_dir = folder / relative
                entries = self._scan_skills_dir(skills_dir)
                if entries is not None:
                    result[skills_dir.as_posix()] = entries
        return result

    def _discover_plugin_skills(self) -> SkillsDirsResult:
        """Scan ``skills/`` subdirs under every installed plugin (the default location);
        a manifest may name additional roots, see
        :meth:`_discover_plugin_manifest_skills`."""
        return self._discover_skill_and_command_dirs(self._plugin_base_dirs(), "skills", inspect_skills_dir)

    def _discover_plugin_manifest_skills(self) -> SkillsDirsResult:
        """Honor a ``plugin.json`` manifest's ``skills`` path(s), which may be a single
        path or a list. Additive to the default ``skills/`` walk."""
        result: SkillsDirsResult = {}
        for plugin_root, _manifest_path, manifest in self._plugin_manifests():
            for resolved in self._manifest_relative_paths(plugin_root, manifest.get("skills")):
                entries = self._scan_skills_dir(resolved)
                if entries is not None:
                    result[resolved.as_posix()] = entries
        return result

    # --- private: plugins ---

    def _plugin_base_dirs(self) -> list[Path]:
        """The plugins root. Copilot installs under
        ``installed-plugins/<marketplace>/<plugin>/`` (directly installed plugins land
        under the ``_direct`` marketplace), so the scans walk it recursively. A missing
        root is skipped by :func:`_walk_under_depth`."""
        return [self._copilot_home() / self._plugins_dir_name]

    def _plugin_manifests(self) -> list[tuple[Path, Path, dict]]:
        """Locate installed plugin manifests, returning ``(plugin_root, manifest_path,
        manifest)`` for each one found under the plugins root.

        A manifest is recognized only at one of the documented locations, and the plugin
        root is derived by stripping that location (see :func:`_plugin_root_for`) so a
        manifest in a subdirectory still resolves its declared paths against the plugin
        itself, and must land on an installed plugin's own directory. A plugin shipping
        more than one manifest keeps the highest-precedence location; unparseable or
        non-dict manifests are skipped.
        """
        by_root: dict[Path, tuple[int, Path]] = {}
        for base in self._plugin_base_dirs():
            for manifest_path in _walk_manifest_candidates(
                base,
                self._plugin_manifest_filename,
                (".plugin", "plugin", ".claude-plugin"),
                _MAX_PLUGIN_RGLOB_DEPTH,
            ):
                located = _plugin_root_for(manifest_path)
                if located is None:
                    continue
                plugin_root, precedence = located
                if plugin_root.parent.parent != base:
                    # A plugin root sits at ``<installed-plugins>/<marketplace>/<plugin>``
                    # (``_direct`` being the marketplace for a directly installed one), so a
                    # ``plugin.json`` vendored deeper inside a plugin is another tool's file
                    # rather than a manifest that may relocate this plugin's components. The
                    # default ``skills/`` and ``.mcp.json`` / ``mcp.json`` walks are not
                    # depth-limited, so a deeper layout still has its components found —
                    # only a non-default *declared* path would be missed.
                    continue
                existing = by_root.get(plugin_root)
                if existing is None or precedence < existing[0]:
                    by_root[plugin_root] = (precedence, manifest_path)
        result: list[tuple[Path, Path, dict]] = []
        for plugin_root, (_precedence, manifest_path) in by_root.items():
            data = self._load_json_file(manifest_path, log_parse_errors=False)
            if isinstance(data, dict):
                result.append((plugin_root, manifest_path, data))
        return result

    def _manifest_relative_paths(self, plugin_root: Path, value: object) -> list[Path]:
        """Resolve a manifest ``mcpServers`` / ``skills`` value to absolute paths under
        ``plugin_root``. Copilot documents both a single path and a list of them
        (``"skills": ["skills/", "extra-skills/"]``). A value that would land outside the
        plugin root is dropped (see :func:`_escapes_plugin_root`), so a manifest cannot
        redirect the scan somewhere else on disk."""
        values = value if isinstance(value, list) else [value]
        resolved: list[Path] = []
        for entry in values:
            if not isinstance(entry, str) or not entry.strip():
                continue
            text = entry.strip()
            if _escapes_plugin_root(text):
                continue
            resolved.append(plugin_root / Path(text))
        return resolved

    # --- COPILOT_HOME resolution ---

    def _copilot_home(self) -> Path:
        """Copilot's config dir (``~/.copilot`` by default). ``COPILOT_HOME`` replaces
        the whole path, but only on an own-home scan — under ``--scan-all-users`` the
        scanner cannot know another user's environment. Mirrors
        ``CodexDiscoverer._codex_home`` and ``ClaudeCodeDiscoverer``'s
        ``CLAUDE_CONFIG_DIR``."""
        if self._scans_own_home():
            copilot_home = os.environ.get("COPILOT_HOME")
            if copilot_home:
                return Path(copilot_home)
        return expand_path(Path(self._install_path), self.home_directory)

    # --- project enumeration ---

    def _discover_project_folders(self) -> list[Path]:
        """Project roots from the ``locations`` map in ``permissions-config.json``,
        which Copilot keys by absolute project path. The saved approvals under each key
        are intentionally not read — every listed location is scanned."""
        data = self._load_json_file(self._copilot_home() / self._permissions_filename)
        if not isinstance(data, dict):
            return []
        locations = data.get("locations")
        if not isinstance(locations, dict):
            return []
        folders: list[Path] = []
        for location in locations:
            if not isinstance(location, str) or not location.strip():
                continue
            candidate = Path(location.strip())
            if candidate.is_absolute():
                folders.append(candidate)
        return folders
