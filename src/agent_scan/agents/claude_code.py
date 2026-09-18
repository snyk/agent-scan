"""Claude Code discoverer: ``~/.claude.json`` + ``~/.claude/skills`` + per-project,
plugin, command, and enterprise (managed-mcp) scopes."""

import logging
import os
import sys
from pathlib import Path

from agent_scan.agents.base import (
    _MAX_PLUGIN_RGLOB_DEPTH,
    AgentDiscoverer,
    McpConfigsResult,
    SkillsDirsResult,
    _walk_under_depth,
)
from agent_scan.models import (
    ClaudeConfigFile,
    CouldNotParseMCPConfig,
    MCPConfig,
    PluginMCPConfigFile,
)
from agent_scan.skill_client import inspect_skills_dir
from agent_scan.well_known_clients import CLAUDE_CODE_NAME, expand_path

logger = logging.getLogger(__name__)

# Format-union for Claude Code ``.mcp.json`` files (project + plugin scope), tried
# in order by ``_parse_mcp_file``: the wrapped ``{"mcpServers": {...}}`` shape
# (``ClaudeConfigFile``) first, then the wrapper-less flat ``{name: serverConfig}``
# shape (``PluginMCPConfigFile``). Mirrors ``vscode.base._VSCODE_FAMILY_FORMATS``.
_CLAUDE_MCP_FORMATS: tuple[type[MCPConfig], ...] = (ClaudeConfigFile, PluginMCPConfigFile)
_MAX_EXTERNAL_PLUGIN_ROOTS = 256


class ClaudeCodeDiscoverer(AgentDiscoverer):
    """Claude Code discovery: ``~/.claude.json`` + ``~/.claude/skills/`` + per-project scopes.

    The public ``discover_mcp_servers`` / ``discover_skills`` methods orchestrate six
    private helpers split by scope:

    * ``_discover_global_folders`` / ``_discover_project_folders`` enumerate where to look.
    * ``_discover_global_mcp_servers`` reads the top-level ``mcpServers`` key in
      ``~/.claude.json``; ``_discover_project_mcp_servers`` reads each
      ``projects.<path>.mcpServers`` block.
    * ``_discover_global_skill`` reads ``~/.claude/skills``;
      ``_discover_project_skills`` reads ``<project>/.claude/skills`` for every
      project listed in ``~/.claude.json``.
    """

    name = CLAUDE_CODE_NAME

    _install_path = "~/.claude"
    _mcp_config_path = "~/.claude.json"
    _skills_subdir = "skills"
    _project_dotclaude_subdir = ".claude"
    # Project-scoped skill dirs scanned at every opened project root and its
    # ancestors. ``.claude/skills`` is Claude Code's canonical project skills
    # location; ``.agents/skills`` is the cross-agent compatibility convention
    # (verified that Claude Code also loads it), shared with the VS Code-family
    # discoverers.
    _project_skills_relative: tuple[str, ...] = (".claude/skills", ".agents/skills")
    # Subtrees under a plugin *root* (see ``_plugin_root_dirs``) that hold the
    # user's *installed* plugins. ``cache`` is the hydrated install tree every
    # installed plugin is copied into — regardless of user/project/local scope,
    # per the plugins-reference "plugin cache" note
    # (https://code.claude.com/docs/en/plugins-reference); ``repos`` is the legacy
    # name kept for back-compat with older installs; ``synced`` holds plugins
    # downloaded from claude.ai. All three can host MCP servers / skills / commands.
    #
    # ``marketplaces/`` is deliberately NOT scanned: it is the cloned marketplace
    # *catalog* — every plugin a marketplace offers, almost all of which the user
    # has not installed. Adding a marketplace clones the catalog but installs
    # nothing; only plugins the user installs are copied into ``cache``/``repos``.
    # Walking the catalog would surface skills/MCP for plugins that were never
    # installed (see https://code.claude.com/docs/en/discover-plugins).
    _plugin_subdirs: tuple[str, ...] = ("cache", "repos", "synced")

    def __init__(self, home_directory: Path | None, target_folders: list[Path] | None = None) -> None:
        super().__init__(home_directory, target_folders)
        self._plugin_base_dirs_cache: list[Path] | None = None

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        path = self._claude_base_dir()
        try:
            if path.exists():
                return path.as_posix()
        except PermissionError:
            logger.warning("Permission error for path %s", path.as_posix())
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        result.update(self._discover_global_mcp_servers())
        result.update(self._discover_project_mcp_servers())
        result.update(self._discover_plugin_mcp_servers())
        result.update(self._discover_plugin_manifest_mcp_servers())
        result.update(self._discover_managed_mcp_servers())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        result.update(self._discover_global_skill())
        result.update(self._discover_project_skills())
        result.update(self._discover_plugin_skills())
        result.update(self._discover_plugin_manifest_skills())
        # NOTE: enterprise/managed skills are a documented Claude Code scope (the
        # "Enterprise" tier in the skills hierarchy, which overrides personal and
        # project skills) but are intentionally NOT discovered here. Unlike
        # ``managed-mcp.json`` — which has a fixed per-OS path (see
        # ``_managed_mcp_path``) — the docs pin managed skills only to "managed
        # settings" and document no concrete skills directory to scan. We do not
        # guess a path by convention; revisit if/when the docs specify one.
        # Follow-up: ADS-365.
        return result

    # --- config-dir resolution (CLAUDE_CONFIG_DIR) ---

    def _claude_base_dir(self) -> Path:
        """The base directory holding Claude Code state (``~/.claude`` by default).

        ``CLAUDE_CONFIG_DIR`` relocates this directory. The env var reflects the
        *scanning process's* environment, so it is honored only when scanning the
        process's own home (see :meth:`_scans_own_home`); under ``--scan-all-users``
        the scanner can't know each *other* target user's env, so the per-home
        default is used instead.
        """
        if self._scans_own_home():
            config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
            if config_dir:
                return Path(config_dir)
        return expand_path(Path(self._install_path), self.home_directory)

    def _config_json_path(self) -> Path:
        """Path to the global ``.claude.json``.

        When ``CLAUDE_CONFIG_DIR`` is active (own-home scan), the config lives at
        ``<base>/.claude.json``; falls back to the legacy ``~/.claude.json`` when
        that relocated file does not exist.
        """
        if self._scans_own_home() and os.environ.get("CLAUDE_CONFIG_DIR"):
            relocated = self._claude_base_dir() / ".claude.json"
            if relocated.exists():
                return relocated
        return expand_path(Path(self._mcp_config_path), self.home_directory)

    # --- private: folder enumeration ---

    def _discover_global_folders(self) -> list[Path]:
        """Folders that hold user-global Claude Code state (``~/.claude``, or the
        ``CLAUDE_CONFIG_DIR`` override on own-home scans)."""
        return [self._claude_base_dir()]

    def _discover_project_folders(self) -> list[Path]:
        """Project root paths recorded under ``projects`` in ``~/.claude.json``."""
        data = self._load_config_raw()
        if not isinstance(data, dict):
            return []
        projects = data.get("projects")
        if not isinstance(projects, dict):
            return []
        return [Path(p) for p in projects if isinstance(p, str)]

    # --- private: MCP discovery ---

    def _discover_global_mcp_servers(self) -> McpConfigsResult:
        """Parse top-level ``mcpServers`` from ``~/.claude.json`` — the user-global scope."""
        config_path = self._config_json_path()
        if not config_path.exists():
            return {}
        data = self._load_config_raw()
        if isinstance(data, CouldNotParseMCPConfig):
            return {config_path.as_posix(): data}
        if not isinstance(data, dict):
            return {}
        top = data.get("mcpServers")
        if not isinstance(top, dict) or not top:
            return {}
        entries = self._validate_servers(top, source=f"global mcpServers in {config_path.as_posix()}")
        return {config_path.as_posix(): entries}

    def _discover_project_mcp_servers(self) -> McpConfigsResult:
        """Per-project MCP discovery for each path in ``_discovery_paths_with_ancestors``.

        Two sources are checked at every path:

        1. ``projects.<path>.mcpServers`` in ``~/.claude.json`` — keyed by the project path.
        2. ``<path>/.mcp.json`` on disk — keyed by the absolute file path.

        A malformed ``.mcp.json`` becomes a ``CouldNotParseMCPConfig`` entry.
        """
        config_path = self._config_json_path()
        data = self._load_config_raw()
        if isinstance(data, CouldNotParseMCPConfig):
            return {config_path.as_posix(): data}
        projects = data.get("projects") if isinstance(data, dict) else None
        if not isinstance(projects, dict):
            projects = {}

        result: McpConfigsResult = {}
        # Iterate every opened project root *and* its ancestors up to filesystem
        # root, so config in a parent folder (e.g. a monorepo root) is picked up
        # for the sub-projects beneath it.
        for path in self._discovery_paths_with_ancestors():
            key = path.as_posix()
            # Source 1: inline ``projects.<path>.mcpServers`` recorded in ``.claude.json``.
            # For an ancestor this only matches if that ancestor was itself opened
            # as a project (i.e. has its own ``projects`` entry); otherwise it misses.
            project_config = projects.get(key)
            if isinstance(project_config, dict):
                project_mcp = project_config.get("mcpServers")
                if isinstance(project_mcp, dict) and project_mcp:
                    result[key] = self._validate_servers(
                        project_mcp, source=f"projects.{key}.mcpServers in {config_path.as_posix()}"
                    )

            # Source 2: a ``.mcp.json`` file in the folder itself — checked at every
            # project root and ancestor, so parent-folder files are discovered too.
            mcp_file = path / ".mcp.json"
            parsed = self._parse_mcp_file(mcp_file, formats=_CLAUDE_MCP_FORMATS)
            # Skip on None (missing/empty file) or an empty server list; a parse
            # failure is a truthy ``CouldNotParseMCPConfig`` and is still recorded.
            if not parsed:
                continue
            result[mcp_file.as_posix()] = parsed
        return result

    # --- private: skills discovery ---

    def _discover_global_skill(self) -> SkillsDirsResult:
        """Scan ``<install>/skills`` under each user-global folder for skills.

        Routes through :meth:`AgentDiscoverer._scan_skills_dir` so a path that is
        a regular file (``NotADirectoryError``) or an unreadable dir under another
        user's home (``PermissionError`` on ``--scan-all-users``) is skipped rather
        than aborting the whole discoverer — the same tolerance the VSCode-family
        skill scans already use.
        """
        result: SkillsDirsResult = {}
        for folder in self._discover_global_folders():
            skills_dir = folder / self._skills_subdir
            entries = self._scan_skills_dir(skills_dir)
            if entries is not None:
                result[skills_dir.as_posix()] = entries
        return result

    def _discover_project_skills(self) -> SkillsDirsResult:
        """For each project (and every ancestor up to root), scan each entry in
        ``_project_skills_relative`` (``.claude/skills`` + ``.agents/skills``) if present.

        Uses :meth:`AgentDiscoverer._scan_skills_dir` for the same is-dir /
        ``PermissionError`` tolerance as :meth:`_discover_global_skill`.
        """
        result: SkillsDirsResult = {}
        for path in self._discovery_paths_with_ancestors():
            for rel in self._project_skills_relative:
                skills_dir = path / rel
                entries = self._scan_skills_dir(skills_dir)
                if entries is not None:
                    result[skills_dir.as_posix()] = entries
        return result

    # --- private: plugin discovery ---

    def _plugin_root_dirs(self) -> list[Path]:
        """Plugin *root* directories — each holds the installed-plugin ``cache``/
        ``repos``/``synced`` subtrees scanned per :attr:`_plugin_subdirs` (and the
        ``marketplaces`` catalog clone, which that attribute deliberately skips).

        The always-present root is ``<base>/plugins`` for each global folder
        (``base`` already honors ``CLAUDE_CONFIG_DIR``). Two env vars add *further*
        roots — they are appended to the default, not substituted for it, so the
        default ``<base>/plugins`` is always scanned alongside them. Their values
        are already at the plugins-root level, so no ``/plugins`` is appended.
        Like ``CLAUDE_CONFIG_DIR`` they reflect the *scanning process's*
        environment, so they are honored only on an own-home scan (see
        :meth:`_scans_own_home`) — under ``--scan-all-users`` the scanner can't
        know another user's env:

        * ``CLAUDE_CODE_PLUGIN_CACHE_DIR`` — documented ambiguously as either an
          additional plugins root or the cache directory itself. This method keeps
          the root interpretation; :meth:`_ambiguous_plugin_cache_bases` adds the
          direct-cache interpretation when the directory has no root-layout markers.
        * ``CLAUDE_CODE_PLUGIN_SEED_DIR`` — ``os.pathsep``-separated read-only seed
          roots mirroring the plugins layout (container/CI pre-population), so it
          remains root-only.

        Both env-var values pass through the same external-root sanitizer; relative
        paths and filesystem anchors are ignored rather than resolved against the
        scanner's working directory or walked as broad roots.

        These env-var arms are own-home-only because they describe the scanner's
        environment. The install and marketplace registries read by the base-dir
        helpers live inside the target home and are therefore honored for every
        scanned home, including ``--scan-all-users``.

        All resolved roots are scanned; results key by absolute path so any overlap
        with the default dedupes, and a non-existent root is skipped downstream.
        """
        roots = [folder / "plugins" for folder in self._discover_global_folders()]
        if self._scans_own_home():
            cache_dir = os.environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR")
            sanitized_cache_dir = self._sanitize_external_root(cache_dir)
            if sanitized_cache_dir is not None:
                roots.append(sanitized_cache_dir)
            seed_dir = os.environ.get("CLAUDE_CODE_PLUGIN_SEED_DIR")
            if seed_dir:
                for raw_seed_dir in seed_dir.split(os.pathsep):
                    sanitized_seed_dir = self._sanitize_external_root(raw_seed_dir)
                    if sanitized_seed_dir is not None:
                        roots.append(sanitized_seed_dir)
        return roots

    def _plugin_base_dirs(self) -> list[Path]:
        """Every bounded base to scan for plugin MCP servers and skills.

        The documented install subdirectories remain the fail-open backstop. The
        internal registries are purely additive: cache entries already covered by a
        fixed base are filtered only to avoid duplicate walks, while plausible
        in-place install roots are added directly (never crossed with subdir names).
        The result is cached because all four plugin discovery arms consume it.
        """
        if self._plugin_base_dirs_cache is not None:
            return self._plugin_base_dirs_cache

        fixed = [root / sub for root in self._plugin_root_dirs() for sub in self._plugin_subdirs]
        extra = [
            *self._ambiguous_plugin_cache_bases(),
            *self._skills_dir_plugin_bases(),
            *self._local_marketplace_dirs(),
        ]
        covered = (*fixed, *extra)
        external: list[Path] = []
        seen_external: set[Path] = set()
        for root in self._installed_plugin_dirs():
            if (
                root in seen_external
                or any(self._is_under(root, base) for base in covered)
                or not self._external_root_has_marker(root)
            ):
                continue
            if len(external) >= _MAX_EXTERNAL_PLUGIN_ROOTS:
                logger.warning(
                    "Plugin install registry exceeds the %d external-root cap; ignoring remaining entries",
                    _MAX_EXTERNAL_PLUGIN_ROOTS,
                )
                break
            seen_external.add(root)
            external.append(root)
        self._plugin_base_dirs_cache = list(dict.fromkeys((*fixed, *extra, *external)))
        return self._plugin_base_dirs_cache

    def _installed_plugin_dirs(self) -> list[Path]:
        """Read additive plugin roots from each target home's install registry.

        ``installed_plugins.json`` is undocumented internal state, so a missing,
        malformed, or future-version registry contributes no extra roots and never
        suppresses the documented directory walk. ``installPath`` is authoritative
        for cache and in-place installs alike, including paths outside the target
        home. Unknown versions are intentionally accepted. Collection is uncapped
        here so cache-covered entries do not consume the external-root budget;
        :meth:`_plugin_base_dirs` caps only roots surviving its coverage and marker
        filters.
        """
        roots: list[Path] = []
        seen: set[Path] = set()
        for folder in self._discover_global_folders():
            data = self._load_json_file(folder / "plugins" / "installed_plugins.json")
            if not isinstance(data, dict):
                continue
            plugins = data.get("plugins")
            if not isinstance(plugins, dict):
                continue
            for entries in plugins.values():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    root = self._sanitize_external_root(entry.get("installPath"))
                    if root is None or root in seen:
                        continue
                    seen.add(root)
                    roots.append(root)
        return roots

    def _local_marketplace_dirs(self) -> list[Path]:
        """Return valid local-directory marketplace roots from the target home.

        Only ``source.source == 'directory'`` is eligible. Git/GitHub/URL catalog
        clones remain excluded because walking them would report plugins the user
        never installed. Both the authoritative install location and declared
        source path are considered to tolerate a moved local checkout.
        """
        roots: list[Path] = []
        seen: set[Path] = set()
        for folder in self._discover_global_folders():
            data = self._load_json_file(folder / "plugins" / "known_marketplaces.json")
            if not isinstance(data, dict):
                continue
            for marketplace in data.values():
                if not isinstance(marketplace, dict):
                    continue
                source = marketplace.get("source")
                if not isinstance(source, dict) or source.get("source") != "directory":
                    continue
                for raw in (marketplace.get("installLocation"), source.get("path")):
                    root = self._sanitize_external_root(raw)
                    if root is None:
                        continue
                    try:
                        has_marker = (root / ".claude-plugin" / "marketplace.json").is_file()
                    except (OSError, ValueError):
                        has_marker = False
                    if not has_marker or root in seen:
                        continue
                    if len(roots) >= _MAX_EXTERNAL_PLUGIN_ROOTS:
                        logger.warning(
                            "Known marketplaces registry exceeds the %d external-root cap; ignoring remaining entries",
                            _MAX_EXTERNAL_PLUGIN_ROOTS,
                        )
                        return roots
                    seen.add(root)
                    roots.append(root)
        return roots

    def _skills_dir_plugin_bases(self) -> list[Path]:
        """Return immediate ``@skills-dir`` children carrying a plugin manifest.

        Gating at the child keeps an ordinary skill folder that happens to contain
        a stray ``.mcp.json`` from being promoted into a plugin root.
        """
        roots: list[Path] = []
        for folder in self._discover_global_folders():
            skills_dir = folder / self._skills_subdir
            try:
                children = list(skills_dir.iterdir())
            except (OSError, ValueError):
                continue
            for child in children:
                try:
                    if (child / ".claude-plugin" / "plugin.json").is_file():
                        roots.append(child)
                except (OSError, ValueError):
                    continue
        return roots

    def _ambiguous_plugin_cache_bases(self) -> list[Path]:
        """Interpret ``CLAUDE_CODE_PLUGIN_CACHE_DIR`` as a direct cache when needed.

        If a known plugins-root marker exists beneath the value, the fixed
        root/subdir walk already covers it. Otherwise the value itself is added as a
        base. As with the root interpretation, this scanner-environment value is
        ignored when scanning another user's home.
        """
        if not self._scans_own_home():
            return []
        root = self._sanitize_external_root(os.environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR"))
        if root is None:
            return []
        try:
            if any((root / marker).is_dir() for marker in ("cache", "repos", "synced", "marketplaces")):
                return []
        except (OSError, ValueError):
            return []
        return [root]

    def _sanitize_external_root(self, raw: object) -> Path | None:
        """Lexically normalize one untrusted external root, rejecting unsafe forms."""
        if not isinstance(raw, str) or not raw.strip():
            return None
        try:
            candidate = expand_path(Path(raw.strip()), self.home_directory)
            candidate = Path(os.path.normpath(candidate))
        except (OSError, ValueError):
            return None
        if not candidate.is_absolute() or candidate.parent == candidate:
            return None
        return candidate

    @staticmethod
    def _external_root_has_marker(root: Path) -> bool:
        """True when an external registry root plausibly contains one plugin."""
        try:
            return (root / ".claude-plugin" / "plugin.json").is_file() or (root / ".mcp.json").is_file()
        except (OSError, ValueError):
            return False

    @staticmethod
    def _is_under(path: Path, base: Path) -> bool:
        """Purely lexical containment used only to suppress duplicate walks."""
        try:
            return path == base or path.is_relative_to(base)
        except ValueError:
            return False

    def _discover_plugin_mcp_servers(self) -> McpConfigsResult:
        """Scan plugin ``.mcp.json`` files (flat ``{name: serverConfig}`` or wrapped
        ``mcpServers``) via the shared :meth:`_discover_plugin_mcp_files`; only the
        format union is Claude-Code-specific.
        """
        return self._discover_plugin_mcp_files(
            self._plugin_base_dirs(),
            (".mcp.json",),
            lambda f: self._parse_mcp_file(f, formats=_CLAUDE_MCP_FORMATS),
        )

    def _discover_plugin_skills(self) -> SkillsDirsResult:
        """Scan ``skills/`` subdirs under every plugin base dir.

        A symlinked ``skills`` directory is yielded from its parent's directory
        listing and ``is_dir`` follows the link, without making the recursive walk
        follow arbitrary symlinked subtrees.
        """
        return self._discover_skill_and_command_dirs(self._plugin_base_dirs(), "skills", inspect_skills_dir)

    # --- private: enterprise/managed MCP discovery ---

    def _managed_mcp_path(self) -> Path | None:
        """Per-OS absolute path to the enterprise ``managed-mcp.json``, or ``None``
        on unsupported platforms. See
        https://code.claude.com/docs/en/managed-mcp."""
        if sys.platform == "darwin":
            return Path("/Library/Application Support/ClaudeCode/managed-mcp.json")
        if sys.platform in ("linux", "linux2"):
            return Path("/etc/claude-code/managed-mcp.json")
        if sys.platform == "win32":
            # ``Program Files`` may live on a non-C: drive or be relocated, so
            # resolve it from the machine-level env var instead of hardcoding the
            # drive. ``PROGRAMW6432`` always points at the 64-bit root (even from a
            # 32-bit process); fall back to ``PROGRAMFILES`` then the conventional
            # default. This is a machine-global path (not per-user), so honoring
            # the scanning process's env is correct even under ``--scan-all-users``.
            # (Python uppercases ``os.environ`` keys on Windows, so the canonical
            # mixed-case ``ProgramW6432``/``ProgramFiles`` vars resolve here.)
            program_files = os.environ.get("PROGRAMW6432") or os.environ.get("PROGRAMFILES") or r"C:\Program Files"
            return Path(program_files) / "ClaudeCode" / "managed-mcp.json"
        return None

    def _discover_managed_mcp_servers(self) -> McpConfigsResult:
        """Parse the system-wide ``managed-mcp.json`` (wrapped ``mcpServers``).

        This is a machine-level file at an absolute system path, not a per-home
        path, so it is identical across every home scanned on one machine;
        downstream keying is by absolute path so duplicates collapse.
        """
        path = self._managed_mcp_path()
        if path is None:
            return {}
        parsed = self._parse_mcp_file(path, formats=(ClaudeConfigFile,))
        if parsed is None:
            return {}
        return {path.as_posix(): parsed}

    # --- private: inline plugin manifest discovery ---

    def _plugin_manifests(self) -> list[tuple[Path, dict]]:
        """``(manifest_path, parsed_dict)`` for every readable ``plugin.json`` under
        the plugin base dirs.

        Recomputed on each call: the cached plugin base dirs are walked and every
        ``plugin.json`` is read and JSON-decoded. A second bounded probe reaches a
        symlinked ``.claude-plugin`` directory without enabling recursive symlink
        following. The inline-MCP and skills manifest scans each call this helper.
        Malformed or non-dict manifests are skipped (so a bad ``plugin.json`` is
        silently ignored, as before).
        """
        manifests: list[tuple[Path, dict]] = []
        seen: set[str] = set()
        for base in self._plugin_base_dirs():
            for manifest in _walk_under_depth(base, "plugin.json", _MAX_PLUGIN_RGLOB_DEPTH, want_file=True):
                key = manifest.as_posix()
                if key in seen:
                    continue
                seen.add(key)
                if not manifest.is_file():
                    continue
                data = self._load_json_file(manifest)
                if isinstance(data, dict):
                    manifests.append((manifest, data))
            for plugin_dir in _walk_under_depth(base, ".claude-plugin", _MAX_PLUGIN_RGLOB_DEPTH, want_file=False):
                manifest = plugin_dir / "plugin.json"
                key = manifest.as_posix()
                if key in seen:
                    continue
                seen.add(key)
                try:
                    is_file = manifest.is_file()
                except (OSError, ValueError):
                    is_file = False
                if not is_file:
                    continue
                data = self._load_json_file(manifest)
                if isinstance(data, dict):
                    manifests.append((manifest, data))
        return manifests

    def _discover_plugin_manifest_mcp_servers(self) -> McpConfigsResult:
        """Parse inline ``mcpServers`` from each plugin's
        ``.claude-plugin/plugin.json`` manifest.

        A plugin can declare its MCP servers inline in the manifest instead of a
        standalone ``.mcp.json``. The ``mcpServers`` value may also be a *string*
        path referencing a separate file — those are already covered by the
        ``.mcp.json`` walk, so only the inline dict form is handled here.
        """
        result: McpConfigsResult = {}
        for manifest, data in self._plugin_manifests():
            inline = data.get("mcpServers")
            if not isinstance(inline, dict) or not inline:
                continue
            result[manifest.as_posix()] = self._validate_servers(
                inline, source=f"plugin manifest {manifest.as_posix()}"
            )
        return result

    def _discover_plugin_manifest_skills(self) -> SkillsDirsResult:
        """Scan skill dirs listed in each plugin's ``.claude-plugin/plugin.json``
        ``skills`` array. Paths are resolved relative to the plugin root (the
        parent of the ``.claude-plugin`` dir). Only string entries are honored.
        """
        result: SkillsDirsResult = {}
        for manifest, data in self._plugin_manifests():
            skills = data.get("skills")
            if not isinstance(skills, list):
                continue
            plugin_root = manifest.parent.parent
            for rel in skills:
                if not isinstance(rel, str):
                    continue
                skills_dir = plugin_root / rel
                if skills_dir.is_dir():
                    result[skills_dir.as_posix()] = inspect_skills_dir(str(skills_dir))
        return result

    # --- internal helpers ---

    def _load_config_raw(self) -> dict | CouldNotParseMCPConfig | None:
        """Read and JSON-decode the global ``.claude.json`` (honoring
        ``CLAUDE_CONFIG_DIR`` on own-home scans). Returns ``None`` if missing,
        a dict on success, or a ``CouldNotParseMCPConfig`` on malformed JSON.
        """
        return self._load_json_file(self._config_json_path())
