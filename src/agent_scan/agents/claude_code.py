"""Claude Code discoverer: ``~/.claude.json`` + ``~/.claude/skills`` + per-project,
plugin, command, and enterprise (managed-mcp) scopes."""

import logging
import os
import sys
from functools import cached_property
from pathlib import Path

from agent_scan.agents.base import (
    _MAX_PLUGIN_RGLOB_DEPTH,
    AgentDiscoverer,
    McpConfigsResult,
    SkillsDirsResult,
    _select_servers_payload,
    _walk_under_depth,
)
from agent_scan.models import (
    CouldNotParseMCPConfig,
)
from agent_scan.skill_client import inspect_commands_dir, inspect_skills_dir
from agent_scan.well_known_clients import CLAUDE_CODE_NAME, expand_path

logger = logging.getLogger(__name__)


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
    # Subtrees under a plugin *root* (see ``_plugin_root_dirs``) that stage
    # installed plugins. ``cache`` is the hydrated install tree and
    # ``marketplaces`` the cloned marketplace sources (the current layout, per
    # ``~/.claude/plugins`` and the plugin-marketplaces docs); ``repos`` is the
    # legacy name kept for back-compat with older installs. All can host MCP
    # servers / skills / commands.
    _plugin_subdirs: tuple[str, ...] = ("cache", "marketplaces", "repos")

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
        result.update(self._discover_global_commands())
        result.update(self._discover_project_commands())
        result.update(self._discover_plugin_commands())
        result.update(self._discover_plugin_manifest_skills())
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
        """Per-project MCP discovery for each path in ``_project_paths_with_ancestors``.

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
        for path in self._project_paths_with_ancestors():
            key = path.as_posix()
            project_config = projects.get(key)
            if isinstance(project_config, dict):
                project_mcp = project_config.get("mcpServers")
                if isinstance(project_mcp, dict) and project_mcp:
                    result[key] = self._validate_servers(
                        project_mcp, source=f"projects.{key}.mcpServers in {config_path.as_posix()}"
                    )

            mcp_file = path / ".mcp.json"
            file_data = self._load_json_file(mcp_file)
            if file_data is None:
                continue
            if isinstance(file_data, CouldNotParseMCPConfig):
                result[mcp_file.as_posix()] = file_data
                continue
            if not isinstance(file_data, dict) or not file_data:
                continue
            file_mcp = _select_servers_payload(file_data)
            if not isinstance(file_mcp, dict) or not file_mcp:
                continue
            result[mcp_file.as_posix()] = self._validate_servers(
                file_mcp, source=f"mcpServers in {mcp_file.as_posix()}"
            )
        return result

    # --- private: skills discovery ---

    def _discover_global_skill(self) -> SkillsDirsResult:
        """Scan ``<install>/skills`` under each user-global folder for skills."""
        result: SkillsDirsResult = {}
        for folder in self._discover_global_folders():
            skills_dir = folder / self._skills_subdir
            if skills_dir.exists():
                result[skills_dir.as_posix()] = inspect_skills_dir(str(skills_dir))
        return result

    def _discover_project_skills(self) -> SkillsDirsResult:
        """For each project (and every ancestor up to root), scan ``<path>/.claude/skills`` if present."""
        result: SkillsDirsResult = {}
        for path in self._project_paths_with_ancestors():
            skills_dir = path / self._project_dotclaude_subdir / self._skills_subdir
            if skills_dir.exists():
                result[skills_dir.as_posix()] = inspect_skills_dir(str(skills_dir))
        return result

    # --- private: plugin discovery ---

    def _plugin_root_dirs(self) -> list[Path]:
        """Plugin *root* directories — each holds the ``cache``/``marketplaces``/
        ``repos`` subtrees (see :attr:`_plugin_subdirs`).

        The default is ``<base>/plugins`` for each global folder (``base`` already
        honors ``CLAUDE_CONFIG_DIR``). Two env vars relocate or extend it; like
        ``CLAUDE_CONFIG_DIR`` they reflect the *scanning process's* environment, so
        they are honored only on an own-home scan (see :meth:`_scans_own_home`) —
        under ``--scan-all-users`` the scanner can't know another user's env:

        * ``CLAUDE_CODE_PLUGIN_CACHE_DIR`` — overrides the plugins root (despite the
          name it is the parent dir; ``cache``/``marketplaces`` live beneath it).
        * ``CLAUDE_CODE_PLUGIN_SEED_DIR`` — ``os.pathsep``-separated read-only seed
          roots mirroring the plugins layout (container/CI pre-population).

        All resolved roots are scanned; results key by absolute path so any overlap
        with the default dedupes, and a non-existent root is skipped downstream.
        """
        roots = [folder / "plugins" for folder in self._discover_global_folders()]
        if self._scans_own_home():
            cache_dir = os.environ.get("CLAUDE_CODE_PLUGIN_CACHE_DIR")
            if cache_dir:
                roots.append(Path(cache_dir))
            seed_dir = os.environ.get("CLAUDE_CODE_PLUGIN_SEED_DIR")
            if seed_dir:
                roots.extend(Path(p) for p in seed_dir.split(os.pathsep) if p)
        return roots

    def _plugin_base_dirs(self) -> list[Path]:
        """Every ``<plugin-root>/<subdir>`` to scan for plugin MCP servers and skills."""
        return [root / sub for root in self._plugin_root_dirs() for sub in self._plugin_subdirs]

    def _discover_plugin_mcp_servers(self) -> McpConfigsResult:
        """Scan plugin ``.mcp.json`` files under every plugin base dir.

        Plugin ``.mcp.json`` files use the flat ``{name: serverConfig}`` format
        (no ``mcpServers`` wrapper). A top-level ``mcpServers`` key is also
        tolerated for plugins that ship the wrapped format.
        """
        result: McpConfigsResult = {}
        for base in self._plugin_base_dirs():
            if not base.exists():
                continue
            for mcp_file in _walk_under_depth(base, ".mcp.json", _MAX_PLUGIN_RGLOB_DEPTH, want_file=True):
                if not mcp_file.is_file():
                    continue
                file_data = self._load_json_file(mcp_file)
                if file_data is None:
                    continue
                if isinstance(file_data, CouldNotParseMCPConfig):
                    result[mcp_file.as_posix()] = file_data
                    continue
                if not isinstance(file_data, dict) or not file_data:
                    continue
                raw_servers = _select_servers_payload(file_data)
                if not isinstance(raw_servers, dict) or not raw_servers:
                    continue
                result[mcp_file.as_posix()] = self._validate_servers(
                    raw_servers, source=f"plugin {mcp_file.as_posix()}"
                )
        return result

    def _discover_plugin_skills(self) -> SkillsDirsResult:
        """Scan ``skills/`` subdirs under every plugin base dir."""
        return self._discover_dirs_under(self._plugin_base_dirs(), "skills", inspect_skills_dir)

    # --- private: commands discovery (commands are skills per current docs) ---

    def _discover_global_commands(self) -> SkillsDirsResult:
        """Scan ``<install>/commands`` for command files under each global folder."""
        result: SkillsDirsResult = {}
        for folder in self._discover_global_folders():
            commands_dir = folder / "commands"
            if commands_dir.exists():
                result[commands_dir.as_posix()] = inspect_commands_dir(str(commands_dir))
        return result

    def _discover_project_commands(self) -> SkillsDirsResult:
        """For each project (and ancestor), scan ``<path>/.claude/commands`` if present."""
        result: SkillsDirsResult = {}
        for path in self._project_paths_with_ancestors():
            commands_dir = path / self._project_dotclaude_subdir / "commands"
            if commands_dir.exists():
                result[commands_dir.as_posix()] = inspect_commands_dir(str(commands_dir))
        return result

    def _discover_plugin_commands(self) -> SkillsDirsResult:
        """Scan ``commands/`` subdirs under every plugin base dir."""
        return self._discover_dirs_under(self._plugin_base_dirs(), "commands", inspect_commands_dir)

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
        parsed = self._parse_mcp_file(path)
        if parsed is None:
            return {}
        return {path.as_posix(): parsed}

    # --- private: inline plugin manifest discovery ---

    @cached_property
    def _plugin_manifests(self) -> list[tuple[Path, dict]]:
        """``(manifest_path, parsed_dict)`` for every readable ``plugin.json`` under
        the plugin base dirs.

        Walked and loaded once and cached for the discoverer's lifetime — the
        inline-MCP and skills manifest scans both consume it, so neither the walk
        nor the JSON read is repeated. Malformed or non-dict manifests are
        skipped (so a bad ``plugin.json`` is silently ignored, as before).
        """
        manifests: list[tuple[Path, dict]] = []
        for base in self._plugin_base_dirs():
            if not base.exists():
                continue
            for manifest in _walk_under_depth(base, "plugin.json", _MAX_PLUGIN_RGLOB_DEPTH, want_file=True):
                if not manifest.is_file():
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
        for manifest, data in self._plugin_manifests:
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
        for manifest, data in self._plugin_manifests:
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
