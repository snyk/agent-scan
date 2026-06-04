"""Codex CLI discoverer: ``~/.codex/config.toml`` MCP servers (TOML) + the
officially-documented skill directories (``~/.agents/skills``, ``/etc/codex/skills``).

Codex stores its MCP servers in a TOML ``[mcp_servers.<name>]`` table inside
``config.toml``, which the data-driven JSON pipeline (``well_known_clients.py`` +
``inspect.py``) can't parse — so Codex MCP servers are invisible to it. This
discoverer closes that gap. Skills follow the layout documented at
https://developers.openai.com/codex/skills and MCP the layout at
https://developers.openai.com/codex/mcp.
"""

import logging
import os
import traceback
from functools import cached_property
from pathlib import Path

# TOML parsing is stdlib from Python 3.11 (``tomllib``). The project still
# declares ``requires-python >=3.10`` (though every real environment — CI 3.12,
# devcontainer 3.11, local 3.13 — is ≥3.11), so the import is guarded: fall back
# to the ``tomli`` backport when it happens to be installed, else degrade to a
# no-op (Codex TOML parsing is skipped and logged as a gap) rather than break
# import on 3.10.
try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 lacks stdlib TOML
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

from agent_scan.agents.base import (
    _MAX_CONFIG_FILE_BYTES,
    AgentDiscoverer,
    McpConfigsResult,
    SkillsDirsResult,
)
from agent_scan.models import CouldNotParseMCPConfig
from agent_scan.well_known_clients import expand_path

logger = logging.getLogger(__name__)


class CodexDiscoverer(AgentDiscoverer):
    """OpenAI Codex CLI discovery: ``~/.codex/config.toml`` MCP servers + documented skills.

    MCP servers live in a TOML ``[mcp_servers.<name>]`` table (stdio via
    ``command``/``args``/``env`` or HTTP via ``url``); the table is a flat
    ``{name: serverConfig}`` map, so it routes straight through the inherited
    :meth:`AgentDiscoverer._validate_servers`.

    Scopes covered:

    * **User / machine** — ``<codex_home>/config.toml`` MCP servers, user
      ``~/.agents/skills``, admin ``/etc/codex/skills``.
    * **Project** — every project recorded in the user config's ``[projects]``
      table (keyed by absolute path) is scanned for its ``<proj>/.codex/config.toml``
      MCP servers and ``<proj>/.agents/skills`` skills, plus every ancestor up to
      the filesystem root (matching Codex's "walk up to the repository root"). The
      ``[projects]`` table is the documented analogue of Claude Code's
      ``~/.claude.json`` ``projects`` map, surfaced through the inherited
      :meth:`AgentDiscoverer._discover_project_folders` /
      :meth:`_project_paths_with_ancestors` seam.

    The ``trust_level`` recorded alongside each project is **never read** — every
    listed project is scanned regardless of trust (the table is treated purely as a
    list of project paths).

    Deliberately not covered (documented gaps, no path):

    * OpenAI-bundled "system" skills: the docs give no concrete path.
    * Configuration profiles: the on-disk shape is ambiguous in the docs.
    """

    # MUST match the Codex entry name in ``well_known_clients.py`` so the Phase-A
    # (data-driven) / Phase-B (this discoverer) merge in
    # ``pipelines.discover_clients_to_inspect`` lines up on a single client.
    name = "codex"

    _install_path = "~/.codex"
    _config_filename = "config.toml"
    # Documented skill locations (developers.openai.com/codex/skills):
    #   user:  $HOME/.agents/skills   (home-relative; the cross-agent convention)
    #   admin: /etc/codex/skills      (absolute, machine-wide; keyed by abs path so
    #                                  it dedups across homes under --scan-all-users)
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
        """MCP servers from the user config plus every registered project's config."""
        result: McpConfigsResult = {}
        result.update(self._discover_user_mcp_servers())
        result.update(self._discover_project_mcp_servers())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        """Skills from the documented user/admin dirs plus every registered project."""
        result: SkillsDirsResult = {}
        result.update(self._discover_global_skills())
        result.update(self._discover_project_skills())
        return result

    # --- private: MCP discovery ---

    def _discover_user_mcp_servers(self) -> McpConfigsResult:
        """Parse the ``mcp_servers`` table in ``<codex_home>/config.toml``."""
        config_path = self._codex_home() / self._config_filename
        return self._mcp_servers_from_data(self._user_config_toml, config_path)

    def _discover_project_mcp_servers(self) -> McpConfigsResult:
        """Parse ``<project>/.codex/config.toml`` ``mcp_servers`` for every registered
        project root and its ancestors (up to the filesystem root).

        Walking ancestors mirrors ``ClaudeCodeDiscoverer._discover_project_mcp_servers``
        so a monorepo root's config is found when only a sub-package is the registered
        project. Each file is keyed by its absolute path, so a file that coincides with
        the user config (e.g. an ancestor equal to ``codex_home``) dedups in the merge.
        """
        result: McpConfigsResult = {}
        for path in self._project_paths_with_ancestors():
            config_path = path / ".codex" / self._config_filename
            result.update(self._mcp_servers_from_data(self._load_toml_file(config_path), config_path))
        return result

    def _mcp_servers_from_data(self, data: dict | CouldNotParseMCPConfig | None, config_path: Path) -> McpConfigsResult:
        """Turn a loaded ``config.toml`` into a (possibly empty) ``{path: result}`` map.

        ``config.toml`` is multi-purpose (model, approval, sandbox, … settings), so
        discovery is gated on the presence of a non-empty ``mcp_servers`` table: a
        config without it returns ``{}`` (no entry) rather than a spurious parse
        failure (mirrors ``ClaudeCodeDiscoverer._discover_global_mcp_servers``).
        Missing/empty/unreadable (``None``) yields ``{}``; malformed TOML
        (``CouldNotParseMCPConfig``) is surfaced keyed by the file.
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
        """Project roots recorded under the ``[projects]`` table in the user config.

        Keys are absolute project paths; the ``trust_level`` value is intentionally
        **not** read — every listed project is returned regardless of trust (the table
        is treated purely as a path list). The returned roots flow into the inherited
        :meth:`_project_paths_with_ancestors`, which every project-scoped scan consumes.
        """
        data = self._user_config_toml
        if not isinstance(data, dict):
            return []
        projects = data.get("projects")
        if not isinstance(projects, dict):
            return []
        return [Path(p) for p in projects if isinstance(p, str)]

    # --- private: skills discovery ---

    def _discover_global_skills(self) -> SkillsDirsResult:
        """Scan the documented user (``~/.agents/skills``) and admin
        (``/etc/codex/skills``) skill directories.

        Both go through :meth:`AgentDiscoverer._scan_skills_dir`, which tolerates a
        missing path, a regular file, or an unreadable dir (``PermissionError``
        under ``--scan-all-users``) by skipping it rather than aborting discovery.
        """
        result: SkillsDirsResult = {}
        skills_dirs = (
            expand_path(Path(self._user_skills_relative), self.home_directory),
            Path(self._admin_skills_dir),
        )
        for skills_dir in skills_dirs:
            entries = self._scan_skills_dir(skills_dir)
            if entries is not None:
                result[skills_dir.as_posix()] = entries
        return result

    def _discover_project_skills(self) -> SkillsDirsResult:
        """Scan ``<project>/.agents/skills`` for every registered project root and its
        ancestors — covering Codex's documented walk of ``.agents/skills`` from the
        working directory up to the repository root."""
        result: SkillsDirsResult = {}
        for path in self._project_paths_with_ancestors():
            skills_dir = path / ".agents" / "skills"
            entries = self._scan_skills_dir(skills_dir)
            if entries is not None:
                result[skills_dir.as_posix()] = entries
        return result

    # --- CODEX_HOME resolution ---

    def _codex_home(self) -> Path:
        """Base directory holding Codex state (``~/.codex`` by default).

        ``CODEX_HOME`` relocates it. The env var reflects the *scanning process's*
        environment, so it is honored only when scanning that process's own home
        (see :meth:`AgentDiscoverer._scans_own_home`); under ``--scan-all-users``
        the scanner can't know each other target user's env, so the per-home
        default is used. Mirrors how ``ClaudeCodeDiscoverer`` treats
        ``CLAUDE_CONFIG_DIR``.
        """
        if self._scans_own_home():
            codex_home = os.environ.get("CODEX_HOME")
            if codex_home:
                return Path(codex_home)
        return expand_path(Path(self._install_path), self.home_directory)

    @cached_property
    def _user_config_toml(self) -> dict | CouldNotParseMCPConfig | None:
        """Parsed ``<codex_home>/config.toml``, read once per discoverer lifetime.

        Both the user-scope MCP scan and the ``[projects]`` enumeration read it, so
        caching avoids re-parsing the same file. A discoverer is constructed once per
        home for a single scan, so the file is stable for its lifetime.
        """
        return self._load_toml_file(self._codex_home() / self._config_filename)

    # --- TOML loader (mirrors AgentDiscoverer._load_json_file semantics) ---

    def _load_toml_file(self, path: Path) -> dict | CouldNotParseMCPConfig | None:
        """TOML-decode ``path``. ``None`` if missing, empty, unreadable (permissions
        / TOML support unavailable), parsed dict on success, ``CouldNotParseMCPConfig``
        on malformed TOML.

        Mirrors :meth:`AgentDiscoverer._load_json_file`: same oversize cap,
        ``PermissionError``-as-missing tolerance, and empty-file-as-empty-config
        handling — only the decoder differs (``tomllib`` vs ``pyjson5``).
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
