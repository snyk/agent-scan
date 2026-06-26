"""opencode discoverer: ``~/.config/opencode/opencode.{json,jsonc}`` + skills +
per-project ``opencode.json`` + per-OS managed configs + ``$OPENCODE_CONFIG`` override."""

import logging
import os
import sqlite3
import sys
from pathlib import Path

from agent_scan.agents.base import (
    AgentDiscoverer,
    McpConfigsResult,
    SkillsDirsResult,
)
from agent_scan.models import MCPConfig, OpenCodeConfigFile
from agent_scan.well_known_clients import expand_path

logger = logging.getLogger(__name__)

# Format union for opencode MCP files. Only one format today; declared as a
# tuple to plug into ``_parse_mcp_file`` uniformly with the other discoverers.
_OPENCODE_MCP_FORMATS: tuple[type[MCPConfig], ...] = (OpenCodeConfigFile,)
# opencode accepts either extension; per https://opencode.ai/docs/config the
# layered-config loader tries each when reading global and project scopes.
_CONFIG_FILENAMES: tuple[str, ...] = ("opencode.json", "opencode.jsonc")


class OpenCodeDiscoverer(AgentDiscoverer):
    """opencode discovery across global, project, managed, env-override, and
    Claude-compatibility scopes.

    Scope sources:

    * Global — ``~/.config/opencode/opencode.{json,jsonc}`` (mcp) and
      ``~/.config/opencode/{skills,skill}`` (skills). ``~/.config/opencode`` is
      XDG-style on every OS opencode supports, including Windows (verified
      empirically). Singular ``skill/`` is opencode's documented
      backwards-compat spelling (https://opencode.ai/docs/config: "Singular
      names (e.g., ``agent/``) are also supported for backwards compatibility").
    * Project — for every project root in ``_project_paths_with_ancestors``
      (and its ancestors): ``<root>/opencode.{json,jsonc}`` plus
      ``<root>/.opencode/{skills,skill}``.
    * Managed — per-OS system-wide ``opencode.{json,jsonc}`` (and skill dirs)
      under ``/Library/Application Support/opencode`` (macOS), ``/etc/opencode``
      (Linux), or ``%ProgramData%\\opencode`` (Windows). See follow-up note in
      :meth:`_managed_config_dir` for the macOS MDM plist scope, which is
      intentionally NOT scanned here.
    * Env overrides — both are honored only on an own-home scan (the env vars
      reflect the *scanning process's* environment, so they must not be applied
      to other users under ``--scan-all-users``):

      - ``$OPENCODE_CONFIG`` names an alternate config file (mcp only).
      - ``$OPENCODE_CONFIG_DIR`` names an alternate global config *directory*;
        treated additively (the default ``~/.config/opencode`` is still scanned
        too) so the scanner never misses configs regardless of whether opencode
        treats this as replacement or addition.

    * Claude-Code compat — opencode's skill discovery
      (https://opencode.ai/docs/skills) lists four extra paths it loads
      alongside its own ``skills/`` dirs:

      - Project: ``<root>/.claude/skills``, ``<root>/.agents/skills``
      - Global: ``~/.claude/skills``, ``~/.agents/skills``

      These are scanned even when Claude Code itself is not installed (an
      opencode-only user may still have authored skills under one of these
      directories — opencode will load them, so the scanner must see them).
      Cross-discoverer overlap when Claude Code *is* also installed is harmless:
      the pipeline keys results by absolute path and dedupes.

    * Second global dir — opencode's own ``ConfigPaths.directories`` also walks
      ``~/.opencode`` (``packages/opencode/src/config/paths.ts``), so that
      location is treated as a second global config root.

    * User-declared skill folders — opencode's config schema
      (``packages/core/src/v1/config/skills.ts``) exposes
      ``skills.paths: string[]`` for "additional paths to skill folders". Every
      ``opencode.json`` we already parse is rechecked for this array, and each
      entry is expanded the way opencode does: ``~/...`` against
      ``home_directory``, relative against the *containing config file's
      directory*.

    * URL-pulled skill cache — opencode's config also exposes
      ``skills.urls: string[]``; the runtime puller writes downloaded skills
      under ``~/.cache/opencode/skills/<Bun.hash(base-url)>/<skill-name>/SKILL.md``
      (``packages/core/src/skill/discovery.ts``). Each hash dir is scanned as a
      skills-dir root.

    Project enumeration is unusual: opencode persists the absolute paths of
    opened projects in a SQLite database at
    ``~/.local/share/opencode/opencode.db`` (Drizzle ``project`` table,
    ``worktree`` column). :meth:`_discover_project_folders` reads it read-only;
    any failure (missing file, lock contention, schema drift) yields an empty
    list rather than aborting discovery.
    """

    name = "opencode"

    _install_path = "~/.config/opencode"
    # opencode's own ``ConfigPaths.directories`` walks ``Global.Path.home`` for
    # a ``.opencode`` dir (packages/opencode/src/config/paths.ts:34-38), so
    # ``~/.opencode`` is a real second global config location alongside
    # ``~/.config/opencode``. Scanned for both ``opencode.{json,jsonc}`` and
    # ``{skills,skill}`` subdirs.
    _install_path_alt = "~/.opencode"
    _data_path = "~/.local/share/opencode"
    # opencode caches URL-pulled skills here. Per
    # packages/core/src/skill/discovery.ts:107 the layout is
    # ``<cache>/skills/<bun-hash-of-base-url>/<skill-name>/SKILL.md``. We walk
    # the ``<hash>`` level so each hash dir is treated like a skills dir root.
    _cache_path = "~/.cache/opencode"
    _db_filename = "opencode.db"
    # Both spellings are documented; ``skills/`` is canonical, ``skill/`` is the
    # backwards-compat alias. We scan both so a user who created either gets
    # picked up; downstream keys by absolute path so a single existing dir
    # appears once.
    _skills_subdirs: tuple[str, ...] = ("skills", "skill")
    # Project-scoped skill dirs scanned at every opened project root and its
    # ancestors. The ``.opencode/`` entries are opencode-native (both spellings
    # per the backwards-compat note above); the ``.claude/`` and ``.agents/``
    # entries are the Claude-Code/cross-agent compat paths opencode also loads
    # per https://opencode.ai/docs/skills.
    _project_skills_relative: tuple[str, ...] = (
        ".opencode/skills",
        ".opencode/skill",
        ".claude/skills",
        ".agents/skills",
    )
    # Global Claude-compat skill dirs scanned in addition to
    # ``~/.config/opencode/{skills,skill}``. Same compat list as above but
    # rooted at the user's home.
    _global_compat_skill_dirs: tuple[str, ...] = (
        "~/.claude/skills",
        "~/.agents/skills",
    )

    # --- public (override AgentDiscoverer abstracts) ---

    def client_exists(self) -> str | None:
        path = self._global_config_dir()
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
        result.update(self._discover_managed_mcp_servers())
        result.update(self._discover_env_override_mcp_servers())
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        result.update(self._discover_global_skills())
        result.update(self._discover_project_skills())
        result.update(self._discover_managed_skills())
        result.update(self._discover_config_skills_paths())
        result.update(self._discover_cached_url_skills())
        return result

    # --- folder resolution ---

    def _default_global_config_dir(self) -> Path:
        """The XDG-style default global config dir, ignoring ``OPENCODE_CONFIG_DIR``."""
        return expand_path(Path(self._install_path), self.home_directory)

    def _global_config_dir(self) -> Path:
        """The single global config dir reported as the install path.

        Kept as the canonical install path for ``client_exists``; the discovery
        sweeps consult :meth:`_global_config_dirs` instead so they cover the
        ``OPENCODE_CONFIG_DIR`` override too.
        """
        return self._default_global_config_dir()

    def _global_config_dirs(self) -> list[Path]:
        """Every global config dir to sweep for MCP/skills.

        Includes (in priority order):

        - ``$OPENCODE_CONFIG_DIR`` when set on an own-home scan — kept additive
          (not a replacement) so the scanner never misses configs regardless of
          whether opencode treats the env var as relocation or as an additional
          search root.
        - ``~/.config/opencode`` — the XDG default.
        - ``~/.opencode`` — opencode's ``ConfigPaths.directories`` also walks
          ``Global.Path.home`` for ``.opencode``, so a user with skills or an
          ``opencode.json`` directly under their home dir gets discovered too.

        Results are downstream-keyed by absolute path, so a single dir that
        appears multiple ways collapses to one entry.
        """
        dirs: list[Path] = []
        if self._scans_own_home():
            override = os.environ.get("OPENCODE_CONFIG_DIR")
            if override:
                dirs.append(Path(override))
        dirs.append(self._default_global_config_dir())
        dirs.append(expand_path(Path(self._install_path_alt), self.home_directory))
        return dirs

    def _data_dir(self) -> Path:
        return expand_path(Path(self._data_path), self.home_directory)

    def _cache_dir(self) -> Path:
        return expand_path(Path(self._cache_path), self.home_directory)

    def _managed_config_dir(self) -> Path | None:
        """System-wide opencode config directory, or ``None`` on unsupported OSes.

        macOS MDM scope NOT scanned here: opencode also exposes managed
        preferences as a plist at ``/Library/Managed Preferences/<user>/
        ai.opencode.managed.plist`` (bundle id ``ai.opencode.managed``). That
        path uses Apple's binary-or-XML plist format, not JSON, and its mcp
        schema is not yet documented end-to-end. Adding plist parsing for a
        speculative schema would be premature; documented in TODO(ADS-MDM).
        """
        if sys.platform == "darwin":
            return Path("/Library/Application Support/opencode")
        if sys.platform in ("linux", "linux2"):
            return Path("/etc/opencode")
        if sys.platform == "win32":
            program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
            return Path(program_data) / "opencode"
        return None

    def _opencode_config_env_path(self) -> Path | None:
        """Resolved ``$OPENCODE_CONFIG`` path on an own-home scan, else ``None``."""
        if not self._scans_own_home():
            return None
        override = os.environ.get("OPENCODE_CONFIG")
        if not override:
            return None
        return Path(override)

    # --- project enumeration (SQLite db) ---

    def _discover_project_folders(self) -> list[Path]:
        """Project paths from opencode's SQLite db (``project.worktree`` column).

        Opened with ``mode=ro&immutable=1`` so a concurrently-running opencode
        cannot block us on the WAL/SHM lock; any sqlite error (missing file,
        schema drift, permission denied) yields ``[]`` rather than aborting the
        whole discoverer.
        """
        db_path = self._data_dir() / self._db_filename
        try:
            if not db_path.exists():
                return []
        except (PermissionError, OSError):
            return []
        # ``immutable=1`` is what lets us co-exist with a live opencode: it tells
        # SQLite the file will not change, so no WAL/SHM is consulted and no lock
        # is taken. Safe for a read-only inspection.
        uri = f"file:{db_path.as_posix()}?mode=ro&immutable=1"
        try:
            con = sqlite3.connect(uri, uri=True)
            try:
                cur = con.execute("SELECT worktree FROM project WHERE worktree IS NOT NULL")
                rows = cur.fetchall()
            finally:
                con.close()
        except sqlite3.Error as e:
            logger.warning("Could not read opencode project table from %s: %s", db_path.as_posix(), e)
            return []
        return [Path(row[0]) for row in rows if isinstance(row[0], str) and row[0]]

    # --- MCP discovery ---

    def _scan_config_dir(self, base: Path) -> McpConfigsResult:
        """Try every ``_CONFIG_FILENAMES`` entry under ``base``; record any hits."""
        result: McpConfigsResult = {}
        for filename in _CONFIG_FILENAMES:
            path = base / filename
            # ``skip_unrecognized=True`` so a file lacking an ``mcp`` block (e.g.
            # an opencode config that only sets ``permission`` / ``theme``) is
            # skipped quietly rather than reported as malformed. The
            # ``_looks_like_mcp_payload`` gate covers wrapper-key detection.
            parsed = self._parse_mcp_file(path, formats=_OPENCODE_MCP_FORMATS, skip_unrecognized=True)
            if not parsed:
                continue
            result[path.as_posix()] = parsed
        return result

    def _discover_global_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        for base in self._global_config_dirs():
            result.update(self._scan_config_dir(base))
        return result

    def _discover_project_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        for project in self._project_paths_with_ancestors():
            result.update(self._scan_config_dir(project))
        return result

    def _discover_managed_mcp_servers(self) -> McpConfigsResult:
        managed_dir = self._managed_config_dir()
        if managed_dir is None:
            return {}
        return self._scan_config_dir(managed_dir)

    def _discover_env_override_mcp_servers(self) -> McpConfigsResult:
        path = self._opencode_config_env_path()
        if path is None:
            return {}
        # An explicitly-named config — do NOT use ``skip_unrecognized``: if the
        # user pointed ``$OPENCODE_CONFIG`` at a file that fails to parse, that's
        # a real signal worth surfacing rather than silently dropping.
        parsed = self._parse_mcp_file(path, formats=_OPENCODE_MCP_FORMATS)
        if not parsed:
            return {}
        return {path.as_posix(): parsed}

    # --- skills discovery ---

    def _record_skills_at(self, result: SkillsDirsResult, path: Path) -> None:
        """If ``path`` is an existing skills dir, record its entries under ``result``.

        Centralized so every skill scope (global, global-compat, project,
        managed) uses the same is-dir / PermissionError tolerance via
        ``_scan_skills_dir``.
        """
        entries = self._scan_skills_dir(path)
        if entries is not None:
            result[path.as_posix()] = entries

    def _discover_global_skills(self) -> SkillsDirsResult:
        """Scan every ``{base}/{skills,skill}`` across the global config dirs
        (default + ``$OPENCODE_CONFIG_DIR``) and the Claude-compat globals."""
        result: SkillsDirsResult = {}
        for base in self._global_config_dirs():
            for sub in self._skills_subdirs:
                self._record_skills_at(result, base / sub)
        for rel in self._global_compat_skill_dirs:
            self._record_skills_at(result, expand_path(Path(rel), self.home_directory))
        return result

    def _discover_project_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        for project in self._project_paths_with_ancestors():
            for rel in self._project_skills_relative:
                self._record_skills_at(result, project / rel)
        return result

    def _discover_managed_skills(self) -> SkillsDirsResult:
        managed_dir = self._managed_config_dir()
        if managed_dir is None:
            return {}
        result: SkillsDirsResult = {}
        for sub in self._skills_subdirs:
            self._record_skills_at(result, managed_dir / sub)
        return result

    # --- skills.paths from user opencode.json (Gap B) ---

    def _iter_candidate_config_files(self) -> list[Path]:
        """Every opencode config file we'd consider for ``skills.paths`` extraction.

        Covers the same scopes as MCP discovery (global, project, managed,
        ``$OPENCODE_CONFIG`` env file) so a ``skills.paths`` declared anywhere
        opencode honors it is picked up. The file may or may not exist;
        ``_load_json_file`` handles missing/unreadable files quietly.
        """
        candidates: list[Path] = []
        for base in self._global_config_dirs():
            for filename in _CONFIG_FILENAMES:
                candidates.append(base / filename)
        for project in self._project_paths_with_ancestors():
            for filename in _CONFIG_FILENAMES:
                candidates.append(project / filename)
        managed = self._managed_config_dir()
        if managed is not None:
            for filename in _CONFIG_FILENAMES:
                candidates.append(managed / filename)
        env_path = self._opencode_config_env_path()
        if env_path is not None:
            candidates.append(env_path)
        return candidates

    def _discover_config_skills_paths(self) -> SkillsDirsResult:
        """Scan every ``skills.paths`` entry referenced from any opencode.json.

        Per ``packages/core/src/v1/config/skills.ts``:

            paths: Schema.optional(Schema.Array(Schema.String))
                .annotate({ description: "Additional paths to skill folders" })

        The opencode loader (``packages/opencode/src/skill/index.ts:211-220``)
        expands each entry — ``~/...`` against the user's home, relative paths
        against the *containing config file's directory* — then globs
        ``**/SKILL.md`` recursively. We mirror the expansion rules; the
        recursive ``**/SKILL.md`` is handled by ``_scan_skills_dir`` only at
        the top level for now (nested skills are a separate follow-up, since
        ``inspect_skills_dir`` is shared infrastructure).

        Malformed config files (already reported by MCP discovery) are skipped
        here — we only consume the ``skills.paths`` array on success.
        """
        result: SkillsDirsResult = {}
        for config_path in self._iter_candidate_config_files():
            data = self._load_json_file(config_path)
            if not isinstance(data, dict):
                continue
            skills = data.get("skills")
            if not isinstance(skills, dict):
                continue
            paths = skills.get("paths")
            if not isinstance(paths, list):
                continue
            for entry in paths:
                if not isinstance(entry, str) or not entry:
                    continue
                resolved = self._resolve_skills_path_entry(entry, config_path)
                self._record_skills_at(result, resolved)
        return result

    def _resolve_skills_path_entry(self, entry: str, config_path: Path) -> Path:
        """Expand a single ``skills.paths`` entry the way opencode does.

        - ``~/...`` -> joined to ``self.home_directory``.
        - Absolute -> as-is.
        - Relative -> joined to the *containing config file's directory*.
        """
        if entry.startswith("~/") or entry == "~":
            return expand_path(Path(entry), self.home_directory)
        candidate = Path(entry)
        if candidate.is_absolute():
            return candidate
        return config_path.parent / candidate

    # --- URL-pulled skills cache (Gap C) ---

    def _discover_cached_url_skills(self) -> SkillsDirsResult:
        """Scan ``~/.cache/opencode/skills/<hash>/`` for skills pulled from
        ``cfg.skills.urls`` URLs.

        Per ``packages/core/src/skill/discovery.ts:107`` the layout is
        ``<cache>/skills/<Bun.hash(base-url)>/<skill-name>/SKILL.md``. Each
        ``<hash>`` directory is structurally identical to a normal skills dir
        root, so we list one level beneath ``skills/`` and feed each match
        through ``_scan_skills_dir``.
        """
        cache_skills = self._cache_dir() / "skills"
        result: SkillsDirsResult = {}
        try:
            if not cache_skills.is_dir():
                return result
            hash_dirs = sorted(cache_skills.iterdir())
        except (PermissionError, OSError):
            return result
        for hash_dir in hash_dirs:
            if not hash_dir.is_dir():
                continue
            self._record_skills_at(result, hash_dir)
        return result
