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
from agent_scan.models import DiscoveryLocationScope, MCPConfig, OpenCodeConfigFile
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
    * Project — for every project root in ``_discovery_paths_with_ancestors``
      (and its ancestors): ``<root>/opencode.{json,jsonc}`` *and*
      ``<root>/.opencode/opencode.{json,jsonc}`` (both are real opencode config
      locations — see :meth:`_project_config_bases`) plus
      ``<root>/.opencode/{skills,skill}``.
    * Managed — per-OS system-wide ``opencode.{json,jsonc}`` (and skill dirs)
      under ``/Library/Application Support/opencode`` (macOS), ``/etc/opencode``
      (Linux), or ``%ProgramData%\\opencode`` (Windows).
    * Env overrides — all are honored only on an own-home scan (the env vars
      reflect the *scanning process's* environment, so they must not be applied
      to other users under ``--scan-all-users``). All are applied *additively*
      to the home-relative defaults so the scanner never misses configs
      regardless of whether opencode treats them as relocation or addition.

      - ``$OPENCODE_CONFIG`` names an alternate config file (mcp only).
      - ``$OPENCODE_CONFIG_DIR`` names an alternate global config *directory*.
      - ``$XDG_CONFIG_HOME``, ``$XDG_DATA_HOME``, ``$XDG_CACHE_HOME`` — opencode
        uses the ``xdg-basedir`` package for every ``Global.Path`` location
        (``packages/core/src/global.ts``), so when these are set opencode reads
        from ``<XDG>/opencode/`` instead of the conventional home-relative paths
        for config, data (SQLite db), and cache (URL-pulled skills),
        respectively.

    * Claude-Code compat — opencode's skill discovery
      (https://opencode.ai/docs/skills) lists four extra paths it loads
      alongside its own ``skills/`` dirs:

      - Project: ``<root>/.claude/skills``, ``<root>/.agents/skills``
      - Global: ``~/.claude/skills``, ``~/.agents/skills``

      These are scanned even when Claude Code itself is not installed (an
      opencode-only user may still have authored skills under one of these
      directories — opencode will load them, so the scanner must see them).
      Cross-discoverer overlap when Claude Code *is* also installed is expected,
      not deduped away. The pipeline dedupes only *within* one agent: it keys
      ``ClientToInspect`` by ``(name, username)`` and unions each one's
      path-keyed ``skills_dirs`` (see ``pipelines.discover_clients_to_inspect``).
      ``opencode`` and ``claude code`` are distinct names, so each reports
      ``~/.claude/skills`` under its own name and it is inspected/attributed
      twice. That is correct rather than redundant — both agents really do load
      those skills, so each should be labeled with them.

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
    opened projects in a SQLite database under ``~/.local/share/opencode``
    (Drizzle ``project`` table, ``worktree`` column). The db filename varies by
    install channel — ``opencode.db`` on ``latest``/``beta``/``prod`` builds,
    ``opencode-<channel>.db`` otherwise — and ``$OPENCODE_DB`` may relocate it on
    own-home scans, so :meth:`_discover_project_folders` globs ``opencode*.db``
    per data dir and additionally honors ``$OPENCODE_DB`` (see
    :meth:`_candidate_db_paths`). Each db is read read-only; any failure (missing
    file, lock contention, schema drift) yields an empty list rather than
    aborting discovery.
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
    # opencode's db filename varies by install channel
    # (packages/core/src/database/database.ts ``path()``): ``opencode.db`` for
    # ``latest``/``beta``/``prod`` builds (or when ``OPENCODE_DISABLE_CHANNEL_DB``
    # is set), and ``opencode-<channel>.db`` for every other channel — e.g. the
    # build-time default ``local`` (``opencode-local.db``) or a dev/preview build
    # named after its git branch. We glob this pattern per data dir so projects
    # from any channel are enumerated. ``opencode*.db`` is start-anchored and
    # matches the ``.db`` suffix, so the ``-wal``/``-shm`` sidecars (which end in
    # ``-wal``/``-shm``) are excluded.
    _DB_GLOB = "opencode*.db"
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
        """Detect an opencode install at any known global config dir or the
        ``$OPENCODE_CONFIG`` file.

        Walks every candidate in :meth:`_global_config_dirs` (XDG override,
        ``$OPENCODE_CONFIG_DIR``, ``~/.config/opencode``, ``~/.opencode``) and
        returns the first one that exists. A user with ``$XDG_CONFIG_HOME``
        relocating their config out of ``~/.config`` would otherwise read as
        "not installed" and skip the whole discoverer.

        The ``$OPENCODE_CONFIG`` file (own-home scans only, via
        :meth:`_opencode_config_env_path`) is checked last: a user who relocates
        their entire config to a file outside any standard dir would otherwise
        read as "not installed", so ``discover`` would bail before
        :meth:`_discover_env_override_mcp_servers` could surface it.
        """
        candidates = list(self._global_config_dirs())
        env_config = self._opencode_config_env_path()
        if env_config is not None:
            candidates.append(env_config)
        for path in candidates:
            try:
                if path.exists():
                    return path.as_posix()
            except (PermissionError, OSError) as e:
                # ``Path.exists()`` re-raises OSErrors other than
                # ENOENT/ENOTDIR/EBADF/ELOOP (e.g. ESTALE on a stale NFS mount,
                # EIO). Tolerate per candidate and keep probing the rest rather
                # than letting one bad path drop the whole discoverer. Matches
                # the ``(PermissionError, OSError)`` guard on the db probe below.
                logger.warning("Error checking opencode candidate path %s: %s", path.as_posix(), e)
        return None

    def discover_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        self._merge_mcp_results(result, self._discover_project_mcp_servers, DiscoveryLocationScope.PROJECT_WORKSPACE)
        self._merge_mcp_results(result, self._discover_global_mcp_servers, DiscoveryLocationScope.USER)
        self._merge_mcp_results(result, self._discover_env_override_mcp_servers, DiscoveryLocationScope.USER)
        self._merge_mcp_results(result, self._discover_managed_mcp_servers, DiscoveryLocationScope.SYSTEM)
        return result

    def discover_skills(self) -> SkillsDirsResult:
        result: SkillsDirsResult = {}
        self._merge_skill_results(result, self._discover_project_skills, DiscoveryLocationScope.PROJECT_WORKSPACE)
        self._merge_skill_results(result, self._discover_global_skills, DiscoveryLocationScope.USER)
        self._merge_skill_results(result, self._discover_cached_url_skills, DiscoveryLocationScope.USER)
        self._merge_scoped_skill_results(
            result,
            self._discover_config_skills_paths(DiscoveryLocationScope.PROJECT_WORKSPACE),
        )
        self._merge_scoped_skill_results(
            result,
            self._discover_config_skills_paths(DiscoveryLocationScope.USER),
        )
        self._merge_skill_results(result, self._discover_managed_skills, DiscoveryLocationScope.SYSTEM)
        self._merge_scoped_skill_results(
            result,
            self._discover_config_skills_paths(DiscoveryLocationScope.SYSTEM),
        )
        return result

    # --- folder resolution ---

    def _default_global_config_dir(self) -> Path:
        """The XDG-style default global config dir, ignoring ``OPENCODE_CONFIG_DIR``."""
        return expand_path(Path(self._install_path), self.home_directory)

    def _xdg_env_dir(self, env_var: str) -> Path | None:
        """Return ``<env>/opencode`` if ``env_var`` is set on an own-home scan.

        opencode resolves every ``Global.Path`` via ``xdg-basedir``
        (``packages/core/src/global.ts``), which honors the standard ``XDG_*``
        env vars. When the scanning process has one set, that's where opencode
        is reading from; the scanner must look there too. Other users under
        ``--scan-all-users`` get the home-relative defaults only.
        """
        if not self._scans_own_home():
            return None
        value = os.environ.get(env_var)
        if not value:
            return None
        # ``.absolute()`` so a relative env value (xdg-basedir/Node don't reject
        # one) still yields an absolute path — the result dicts are keyed by
        # ``.as_posix()`` and downstream dedup/attribution assumes absolute keys.
        # Matches the ``.absolute()`` guard on the SQLite db path below.
        return (Path(value) / "opencode").absolute()

    def _global_config_dirs(self) -> list[Path]:
        """Every global config dir to sweep for MCP/skills.

        Includes (all scanned additively):

        - ``$XDG_CONFIG_HOME/opencode`` when set on an own-home scan — opencode
          reads its config from there instead of ``~/.config/opencode`` per
          ``xdg-basedir`` resolution. Additive: defaults are still scanned.
        - ``$OPENCODE_CONFIG_DIR`` when set on an own-home scan — opencode's
          alternate config dir.
        - ``~/.config/opencode`` — the XDG default.
        - ``~/.opencode`` — opencode's ``ConfigPaths.directories`` also walks
          ``Global.Path.home`` for ``.opencode``, so a user with skills or an
          ``opencode.json`` directly under their home dir gets discovered too.

        Results are downstream-keyed by absolute path, so a single dir that
        appears multiple ways collapses to one entry.
        """
        dirs: list[Path] = []
        xdg = self._xdg_env_dir("XDG_CONFIG_HOME")
        if xdg is not None:
            dirs.append(xdg)
        if self._scans_own_home():
            override = os.environ.get("OPENCODE_CONFIG_DIR")
            if override:
                # ``.absolute()`` keeps keys absolute even for a relative env
                # value (see ``_xdg_env_dir``).
                dirs.append(Path(override).absolute())
        dirs.append(self._default_global_config_dir())
        dirs.append(expand_path(Path(self._install_path_alt), self.home_directory))
        return dirs

    def _data_dirs(self) -> list[Path]:
        """Every data dir to consult for opencode SQLite db files.

        Includes ``$XDG_DATA_HOME/opencode`` on own-home scans (where opencode
        actually persists projects when XDG is set) plus the home-relative
        default ``~/.local/share/opencode``.
        """
        dirs: list[Path] = []
        xdg = self._xdg_env_dir("XDG_DATA_HOME")
        if xdg is not None:
            dirs.append(xdg)
        dirs.append(expand_path(Path(self._data_path), self.home_directory))
        return dirs

    def _cache_dirs(self) -> list[Path]:
        """Every cache dir to consult for URL-pulled skills.

        Includes ``$XDG_CACHE_HOME/opencode`` on own-home scans plus the
        home-relative default ``~/.cache/opencode``.
        """
        dirs: list[Path] = []
        xdg = self._xdg_env_dir("XDG_CACHE_HOME")
        if xdg is not None:
            dirs.append(xdg)
        dirs.append(expand_path(Path(self._cache_path), self.home_directory))
        return dirs

    def _managed_config_dir(self) -> Path | None:
        """System-wide opencode config directory, or ``None`` on unsupported OSes.

        ``/Library/Application Support/opencode`` (macOS), ``/etc/opencode``
        (Linux), or ``%ProgramData%\\opencode`` (Windows).
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
        # ``.absolute()`` so a relative env value yields an absolute key /
        # ``client_path`` (see ``_xdg_env_dir``).
        return Path(override).absolute()

    def _opencode_db_value(self) -> str | None:
        """Raw ``$OPENCODE_DB`` value on an own-home scan, else ``None``.

        Mirrors :meth:`_opencode_config_env_path`'s own-home gate (the env var
        reflects the *scanning process's* environment, not another user's under
        ``--scan-all-users``). The raw string is returned because resolution
        differs by shape — ``:memory:`` has no backing file, an absolute path is
        used as-is, and a relative path is joined to the data dir — which
        :meth:`_resolve_db_env_paths` handles. An empty value is treated as unset,
        matching the ``OPENCODE_CONFIG``/``OPENCODE_CONFIG_DIR`` handling.
        """
        if not self._scans_own_home():
            return None
        return os.environ.get("OPENCODE_DB") or None

    def _resolve_db_env_paths(self) -> list[Path]:
        """Resolve ``$OPENCODE_DB`` (own-home only) to concrete db file paths.

        Per ``packages/core/src/database/database.ts`` ``path()``: ``:memory:``
        has no backing file (skipped — nothing to scan); an absolute path is used
        as-is; a relative value is joined to ``Global.Path.data``. opencode joins
        a relative value to whichever data dir is active, and this session-less
        scanner can't know which, so it resolves against *every* data dir (an
        additive superset — a join that doesn't exist on disk is filtered by the
        ``is_file()`` guard in :meth:`_discover_project_folders`).

        ``.absolute()`` (never ``.resolve()``) keeps keys absolute for a relative
        env value while preserving the ``is_file()`` symlink-follow semantics the
        FIFO hang-defense relies on (see :meth:`_xdg_env_dir`).
        """
        value = self._opencode_db_value()
        if value is None or value == ":memory:":
            return []
        candidate = Path(value)
        if candidate.is_absolute():
            return [candidate.absolute()]
        return [(data_dir / candidate).absolute() for data_dir in self._data_dirs()]

    # --- project enumeration (SQLite db) ---

    def _candidate_db_paths(self) -> list[Path]:
        """Every opencode SQLite db file to consult for opened projects.

        The ``$OPENCODE_DB`` override paths (own-home only, see
        :meth:`_resolve_db_env_paths`) come first, followed by every
        ``opencode*.db`` glob hit in each data dir from :meth:`_data_dirs`. Paths
        are deduplicated by ``.as_posix()`` so a relative ``$OPENCODE_DB`` that
        coincides with a globbed file is opened — and warned about — only once.
        Globbing tolerates a per-dir ``PermissionError``/``OSError`` (the
        ``sorted(dir.glob(...))`` idiom used across the discoverers).
        """
        seen: set[str] = set()
        candidates: list[Path] = []

        def add(path: Path) -> None:
            key = path.as_posix()
            if key not in seen:
                seen.add(key)
                candidates.append(path)

        for path in self._resolve_db_env_paths():
            add(path)
        for data_dir in self._data_dirs():
            try:
                matches = sorted(data_dir.glob(self._DB_GLOB))
            except (PermissionError, OSError):
                continue
            for path in matches:
                add(path)
        return candidates

    def _discover_project_folders(self) -> list[Path]:
        """Project paths from opencode's SQLite db (``project.worktree`` column).

        Reads every candidate db from :meth:`_candidate_db_paths` (the
        ``opencode*.db`` glob across the data dirs in :meth:`_data_dirs` plus any
        ``$OPENCODE_DB`` override on own-home scans), deduplicating worktree
        paths. :meth:`_read_worktrees` opens each db read-only (preferring a
        WAL-aware ``mode=ro`` read, falling back to an ``immutable=1`` snapshot
        when that open is denied); per-db sqlite errors (missing file, schema
        drift, permission denied) are tolerated rather than aborting the whole
        discoverer.
        """
        seen: set[str] = set()
        result: list[Path] = []
        for db_path in self._candidate_db_paths():
            try:
                # ``is_file()`` (not ``exists()``) so a non-regular file planted
                # at this path — a FIFO/socket/device, the classic
                # ``--scan-all-users`` hostile-home case — is skipped before
                # ``sqlite3.connect`` can block on open()/first-read waiting for
                # a writer and hang the scan. Mirrors the ``is_file()`` guard the
                # plugin/extension MCP walks use for the same defense. Follows
                # symlinks, so a symlink to a real db still works; a symlink to a
                # FIFO is rejected. Like ``exists()``, ``is_file()`` re-raises
                # OSErrors outside the ENOENT/ENOTDIR ignore set (ESTALE, EIO),
                # so the per-candidate tolerance below is still needed.
                if not db_path.is_file():
                    continue
            except (PermissionError, OSError):
                continue
            rows = self._read_worktrees(db_path)
            if rows is None:
                continue
            for row in rows:
                if not isinstance(row[0], str) or not row[0] or row[0] in seen:
                    continue
                seen.add(row[0])
                result.append(Path(row[0]))
        return result

    def _read_worktrees(self, db_path: Path) -> list[tuple[object, ...]] | None:
        """Read the ``project.worktree`` column read-only, preferring a live
        (WAL-aware) read and falling back to an immutable snapshot. ``None`` on
        any sqlite failure (missing table, corruption, denied open).

        ``mode=ro`` reads the latest *committed* state, including rows still in
        the ``-wal`` that opencode hasn't checkpointed into the main db yet —
        where its most-recently-opened projects live, since it keeps a
        long-lived WAL connection and checkpoints lazily. But a plain read-only
        open of a WAL db must read/build the ``-shm`` wal-index, which an
        unprivileged scanner reading *another* user's home under
        ``--scan-all-users`` may lack permission to write; that open fails
        outright. So we fall back to ``immutable=1``, which tells SQLite the
        file never changes and to read the main db file directly with no
        ``-wal``/``-shm`` consulted and no lock taken: the open always succeeds,
        at the cost of missing un-checkpointed rows (and tolerating a torn read
        of an in-flight write — a bogus worktree string just yields a Path whose
        ancestor walk misses on a handful of stats). Best case (own-home / root
        scan) we get freshness; worst case we still get every checkpointed
        project instead of dropping the user entirely.

        ``no such table`` (schema drift) also raises ``OperationalError``, so a
        drifted db is probed in both modes before the warning — rare and cheap
        (no rows, fast fail), and preferable to matching on error-message text.

        ``as_uri()`` produces the canonical ``file:///`` form on every OS
        (Windows needs the third slash so ``C:`` isn't parsed as URI authority)
        and percent-encodes any ``?``/``#``/whitespace in the path so they don't
        corrupt the query string. ``.absolute()`` guards a relative
        ``$XDG_DATA_HOME`` — ``as_uri`` raises ValueError on relative paths.
        """
        base = db_path.absolute().as_uri()
        last_error: sqlite3.Error | None = None
        for suffix in ("?mode=ro", "?mode=ro&immutable=1"):
            try:
                con = sqlite3.connect(f"{base}{suffix}", uri=True)
                try:
                    return con.execute("SELECT worktree FROM project WHERE worktree IS NOT NULL").fetchall()
                finally:
                    con.close()
            except sqlite3.Error as e:
                last_error = e
                continue
        logger.warning("Could not read opencode project table from %s: %s", db_path.as_posix(), last_error)
        return None

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

    def _project_config_bases(self, project: Path) -> tuple[Path, ...]:
        """Every dir under an opened project root that may hold an ``opencode.{json,jsonc}``.

        opencode loads a project's config from both the project root
        (``<root>/opencode.{json,jsonc}``) *and* the project's ``.opencode``
        directory (``<root>/.opencode/opencode.{json,jsonc}``) — see opencode's
        ``config.ts`` loader: step 4 walks up for ``opencode.json{,c}`` and step
        5 walks up for ``.opencode`` dirs, loading ``opencode.json{,c}`` from each.
        The scanner previously only looked at the root, so a project whose MCP
        block lives in ``.opencode/opencode.jsonc`` was invisible in discovery.
        """
        return (project, project / ".opencode")

    def _discover_global_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        for base in self._global_config_dirs():
            result.update(self._scan_config_dir(base))
        return result

    def _discover_project_mcp_servers(self) -> McpConfigsResult:
        result: McpConfigsResult = {}
        for project in self._discovery_paths_with_ancestors():
            for base in self._project_config_bases(project):
                result.update(self._scan_config_dir(base))
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
        for project in self._discovery_paths_with_ancestors():
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
        return [path for path, _scope in self._iter_scoped_candidate_config_files()]

    def _iter_scoped_candidate_config_files(
        self, source_scope: DiscoveryLocationScope | None = None
    ) -> list[tuple[Path, DiscoveryLocationScope]]:
        candidates: list[tuple[Path, DiscoveryLocationScope]] = []
        if source_scope in (None, DiscoveryLocationScope.USER):
            for base in self._global_config_dirs():
                for filename in _CONFIG_FILENAMES:
                    candidates.append((base / filename, DiscoveryLocationScope.USER))
            env_path = self._opencode_config_env_path()
            if env_path is not None:
                candidates.append((env_path, DiscoveryLocationScope.USER))
        if source_scope in (None, DiscoveryLocationScope.PROJECT_WORKSPACE):
            for project in self._discovery_paths_with_ancestors():
                for base in self._project_config_bases(project):
                    for filename in _CONFIG_FILENAMES:
                        candidates.append((base / filename, DiscoveryLocationScope.PROJECT_WORKSPACE))
        if source_scope in (None, DiscoveryLocationScope.SYSTEM):
            managed = self._managed_config_dir()
            if managed is not None:
                for filename in _CONFIG_FILENAMES:
                    candidates.append((managed / filename, DiscoveryLocationScope.SYSTEM))
        return candidates

    def _discover_config_skills_paths(self, source_scope: DiscoveryLocationScope | None = None) -> SkillsDirsResult:
        """Scan every ``skills.paths`` entry referenced from any opencode.json.

        Per ``packages/core/src/v1/config/skills.ts``:

            paths: Schema.optional(Schema.Array(Schema.String))
                .annotate({ description: "Additional paths to skill folders" })

        The opencode loader (``packages/opencode/src/skill/index.ts:211-214``)
        merges all config scopes into one config and resolves each entry —
        ``~/...`` against the user's home, absolute as-is, and **relative entries
        against the instance/project directory** (the cwd within the worktree),
        *not* the declaring config file's directory. Since this scanner is
        session-less, we resolve relative entries against every opened-project
        worktree (see :meth:`_resolve_skills_path_entry`) and scan each resolved
        directory via ``_scan_skills_dir``.

        Malformed config files (already reported by MCP discovery) are skipped
        here — we only consume the ``skills.paths`` array on success.
        """
        result: SkillsDirsResult = {}
        # opencode's instance dirs (the db ``worktree`` leaves); computed once so
        # the relative-entry resolution below doesn't re-read the SQLite db per
        # candidate config file.
        worktrees = (
            self._all_discovery_folders() if self._scope_enabled(DiscoveryLocationScope.PROJECT_WORKSPACE) else []
        )
        for config_path, config_scope in self._iter_scoped_candidate_config_files(source_scope):
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
                is_project_relative = entry != "~" and not entry.startswith("~/") and not Path(entry).is_absolute()
                result_scope = DiscoveryLocationScope.PROJECT_WORKSPACE if is_project_relative else config_scope
                if not self._scope_enabled(result_scope):
                    continue
                for resolved in self._resolve_skills_path_entry(entry, worktrees):
                    entries = self._scan_skills_dir(resolved)
                    if entries is not None:
                        key = resolved.as_posix()
                        result[key] = self._scope_skill_results({key: entries}, result_scope)[key]
        return result

    def _resolve_skills_path_entry(self, entry: str, worktrees: list[Path]) -> list[Path]:
        """Expand a single ``skills.paths`` entry the way opencode does.

        - ``~`` / ``~/...`` -> the scanned user's home (one path).
        - Absolute -> as-is (one path).
        - Relative -> opencode joins it to the *instance/project directory* (the
          cwd within the worktree), not the declaring config file's dir, so we
          resolve it against every opened-project ``worktree`` (one path each).
          With no opened projects there is no anchor and the entry resolves to
          nothing — matching that opencode would never load it from the config
          dir.
        """
        if entry == "~" or entry.startswith("~/"):
            return [expand_path(Path(entry), self.home_directory)]
        candidate = Path(entry)
        if candidate.is_absolute():
            return [candidate]
        return [worktree / candidate for worktree in worktrees]

    # --- URL-pulled skills cache (Gap C) ---

    def _discover_cached_url_skills(self) -> SkillsDirsResult:
        """Scan ``<cache>/opencode/skills/<hash>/`` for URL-pulled skills.

        Iterates every cache dir in :meth:`_cache_dirs` (XDG override +
        default). Per ``packages/core/src/skill/discovery.ts:107`` the layout
        under each cache root is ``skills/<Bun.hash(base-url)>/<skill-name>/SKILL.md``.
        Each ``<hash>`` directory is structurally identical to a normal skills
        dir root, so we list one level beneath ``skills/`` and feed each match
        through ``_scan_skills_dir``.
        """
        result: SkillsDirsResult = {}
        for cache_dir in self._cache_dirs():
            cache_skills = cache_dir / "skills"
            try:
                if not cache_skills.is_dir():
                    continue
                # Sort for deterministic ordering in tests/output; opencode's
                # runtime doesn't impose any order on the bun-hash directories
                # (each maps to a distinct base URL via Bun.hash, so iteration
                # order is FS-dependent).
                hash_dirs = sorted(cache_skills.iterdir())
            except (PermissionError, OSError):
                continue
            for hash_dir in hash_dirs:
                if not hash_dir.is_dir():
                    continue
                self._record_skills_at(result, hash_dir)
        return result
