"""Abstract per-agent discoverer and shared discovery infrastructure.

This package sits alongside the data-driven discovery pipeline
(`well_known_clients.py` + `inspect.py`). ``AgentDiscoverer`` is the abstract
base every concrete discoverer extends; each subclass owns the agent-specific
knowledge of where to look for config files and skills directories. The
module-level helpers here are shared infrastructure consumed
by the concrete discoverers in sibling modules.
"""

import logging
import os
import traceback
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from pathlib import Path

import pyjson5

from agent_scan.models import (
    SERVER_CONFIG_DISCRIMINATOR_KEYS,
    ClientToInspect,
    CouldNotParseMCPConfig,
    FileNotFoundConfig,
    MCPConfig,
    MCPServerMap,
    RemoteServer,
    SkillServer,
    StdioServer,
    UnknownConfigFormat,
)
from agent_scan.signed_binary import check_server_signature
from agent_scan.skill_client import inspect_skills_dir

logger = logging.getLogger(__name__)
McpConfigsResult = dict[
    str,
    list[tuple[str, StdioServer | RemoteServer]] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig,
]
SkillsDirsResult = dict[str, list[tuple[str, SkillServer]] | FileNotFoundConfig]
# Return type of the per-file MCP parsers (``_parse_mcp_file`` /
# ``_parse_settings_mcp_gated``): parsed servers, a parse failure, or ``None``
# when the file is absent/empty/not-MCP.
McpScanResult = list[tuple[str, StdioServer | RemoteServer]] | CouldNotParseMCPConfig | None

# Cap traversal into ``~/.claude/plugins/{cache,repos}``
_MAX_PLUGIN_RGLOB_DEPTH = 10

# Cap the size of a config/skill JSON file read whole into memory. Real MCP /
# settings files are KB-scale; without a cap a multi-GB file planted under an
# attacker-influenceable tree (the extension / workspace dirs walked under
# ``--scan-all-users``) would be read entirely into memory. Files over the cap
# are treated as unreadable (skipped) rather than parsed.
_MAX_CONFIG_FILE_BYTES = 20 * 1024 * 1024  # 20 MiB


def _walk_under_depth(base: Path, name: str, max_path_depth: int, *, want_file: bool) -> Iterator[Path]:
    """Yield paths named ``name`` under ``base``, pruning traversal so each yielded
    path's relative parts count is at most ``max_path_depth``.

    Unlike ``Path.rglob`` + post-hoc filtering, traversal stops at the cap rather
    than walking the full subtree first — so a pathologically deep plugin layout
    cannot blow up the walk. When ``want_file`` is True, only file entries are
    yielded; otherwise directory entries.

    An unreadable ``base`` is skipped (yielding nothing), not propagated: on
    Python 3.12+ ``Path.exists()`` re-raises ``PermissionError`` (rather than
    returning ``False``) when an ancestor isn't traversable — the routine
    ``--scan-all-users`` case of an unprivileged scan hitting another user's
    home. Unguarded, that would propagate out of ``discover()`` and the pipeline
    would drop the *whole* discoverer, discarding every already-collected
    reachable source (user ``mcp.json``, ``settings.json``, workspace MCP, …) for
    that IDE/user — a silent false negative. The walk is materialized inside the
    guard so an error surfacing mid-traversal is tolerated too, not just the
    leading ``exists()`` probe. Mirrors the tolerance ``_load_json_file`` and
    ``profiles_dir.iterdir`` already apply.
    """
    try:
        if not base.exists():
            return
        hits: list[Path] = []
        for root_str, dirs, files in os.walk(base):
            root = Path(root_str)
            dir_depth = len(root.relative_to(base).parts)
            candidates = files if want_file else dirs
            if name in candidates:
                hits.append(root / name)
            # The dir we're in is at depth `dir_depth`; an entry inside it sits at
            # depth+1. Prune once depth+1 reaches the cap so we don't descend further.
            if dir_depth + 1 >= max_path_depth:
                dirs.clear()
    except (PermissionError, OSError):
        logger.warning("Permission error walking %s", base.as_posix())
        return
    yield from hits


def _looks_like_mcp_payload(data: dict) -> bool:
    """True if a parsed JSON dict has a recognizable MCP shape.

    Used to gate *opportunistic* discovery — the extension/plugin walks surface
    every file merely *named* ``mcp.json``, and extensions routinely ship
    unrelated files under that name (a JSON schema, a fixture, another tool's
    config). Without a gate each unparseable one becomes a
    ``CouldNotParseMCPConfig`` false positive. A file is recognized when it
    either:

    * carries a wrapper key (``mcpServers``/``mcp``/``servers``) — in which case a
      later validation failure is a *genuine* malformed-MCP signal worth
      surfacing rather than swallowing; or
    * is a non-empty flat ``{name: serverConfig}`` map whose every value is a dict
      bearing a server discriminator (``command``/``url``/``serverUrl``/``httpUrl``) —
      the wrapper-less shape that is still valid MCP (Claude Code plugin format).

    Everything else is treated as "not an MCP file" and skipped by callers that
    opt in via ``_parse_mcp_file(..., skip_unrecognized=True)``.
    """
    if any(key in data for key in ("mcpServers", "mcp", "servers")):
        return True
    return bool(data) and all(
        isinstance(value, dict) and any(disc in value for disc in SERVER_CONFIG_DISCRIMINATOR_KEYS)
        for value in data.values()
    )


class AgentDiscoverer(ABC):
    """Abstract per-agent discoverer.

    Concrete subclasses encapsulate one agent's filesystem layout: where the
    install lives, which JSON file(s) hold its MCP servers, and which directory
    holds its skills. Subclasses MUST set the ``name`` class attribute to the
    canonical agent name used in ``well_known_clients``; this is enforced in
    ``__init_subclass__``.

    A discoverer is bound to a single user's ``home_directory`` at construction;
    the multi-user (``--scan-all-users``) loop in ``pipelines`` constructs one
    discoverer per home directory.

    Unlike the legacy ``inspect.py`` pipeline, this abstraction does NOT consult
    the ``CandidateClient`` row's ``mcp_config_globs`` / ``skills_dir_globs``;
    subclasses encode their layout directly. An agent that genuinely needs
    glob-based discovery should override ``discover_mcp_servers`` /
    ``discover_skills`` to handle it explicitly.
    """

    name: str = ""

    def __init__(self, home_directory: Path | None) -> None:
        # ``None`` is the own-home sentinel; normalize to ``Path.home()`` so the
        # stored home is always concrete. ``expand_path`` treats ``None`` as
        # "unknown home — don't expand", which would leave a ``~``-prefixed literal
        # (e.g. ``~/.claude``) on an own-home scan whose relocating env var is unset.
        self.home_directory = home_directory if home_directory is not None else Path.home()
        # Lazily-populated cache for _project_paths_with_ancestors. A discoverer
        # serves a single scan (see find_discoverers), so the project list is
        # stable for its lifetime and the discovery methods that consult it need
        # not re-walk workspaceStorage / re-read ~/.claude.json each time.
        self._project_paths_cache: list[Path] | None = None

    def _scans_own_home(self) -> bool:
        """True when this discoverer targets the scanning process's own user.

        Env-var-relocated config paths (``CLAUDE_CONFIG_DIR``, ``VSCODE_PORTABLE``)
        reflect the *scanning process's* environment, so they may only be honored
        when the home being scanned is that same user's. Other users' homes under
        ``--scan-all-users`` must compare unequal — the scanner can't know their env.

        The scanning user's own home is spelled two ways, so we accept either and
        resolve both sides to absorb symlinks: ``Path.home()`` (``$HOME``, used in
        single-user mode) and this uid's passwd ``pw_dir`` (used by
        ``--scan-all-users``, which sources homes from ``pwd.getpwall()`` and can
        differ from ``$HOME`` for a sudo-rewritten / symlinked / container home).
        ``pwd``/``os.getuid`` are POSIX-only; the guarded import skips the extra
        candidate on Windows.
        """
        candidates = {Path.home()}
        try:
            import pwd

            candidates.add(Path(pwd.getpwuid(os.getuid()).pw_dir))
        except (ImportError, AttributeError, KeyError, OSError):
            pass
        if self.home_directory in candidates:
            return True
        try:
            resolved_home = self.home_directory.resolve()
            return any(resolved_home == candidate.resolve() for candidate in candidates)
        except OSError:
            return False

    def __init_subclass__(cls, *, abstract: bool = False, **kwargs: object) -> None:
        """Enforce a non-empty ``name`` on concrete subclasses.

        Pass ``abstract=True`` (e.g. ``class VSCodeFamilyDiscoverer(AgentDiscoverer, abstract=True)``)
        for intermediate base classes that exist only to share implementation
        with their own concrete subclasses; those don't need a ``name`` of
        their own and won't ever be registered.
        """
        super().__init_subclass__(**kwargs)
        if abstract:
            return
        if not cls.name:
            raise TypeError(f"{cls.__name__} must set a non-empty 'name' class attribute")

    @abstractmethod
    def client_exists(self) -> str | None:
        """Return the resolved install path if the agent is present, else None."""

    @abstractmethod
    def discover_mcp_servers(self) -> McpConfigsResult:
        """Parse the agent's MCP config file(s) and return them keyed by absolute path."""

    @abstractmethod
    def discover_skills(self) -> SkillsDirsResult:
        """List the agent's skills, keyed by absolute skills-dir path."""

    def discover(self) -> ClientToInspect | None:
        """Assemble a ClientToInspect, or None when the agent isn't installed."""
        client_path = self.client_exists()
        if client_path is None:
            return None
        mcp_configs = self.discover_mcp_servers()
        skills_dirs = self.discover_skills()
        return ClientToInspect(
            name=self.name,
            client_path=client_path,
            mcp_configs=mcp_configs,
            skills_dirs=skills_dirs,
        )

    # --- shared helpers (inherited by every concrete subclass) ---

    def _load_json_file(self, path: Path) -> dict | CouldNotParseMCPConfig | None:
        """JSON-decode an arbitrary file. ``None`` if missing, unreadable (denied
        permissions), or over the ``_MAX_CONFIG_FILE_BYTES`` cap; parsed dict on
        success; ``CouldNotParseMCPConfig`` on malformed JSON.

        Uses ``pyjson5`` to match the legacy ``mcp_client.scan_mcp_config_file``
        path, which tolerates ``//`` comments and trailing commas. An empty or
        whitespace-only file is treated as an empty config (also matching legacy).

        ``PermissionError`` is treated like a missing file — under
        ``--scan-all-users`` an unprivileged process routinely hits homes it
        can't read, and surfacing those as ``CouldNotParseMCPConfig`` would
        misclassify access-control denials as malformed-config errors.
        """
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
            return pyjson5.loads(content)
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

    def _servers_to_signed_list(self, validated: MCPConfig) -> list[tuple[str, StdioServer | RemoteServer]]:
        """Materialize a validated config's servers into ``(name, server)`` tuples,
        replacing each Stdio entry with its signature-checked form.

        Shared by :meth:`_validate_servers` and :meth:`_parse_mcp_file` so the
        signature-check step stays in one place.

        Operates on a shallow copy: ``get_servers()`` may return the validated
        model's live dict (e.g. ``MCPServerMap.servers``), and this helper must not
        mutate the model the caller passed in.
        """
        servers = dict(validated.get_servers())
        for name, server_config in servers.items():
            if isinstance(server_config, StdioServer):
                servers[name] = check_server_signature(server_config)
        return list(servers.items())

    def _validate_servers(
        self, raw: dict, source: str
    ) -> list[tuple[str, StdioServer | RemoteServer]] | CouldNotParseMCPConfig:
        """Validate a raw ``mcpServers`` mapping into typed Stdio/Remote server entries.

        Input is the *already-extracted* server map (e.g. the value of
        ``mcpServers``). For format-aware whole-file parsing (where the wrapper
        layout differs across agents), use :meth:`_parse_mcp_file` instead.
        """
        try:
            validated = MCPServerMap(servers=raw)
        except Exception as e:
            logger.exception("Invalid %s: %s", source, e)
            return CouldNotParseMCPConfig(
                message=f"could not parse {source}",
                traceback=traceback.format_exc(),
                is_failure=True,
            )
        return self._servers_to_signed_list(validated)

    def _parse_mcp_file(
        self,
        path: Path,
        *,
        formats: tuple[type[MCPConfig], ...],
        skip_unrecognized: bool = False,
    ) -> list[tuple[str, StdioServer | RemoteServer]] | CouldNotParseMCPConfig | None:
        """Load ``path``, try each ``MCPConfig`` subclass in order, return the first
        that validates.

        Returns:
          * ``None`` if the file is missing, empty, or unreadable due to permissions
            (matches ``_load_json_file`` semantics).
          * A list of ``(name, server)`` tuples if any of ``formats`` validates the file.
          * ``CouldNotParseMCPConfig`` if the JSON is malformed, or if none of
            ``formats`` validates the file.

        ``formats`` order matters: the first model whose ``model_validate``
        succeeds wins. This mirrors the strategy in
        ``mcp_client.scan_mcp_config_file``.

        ``skip_unrecognized`` is an opt-in for *opportunistic* walks that match
        every file merely *named* ``mcp.json`` (the extension walk). When set, a
        valid-JSON file with no recognizable MCP shape (see
        :func:`_looks_like_mcp_payload`) returns ``None`` instead of
        ``CouldNotParseMCPConfig``, so an unrelated extension file isn't reported as
        malformed; a wrapper-keyed file that then fails to validate is still
        surfaced. Callers parsing an explicitly-named config (e.g.
        ``~/.vscode/mcp.json``) leave it off so genuine malformations are reported.
        """
        data = self._load_json_file(path)
        if data is None:
            return None
        if isinstance(data, CouldNotParseMCPConfig):
            return data
        if not isinstance(data, dict):
            # A non-object root (JSON array/scalar) is no known MCP shape. An
            # opportunistic walk merely matched the filename, so skip it. An
            # explicitly-named config falls through to the format loop below, where
            # every ``model_validate`` rejects the non-dict and the last error
            # surfaces as CouldNotParseMCPConfig (legacy ``scan_mcp_config_file``
            # parity).
            if skip_unrecognized:
                return None
        elif not data:
            # Empty object: no servers and not malformed — skip quietly
            # (legacy returns a zero-server ``ConfigWithoutMCP`` for ``{}``).
            return None
        elif skip_unrecognized and not _looks_like_mcp_payload(data):
            return None

        last_error: Exception | None = None
        for model in formats:
            try:
                validated = model.model_validate(data)
            except Exception as e:
                last_error = e
                continue
            return self._servers_to_signed_list(validated)

        # None of the formats validated — record as parse failure. Use logger.error
        # (not logger.exception): this runs outside any active except handler, so
        # exc_info would resolve to an empty (None, None, None) and tack a bogus
        # "NoneType: None" traceback onto the line. The real traceback is captured
        # from last_error into the returned object's ``traceback`` field below.
        logger.error("No MCP format matched %s; last error: %s", path.as_posix(), last_error)
        return CouldNotParseMCPConfig(
            message=f"could not parse {path.as_posix()} as any of {[m.__name__ for m in formats]}",
            traceback="".join(traceback.format_exception(type(last_error), last_error, last_error.__traceback__))
            if last_error is not None
            else "",
            is_failure=True,
        )

    def _scan_skills_dir(self, path: Path) -> list[tuple[str, SkillServer]] | None:
        """Return the parsed skill list for ``path`` if it's an existing directory,
        else ``None``. Thin wrapper that hides the existence check from callers.
        """
        try:
            if not path.exists() or not path.is_dir():
                return None
        except PermissionError:
            return None
        return inspect_skills_dir(str(path))

    def _discover_skill_and_command_dirs(
        self,
        bases: list[Path],
        subdir_name: str,
        inspect_fn: Callable[[str], list[tuple[str, SkillServer]]],
    ) -> SkillsDirsResult:
        """Walk each base dir for ``subdir_name`` directories and inspect each hit.

        Shared by the Claude Code plugin ``skills``/``commands`` walks and the
        VSCode-family extension ``skills`` walk — all iterate identically:
        ``_walk_under_depth`` for the named directory under each base (skipping
        unreadable bases, see its docstring), then run ``inspect_fn``
        (``inspect_skills_dir`` or ``inspect_commands_dir``) on each match.
        """
        result: SkillsDirsResult = {}
        for base in bases:
            for found in _walk_under_depth(base, subdir_name, _MAX_PLUGIN_RGLOB_DEPTH, want_file=False):
                if found.is_dir():
                    result[found.as_posix()] = inspect_fn(str(found))
        return result

    def _discover_plugin_mcp_files(
        self,
        bases: list[Path],
        filenames: tuple[str, ...],
        parse_fn: Callable[[Path], McpScanResult],
    ) -> McpConfigsResult:
        """Walk each base dir for plugin MCP files named in ``filenames``, parse
        each hit via ``parse_fn``, keyed by absolute path.

        The MCP counterpart of :meth:`_discover_skill_and_command_dirs`, shared by
        the Claude Code, Codex, and Cursor plugin walks. Each agent supplies its own
        ``filenames`` and ``parse_fn`` (format union / snake-case / ``skip_unrecognized``
        policy), so per-agent parsing stays in the subclass while the walk is shared.
        A falsy result (``None`` or empty list) is skipped; a truthy
        ``CouldNotParseMCPConfig`` is recorded.
        """
        result: McpConfigsResult = {}
        for base in bases:
            for name in filenames:
                for mcp_file in _walk_under_depth(base, name, _MAX_PLUGIN_RGLOB_DEPTH, want_file=True):
                    if not mcp_file.is_file():
                        continue
                    parsed = parse_fn(mcp_file)
                    if not parsed:
                        continue
                    result[mcp_file.as_posix()] = parsed
        return result

    # --- shared project-folder enumeration (used by both Claude Code and the VSCode family) ---

    def _discover_project_folders(self) -> list[Path]:
        """Return the project roots this agent has opened.

        Each subclass surfaces them from its own source of truth: Claude Code
        reads the ``projects`` map in ``~/.claude.json``; the VSCode family
        walks ``<userdata>/User/workspaceStorage``. Discoverers without a
        project concept return ``[]`` so the ancestor walk is a no-op.
        """
        return []

    def _project_paths_with_ancestors(self) -> list[Path]:
        """Project roots plus every ancestor up to filesystem root, deduplicated.

        Walking up lets project-scope MCP and skills discovery pick up config
        living in any parent folder of an opened project (e.g. a monorepo root
        that contains many project subdirectories).

        The result is cached for the discoverer's lifetime.
        """
        if self._project_paths_cache is not None:
            return self._project_paths_cache
        seen: set[Path] = set()
        result: list[Path] = []
        for project_path in self._discover_project_folders():
            cur = project_path
            while True:
                if cur not in seen:
                    seen.add(cur)
                    result.append(cur)
                parent = cur.parent
                if parent == cur:
                    break
                cur = parent
        self._project_paths_cache = result
        return result
