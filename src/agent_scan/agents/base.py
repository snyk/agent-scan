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
    ClaudeConfigFile,
    ClientToInspect,
    CouldNotParseMCPConfig,
    FileNotFoundConfig,
    MCPConfig,
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

# Top-level keys that only ever appear on a single server config (StdioServer.command,
# RemoteServer.url/serverUrl/httpUrl). Used by ``_looks_like_mcp_payload`` to recognize a
# wrapper-less flat ``{name: serverConfig}`` MCP payload. Must stay in sync with
# RemoteServer's URL AliasChoices and the PluginMCPConfigFile flat-format gate in models.py.
_SERVER_CONFIG_DISCRIMINATOR_KEYS = frozenset({"command", "url", "serverUrl", "httpUrl"})


def _walk_under_depth(base: Path, name: str, max_path_depth: int, *, want_file: bool) -> Iterator[Path]:
    """Yield paths named ``name`` under ``base``, pruning traversal so each yielded
    path's relative parts count is at most ``max_path_depth``.

    Unlike ``Path.rglob`` + post-hoc filtering, traversal stops at the cap rather
    than walking the full subtree first — so a pathologically deep plugin layout
    cannot blow up the walk. When ``want_file`` is True, only file entries are
    yielded; otherwise directory entries.
    """
    for root_str, dirs, files in os.walk(base):
        root = Path(root_str)
        dir_depth = len(root.relative_to(base).parts)
        candidates = files if want_file else dirs
        if name in candidates:
            yield root / name
        # The dir we're in is at depth `dir_depth`; an entry inside it sits at
        # depth+1. Prune once depth+1 reaches the cap so we don't descend further.
        if dir_depth + 1 >= max_path_depth:
            dirs.clear()


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
        isinstance(value, dict) and any(disc in value for disc in _SERVER_CONFIG_DISCRIMINATOR_KEYS)
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
    the multi-user (`--scan-all-users`) loop in ``pipelines`` constructs one
    discoverer per home directory.

    Note: this abstraction intentionally does NOT consult the corresponding
    ``CandidateClient`` row's ``mcp_config_globs`` / ``skills_dir_globs``
    fields. Subclasses encode their layout directly. If a future agent
    genuinely needs glob-based discovery, override ``discover_mcp_servers`` /
    ``discover_skills`` to handle it explicitly.
    """

    name: str = ""

    def __init__(self, home_directory: Path | None) -> None:
        self.home_directory = home_directory
        # Lazily-populated cache for _project_paths_with_ancestors. A discoverer
        # is constructed once per home and used for a single scan (see
        # find_discoverers), so the project list is stable for its lifetime and
        # the several discovery methods that consult it need not re-walk the
        # workspaceStorage tree / re-read ~/.claude.json each time.
        self._project_paths_cache: list[Path] | None = None

    def _scans_own_home(self) -> bool:
        """True when this discoverer targets the scanning process's own user.

        Env-var-relocated config paths (``CLAUDE_CONFIG_DIR``, ``VSCODE_PORTABLE``)
        reflect the *scanning process's* environment, so they may only be honored
        when the home being scanned is that same user's. ``home_directory is None``
        is the explicit own-home sentinel, but production never passes it: for the
        current user ``get_readable_home_directories`` returns ``Path.home()`` (see
        ``pipelines.discover_clients_to_inspect``), so an equal ``Path.home()`` must
        also count as own-home — otherwise those env paths never activate in a real
        scan. Other users' homes under ``--scan-all-users`` compare unequal and are
        correctly excluded (the scanner can't know their env).
        """
        return self.home_directory is None or self.home_directory == Path.home()

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
        """JSON-decode an arbitrary file. ``None`` if missing or unreadable due to
        permissions, parsed dict on success, ``CouldNotParseMCPConfig`` on
        malformed JSON.

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
        """
        servers = validated.get_servers()
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
            validated = ClaudeConfigFile(mcpServers=raw)
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
        formats: tuple[type[MCPConfig], ...] = (ClaudeConfigFile,),
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
        :func:`_looks_like_mcp_payload`) returns ``None`` (skip) instead of a
        ``CouldNotParseMCPConfig`` — so an unrelated extension file isn't reported
        as a malformed config. A wrapper-keyed file that then fails to validate is
        still surfaced as malformed. Callers parsing an explicitly-named config
        file (e.g. ``~/.vscode/mcp.json``) leave this off so genuine malformations
        there are still reported.
        """
        data = self._load_json_file(path)
        if data is None:
            return None
        if isinstance(data, CouldNotParseMCPConfig):
            return data
        if not isinstance(data, dict) or not data:
            return None
        if skip_unrecognized and not _looks_like_mcp_payload(data):
            return None

        last_error: Exception | None = None
        for model in formats:
            try:
                validated = model.model_validate(data)
            except Exception as e:
                last_error = e
                continue
            return self._servers_to_signed_list(validated)

        # None of the formats validated — record as parse failure.
        logger.exception("No MCP format matched %s; last error: %s", path.as_posix(), last_error)
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

    def _discover_dirs_under(
        self,
        bases: list[Path],
        subdir_name: str,
        inspect_fn: Callable[[str], list[tuple[str, SkillServer]]],
    ) -> SkillsDirsResult:
        """Walk each base dir for ``subdir_name`` directories and inspect each hit.

        Shared by the Claude Code plugin ``skills``/``commands`` walks and the
        VSCode-family extension ``skills`` walk — all iterate identically: for
        each existing base, ``_walk_under_depth`` for the named directory, then
        run ``inspect_fn`` (``inspect_skills_dir`` or ``inspect_commands_dir``)
        on each match.
        """
        result: SkillsDirsResult = {}
        for base in bases:
            if not base.exists():
                continue
            for found in _walk_under_depth(base, subdir_name, _MAX_PLUGIN_RGLOB_DEPTH, want_file=False):
                if found.is_dir():
                    result[found.as_posix()] = inspect_fn(str(found))
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

        The result is cached for the discoverer's lifetime
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
