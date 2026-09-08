import glob
import logging
import traceback
from pathlib import Path

from httpx import HTTPStatusError

from agent_scan.agents.base import DiscoveryScope
from agent_scan.mcp_client import check_server, scan_mcp_config_file
from agent_scan.models import (
    AUTOMATIC_DISCOVERY_SCOPES,
    LOCATION_SCOPE_PRECEDENCE,
    CandidateClient,
    ClientToInspect,
    CouldNotParseMCPConfig,
    DiscoveredServer,
    DiscoveredSkill,
    DiscoveryLocationScope,
    FileNotFoundConfig,
    InspectedPath,
    InspectedServer,
    InspectedSkill,
    MCPConfig,
    RemoteServer,
    ScanError,
    ServerHTTPError,
    ServerStartupError,
    SkillFile,
    SkillScanError,
    StdioServer,
    TokenAndClientInfo,
    UnknownConfigFormat,
    UnknownMCPConfig,
    UserDeclinedError,
)
from agent_scan.signed_binary import check_server_signature
from agent_scan.skill_client import (
    SkillInspectionError,
    collect_skill_files,
    inspect_skills_dir,
    resolve_skill_name,
)
from agent_scan.traffic_capture import TrafficCapture
from agent_scan.utils import get_relative_path
from agent_scan.well_known_clients import expand_path

logger = logging.getLogger(__name__)


def _inspection_component_name(name: str, component_type: str, source_path: str) -> str:
    """Keep unnamed components attributable without exposing a home-directory path."""
    return name or f"unnamed {component_type} ({get_relative_path(source_path)})"


def _inspection_error_to_scan_error(
    error: ServerStartupError | ServerHTTPError | SkillScanError | UserDeclinedError,
) -> ScanError:
    """Normalize a concrete inspection failure."""
    return ScanError(
        message=error.message,
        exception=error.sub_exception_message,
        traceback=error.traceback,
        is_failure=error.is_failure,
        category=error.category,
        server_output=error.server_output if isinstance(error, ServerStartupError | ServerHTTPError) else None,
    )


def _servers_by_origin(mcp_config: MCPConfig) -> dict[str | None, dict[str, StdioServer | RemoteServer]]:
    """Group a parsed config's servers by the block that declared them.

    Almost every config format holds one location scope, so its servers come back
    under a single ``None`` origin. ``~/.claude.json`` is the exception and
    reports each ``projects.<path>`` block separately.
    """
    by_origin = getattr(mcp_config, "get_servers_by_origin", None)
    if by_origin is None:
        return {None: mcp_config.get_servers()}
    return by_origin()


def _discovered_servers(
    mcp_config: MCPConfig,
    path_scope: DiscoveryLocationScope,
    skipped: frozenset[DiscoveryLocationScope],
) -> list[DiscoveredServer]:
    """Label each server with the scope of the block that declared it.

    The exclusion is applied per entry rather than per file because a single
    file can mix scopes: labelling all of ``~/.claude.json`` with one scope makes
    either its user-global or its project servers wrong, and then
    ``--skip-discovery-scopes`` filters the wrong half.

    Servers under a project-path key are project-scoped regardless of where the
    declaring file lives — that nesting is what makes them project config.
    """
    discovered: list[DiscoveredServer] = []
    for origin, servers in _servers_by_origin(mcp_config).items():
        scope = path_scope if origin is None else DiscoveryLocationScope.PROJECT_WORKSPACE
        if scope in skipped:
            continue
        for server_name, server in servers.items():
            if isinstance(server, StdioServer):
                server = check_server_signature(server)
            discovered.append(DiscoveredServer(name=server_name, server=server, scope=scope))
    return discovered


def _resolved_key(path: str, home_directory: Path | None) -> str:
    """Absolute, symlink-resolved key for deduplicating two spellings of one file.

    Resolution is guarded the way ``pipelines`` guards its target folders: these
    paths include glob matches over trees another user can write to, and a stale
    mount or a NUL byte would otherwise abort discovery for the whole home. On
    failure the literal expanded spelling is used, which at worst leaves two keys
    where there should be one.
    """
    expanded = expand_path(Path(path), home_directory)
    try:
        return str(expanded.resolve())
    except (OSError, RuntimeError, ValueError):
        return str(expanded)


def _merge_resolved_scope(
    resolved: dict[str, DiscoveryLocationScope],
    key: str,
    scope: DiscoveryLocationScope,
) -> None:
    """Record *scope* for *key*, keeping the higher-precedence label on collision.

    Two declarations can name the same file by different spellings -- an explicit
    path and a glob that matches it, or a ``~``-prefixed and a relative form.
    Re-keying by resolved path collapses them, so without a precedence rule the
    surviving label depends on declaration order: globs are inserted after
    explicit paths, so a plugin glob would silently relabel a user config.
    Mirrors what the discoverers do in ``AgentDiscoverer._merge_mcp_results``.
    """
    existing = resolved.get(key)
    if existing is None or LOCATION_SCOPE_PRECEDENCE[scope] > LOCATION_SCOPE_PRECEDENCE[existing]:
        resolved[key] = scope


def _resolve_glob_with_depth(pattern: str, max_depth: int) -> list[str]:
    """Glob with ``**`` but discard matches deeper than *max_depth* levels below the ``**`` anchor."""
    star_idx = pattern.find("**")
    if star_idx == -1:
        return glob.glob(pattern)
    base = pattern[:star_idx].rstrip("/\\")
    base_depth = len(Path(base).parts)
    results: list[str] = []
    for match in glob.glob(pattern, recursive=True):
        if len(Path(match).parts) - base_depth <= max_depth:
            results.append(match)
    return results


async def get_mcp_config_per_client(
    client: CandidateClient,
    home_dirs: list[tuple[Path, str]],
    create_file_not_found_error: bool = False,
    *,
    scope: DiscoveryScope = DiscoveryScope.ALL,
    skip_discovery_scopes: set[DiscoveryLocationScope] | frozenset[DiscoveryLocationScope] | None = None,
) -> list[ClientToInspect]:
    """
    Looks for Client (Cursor, VSCode, etc.) across all home directories in the machine.
    """
    ctis: list[ClientToInspect] = []

    if any(path.startswith("~") for path in client.client_exists_paths):
        for home_directory, username in home_dirs:
            cti = await get_mcp_config_per_home_directory(
                client,
                home_directory,
                create_file_not_found_error,
                scope=scope,
                skip_discovery_scopes=skip_discovery_scopes,
            )
            if cti is not None:
                cti.username = username
                ctis.append(cti)
    else:
        cti = await get_mcp_config_per_home_directory(
            client,
            None,
            create_file_not_found_error,
            scope=scope,
            skip_discovery_scopes=skip_discovery_scopes,
        )
        if cti is not None:
            ctis.append(cti)
    return ctis


async def get_mcp_config_per_home_directory(
    client: CandidateClient,
    home_directory: Path | None,
    create_file_not_found_error: bool = False,
    *,
    scope: DiscoveryScope = DiscoveryScope.ALL,
    skip_discovery_scopes: set[DiscoveryLocationScope] | frozenset[DiscoveryLocationScope] | None = None,
) -> ClientToInspect | None:
    """
    Looks for Client (Cursor, VSCode, etc.) config files.
    If found, returns a ClientToInspect object with the MCP config paths and skills dir paths.
    If not found, returns None.

    ``scope`` gates the two halves the same way ``AgentDiscoverer.discover`` does, so a
    servers-only request does not pay for the skills glob (and vice versa).

    Client detection always runs, so an installed agent never disappears from a
    scoped report -- it comes back with only its in-scope components. The one
    exception is ``skip_discovery_scopes`` covering every automatic scope, which
    asks for no discovery at all and so withholds presence too.
    """
    scope = DiscoveryScope(scope)
    want_servers = scope in (DiscoveryScope.SERVERS, DiscoveryScope.ALL)
    want_skills = scope in (DiscoveryScope.SKILLS, DiscoveryScope.ALL)
    skipped = frozenset(DiscoveryLocationScope(value) for value in skip_discovery_scopes or ())

    def location_scope(path: str, overrides: dict[str, DiscoveryLocationScope]) -> DiscoveryLocationScope:
        return overrides.get(path, client.default_location_scope)

    def mcp_path_enabled(path: str) -> bool:
        """Whether any scope this file can yield survives the exclusion.

        A file whose format nests several tiers has to be opened even when its
        declared scope is excluded, so the per-entry filter in
        ``_discovered_servers`` can keep the nested scopes that are still wanted.
        """
        possible = {location_scope(path, client.mcp_config_path_scopes)}
        possible |= client.mcp_config_path_nested_scopes.get(path, set())
        return bool(possible - skipped)

    enabled_mcp_paths = [path for path in client.mcp_config_paths if mcp_path_enabled(path)]
    enabled_skill_paths = [
        path for path in client.skills_dir_paths if location_scope(path, client.skills_dir_path_scopes) not in skipped
    ]
    enabled_mcp_globs = [
        pattern
        for pattern in client.mcp_config_globs
        if location_scope(pattern, client.mcp_config_glob_scopes) not in skipped
    ]
    enabled_skill_globs = [
        pattern
        for pattern in client.skills_dir_globs
        if location_scope(pattern, client.skills_dir_glob_scopes) not in skipped
    ]
    # Excluding every automatic scope means "discover nothing", including the
    # fact that an agent is installed and where -- otherwise the session-start
    # event still discloses that. Mirrors ``find_discoverers``, which
    # short-circuits on the same condition. Anything short of that keeps the
    # client so a caller can tell "installed, nothing in scope" from
    # "not installed": the pipeline logs a not-present message otherwise, and
    # derives the scanned username from the surviving clients.
    if skipped >= AUTOMATIC_DISCOVERY_SCOPES:
        return None

    # check if client exists
    client_path: str | None = None
    for path in client.client_exists_paths:
        path_expanded = expand_path(Path(path), home_directory) if home_directory is not None else Path(path)
        try:
            if path_expanded.exists():
                client_path = path_expanded.as_posix()
                break
        except PermissionError:
            logger.warning(f"Permission error for path {path_expanded.as_posix()}")
            continue

    if client_path is None:
        return None

    # parse mcp configs
    mcp_configs: dict[
        str,
        list[DiscoveredServer] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig,
    ] = {}

    all_mcp_config_paths: dict[str, DiscoveryLocationScope] = {}
    if want_servers:
        for path in enabled_mcp_paths:
            _merge_resolved_scope(all_mcp_config_paths, path, location_scope(path, client.mcp_config_path_scopes))
        for glob_pattern in enabled_mcp_globs:
            expanded_glob = str(expand_path(Path(glob_pattern), home_directory))
            glob_scope = location_scope(glob_pattern, client.mcp_config_glob_scopes)
            for match in _resolve_glob_with_depth(expanded_glob, client.max_glob_depth):
                _merge_resolved_scope(all_mcp_config_paths, match, glob_scope)
        resolved_mcp_paths: dict[str, DiscoveryLocationScope] = {}
        for path, path_scope in all_mcp_config_paths.items():
            _merge_resolved_scope(resolved_mcp_paths, _resolved_key(path, home_directory), path_scope)
        all_mcp_config_paths = resolved_mcp_paths

    for mcp_config_path, path_scope in all_mcp_config_paths.items():
        mcp_config_path_expanded = expand_path(Path(mcp_config_path), home_directory)
        if not mcp_config_path_expanded.exists():
            if create_file_not_found_error:
                mcp_configs[mcp_config_path_expanded.as_posix()] = FileNotFoundConfig(
                    message=f"file {mcp_config_path_expanded.as_posix()} does not exist",
                    is_failure=False,
                )
            continue
        try:
            mcp_config = await scan_mcp_config_file(str(mcp_config_path_expanded))
            if isinstance(mcp_config, UnknownMCPConfig):
                mcp_configs[mcp_config_path_expanded.as_posix()] = UnknownConfigFormat(
                    message=f"Unknown MCP config: {mcp_config_path_expanded.as_posix()}",
                    is_failure=False,
                )
                continue

            mcp_configs[mcp_config_path_expanded.as_posix()] = _discovered_servers(mcp_config, path_scope, skipped)
        except Exception as e:
            logger.exception(f"Error parsing MCP config file {mcp_config_path_expanded.as_posix()}: {e}")
            mcp_configs[mcp_config_path_expanded.as_posix()] = CouldNotParseMCPConfig(
                message=f"could not parse file {mcp_config_path_expanded.as_posix()}",
                traceback=traceback.format_exc(),
                is_failure=True,
            )

    # parse skills dirs
    skills_dirs: dict[str, list[DiscoveredSkill] | FileNotFoundConfig] = {}

    all_skills_dir_paths: dict[str, DiscoveryLocationScope] = {}
    if want_skills:
        for path in enabled_skill_paths:
            _merge_resolved_scope(all_skills_dir_paths, path, location_scope(path, client.skills_dir_path_scopes))
        for glob_pattern in enabled_skill_globs:
            expanded_glob = str(expand_path(Path(glob_pattern), home_directory))
            glob_scope = location_scope(glob_pattern, client.skills_dir_glob_scopes)
            for match in _resolve_glob_with_depth(expanded_glob, client.max_glob_depth):
                if Path(match).is_dir():
                    _merge_resolved_scope(all_skills_dir_paths, match, glob_scope)
        resolved_skill_paths: dict[str, DiscoveryLocationScope] = {}
        for path, path_scope in all_skills_dir_paths.items():
            _merge_resolved_scope(resolved_skill_paths, _resolved_key(path, home_directory), path_scope)
        all_skills_dir_paths = resolved_skill_paths

    for skills_dir_path, path_scope in all_skills_dir_paths.items():
        skills_dir_path_expanded = expand_path(Path(skills_dir_path), home_directory)
        if skills_dir_path_expanded.exists():
            skills_dirs[skills_dir_path_expanded.as_posix()] = [
                skill.model_copy(update={"scope": path_scope})
                for skill in inspect_skills_dir(str(skills_dir_path_expanded))
            ]
        elif create_file_not_found_error:
            skills_dirs[skills_dir_path_expanded.as_posix()] = FileNotFoundConfig(
                message=f"Skills dir {skills_dir_path_expanded.as_posix()} does not exist"
            )

    return ClientToInspect(
        name=client.name,
        client_path=client_path,
        mcp_configs=mcp_configs,
        skills_dirs=skills_dirs,
    )


def find_relevant_token(tokens: list[TokenAndClientInfo], name: str) -> TokenAndClientInfo | None:
    """
    Find the relevant token for a given name.
    """
    for token in tokens:
        if token.server_name == name:
            return token
    return None


def _inspect_skill(skill: DiscoveredSkill) -> InspectedSkill:
    files: list[SkillFile] = []
    skill_name = skill.name
    error: ScanError | None = None
    try:
        files = collect_skill_files(skill.path)
    except Exception as collection_error:
        error = ScanError(
            message="could not collect skill files",
            exception=str(collection_error),
            traceback=traceback.format_exc(),
            is_failure=True,
            category="skill_scan_error",
        )
    else:
        try:
            skill_name = resolve_skill_name(skill)
            error = None
        except SkillInspectionError as inspection_error:
            error = ScanError(
                message="could not inspect skill",
                exception=str(inspection_error),
                traceback=traceback.format_exc(),
                is_failure=True,
                category="skill_scan_error",
            )
        except Exception as inspection_error:
            error = ScanError(
                message="could not inspect skill",
                exception=str(inspection_error),
                traceback=traceback.format_exc(),
                is_failure=True,
                category="skill_scan_error",
            )
    return InspectedSkill(
        name=_inspection_component_name(skill_name, "skill", skill.path),
        installation_path=skill.path,
        files=files,
        error=error,
    )


async def _inspect_stdio_server(
    name: str,
    config: StdioServer,
    config_path: str,
    timeout: int,
    tokens: list[TokenAndClientInfo],
    *,
    stream_stderr: bool,
) -> InspectedServer:
    traffic_capture = TrafficCapture()
    try:
        signature, _ = await check_server(
            config,
            timeout,
            traffic_capture,
            find_relevant_token(tokens, name),
            server_name=name,
            config_path=config_path,
            stream_stderr=stream_stderr,
        )
        return InspectedServer(
            name=name,
            config_path=config_path,
            server=config,
            signature=signature,
        )
    except Exception as exception:
        error = ServerStartupError(
            message="could not start server",
            traceback=traceback.format_exc(),
            sub_exception_message=str(exception),
            is_failure=True,
            server_output=traffic_capture.get_traffic_log(),
        )
        return InspectedServer(
            name=name,
            config_path=config_path,
            server=config,
            error=_inspection_error_to_scan_error(error),
        )


async def _inspect_remote_server(
    name: str,
    config: RemoteServer,
    config_path: str,
    timeout: int,
    tokens: list[TokenAndClientInfo],
) -> InspectedServer:
    traffic_capture = TrafficCapture()
    try:
        signature, fixed_config = await check_server(
            config.model_copy(deep=True),
            timeout,
            traffic_capture,
            find_relevant_token(tokens, name),
            server_name=name,
            config_path=config_path,
            stream_stderr=False,
        )
        assert isinstance(fixed_config, RemoteServer), f"Fixed config is not a RemoteServer: {fixed_config}"
        return InspectedServer(
            name=name,
            config_path=config_path,
            server=fixed_config,
            signature=signature,
        )
    except HTTPStatusError as exception:
        config.type = "http" if config.type is None else config.type
        error: ServerHTTPError | ServerStartupError = ServerHTTPError(
            message="server returned HTTP status code",
            traceback=traceback.format_exc(),
            is_failure=True,
            sub_exception_message=str(exception),
            server_output=traffic_capture.get_traffic_log(),
        )
    except Exception as exception:
        config.type = "http" if config.type is None else config.type
        error = ServerStartupError(
            message="could not start server",
            traceback=traceback.format_exc(),
            sub_exception_message=str(exception),
            is_failure=True,
            category="server_startup",
            server_output=traffic_capture.get_traffic_log(),
        )
    return InspectedServer(
        name=name,
        config_path=config_path,
        server=config,
        error=_inspection_error_to_scan_error(error),
    )


async def _inspect_server(
    name: str,
    config: StdioServer | RemoteServer,
    config_path: str,
    timeout: int,
    tokens: list[TokenAndClientInfo],
    *,
    stream_stderr: bool,
    declined: bool,
    do_stdio_handshake: bool,
) -> InspectedServer:
    if declined:
        error = UserDeclinedError(
            message="Skipped by user consent (stdio server was not started)",
            is_failure=True,
        )
        return InspectedServer(
            name=name,
            config_path=config_path,
            server=config,
            error=_inspection_error_to_scan_error(error),
        )
    if not do_stdio_handshake and isinstance(config, StdioServer):
        return InspectedServer(name=name, config_path=config_path, server=config)
    if isinstance(config, StdioServer):
        return await _inspect_stdio_server(
            name,
            config,
            config_path,
            timeout,
            tokens,
            stream_stderr=stream_stderr,
        )
    return await _inspect_remote_server(name, config, config_path, timeout, tokens)


async def _inspect_server_configs(
    client: ClientToInspect,
    timeout: int,
    tokens: list[TokenAndClientInfo],
    *,
    stream_stderr: bool,
    declined_servers: set[tuple[str, str]],
    do_stdio_handshake: bool,
) -> tuple[list[InspectedServer], list[ScanError]]:
    servers: list[InspectedServer] = []
    candidate_errors: list[ScanError] = []
    for config_path, servers_or_error in client.mcp_configs.items():
        if isinstance(servers_or_error, FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig):
            candidate_errors.append(_config_error_to_scan_error(servers_or_error))
            continue
        for discovered_server in servers_or_error:
            name = discovered_server.name
            config = discovered_server.server
            inspected_server = await _inspect_server(
                name,
                config,
                config_path,
                timeout,
                tokens,
                stream_stderr=stream_stderr,
                declined=(config_path, name) in declined_servers,
                do_stdio_handshake=do_stdio_handshake,
            )
            inspected_server.name = _inspection_component_name(name, "server", config_path)
            servers.append(inspected_server)
    return servers, candidate_errors


def _inspect_skill_configs(client: ClientToInspect) -> tuple[list[InspectedSkill], list[ScanError]]:
    skills: list[InspectedSkill] = []
    candidate_errors: list[ScanError] = []
    for skills_or_error in client.skills_dirs.values():
        if isinstance(skills_or_error, FileNotFoundConfig):
            candidate_errors.append(_config_error_to_scan_error(skills_or_error))
            continue
        skills.extend(_inspect_skill(skill) for skill in skills_or_error)
    return skills, candidate_errors


async def inspect_client(
    client: ClientToInspect,
    timeout: int,
    tokens: list[TokenAndClientInfo],
    scan_skills: bool,
    *,
    stream_stderr: bool = False,
    declined_servers: set[tuple[str, str]] | None = None,
    do_stdio_handshake: bool = False,
) -> InspectedPath:
    """Inspect one client and return its normalized inspection result."""
    servers, candidate_errors = await _inspect_server_configs(
        client,
        timeout,
        tokens,
        stream_stderr=stream_stderr,
        declined_servers=declined_servers or set(),
        do_stdio_handshake=do_stdio_handshake,
    )

    if scan_skills:
        skills, skill_errors = _inspect_skill_configs(client)
        candidate_errors.extend(skill_errors)
    else:
        skills = []

    return InspectedPath(
        client=client.name,
        path=client.client_path,
        servers=servers,
        skills=skills,
        error=_join_scan_errors(candidate_errors),
    )


def _config_error_to_scan_error(
    error: FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig | SkillScanError,
) -> ScanError:
    """Normalize a config-level inspection error for either result model."""
    return ScanError(
        message=error.message,
        exception=error.sub_exception_message,
        traceback=error.traceback,
        is_failure=error.is_failure,
        category=error.category,
    )


def _join_scan_errors(errors: list[ScanError]) -> ScanError | None:
    """Combine config-level errors into the single error carried by a path."""
    if not errors:
        return None
    error_category = next((error.category for error in errors if error.category is not None), None)
    return ScanError(
        message="\n".join(error.message or "" for error in errors),
        exception="\n".join(str(error.exception) for error in errors),
        traceback="\n".join(error.traceback or "missing traceback" for error in errors),
        is_failure=any(error.is_failure for error in errors),
        category=error_category,
    )
