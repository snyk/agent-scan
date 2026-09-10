import glob
import logging
import traceback
from pathlib import Path

from httpx import HTTPStatusError

from agent_scan.agents.base import DiscoveryScope
from agent_scan.mcp_client import check_server, scan_mcp_config_file
from agent_scan.models import (
    CandidateClient,
    ClientToInspect,
    CouldNotParseMCPConfig,
    DiscoveredSkill,
    FileNotFoundConfig,
    InspectedPath,
    InspectedServer,
    InspectedSkill,
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
) -> list[ClientToInspect]:
    """
    Looks for Client (Cursor, VSCode, etc.) across all home directories in the machine.
    """
    ctis: list[ClientToInspect] = []

    if any(path.startswith("~") for path in client.client_exists_paths):
        for home_directory, username in home_dirs:
            cti = await get_mcp_config_per_home_directory(
                client, home_directory, create_file_not_found_error, scope=scope
            )
            if cti is not None:
                cti.username = username
                ctis.append(cti)
    else:
        cti = await get_mcp_config_per_home_directory(client, None, create_file_not_found_error, scope=scope)
        if cti is not None:
            ctis.append(cti)
    return ctis


async def get_mcp_config_per_home_directory(
    client: CandidateClient,
    home_directory: Path | None,
    create_file_not_found_error: bool = False,
    *,
    scope: DiscoveryScope = DiscoveryScope.ALL,
) -> ClientToInspect | None:
    """
    Looks for Client (Cursor, VSCode, etc.) config files.
    If found, returns a ClientToInspect object with the MCP config paths and skills dir paths.
    If not found, returns None.

    ``scope`` gates the two halves the same way ``AgentDiscoverer.discover`` does, so a
    servers-only request does not pay for the skills glob (and vice versa). Client
    detection itself always runs, so a client never disappears from a scoped report.
    """
    scope = DiscoveryScope(scope)
    want_servers = scope in (DiscoveryScope.SERVERS, DiscoveryScope.ALL)
    want_skills = scope in (DiscoveryScope.SKILLS, DiscoveryScope.ALL)

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
        list[tuple[str, StdioServer | RemoteServer]]
        | FileNotFoundConfig
        | UnknownConfigFormat
        | CouldNotParseMCPConfig,
    ] = {}

    all_mcp_config_paths: list[str] = []
    if want_servers:
        all_mcp_config_paths = list(client.mcp_config_paths)
        for glob_pattern in client.mcp_config_globs:
            expanded_glob = str(expand_path(Path(glob_pattern), home_directory))
            all_mcp_config_paths.extend(_resolve_glob_with_depth(expanded_glob, client.max_glob_depth))
        all_mcp_config_paths = list(
            dict.fromkeys(str(expand_path(Path(p), home_directory).resolve()) for p in all_mcp_config_paths)
        )

    for mcp_config_path in all_mcp_config_paths:
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

            server_configs_by_name = mcp_config.get_servers()
            for server_config in server_configs_by_name.values():
                if isinstance(server_config, StdioServer):
                    server_config = check_server_signature(server_config)
            mcp_configs[mcp_config_path_expanded.as_posix()] = [
                (server_name, server) for server_name, server in server_configs_by_name.items()
            ]
        except Exception as e:
            logger.exception(f"Error parsing MCP config file {mcp_config_path_expanded.as_posix()}: {e}")
            mcp_configs[mcp_config_path_expanded.as_posix()] = CouldNotParseMCPConfig(
                message=f"could not parse file {mcp_config_path_expanded.as_posix()}",
                traceback=traceback.format_exc(),
                is_failure=True,
            )

    # parse skills dirs
    skills_dirs: dict[str, list[DiscoveredSkill] | FileNotFoundConfig] = {}

    all_skills_dir_paths: list[str] = []
    if want_skills:
        all_skills_dir_paths = list(client.skills_dir_paths)
        for glob_pattern in client.skills_dir_globs:
            expanded_glob = str(expand_path(Path(glob_pattern), home_directory))
            for match in _resolve_glob_with_depth(expanded_glob, client.max_glob_depth):
                if Path(match).is_dir():
                    all_skills_dir_paths.append(match)
        all_skills_dir_paths = list(
            dict.fromkeys(str(expand_path(Path(p), home_directory).resolve()) for p in all_skills_dir_paths)
        )

    for skills_dir_path in all_skills_dir_paths:
        skills_dir_path_expanded = expand_path(Path(skills_dir_path), home_directory)
        if skills_dir_path_expanded.exists():
            skills_dirs[skills_dir_path_expanded.as_posix()] = inspect_skills_dir(str(skills_dir_path_expanded))
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
    *,
    probe_transports: bool = True,
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
            probe_transports=probe_transports,
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
    probe_transports: bool = True,
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
    return await _inspect_remote_server(name, config, config_path, timeout, tokens, probe_transports=probe_transports)


async def _inspect_server_configs(
    client: ClientToInspect,
    timeout: int,
    tokens: list[TokenAndClientInfo],
    *,
    stream_stderr: bool,
    declined_servers: set[tuple[str, str]],
    do_stdio_handshake: bool,
    probe_transports: bool = True,
) -> tuple[list[InspectedServer], list[ScanError]]:
    servers: list[InspectedServer] = []
    candidate_errors: list[ScanError] = []
    for config_path, servers_or_error in client.mcp_configs.items():
        if isinstance(servers_or_error, FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig):
            candidate_errors.append(_config_error_to_scan_error(servers_or_error))
            continue
        for name, config in servers_or_error:
            inspected_server = await _inspect_server(
                name,
                config,
                config_path,
                timeout,
                tokens,
                stream_stderr=stream_stderr,
                declined=(config_path, name) in declined_servers,
                do_stdio_handshake=do_stdio_handshake,
                probe_transports=probe_transports,
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
    probe_transports: bool = True,
) -> InspectedPath:
    """Inspect one client and return its normalized inspection result."""
    servers, candidate_errors = await _inspect_server_configs(
        client,
        timeout,
        tokens,
        stream_stderr=stream_stderr,
        declined_servers=declined_servers or set(),
        do_stdio_handshake=do_stdio_handshake,
        probe_transports=probe_transports,
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
