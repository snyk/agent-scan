import logging
import traceback
from pathlib import Path

from httpx import HTTPStatusError

from agent_scan.mcp_client import check_server, scan_mcp_config_file
from agent_scan.models import (
    CandidateClient,
    ClientToInspect,
    CouldNotParseMCPConfig,
    FileNotFoundConfig,
    InspectedClient,
    InspectedExtensions,
    RemoteServer,
    ScanError,
    ScanPathResult,
    ServerHTTPError,
    ServerScanResult,
    ServerSignature,
    ServerStartupError,
    SkillScannError,
    SkillServer,
    StdioServer,
    TokenAndClientInfo,
    UnknownConfigFormat,
    UnknownMCPConfig,
)
from agent_scan.signed_binary import check_server_signature
from agent_scan.skill_client import inspect_skill, inspect_skills_dir
from agent_scan.traffic_capture import TrafficCapture
from agent_scan.well_known_clients import expand_path, get_readable_home_directories

logger = logging.getLogger(__name__)


async def get_mcp_config_per_client(client: CandidateClient, all_users: bool = False) -> list[ClientToInspect]:
    """
    Looks for Client (Cursor, VSCode, etc.) across all home directories in the machine.
    """
    ctis: list[ClientToInspect] = []

    if any(path.startswith("~") for path in client.client_exists_paths):
        for home_directory in get_readable_home_directories(all_users):
            cti = await get_mcp_config_per_home_directory(client, home_directory)
            if cti is not None:
                ctis.append(cti)
    else:
        cti = await get_mcp_config_per_home_directory(client, None)
        if cti is not None:
            ctis.append(cti)
    return ctis


async def get_mcp_config_per_home_directory(
    client: CandidateClient, home_directory: Path | None
) -> ClientToInspect | None:
    """
    Looks for Client (Cursor, VSCode, etc.) config files.
    If found, returns a ClientToInspect object with the MCP config paths and skills dir paths.
    If not found, returns None.
    """

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
    for mcp_config_path in client.mcp_config_paths:
        mcp_config_path_expanded = expand_path(Path(mcp_config_path), home_directory)
        if not mcp_config_path_expanded.exists():
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
    skills_dirs: dict[str, list[tuple[str, SkillServer]] | FileNotFoundConfig] = {}
    for skills_dir_path in client.skills_dir_paths:
        skills_dir_path_expanded = expand_path(Path(skills_dir_path), home_directory)
        if skills_dir_path_expanded.exists():
            skills_dirs[skills_dir_path_expanded.as_posix()] = inspect_skills_dir(str(skills_dir_path_expanded))
        else:
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


async def inspect_extension(
    name: str,
    config: StdioServer | RemoteServer | SkillServer,
    timeout: int,
    token: TokenAndClientInfo | None = None,
) -> InspectedExtensions:
    """
    Scan an extension (MCP server or skill) and return a InspectedExtensions object.
    """
    traffic_capture = TrafficCapture()
    if isinstance(config, StdioServer):
        try:
            signature, _ = await check_server(config, timeout, traffic_capture, token)
            return InspectedExtensions(name=name, config=config, signature_or_error=signature)
        except Exception as e:
            return InspectedExtensions(
                name=name,
                config=config,
                signature_or_error=ServerStartupError(
                    message="could not start server",
                    traceback=traceback.format_exc(),
                    sub_exception_message=str(e),
                    is_failure=True,
                    server_output=traffic_capture.get_traffic_log(),
                ),
            )

    if isinstance(config, RemoteServer):
        try:
            signature, fixed_config = await check_server(config.model_copy(deep=True), timeout, traffic_capture, token)
            assert isinstance(fixed_config, RemoteServer), f"Fixed config is not a RemoteServer: {fixed_config}"
            return InspectedExtensions(name=name, config=fixed_config, signature_or_error=signature)
        except HTTPStatusError as e:
            config.type = "http" if config.type is None else config.type
            return InspectedExtensions(
                name=name,
                config=config,
                signature_or_error=ServerHTTPError(
                    message="server returned HTTP status code",
                    traceback=traceback.format_exc(),
                    is_failure=True,
                    sub_exception_message=str(e),
                    server_output=traffic_capture.get_traffic_log(),
                ),
            )
        except Exception as e:
            config.type = "http" if config.type is None else config.type
            return InspectedExtensions(
                name=name,
                config=config,
                signature_or_error=ServerStartupError(
                    message="could not start server",
                    traceback=traceback.format_exc(),
                    sub_exception_message=str(e),
                    is_failure=True,
                    category="server_startup",
                    server_output=traffic_capture.get_traffic_log() if traffic_capture else None,
                ),
            )

    elif isinstance(config, SkillServer):
        try:
            signature = inspect_skill(config)
            return InspectedExtensions(name=name, config=config, signature_or_error=signature)
        except Exception as e:
            return InspectedExtensions(
                name=name,
                config=config,
                signature_or_error=SkillScannError(
                    message="could not inspect skill",
                    traceback=traceback.format_exc(),
                    is_failure=True,
                    category="skill_scan_error",
                    sub_exception_message=str(e),
                ),
            )


async def inspect_client(
    client: ClientToInspect,
    timeout: int,
    tokens: list[TokenAndClientInfo],
    scan_skills: bool,
) -> InspectedClient:
    """
    Scan a client (Cursor, VSCode, etc.) and return a InspectedClient object.
    """
    extensions: dict[
        str,
        list[InspectedExtensions] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig | SkillScannError,
    ] = {}
    for mcp_config_path, mcp_configs in client.mcp_configs.items():
        if isinstance(mcp_configs, FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig):
            extensions[mcp_config_path] = mcp_configs
            continue
        extensions_for_mcp_config: list[InspectedExtensions] = []
        for name, server in mcp_configs:
            extension = await inspect_extension(name, server, timeout, find_relevant_token(tokens, name))
            extensions_for_mcp_config.append(extension)
        extensions[mcp_config_path] = extensions_for_mcp_config

    if scan_skills:
        for skills_dir_path, skills_dirs in client.skills_dirs.items():
            if isinstance(skills_dirs, FileNotFoundConfig):
                extensions[skills_dir_path] = skills_dirs
                continue
            extensions_for_skills_dir: list[InspectedExtensions] = []
            for name, skill in skills_dirs:
                extension = await inspect_extension(name, skill, timeout)
                extensions_for_skills_dir.append(extension)
            extensions[skills_dir_path] = extensions_for_skills_dir
    return InspectedClient(name=client.name, client_path=client.client_path, extensions=extensions)


def inspected_client_to_scan_path_result(inspected_client: InspectedClient) -> ScanPathResult:
    """
    Convert a InspectedClient object to a ScanPathResult object.
    """
    servers: list[ServerScanResult] = []
    candidate_errors: list[ScanError] = []
    for _, extensions_or_error in inspected_client.extensions.items():
        if isinstance(
            extensions_or_error, FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig | SkillScannError
        ):
            candidate_errors.append(
                ScanError(
                    message=extensions_or_error.message,
                    exception=extensions_or_error.sub_exception_message,
                    traceback=extensions_or_error.traceback,
                    is_failure=extensions_or_error.is_failure,
                    category=extensions_or_error.category,
                )
            )
            continue
        for extension in extensions_or_error:
            if isinstance(extension.signature_or_error, ServerSignature):
                servers.append(
                    ServerScanResult(
                        name=extension.name, server=extension.config, signature=extension.signature_or_error, error=None
                    )
                )
            else:
                servers.append(
                    ServerScanResult(
                        name=extension.name,
                        server=extension.config,
                        signature=None,
                        error=ScanError(
                            message=extension.signature_or_error.message,
                            exception=extension.signature_or_error.sub_exception_message,
                            traceback=extension.signature_or_error.traceback,
                            is_failure=extension.signature_or_error.is_failure,
                            category=extension.signature_or_error.category,
                            server_output=extension.signature_or_error.server_output
                            if isinstance(extension.signature_or_error, ServerStartupError | ServerHTTPError)
                            else None,
                        ),
                    )
                )
    joined_error: None | ScanError = None
    if len(candidate_errors) > 0 and len(servers) == 0:
        joined_error = ScanError(
            message="\n".join([error.message or "" for error in candidate_errors]),
            exception="\n".join([str(error.exception) for error in candidate_errors]),
            traceback="\n".join([error.traceback or "missing traceback" for error in candidate_errors]),
            is_failure=True,
        )
    return ScanPathResult(
        client=inspected_client.name,
        path=inspected_client.client_path,
        servers=servers,
        issues=[],
        labels=[],
        error=joined_error,
    )
