import getpass
import logging
import os
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from agent_scan.agents import DiscoveryScope, find_discoverers
from agent_scan.direct_scanner import direct_scan_to_server_config, is_direct_scan
from agent_scan.inspect import (
    get_mcp_config_per_client,
    inspect_client,
)
from agent_scan.models import (
    CandidateClient,
    ClientToInspect,
    ControlServer,
    DiscoveredSkill,
    InspectedPath,
    RemoteServer,
    ScanError,
    ScanResponse,
    StdioServer,
    TokenAndClientInfo,
)
from agent_scan.redact import redact_inspected_path
from agent_scan.utils import get_readable_home_directories
from agent_scan.verify_api import analyze_machine
from agent_scan.well_known_clients import get_well_known_clients

logger = logging.getLogger(__name__)


class InspectArgs(BaseModel):
    timeout: int
    tokens: list[TokenAndClientInfo]
    paths: list[str]
    all_users: bool = False
    scan_skills: bool = False
    discovery_scope: DiscoveryScope = DiscoveryScope.ALL
    target_folders: list[str] = Field(default_factory=list)
    probe_transports: bool = True


class AnalyzeArgs(BaseModel):
    analysis_url: str
    identifier: str | None = None
    additional_headers: dict | None = None
    max_retries: int = 3
    skip_ssl_verify: bool = False
    show_analysis_results: bool = False


class PushArgs(BaseModel):
    control_servers: list[ControlServer]
    # Already resolved by the caller (e.g. cli.py's _effective_push_key,
    # which also enforces evo's mint-your-own-key rule). This pipeline does
    # not derive it from control_servers headers itself.
    push_key: str | None = None
    skip_ssl_verify: bool = False
    version: str | None = None


async def discover_clients_to_inspect(
    inspect_args: InspectArgs,
) -> tuple[list[ClientToInspect], list[InspectedPath], list[str]]:
    """
    Discover the clients/configs that would be inspected, without actually
    starting any MCP servers.
    """
    home_dirs_with_users = get_readable_home_directories(all_users=inspect_args.all_users)
    all_usernames: list[str] = [username for _path, username in home_dirs_with_users]

    unresolved_paths: list[InspectedPath] = []
    clients_to_inspect: list[ClientToInspect] = []
    if inspect_args.paths:
        for path in inspect_args.paths:
            ctis = await client_to_inspect_from_path(path, True, home_dirs_with_users, inspect_args.scan_skills)
            if ctis:
                clients_to_inspect.extend(ctis)
            else:
                normalized_path = path.replace("\\", "/")
                unresolved_paths.append(
                    InspectedPath(
                        path=normalized_path,
                        client=normalized_path,
                        error=ScanError(
                            message="File or folder not found", is_failure=False, category="file_not_found"
                        ),
                    )
                )
    else:
        target_folders: list[Path] = []
        seen_target_folders: set[Path] = set()
        for raw_path in inspect_args.target_folders:
            target_path = Path(raw_path).expanduser()
            try:
                key = target_path.resolve()
            except (OSError, RuntimeError, ValueError):
                # Target folders come from untrusted hook-payload JSON, where a NUL byte
                # raises ValueError; fall back to the literal path so one bad entry cannot
                # abort the whole discovery.
                key = target_path
            if key in seen_target_folders:
                continue
            seen_target_folders.add(key)
            try:
                exists = key.exists()
            except (OSError, RuntimeError, ValueError):
                logger.warning("Skipping inaccessible target folder: %s", target_path)
                continue
            if not exists:
                logger.warning("Skipping non-existent target folder: %s", target_path)
                continue
            target_folders.append(target_path)

        # Phase A — legacy path. Runs for EVERY well-known client including Claude Code.
        for client in get_well_known_clients():
            ctis = await get_mcp_config_per_client(client, home_dirs_with_users, scope=inspect_args.discovery_scope)
            if ctis:
                clients_to_inspect.extend(ctis)
            else:
                logger.info(f"Client {client.name} does not exist on this machine. {client.client_exists_paths}")

        # Phase B — ABC path. Runs sequentially after Phase A and merges into its output.
        for home_directory, username in home_dirs_with_users:
            for discoverer in find_discoverers(home_directory, target_folders=target_folders):
                try:
                    cti = discoverer.discover(inspect_args.discovery_scope)
                except Exception:
                    logger.exception("Discoverer %s.discover() raised; skipping", type(discoverer).__name__)
                    continue
                if cti is None:
                    continue
                cti.username = username
                existing = next(
                    (c for c in clients_to_inspect if c.name == cti.name and c.username == cti.username),
                    None,
                )
                if existing is None:
                    clients_to_inspect.append(cti)
                else:
                    # Dict union: legacy keys first (insertion order), ABC keys appended.
                    # ABC values win on key collision (e.g., both phases emit a server
                    # under ``~/.claude.json``). Distinct keys from each phase coexist
                    # — same-name servers under different keys are kept as separate
                    # registrations (e.g., the same ``github`` server configured in
                    # two projects must both reach the inspector).
                    existing.mcp_configs = {**existing.mcp_configs, **cti.mcp_configs}
                    existing.skills_dirs = {**existing.skills_dirs, **cti.skills_dirs}

    # Only report usernames where an agent was detected in their home directory.
    # When no usernames were associated with detected agents:
    #   - Discovery mode with --scan-all-users: fall back to all readable usernames.
    #   - Otherwise (explicit paths or single-user mode): fall back to the current OS user only,
    #     to avoid disclosing unrelated usernames on the machine.
    detected_usernames: list[str] = sorted({cti.username for cti in clients_to_inspect if cti.username is not None})
    if detected_usernames:
        scanned_usernames = detected_usernames
    elif not inspect_args.paths and inspect_args.all_users:
        scanned_usernames = all_usernames
    else:
        scanned_usernames = [getpass.getuser()]

    return clients_to_inspect, unresolved_paths, scanned_usernames


async def inspect_pipeline(
    inspect_args: InspectArgs,
    *,
    clients_to_inspect: list[ClientToInspect] | None = None,
    unresolved_paths: list[InspectedPath] | None = None,
    scanned_usernames: list[str] | None = None,
    stream_stderr: bool = False,
    declined_servers: set[tuple[str, str]] | None = None,
    do_stdio_handshake: bool = False,
) -> tuple[list[InspectedPath], list[str]]:
    """Inspect each discovered client and return ``InspectedPath`` results.

    This result is shared by both ``inspect`` and the v2026-07-10 ``scan``
    path.
    Unresolved explicit paths (e.g. file-not-found) already have their error
    represented by an otherwise-empty ``InspectedPath`` and are included directly.
    """
    if clients_to_inspect is None:
        clients_to_inspect, unresolved_paths, scanned_usernames = await discover_clients_to_inspect(inspect_args)
    inspected_paths = list(unresolved_paths or [])
    for client_to_inspect in clients_to_inspect:
        inspected_paths.append(
            await inspect_client(
                client_to_inspect,
                inspect_args.timeout,
                inspect_args.tokens,
                inspect_args.scan_skills,
                stream_stderr=stream_stderr,
                declined_servers=declined_servers,
                do_stdio_handshake=do_stdio_handshake,
                probe_transports=inspect_args.probe_transports,
            )
        )
    # redact: applied here so every caller of inspect_pipeline (both `mcp-scan
    # scan` and `mcp-scan inspect`) gets sanitized results, since `inspect`
    # prints/dumps them directly without going through the analyze/push
    # pipeline's API-boundary sanitization.
    inspected_paths = [redact_inspected_path(path) for path in inspected_paths]

    return inspected_paths, scanned_usernames or []


async def inspect_analyze_push_pipeline(
    inspect_args: InspectArgs,
    analyze_args: AnalyzeArgs,
    push_args: PushArgs,
    verbose: bool = False,
    *,
    clients_to_inspect: list[ClientToInspect] | None = None,
    unresolved_paths: list[InspectedPath] | None = None,
    scanned_usernames: list[str] | None = None,
    stream_stderr: bool = False,
    declined_servers: set[tuple[str, str]] | None = None,
    do_stdio_handshake: bool = False,
) -> ScanResponse:
    """
    Pipeline the scan and analyze the machine.
    """
    # inspect
    inspected_paths, scanned_usernames = await inspect_pipeline(
        inspect_args,
        clients_to_inspect=clients_to_inspect,
        unresolved_paths=unresolved_paths,
        scanned_usernames=scanned_usernames,
        stream_stderr=stream_stderr,
        declined_servers=declined_servers,
        do_stdio_handshake=do_stdio_handshake,
    )

    scan_context = {"cli_version": push_args.version}
    # analyze
    response = await analyze_machine(
        inspected_paths,
        analysis_url=analyze_args.analysis_url,
        identifier=analyze_args.identifier,
        additional_headers=analyze_args.additional_headers,
        verbose=verbose,
        skip_pushing=bool(push_args.control_servers) or bool(push_args.push_key),
        push_key=push_args.push_key,
        max_retries=analyze_args.max_retries,
        skip_ssl_verify=analyze_args.skip_ssl_verify,
        scan_context=scan_context,
        scanned_usernames=scanned_usernames,
        show_analysis_results=analyze_args.show_analysis_results,
    )

    return response


def single_remote_client_to_inspect(
    name: str | None,
    url: str,
    server_type: Literal["sse", "http"] | None = None,
) -> ClientToInspect:
    """Build a one-server plan for ``--url``, bypassing discovery entirely.

    Mirrors the direct-scan branch of ``client_to_inspect_from_path`` so the
    rest of the pipeline sees exactly the shape it always sees. The fallback
    chain for the display name matches ``mcp_auth``: explicit name, else the
    URL's hostname, else the raw URL.
    """
    server_name = name or urlparse(url).hostname or url
    return ClientToInspect(
        name="not-available",
        client_path=url,
        mcp_configs={url: [(server_name, RemoteServer(url=url, type=server_type))]},
        skills_dirs={},
    )


def filter_clients_to_server(
    clients: list[ClientToInspect],
    server_name: str,
    server_type: Literal["sse", "http"] | None = None,
) -> list[ClientToInspect]:
    """Narrow a discovered plan down to entries named exactly ``server_name``.

    Clients left holding nothing are dropped. ``skills_dirs`` is emptied
    because a single-server scan never wants skills. When ``server_type`` is
    given it overrides the configured transport on matched remote servers,
    which is what lets ``--server-type`` correct a wrong type in a config.
    """
    filtered: list[ClientToInspect] = []
    for client in clients:
        kept: dict[str, list[tuple[str, StdioServer | RemoteServer]]] = {}
        for config_path, entries in client.mcp_configs.items():
            # Values may be error sentinels rather than lists; skip those.
            if not isinstance(entries, list):
                continue
            matches = [(entry_name, cfg) for entry_name, cfg in entries if entry_name == server_name]
            if not matches:
                continue
            if server_type is not None:
                for _entry_name, cfg in matches:
                    if isinstance(cfg, RemoteServer):
                        cfg.type = server_type
            kept[config_path] = matches
        if kept:
            filtered.append(
                ClientToInspect(
                    name=client.name,
                    client_path=client.client_path,
                    username=client.username,
                    mcp_configs=kept,
                    skills_dirs={},
                )
            )
    return filtered


async def discover_servers_by_name(
    inspect_args: InspectArgs,
    *,
    remote_only: bool = False,
) -> dict[str, StdioServer | RemoteServer]:
    """Map discovered server name -> config, first occurrence winning.

    Extracted from ``mcp_auth`` so that ``scan --server`` and ``mcp-auth``
    agree on what "the server named X" means. ``remote_only`` reproduces
    ``mcp_auth``'s behavior of ignoring stdio servers, which it cannot
    authenticate; ``scan`` passes False because it can target either.
    """
    clients_to_inspect, _, _ = await discover_clients_to_inspect(inspect_args)
    servers: dict[str, StdioServer | RemoteServer] = {}
    for client in clients_to_inspect:
        for _config_path, entries in client.mcp_configs.items():
            if not isinstance(entries, list):
                continue
            for entry_name, server in entries:
                if remote_only and not isinstance(server, RemoteServer):
                    continue
                servers.setdefault(entry_name, server)
    return servers


async def client_to_inspect_from_path(
    path: str,
    use_path_as_client_name: bool = False,
    home_dirs: list[tuple[Path, str]] | None = None,
    scan_skills: bool = False,
) -> list[ClientToInspect]:
    if home_dirs is None:
        home_dirs = [(Path.home(), getpass.getuser())]
    if is_direct_scan(path):
        server_name, server_config = direct_scan_to_server_config(path)
        return [
            ClientToInspect(
                name=path if use_path_as_client_name else "not-available",
                client_path=path,
                mcp_configs={
                    path: [(server_name, server_config)],
                },
                skills_dirs={},
            )
        ]
    elif scan_skills and os.path.isdir(os.path.expanduser(path)):
        if os.path.exists(os.path.join(path, "SKILL.md")):
            # split last segment from all other dirs in the path (account for trailing slash)
            last_dir = os.path.basename(os.path.normpath(path))

            path_without_last_dir = os.path.dirname(path)
            return [
                ClientToInspect(
                    name=path if use_path_as_client_name else "not-available",
                    client_path=path_without_last_dir,
                    mcp_configs={},
                    skills_dirs={
                        path_without_last_dir: [DiscoveredSkill(name=last_dir, path=path)],
                    },
                )
            ]
        else:
            candidate_client = CandidateClient(
                name=path if use_path_as_client_name else "not-available",
                client_exists_paths=[path],
                mcp_config_paths=[],
                skills_dir_paths=[path],
            )
            return await get_mcp_config_per_client(
                candidate_client, home_dirs=home_dirs, create_file_not_found_error=True
            )
    elif scan_skills and os.path.basename(os.path.normpath(path)).lower() == "skill.md":
        skill_directory = os.path.basename(os.path.dirname(os.path.normpath(path)))
        parent_of_skill_directory = os.path.dirname(os.path.dirname(os.path.normpath(path)))

        return [
            ClientToInspect(
                name=path if use_path_as_client_name else "not-available",
                client_path=parent_of_skill_directory,
                mcp_configs={},
                skills_dirs={
                    parent_of_skill_directory: [DiscoveredSkill(name=skill_directory, path=os.path.dirname(path))],
                },
            )
        ]
    else:
        candidate_client = CandidateClient(
            name=path if use_path_as_client_name else "not-available",
            client_exists_paths=[path],
            mcp_config_paths=[path],
            skills_dir_paths=[],
        )
        return await get_mcp_config_per_client(candidate_client, home_dirs=home_dirs, create_file_not_found_error=True)
