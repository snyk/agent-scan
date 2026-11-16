import getpass
import logging
import os
from pathlib import Path

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
    ScanError,
    ScanResponse,
    TokenAndClientInfo,
)
from agent_scan.redact import redact_inspected_path
from agent_scan.remote_discovery.builder import build_clients
from agent_scan.remote_discovery.client import run_remote_discovery
from agent_scan.utils import get_readable_home_directories
from agent_scan.verify_api import AgentScanConfig, analyze_machine
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


class AnalyzeArgs(BaseModel):
    analysis_url: str
    identifier: str | None = None
    additional_headers: dict | None = None
    max_retries: int = 3
    skip_ssl_verify: bool = False
    show_analysis_results: bool = False
    agent_scan_config: AgentScanConfig | None = None


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
                _merge_client(clients_to_inspect, cti)

    return clients_to_inspect, unresolved_paths, _scanned_usernames(clients_to_inspect, inspect_args, all_usernames)


def _merge_client(clients_to_inspect: list[ClientToInspect], cti: ClientToInspect) -> None:
    """Add ``cti``, or union it into the entry with the same (name, username)."""
    existing = next(
        (c for c in clients_to_inspect if c.name == cti.name and c.username == cti.username),
        None,
    )
    if existing is None:
        clients_to_inspect.append(cti)
        return
    # Dict union: existing keys first (insertion order), new keys appended.
    # New values win on key collision (e.g., both phases emit a server
    # under ``~/.claude.json``). Distinct keys from each source coexist
    # — same-name servers under different keys are kept as separate
    # registrations (e.g., the same ``github`` server configured in
    # two projects must both reach the inspector).
    existing.mcp_configs = {**existing.mcp_configs, **cti.mcp_configs}
    existing.skills_dirs = {**existing.skills_dirs, **cti.skills_dirs}


def _merge_local_only(
    clients_to_inspect: list[ClientToInspect],
    home_dirs_with_users: list[tuple[Path, str]],
    scope: DiscoveryScope,
) -> None:
    """Merge in what backend discovery can't read yet (see ``discover_local_only``)."""
    for home_directory, username in home_dirs_with_users:
        for discoverer in find_discoverers(home_directory):
            try:
                cti = discoverer.discover_local_only(scope)
            except Exception:
                logger.exception("Discoverer %s.discover_local_only() raised; skipping", type(discoverer).__name__)
                continue
            if cti is None or not (cti.mcp_configs or cti.skills_dirs):
                continue
            cti.username = username
            _merge_client(clients_to_inspect, cti)


def _scanned_usernames(
    clients_to_inspect: list[ClientToInspect], inspect_args: InspectArgs, all_usernames: list[str]
) -> list[str]:
    # Only report usernames where an agent was detected in their home directory.
    # When no usernames were associated with detected agents:
    #   - Discovery mode with --scan-all-users: fall back to all readable usernames.
    #   - Otherwise (explicit paths or single-user mode): fall back to the current OS user only,
    #     to avoid disclosing unrelated usernames on the machine.
    detected_usernames: list[str] = sorted({cti.username for cti in clients_to_inspect if cti.username is not None})
    if detected_usernames:
        return detected_usernames
    if not inspect_args.paths and inspect_args.all_users:
        return all_usernames
    return [getpass.getuser()]


def supports_remote_discovery(inspect_args: InspectArgs) -> bool:
    """Backend discovery only covers whole-machine discovery, not explicit paths or target folders."""
    return not inspect_args.paths and not inspect_args.target_folders


async def discover_clients_remotely(
    inspect_args: InspectArgs,
    discovery_url: str,
    push_key: str,
    cli_version: str | None = None,
    skip_ssl_verify: bool = False,
) -> tuple[list[ClientToInspect], list[InspectedPath], list[str]] | None:
    """``discover_clients_to_inspect`` through the coding-agent-discovery service.

    Returns None if the backend fails, so the caller can run legacy discovery instead.
    """
    try:
        remote = await run_remote_discovery(
            discovery_url,
            scope=inspect_args.discovery_scope.value,
            push_key=push_key,
            cli_version=cli_version,
            all_users=inspect_args.all_users,
            skip_ssl_verify=skip_ssl_verify,
        )
        clients_to_inspect = build_clients(remote.found)
    except Exception as e:
        # Includes malformed responses (KeyError/TypeError), not just transport errors.
        logger.warning("Remote discovery failed (%s: %s); using local discovery.", type(e).__name__, e)
        return None
    logger.info(
        "Remote discovery: %d clients, %d rounds, %d ops, %.2fs, partial=%s",
        len(clients_to_inspect),
        remote.rounds,
        remote.ops,
        remote.duration_s,
        remote.partial,
    )
    home_dirs_with_users = get_readable_home_directories(all_users=inspect_args.all_users)
    _merge_local_only(clients_to_inspect, home_dirs_with_users, inspect_args.discovery_scope)
    all_usernames = [username for _path, username in home_dirs_with_users]
    return clients_to_inspect, [], _scanned_usernames(clients_to_inspect, inspect_args, all_usernames)


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
        agent_scan_config=analyze_args.agent_scan_config,
    )

    return response


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
