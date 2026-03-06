import logging
import os

from pydantic import BaseModel

from agent_scan.inspect import (
    get_mcp_config_per_client,
    inspect_client,
    inspected_client_to_scan_path_result,
)
from agent_scan.models import (
    AnalyzedMachine,
    CandidateClient,
    ClientNotFoundError,
    ClientToInspect,
    ControlServer,
    InspectedClient,
    InspectedMachine,
    ScanPathResult,
    SkillServer,
    TokenAndClientInfo,
)
from agent_scan.redact import redact_scan_result
from agent_scan.upload import upload
from agent_scan.utils import get_push_key
from agent_scan.verify_api import analyze_machine
from agent_scan.well_known_clients import get_well_known_clients

logger = logging.getLogger(__name__)


class InspectArgs(BaseModel):
    timeout: int
    tokens: list[TokenAndClientInfo]
    paths: list[str]
    inspect_skills: bool = False


class AnalyzeArgs(BaseModel):
    analysis_url: str
    identifier: str | None = None
    additional_headers: dict | None = None
    opt_out_of_identity: bool = False
    max_retries: int = 3
    skip_ssl_verify: bool = False


class PushArgs(BaseModel):
    control_servers: list[ControlServer]
    skip_ssl_verify: bool = False
    version: str | None = None


async def inspect_pipeline(
    inspect_args: InspectArgs,
) -> InspectedMachine:
    # fetch clients to inspect
    if inspect_args.paths:
        clients_to_inspect = [await client_to_inspect_from_path(path, True) for path in inspect_args.paths]
    else:
        clients_to_inspect = [await get_mcp_config_per_client(client) for client in get_well_known_clients()]

    # inspect
    inspected_clients: list[InspectedClient | ClientNotFoundError] = []
    for i, client_to_inspect in enumerate(clients_to_inspect):
        if client_to_inspect is None and inspect_args.paths:
            inspected_clients.append(
                ClientNotFoundError(
                    message=f"Client {inspect_args.paths[i]} not found.",
                )
            )
        elif client_to_inspect is None:
            logger.info(
                f"Client {get_well_known_clients()[i].name} does not exist os this machine. {get_well_known_clients()[i].client_exists_paths}"
            )
            continue
        else:
            inspected_client = await inspect_client(
                client_to_inspect, inspect_args.timeout, inspect_args.tokens, inspect_skills=inspect_args.inspect_skills
            )
            inspected_clients.append(inspected_client)
    return InspectedMachine(
        clients=inspected_clients,
    )


async def analyze_pipeline(
    inspected_machine: InspectedMachine,
    analyze_args: AnalyzeArgs,
    push_args: PushArgs,
    verbose: bool = False,
) -> AnalyzedMachine:
    scan_path_results = [inspected_client_to_scan_path_result(rv) for rv in inspected_machine.clients]
    redacted_scan_path_results = [redact_scan_result(rv) for rv in scan_path_results]

    scan_context = {"cli_version": push_args.version}
    verified_scan_path_results = await analyze_machine(
        redacted_scan_path_results,
        analysis_url=analyze_args.analysis_url,
        identifier=analyze_args.identifier,
        additional_headers=analyze_args.additional_headers,
        opt_out_of_identity=analyze_args.opt_out_of_identity,
        verbose=verbose,
        skip_pushing=bool(push_args.control_servers),
        push_key=get_push_key(push_args.control_servers),
        max_retries=analyze_args.max_retries,
        skip_ssl_verify=analyze_args.skip_ssl_verify,
        scan_context=scan_context,
    )
    AnalyzedMachine(
        clients=verified_scan_path_results,
    )


async def inspect_analyze_push_pipeline(
    inspect_args: InspectArgs,
    analyze_args: AnalyzeArgs,
    push_args: PushArgs,
    verbose: bool = False,
) -> list[ScanPathResult]:
    """
    Pipeline the scan and analyze the machine.
    """
    # inspect
    scan_path_results = await inspect_pipeline(inspect_args)

    # redact
    redacted_scan_path_results = [inspected_client_to_scan_path_result(rv) for rv in scan_path_results]

    scan_context = {"cli_version": push_args.version}
    # analyze
    verified_scan_path_results = await analyze_machine(
        redacted_scan_path_results,
        analysis_url=analyze_args.analysis_url,
        identifier=analyze_args.identifier,
        additional_headers=analyze_args.additional_headers,
        opt_out_of_identity=analyze_args.opt_out_of_identity,
        verbose=verbose,
        skip_pushing=bool(push_args.control_servers),
        push_key=get_push_key(push_args.control_servers),
        max_retries=analyze_args.max_retries,
        skip_ssl_verify=analyze_args.skip_ssl_verify,
        scan_context=scan_context,
    )
    # push
    for control_server in push_args.control_servers:
        await upload(
            verified_scan_path_results,
            control_server.url,
            control_server.identifier,
            control_server.opt_out,
            verbose=verbose,
            additional_headers=control_server.headers,
            skip_ssl_verify=push_args.skip_ssl_verify,
            scan_context=scan_context,
        )

    return verified_scan_path_results


async def client_to_inspect_from_path(path: str, use_path_as_client_name: bool = False) -> ClientToInspect | None:
    if os.path.isdir(os.path.expanduser(path)):
        if os.path.exists(os.path.join(path, "SKILL.md")):
            # split last segment from all other dirs in the path (account for trailing slash)
            last_dir = os.path.basename(os.path.normpath(path))

            path_without_last_dir = os.path.dirname(path)
            return ClientToInspect(
                name="not-available" if use_path_as_client_name else path,
                client_path=path_without_last_dir,
                mcp_configs={},
                skills_dirs={
                    path_without_last_dir: [(last_dir, SkillServer(path=path))],
                },
            )
        else:
            candidate_client = CandidateClient(
                name="not-available" if use_path_as_client_name else path,
                client_exists_paths=[path],
                mcp_config_paths=[],
                skills_dir_paths=[path],
            )
            return await get_mcp_config_per_client(candidate_client)
    elif os.path.basename(os.path.normpath(path)).lower() == "skill.md":
        skill_directory = os.path.basename(os.path.dirname(os.path.normpath(path)))
        parent_of_skill_directory = os.path.dirname(os.path.dirname(os.path.normpath(path)))

        return ClientToInspect(
            name="not-available" if use_path_as_client_name else path,
            client_path=parent_of_skill_directory,
            mcp_configs={},
            skills_dirs={
                parent_of_skill_directory: [(skill_directory, SkillServer(path=os.path.dirname(path)))],
            },
        )
    else:
        candidate_client = CandidateClient(
            name="not-available" if use_path_as_client_name else path,
            client_exists_paths=[path],
            mcp_config_paths=[path],
            skills_dir_paths=[],
        )
        return await get_mcp_config_per_client(candidate_client)
