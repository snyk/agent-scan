import json
import os
import subprocess
from unittest.mock import patch

import pytest

from agent_scan.models import CandidateClient, ScanError, ScanPathResult, ServerScanResult, SkillServer
from agent_scan.pipelines import InspectArgs, inspect_pipeline
from agent_scan.signed_binary import check_server_signature
from agent_scan.skill_client import inspect_skill, inspect_skills_dir

TEST_CANDIDATE_CLIENTS = [
    CandidateClient(
        name="test-client",
        client_exists_paths=["tests/mcp_servers/.test-client"],
        mcp_config_paths=["tests/mcp_servers/.test-client/mcp.json"],
        skills_dir_paths=["tests/mcp_servers/.test-client/skills"],
    ),
    CandidateClient(
        name="test-client-invalid",
        client_exists_paths=["tests/mcp_servers/.test-client-invalid"],
        mcp_config_paths=["tests/mcp_servers/.test-client-invalid/mcp.json"],
        skills_dir_paths=["tests/mcp_servers/.test-client-invalid/skills"],
    ),
]


def compare_scan_server(
    ssr_0: ServerScanResult,
    ssr_1: ServerScanResult,
    traceback_flexible: bool = False,
):
    if ssr_0.name != ssr_1.name:
        raise ValueError(f"Name mismatch: {ssr_0.name} != {ssr_1.name}")
    if ssr_0.server != ssr_1.server:
        raise ValueError(f"Server mismatch: {ssr_0.server} != {ssr_1.server}")
    if ssr_0.signature != ssr_1.signature:
        raise ValueError(f"Signature mismatch: {ssr_0.signature} != {ssr_1.signature}")
    compare_scan_errors(ssr_0.error, ssr_1.error, traceback_flexible)


def compare_scan_errors(
    se_0: ScanError | None,
    se_1: ScanError | None,
    traceback_flexible: bool = False,
):
    if se_0 is None and se_1 is None:
        return
    if se_0 is None or se_1 is None:
        raise ValueError(f"One of the errors is None: {se_0} != {se_1}")
    if se_0.message != se_1.message:
        raise ValueError(f"Message mismatch: {se_0.message} != {se_1.message}")
    if se_0.exception != se_1.exception:
        raise ValueError(f"Exception mismatch: {se_0.exception} != {se_1.exception}")
    if se_0.is_failure != se_1.is_failure:
        raise ValueError(f"Is failure mismatch: {se_0.is_failure} != {se_1.is_failure}")
    if se_0.category != se_1.category:
        raise ValueError(f"Category mismatch: {se_0.category} != {se_1.category}")
    if se_0.server_output != se_1.server_output:
        raise ValueError(f"Server output mismatch: {se_0.server_output} != {se_1.server_output}")
    if not traceback_flexible and se_0.traceback != se_1.traceback:
        raise ValueError(f"Traceback mismatch: {se_0.traceback} != {se_1.traceback}")
    else:
        if se_0.traceback is None and se_1.traceback is None:
            return
        if se_0.traceback is None or se_1.traceback is None:
            raise ValueError(f"One of the tracebacks is None: {se_0.traceback} != {se_1.traceback}")
        count_common_suffix = 0
        for i in range(min(len(se_0.traceback), len(se_1.traceback))):
            if se_0.traceback[-i] == se_1.traceback[-i]:
                count_common_suffix += 1
            else:
                break
        if count_common_suffix < 100:
            raise ValueError(
                f"Traceback mismatch: {se_0.traceback} != {se_1.traceback}. More than 100 characters of the traceback are different."
            )


def compare_scan_path_results(
    spr_0: ScanPathResult,
    spr_1: ScanPathResult,
    ignore_client: bool = False,
    ignore_path: bool = False,
    ignore_skills: bool = False,
    ignore_issues: bool = False,
    ignore_labels: bool = False,
    traceback_flexible: bool = False,
):
    if not ignore_client and spr_0.client != spr_1.client:
        raise ValueError(f"Client mismatch: {spr_0.client} != {spr_1.client}")

    if not ignore_path and spr_0.path != spr_1.path:
        raise ValueError(f"Path mismatch: {spr_0.path} != {spr_1.path}")

    servers_0 = [
        server for server in spr_0.servers or [] if not ignore_skills or not isinstance(server.server, SkillServer)
    ]
    servers_1 = [
        server for server in spr_1.servers or [] if not ignore_skills or not isinstance(server.server, SkillServer)
    ]
    if len(servers_0) != len(servers_1):
        raise ValueError(f"Number of servers mismatch: {len(servers_0)} != {len(servers_1)}")
    for server_0, server_1 in zip(servers_0, servers_1, strict=True):
        compare_scan_server(server_0, server_1, traceback_flexible=traceback_flexible)

    if not ignore_issues and spr_0.issues != spr_1.issues:
        raise ValueError(f"Issues mismatch: {spr_0.issues} != {spr_1.issues}")
    if not ignore_labels and spr_0.labels != spr_1.labels:
        raise ValueError(f"Labels mismatch: {spr_0.labels} != {spr_1.labels}")


@pytest.mark.asyncio
@patch("agent_scan.pipelines.get_well_known_clients", return_value=TEST_CANDIDATE_CLIENTS)
async def test_inspect_clients(mock_get_well_known_clients):
    result_test_client_stdout = subprocess.run(
        ["uv", "run", "-m", "src.agent_scan.run", "inspect", "--json", "tests/mcp_servers/.test-client/mcp.json"],
        capture_output=True,
        text=True,
    )
    result_test_client_dict = json.loads(result_test_client_stdout.stdout)
    result_test_client = ScanPathResult.model_validate(
        result_test_client_dict["tests/mcp_servers/.test-client/mcp.json"], by_alias=False, by_name=True
    )
    for server in result_test_client.servers or []:
        if server.server.type == "stdio":
            server.server = check_server_signature(server.server)
    result_test_client_invalid_stdout = subprocess.run(
        [
            "uv",
            "run",
            "-m",
            "src.agent_scan.run",
            "inspect",
            "--json",
            "tests/mcp_servers/.test-client-invalid/mcp.json",
        ],
        capture_output=True,
        text=True,
    )
    result_test_client_invalid_dict = json.loads(result_test_client_invalid_stdout.stdout)
    result_test_client_invalid = ScanPathResult.model_validate(
        result_test_client_invalid_dict["tests/mcp_servers/.test-client-invalid/mcp.json"], by_alias=False, by_name=True
    )
    for server in result_test_client_invalid.servers or []:
        if server.server.type == "stdio":
            server.server = check_server_signature(server.server)

    spr_0, spr_1 = await inspect_pipeline(
        inspect_args=InspectArgs(
            timeout=10,
            tokens=[],
            paths=[],
        ),
    )

    assert spr_0.client == "test-client"
    assert spr_1.client == "test-client-invalid"
    result_test_client.client = "test-client"
    result_test_client_invalid.client = "test-client-invalid"

    assert result_test_client.path == spr_0.path + "/mcp.json"
    assert result_test_client_invalid.path == spr_1.path + "/mcp.json"

    compare_scan_path_results(
        result_test_client,
        spr_0,
        ignore_client=True,
        ignore_skills=True,
        ignore_path=True,
        traceback_flexible=True,
    )
    compare_scan_path_results(
        result_test_client_invalid,
        spr_1,
        ignore_client=True,
        ignore_skills=True,
        ignore_path=True,
        traceback_flexible=True,
    )


def test_inspect_skills_dir():
    skills_dir = os.path.join("tests", "skills")
    skills_servers = inspect_skills_dir(skills_dir)
    sub_dirs = [sub_dir for sub_dir in os.listdir(skills_dir) if os.path.isdir(os.path.join(skills_dir, sub_dir))]
    assert len(sub_dirs) == len(skills_servers)
    for (path, skill_server), sub_dir in zip(skills_servers, sub_dirs, strict=True):
        assert path == sub_dir
        assert isinstance(skill_server, SkillServer)
        assert skill_server.path in [os.path.join(skills_dir, sub_dir) for sub_dir in sub_dirs]


@pytest.mark.parametrize("path, skill_server", inspect_skills_dir(os.path.join("tests", "skills")))
def test_inspect_skill(path: str, skill_server: SkillServer):
    inspect_skill(skill_server)
