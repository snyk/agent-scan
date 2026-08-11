from typing import Literal

import pytest

from agent_scan.inspect import get_mcp_config_per_client, inspect_client
from agent_scan.models import (
    CandidateClient,
    CouldNotParseMCPConfig,
    FileNotFoundConfig,
    RemoteServer,
    SkillServer,
    StdioServer,
    UnknownConfigFormat,
)

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
    CandidateClient(
        name="test-client-does-not-exist",
        client_exists_paths=["tests/mcp_servers/.test-client-invalid"],
        mcp_config_paths=["tests/mcp_servers/.test-client-invalid/mcp.json.does.not.exist"],
        skills_dir_paths=["tests/mcp_servers/.test-client-invalid/skills.does.not.exist"],
    ),
]


@pytest.mark.parametrize("create_file_not_found_error", [True, False])
@pytest.mark.parametrize(
    "client, test_type",
    [
        (TEST_CANDIDATE_CLIENTS[0], "valid"),
        (TEST_CANDIDATE_CLIENTS[1], "invalid"),
        (TEST_CANDIDATE_CLIENTS[2], "does-not-exist"),
    ],
)
@pytest.mark.asyncio
async def test_get_mcp_config_per_client(
    create_file_not_found_error: bool,
    client: CandidateClient,
    test_type: Literal["valid", "invalid", "does-not-exist"],
):
    ctis = await get_mcp_config_per_client(client, [], create_file_not_found_error)
    assert len(ctis) == 1

    assert ctis[0].mcp_configs is not None
    assert ctis[0].skills_dirs is not None
    for _, servers in ctis[0].mcp_configs.items():
        if test_type == "valid":
            assert isinstance(servers, list)
            for _, server in servers:
                assert isinstance(server, StdioServer | RemoteServer)
        elif test_type == "invalid":
            assert isinstance(servers, UnknownConfigFormat | CouldNotParseMCPConfig)
            assert not servers.is_failure
        elif test_type == "does-not-exist":
            if create_file_not_found_error:
                assert isinstance(servers, FileNotFoundConfig)
            else:
                assert isinstance(servers, list)
                assert len(servers) == 0
    for _, skills_dir in ctis[0].skills_dirs.items():
        if test_type in ["valid", "invalid"]:
            assert isinstance(skills_dir, list)
            for _, skill_dir in skills_dir:
                assert isinstance(skill_dir, SkillServer)
        elif test_type == "does-not-exist":
            if create_file_not_found_error:
                assert isinstance(skills_dir, FileNotFoundConfig)
                assert not skills_dir.is_failure
            else:
                assert isinstance(skills_dir, list)
                assert len(skills_dir) == 0


@pytest.mark.parametrize(
    "client, test_type",
    [
        (TEST_CANDIDATE_CLIENTS[0], "valid"),
        (TEST_CANDIDATE_CLIENTS[1], "invalid"),
        (TEST_CANDIDATE_CLIENTS[2], "does-not-exist"),
    ],
)
@pytest.mark.asyncio
async def test_inspect_client(
    client: CandidateClient, test_type: Literal["valid", "invalid", "does-not-exist"]
):
    ctis = await get_mcp_config_per_client(client, [], False)
    # ``do_stdio_handshake=True`` so the test fixtures' stdio servers are
    # actually handshaked (and fail with ``server_startup``, which is
    # what the ``valid`` assertion below expects).
    inspected_path = await inspect_client(ctis[0], 10, [], True, do_stdio_handshake=True)
    if test_type == "invalid":
        assert inspected_path.error is not None
        assert not inspected_path.error.is_failure
    else:
        assert inspected_path.error is None
    errors_by_server = {server.error.category for server in inspected_path.servers if server.error is not None}
    errors_by_server.update(skill.error.category for skill in inspected_path.skills if skill.error is not None)
    print(f"type: {test_type} errors_by_server: {errors_by_server}")
    if test_type == "valid":
        assert errors_by_server == {"server_startup"}
    elif test_type == "does-not-exist":
        assert errors_by_server == set()
    else:
        assert errors_by_server == {"skill_scan_error"}
