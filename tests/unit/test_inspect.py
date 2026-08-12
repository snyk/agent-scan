import getpass
import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import HTTPStatusError, Request, Response

from agent_scan.inspect import (
    get_mcp_config_per_client,
    inspect_client,
    inspect_client_legacy,
    inspect_extension_legacy,
    inspected_client_to_scan_path_result,
)
from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import (
    CandidateClient,
    ClientToInspect,
    CouldNotParseMCPConfig,
    InspectedSkill,
    RemoteServer,
    ServerHTTPError,
    ServerStartupError,
    SkillServer,
    StdioServer,
)
from agent_scan.pipelines import InspectArgs, inspect_pipeline_legacy
from tests.unit._secret_fixtures import synthetic_secret

TEST_CANDIDATE_CLIENT = CandidateClient(
    name="test-client",
    client_exists_paths=["tests/mcp_servers/.test-client"],
    mcp_config_paths=["tests/mcp_servers/.test-client/mcp.json"],
    skills_dir_paths=["tests/mcp_servers/.test-client/skills"],
)


@pytest.mark.asyncio
async def test_inspect_client_rejects_symlink_before_reading_skill(tmp_path):
    """A symlinked skill file must be rejected by collection, not opened by the
    legacy signature reader first."""
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    outside_file = tmp_path / "outside.md"
    outside_file.write_bytes(b"\xff\xfe")
    (skill_dir / "SKILL.md").symlink_to(outside_file)
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={},
        skills_dirs={str(skill_dir.parent): [("skill", SkillServer(path=str(skill_dir)))]},
    )

    result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert len(result.skills) == 1
    assert result.skills[0].files == []
    assert result.skills[0].error is not None
    assert result.skills[0].error.exception == "Skill directory must not contain symbolic links"


@pytest.mark.asyncio
async def test_inspect_client_records_stdio_server_without_handshake():
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={
            "/proj/.mcp.json": [("sqlite", StdioServer(command="sqlite-mcp"))],
        },
        skills_dirs={},
    )

    result = await inspect_client(
        client,
        timeout=1,
        tokens=[],
        scan_skills=False,
        do_stdio_handshake=False,
    )

    assert len(result.servers) == 1
    assert result.servers[0].name == "sqlite"
    assert result.servers[0].config_path == "/proj/.mcp.json"
    assert result.servers[0].signature is None
    assert result.servers[0].error is None


@pytest.mark.asyncio
async def test_inspect_extension_legacy_preserves_direct_http_status_error_category():
    request = Request("POST", "https://example.test/mcp")
    status_error = HTTPStatusError(
        "server error",
        request=request,
        response=Response(500, request=request),
    )

    with patch("agent_scan.inspect.check_server", new_callable=AsyncMock, side_effect=status_error):
        result = await inspect_extension_legacy(
            "remote",
            RemoteServer(url="https://example.test/mcp", type="http"),
            timeout=1,
        )

    assert isinstance(result.signature_or_error, ServerHTTPError)
    assert result.signature_or_error.category == "server_http_error"


@pytest.mark.asyncio
async def test_inspect_client_inspects_server_without_legacy_extension():
    from mcp.types import Implementation, InitializeResult

    from agent_scan.models import ServerSignature

    remote = RemoteServer(url="https://example.test/mcp", type="http")
    signature = ServerSignature(
        metadata=InitializeResult(
            protocolVersion="2024-11-05",
            capabilities={},
            serverInfo=Implementation(name="server", version="1"),
        )
    )
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={"/proj/.mcp.json": [("remote", remote)]},
        skills_dirs={},
    )

    with (
        patch("agent_scan.inspect.inspect_extension_legacy", side_effect=AssertionError("legacy path used")),
        patch("agent_scan.inspect.check_server", new_callable=AsyncMock, return_value=(signature, remote)),
    ):
        result = await inspect_client(client, timeout=1, tokens=[], scan_skills=False)

    assert len(result.servers) == 1
    assert result.servers[0].signature == signature
    assert result.servers[0].error is None


@pytest.mark.asyncio
async def test_inspect_client_converts_server_error_without_legacy_union():
    request = Request("POST", "https://example.test/mcp")
    status_error = HTTPStatusError(
        "server error",
        request=request,
        response=Response(500, request=request),
    )
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={"/proj/.mcp.json": [("remote", RemoteServer(url="https://example.test/mcp", type="http"))]},
        skills_dirs={},
    )

    with patch("agent_scan.inspect.check_server", new_callable=AsyncMock, side_effect=status_error):
        result = await inspect_client(client, timeout=1, tokens=[], scan_skills=False)

    assert len(result.servers) == 1
    assert result.servers[0].signature is None
    assert result.servers[0].error is not None
    assert result.servers[0].error.category == "server_http_error"


@pytest.fixture
def home_dirs_with_agent():
    """Create temp home dirs where only some have an agent (client) installed."""
    tmp = tempfile.mkdtemp()
    alice_home = Path(tmp) / "alice"
    bob_home = Path(tmp) / "bob"
    charlie_home = Path(tmp) / "charlie"

    # Alice has the client installed
    (alice_home / ".fake-client").mkdir(parents=True)
    (alice_home / ".fake-client" / "mcp.json").write_text('{"mcpServers": {}}')

    # Bob has the client installed
    (bob_home / ".fake-client").mkdir(parents=True)
    (bob_home / ".fake-client" / "mcp.json").write_text('{"mcpServers": {}}')

    # Charlie does NOT have the client installed
    charlie_home.mkdir(parents=True)

    candidate = CandidateClient(
        name="fake-client",
        client_exists_paths=["~/.fake-client"],
        mcp_config_paths=["~/.fake-client/mcp.json"],
        skills_dir_paths=[],
    )

    home_dirs = [
        (alice_home, "alice"),
        (bob_home, "bob"),
        (charlie_home, "charlie"),
    ]

    yield candidate, home_dirs

    shutil.rmtree(tmp)


# --- get_mcp_config_per_client tests ---


@pytest.mark.asyncio
async def test_get_mcp_config_per_client_sets_username_for_detected_agents(home_dirs_with_agent):
    """Only home dirs where the agent is detected should produce a ClientToInspect with the username set."""
    candidate, home_dirs = home_dirs_with_agent

    ctis = await get_mcp_config_per_client(candidate, home_dirs)

    assert len(ctis) == 2
    usernames = {cti.username for cti in ctis}
    assert usernames == {"alice", "bob"}


@pytest.mark.asyncio
async def test_get_mcp_config_per_client_no_username_for_absolute_paths():
    """Clients with absolute (non-~) paths should have username=None."""
    ctis = await get_mcp_config_per_client(TEST_CANDIDATE_CLIENT, [])

    assert len(ctis) == 1
    assert ctis[0].username is None


# --- get_mcp_config_per_client filtering tests ---


@pytest.mark.asyncio
async def test_detected_usernames_filtering(home_dirs_with_agent):
    """Only usernames with a detected agent should be in the scanned list; fall back to all if none detected."""
    candidate, home_dirs = home_dirs_with_agent

    ctis = await get_mcp_config_per_client(candidate, home_dirs)
    all_usernames = [username for _, username in home_dirs]

    detected_usernames = list({cti.username for cti in ctis if cti is not None and cti.username is not None})
    scanned_usernames = detected_usernames if detected_usernames else all_usernames

    assert "charlie" not in scanned_usernames
    assert set(scanned_usernames) == {"alice", "bob"}


@pytest.mark.asyncio
async def test_detected_usernames_falls_back_to_all_when_none_detected():
    """When no agents are detected, scanned_usernames should include all usernames."""
    tmp = tempfile.mkdtemp()
    try:
        home_dirs = [
            (Path(tmp) / "alice", "alice"),
            (Path(tmp) / "bob", "bob"),
        ]
        for home, _ in home_dirs:
            home.mkdir(parents=True, exist_ok=True)

        candidate = CandidateClient(
            name="nonexistent-client",
            client_exists_paths=["~/.nonexistent-client"],
            mcp_config_paths=[],
            skills_dir_paths=[],
        )

        ctis = await get_mcp_config_per_client(candidate, home_dirs)
        all_usernames = [username for _, username in home_dirs]

        detected_usernames = list({cti.username for cti in ctis if cti is not None and cti.username is not None})
        scanned_usernames = detected_usernames if detected_usernames else all_usernames

        assert len(ctis) == 0
        assert set(scanned_usernames) == {"alice", "bob"}
    finally:
        shutil.rmtree(tmp)


# --- inspect_pipeline_legacy username-reporting tests ---


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_reports_only_detected_usernames(home_dirs_with_agent):
    """inspect_pipeline_legacy should only include usernames where an agent was actually found."""
    candidate, home_dirs = home_dirs_with_agent

    with (
        patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
        patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
        patch("agent_scan.pipelines.inspect_client_legacy", new_callable=AsyncMock) as mock_inspect,
        patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
    ):
        mock_inspect.return_value = None
        mock_to_result.return_value = None

        args = InspectArgs(timeout=10, tokens=[], paths=[])
        _, scanned_usernames = await inspect_pipeline_legacy(args)

    assert sorted(scanned_usernames) == ["alice", "bob"]
    assert "charlie" not in scanned_usernames


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_falls_back_to_all_usernames_when_no_agents_detected():
    """When no agents are detected and all_users is set, the legacy pipeline should report all usernames."""
    tmp = tempfile.mkdtemp()
    try:
        home_dirs = [
            (Path(tmp) / "alice", "alice"),
            (Path(tmp) / "bob", "bob"),
        ]
        for home, _ in home_dirs:
            home.mkdir(parents=True, exist_ok=True)

        candidate = CandidateClient(
            name="nonexistent-client",
            client_exists_paths=["~/.nonexistent-client"],
            mcp_config_paths=[],
            skills_dir_paths=[],
        )

        with (
            patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
            patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
        ):
            args = InspectArgs(timeout=10, tokens=[], paths=[], all_users=True)
            _, scanned_usernames = await inspect_pipeline_legacy(args)

        assert sorted(scanned_usernames) == ["alice", "bob"]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_detected_usernames_are_sorted():
    """Detected usernames should be returned in sorted order for deterministic output."""
    tmp = tempfile.mkdtemp()
    try:
        # Create home dirs in reverse-alpha order
        usernames = ["charlie", "bob", "alice"]
        home_dirs = []
        for name in usernames:
            home = Path(tmp) / name
            (home / ".fake-client").mkdir(parents=True)
            (home / ".fake-client" / "mcp.json").write_text('{"mcpServers": {}}')
            home_dirs.append((home, name))

        candidate = CandidateClient(
            name="fake-client",
            client_exists_paths=["~/.fake-client"],
            mcp_config_paths=["~/.fake-client/mcp.json"],
            skills_dir_paths=[],
        )

        with (
            patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
            patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
            patch("agent_scan.pipelines.inspect_client_legacy", new_callable=AsyncMock) as mock_inspect,
            patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
        ):
            mock_inspect.return_value = None
            mock_to_result.return_value = None

            args = InspectArgs(timeout=10, tokens=[], paths=[])
            _, scanned_usernames = await inspect_pipeline_legacy(args)

        assert scanned_usernames == ["alice", "bob", "charlie"]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_single_user_detected_among_many():
    """When only one user out of many has an agent, only that username should be reported."""
    tmp = tempfile.mkdtemp()
    try:
        home_dirs = []
        for name in ["alice", "bob", "charlie"]:
            home = Path(tmp) / name
            home.mkdir(parents=True)
            home_dirs.append((home, name))

        # Only bob has the client
        (Path(tmp) / "bob" / ".fake-client").mkdir(parents=True)
        (Path(tmp) / "bob" / ".fake-client" / "mcp.json").write_text('{"mcpServers": {}}')

        candidate = CandidateClient(
            name="fake-client",
            client_exists_paths=["~/.fake-client"],
            mcp_config_paths=["~/.fake-client/mcp.json"],
            skills_dir_paths=[],
        )

        with (
            patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
            patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
            patch("agent_scan.pipelines.inspect_client_legacy", new_callable=AsyncMock) as mock_inspect,
            patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
        ):
            mock_inspect.return_value = None
            mock_to_result.return_value = None

            args = InspectArgs(timeout=10, tokens=[], paths=[])
            _, scanned_usernames = await inspect_pipeline_legacy(args)

        assert scanned_usernames == ["bob"]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_deduplicates_usernames_across_clients():
    """When multiple clients detect the same user, the username should appear only once."""
    tmp = tempfile.mkdtemp()
    try:
        alice_home = Path(tmp) / "alice"
        # Alice has two different clients installed
        (alice_home / ".client-a").mkdir(parents=True)
        (alice_home / ".client-a" / "mcp.json").write_text('{"mcpServers": {}}')
        (alice_home / ".client-b").mkdir(parents=True)
        (alice_home / ".client-b" / "mcp.json").write_text('{"mcpServers": {}}')

        home_dirs = [(alice_home, "alice")]

        candidates = [
            CandidateClient(
                name="client-a",
                client_exists_paths=["~/.client-a"],
                mcp_config_paths=["~/.client-a/mcp.json"],
                skills_dir_paths=[],
            ),
            CandidateClient(
                name="client-b",
                client_exists_paths=["~/.client-b"],
                mcp_config_paths=["~/.client-b/mcp.json"],
                skills_dir_paths=[],
            ),
        ]

        with (
            patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
            patch("agent_scan.pipelines.get_well_known_clients", return_value=candidates),
            patch("agent_scan.pipelines.inspect_client_legacy", new_callable=AsyncMock) as mock_inspect,
            patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
        ):
            mock_inspect.return_value = None
            mock_to_result.return_value = None

            args = InspectArgs(timeout=10, tokens=[], paths=[])
            _, scanned_usernames = await inspect_pipeline_legacy(args)

        assert scanned_usernames == ["alice"]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_no_clients_returns_empty_results():
    """When no MCP clients are installed, the legacy pipeline should return no scan path results."""
    tmp = tempfile.mkdtemp()
    try:
        home_dirs = [(Path(tmp) / "alice", "alice")]
        (Path(tmp) / "alice").mkdir()

        candidate = CandidateClient(
            name="nonexistent-client",
            client_exists_paths=["~/.nonexistent-client"],
            mcp_config_paths=[],
            skills_dir_paths=[],
        )

        with (
            patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
            patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
        ):
            args = InspectArgs(timeout=10, tokens=[], paths=[])
            results, _ = await inspect_pipeline_legacy(args)

        assert results == []
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_missing_explicit_path_returns_file_not_found_error():
    """An explicit missing path should produce a legacy file-not-found error result."""
    with (
        patch("agent_scan.pipelines.get_readable_home_directories", return_value=[]),
        patch("agent_scan.pipelines.client_to_inspect_from_path", new_callable=AsyncMock, return_value=[]),
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=["/nonexistent/path.json"])
        results, _ = await inspect_pipeline_legacy(args)

    assert len(results) == 1
    assert results[0].path == "/nonexistent/path.json"
    assert results[0].error is not None
    assert results[0].error.category == "file_not_found"


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_paths_mode_does_not_leak_all_usernames():
    """When using --paths, scanned_usernames should not fall back to all readable usernames."""
    tmp = tempfile.mkdtemp()
    try:
        home_dirs = [
            (Path(tmp) / "alice", "alice"),
            (Path(tmp) / "bob", "bob"),
        ]
        for home, _ in home_dirs:
            home.mkdir(parents=True, exist_ok=True)

        with (
            patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
            patch(
                "agent_scan.pipelines.client_to_inspect_from_path",
                new_callable=AsyncMock,
                return_value=[ClientToInspect(name="test", client_path="/some/path", mcp_configs={}, skills_dirs={})],
            ),
            patch("agent_scan.pipelines.inspect_client_legacy", new_callable=AsyncMock) as mock_inspect,
            patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
        ):
            mock_inspect.return_value = None
            mock_to_result.return_value = None

            args = InspectArgs(timeout=10, tokens=[], paths=["/some/path/mcp.json"])
            _, scanned_usernames = await inspect_pipeline_legacy(args)

        assert scanned_usernames == [getpass.getuser()]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_discovery_mode_falls_back_to_all_usernames_when_no_agents_detected():
    """Without --paths but with --scan-all-users, when no agents are detected, all readable usernames should be reported."""
    tmp = tempfile.mkdtemp()
    try:
        home_dirs = [
            (Path(tmp) / "alice", "alice"),
            (Path(tmp) / "bob", "bob"),
        ]
        for home, _ in home_dirs:
            home.mkdir(parents=True, exist_ok=True)

        candidate = CandidateClient(
            name="nonexistent-client",
            client_exists_paths=["~/.nonexistent-client"],
            mcp_config_paths=[],
            skills_dir_paths=[],
        )

        with (
            patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
            patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
        ):
            args = InspectArgs(timeout=10, tokens=[], paths=[], all_users=True)
            _, scanned_usernames = await inspect_pipeline_legacy(args)

        assert sorted(scanned_usernames) == ["alice", "bob"]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_glob_discovers_plugin_mcp_configs():
    """mcp_config_globs should discover .mcp.json files inside a plugin cache tree."""
    tmp = tempfile.mkdtemp()
    try:
        home = Path(tmp) / "user"
        # Simulate client exists
        (home / ".fake-client").mkdir(parents=True)

        # Create plugin cache with .mcp.json
        plugin_dir = home / ".fake-client" / "plugins" / "cache" / "marketplace" / "my-plugin" / "v1"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / ".mcp.json").write_text('{"my-server": {"command": "node", "args": ["server.js"]}}')

        # Create plugin cache with skills
        skills_plugin_dir = home / ".fake-client" / "plugins" / "cache" / "marketplace" / "skill-plugin" / "v1"
        skills_dir = skills_plugin_dir / "skills" / "my-skill"
        skills_dir.mkdir(parents=True)
        (skills_dir / "SKILL.md").write_text("# My Skill\nA test skill.")

        candidate = CandidateClient(
            name="fake-client",
            client_exists_paths=["~/.fake-client"],
            mcp_config_paths=[],
            skills_dir_paths=[],
            mcp_config_globs=["~/.fake-client/plugins/cache/**/.mcp.json"],
            skills_dir_globs=["~/.fake-client/plugins/cache/**/skills"],
        )

        ctis = await get_mcp_config_per_client(candidate, [(home, "user")])
        assert len(ctis) == 1
        cti = ctis[0]

        mcp_paths = [p for p, v in cti.mcp_configs.items() if isinstance(v, list)]
        assert len(mcp_paths) == 1
        servers = cti.mcp_configs[mcp_paths[0]]
        assert isinstance(servers, list)
        assert len(servers) == 1
        assert servers[0][0] == "my-server"

        skills_paths = [p for p, v in cti.skills_dirs.items() if isinstance(v, list)]
        assert len(skills_paths) == 1
        skills = cti.skills_dirs[skills_paths[0]]
        assert isinstance(skills, list)
        assert len(skills) == 1
        assert skills[0][0] == "my-skill"
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_glob_no_matches_still_works():
    """When mcp_config_globs match nothing, the client should still be discovered with empty configs."""
    tmp = tempfile.mkdtemp()
    try:
        home = Path(tmp) / "user"
        (home / ".fake-client").mkdir(parents=True)

        candidate = CandidateClient(
            name="fake-client",
            client_exists_paths=["~/.fake-client"],
            mcp_config_paths=[],
            skills_dir_paths=[],
            mcp_config_globs=["~/.fake-client/plugins/cache/**/.mcp.json"],
        )

        ctis = await get_mcp_config_per_client(candidate, [(home, "user")])
        assert len(ctis) == 1
        assert len(ctis[0].mcp_configs) == 0
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_glob_deduplicates_with_explicit_paths():
    """When a glob matches a path already in mcp_config_paths, scan_mcp_config_file should only be called once."""
    tmp = tempfile.mkdtemp()
    try:
        home = Path(tmp) / "user"
        (home / ".fake-client").mkdir(parents=True)

        plugin_dir = home / ".fake-client" / "plugins" / "cache" / "mp" / "my-plugin" / "v1"
        plugin_dir.mkdir(parents=True)
        mcp_json = plugin_dir / ".mcp.json"
        mcp_json.write_text('{"srv": {"command": "node", "args": ["s.js"]}}')

        candidate = CandidateClient(
            name="fake-client",
            client_exists_paths=["~/.fake-client"],
            mcp_config_paths=[str(mcp_json)],
            skills_dir_paths=[],
            mcp_config_globs=["~/.fake-client/plugins/cache/**/.mcp.json"],
        )

        with patch("agent_scan.inspect.scan_mcp_config_file", wraps=scan_mcp_config_file) as spy:
            ctis = await get_mcp_config_per_client(candidate, [(home, "user")])

        assert len(ctis) == 1
        assert spy.call_count == 1, f"scan_mcp_config_file called {spy.call_count} times, expected 1"
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_glob_respects_max_depth():
    """Matches beyond max_glob_depth should be excluded."""
    tmp = tempfile.mkdtemp()
    try:
        home = Path(tmp) / "user"
        (home / ".fake-client").mkdir(parents=True)

        cache = home / ".fake-client" / "plugins" / "cache"

        # Shallow plugin (depth 3 below cache/): should be found
        shallow = cache / "marketplace" / "shallow-plugin" / "v1"
        shallow.mkdir(parents=True)
        (shallow / ".mcp.json").write_text('{"shallow-srv": {"command": "node", "args": ["s.js"]}}')

        # Deep plugin (depth 7 below cache/): should be excluded
        deep = cache / "a" / "b" / "c" / "d" / "e" / "f" / "deep-plugin"
        deep.mkdir(parents=True)
        (deep / ".mcp.json").write_text('{"deep-srv": {"command": "node", "args": ["d.js"]}}')

        candidate = CandidateClient(
            name="fake-client",
            client_exists_paths=["~/.fake-client"],
            mcp_config_paths=[],
            skills_dir_paths=[],
            mcp_config_globs=["~/.fake-client/plugins/cache/**/.mcp.json"],
            max_glob_depth=6,
        )

        ctis = await get_mcp_config_per_client(candidate, [(home, "user")])
        assert len(ctis) == 1

        all_server_names = []
        for v in ctis[0].mcp_configs.values():
            if isinstance(v, list):
                all_server_names.extend(name for name, _ in v)

        assert "shallow-srv" in all_server_names
        assert "deep-srv" not in all_server_names
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_legacy_discovery_mode_without_all_users_falls_back_to_current_user():
    """Without --paths and without --scan-all-users, when no agents are detected, only the current user should be reported."""
    tmp = tempfile.mkdtemp()
    try:
        home_dirs = [
            (Path(tmp) / "alice", "alice"),
            (Path(tmp) / "bob", "bob"),
        ]
        for home, _ in home_dirs:
            home.mkdir(parents=True, exist_ok=True)

        candidate = CandidateClient(
            name="nonexistent-client",
            client_exists_paths=["~/.nonexistent-client"],
            mcp_config_paths=[],
            skills_dir_paths=[],
        )

        with (
            patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
            patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
        ):
            args = InspectArgs(timeout=10, tokens=[], paths=[], all_users=False)
            _, scanned_usernames = await inspect_pipeline_legacy(args)

        assert scanned_usernames == [getpass.getuser()]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_client_legacy_default_does_not_handshake_stdio_servers():
    """The default behavior (no ``do_stdio_handshake`` kwarg) must NOT start
    any stdio subprocess. This is the load-bearing safe-default property:
    spawning subprocesses from a user config is the dangerous action, so
    every caller must explicitly opt in.

    A caller that forgets to forward ``do_stdio_handshake=True`` falls
    through to this safe path: every stdio server is recorded on the
    InspectedExtension list with no signature and no error, and
    ``inspect_extension_legacy`` is only invoked for remote MCP servers (skills
    do not flow through this code path). The test installs a side_effect
    that raises if ``inspect_extension_legacy`` is ever called for a stdio
    server — so any future refactor that flips the default fails loudly
    here.

    The downstream ``ServerScanResult`` exposes the skipped stdio server
    with both ``signature`` and ``error`` set to ``None`` — the configured
    entry is preserved without manufacturing an issue (the skip is the
    documented behavior of this path, not a failure to report).
    """
    stdio_a = StdioServer(command="echo", args=["a"])
    stdio_b = StdioServer(command="python", args=["-c", "print(1)"])
    remote = RemoteServer(url="https://example.com/mcp", type="http")

    client = ClientToInspect(
        name="test",
        client_path="/some/path",
        mcp_configs={
            "/cfg.json": [
                ("stdio-a", stdio_a),
                ("stdio-b", stdio_b),
                ("remote", remote),
            ]
        },
        skills_dirs={},
    )

    with patch("agent_scan.inspect.inspect_extension_legacy", new_callable=AsyncMock) as mock_inspect_extension:

        async def fake_inspect(name, server, *args, **kwargs):
            from mcp.types import Implementation, InitializeResult

            from agent_scan.models import InspectedExtension, ServerSignature

            if isinstance(server, StdioServer):
                raise AssertionError(
                    f"inspect_extension_legacy must not be called for stdio server {name!r} on the default path"
                )
            return InspectedExtension(
                name=name,
                config=server,
                signature_or_error=ServerSignature(
                    metadata=InitializeResult(
                        protocolVersion="2024-11-05",
                        capabilities={},
                        serverInfo=Implementation(name="x", version="1"),
                    ),
                ),
            )

        mock_inspect_extension.side_effect = fake_inspect

        # Intentionally omit ``do_stdio_handshake`` to verify the safe
        # default kicks in.
        result = await inspect_client_legacy(client, timeout=10, tokens=[], scan_skills=False)

    extensions = result.extensions["/cfg.json"]
    assert len(extensions) == 3

    for name in ("stdio-a", "stdio-b"):
        ext = next(e for e in extensions if e.name == name)
        assert ext.signature_or_error is None

    # Remote server still gets a handshake.
    remote_call_names = [call.args[0] for call in mock_inspect_extension.call_args_list]
    assert remote_call_names == ["remote"]

    # ServerScanResult conversion preserves the server with no signature
    # and no error for the default-skipped stdio entries.
    scan_path_result = inspected_client_to_scan_path_result(result)
    by_name = {s.name: s for s in scan_path_result.servers or []}
    assert by_name["stdio-a"].signature is None
    assert by_name["stdio-a"].error is None
    assert by_name["stdio-b"].signature is None
    assert by_name["stdio-b"].error is None
    # The remote server still carries a signature.
    assert by_name["remote"].signature is not None
    assert by_name["remote"].error is None


@pytest.mark.asyncio
async def test_inspect_client_legacy_explicit_do_stdio_handshake_runs_stdio_servers():
    """When the caller explicitly opts in via ``do_stdio_handshake=True``,
    stdio servers flow through ``inspect_extension_legacy`` as expected. This
    is the path taken by every command that wants real stdio handshakes
    (interactive ``scan`` / ``inspect``, or ``--ci --dangerously-run-mcp-servers``
    overriding the push-key skip)."""
    stdio = StdioServer(command="echo", args=["hi"])

    client = ClientToInspect(
        name="test",
        client_path="/some/path",
        mcp_configs={"/cfg.json": [("stdio", stdio)]},
        skills_dirs={},
    )

    with patch("agent_scan.inspect.inspect_extension_legacy", new_callable=AsyncMock) as mock_inspect_extension:
        from mcp.types import Implementation, InitializeResult

        from agent_scan.models import InspectedExtension, ServerSignature

        mock_inspect_extension.return_value = InspectedExtension(
            name="stdio",
            config=stdio,
            signature_or_error=ServerSignature(
                metadata=InitializeResult(
                    protocolVersion="2024-11-05",
                    capabilities={},
                    serverInfo=Implementation(name="x", version="1"),
                ),
            ),
        )

        await inspect_client_legacy(client, timeout=10, tokens=[], scan_skills=False, do_stdio_handshake=True)

    mock_inspect_extension.assert_awaited_once()


# --- config_path propagation tests ---


def _signature() -> "object":
    from mcp.types import Implementation, InitializeResult

    from agent_scan.models import ServerSignature

    return ServerSignature(
        metadata=InitializeResult(
            protocolVersion="2024-11-05",
            capabilities={},
            serverInfo=Implementation(name="x", version="1"),
        ),
    )


def test_inspected_client_to_scan_path_result_sets_config_path_per_server():
    """Every ServerScanResult must carry the config-file path it was
    discovered in. The config path is the key of ``InspectedClient.extensions``;
    the converter must propagate it onto each server across all three branches
    (inspected signature, recorded-but-not-inspected ``None``, and error)."""
    from agent_scan.models import InspectedClient, InspectedExtension

    cfg_path = "/home/u/.config/agent/.mcp.json"
    ok = InspectedExtension(name="ok", config=StdioServer(command="echo"), signature_or_error=_signature())
    not_inspected = InspectedExtension(name="skip", config=StdioServer(command="echo"))
    errored = InspectedExtension(
        name="boom",
        config=RemoteServer(url="https://example.com/mcp", type="http"),
        signature_or_error=ServerStartupError(message="boom", sub_exception_message="details"),
    )

    client = InspectedClient(
        name="test",
        client_path="/install/path",
        extensions={cfg_path: [ok, not_inspected, errored]},
    )

    result = inspected_client_to_scan_path_result(client)

    by_name = {s.name: s for s in result.servers or []}
    assert by_name["ok"].config_path == cfg_path
    assert by_name["skip"].config_path == cfg_path
    assert by_name["boom"].config_path == cfg_path
    assert by_name["boom"].error is not None
    assert by_name["boom"].error.category == "server_startup"
    # The top-level ScanPathResult.path stays the client install path, not the config file.
    assert result.path == "/install/path"


def test_inspected_client_to_scan_path_result_config_path_multiple_files():
    """A single client flattens multiple config files into one ScanPathResult;
    each server must retain the config path of the file it came from."""
    from agent_scan.models import InspectedClient, InspectedExtension

    cfg_a = "/home/u/.cursor/mcp.json"
    cfg_b = "/home/u/project/.mcp.json"
    ext_a = InspectedExtension(name="srv-a", config=StdioServer(command="a"), signature_or_error=_signature())
    ext_b = InspectedExtension(name="srv-b", config=StdioServer(command="b"), signature_or_error=_signature())

    client = InspectedClient(
        name="test",
        client_path="/install/path",
        extensions={cfg_a: [ext_a], cfg_b: [ext_b]},
    )

    result = inspected_client_to_scan_path_result(client)

    by_name = {s.name: s for s in result.servers or []}
    assert by_name["srv-a"].config_path == cfg_a
    assert by_name["srv-b"].config_path == cfg_b


def test_server_scan_result_clone_preserves_config_path():
    """clone() must propagate config_path so the analysis-payload copy
    (built via ScanPathResult.clone()/ServerScanResult.clone()) carries it too."""
    from agent_scan.models import ServerScanResult

    original = ServerScanResult(
        name="srv",
        config_path="/home/u/.mcp.json",
        server=StdioServer(command="echo"),
    )
    cloned = original.clone()
    assert cloned.config_path == "/home/u/.mcp.json"


def test_config_path_survives_serialization_round_trip():
    """config_path must serialize into the upload payload and round-trip back."""
    from agent_scan.models import (
        ScanPathResult,
        ScanPathResultsCreate,
        ScanUserInfo,
        ServerScanResult,
    )

    payload = ScanPathResultsCreate(
        scan_path_results=[
            ScanPathResult(
                client="test",
                path="/install/path",
                servers=[
                    ServerScanResult(
                        name="srv",
                        config_path="/home/u/.mcp.json",
                        server=StdioServer(command="echo"),
                    )
                ],
            )
        ],
        scan_user_info=ScanUserInfo(),
    )

    restored = ScanPathResultsCreate.model_validate_json(payload.model_dump_json())
    assert restored.scan_path_results[0].servers[0].config_path == "/home/u/.mcp.json"


@pytest.mark.asyncio
async def test_inspect_client_collects_skills_and_joins_config_errors(tmp_path):
    skill_dir = tmp_path / "my-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: my-skill\ndescription: test\n---\ndo things")
    (skill_dir / "run.py").write_text("print('hi')")
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={
            "/proj/bad.json": CouldNotParseMCPConfig(message="bad config", traceback="tb"),
        },
        skills_dirs={"/proj/skills": [("my-skill", SkillServer(path=str(skill_dir)))]},
    )

    result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert result.client == "cursor"
    assert result.path == "/proj"
    assert [s.name for s in result.skills] == ["my-skill"]
    skill = result.skills[0]
    assert isinstance(skill, InspectedSkill)
    assert skill.installation_path == str(skill_dir)
    assert {f.path for f in skill.files} == {"SKILL.md", "run.py"}
    assert skill.error is None

    assert result.error is not None and "bad config" in (result.error.message or "")


@pytest.mark.asyncio
async def test_inspect_client_carries_skill_file_collection_error(tmp_path):
    skill_path = tmp_path / "missing-skill"
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={},
        skills_dirs={"/proj/skills": [("missing-skill", SkillServer(path=str(skill_path)))]},
    )

    result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert len(result.skills) == 1
    skill = result.skills[0]
    assert skill.files == []
    assert skill.error is not None
    assert skill.error.category == "skill_scan_error"
    assert "collect skill files" in (skill.error.message or "")
    assert str(skill_path) not in (skill.error.message or "")


@pytest.mark.asyncio
async def test_inspect_client_reports_manifest_validation_as_inspection_error(tmp_path):
    skill_path = tmp_path / "malformed-skill"
    skill_path.mkdir()
    (skill_path / "SKILL.md").write_text("---\nname: malformed\n---\nmissing description")
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={},
        skills_dirs={"/proj/skills": [("malformed", SkillServer(path=str(skill_path)))]},
    )

    result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert result.skills[0].error is not None
    assert result.skills[0].error.message == "could not inspect skill"
    assert "Missing description" in (result.skills[0].error.exception or "")


@pytest.mark.asyncio
@pytest.mark.parametrize("frontmatter", ["", "a scalar", "- a list item"])
async def test_inspect_client_rejects_non_mapping_manifest_frontmatter(tmp_path, frontmatter):
    skill_path = tmp_path / "malformed-skill"
    skill_path.mkdir()
    (skill_path / "SKILL.md").write_text(f"---\n{frontmatter}\n---\nbody")
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={},
        skills_dirs={"/proj/skills": [("malformed", SkillServer(path=str(skill_path)))]},
    )

    result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert result.skills[0].error is not None
    assert result.skills[0].error.message == "could not inspect skill"
    assert "YAML frontmatter must be a mapping" in (result.skills[0].error.exception or "")


@pytest.mark.asyncio
async def test_inspect_client_validates_manifest_before_redaction(tmp_path):
    secret = synthetic_secret()
    skill_path = tmp_path / "secret-skill"
    skill_path.mkdir()
    (skill_path / "SKILL.md").write_text(f"---\nname: secret-skill\ndescription: {secret}\n---\ndo things")
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={},
        skills_dirs={"/proj/skills": [("secret-skill", SkillServer(path=str(skill_path)))]},
    )

    result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert result.skills[0].error is None
    assert secret not in result.skills[0].files[0].content
    assert "**REDACTED_SECRET_" in result.skills[0].files[0].content


@pytest.mark.asyncio
async def test_inspect_client_recovers_from_unexpected_collection_error(tmp_path):
    skill_path = tmp_path / "skill"
    skill_path.mkdir()
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={},
        skills_dirs={"/proj/skills": [("skill", SkillServer(path=str(skill_path)))]},
    )

    with patch("agent_scan.inspect.collect_skill_files", side_effect=RuntimeError("unexpected")):
        result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert result.skills[0].files == []
    assert result.skills[0].error is not None
    assert result.skills[0].error.category == "skill_scan_error"
    assert result.skills[0].error.exception == "unexpected"
    assert result.skills[0].error.traceback is not None
    assert "RuntimeError: unexpected" in result.skills[0].error.traceback
