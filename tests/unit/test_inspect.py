import getpass
import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import HTTPStatusError, Request, Response
from mcp.shared.auth import OAuthToken
from mcp.types import Implementation, InitializeResult

from agent_scan.agents import DiscoveryScope
from agent_scan.inspect import (
    get_mcp_config_per_client,
    inspect_client,
)
from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import (
    CandidateClient,
    ClientToInspect,
    CouldNotParseMCPConfig,
    DiscoveredSkill,
    DiscoveryLocationScope,
    InspectedPath,
    InspectedServer,
    InspectedSkill,
    RemoteServer,
    ScanError,
    ServerSignature,
    StdioServer,
    TokenAndClientInfo,
)
from agent_scan.pipelines import InspectArgs, inspect_pipeline
from tests.unit._secret_fixtures import synthetic_secret

TEST_CANDIDATE_CLIENT = CandidateClient(
    name="test-client",
    client_exists_paths=["tests/mcp_servers/.test-client"],
    mcp_config_paths=["tests/mcp_servers/.test-client/mcp.json"],
    skills_dir_paths=["tests/mcp_servers/.test-client/skills"],
)


@pytest.mark.asyncio
async def test_inspect_client_follows_symlinked_skill_md(tmp_path):
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir()
    outside_file = tmp_path / "outside.md"
    content = "---\nname: linked-skill\ndescription: linked skill\n---\n# Instructions"
    outside_file.write_text(content)
    (skill_dir / "SKILL.md").symlink_to(outside_file)
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={},
        skills_dirs={str(skill_dir.parent): [DiscoveredSkill(name="skill", path=str(skill_dir))]},
    )

    result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert len(result.skills) == 1
    assert result.skills[0].name == "linked-skill"
    assert [(file.path, file.content) for file in result.skills[0].files] == [("SKILL.md", content)]
    assert result.skills[0].error is None


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
async def test_inspect_client_attributes_empty_component_names_to_their_source():
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={
            "/proj/.mcp.json": [("", StdioServer(command="sqlite-mcp"))],
        },
        skills_dirs={
            "/proj/skills": [DiscoveredSkill(name="", path="/proj/skills/unnamed")],
        },
    )

    with patch("agent_scan.inspect.collect_skill_files", return_value=[]):
        result = await inspect_client(
            client,
            timeout=1,
            tokens=[],
            scan_skills=True,
            do_stdio_handshake=False,
        )

    assert result.servers[0].name == "unnamed server (/proj/.mcp.json)"
    assert result.skills[0].name == "unnamed skill (/proj/skills/unnamed)"


@pytest.mark.asyncio
async def test_inspect_client_uses_original_empty_server_name_for_oauth_token_lookup():
    config = StdioServer(command="sqlite-mcp")
    token = TokenAndClientInfo(
        token=OAuthToken(access_token="test-token", token_type="Bearer"),
        server_name="",
        client_id="client-id",
        token_url="https://example.test/token",
        mcp_server_url="https://example.test/mcp",
        updated_at=0,
    )
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
        mcp_configs={"/proj/.mcp.json": [("", config)]},
        skills_dirs={},
    )

    with patch("agent_scan.inspect.check_server", new_callable=AsyncMock, return_value=(signature, config)) as check:
        result = await inspect_client(
            client,
            timeout=1,
            tokens=[token],
            scan_skills=False,
            do_stdio_handshake=True,
        )

    assert check.await_args.args[3] == token
    assert result.servers[0].name == "unnamed server (/proj/.mcp.json)"


@pytest.mark.asyncio
async def test_inspect_client_returns_server_signature():
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

    with patch("agent_scan.inspect.check_server", new_callable=AsyncMock, return_value=(signature, remote)):
        result = await inspect_client(client, timeout=1, tokens=[], scan_skills=False)

    assert len(result.servers) == 1
    assert result.servers[0].signature == signature
    assert result.servers[0].error is None


@pytest.mark.asyncio
async def test_inspect_client_converts_server_http_error():
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


# --- inspect_pipeline username-reporting tests ---


@pytest.mark.asyncio
async def test_inspect_pipeline_reports_only_detected_usernames(home_dirs_with_agent):
    """inspect_pipeline should only include usernames where an agent was actually found."""
    candidate, home_dirs = home_dirs_with_agent

    with (
        patch("agent_scan.pipelines.get_readable_home_directories", return_value=home_dirs),
        patch("agent_scan.pipelines.get_well_known_clients", return_value=[candidate]),
        patch("agent_scan.pipelines.inspect_client", new_callable=AsyncMock) as mock_inspect,
    ):
        mock_inspect.return_value = InspectedPath(path="/test")

        args = InspectArgs(timeout=10, tokens=[], paths=[])
        _, scanned_usernames = await inspect_pipeline(args)

    assert sorted(scanned_usernames) == ["alice", "bob"]
    assert "charlie" not in scanned_usernames


@pytest.mark.asyncio
async def test_inspect_pipeline_falls_back_to_all_usernames_when_no_agents_detected():
    """When no agents are detected and all_users is set, inspect_pipeline should report all usernames."""
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
            _, scanned_usernames = await inspect_pipeline(args)

        assert sorted(scanned_usernames) == ["alice", "bob"]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_detected_usernames_are_sorted():
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
            patch("agent_scan.pipelines.inspect_client", new_callable=AsyncMock) as mock_inspect,
        ):
            mock_inspect.return_value = InspectedPath(path="/test")

            args = InspectArgs(timeout=10, tokens=[], paths=[])
            _, scanned_usernames = await inspect_pipeline(args)

        assert scanned_usernames == ["alice", "bob", "charlie"]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_single_user_detected_among_many():
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
            patch("agent_scan.pipelines.inspect_client", new_callable=AsyncMock) as mock_inspect,
        ):
            mock_inspect.return_value = InspectedPath(path="/test")

            args = InspectArgs(timeout=10, tokens=[], paths=[])
            _, scanned_usernames = await inspect_pipeline(args)

        assert scanned_usernames == ["bob"]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_deduplicates_usernames_across_clients():
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
            patch("agent_scan.pipelines.inspect_client", new_callable=AsyncMock) as mock_inspect,
        ):
            mock_inspect.return_value = InspectedPath(path="/test")

            args = InspectArgs(timeout=10, tokens=[], paths=[])
            _, scanned_usernames = await inspect_pipeline(args)

        assert scanned_usernames == ["alice"]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_no_clients_returns_empty_results():
    """When no MCP clients are installed, inspect_pipeline should return empty scan_path_results."""
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
            results, _ = await inspect_pipeline(args)

        assert results == []
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_redacts_server_secrets_and_env():
    """`mcp-scan inspect` must not leak secrets: inspect_pipeline previously
    only redacted results on the `scan` path (via inspect_analyze_push_pipeline),
    so `inspect` returned raw env vars and unredacted tracebacks/server_output.
    Redaction now happens inside inspect_pipeline itself, so every caller
    (both `scan` and `inspect`) gets sanitized results."""
    fake_api_key = synthetic_secret()
    raw_result = InspectedPath(
        path="/some/path/mcp.json",
        servers=[
            InspectedServer(
                name="stdio",
                server=StdioServer(command="npx", args=["some-server"], env={"API_KEY": "shh"}),
                error=ScanError(
                    message="startup failed",
                    traceback=f"ConnectionError: token={fake_api_key} rejected",
                    server_output=f'stderr: loading /home/alice/.config/secrets.json\n{{"auth": "{fake_api_key}"}}',
                ),
            )
        ],
    )

    with (
        patch("agent_scan.pipelines.get_readable_home_directories", return_value=[]),
        patch(
            "agent_scan.pipelines.client_to_inspect_from_path",
            new_callable=AsyncMock,
            return_value=[ClientToInspect(name="test", client_path="/some/path", mcp_configs={}, skills_dirs={})],
        ),
        patch("agent_scan.pipelines.inspect_client", new_callable=AsyncMock, return_value=raw_result),
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=["/some/path/mcp.json"])
        results, _ = await inspect_pipeline(args)

    assert len(results) == 1
    server = results[0].servers[0]
    assert server.server.env["API_KEY"] == "**REDACTED**"
    assert fake_api_key not in server.error.traceback
    assert fake_api_key not in server.error.server_output
    assert "/home/alice/.config/secrets.json" not in server.error.server_output


@pytest.mark.asyncio
async def test_inspect_pipeline_missing_explicit_path_returns_file_not_found_error():
    """When an explicit path doesn't exist, inspect_pipeline should return a file_not_found error result."""
    with (
        patch("agent_scan.pipelines.get_readable_home_directories", return_value=[]),
        patch("agent_scan.pipelines.client_to_inspect_from_path", new_callable=AsyncMock, return_value=[]),
    ):
        args = InspectArgs(timeout=10, tokens=[], paths=["/nonexistent/path.json"])
        results, _ = await inspect_pipeline(args)

    assert len(results) == 1
    assert results[0].path == "/nonexistent/path.json"
    assert results[0].error is not None
    assert results[0].error.category == "file_not_found"


@pytest.mark.asyncio
async def test_inspect_pipeline_paths_mode_does_not_leak_all_usernames():
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
            patch("agent_scan.pipelines.inspect_client", new_callable=AsyncMock) as mock_inspect,
        ):
            mock_inspect.return_value = InspectedPath(path="/test")

            args = InspectArgs(timeout=10, tokens=[], paths=["/some/path/mcp.json"])
            _, scanned_usernames = await inspect_pipeline(args)

        assert scanned_usernames == [getpass.getuser()]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_discovery_mode_falls_back_to_all_usernames_when_no_agents_detected():
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
            _, scanned_usernames = await inspect_pipeline(args)

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
        assert skills[0].name == "my-skill"
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_legacy_discovery_skips_selected_location_before_plugin_glob(tmp_path):
    home = tmp_path / "user"
    client_root = home / ".fake-client"
    client_root.mkdir(parents=True)
    (client_root / "mcp.json").write_text('{"mcpServers": {"user-server": {"command": "user"}}}')
    plugin = client_root / "plugins" / "cache" / "vendor" / "plugin"
    plugin.mkdir(parents=True)
    (plugin / ".mcp.json").write_text('{"plugin-server": {"command": "plugin"}}')
    pattern = "~/.fake-client/plugins/cache/**/.mcp.json"
    candidate = CandidateClient(
        name="fake-client",
        client_exists_paths=["~/.fake-client"],
        mcp_config_paths=["~/.fake-client/mcp.json"],
        skills_dir_paths=[],
        mcp_config_globs=[pattern],
        mcp_config_glob_scopes={pattern: DiscoveryLocationScope.EXTENSION_PLUGIN},
    )

    ctis = await get_mcp_config_per_client(
        candidate,
        [(home, "user")],
        skip_discovery_scopes={DiscoveryLocationScope.EXTENSION_PLUGIN},
    )

    entries = [server for value in ctis[0].mcp_configs.values() if isinstance(value, list) for server in value]
    assert [server.name for server in entries] == ["user-server"]
    assert entries[0].scope is DiscoveryLocationScope.USER


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
        skills_dirs={"/proj/skills": [DiscoveredSkill(name="my-skill", path=str(skill_dir))]},
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
async def test_inspect_skill_prefers_frontmatter_name_over_directory_name(tmp_path):
    skill_dir = tmp_path / "random-dir-name"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\nname: authentic-skill-name\ndescription: test skill\n---\n# Body")
    (skill_dir / "helper.py").write_text("print('test')")

    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={},
        skills_dirs={"/proj/skills": [DiscoveredSkill(name="random-dir-name", path=str(skill_dir))]},
    )

    result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert len(result.skills) == 1
    skill = result.skills[0]
    assert skill.name == "authentic-skill-name"
    assert skill.installation_path == str(skill_dir)
    assert skill.error is None


@pytest.mark.asyncio
async def test_inspect_skill_falls_back_to_directory_name_on_frontmatter_error(tmp_path):
    skill_dir = tmp_path / "failing-dir-name"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("---\ninvalid: yaml [unterminated\n---\n# Body")
    (skill_dir / "helper.py").write_text("print('still useful for diagnostics')")

    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={},
        skills_dirs={"/proj/skills": [DiscoveredSkill(name="failing-dir-name", path=str(skill_dir))]},
    )

    result = await inspect_client(client, timeout=1, tokens=[], scan_skills=True)

    assert len(result.skills) == 1
    skill = result.skills[0]
    assert skill.name == "failing-dir-name"
    assert {file.path for file in skill.files} == {"SKILL.md", "helper.py"}
    assert skill.error is not None
    assert skill.error.category == "skill_scan_error"


# --- discovery scope tests ---


@pytest.fixture
def scoped_candidate(tmp_path):
    """A client exposing both an MCP config and a skills dir, for scope gating."""
    home = tmp_path / "user"
    (home / ".fake-client").mkdir(parents=True)

    plugin_dir = home / ".fake-client" / "plugins" / "cache" / "market" / "server-plugin" / "v1"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".mcp.json").write_text('{"my-server": {"command": "node", "args": ["server.js"]}}')

    skills_dir = home / ".fake-client" / "plugins" / "cache" / "market" / "skill-plugin" / "v1" / "skills" / "my-skill"
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
    return candidate, home


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scope, expect_servers, expect_skills",
    [
        (DiscoveryScope.ALL, True, True),
        (DiscoveryScope.SERVERS, True, False),
        (DiscoveryScope.SKILLS, False, True),
    ],
)
async def test_scope_only_populates_requested_half(scoped_candidate, scope, expect_servers, expect_skills):
    """Mirror of AgentDiscoverer.discover's scope gate, for the well-known-client path."""
    candidate, home = scoped_candidate

    ctis = await get_mcp_config_per_client(candidate, [(home, "user")], scope=scope)

    assert len(ctis) == 1
    cti = ctis[0]
    assert bool([path for path, value in cti.mcp_configs.items() if isinstance(value, list)]) is expect_servers
    assert bool([path for path, value in cti.skills_dirs.items() if isinstance(value, list)]) is expect_skills


@pytest.mark.asyncio
async def test_servers_scope_does_no_skills_filesystem_work(scoped_candidate):
    """``--scope servers`` exists to save latency, so the skills sweep must not run at all."""
    candidate, home = scoped_candidate

    with patch("agent_scan.inspect.inspect_skills_dir") as inspect_skills:
        await get_mcp_config_per_client(candidate, [(home, "user")], scope=DiscoveryScope.SERVERS)

    inspect_skills.assert_not_called()


@pytest.mark.asyncio
async def test_scope_defaults_to_all(scoped_candidate):
    candidate, home = scoped_candidate

    ctis = await get_mcp_config_per_client(candidate, [(home, "user")])

    assert [path for path, value in ctis[0].mcp_configs.items() if isinstance(value, list)]
    assert [path for path, value in ctis[0].skills_dirs.items() if isinstance(value, list)]


@pytest.mark.asyncio
async def test_client_detection_is_scope_independent(scoped_candidate):
    """The client_exists probe must run whatever the scope, or clients vanish from reports."""
    candidate, home = scoped_candidate

    for scope in DiscoveryScope:
        ctis = await get_mcp_config_per_client(candidate, [(home, "user")], scope=scope)
        assert len(ctis) == 1, scope
        assert ctis[0].client_path is not None, scope


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scope,mcp_config_paths,skills_dir_paths",
    [
        (DiscoveryScope.SERVERS, [], ["~/.fake-client/skills"]),
        (DiscoveryScope.SKILLS, ["~/.fake-client/mcp.json"], []),
    ],
)
async def test_client_detection_runs_when_requested_half_has_no_configured_sources(
    tmp_path, scope, mcp_config_paths, skills_dir_paths
):
    home = tmp_path / "user"
    (home / ".fake-client").mkdir(parents=True)
    candidate = CandidateClient(
        name="fake-client",
        client_exists_paths=["~/.fake-client"],
        mcp_config_paths=mcp_config_paths,
        skills_dir_paths=skills_dir_paths,
    )

    ctis = await get_mcp_config_per_client(candidate, [(home, "user")], scope=scope)

    assert len(ctis) == 1
    assert ctis[0].client_path == (home / ".fake-client").as_posix()
    assert ctis[0].mcp_configs == {}
    assert ctis[0].skills_dirs == {}


@pytest.mark.asyncio
async def test_client_detection_is_skipped_when_exclusions_remove_all_requested_sources(tmp_path):
    home = tmp_path / "user"
    (home / ".fake-client").mkdir(parents=True)
    candidate = CandidateClient(
        name="fake-client",
        client_exists_paths=["~/.fake-client"],
        mcp_config_paths=["~/.fake-client/mcp.json"],
        skills_dir_paths=[],
    )

    ctis = await get_mcp_config_per_client(
        candidate,
        [(home, "user")],
        scope=DiscoveryScope.SERVERS,
        skip_discovery_scopes={DiscoveryLocationScope.USER},
    )

    assert ctis == []
