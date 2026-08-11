import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from httpx import HTTPStatusError, Request, Response

from agent_scan.inspect import (
    get_mcp_config_per_client,
    inspect_client,
)
from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import (
    CandidateClient,
    ClientToInspect,
    CouldNotParseMCPConfig,
    InspectedSkill,
    RemoteServer,
    SkillServer,
    StdioServer,
)

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
async def test_inspect_client_attributes_empty_component_names_to_their_source():
    client = ClientToInspect(
        name="cursor",
        client_path="/proj",
        mcp_configs={
            "/proj/.mcp.json": [("", StdioServer(command="sqlite-mcp"))],
        },
        skills_dirs={
            "/proj/skills": [("", SkillServer(path="/proj/skills/unnamed"))],
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

    with patch("agent_scan.inspect.check_server", new_callable=AsyncMock, return_value=(signature, remote)):
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
