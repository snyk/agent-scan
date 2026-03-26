import getpass
import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.inspect import get_mcp_config_per_client
from agent_scan.models import CandidateClient, ClientToInspect
from agent_scan.pipelines import InspectArgs, inspect_pipeline

TEST_CANDIDATE_CLIENT = CandidateClient(
    name="test-client",
    client_exists_paths=["tests/mcp_servers/.test-client"],
    mcp_config_paths=["tests/mcp_servers/.test-client/mcp.json"],
    skills_dir_paths=["tests/mcp_servers/.test-client/skills"],
)


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
        patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
    ):
        mock_inspect.return_value = None
        mock_to_result.return_value = None

        args = InspectArgs(timeout=10, tokens=[], paths=[])
        _, scanned_usernames = await inspect_pipeline(args)

    assert sorted(scanned_usernames) == ["alice", "bob"]
    assert "charlie" not in scanned_usernames


@pytest.mark.asyncio
async def test_inspect_pipeline_falls_back_to_all_usernames_when_no_agents_detected():
    """When no agents are detected for any user, inspect_pipeline should report all usernames."""
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
            args = InspectArgs(timeout=10, tokens=[], paths=[])
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
            patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
        ):
            mock_inspect.return_value = None
            mock_to_result.return_value = None

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
            patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
        ):
            mock_inspect.return_value = None
            mock_to_result.return_value = None

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
            patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
        ):
            mock_inspect.return_value = None
            mock_to_result.return_value = None

            args = InspectArgs(timeout=10, tokens=[], paths=[])
            _, scanned_usernames = await inspect_pipeline(args)

        assert scanned_usernames == ["alice"]
    finally:
        shutil.rmtree(tmp)


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
            patch("agent_scan.pipelines.inspected_client_to_scan_path_result") as mock_to_result,
        ):
            mock_inspect.return_value = None
            mock_to_result.return_value = None

            args = InspectArgs(timeout=10, tokens=[], paths=["/some/path/mcp.json"])
            _, scanned_usernames = await inspect_pipeline(args)

        assert scanned_usernames == [getpass.getuser()]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_pipeline_discovery_mode_falls_back_to_all_usernames_when_no_agents_detected():
    """Without --paths, when no agents are detected, all readable usernames should be reported (original behavior)."""
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
            args = InspectArgs(timeout=10, tokens=[], paths=[])
            _, scanned_usernames = await inspect_pipeline(args)

        assert sorted(scanned_usernames) == ["alice", "bob"]
    finally:
        shutil.rmtree(tmp)
