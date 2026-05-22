import getpass
import shutil
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.inspect import get_mcp_config_per_client, inspect_client
from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import (
    CandidateClient,
    ClientToInspect,
    SkippedByRuntimeConfigError,
    StdioServer,
)
from agent_scan.pipelines import InspectArgs, inspect_pipeline
from agent_scan.runtime_config import RuntimeConfig, set_runtime_config

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
async def test_inspect_pipeline_discovery_mode_without_all_users_falls_back_to_current_user():
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
            _, scanned_usernames = await inspect_pipeline(args)

        assert scanned_usernames == [getpass.getuser()]
    finally:
        shutil.rmtree(tmp)


@pytest.mark.asyncio
async def test_inspect_client_skips_server_per_runtime_config_without_starting_subprocess():
    """When runtime_config.skip_servers matches, inspect_extension must not run.

    This is the load-bearing guarantee: the *whole point* of skipping is to
    avoid starting the subprocess (and, by extension, avoid the consent
    prompt, the env var passthrough, the network egress, etc.). If we
    only labelled the result without preventing the call, the skip would
    be a lie.
    """
    set_runtime_config(RuntimeConfig(config={"skip_servers": ["entra-mcp-proxy"]}, source="bootstrap"))

    skipped = StdioServer(
        command="uvx",
        args=[
            "--from",
            "git+ssh://github.eagleview.com/infrastructure/entra-mcp-proxy.git",
            "entra-mcp-proxy",
        ],
    )
    kept = StdioServer(command="echo", args=["hello"])

    client = ClientToInspect(
        name="test",
        client_path="/some/path",
        mcp_configs={"/cfg.json": [("entra-mcp-proxy", skipped), ("other", kept)]},
        skills_dirs={},
    )

    with patch("agent_scan.inspect.inspect_extension", new_callable=AsyncMock) as mock_inspect_extension:
        # Returning a sentinel that satisfies InspectedExtensions shape isn't
        # required for the kept server because we only assert call counts/args
        # here; the test fails the moment inspect_extension is invoked for the
        # skipped server (which is the regression we care about).
        mock_inspect_extension.side_effect = AssertionError(
            "inspect_extension must not be called when runtime_config skips the server"
        )

        # Make the kept-server call a no-op success so we can finish the loop
        # without exercising the real MCP subprocess machinery.
        async def fake_inspect(name, server, *args, **kwargs):
            if name == "other":
                from mcp.types import Implementation, InitializeResult

                from agent_scan.models import InspectedExtensions, ServerSignature

                return InspectedExtensions(
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
            raise AssertionError(f"inspect_extension must not be called for skipped server {name!r}")

        mock_inspect_extension.side_effect = fake_inspect

        result = await inspect_client(client, timeout=10, tokens=[], scan_skills=False)

    extensions = result.extensions["/cfg.json"]
    assert len(extensions) == 2

    skipped_ext = next(e for e in extensions if e.name == "entra-mcp-proxy")
    assert isinstance(skipped_ext.signature_or_error, SkippedByRuntimeConfigError)
    assert skipped_ext.signature_or_error.is_failure is True
    assert "entra-mcp-proxy" in (skipped_ext.signature_or_error.message or "")

    # Sanity: the non-skipped server did go through inspect_extension exactly once.
    call_names = [call.args[0] for call in mock_inspect_extension.call_args_list]
    assert call_names == ["other"]
