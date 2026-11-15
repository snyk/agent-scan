"""Tests for single-server targeting (--server / --url / --server-type)."""

from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.models import ClientToInspect, FileNotFoundConfig, RemoteServer, StdioServer
from agent_scan.pipelines import (
    InspectArgs,
    discover_servers_by_name,
    filter_clients_to_server,
    single_remote_client_to_inspect,
)


def _client(name, configs, *, username=None, skills=None):
    return ClientToInspect(
        name=name,
        client_path=f"/home/{name}",
        username=username,
        mcp_configs=configs,
        skills_dirs=skills or {},
    )


class TestSingleRemoteClientToInspect:
    def test_builds_one_remote_server_with_pinned_type(self):
        client = single_remote_client_to_inspect("snyk", "https://api.snyk.io/mcp-server/mcp", "http")

        entries = client.mcp_configs["https://api.snyk.io/mcp-server/mcp"]
        assert len(entries) == 1
        entry_name, config = entries[0]
        assert entry_name == "snyk"
        assert isinstance(config, RemoteServer)
        assert config.url == "https://api.snyk.io/mcp-server/mcp"
        assert config.type == "http"

    def test_skills_are_never_included(self):
        client = single_remote_client_to_inspect("snyk", "https://example.test/mcp", None)
        assert client.skills_dirs == {}

    def test_name_falls_back_to_hostname_then_url(self):
        by_host = single_remote_client_to_inspect(None, "https://example.test/mcp", None)
        assert by_host.mcp_configs["https://example.test/mcp"][0][0] == "example.test"

        # No hostname to extract -> the raw target is used as the label.
        by_url = single_remote_client_to_inspect(None, "not-a-url", None)
        assert by_url.mcp_configs["not-a-url"][0][0] == "not-a-url"

    def test_type_may_stay_unset(self):
        client = single_remote_client_to_inspect("x", "https://example.test/mcp", None)
        assert client.mcp_configs["https://example.test/mcp"][0][1].type is None


class TestFilterClientsToServer:
    def test_keeps_only_the_named_entry(self):
        clients = [
            _client(
                "cursor",
                {
                    "/cfg.json": [
                        ("wanted", RemoteServer(url="https://a.test/mcp", type="http")),
                        ("other", RemoteServer(url="https://b.test/mcp", type="http")),
                    ]
                },
            )
        ]

        filtered = filter_clients_to_server(clients, "wanted")

        assert len(filtered) == 1
        entries = filtered[0].mcp_configs["/cfg.json"]
        assert [name for name, _ in entries] == ["wanted"]

    def test_drops_clients_with_no_match(self):
        clients = [
            _client("cursor", {"/a.json": [("x", RemoteServer(url="https://a.test/mcp"))]}),
            _client("vscode", {"/b.json": [("wanted", RemoteServer(url="https://b.test/mcp"))]}),
        ]

        filtered = filter_clients_to_server(clients, "wanted")

        assert [c.name for c in filtered] == ["vscode"]

    def test_no_match_returns_empty(self):
        clients = [_client("cursor", {"/a.json": [("x", RemoteServer(url="https://a.test/mcp"))]})]
        assert filter_clients_to_server(clients, "absent") == []

    def test_server_type_overrides_configured_transport(self):
        clients = [_client("cursor", {"/a.json": [("wanted", RemoteServer(url="https://a.test/mcp", type="http"))]})]

        filtered = filter_clients_to_server(clients, "wanted", "sse")

        assert filtered[0].mcp_configs["/a.json"][0][1].type == "sse"

    def test_skills_are_dropped_and_username_preserved(self):
        clients = [
            _client(
                "cursor",
                {"/a.json": [("wanted", RemoteServer(url="https://a.test/mcp"))]},
                username="az",
                skills={"/skills": []},
            )
        ]

        filtered = filter_clients_to_server(clients, "wanted")

        assert filtered[0].skills_dirs == {}
        assert filtered[0].username == "az"

    def test_error_sentinel_config_values_are_skipped(self):
        # mcp_configs values are not always lists; unparseable files use sentinels.
        clients = [
            _client(
                "cursor",
                {
                    "/broken.json": FileNotFoundConfig(message="File or folder not found"),
                    "/ok.json": [("wanted", RemoteServer(url="https://a.test/mcp"))],
                },
            )
        ]

        filtered = filter_clients_to_server(clients, "wanted")

        assert list(filtered[0].mcp_configs) == ["/ok.json"]

    def test_matches_stdio_servers_too(self):
        clients = [_client("cursor", {"/a.json": [("local", StdioServer(command="npx", args=["-y", "pkg"]))]})]

        filtered = filter_clients_to_server(clients, "local")

        assert isinstance(filtered[0].mcp_configs["/a.json"][0][1], StdioServer)

    def test_duplicate_name_across_configs_keeps_only_first_occurrence(self):
        # Same name configured in two different places (e.g. a global config
        # and a per-project one) must resolve to exactly one server, matching
        # discover_servers_by_name's first-occurrence-wins definition of "the
        # server named X" -- not every matching entry across every client.
        clients = [
            _client(
                "cursor",
                {"/global.json": [("wanted", RemoteServer(url="https://a.test/mcp"))]},
            ),
            _client(
                "vscode",
                {"/project.json": [("wanted", RemoteServer(url="https://b.test/mcp"))]},
            ),
        ]

        filtered = filter_clients_to_server(clients, "wanted")

        assert len(filtered) == 1
        assert filtered[0].name == "cursor"
        assert list(filtered[0].mcp_configs) == ["/global.json"]
        assert filtered[0].mcp_configs["/global.json"][0][1].url == "https://a.test/mcp"


class TestDiscoverServersByName:
    @pytest.fixture
    def clients(self):
        return [
            _client(
                "cursor",
                {
                    "/a.json": [
                        ("remote", RemoteServer(url="https://a.test/mcp", type="http")),
                        ("local", StdioServer(command="npx", args=[])),
                    ]
                },
            ),
            _client("vscode", {"/b.json": [("remote", RemoteServer(url="https://DIFFERENT.test/mcp"))]}),
        ]

    @pytest.mark.asyncio
    async def test_remote_only_excludes_stdio(self, clients):
        with patch("agent_scan.pipelines.discover_clients_to_inspect", new=AsyncMock(return_value=(clients, [], []))):
            found = await discover_servers_by_name(_args(), remote_only=True)

        assert set(found) == {"remote"}

    @pytest.mark.asyncio
    async def test_includes_stdio_by_default(self, clients):
        with patch("agent_scan.pipelines.discover_clients_to_inspect", new=AsyncMock(return_value=(clients, [], []))):
            found = await discover_servers_by_name(_args())

        assert set(found) == {"remote", "local"}

    @pytest.mark.asyncio
    async def test_first_occurrence_wins_on_duplicate_names(self, clients):
        # Both clients define "remote"; mcp-auth's historical behavior keeps the first.
        with patch("agent_scan.pipelines.discover_clients_to_inspect", new=AsyncMock(return_value=(clients, [], []))):
            found = await discover_servers_by_name(_args(), remote_only=True)

        assert found["remote"].url == "https://a.test/mcp"


def _args():
    return InspectArgs(timeout=10, tokens=[], paths=[], all_users=False, scan_skills=False)
