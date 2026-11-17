import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.models import ClientToInspect, StdioServer
from agent_scan.pipelines import InspectArgs, RemoteOutcome, discover_clients
from agent_scan.remote_discovery import parity
from agent_scan.remote_discovery.parity import LocalPhaseKeys, compare, counts


def _client(name="cursor", mcp=None, skills=None) -> ClientToInspect:
    return ClientToInspect(
        name=name, client_path=f"~/.{name}", username="alice", mcp_configs=mcp or {}, skills_dirs=skills or {}
    )


def _servers(command="npx"):
    return [("srv", StdioServer(command=command))]


def test_counts():
    clients = [_client(mcp={"/a.json": _servers(), "/b.json": []}, skills={"/s": []})]
    assert counts(clients) == {"clients": 1, "mcp_configs": 2, "mcp_servers": 1, "skills_dirs": 1}


def test_identical():
    local = [_client(mcp={"/a.json": _servers()})]
    remote = [_client(mcp={"/a.json": _servers()})]
    result = compare(local, remote, ["cursor"], LocalPhaseKeys())
    assert result == {"comparison": "identical", "expected_only_local": 0, "expected_only_remote": 0}


def test_reports_paths_only_on_one_side_and_content_mismatch():
    local = [_client(mcp={"/a.json": _servers(), "/local.json": []})]
    remote = [_client(mcp={"/a.json": _servers("uvx"), "/remote.json": []})]
    result = compare(local, remote, ["cursor"], LocalPhaseKeys())
    assert result["comparison"] == "different"
    assert result["only_local"] == [{"client": "cursor", "kind": "mcp_config", "path": "/local.json"}]
    assert result["only_remote"] == [{"client": "cursor", "kind": "mcp_config", "path": "/remote.json"}]
    assert result["content_mismatch"] == [{"client": "cursor", "kind": "mcp_config", "path": "/a.json"}]


def test_expected_extras_are_counted_apart():
    table_only = ("cursor", "alice", "mcp_config", "/settings.json")
    local = [_client(mcp={"/settings.json": []})]
    remote = [_client(mcp={"//wsl.localhost/Ubuntu/home/a/.cursor/mcp.json": []})]
    result = compare(local, remote, ["cursor"], LocalPhaseKeys(well_known={table_only}))
    assert result == {"comparison": "identical", "expected_only_local": 1, "expected_only_remote": 1}


def test_table_key_also_found_by_discoverer_is_not_expected():
    key = ("cursor", "alice", "mcp_config", "/mcp.json")
    result = compare(
        [_client(mcp={"/mcp.json": []})], [], ["cursor"], LocalPhaseKeys(well_known={key}, discoverers={key})
    )
    assert result["comparison"] == "different"
    assert result["only_local_count"] == 1


def test_unsupported_agents_are_not_compared():
    result = compare([_client(name="windsurf", mcp={"/w.json": []})], [], ["cursor"], LocalPhaseKeys())
    assert result["comparison"] == "identical"


def test_lists_are_capped(monkeypatch):
    monkeypatch.setattr(parity, "MAX_LISTED", 2)
    local = [_client(mcp={f"/{i}.json": [] for i in range(5)})]
    result = compare(local, [], ["cursor"], LocalPhaseKeys())
    assert len(result["only_local"]) == 2 and result["only_local_count"] == 5


@pytest.mark.asyncio
async def test_shadow_timeout_keeps_local(monkeypatch):
    async def slow(*_args, **_kwargs):
        await asyncio.sleep(10)
        return RemoteOutcome(None, "error")

    monkeypatch.setattr("agent_scan.pipelines.SHADOW_TIMEOUT_S", 0.01)
    local = ([_client()], [], ["alice"])
    with (
        patch("agent_scan.pipelines.discover_clients_to_inspect", new=AsyncMock(return_value=local)),
        patch("agent_scan.pipelines.discover_clients_remotely", new=slow),
    ):
        discovered, metadata = await discover_clients(
            InspectArgs(timeout=10, tokens=[], paths=[]), "shadow", "https://x", "k"
        )
    assert discovered == local
    assert metadata["comparison"] == "failed" and metadata["remote_error_reason"] == "shadow_timeout"
