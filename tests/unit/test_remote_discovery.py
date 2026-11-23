"""Remote discovery: the CLI-side op executor and the ``found`` -> ``ClientToInspect`` merge."""

import os
from pathlib import Path

import pytest

from agent_scan.remote_discovery.builder import build_clients
from agent_scan.remote_discovery.executor import run_op


def _find(root: Path, **op: object) -> list[str]:
    result = run_op({"op_id": "1", "kind": "find", "roots": [str(root)], "max_depth": 6, **op})
    assert result["status"] == "ok"
    return sorted(Path(m["path"]).relative_to(root).as_posix() for m in result["matches"])


def test_find_follows_only_child_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "deep").mkdir(parents=True)
    (target / "deep/.mcp.json").write_text("{}")
    (tmp_path / "root/sub").mkdir(parents=True)
    os.symlink(target, tmp_path / "root/a")
    os.symlink(target, tmp_path / "root/sub/b")
    os.symlink(tmp_path / "root", tmp_path / "root/sub/loop")
    root = tmp_path / "root"

    assert _find(root, file_names=[".mcp.json"]) == []
    assert _find(root, file_names=[".mcp.json"], follow_child_links=True) == ["a/deep/.mcp.json"]


def test_find_file_suffixes(tmp_path: Path) -> None:
    (tmp_path / "x.json").mkdir()
    for name in ("a.json", "b.md", "sub/c.json"):
        (tmp_path / name).parent.mkdir(exist_ok=True)
        (tmp_path / name).write_text("{}")
    (tmp_path / "D.JSON").write_text("{}")

    assert _find(tmp_path, file_suffixes=[".json"], max_depth=1) == ["a.json"]
    assert _find(tmp_path, file_suffixes=[".json"], max_depth=1, ignore_case=True) == ["D.JSON", "a.json"]
    assert _find(tmp_path, file_suffixes=[".json"]) == ["a.json", "sub/c.json"]


def test_env_sends_values_as_set(monkeypatch) -> None:
    monkeypatch.setenv("CODEX_HOME", "/opt/codex")
    monkeypatch.setenv("COPILOT_HOME", "relative/dir")
    monkeypatch.setenv("LONG", "/" + "x" * 5000)
    monkeypatch.delenv("UNSET_VAR", raising=False)
    op = {"op_id": "1", "kind": "env", "names": ["CODEX_HOME", "COPILOT_HOME", "LONG", "UNSET_VAR", "lower", "A-B"]}
    result = run_op(op)
    assert result["status"] == "ok"
    assert result["values"] == {
        "CODEX_HOME": "/opt/codex",
        "COPILOT_HOME": "relative/dir",
        "LONG": None,
        "UNSET_VAR": None,
    }


def test_find_read_skips_files_over_budget_without_reading(tmp_path: Path, monkeypatch) -> None:
    from agent_scan.remote_discovery import executor

    for name, size in (("a.json", 6), ("b.json", 6), ("c.json", 2)):
        (tmp_path / name).write_bytes(b"x" * size)
    monkeypatch.setattr(executor, "MAX_FIND_READ_BYTES", 10)
    opened: list[str] = []
    real_open = open

    def spy(path, *a, **k):
        opened.append(Path(path).name)
        return real_open(path, *a, **k)

    monkeypatch.setattr(executor, "open", spy, raising=False)
    op = {"op_id": "1", "kind": "find", "roots": [str(tmp_path)], "max_depth": 1, "file_suffixes": [".json"]}
    result = run_op({**op, "read": True})

    read = sorted(Path(f["path"]).name for f in result["files"])
    skipped = [Path(s["path"]).name for s in result["skipped"]]
    assert sum(f["size"] for f in result["files"]) <= 10
    assert len(read) == 2 and len(skipped) == 1
    assert set(opened) == set(read)


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (PermissionError(13, "denied"), "unreadable"),
        # Say, a OneDrive file macOS can't download.
        (OSError(11, "resource deadlock avoided"), "read_error"),
        (ValueError("bad path"), "read_error"),
    ],
)
def test_read_errors_report_reason(tmp_path: Path, monkeypatch, error: Exception, reason: str) -> None:
    from agent_scan.remote_discovery import executor

    path = tmp_path / "mcp.json"
    path.write_text("{}")

    def failing_open(*_a, **_k):
        raise error

    monkeypatch.setattr(executor, "open", failing_open, raising=False)
    result = run_op({"op_id": "1", "kind": "read", "paths": [str(path)]})

    assert result["files"] == []
    assert [(s["path"], s["reason"]) for s in result["skipped"]] == [(str(path), reason)]


def test_cancelled_op_stops() -> None:
    import threading

    from agent_scan.remote_discovery.executor import OpCancelled

    cancel = threading.Event()
    cancel.set()
    with pytest.raises(OpCancelled):
        run_op({"op_id": "1", "kind": "find", "roots": ["/"], "max_depth": 6, "file_names": ["x"]}, cancel)


def test_env_caps_names() -> None:
    names = [f"V{i}" for i in range(100)]
    assert len(run_op({"op_id": "1", "kind": "env", "names": names})["values"]) == 64


def _mcp(key: str, name: str, **flags: bool) -> dict:
    return {
        "client": "claude code",
        "username": "me",
        "key": key,
        "candidates": [{"maps": [{name: {"command": name}}]}],
        "fallback": {"kind": "parse_error", "message": "x"},
        **flags,
    }


def test_merge_last_write_wins_and_canonical(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text("{}")
    link = tmp_path / "link.json"
    os.symlink(real, link)
    found = {
        "clients": [{"name": "claude code", "client_path": "/x", "username": "me"}],
        "mcp_configs": [
            _mcp("/a.json", "first"),
            _mcp("/a.json", "second"),
            _mcp(str(link), "via-link", canonical=True),
            _mcp(str(real), "direct", canonical=True),
        ],
        "skills_dirs": [],
    }
    (client,) = build_clients(found)
    configs = client.mcp_configs
    assert [name for name, _ in configs["/a.json"]] == ["second"]
    # Two spellings of one file merge under its resolved path.
    assert [name for name, _ in configs[real.resolve().as_posix()]] == ["via-link", "direct"]
    assert str(link) not in configs


def _stdio_found(raw: dict, roots: list[str]) -> dict:
    return {
        "clients": [{"name": "codex", "client_path": "/x", "username": "me"}],
        "mcp_configs": [
            {
                "client": "codex",
                "username": "me",
                "key": "/c.toml",
                "candidates": [{"maps": [{"tool": raw}]}],
                "fallback": {"kind": "parse_error", "message": "x"},
                "stdio_roots": {"tool": roots},
            }
        ],
        "skills_dirs": [],
    }


def test_stdio_roots_resolve_one_executable(tmp_path: Path, monkeypatch) -> None:
    signed: list[str | None] = []

    def fake_sign(server, *, signature_command=None):
        signed.append(signature_command)
        return server

    monkeypatch.setattr("agent_scan.remote_discovery.builder.check_server_signature", fake_sign)
    plugin = tmp_path / "plugin"
    (plugin / "bin").mkdir(parents=True)
    (plugin / "bin/run tool").write_text("#!/bin/sh\n")
    raw = {"command": "./bin/run tool", "args": ["--x"], "cwd": "."}
    found = _stdio_found(raw, [str(tmp_path / "missing"), str(plugin)])
    (client,) = build_clients(found)
    ((_, server),) = client.mcp_configs["/c.toml"]
    executable = str((plugin / "bin/run tool").resolve())
    assert signed == [executable]
    # The uploaded command stays as configured; the resolved one is runtime context.
    assert (server.command, server.args) == ("./bin/run tool", ["--x"])
    assert (server.runtime_command, server.runtime_cwd) == (executable, str(plugin.resolve()))


def test_stdio_roots_ignored_when_ambiguous_or_escaping(tmp_path: Path, monkeypatch) -> None:
    signed: list[str | None] = []

    def fake_sign(server, *, signature_command=None):
        signed.append(signature_command)
        return server

    monkeypatch.setattr("agent_scan.remote_discovery.builder.check_server_signature", fake_sign)
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "tool").write_text("")
    (tmp_path / "outside").write_text("")
    roots = [str(tmp_path / "a"), str(tmp_path / "b")]
    build_clients(_stdio_found({"command": "./tool", "cwd": "."}, roots))
    build_clients(_stdio_found({"command": "../outside", "cwd": "."}, [str(tmp_path / "a")]))
    assert signed == [None, None]


# --- run_remote_discovery retries ---

_EMPTY_FOUND: dict[str, list[dict]] = {"clients": [], "mcp_configs": [], "skills_dirs": []}


async def _serve(statuses: dict[str, list[int]], init_found: dict[str, list[dict]] | None = None):
    """A discovery backend that answers each path with the given statuses in turn, then 200."""
    from aiohttp import web
    from aiohttp.test_utils import TestServer

    bodies: dict[str, list[bytes]] = {}

    async def handle(request):
        from agent_scan.remote_discovery.client import DISCOVERY_API_VERSION

        if request.query.get("version") != DISCOVERY_API_VERSION:
            return web.Response(status=404, text="no version")
        bodies.setdefault(request.path, []).append(await request.read())
        queue = statuses.get(request.path, [])
        if queue:
            return web.Response(status=queue.pop(0), text="busy")
        if request.path.endswith("/sessions"):
            ops = [{"op_id": "1", "kind": "env", "names": []}]
            found = init_found or _EMPTY_FOUND
            return web.json_response({"session_id": "s1", "round": 1, "ops": ops, "found": found, "done": False})
        return web.json_response({"session_id": "s1", "round": 2, "ops": [], "found": _EMPTY_FOUND, "done": True})

    app = web.Application()
    app.router.add_post("/{tail:.*}", handle)
    server = TestServer(app)
    await server.start_server()
    return server, bodies


_SESSIONS = "/hidden/coding-agent-discovery/sessions"
_HOMES = [(Path("/Users/me"), "me")]
_STEPS = f"{_SESSIONS}/s1/steps"


async def _discover(server):
    from unittest.mock import AsyncMock, patch

    from agent_scan.remote_discovery.client import run_remote_discovery

    with (
        patch("agent_scan.remote_discovery.client.asyncio.sleep", new=AsyncMock()) as sleep,
        patch("agent_scan.remote_discovery.client.get_readable_home_directories", return_value=_HOMES),
    ):
        result = await run_remote_discovery(str(server.make_url("/")).rstrip("/"))
    return result, sleep


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
async def test_init_retried_on_transient_status(status) -> None:
    server, bodies = await _serve({_SESSIONS: [status]})
    try:
        result, sleep = await _discover(server)
    finally:
        await server.close()
    assert len(bodies[_SESSIONS]) == 2
    assert result.retries == 1
    sleep.assert_awaited_once()


@pytest.mark.asyncio
async def test_no_homes_skips_the_backend() -> None:
    from unittest.mock import patch

    from agent_scan.remote_discovery.client import run_remote_discovery

    server, bodies = await _serve({})
    try:
        with patch("agent_scan.remote_discovery.client.get_readable_home_directories", return_value=[]):
            result = await run_remote_discovery(str(server.make_url("/")).rstrip("/"), all_users=True)
    finally:
        await server.close()
    assert bodies == {}
    assert result.found == {"clients": [], "mcp_configs": [], "skills_dirs": []}
    assert (result.session_id, result.rounds, result.partial) == ("", 0, False)


@pytest.mark.asyncio
async def test_init_sends_client_identifier() -> None:
    import json
    from unittest.mock import patch

    from agent_scan.remote_discovery.client import run_remote_discovery

    server, bodies = await _serve({})
    try:
        with patch("agent_scan.remote_discovery.client.get_readable_home_directories", return_value=_HOMES):
            await run_remote_discovery(
                str(server.make_url("/")).rstrip("/"), cli_version="1.2.3", identifier="machine-1"
            )
    finally:
        await server.close()
    client = json.loads(bodies[_SESSIONS][0])["client"]
    assert client["identifier"] == "machine-1"
    assert client["cli_version"] == "1.2.3"


@pytest.mark.asyncio
async def test_timeout_stops_a_slow_op() -> None:
    import asyncio
    import time
    from unittest.mock import patch

    from agent_scan.remote_discovery import client
    from agent_scan.remote_discovery.executor import OpCancelled

    stopped: list[bool] = []

    def slow_op(op, cancel):
        while not cancel.is_set():
            time.sleep(0.01)
        stopped.append(True)
        raise OpCancelled

    server, _bodies = await _serve({})
    try:
        with (
            patch.object(client, "run_op", slow_op),
            patch("agent_scan.remote_discovery.client.get_readable_home_directories", return_value=_HOMES),
        ):
            started = time.monotonic()
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(client.run_remote_discovery(str(server.make_url("/")).rstrip("/")), 0.3)
            assert time.monotonic() - started < 2
            for _ in range(100):
                if stopped:
                    break
                await asyncio.sleep(0.01)
    finally:
        await server.close()
    assert stopped == [True]


@pytest.mark.asyncio
async def test_request_timeout_is_retried() -> None:
    import asyncio
    from unittest.mock import patch

    from aiohttp import web
    from aiohttp.test_utils import TestServer

    from agent_scan.remote_discovery import client

    calls = 0

    async def handle(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            await asyncio.sleep(1)
        return web.json_response({"session_id": "s1", "round": 1, "ops": [], "found": _EMPTY_FOUND, "done": True})

    app = web.Application()
    app.router.add_post("/{tail:.*}", handle)
    server = TestServer(app)
    await server.start_server()
    try:
        with (
            patch.object(client, "REQUEST_TIMEOUT_S", 0.2),
            patch.object(client, "_retry_delay", return_value=0),
            patch("agent_scan.remote_discovery.client.get_readable_home_directories", return_value=_HOMES),
        ):
            result = await client.run_remote_discovery(str(server.make_url("/")).rstrip("/"))
    finally:
        await server.close()
    assert calls == 2
    assert result.retries == 1


@pytest.mark.asyncio
async def test_step_retry_resends_identical_body() -> None:
    server, bodies = await _serve({_STEPS: [502, 503]})
    try:
        result, _sleep = await _discover(server)
    finally:
        await server.close()
    assert len(bodies[_STEPS]) == 3
    assert len(set(bodies[_STEPS])) == 1
    assert result.retries == 2


@pytest.mark.asyncio
async def test_gives_up_after_max_retries() -> None:
    from agent_scan.remote_discovery.client import MAX_RETRIES, RemoteDiscoveryError

    server, bodies = await _serve({_SESSIONS: [503] * (MAX_RETRIES + 1)})
    try:
        with pytest.raises(RemoteDiscoveryError) as exc:
            await _discover(server)
    finally:
        await server.close()
    assert exc.value.reason == "http_503"
    assert len(bodies[_SESSIONS]) == MAX_RETRIES + 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 401, 404, 409, 410, 413])
async def test_client_errors_not_retried(status) -> None:
    from agent_scan.remote_discovery.client import RemoteDiscoveryError

    server, bodies = await _serve({_SESSIONS: [status]})
    try:
        with pytest.raises(RemoteDiscoveryError) as exc:
            await _discover(server)
    finally:
        await server.close()
    assert exc.value.reason == f"http_{status}"
    assert len(bodies[_SESSIONS]) == 1


@pytest.mark.asyncio
async def test_lost_session_restarts_from_init() -> None:
    client = {"name": "cursor"}
    server, bodies = await _serve({_STEPS: [404]}, init_found={**_EMPTY_FOUND, "clients": [client]})
    try:
        result, _sleep = await _discover(server)
    finally:
        await server.close()
    assert len(bodies[_SESSIONS]) == 2
    assert len(bodies[_STEPS]) == 2
    assert result.restarts == 1
    assert result.found["clients"] == [client]
    assert (result.session_id, result.rounds, result.partial) == ("s1", 1, False)


@pytest.mark.asyncio
async def test_lost_session_restarts_only_once() -> None:
    from agent_scan.remote_discovery.client import MAX_RESTARTS, RemoteDiscoveryError

    server, bodies = await _serve({_STEPS: [404] * (MAX_RESTARTS + 1)})
    try:
        with pytest.raises(RemoteDiscoveryError) as exc:
            await _discover(server)
    finally:
        await server.close()
    assert exc.value.reason == "http_404"
    assert len(bodies[_SESSIONS]) == MAX_RESTARTS + 1


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 409, 410, 413])
async def test_other_step_errors_do_not_restart(status) -> None:
    from agent_scan.remote_discovery.client import RemoteDiscoveryError

    server, bodies = await _serve({_STEPS: [status]})
    try:
        with pytest.raises(RemoteDiscoveryError) as exc:
            await _discover(server)
    finally:
        await server.close()
    assert exc.value.reason == f"http_{status}"
    assert len(bodies[_SESSIONS]) == 1


def test_retry_delay_honors_retry_after_and_caps() -> None:
    from agent_scan.remote_discovery.client import MAX_RETRY_DELAY_S, _retry_after, _retry_delay

    assert _retry_delay(0, _retry_after("2")) == 2.0
    assert _retry_delay(0, _retry_after("600")) == MAX_RETRY_DELAY_S
    assert _retry_after("Wed, 21 Oct 2026 07:28:00 GMT") is None
    assert 0.75 <= _retry_delay(0, None) <= 1.25
    assert 3.0 <= _retry_delay(2, None) <= 5.0


@pytest.mark.asyncio
async def test_connection_errors_retried_then_raised() -> None:
    import socket
    from unittest.mock import AsyncMock, patch

    import aiohttp

    from agent_scan.remote_discovery.client import MAX_RETRIES, run_remote_discovery

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with (
        patch("agent_scan.remote_discovery.client.asyncio.sleep", new=AsyncMock()) as sleep,
        patch("agent_scan.remote_discovery.client.get_readable_home_directories", return_value=_HOMES),
        pytest.raises(aiohttp.ClientConnectionError),
    ):
        await run_remote_discovery(f"http://127.0.0.1:{port}")
    assert sleep.await_count == MAX_RETRIES
