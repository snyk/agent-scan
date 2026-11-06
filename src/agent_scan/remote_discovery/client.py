"""Drive one discovery session: init, then run ops and post results until the backend is done."""

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

import aiohttp

from agent_scan.agents.base import is_own_home
from agent_scan.remote_discovery import trace as trace_output
from agent_scan.remote_discovery.executor import run_op, to_wire
from agent_scan.utils import get_readable_home_directories

# Env vars the backend may use to relocate agent config folders (own home only).
FORWARDED_ENV = ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "VSCODE_PORTABLE", "XDG_CONFIG_HOME")
MAX_ROUNDS = 25


class RemoteDiscoveryError(Exception):
    pass


@dataclass
class RemoteResult:
    session_id: str = ""
    found: dict[str, list[dict[str, Any]]] = field(
        default_factory=lambda: {"clients": [], "mcp_configs": [], "skills_dirs": []}
    )
    supported_agents: list[str] = field(default_factory=list)
    partial: bool = False
    rounds: int = 0
    ops: int = 0
    duration_s: float = 0.0
    bytes_sent: int = 0

    def add(self, found: dict[str, list[dict[str, Any]]]) -> None:
        for name in self.found:
            self.found[name].extend(found.get(name, []))


async def _post(
    session: aiohttp.ClientSession,
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    result: RemoteResult,
    trace: bool,
) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    result.bytes_sent += len(body)
    if trace:
        trace_output.request(url, payload, len(body))
    started = time.monotonic()
    async with session.post(url, data=body, headers={**headers, "Content-Type": "application/json"}) as response:
        if response.status >= 400:
            # Detail only: bounded reason strings, never request content.
            raise RemoteDiscoveryError(f"{url} returned {response.status}: {(await response.text())[:300]}")
        data = await response.json()
    if trace:
        trace_output.response(response.status, data, (time.monotonic() - started) * 1000)
    return data


def _env() -> dict[str, str | None]:
    env = {name: os.environ.get(name) for name in FORWARDED_ENV}
    return {name: to_wire(value) if value else value for name, value in env.items()}


def wsl_distro(home: Path) -> str | None:
    """The distro of a WSL home (``\\\\wsl.localhost\\<distro>\\...``) on Windows."""
    if sys.platform != "win32":
        return None
    server, _, share = PureWindowsPath(home).drive.lstrip("\\").partition("\\")
    return share if server.lower() in ("wsl.localhost", "wsl$") and share else None


def homes(all_users: bool) -> list[dict[str, Any]]:
    """The homes legacy would scan, in its order. With ``all_users`` on Windows this
    includes WSL homes (``//wsl.localhost/<distro>/home/<user>``)."""
    out = []
    for home, username in get_readable_home_directories(all_users=all_users):
        entry: dict[str, Any] = {"username": username, "home": home.as_posix(), "own": is_own_home(home)}
        distro = wsl_distro(home)
        if distro:
            entry["wsl_distro"] = distro
        out.append(entry)
    return out


async def run_remote_discovery(
    backend_url: str,
    *,
    scope: str = "all",
    agents: list[str] | None = None,
    push_key: str | None = None,
    cli_version: str | None = None,
    all_users: bool = False,
    trace: bool = False,
) -> RemoteResult:
    started = time.monotonic()
    base = backend_url.rstrip("/") + "/hidden/coding-agent-discovery/sessions"
    headers = {"X-Push-Key": push_key} if push_key else {}
    init = {
        "client": {"os": sys.platform, "cli_version": cli_version},
        "homes": homes(all_users),
        "env": _env(),
        "cwd": to_wire(os.getcwd()),
        "scope": scope,
        "agents": agents or [],
    }
    result = RemoteResult()
    timeout = aiohttp.ClientTimeout(total=120)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        response = await _post(session, base, init, headers, result, trace)
        result.session_id = response["session_id"]
        result.supported_agents = response.get("supported_agents", [])
        while True:
            result.add(response["found"])
            result.partial = result.partial or response.get("partial", False)
            if response["done"]:
                break
            if result.rounds >= MAX_ROUNDS:
                raise RemoteDiscoveryError("too many rounds")
            ops = response["ops"]
            step = {"round": response["round"], "results": [run_op(op) for op in ops]}
            result.rounds += 1
            result.ops += len(ops)
            response = await _post(session, f"{base}/{result.session_id}/steps", step, headers, result, trace)
    result.duration_s = time.monotonic() - started
    return result
