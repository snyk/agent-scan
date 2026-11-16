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
from agent_scan.remote_discovery.executor import run_op, to_wire
from agent_scan.utils import get_readable_home_directories
from agent_scan.verify_api import setup_tcp_connector

MAX_ROUNDS = 25


class RemoteDiscoveryError(Exception):
    def __init__(self, message: str, reason: str) -> None:
        super().__init__(message)
        # Bounded label for scan metadata, e.g. ``http_503``.
        self.reason = reason


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
) -> dict[str, Any]:
    body = json.dumps(payload).encode()
    result.bytes_sent += len(body)
    async with session.post(url, data=body, headers={**headers, "Content-Type": "application/json"}) as response:
        if response.status >= 400:
            # Detail only: bounded reason strings, never request content.
            raise RemoteDiscoveryError(
                f"{url} returned {response.status}: {(await response.text())[:300]}", f"http_{response.status}"
            )
        data = await response.json()
    return data


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
    skip_ssl_verify: bool = False,
) -> RemoteResult:
    started = time.monotonic()
    base = backend_url.rstrip("/") + "/hidden/coding-agent-discovery/sessions"
    headers = {"X-Push-Key": push_key} if push_key else {}
    init = {
        "client": {"os": sys.platform, "cli_version": cli_version},
        "homes": homes(all_users),
        "cwd": to_wire(os.getcwd()),
        "scope": scope,
        "agents": agents or [],
    }
    result = RemoteResult()
    timeout = aiohttp.ClientTimeout(total=120)
    async with aiohttp.ClientSession(
        timeout=timeout, connector=setup_tcp_connector(skip_ssl_verify), trust_env=True
    ) as session:
        response = await _post(session, base, init, headers, result)
        result.session_id = response["session_id"]
        result.supported_agents = response.get("supported_agents", [])
        while True:
            result.add(response["found"])
            result.partial = result.partial or response.get("partial", False)
            if response["done"]:
                break
            if result.rounds >= MAX_ROUNDS:
                raise RemoteDiscoveryError("too many rounds", "too_many_rounds")
            ops = response["ops"]
            step = {"round": response["round"], "results": [run_op(op) for op in ops]}
            result.rounds += 1
            result.ops += len(ops)
            response = await _post(session, f"{base}/{result.session_id}/steps", step, headers, result)
    result.duration_s = time.monotonic() - started
    return result
