"""Drive one discovery session: init, then run ops and post results until the backend is done."""

import asyncio
import json
import logging
import os
import random
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

import aiohttp

from agent_scan.agents.base import is_own_home
from agent_scan.machine_auth import TENANT_API_VERSION, MachineAuth
from agent_scan.remote_discovery.executor import run_op, to_wire
from agent_scan.utils import get_readable_home_directories
from agent_scan.verify_api import RETRYABLE_TRANSPORT_EXCEPTIONS, setup_tcp_connector

logger = logging.getLogger(__name__)

# The gateway 404s /hidden routes without a version; this is the service's published spec version.
DISCOVERY_API_VERSION = "2025-09-02"
MAX_ROUNDS = 25
MAX_RETRIES = 3
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})
# Per request; the backend's own session deadline is 600 s.
REQUEST_TIMEOUT_S = 60
MAX_RETRY_DELAY_S = 10.0
# New sessions started after the backend lost one, e.g. when the machine slept past its TTL.
MAX_RESTARTS = 1


class RemoteDiscoveryError(Exception):
    def __init__(self, message: str, reason: str, status: int | None = None) -> None:
        super().__init__(message)
        # Bounded label for scan metadata, e.g. ``http_503``.
        self.reason = reason
        self.status = status


class _SessionLost(Exception):
    """A step got 404: the backend no longer has the session."""

    def __init__(self, error: RemoteDiscoveryError) -> None:
        super().__init__(str(error))
        self.error = error


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
    retries: int = 0
    restarts: int = 0

    def add(self, found: dict[str, list[dict[str, Any]]]) -> None:
        for name in self.found:
            self.found[name].extend(found.get(name, []))

    def reset_session(self) -> None:
        """Drop what the lost session returned; request counters keep counting."""
        fresh = RemoteResult()
        self.session_id, self.found, self.supported_agents = "", fresh.found, []
        self.partial, self.rounds = False, 0


async def _post(
    session: aiohttp.ClientSession,
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    result: RemoteResult,
) -> dict[str, Any]:
    """POST with retries on 429/5xx, timeouts and connection errors.

    Resending the same bytes is safe: the backend replays a step it has already applied.
    """
    body = json.dumps(payload).encode()
    for attempt in range(MAX_RETRIES + 1):
        result.bytes_sent += len(body)
        retry_after: float | None = None
        try:
            async with session.post(
                url, data=body, headers={**headers, "Content-Type": "application/json"}
            ) as response:
                if response.status < 400:
                    return await response.json()
                if response.status not in RETRYABLE_STATUSES or attempt == MAX_RETRIES:
                    # Detail only: bounded reason strings, never request content.
                    raise RemoteDiscoveryError(
                        f"{url} returned {response.status}: {(await response.text())[:300]}",
                        f"http_{response.status}",
                        response.status,
                    )
                retry_after = _retry_after(response.headers.get("Retry-After"))
        except RETRYABLE_TRANSPORT_EXCEPTIONS:
            if attempt == MAX_RETRIES:
                raise
        result.retries += 1
        await asyncio.sleep(_retry_delay(attempt, retry_after))
    raise AssertionError("unreachable")


def _retry_after(value: str | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None


def _retry_delay(attempt: int, retry_after: float | None) -> float:
    """Retry-After when given, else 1 s, 2 s, 4 s with jitter so a fleet doesn't retry in step."""
    delay = retry_after if retry_after is not None else 2**attempt * random.uniform(0.75, 1.25)
    return min(max(delay, 0.0), MAX_RETRY_DELAY_S)


async def _run_ops(ops: list[dict[str, Any]], cancel: threading.Event) -> list[dict[str, Any]]:
    """Run ops off the event loop, so a caller's timeout can stop a long find or read."""
    try:
        return await asyncio.to_thread(lambda: [run_op(op, cancel) for op in ops])
    except asyncio.CancelledError:
        cancel.set()
        raise


def wsl_distro(home: Path) -> str | None:
    """The distro of a WSL home (``\\\\wsl.localhost\\<distro>\\...``) on Windows."""
    if sys.platform != "win32":
        return None
    server, _, share = PureWindowsPath(home).drive.lstrip("\\").partition("\\")
    return share if server.lower() in ("wsl.localhost", "wsl$") and share else None


def homes(all_users: bool, home_dirs_with_users: list[tuple[Path, str]] | None = None) -> list[dict[str, Any]]:
    """The homes legacy would scan, in its order. With ``all_users`` on Windows this
    includes WSL homes (``//wsl.localhost/<distro>/home/<user>``). Looked up unless
    ``home_dirs_with_users`` is given."""
    if home_dirs_with_users is None:
        home_dirs_with_users = get_readable_home_directories(all_users=all_users)
    out = []
    for home, username in home_dirs_with_users:
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
    identifier: str | None = None,
    all_users: bool = False,
    skip_ssl_verify: bool = False,
    machine_auth: MachineAuth | None = None,
    home_dirs_with_users: list[tuple[Path, str]] | None = None,
) -> RemoteResult:
    """Run one discovery session.

    With ``machine_auth`` the session runs on the tenant routes of its Snyk API
    with the machine token, and ``backend_url`` and ``push_key`` are unused.
    """
    started = time.monotonic()
    if machine_auth is not None:
        base = machine_auth.tenant_path("/coding-agent-discovery/sessions")
        query = f"?version={TENANT_API_VERSION}"
        headers = machine_auth.headers
    else:
        base = backend_url.rstrip("/") + "/hidden/coding-agent-discovery/sessions"
        query = f"?version={DISCOVERY_API_VERSION}"
        headers = {"X-Push-Key": push_key} if push_key else {}
    home_list = homes(all_users, home_dirs_with_users)
    if not home_list:
        # The backend rejects an empty homes list, and local discovery finds nothing either.
        logger.info("Remote discovery skipped: no readable home directories.")
        return RemoteResult(duration_s=time.monotonic() - started)
    init = {
        "client": {"os": sys.platform, "cli_version": cli_version, "identifier": identifier},
        "homes": home_list,
        "cwd": to_wire(os.getcwd()),
        "scope": scope,
        "agents": agents or [],
    }
    result = RemoteResult()
    cancel = threading.Event()
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_S)
    async with aiohttp.ClientSession(
        timeout=timeout, connector=setup_tcp_connector(skip_ssl_verify), trust_env=True
    ) as session:
        for attempt in range(MAX_RESTARTS + 1):
            try:
                await _run_session(session, base, query, init, headers, result, cancel)
                break
            except _SessionLost as lost:
                if attempt == MAX_RESTARTS:
                    raise lost.error from None
                logger.info("Remote discovery session was lost; starting a new one.")
                result.reset_session()
                result.restarts += 1
    result.duration_s = time.monotonic() - started
    return result


async def _run_session(
    session: aiohttp.ClientSession,
    base: str,
    query: str,
    init: dict[str, Any],
    headers: dict[str, str],
    result: RemoteResult,
    cancel: threading.Event,
) -> None:
    response = await _post(session, base + query, init, headers, result)
    result.session_id = response["session_id"]
    result.supported_agents = response.get("supported_agents", [])
    while True:
        result.add(response["found"])
        result.partial = result.partial or response.get("partial", False)
        if response["done"]:
            return
        if result.rounds >= MAX_ROUNDS:
            raise RemoteDiscoveryError("too many rounds", "too_many_rounds")
        ops = response["ops"]
        step = {"round": response["round"], "results": await _run_ops(ops, cancel)}
        result.rounds += 1
        result.ops += len(ops)
        try:
            response = await _post(session, f"{base}/{result.session_id}/steps{query}", step, headers, result)
        except RemoteDiscoveryError as error:
            # Steps only: an init 404 means the route is missing, not the session.
            if error.status == 404:
                raise _SessionLost(error) from error
            raise
