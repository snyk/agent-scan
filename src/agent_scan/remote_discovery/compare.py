"""Compare legacy discovery with backend discovery for the agents the backend supports.

The diff is raw: the backend must reproduce legacy output exactly, duplicates included.
Client order is not compared; clients are matched by name and username.

The backend also finds things legacy misses (WSL folders, ``~/.cursor-server``). Those
are reported apart as expected; anything else that differs is a failure.
"""

import time
from dataclasses import dataclass, field
from typing import Any

from agent_scan.agents import DiscoveryScope
from agent_scan.models import ClientToInspect
from agent_scan.pipelines import InspectArgs, discover_clients_to_inspect


def _strip_traceback(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_traceback(v) for k, v in value.items() if k != "traceback"}
    if isinstance(value, list):
        return [_strip_traceback(v) for v in value]
    return value


def comparable(clients: list[ClientToInspect]) -> list[dict[str, Any]]:
    dumped = [_strip_traceback(c.model_dump(mode="json")) for c in clients]
    return sorted(dumped, key=lambda c: (c["name"], c["username"] or ""))


async def legacy_clients(scope: str, agents: list[str], all_users: bool = False) -> tuple[list[ClientToInspect], float]:
    started = time.monotonic()
    clients, _unresolved, _usernames = await discover_clients_to_inspect(
        InspectArgs(timeout=10, tokens=[], paths=[], discovery_scope=DiscoveryScope(scope), all_users=all_users)
    )
    return [c for c in clients if c.name in agents], time.monotonic() - started


def backend_only_expected(path: str) -> bool:
    """Paths only the backend scans: inside WSL distros, and Cursor's remote server."""
    wire = path.replace("\\", "/")
    return wire.lower().startswith(("//wsl.localhost/", "//wsl$/")) or "/.cursor-server" in wire


@dataclass
class Diff:
    unexpected: list[str] = field(default_factory=list)
    expected: list[str] = field(default_factory=list)


def _diff_maps(kind: str, legacy: dict[str, Any], remote: dict[str, Any], out: Diff, header: list[str]) -> None:
    def fail(line: str) -> None:
        # The client header is printed once, before its first failure.
        out.unexpected.extend([*header, line])
        header.clear()

    for key in sorted(set(legacy) | set(remote)):
        if key not in remote:
            fail(f"  {kind} only in legacy: {key}")
        elif key not in legacy:
            if backend_only_expected(key):
                out.expected.append(f"  {kind} only in remote: {key}")
            else:
                fail(f"  {kind} only in remote: {key}")
        elif legacy[key] != remote[key]:
            fail(f"  {kind} differs: {key}\n    legacy: {legacy[key]}\n    remote: {remote[key]}")


def diff(legacy: list[dict[str, Any]], remote: list[dict[str, Any]]) -> Diff:
    """Differences split into unexpected (parity failures) and expected backend extras."""
    out = Diff()
    if legacy == remote:
        return out
    legacy_by_name = {(c["name"], c["username"]): c for c in legacy}
    remote_by_name = {(c["name"], c["username"]): c for c in remote}
    for name in sorted(set(legacy_by_name) - set(remote_by_name), key=str):
        out.unexpected.append(f"client only in legacy: {name}")
    for name in sorted(set(remote_by_name) - set(legacy_by_name), key=str):
        line = f"client only in remote: {name} at {remote_by_name[name]['client_path']}"
        (out.expected if backend_only_expected(remote_by_name[name]["client_path"]) else out.unexpected).append(line)
    for name, client in legacy_by_name.items():
        other = remote_by_name.get(name)
        if other is None:
            continue
        header = [f"client {client['name']} ({client['username']}):"]
        if client["client_path"] != other["client_path"]:
            out.unexpected.extend(
                [*header, f"  client_path legacy={client['client_path']} remote={other['client_path']}"]
            )
            header.clear()
        _diff_maps("mcp_config", client["mcp_configs"], other["mcp_configs"], out, header)
        _diff_maps("skills_dir", client["skills_dirs"], other["skills_dirs"], out, header)
    return out
