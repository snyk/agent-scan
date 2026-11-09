"""Compare legacy discovery with backend discovery for the agents the backend supports.

The backend must reproduce legacy's discoverers (the pipeline's Phase B) exactly. Client
order is not compared; clients are matched by name and username.

Reported apart as expected:

* what the backend finds and legacy misses (WSL folders, ``~/.cursor-server``);
* what only legacy's well-known client table (Phase A) adds, which the backend drops on
  purpose: duplicates under resolved keys and empty entries.

Anything else that differs is a failure.
"""

import time
from dataclasses import dataclass, field
from typing import Any

from agent_scan.agents import DiscoveryScope, find_discoverers
from agent_scan.inspect import get_mcp_config_per_client
from agent_scan.models import ClientToInspect
from agent_scan.utils import get_readable_home_directories
from agent_scan.well_known_clients import get_well_known_clients


def _strip_traceback(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_traceback(v) for k, v in value.items() if k != "traceback"}
    if isinstance(value, list):
        return [_strip_traceback(v) for v in value]
    return value


def comparable(clients: list[ClientToInspect]) -> list[dict[str, Any]]:
    dumped = [_strip_traceback(c.model_dump(mode="json")) for c in clients]
    return sorted(dumped, key=lambda c: (c["name"], c["username"] or ""))


@dataclass
class Legacy:
    discoverers: list[ClientToInspect]
    well_known: list[ClientToInspect]
    seconds: float


async def legacy_clients(scope: str, agents: list[str], all_users: bool = False) -> Legacy:
    """Legacy's two discovery phases (``discover_clients_to_inspect``), kept apart."""
    started = time.monotonic()
    discovery_scope = DiscoveryScope(scope)
    homes = get_readable_home_directories(all_users=all_users)
    well_known: list[ClientToInspect] = []
    for client in get_well_known_clients():
        if client.name in agents:
            well_known.extend(await get_mcp_config_per_client(client, homes, scope=discovery_scope) or [])
    discoverers: list[ClientToInspect] = []
    for home, username in homes:
        for discoverer in find_discoverers(home, target_folders=[]):
            cti = discoverer.discover(discovery_scope)
            if cti is not None and cti.name in agents:
                cti.username = username
                discoverers.append(cti)
    return Legacy(discoverers, well_known, time.monotonic() - started)


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


def well_known_extras(well_known: list[dict[str, Any]], discoverers: list[dict[str, Any]]) -> list[str]:
    """What only the well-known table adds on top of the discoverers."""
    by_name = {(c["name"], c["username"]): c for c in discoverers}
    lines: list[str] = []
    for client in well_known:
        name = (client["name"], client["username"])
        other = by_name.get(name)
        if other is None:
            lines.append(f"client only in legacy well-known table: {name} at {client['client_path']}")
            continue
        for kind in ("mcp_configs", "skills_dirs"):
            for key in sorted(set(client[kind]) - set(other[kind])):
                lines.append(f"  {kind} only in legacy well-known table: {key}")
    return lines
