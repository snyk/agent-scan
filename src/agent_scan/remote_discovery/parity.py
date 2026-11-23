"""Shadow-mode comparison of local and remote discovery, sent in ``scan_metadata``.

Only stable values go in, so the metadata stays the same across scans of an unchanged
machine. Timings and session IDs stay out.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any

from agent_scan.models import ClientToInspect, StdioServer

MAX_LISTED = 50

WSL_SHARES = ("//wsl.localhost/", "//wsl$/")

# (client name, username, "mcp_config" | "skills_dir", path)
Key = tuple[str, str | None, str, str]


@dataclass
class LocalPhaseKeys:
    """Keys from the well-known table and from discoverers, for agents that have a discoverer."""

    well_known: set[Key] = field(default_factory=set)
    discoverers: set[Key] = field(default_factory=set)

    def expected_only_local(self) -> set[Key]:
        # The backend reproduces the discoverers, not the table's extras for those agents.
        return self.well_known - self.discoverers


def client_keys(client: ClientToInspect) -> set[Key]:
    return {(client.name, client.username, "mcp_config", k) for k in client.mcp_configs} | {
        (client.name, client.username, "skills_dir", k) for k in client.skills_dirs
    }


def counts(clients: list[ClientToInspect]) -> dict[str, int]:
    return {
        "clients": len(clients),
        "mcp_configs": sum(len(c.mcp_configs) for c in clients),
        "mcp_servers": sum(len(v) for c in clients for v in c.mcp_configs.values() if isinstance(v, list)),
        "skills_dirs": sum(len(c.skills_dirs) for c in clients),
    }


def _values(clients: list[ClientToInspect]) -> tuple[dict[Key, Any], int]:
    """Values by key, plus how many repeated keys were dropped. The first value wins:
    discoverers merge into the first client of a (name, username), so a later repeat
    is a well-known table entry for another home (say, a WSL home with the same username)."""
    out: dict[Key, Any] = {}
    repeats = 0
    for client in clients:
        for key, value in client.mcp_configs.items():
            k: Key = (client.name, client.username, "mcp_config", key)
            if k in out:
                repeats += 1
                continue
            out[k] = _dump_config(value)
        for key, skills in client.skills_dirs.items():
            k = (client.name, client.username, "skills_dir", key)
            if k in out:
                repeats += 1
                continue
            dumped = (
                [s.model_dump(mode="json") for s in skills]
                if isinstance(skills, list)
                else skills.model_dump(mode="json")
            )
            out[k] = _strip_traceback(dumped)
    return out, repeats


def _dump_config(value: Any) -> Any:
    if not isinstance(value, list):
        return _strip_traceback(value.model_dump(mode="json"))
    dumped = []
    for name, server in value:
        server_json = server.model_dump(mode="json")
        if isinstance(server, StdioServer) and server.runtime_command is not None:
            server_json["runtime"] = [server.runtime_command, server.runtime_cwd]
        dumped.append([name, server_json])
    return dumped


def _strip_traceback(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_traceback(v) for k, v in value.items() if k != "traceback"}
    if isinstance(value, list):
        return [_strip_traceback(v) for v in value]
    return value


def backend_only_expected(path: str) -> bool:
    """Paths only the backend scans: inside WSL distros, and Cursor's remote server."""
    wire = path.replace("\\", "/")
    return wire.lower().startswith(("//wsl.localhost/", "//wsl$/")) or "/.cursor-server" in wire


def _wsl_roots(homes: Sequence[tuple[PurePath, str]]) -> dict[str, list[str]]:
    """``//wsl.localhost/<distro>`` of each username's WSL homes."""
    roots: dict[str, list[str]] = {}
    for home, username in homes:
        parts = home.as_posix().split("/")
        if len(parts) > 3 and f"//{parts[2]}/".lower() in WSL_SHARES:
            root = "/".join(parts[:4])
            if root not in roots.setdefault(username, []):
                roots[username].append(root)
    return roots


def _wsl_key(key: Key, roots: dict[str, list[str]], remote: dict[Key, Any]) -> Key:
    """A local key holding a Linux path from a WSL home's config, in the backend's
    ``//wsl.localhost/<distro>/...`` form. With several distros, the one the backend
    reported wins."""
    name, username, kind, path = key
    candidates = roots.get(username) if username is not None else None
    if not candidates or not path.startswith("/") or path.startswith("//"):
        return key
    mapped = [(name, username, kind, f"{root}/{path.lstrip('/')}") for root in candidates]
    return next((m for m in mapped if m in remote), mapped[0])


def _listed(keys: set[Key]) -> list[dict[str, str]]:
    return [{"client": k[0], "kind": k[2], "path": k[3]} for k in sorted(keys, key=lambda k: (k[0], k[2], k[3]))]


def compare(
    local: list[ClientToInspect],
    remote: list[ClientToInspect],
    supported_agents: list[str],
    phase_keys: LocalPhaseKeys,
    homes: Sequence[tuple[PurePath, str]] | None = None,
) -> dict[str, Any]:
    """Key-level diff over the agents the backend supports, with expected extras counted apart.

    ``homes`` are the scanned homes; local keys in their WSL homes are compared in the
    backend's ``//wsl.localhost/...`` form."""
    supported = set(supported_agents)
    raw_local, repeats = _values([c for c in local if c.name in supported])
    remote_values, _ = _values(remote)
    expected_only_local = phase_keys.expected_only_local()
    roots = _wsl_roots(homes or [])
    local_values: dict[Key, Any] = {}
    if roots:
        for key, value in raw_local.items():
            local_values.setdefault(_wsl_key(key, roots, remote_values), value)
        expected_only_local = {_wsl_key(k, roots, remote_values) for k in expected_only_local}
    else:
        local_values = raw_local
    only_local = set(local_values) - set(remote_values)
    only_remote = set(remote_values) - set(local_values)
    expected_local = only_local & expected_only_local
    expected_remote = {k for k in only_remote if backend_only_expected(k[3])}
    only_local -= expected_local
    only_remote -= expected_remote
    mismatched = {k for k in set(local_values) & set(remote_values) if local_values[k] != remote_values[k]}
    listed = {
        "only_local": _listed(only_local),
        "only_remote": _listed(only_remote),
        "content_mismatch": _listed(mismatched),
    }
    result: dict[str, Any] = {
        "comparison": "different" if only_local or only_remote or mismatched else "identical",
        "expected_only_local": len(expected_local),
        "expected_only_remote": len(expected_remote),
    }
    if repeats:
        result["local_repeated_keys"] = repeats
    for name, entries in listed.items():
        if entries:
            result[name] = entries[:MAX_LISTED]
            result[f"{name}_count"] = len(entries)
    return result
