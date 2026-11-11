"""Turn the backend's ``found`` items into the same ``ClientToInspect`` list that
``pipelines.discover_clients_to_inspect`` builds.

The backend did all file parsing; this only validates server maps with our models, runs
the signature check and resolves the keys the backend marks ``canonical``.
"""

import os
from pathlib import Path, PureWindowsPath
from typing import Any

from pydantic import ValidationError

from agent_scan.agents.base import _canonicalize_keys
from agent_scan.models import (
    ClientToInspect,
    CouldNotParseMCPConfig,
    DiscoveredSkill,
    MCPServerMap,
    RemoteServer,
    StdioServer,
    UnknownConfigFormat,
)
from agent_scan.signed_binary import check_server_signature

McpValue = list[tuple[str, StdioServer | RemoteServer]] | UnknownConfigFormat | CouldNotParseMCPConfig


def _servers(candidate: dict[str, Any]) -> dict[str, StdioServer | RemoteServer] | None:
    servers: dict[str, StdioServer | RemoteServer] = {}
    try:
        for raw in candidate["maps"]:
            servers.update(MCPServerMap(servers=raw).servers)
    except ValidationError:
        return None
    return servers


def resolve_relative_stdio(raw: Any, roots: list[str]) -> tuple[str, str] | None:
    """``CodexDiscoverer._relative_stdio_candidates``: the ``(executable, cwd)`` when
    exactly one root holds the relative command."""
    if not isinstance(raw, dict):
        return None
    command, cwd = raw.get("command"), raw.get("cwd")
    if not isinstance(command, str) or not command or not isinstance(cwd, str) or not cwd:
        return None
    if Path(command).is_absolute() or ("/" not in command and "\\" not in command):
        return None
    args = raw.get("args")
    if args is not None and (not isinstance(args, list) or not all(isinstance(a, str) for a in args)):
        return None
    cwd_path = Path(cwd)
    found: set[tuple[Path, Path]] = set()
    for raw_root in roots:
        try:
            root = Path(raw_root).resolve()
            workdir = root if cwd_path.is_absolute() else (root / cwd_path).resolve()
            executable = (workdir / command).resolve()
            if executable.is_relative_to(root) and executable.is_file():
                found.add((executable, workdir))
        except (OSError, RuntimeError, ValueError):
            continue
    if len(found) != 1:
        return None
    executable, workdir = found.pop()
    return str(executable), str(workdir)


def _signed(server: StdioServer, raw: Any, roots: list[str] | None) -> StdioServer:
    """The signature check, run on the resolved executable when there is one. The
    configured command and args are kept for the uploaded inventory."""
    resolved = resolve_relative_stdio(raw, roots) if roots else None
    if resolved is None:
        return check_server_signature(server)
    server.command = raw["command"]
    server.args = list(raw.get("args") or [])
    server.set_runtime_context(*resolved)
    return check_server_signature(server, signature_command=resolved[0])


def mcp_value(entry: dict[str, Any]) -> McpValue | None:
    """First candidate that validates wins, else the fallback. ``None`` drops the entry."""
    stdio_roots = entry.get("stdio_roots") or {}
    for candidate in entry.get("candidates", []):
        servers = _servers(candidate)
        if servers is None:
            continue
        raw: dict[str, Any] = {}
        for server_map in candidate["maps"]:
            raw.update(server_map)
        result = [
            (
                name,
                _signed(server, raw.get(name), stdio_roots.get(name)) if isinstance(server, StdioServer) else server,
            )
            for name, server in servers.items()
        ]
        if not result and entry.get("skip_if_empty"):
            return None
        return result
    fallback = entry["fallback"]
    kind = fallback["kind"]
    if kind == "empty":
        return None if entry.get("skip_if_empty") else []
    if kind == "unknown_format":
        return UnknownConfigFormat(message=fallback["message"], is_failure=False)
    return CouldNotParseMCPConfig(message=fallback["message"], traceback="", is_failure=True)


def _native(path: str) -> str:
    """Legacy builds skill paths with ``str(Path)``: backslashes on Windows."""
    return str(PureWindowsPath(path)) if os.name == "nt" else path


def _skills(entry: dict[str, Any]) -> list[DiscoveredSkill]:
    return [DiscoveredSkill(name=s["name"], path=_native(s["path"])) for s in entry["skills"]]


def _merge(entries: list[tuple[dict[str, Any], Any]]) -> dict[str, Any]:
    """Last write wins per key. Entries marked ``canonical`` are then re-keyed like
    ``_canonicalize_keys``."""
    merged: dict[str, Any] = {}
    canonical: set[str] = set()
    for entry, value in entries:
        merged[entry["key"]] = value
        if entry.get("canonical"):
            canonical.add(entry["key"])
    if not canonical:
        return merged
    literal = {k: v for k, v in merged.items() if k not in canonical}
    return {**literal, **_canonicalize_keys({k: v for k, v in merged.items() if k in canonical})}


def build_clients(found: dict[str, list[dict[str, Any]]]) -> list[ClientToInspect]:
    """One ``ClientToInspect`` per (client, username), in the backend's order. A dropped
    entry (``skip_if_empty``) doesn't overwrite an earlier one."""
    out: dict[tuple[str, str | None], ClientToInspect] = {}
    for client in found["clients"]:
        out.setdefault(
            (client["name"], client.get("username")),
            ClientToInspect(
                name=client["name"],
                client_path=client["client_path"],
                username=client.get("username"),
                mcp_configs={},
                skills_dirs={},
            ),
        )
    mcp: dict[tuple[str, str | None], list[tuple[dict[str, Any], Any]]] = {}
    for entry in found["mcp_configs"]:
        value = mcp_value(entry)
        if value is not None:
            mcp.setdefault((entry["client"], entry.get("username")), []).append((entry, value))
    skills: dict[tuple[str, str | None], list[tuple[dict[str, Any], Any]]] = {}
    for entry in found["skills_dirs"]:
        skills.setdefault((entry["client"], entry.get("username")), []).append((entry, _skills(entry)))
    for key, client in out.items():
        client.mcp_configs = _merge(mcp.get(key, []))
        client.skills_dirs = _merge(skills.get(key, []))
    return list(out.values())
