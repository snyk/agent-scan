"""Turn the backend's ``found`` items into the same ``ClientToInspect`` list that
``pipelines.discover_clients_to_inspect`` builds.

The backend did all file parsing; this only validates server maps with our models and
runs the signature check.
"""

import os
from pathlib import PureWindowsPath
from typing import Any

from pydantic import ValidationError

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


def mcp_value(entry: dict[str, Any]) -> McpValue | None:
    """First candidate that validates wins, else the fallback. ``None`` drops the entry."""
    for candidate in entry.get("candidates", []):
        servers = _servers(candidate)
        if servers is None:
            continue
        result = [
            (name, check_server_signature(server) if isinstance(server, StdioServer) else server)
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


def build_clients(found: dict[str, list[dict[str, Any]]]) -> list[ClientToInspect]:
    """One ``ClientToInspect`` per (client, username), in the backend's order. Entries are
    applied in order and the last one for a key wins, like the pipeline's dict merges. A
    dropped entry (``skip_if_empty``) doesn't overwrite an earlier one."""
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
    for entry in found["mcp_configs"]:
        client = out.get((entry["client"], entry.get("username")))
        value = mcp_value(entry)
        if client is not None and value is not None:
            client.mcp_configs[entry["key"]] = value
    for entry in found["skills_dirs"]:
        client = out.get((entry["client"], entry.get("username")))
        if client is not None:
            client.skills_dirs[entry["key"]] = [
                DiscoveredSkill(name=s["name"], path=_native(s["path"])) for s in entry["skills"]
            ]
    return list(out.values())
