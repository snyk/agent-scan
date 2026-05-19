"""
Install/uninstall the MCP stdio shim into discovered client configs.

The shim wraps each stdio server's command so that the JSON-RPC response
containing tool definitions is captured to a file in /tmp.  The scanner
can later read those files to obtain tool signatures without starting
the servers itself.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pyjson5

from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import StdioServer

logger = logging.getLogger(__name__)

SHIM_SCRIPT_UNIX = Path(__file__).parent / "snyk_mcp_stdio_local_proxy.sh"
SHIM_SCRIPT_WINDOWS = Path(__file__).parent / "snyk_mcp_stdio_local_proxy.cmd"
SHIM_MARKER = "snyk_mcp_stdio_local_proxy"


def _get_shim_path() -> Path:
    if sys.platform == "win32":
        return SHIM_SCRIPT_WINDOWS
    return SHIM_SCRIPT_UNIX


def _is_shimmed_raw(server: dict) -> bool:
    return SHIM_MARKER in server.get("command", "")


async def _get_stdio_server_names(config_path: str) -> set[str]:
    """Use the project's config parser to find which servers are stdio."""
    try:
        mcp_config = await scan_mcp_config_file(config_path)
        return {name for name, server in mcp_config.get_servers().items() if isinstance(server, StdioServer)}
    except Exception:
        logger.exception("Failed to parse config via scan_mcp_config_file: %s", config_path)
        return set()


def _resolve_servers(config: dict) -> dict | None:
    """Walk into config and return the raw servers dict."""
    for key_path in [["mcpServers"], ["servers"], ["mcp", "servers"]]:
        node: dict | None = config
        for key in key_path:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                node = None
                break
        if isinstance(node, dict) and node:
            return node

    projects = config.get("projects")
    if isinstance(projects, dict):
        for proj in projects.values():
            if isinstance(proj, dict) and "mcpServers" in proj:
                return proj["mcpServers"]

    return None


async def install_shim_into_config(config_path: str) -> list[str]:
    """
    Install the shim into a single config file.
    Returns a list of server names that were shimmed.
    """
    path = Path(config_path).expanduser()
    if not path.exists():
        logger.warning("Config file not found: %s", path)
        return []

    shim_script = _get_shim_path()
    shim_path = str(shim_script.resolve())
    if not shim_script.exists():
        logger.error("Shim script not found: %s", shim_path)
        return []

    stdio_names = await _get_stdio_server_names(config_path)
    if not stdio_names:
        return []

    try:
        raw = path.read_text(encoding="utf-8")
        config = pyjson5.loads(raw) if raw.strip() else {}
    except Exception:
        logger.exception("Failed to parse config: %s", path)
        return []

    servers = _resolve_servers(config)
    if not servers:
        return []

    shimmed: list[str] = []
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        if name not in stdio_names:
            continue
        if _is_shimmed_raw(server):
            continue

        old_command = server.get("command", "")
        old_args = server.get("args", [])
        server["command"] = shim_path
        server["args"] = [old_command] + (old_args or [])
        shimmed.append(name)

    if not shimmed:
        return []

    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return shimmed


async def uninstall_shim_from_config(config_path: str) -> list[str]:
    """
    Remove the shim from a single config file.
    Returns a list of server names that were unshimmed.
    """
    path = Path(config_path).expanduser()
    if not path.exists():
        return []

    try:
        raw = path.read_text(encoding="utf-8")
        config = pyjson5.loads(raw) if raw.strip() else {}
    except Exception:
        logger.exception("Failed to parse config: %s", path)
        return []

    servers = _resolve_servers(config)
    if not servers:
        return []

    unshimmed: list[str] = []
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        if not _is_shimmed_raw(server):
            continue
        args = server.get("args", [])
        if not args:
            logger.warning("%s is shimmed but has no args", name)
            continue
        server["command"] = args[0]
        server["args"] = args[1:]
        unshimmed.append(name)

    if not unshimmed:
        return []

    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return unshimmed


def _get_shim_log_dir() -> Path:
    if sys.platform == "win32":
        import tempfile

        return Path(tempfile.gettempdir())
    return Path("/tmp")


class ServerCapture:
    """Captured capabilities for a single server."""

    def __init__(self) -> None:
        self.tools: list[dict] = []
        self.prompts: list[dict] = []
        self.resources: list[dict] = []
        self.resource_templates: list[dict] = []


def read_signatures() -> dict[str, ServerCapture]:
    """
    Read captured signatures from shim log files.
    Returns a dict mapping server hash -> ServerCapture.
    """
    tmp = _get_shim_log_dir()
    log_files = list(tmp.glob("snyk_mcp_stdio_local_proxy.*"))

    if not log_files:
        return {}

    by_hash: dict[str, list[Path]] = {}
    for f in log_files:
        parts = f.name.split(".")
        if len(parts) >= 3:
            by_hash.setdefault(parts[1], []).append(f)

    results: dict[str, ServerCapture] = {}
    for h, files in by_hash.items():
        best = max(files, key=lambda p: (p.stat().st_size, p.stat().st_mtime))
        capture = ServerCapture()
        content = best.read_text().strip()
        if content:
            for line in content.splitlines():
                try:
                    data = json.loads(line)
                    result = data.get("result", data)
                    if "tools" in result:
                        capture.tools = result["tools"]
                    if "prompts" in result:
                        capture.prompts = result["prompts"]
                    if "resources" in result:
                        capture.resources = result["resources"]
                    if "resourceTemplates" in result:
                        capture.resource_templates = result["resourceTemplates"]
                except json.JSONDecodeError:
                    pass
        results[h] = capture

    return results
