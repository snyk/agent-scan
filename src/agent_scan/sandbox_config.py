"""Build the effective MCP config used inside the execution sandbox.

Every stdio server entry gets HTTP_PROXY/HTTPS_PROXY/NO_PROXY merged into its
``env``. This matters because the MCP SDK's stdio transport
(``mcp.client.stdio.stdio_client``) spawns each server with a curated
environment -- ``HOME``, ``LOGNAME``, ``PATH``, ``SHELL``, ``TERM``, ``USER``
only, from ``get_default_environment()`` -- merged with ``server.env`` if
set. The sandbox container's own ``HTTP_PROXY`` never reaches the spawned
server process unless it's explicitly present in that server's ``env``, and
the sandbox's Docker network has no route out except through the egress
proxy, so an un-proxied server simply can't reach the network at all.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agent_scan.direct_scanner import direct_scan_to_server_config, is_direct_scan
from agent_scan.models import StdioServer

if TYPE_CHECKING:
    from pathlib import Path

DEFAULT_NO_PROXY = "localhost,127.0.0.1"


def _inject_proxy_env(
    server: StdioServer, proxy_url: str, no_proxy: str, extra_env: dict[str, str] | None = None
) -> StdioServer:
    proxy_vars = {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "NO_PROXY": no_proxy,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "no_proxy": no_proxy,
    }
    # Precedence, lowest to highest: the server's own config env, then the operator's
    # --env overrides, then the injected proxy vars. The proxy vars must win on
    # collision -- a client-supplied env (or an operator's own --env) that sets its
    # own HTTP_PROXY/HTTPS_PROXY/NO_PROXY (accidentally or maliciously) must not be
    # able to override the containment control by being spread last.
    merged_env = {**(server.env or {}), **(extra_env or {}), **proxy_vars}
    return server.model_copy(update={"env": merged_env})


def build_sandbox_config(
    target: str,
    proxy_url: str,
    *,
    input_dir: Path | None = None,
    no_proxy: str = DEFAULT_NO_PROXY,
    extra_env: dict[str, str] | None = None,
) -> dict:
    """Return an ``{"mcpServers": {...}}`` dict ready to write into the sandbox mount.

    ``target`` is either a direct-scan prefixed string (``npm:...``,
    ``pypi:...``) or a path relative to ``input_dir`` pointing at the
    client-supplied config file. ``extra_env`` (from ``sandbox-scan --env``)
    is merged into every stdio server's env for either target type -- direct-scan
    targets otherwise have no way to receive credentials a real server might need
    (e.g. an API token), since ``direct_scan_to_server_config()`` never sets ``env``.
    """
    if is_direct_scan(target):
        if target.startswith(("oci:", "nuget:", "mcpb:")):
            raise ValueError(
                "oci:/nuget:/mcpb: targets aren't supported by sandbox-scan yet "
                "(oci: needs nested Docker, nuget:/mcpb: aren't implemented, in this phase)"
            )
        name, server = direct_scan_to_server_config(target)
        if isinstance(server, StdioServer):
            server = _inject_proxy_env(server, proxy_url, no_proxy, extra_env)
        return {"mcpServers": {name: server.model_dump(exclude_none=True)}}

    if input_dir is None:
        raise ValueError("input_dir is required when target is not a direct-scan prefix (npm:/pypi:)")

    config_path = input_dir / target
    resolved_config_path = config_path.resolve()
    resolved_input_dir = input_dir.resolve()
    if not resolved_config_path.is_relative_to(resolved_input_dir):
        raise ValueError(f"target must resolve to a path inside input_dir, got {resolved_config_path}")

    try:
        config = json.loads(resolved_config_path.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"could not read config at {resolved_config_path}: {e}") from e
    servers = config.get("mcpServers", {})
    for name, raw in servers.items():
        if "command" in raw:
            stdio = StdioServer.model_validate(raw)
            servers[name] = _inject_proxy_env(stdio, proxy_url, no_proxy, extra_env).model_dump(exclude_none=True)
    return config
