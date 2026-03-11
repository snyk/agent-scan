"""
Scans MCP servers directly from package or URL.
"""

import tempfile
from collections.abc import Callable, Coroutine
from typing import Any

from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import MCPConfig, RemoteServer, StdioServer

SUPPORTED_TYPES = ["streamable-https", "streamable-http", "sse", "pypi", "npm", "oci", "nuget", "mcpb"]


def is_direct_scan(path: str) -> bool:
    return any(path.startswith(f"{t}:") for t in SUPPORTED_TYPES)


def _parse_direct_scan(path: str) -> tuple[str, str]:
    scan_type = path.split(":")[0]
    value = path[len(scan_type) + 1 :]
    return scan_type, value


def _parse_package_name_version(value: str) -> tuple[str, str]:
    """Split a package specifier into (name, version), handling scoped packages like @scope/pkg@version."""
    if "@" in value.lstrip("@"):
        name, version = value.rsplit("@", 1)
        return name, version
    return value, "latest"


def direct_scan_to_server_config(path: str) -> tuple[str, StdioServer | RemoteServer]:
    """Parse a direct scan path and return (server_name, server_config)."""
    scan_type, value = _parse_direct_scan(path)

    if scan_type == "streamable-https":
        return ("http-mcp-server", RemoteServer(url=f"https://{value}"))
    elif scan_type == "streamable-http":
        return ("http-mcp-server", RemoteServer(url=f"http://{value}"))
    elif scan_type == "sse":
        return ("sse-mcp-server", RemoteServer(url=value, type="sse"))
    elif scan_type == "npm":
        name, version = _parse_package_name_version(value)
        return (name, StdioServer(command="npx", args=["-y", f"{name}@{version}"]))
    elif scan_type == "pypi":
        name, version = _parse_package_name_version(value)
        return (name, StdioServer(command="uvx", args=[f"{name}@{version}"]))
    elif scan_type == "oci":
        return (value, StdioServer(command="docker", args=["run", "-i", "--rm", value]))
    else:
        raise ValueError(f"Unsupported direct scan type: {scan_type}")


async def scan_streamable_https(url: str, secure=True):
    config_file = f"""
{{
    "mcpServers": {{
        "http-mcp-server": {{
            "url": "http{"s" if secure else ""}://{url}"
        }}
    }}
}}
    """

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(config_file.encode())
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


async def scan_streamable_http(url: str):
    return await scan_streamable_https(url, secure=False)


async def scan_npm(package_name: str):
    name, version = _parse_package_name_version(package_name)

    config_file = f"""{{
    "mcpServers": {{
        "{name}": {{
            "command": "npx",
            "args": [
                "-y",
                "{name}@{version}"
            ],
            "type": "stdio",
            "env": {{}}
        }}
    }}
}}"""

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(config_file.encode())
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


async def scan_pypi(package_name: str):
    name, version = _parse_package_name_version(package_name)
    config_file = f"""{{
    "mcpServers": {{
        "{name}": {{
            "command": "uvx",
            "args": [
                "{name}@{version}"
            ],
            "type": "stdio",
            "env": {{}}
        }}
    }}
}}"""

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(config_file.encode())
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


async def scan_oci(oci_url: str):
    config_file = f"""{{
    "mcpServers": {{
        "{oci_url}": {{
            "command": "docker",
            "args": [
                "run", "-i", "--rm",
                "{oci_url}"
            ],
            "type": "stdio",
            "env": {{}}
        }}
    }}
}}"""

    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(config_file.encode())
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


SCANNERS: dict[str, Callable[..., Coroutine[Any, Any, MCPConfig]]] = {
    "streamable-https": scan_streamable_https,
    "streamable-http": scan_streamable_http,
    "npm": scan_npm,
    "pypi": scan_pypi,
    "oci": scan_oci,
}


async def direct_scan(path: str):
    """
    Scans an MCP server directly from a package or URL.
    """
    scan_type = path.split(":")[0]
    if scan_type not in SCANNERS:
        raise ValueError(f"Unsupported scan type: {scan_type}")

    return await SCANNERS[scan_type](path[len(scan_type) + 1 :])
