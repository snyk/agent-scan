"""
Scans MCP servers directly from package, URL or provided tool signatures.
"""

import json
import tempfile
from collections.abc import Callable, Coroutine
from typing import Any

from mcp.types import Tool

from agent_scan.mcp_client import scan_mcp_config_file
from agent_scan.models import MCPConfig, StaticToolsConfig, StaticToolsServer

SUPPORTED_TYPES = ["streamable-https", "streamable-http", "sse", "pypi", "npm", "oci", "nuget", "mcpb", "tools"]


def is_direct_scan(path: str) -> bool:
    return any(path.startswith(f"{t}:") for t in SUPPORTED_TYPES)


async def scan_streamable_https(url: str, secure=True):
    # Validate URL to prevent injection attacks
    if not url or len(url) > 2048:
        raise ValueError("Invalid URL: URL is empty or too long")
    # Prevent newlines and control characters that could break JSON or enable injection
    if any(c in url for c in ['\n', '\r', '\x00', '\x01', '\x02', '\x03']):
        raise ValueError("Invalid URL: URL contains control characters")

    config = {
        "mcpServers": {
            "http-mcp-server": {
                "url": f"http{'s' if secure else ''}://{url}"
            }
        }
    }
    config_file = json.dumps(config, indent=4)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as tmp:
        tmp.write(config_file)
        tmp.flush()
        print(config_file)
        return await scan_mcp_config_file(tmp.name)


async def scan_streamable_http(url: str):
    return await scan_streamable_https(url, secure=False)


def _validate_package_name(name: str) -> None:
    """Validate package name to prevent injection attacks."""
    if not name or len(name) > 214:  # npm package name max length
        raise ValueError("Invalid package name: name is empty or too long")
    # Prevent control characters and path traversal attempts
    if any(c in name for c in ['\n', '\r', '\x00', '\x01', '\x02', '\x03', '..', '/', '\\']):
        raise ValueError("Invalid package name: contains invalid characters")


def _validate_version(version: str) -> None:
    """Validate version string to prevent injection attacks."""
    if not version:
        raise ValueError("Invalid version: version is empty")
    if len(version) > 100:
        raise ValueError("Invalid version: version is too long")
    # Only allow alphanumeric, dots, hyphens, and underscores (semver-compatible)
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    if not all(c in allowed_chars for c in version):
        raise ValueError("Invalid version: contains invalid characters")


async def scan_npm(package_name: str):
    if "@" in package_name:
        # Handle scoped packages like @scope/name@version
        parts = package_name.rsplit("@", 1)
        if package_name.startswith("@"):
            name = "@" + parts[0][1:]  # Keep the @ for scoped packages
            version = parts[1] if len(parts) > 1 else "latest"
        else:
            name, version = parts[0], parts[1]
    else:
        name, version = package_name, "latest"

    _validate_package_name(name)
    _validate_version(version)

    config = {
        "mcpServers": {
            name: {
                "command": "npx",
                "args": ["-y", f"{name}@{version}"],
                "type": "stdio",
                "env": {}
            }
        }
    }
    config_file = json.dumps(config, indent=4)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as tmp:
        tmp.write(config_file)
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


async def scan_pypi(package_name: str):
    if "@" in package_name:
        name, version = package_name.rsplit("@", 1)
    else:
        name, version = package_name, "latest"

    _validate_package_name(name)
    _validate_version(version)

    config = {
        "mcpServers": {
            name: {
                "command": "uvx",
                "args": [f"{name}@{version}"],
                "type": "stdio",
                "env": {}
            }
        }
    }
    config_file = json.dumps(config, indent=4)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as tmp:
        tmp.write(config_file)
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


def _validate_oci_url(oci_url: str) -> None:
    """Validate OCI URL to prevent injection attacks."""
    if not oci_url or len(oci_url) > 255:
        raise ValueError("Invalid OCI URL: URL is empty or too long")
    # Prevent control characters and shell metacharacters
    if any(c in oci_url for c in ['\n', '\r', '\x00', '\x01', '\x02', '\x03', ';', '&', '|', '$', '`']):
        raise ValueError("Invalid OCI URL: contains invalid characters")
    # Basic OCI reference format validation (registry/repository:tag or registry/repository@digest)
    if oci_url.startswith("/") or oci_url.endswith("/"):
        raise ValueError("Invalid OCI URL: cannot start or end with slash")


async def scan_oci(oci_url: str):
    _validate_oci_url(oci_url)

    config = {
        "mcpServers": {
            oci_url: {
                "command": "docker",
                "args": ["run", "-i", "--rm", oci_url],
                "type": "stdio",
                "env": {}
            }
        }
    }
    config_file = json.dumps(config, indent=4)

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json') as tmp:
        tmp.write(config_file)
        tmp.flush()
        return await scan_mcp_config_file(tmp.name)


async def scan_tools(path: str):
    # check if path starts with '{', if so parse as JSON
    if path.startswith("["):
        raw_tools = json.loads(path)
    else:
        with open(path) as f:
            raw_tools = json.load(f)

    # Expect a list of tool dicts. Construct proper Tool models, preserving schemas.
    tools: list[Tool] = []
    for item in raw_tools:
        # Be defensive about missing keys and default to empty schemas
        tools.append(
            Tool(
                name=item.get("name", "<unnamed-tool>"),
                description=item.get("description"),
                inputSchema=item.get("inputSchema", {}),
                outputSchema=item.get("outputSchema", {}),
                annotations=item.get("annotations"),
                meta=item.get("meta", {}),
            )
        )

    server_name = path if not path.startswith("[") else "<tools>"
    return StaticToolsConfig(signature={server_name: StaticToolsServer(name=server_name, signature=tools)})


SCANNERS: dict[str, Callable[..., Coroutine[Any, Any, MCPConfig]]] = {
    "streamable-https": scan_streamable_https,
    "streamable-http": scan_streamable_http,
    "npm": scan_npm,
    "pypi": scan_pypi,
    "oci": scan_oci,
    "tools": scan_tools,
}


async def direct_scan(path: str):
    """
    Scans an MCP server directly from a package or URL.
    """
    scan_type = path.split(":")[0]
    if scan_type not in SCANNERS:
        raise ValueError(f"Unsupported scan type: {scan_type}")

    return await SCANNERS[scan_type](path[len(scan_type) + 1 :])
