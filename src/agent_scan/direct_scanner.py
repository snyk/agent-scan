"""
Scans MCP servers directly from package or URL.
"""

from agent_scan.models import RemoteServer, StdioServer

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
