"""Internal models for location-aware component discovery."""

from collections.abc import Iterator
from enum import Enum

from pydantic import BaseModel, Field, model_validator

from agent_scan.models.mcp import RemoteServer, StdioServer


class DiscoveryLocationScope(str, Enum):
    """Filesystem/location tier from which a component was discovered."""

    SYSTEM = "system"
    USER = "user"
    PROJECT_WORKSPACE = "project_workspace"
    EXTENSION_PLUGIN = "extension_plugin"
    CUSTOM = "custom"


AUTOMATIC_DISCOVERY_SCOPES = frozenset(
    {
        DiscoveryLocationScope.SYSTEM,
        DiscoveryLocationScope.USER,
        DiscoveryLocationScope.PROJECT_WORKSPACE,
        DiscoveryLocationScope.EXTENSION_PLUGIN,
    }
)


class DiscoveredServer(BaseModel):
    """An MCP server found locally before inspection.

    Iteration and integer indexing intentionally expose the historical
    ``(name, server)`` pair so internal callers can migrate without changing
    inspection or Analysis API models.
    """

    name: str
    server: StdioServer | RemoteServer
    scope: DiscoveryLocationScope = Field(default=DiscoveryLocationScope.CUSTOM)

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_pair(cls, value: object) -> object:
        if isinstance(value, tuple) and len(value) == 2:
            return {"name": value[0], "server": value[1]}
        return value

    def __iter__(self) -> Iterator[str | StdioServer | RemoteServer]:
        yield self.name
        yield self.server

    def __len__(self) -> int:
        return 2

    def __getitem__(self, index: int) -> str | StdioServer | RemoteServer:
        if index == 0 or index == -2:
            return self.name
        if index == 1 or index == -1:
            return self.server
        raise IndexError(index)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, tuple) and len(other) == 2:
            return (self.name, self.server) == other
        return super().__eq__(other)


__all__ = ["AUTOMATIC_DISCOVERY_SCOPES", "DiscoveredServer", "DiscoveryLocationScope"]
