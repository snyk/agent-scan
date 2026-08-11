"""Models owned by the legacy v2025-09-02 analysis contract.

The legacy pipeline also uses these models as its internal inspection result.
That coupling is intentional here and disappears with the old API version.
"""

from itertools import chain
from typing import Any

from pydantic import BaseModel, Field, RootModel

from agent_scan.models.api.common import ScanUserInfo
from agent_scan.models.errors import ScanError
from agent_scan.models.mcp import Entity, RemoteServer, ServerSignature, StdioServer
from agent_scan.models.skill import SkillFile, SkillServer


# Analysis findings
# -----------------
# Findings and labels reference servers and entities by their positions in the
# legacy ScanPathResult collections.
class ScalarToolLabels(BaseModel):
    is_public_sink: int | float
    destructive: int | float
    untrusted_content: int | float
    private_data: int | float


class Issue(BaseModel):
    code: str
    message: str
    reference: tuple[int, int | None] | None = Field(
        default=None,
        description=(
            "Index referenced by the issue: (server_index, entity_index), "
            "(server_index, None), or None for a global issue."
        ),
    )
    extra_data: dict[str, Any] | None = None


class ToolReferenceWithLabel(BaseModel):
    reference: tuple[int, int]
    label_value: float


class ToxicFlowExtraData(RootModel[dict[str, list[ToolReferenceWithLabel]]]):
    pass


# Server inspection and analysis result
# -------------------------------------
# The legacy contract represents MCP servers and skills in the same collection.
class ServerScanResult(BaseModel):
    name: str | None = None
    # Absolute path of the config file this server was discovered in (e.g. a
    # project ``.mcp.json`` or ``~/.claude.json``). A single client can flatten
    # servers from several config files into one ScanPathResult, so the
    # provenance is tracked per server rather than at the ScanPathResult level.
    # Sent absolute to both backends, matching SkillServer.path.
    config_path: str | None = None
    server: StdioServer | RemoteServer | SkillServer
    signature: ServerSignature | None = None
    error: ScanError | None = None
    skill_files: list[SkillFile] | None = None

    @property
    def entities(self) -> list[Entity]:
        return self.signature.entities if self.signature is not None else []

    def clone(self) -> "ServerScanResult":
        """Create a copy of the ServerScanResult instance.

        This is NOT the same as ``model_copy(deep=True)``, because it does not clone
        the error. This is crucial to avoid issues with serialization of exceptions -
        do not replace this with ``model_copy``.
        """
        return ServerScanResult(
            name=self.name,
            config_path=self.config_path,
            server=self.server.model_copy(deep=True),
            signature=self.signature.model_copy(deep=True) if self.signature else None,
            error=self.error.clone() if self.error else None,
            skill_files=[item.model_copy(deep=True) for item in self.skill_files] if self.skill_files else None,
        )


# Path-level result
# -----------------
# This type is both the old API payload and the old pipeline's internal state;
# issues and labels are therefore mixed with inspection data.
class ScanPathResult(BaseModel):
    client: str | None = None
    path: str
    # servers is None if the MCP configuration file was missing or unparseable
    # which prevented server discovery.
    servers: list[ServerScanResult] | None = None
    issues: list[Issue] = Field(default_factory=list)
    labels: list[list[ScalarToolLabels]] = Field(default_factory=list)
    error: ScanError | None = None

    @property
    def entities(self) -> list[Entity]:
        return list(chain.from_iterable(server.entities for server in self.servers)) if self.servers else []

    def clone(self) -> "ScanPathResult":
        """Create a copy of the ScanPathResult instance.

        This is NOT the same as ``model_copy(deep=True)``, because it does not clone
        the error. This is crucial to avoid issues with serialization of exceptions -
        do not replace this with ``model_copy``.
        """
        return ScanPathResult(
            path=self.path,
            client=self.client,
            servers=[server.clone() for server in self.servers] if self.servers else None,
            issues=[issue.model_copy(deep=True) for issue in self.issues],
            labels=[[label.model_copy(deep=True) for label in labels] for labels in self.labels],
            error=self.error.clone() if self.error else None,
        )


# Request payload
class ScanPathResultsCreate(BaseModel):
    scan_path_results: list[ScanPathResult]
    scan_user_info: ScanUserInfo
    scan_metadata: dict[str, Any] | None = None
