"""Models for the discovery-to-inspection lifecycle and its final inventory."""

from pydantic import BaseModel, Field

from agent_scan.models.errors import (
    CouldNotParseMCPConfig,
    FileNotFoundConfig,
    ScanError,
    ServerHTTPError,
    ServerStartupError,
    SkillScanError,
    UnknownConfigFormat,
    UserDeclinedError,
)
from agent_scan.models.mcp import RemoteServer, ServerSignature, StdioServer
from agent_scan.models.skill import SkillFile, SkillServer


class CandidateClient(BaseModel):
    """Static discovery rules for one supported agent/client."""

    name: str
    client_exists_paths: list[str]
    mcp_config_paths: list[str]
    skills_dir_paths: list[str]
    mcp_config_globs: list[str] = Field(default_factory=list)
    skills_dir_globs: list[str] = Field(default_factory=list)
    max_glob_depth: int = 6


class ClientToInspect(BaseModel):
    """A discovered client and the config/skill inputs queued for inspection."""

    name: str
    client_path: str
    username: str | None = None
    mcp_configs: dict[
        str,
        list[tuple[str, StdioServer | RemoteServer]]
        | FileNotFoundConfig
        | UnknownConfigFormat
        | CouldNotParseMCPConfig,
    ]
    skills_dirs: dict[str, list[tuple[str, SkillServer]] | FileNotFoundConfig]


class InspectedExtension(BaseModel):
    """Intermediate result for one discovered MCP server or legacy skill."""

    name: str
    config: StdioServer | RemoteServer | SkillServer
    # ``None`` means the extension was recorded without being inspected and
    # without an error to report - used for stdio MCP servers on the push-key
    # path, where the scan never starts the subprocess and the absence
    # of a handshake is the documented behavior rather than a failure.
    signature_or_error: (
        ServerSignature | ServerStartupError | ServerHTTPError | SkillScanError | UserDeclinedError | None
    ) = None


class InspectedClient(BaseModel):
    """Intermediate inspection output before it is normalized by component kind."""

    name: str
    client_path: str
    extensions: dict[
        str,
        list[InspectedExtension] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig | SkillScanError,
    ]


class InspectedServer(BaseModel):
    """The MCP server data needed by inspect output and backend analysis."""

    name: str
    # Absolute path of the config file this server was discovered in (e.g. a
    # project ``.mcp.json`` or ``~/.claude.json``).
    config_path: str | None = None
    server: StdioServer | RemoteServer
    signature: ServerSignature | None = None
    error: ScanError | None = None


class InspectedSkill(BaseModel):
    """The skill data needed by inspect output and backend analysis."""

    name: str
    installation_path: str
    files: list[SkillFile] = Field(default_factory=list)
    error: ScanError | None = None


class InspectedPath(BaseModel):
    """Minimal normalized result of inspecting one client or explicit path.

    The v2026-07-10 API boundary converts this inventory into its versioned wire
    models and can anonymize ``path`` before transmission.
    """

    client: str | None = None
    path: str
    servers: list[InspectedServer] = Field(default_factory=list)
    skills: list[InspectedSkill] = Field(default_factory=list)
    error: ScanError | None = None
