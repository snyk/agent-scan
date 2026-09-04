"""Models for the discovery-to-inspection lifecycle and its results."""

from pydantic import BaseModel, Field

from agent_scan.models.discovery import DiscoveredServer, DiscoveryLocationScope
from agent_scan.models.errors import CouldNotParseMCPConfig, FileNotFoundConfig, ScanError, UnknownConfigFormat
from agent_scan.models.mcp import RemoteServer, ServerSignature, StdioServer
from agent_scan.models.skill import DiscoveredSkill, SkillFile


class CandidateClient(BaseModel):
    """Static discovery rules for one supported agent/client."""

    name: str
    client_exists_paths: list[str]
    mcp_config_paths: list[str]
    skills_dir_paths: list[str]
    mcp_config_globs: list[str] = Field(default_factory=list)
    skills_dir_globs: list[str] = Field(default_factory=list)
    max_glob_depth: int = 6
    default_location_scope: DiscoveryLocationScope = DiscoveryLocationScope.USER
    mcp_config_path_scopes: dict[str, DiscoveryLocationScope] = Field(default_factory=dict)
    skills_dir_path_scopes: dict[str, DiscoveryLocationScope] = Field(default_factory=dict)
    mcp_config_glob_scopes: dict[str, DiscoveryLocationScope] = Field(default_factory=dict)
    skills_dir_glob_scopes: dict[str, DiscoveryLocationScope] = Field(default_factory=dict)


class ClientToInspect(BaseModel):
    """A discovered client and the config/skill inputs queued for inspection."""

    name: str
    client_path: str
    username: str | None = None
    mcp_configs: dict[
        str,
        list[DiscoveredServer] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig,
    ]
    skills_dirs: dict[str, list[DiscoveredSkill] | FileNotFoundConfig]


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

    name: str = Field(
        description="Canonical directory-skill name from SKILL.md frontmatter, or the discovered command identifier."
    )
    installation_path: str
    files: list[SkillFile] = Field(default_factory=list)
    error: ScanError | None = None


class InspectedPath(BaseModel):
    """Minimal normalized result of inspecting one client or explicit path.

    The v2026-07-10 API boundary converts this result into its versioned wire
    models and can anonymize ``path`` before transmission.
    """

    client: str | None = None
    path: str = Field(description="Local path represented by this result, such as '~/.cursor' for a discovered client.")
    servers: list[InspectedServer] = Field(default_factory=list)
    skills: list[InspectedSkill] = Field(default_factory=list)
    error: ScanError | None = None
