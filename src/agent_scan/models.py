import logging
import os
import re
from itertools import chain
from typing import Any, Literal, TypeAlias

from lark import Lark
from mcp.client.auth import TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.types import Completion, InitializeResult, Prompt, Resource, ResourceTemplate, Tool
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    RootModel,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic.alias_generators import to_camel

# Error categories for structured error classification
ErrorCategory = Literal[
    "file_not_found",  # Config file does not exist (not a failure)
    "unknown_config",  # Unknown/unsupported MCP config format (not a failure)
    "parse_error",  # Config file exists but couldn't be parsed
    "server_startup",  # MCP server failed to start
    "server_http_error",  # MCP server returned HTTP error
    "analysis_error",  # Could not reach/use analysis server
    "skill_scan_error",  # Could not scan skill
]

logger = logging.getLogger(__name__)

Entity: TypeAlias = Prompt | Resource | Tool | ResourceTemplate | Completion
Metadata: TypeAlias = InitializeResult


class CommandParsingError(Exception):
    pass


# Cache the Lark parser to avoid recreation on every call
_command_parser = None


def rebalance_command_args(command, args):
    # If the command string already points to an existing path (e.g. it contains
    # spaces like "/Library/Application Support/..."), don't split it on whitespace.
    if os.path.exists(command):
        return command, args

    # create a parser that splits on whitespace,
    # unless it is inside "." or '.'
    # unless that is escaped
    # permit arbitrary whitespace between parts
    global _command_parser
    if _command_parser is None:
        _command_parser = Lark(
            r"""
            command: WORD+
            WORD: (PART|SQUOTEDPART|DQUOTEDPART)
            PART: /[^\s'"]+/
            SQUOTEDPART: /'[^']*'/
            DQUOTEDPART: /"[^"]*"/
            %import common.WS
            %ignore WS
            """,
            parser="lalr",
            start="command",
            regex=True,
        )
    try:
        tree = _command_parser.parse(command)
        command_parts = [node.value for node in tree.children]
        args = command_parts[1:] + (args or [])
        command = command_parts[0]
    except Exception as e:
        raise CommandParsingError(f"Failed to parse command: {e}") from e
    return command, args


class StartMCPServerError(Exception):
    pass


class ScalarToolLabels(BaseModel):
    is_public_sink: int | float
    destructive: int | float
    untrusted_content: int | float
    private_data: int | float


class RemoteServer(BaseModel):
    model_config = ConfigDict()
    url: str
    type: Literal["sse", "http"] | None = None
    headers: dict[str, str] = Field(default_factory=dict)


class StdioServer(BaseModel):
    model_config = ConfigDict()
    command: str
    args: list[str] | None = None
    type: Literal["stdio"] | None = "stdio"
    env: dict[str, str] | None = None
    binary_identifier: str | None = None

    @model_validator(mode="after")
    def rebalance_command(self) -> "StdioServer":
        """Rebalance command and args on model creation."""
        self.command, self.args = rebalance_command_args(self.command, self.args)
        return self


class SkillServer(BaseModel):
    model_config = ConfigDict()
    path: str
    type: Literal["skill"] | None = "skill"


class MCPConfig(BaseModel):
    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        raise NotImplementedError("Subclasses must implement this method")

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        raise NotImplementedError("Subclasses must implement this method")


class ClaudeConfigFile(MCPConfig):
    model_config = ConfigDict()
    mcpServers: dict[str, StdioServer | RemoteServer]

    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        return self.mcpServers

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        self.mcpServers = servers


class ClaudeCodeConfigFile(MCPConfig):
    model_config = ConfigDict()
    projects: dict[str, ClaudeConfigFile]

    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        servers: dict[str, StdioServer | RemoteServer] = {}
        for proj in self.projects.values():
            servers.update(proj.get_servers())
        return servers

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        self.projects = {"~": ClaudeConfigFile(mcpServers=servers)}


class VSCodeMCPConfig(MCPConfig):
    # see https://code.visualstudio.com/docs/copilot/chat/mcp-servers
    model_config = ConfigDict()
    inputs: list[Any] | None = None
    servers: dict[str, StdioServer | RemoteServer]

    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        return self.servers

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        self.servers = servers


class VSCodeConfigFile(MCPConfig):
    model_config = ConfigDict()
    mcp: VSCodeMCPConfig

    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        return self.mcp.servers

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        self.mcp.servers = servers


class UnknownMCPConfig(MCPConfig):
    """
    Represents an MCP configuration the scanner cannot interpret.

    Used when:
    1. The config format is not yet supported (a new client config format the scanner does not parse for)
    2. The config lacks MCP details (an existing client config with MCP info missing or empty)

    This type intentionally resolves to an empty server set.
    """

    model_config = ConfigDict()

    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        return {}

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        pass


class ScanError(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    message: str | None = None
    exception: Exception | str | None = None
    traceback: str | None = None
    is_failure: bool = True
    category: ErrorCategory | None = None
    server_output: str | None = None  # Captured MCP traffic (sent/received messages + stderr)

    @field_serializer("exception")
    def serialize_exception(self, exception: Exception | None, _info) -> str | None:
        return str(exception) if exception else None

    @property
    def text(self) -> str:
        return self.message or (str(self.exception) or "")

    def clone(self) -> "ScanError":
        """
        Create a copy of the ScanError instance. This is not the same as `model_copy(deep=True)`, because it does not
        clone the exception. This is crucial to avoid issues with serialization of exceptions.
        """
        return ScanError(
            message=self.message,
            exception=self.exception,
            traceback=self.traceback,
            is_failure=self.is_failure,
            category=self.category,
            server_output=self.server_output,
        )


class Issue(BaseModel):
    code: str
    message: str
    reference: None | tuple[int, int | None] = Field(
        description="The index of the tool the issue references. (server_index, entity_index) if it is a entity issue, (server_index, None) if it is a server issue, None if it is a global issue",
    )
    extra_data: dict[str, Any] | None = Field(
        default=None,
        description="Extra data to provide more context about the issue.",
    )


class ServerSignature(BaseModel):
    metadata: Metadata
    prompts: list[Prompt] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    resource_templates: list[ResourceTemplate] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)

    @property
    def entities(self) -> list[Entity]:
        return self.prompts + self.resources + self.resource_templates + self.tools


class ServerScanResult(BaseModel):
    model_config = ConfigDict()
    name: str | None = None
    server: StdioServer | RemoteServer | SkillServer
    signature: ServerSignature | None = None
    error: ScanError | None = None

    @property
    def entities(self) -> list[Entity]:
        if self.signature is not None:
            return self.signature.entities
        else:
            return []

    @property
    def is_verified(self) -> bool:
        return self.result is not None

    def clone(self) -> "ServerScanResult":
        """
        Create a copy of the ServerScanResult instance. This is not the same as `model_copy(deep=True)`, because it does not
        clone the error. This is crucial to avoid issues with serialization of exceptions.
        """
        output = ServerScanResult(
            name=self.name,
            server=self.server.model_copy(deep=True),
            signature=self.signature.model_copy(deep=True) if self.signature else None,
            error=self.error.clone() if self.error else None,
        )
        return output


class ScanPathResult(BaseModel):
    model_config = ConfigDict()
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
        """
        Create a copy of the ScanPathResult instance. This is not the same as `model_copy(deep=True)`, because it does not
        clone the error. This is crucial to avoid issues with serialization of exceptions.
        """
        output = ScanPathResult(
            path=self.path,
            client=self.client,
            servers=[server.clone() for server in self.servers] if self.servers else None,
            issues=[issue.model_copy(deep=True) for issue in self.issues],
            labels=[[label.model_copy(deep=True) for label in labels] for labels in self.labels],
            error=self.error.clone() if self.error else None,
        )
        return output


class ScanUserInfo(BaseModel):
    hostname: str | None = None
    username: str | None = None
    identifier: str | None = None
    ip_address: str | None = None
    anonymous_identifier: str | None = None


def entity_to_tool(
    entity: Entity,
) -> Tool:
    """
    Transform any entity into a tool.
    """
    if isinstance(entity, Tool):
        return entity
    elif isinstance(entity, Resource):
        return Tool(
            name=entity.name,
            description=entity.description,
            inputSchema={},
            annotations=None,
        )
    elif isinstance(entity, ResourceTemplate):
        # get parameters from uriTemplate
        params = re.findall(r"\{(\w+)\}", entity.uriTemplate)
        return Tool(
            name=entity.name,
            description=entity.description,
            inputSchema={
                "type": "object",
                "properties": {
                    param: {
                        "type": "string",
                        "description": param,
                    }
                    for param in params
                },
                "required": params,
            },
            annotations=None,
        )
    elif isinstance(entity, Prompt):
        return Tool(
            name=entity.name,
            description=entity.description,
            inputSchema={
                "type": "object",
                "properties": {
                    entity.name: {
                        "type": "string",
                        "description": entity.description,
                    }
                    for entity in entity.arguments or []
                },
                "required": [pa.name for pa in entity.arguments or [] if pa.required],
            },
        )
    else:
        raise ValueError(f"Unknown entity type: {type(entity)}")


class ToolReferenceWithLabel(BaseModel):
    reference: tuple[int, int]
    label_value: float


class ToxicFlowExtraData(RootModel[dict[str, list[ToolReferenceWithLabel]]]):
    pass


class AnalysisServerResponse(BaseModel):
    issues: list[Issue]
    labels: list[list[ScalarToolLabels]]


class ScanPathResultsCreate(BaseModel):
    scan_path_results: list[ScanPathResult]
    scan_user_info: ScanUserInfo
    scan_metadata: dict[str, Any] | None = None


class TokenAndClientInfo(BaseModel):
    # Use Field(alias=...) for the 'token' because OAuthToken's
    # internal fields (accessToken) are also camelCase.
    token: OAuthToken = Field(alias="token")

    server_name: str
    client_id: str
    token_url: str
    mcp_server_url: str
    updated_at: int

    model_config = ConfigDict(
        # This converts snake_case to camelCase for lookup
        alias_generator=to_camel,
        # This allows you to still populate via snake_case in Python
        populate_by_name=True,
    )

    @field_validator("token", mode="before")
    @classmethod
    def map_token_keys(cls, v: Any) -> Any:
        if isinstance(v, dict):
            # Map the camelCase keys to snake_case for the OAuthToken model
            mapping = {
                "accessToken": "access_token",
                "tokenType": "token_type",
                "refreshToken": "refresh_token",
                "expiresIn": "expires_in",
            }
            return {mapping.get(k, k): val for k, val in v.items()}
        return v


class TokenAndClientInfoList(RootModel):
    root: list[TokenAndClientInfo]


class FileTokenStorage(TokenStorage):
    def __init__(self, data: TokenAndClientInfo):
        self.data = data

    async def get_tokens(self) -> OAuthToken | None:
        return self.data.token

    async def set_tokens(self, tokens: OAuthToken) -> None:
        raise NotImplementedError("set_tokens is not supported for FileTokenStorage")

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return OAuthClientInformationFull(
            client_id=self.data.client_id,
            redirect_uris=["http://localhost:3030/callback"],
        )

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store client information."""
        raise NotImplementedError("set_client_info is not supported for FileTokenStorage")


class SerializedException(BaseModel):
    message: str
    traceback: str | None = None
    is_failure: bool = True
    sub_exception_message: str | None = None
    category: ErrorCategory


class FileNotFoundConfig(SerializedException):
    category: Literal["file_not_found"] = "file_not_found"
    is_failure: Literal[False] = False


class UnknownConfigFormat(SerializedException):
    category: Literal["unknown_config"] = "unknown_config"
    is_failure: Literal[False] = False


class CouldNotParseMCPConfig(SerializedException):
    category: Literal["parse_error"] = "parse_error"


class ServerStartupError(SerializedException):
    category: Literal["server_startup"] = "server_startup"
    server_output: str | None = None


class SkillScannError(SerializedException):
    category: Literal["skill_scan_error"] = "skill_scan_error"


class ServerHTTPError(SerializedException):
    category: Literal["server_http_error"] = "server_http_error"
    server_output: str | None = None


class AnalysisError(SerializedException):
    category: Literal["analysis_error"] = "analysis_error"


class CandidateClient(BaseModel):
    model_config = ConfigDict()
    name: str
    client_exists_paths: list[str]
    mcp_config_paths: list[str]
    skills_dir_paths: list[str]


class ClientToInspect(BaseModel):
    name: str
    client_path: str
    mcp_configs: dict[
        str,
        list[tuple[str, StdioServer | RemoteServer]]
        | FileNotFoundConfig
        | UnknownConfigFormat
        | CouldNotParseMCPConfig,
    ]
    skills_dirs: dict[str, list[tuple[str, SkillServer]] | FileNotFoundConfig]


class InspectedExtensions(BaseModel):
    name: str  # ignore if name is available in the config
    config: StdioServer | RemoteServer | SkillServer
    signature_or_error: ServerSignature | ServerStartupError | ServerHTTPError | SkillScannError


class InspectedClient(BaseModel):
    name: str
    client_path: str
    extensions: dict[
        str,
        list[InspectedExtensions] | FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig | SkillScannError,
    ]


class InspectedMachine(BaseModel):
    clients: list[InspectedClient]


class NewIssue(BaseModel):
    code: str
    message: str
    reference: None | tuple[tuple[str, int], int | None] = Field(
        description="The index of the tool the issue references. ((config_path, server_index), entity_index) if it is a entity issue, ((config_path, server_index), None) if it is a server issue, None if it is a global issue",
    )
    extra_data: dict[str, Any] | None = Field(
        default=None,
        description="Extra data to provide more context about the issue.",
    )


class ClientAnalysis(BaseModel):
    labels: list[list[ScalarToolLabels]]
    issues: list[NewIssue]


class AnalyzedMachine(BaseModel):
    machine: InspectedMachine
    analysis: list[ClientAnalysis] | AnalysisError


class ControlServer(BaseModel):
    url: str
    headers: dict[str, str]
    identifier: str | None = None
