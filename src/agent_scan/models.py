import logging
import os
import re
from itertools import chain
from typing import Annotated, Any, Literal, TypeAlias
from uuid import UUID

from lark import Lark
from mcp.client.auth import TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.types import Completion, InitializeResult, Prompt, Resource, ResourceTemplate, Tool
from pydantic import (
    AliasChoices,
    BaseModel,
    BeforeValidator,
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
    "user_declined",  # User declined to start a stdio server during the consent prompt
    "skipped_by_runtime_config",  # Server skipped because runtime_config.skip_servers matched
]

# Mapping from failure categories to codes
# These codes are different from the ones from analysis findings like E001, E002, etc
FAILURE_CATEGORY_TO_CODE: dict[ErrorCategory | None, str] = {
    "server_startup": "X001",
    "skill_scan_error": "X002",
    "file_not_found": "X003",
    "unknown_config": "X004",
    "parse_error": "X005",
    "server_http_error": "X006",
    "analysis_error": "X007",
    None: "X008",
    "user_declined": "X009",
    "skipped_by_runtime_config": "X010",
}

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


# Top-level keys that mark a JSON object as a single MCP *server config* rather
# than a ``{name: serverConfig}`` map: ``command`` (StdioServer) and the remote
# URL aliases (RemoteServer). Single source of truth reused by RemoteServer's
# ``validation_alias``, the ``PluginMCPConfigFile`` flat-format gate, and
# ``base._looks_like_mcp_payload``. A drift guard
# (test_server_config_discriminator_keys_match_model_required_fields) keeps it in
# sync with the models' required fields.
_REMOTE_URL_ALIASES = ("url", "serverUrl", "httpUrl")
SERVER_CONFIG_DISCRIMINATOR_KEYS = frozenset({"command", *_REMOTE_URL_ALIASES})


class RemoteServer(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    # ``serverUrl`` (Figma/Antigravity) and ``httpUrl`` (Gemini CLI Streamable HTTP)
    # are vendor aliases for the same remote-server URL. First present wins.
    url: str = Field(validation_alias=AliasChoices(*_REMOTE_URL_ALIASES))
    # ``sse``/``http`` are the transports the client implements
    # (``streamable-http`` folds onto ``http`` below). ``ws`` -- a documented
    # Claude Code WebSocket transport -- is intentionally NOT accepted here yet:
    # the scanner can't connect to it, and emitting ``type: "ws"`` breaks the
    # downstream consumers (invariant-mcp-scan-backend / invariant-platform),
    # which validate against ``{sse, http}`` only and would reject the payload.
    # Until ``ws`` is supported end-to-end across those repos, a ``ws`` server
    # fails validation (sinking its config file) rather than being emitted.
    # TODO(ADS-384): re-add ``"ws"`` once the backend + platform accept it.
    # https://snyksec.atlassian.net/browse/ADS-384
    type: Literal["sse", "http"] | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("type", mode="before")
    @classmethod
    def _normalize_transport(cls, v: Any) -> Any:
        """Fold documented transport spellings onto the values the client speaks.

        Claude Code documents ``type: "streamable-http"`` (and the ``-https``
        spelling), which is the same HTTP Streamable transport already
        implemented under ``http``, so it is folded on here; matching is
        case-insensitive. Without this, a single such server raised a
        ``ValidationError`` that sank the whole ``mcpServers`` map into
        ``CouldNotParseMCPConfig`` -- losing every valid sibling (coverage
        analysis §7.1).

        Note: Claude Code also documents a ``type: "ws"`` WebSocket transport,
        but it is deliberately left unsupported for now -- see the TODO(ADS-384)
        on the ``type`` field above.
        """
        if not isinstance(v, str):
            return v
        normalized = v.strip().lower()
        if normalized in ("streamable-http", "streamable-https"):
            return "http"
        return normalized


def _coerce_none_to_empty_list(v: Any) -> Any:
    """Coerce None to [] before Pydantic type-checks the args field.

    Used as a BeforeValidator so user JSON containing `"args": null` (or
    omitting `args` entirely) is normalized to an empty list rather than
    rejected by the `list[str]` type check on StdioServer.args.
    """
    return [] if v is None else v


class StdioServer(BaseModel):
    model_config = ConfigDict()
    command: str
    args: Annotated[list[str], BeforeValidator(_coerce_none_to_empty_list)] = Field(default_factory=list)
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


class MCPServerMap(MCPConfig):
    """Agent-neutral model for an *already-extracted* ``{name: serverConfig}`` map.

    Unlike the file-format models (``ClaudeConfigFile``/``VSCodeMCPConfig``/…) whose
    field names match a literal top-level wrapper key in the on-disk file, this model
    is built directly from a server map the caller has already pulled out of whatever
    wrapper it lived under. It is therefore never placed in a ``_parse_mcp_file``
    format-union — only constructed directly (see ``AgentDiscoverer._validate_servers``).
    """

    model_config = ConfigDict()
    servers: dict[str, StdioServer | RemoteServer]

    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        return self.servers

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        self.servers = servers


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


class PluginMCPConfigFile(MCPConfig):
    """Flat ``{name: serverConfig, …}`` format used by Claude Code plugin ``.mcp.json`` files."""

    model_config = ConfigDict()
    servers: dict[str, StdioServer | RemoteServer]

    @model_validator(mode="before")
    @classmethod
    def wrap_flat_dict(cls, data: Any) -> Any:
        if not isinstance(data, dict) or len(data) == 0:
            raise ValueError("empty or non-dict")
        for v in data.values():
            if not isinstance(v, dict):
                raise ValueError("values must be dicts")
            if not any(key in v for key in SERVER_CONFIG_DISCRIMINATOR_KEYS):
                raise ValueError("values must look like server configs")
        return {"servers": data}

    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        return self.servers

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        self.servers = servers


class OpenCodeConfigFile(MCPConfig):
    """opencode's ``opencode.json`` ``mcp`` block: ``{"mcp": {name: {type:"local"|"remote", ...}}}``.

    Translates opencode's per-entry shape into the canonical
    ``StdioServer`` / ``RemoteServer`` types via a ``before`` model validator,
    which lets this model slot into ``_parse_mcp_file``'s format union like the
    other file-format models. Per-entry rules:

    * ``type: "local"`` -> ``StdioServer`` (``command`` is a single array combining
      executable + args; ``environment`` maps onto ``env``).
    * ``type: "remote"`` -> ``RemoteServer`` (``url`` matches; ``type`` is folded
      onto ``"http"`` since opencode does not distinguish sse vs streamable-http).
    * Entries whose ``enabled`` field is exactly ``False`` are dropped before
      typed validation runs — opencode treats unset/``true`` as enabled.
    """

    model_config = ConfigDict()
    servers: dict[str, StdioServer | RemoteServer]

    @model_validator(mode="before")
    @classmethod
    def _extract_mcp_block(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            raise ValueError("opencode config must be a JSON object")
        mcp = data.get("mcp")
        if not isinstance(mcp, dict):
            raise ValueError("opencode config has no 'mcp' block")
        servers: dict[str, dict[str, Any]] = {}
        for name, entry in mcp.items():
            if not isinstance(entry, dict):
                raise ValueError(f"opencode mcp entry {name!r} must be an object")
            if entry.get("enabled") is False:
                continue
            entry_type = entry.get("type")
            if entry_type == "local":
                command = entry.get("command")
                if not isinstance(command, list) or not command or not all(isinstance(c, str) for c in command):
                    raise ValueError(f"opencode mcp entry {name!r} 'command' must be a non-empty string array")
                servers[name] = {
                    "command": command[0],
                    "args": list(command[1:]),
                    "env": entry.get("environment"),
                    "type": "stdio",
                }
            elif entry_type == "remote":
                url = entry.get("url")
                if not isinstance(url, str) or not url:
                    raise ValueError(f"opencode mcp entry {name!r} 'url' must be a non-empty string")
                servers[name] = {
                    "url": url,
                    "type": "http",
                    "headers": entry.get("headers") or {},
                }
            else:
                # Unknown ``type`` (e.g. a transport added in a future opencode
                # release). Skip the single entry rather than sinking the whole
                # file: dropping parseable siblings on the floor would silently
                # hide every other MCP server in the same config. The warning
                # is the audit trail — operators who see it can file a ticket to
                # add the new transport. Malformed *known* entries (e.g.
                # ``local`` with no ``command``) still raise above; the
                # tolerance applies only to entirely unrecognized types.
                logger.warning(
                    "opencode mcp entry %r has unrecognized type %r; skipping entry "
                    "(file an issue if opencode added a new transport)",
                    name,
                    entry_type,
                )
                continue
        return {"servers": servers}

    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        return self.servers

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        self.servers = servers


class UnknownMCPConfig(MCPConfig):
    """
    Represents an MCP configuration the scanner cannot interpret.

    Used when:
    1. The config format is not yet supported (a new client config format the scanner does not parse for)
    2. The config lacks MCP details (an existing client config with MCP info missing or empty)

    This type intentionally resolves to an empty server set.
    """

    model_config = ConfigDict()
    mcp: list[Any] | dict[str, Any]

    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        return {}

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        pass


class ConfigWithoutMCP(MCPConfig):
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
    # Absolute path of the config file this server was discovered in (e.g. a
    # project ``.mcp.json`` or ``~/.claude.json``). A single client can flatten
    # servers from several config files into one ScanPathResult, so the
    # provenance is tracked per server rather than at the ScanPathResult level.
    # Sent absolute to both backends, matching SkillServer.path.
    config_path: str | None = None
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
            config_path=self.config_path,
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
    username: list[str] | None = None
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


# WARNING: These models must stay in sync with backend/models/base.py in
# invariant-platform. There is NO automated enforcement -- if one side
# changes without the other, bootstrap will silently degrade to defaults
# (the Pydantic validation on the client side will reject the response).
# When modifying these models, search invariant-platform for the matching
# class names and update both sides in a coordinated PR.
class HomeDirectoryEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    path: str
    username: str


class ClientInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    version: str
    command: Literal["scan", "inspect", "evo", "guard"]
    subcommand: str | None = None
    control_identifier: str | None = None
    argv_flags: list[str] = Field(default_factory=list)


class HostInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    os: str
    os_release: str
    os_version: str
    arch: str
    processor: str
    hostname: str
    current_username: str
    is_ci: bool
    is_wsl: bool
    is_container: bool
    shell: str | None = None
    term: str | None = None
    locale: str | None = None
    timezone: str | None = None


class PathsInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    cwd: str
    current_home_dir: str
    home_directories: list[HomeDirectoryEntry]
    home_directories_truncated: bool
    executable: str


class ClientBootstrapRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    client: ClientInfo
    host: HostInfo


class ClientBootstrapResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    bootstrap_event_id: UUID
    # TODO: plumbing only — the bootstrap response carries a free-form
    # runtime_config dict that the client currently stores on
    # RuntimeConfig.config but does not yet read. Future work will consume
    # specific keys (feature flags, scan limits, etc.) on the client side;
    # until then this field is intentionally parsed-and-stashed so the
    # control server can begin emitting it without a coordinated client
    # release. See follow-up tracked alongside the bootstrap rollout.
    runtime_config: dict[str, Any] = Field(default_factory=dict)


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


class UserDeclinedError(SerializedException):
    category: Literal["user_declined"] = "user_declined"


class SkippedByRuntimeConfigError(SerializedException):
    category: Literal["skipped_by_runtime_config"] = "skipped_by_runtime_config"


class AnalysisError(SerializedException):
    category: Literal["analysis_error"] = "analysis_error"


class CandidateClient(BaseModel):
    model_config = ConfigDict()
    name: str
    client_exists_paths: list[str]
    mcp_config_paths: list[str]
    skills_dir_paths: list[str]
    mcp_config_globs: list[str] = Field(default_factory=list)
    skills_dir_globs: list[str] = Field(default_factory=list)
    max_glob_depth: int = Field(default=6)


class ClientToInspect(BaseModel):
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


class InspectedExtensions(BaseModel):
    name: str  # ignore if name is available in the config
    config: StdioServer | RemoteServer | SkillServer
    # ``None`` means the extension was recorded without being inspected and
    # without an error to report — used for stdio MCP servers on the push-key
    # path, where the scan never starts the subprocess and the absence
    # of a handshake is the documented behavior rather than a failure.
    signature_or_error: (
        ServerSignature
        | ServerStartupError
        | ServerHTTPError
        | SkillScannError
        | UserDeclinedError
        | SkippedByRuntimeConfigError
        | None
    ) = None


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
    identifier: str
