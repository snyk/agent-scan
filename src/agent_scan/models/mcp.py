"""MCP configuration, runtime server, and inspected signature models."""

import logging
import os
import re
from typing import Annotated, Any, Literal, TypeAlias

from lark import Lark
from mcp.types import Completion, InitializeResult, Prompt, Resource, ResourceTemplate, Tool
from pydantic import (
    AliasChoices,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

logger = logging.getLogger(__name__)


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
        analysis section 7.1).

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


class MCPConfig(BaseModel):
    def get_servers(self) -> dict[str, StdioServer | RemoteServer]:
        raise NotImplementedError("Subclasses must implement this method")

    def set_servers(self, servers: dict[str, StdioServer | RemoteServer]) -> None:
        raise NotImplementedError("Subclasses must implement this method")


class MCPServerMap(MCPConfig):
    """Agent-neutral model for an *already-extracted* ``{name: serverConfig}`` map.

    Unlike the file-format models (``ClaudeConfigFile``/``VSCodeMCPConfig``/...) whose
    field names match a literal top-level wrapper key in the on-disk file, this model
    is built directly from a server map the caller has already pulled out of whatever
    wrapper it lived under. It is therefore never placed in a ``_parse_mcp_file``
    format-union - only constructed directly (see ``AgentDiscoverer._validate_servers``).
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
    """Flat ``{name: serverConfig, ...}`` format used by Claude Code plugin ``.mcp.json`` files."""

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
    """opencode's ``opencode.json`` ``mcp`` block: ``{"mcp": {name: {type:"local"|"remote", ...}}}``
    from https://opencode.ai/config.json.

    Translates opencode's per-entry shape into the canonical
    ``StdioServer`` / ``RemoteServer`` types via a ``before`` model validator,
    which lets this model slot into ``_parse_mcp_file``'s format union like the
    other file-format models. Per-entry rules:

    * ``type: "local"`` -> ``StdioServer`` (``command`` is a single array combining
      executable + args; ``environment`` maps onto ``env``).
    * ``type: "remote"`` -> ``RemoteServer`` (``url`` matches; ``type`` is folded
      onto ``"http"`` since opencode does not distinguish sse vs streamable-http).
    * Entries whose ``enabled`` field is exactly ``False`` are dropped before
      typed validation runs - opencode treats unset/``true`` as enabled.
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
                # is the audit trail - operators who see it can file a ticket to
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


# ============================================================================
# MCP server signature and entity utilities
# ============================================================================

Entity: TypeAlias = Prompt | Resource | Tool | ResourceTemplate | Completion
Metadata: TypeAlias = InitializeResult


class ServerSignature(BaseModel):
    metadata: Metadata
    prompts: list[Prompt] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    resource_templates: list[ResourceTemplate] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)

    @property
    def entities(self) -> list[Entity]:
        return self.prompts + self.resources + self.resource_templates + self.tools


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
