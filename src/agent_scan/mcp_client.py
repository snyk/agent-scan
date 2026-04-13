import asyncio
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal
from urllib.parse import urlparse

import httpx
import pyjson5
from mcp import ClientSession, StdioServerParameters
from mcp.client.auth import OAuthClientProvider
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientInformationFull

from agent_scan.models import (
    ClaudeCodeConfigFile,
    ClaudeConfigFile,
    ConfigWithoutMCP,
    FileTokenStorage,
    InteractiveTokenStorage,
    MCPConfig,
    RemoteServer,
    ServerSignature,
    StdioServer,
    TokenAndClientInfo,
    UnknownMCPConfig,
    VSCodeConfigFile,
    VSCodeMCPConfig,
)
from agent_scan.oauth import build_oauth_client_provider
from agent_scan.traffic_capture import PipeStderrCapture, TrafficCapture, capturing_client
from agent_scan.utils import resolve_command_and_args

# Set up logger for this module
logger = logging.getLogger(__name__)


@asynccontextmanager
async def streamablehttp_client_without_session(
    url: str,
    headers: dict[str, str],
    timeout: int,
    oauth_client_provider: OAuthClientProvider | None = None,
):
    async with httpx.AsyncClient(
        auth=oauth_client_provider, follow_redirects=True, headers=headers, timeout=timeout
    ) as custom_client:
        async with streamable_http_client(url=url, http_client=custom_client) as (read, write, _):
            yield read, write


@asynccontextmanager
async def get_client(
    server_config: StdioServer | RemoteServer,
    timeout: int | None = None,
    traffic_capture: TrafficCapture | None = None,
    token: TokenAndClientInfo | None = None,
    enable_oauth: bool = False,
    oauth_client_id: str | None = None,
) -> AsyncIterator[tuple]:
    """
    Create an MCP client for the given server config.

    If traffic_capture is provided, all MCP protocol traffic will be captured
    for debugging purposes.
    """
    # Construct the OAuthClientProvider centrally
    oauth_client_provider: OAuthClientProvider | None = None
    if token and isinstance(server_config, RemoteServer):
        storage = FileTokenStorage(data=token)
        oauth_client_provider, _ = build_oauth_client_provider(
            server_url=token.mcp_server_url,
            storage=storage,
        )
    elif enable_oauth and isinstance(server_config, RemoteServer):
        storage = InteractiveTokenStorage(server_url=server_config.url)
        if oauth_client_id:
            await storage.set_client_info(
                OAuthClientInformationFull(
                    client_id=oauth_client_id,
                    redirect_uris=["http://localhost:3030/callback"],
                )
            )
        oauth_client_provider, _ = build_oauth_client_provider(
            server_url=server_config.url,
            storage=storage,
        )

    if isinstance(server_config, RemoteServer) and server_config.type == "sse":
        logger.debug("Creating SSE client with URL: %s", server_config.url)
        sse_kwargs: dict = {
            "url": server_config.url,
            "headers": server_config.headers,
            "timeout": timeout,
        }
        if oauth_client_provider is not None:
            sse_kwargs["auth"] = oauth_client_provider
        client_cm = sse_client(**sse_kwargs)
    elif isinstance(server_config, RemoteServer) and server_config.type == "http":
        logger.debug(
            "Creating Streamable HTTP client with URL: %s with headers %s", server_config.url, server_config.headers
        )
        client_cm = streamablehttp_client_without_session(
            url=server_config.url,
            headers=server_config.headers,
            timeout=timeout or 60,
            oauth_client_provider=oauth_client_provider,
        )
    elif isinstance(server_config, StdioServer):
        logger.debug("Creating stdio client")

        command, args = resolve_command_and_args(server_config)
        server_params = StdioServerParameters(
            command=command,
            args=args,
            env=server_config.env,
        )
        # Create stderr capture with real pipe if traffic capture is enabled
        stderr_capture = PipeStderrCapture(traffic_capture) if traffic_capture else None
        client_cm = stdio_client(server_params, errlog=stderr_capture)
    else:
        raise ValueError(f"Invalid server config: {server_config}")

    # Wrap client to capture traffic if requested
    if traffic_capture:
        # Start stderr reader for stdio servers
        if isinstance(server_config, StdioServer) and stderr_capture:
            await stderr_capture.start_reading()
        try:
            async with capturing_client(client_cm, traffic_capture) as streams:
                yield streams
        finally:
            # Clean up stderr capture
            if isinstance(server_config, StdioServer) and stderr_capture:
                await stderr_capture.close()
    else:
        async with client_cm as streams:
            yield streams


async def _check_server_pass(
    server_config: StdioServer | RemoteServer,
    timeout: int,
    traffic_capture: TrafficCapture | None = None,
    token: TokenAndClientInfo | None = None,
    enable_oauth: bool = False,
    oauth_client_id: str | None = None,
) -> ServerSignature:
    async def _check_server() -> ServerSignature:
        async with get_client(
            server_config,
            timeout=timeout,
            traffic_capture=traffic_capture,
            token=token,
            enable_oauth=enable_oauth,
            oauth_client_id=oauth_client_id,
        ) as (
            read,
            write,
        ):
            async with ClientSession(read, write) as session:
                meta = await session.initialize()
                logger.debug("Server initialized with metadata: %s", meta)
                # for see servers we need to check the announced capabilities
                prompts: list = []
                resources: list = []
                resource_templates: list = []
                tools: list = []
                # completions are currently not implemented
                completions: list = []  # noqa: F841
                logger.debug(f"Server capabilities: {meta.capabilities}")
                if isinstance(server_config, StdioServer) or meta.capabilities.prompts:
                    logger.debug("Fetching prompts")
                    try:
                        prompts += (await session.list_prompts()).prompts
                        logger.debug("Found %d prompts", len(prompts))
                    except Exception:
                        logger.exception("Failed to list prompts")

                logger.debug("Server capabilities: %s", meta.capabilities)
                if isinstance(server_config, StdioServer) or meta.capabilities.resources:
                    logger.debug("Fetching resources")
                    try:
                        resources += (await session.list_resources()).resources
                        logger.debug("Found %d resources", len(resources))
                    except Exception:
                        logger.exception("Failed to list resources")

                    logger.debug("Fetching resource templates")
                    try:
                        resource_templates += (await session.list_resource_templates()).resourceTemplates
                        logger.debug("Found %d resource templates", len(resource_templates))
                    except Exception:
                        logger.exception("Failed to list resource templates")

                if isinstance(server_config, StdioServer) or meta.capabilities.tools:
                    logger.debug("Fetching tools")
                    try:
                        tools += (await session.list_tools()).tools
                        logger.debug("Found %d tools", len(tools))
                    except Exception:
                        logger.exception("Failed to list tools")
                logger.info("Server check completed successfully")
                return ServerSignature(
                    metadata=meta,
                    prompts=prompts,
                    resources=resources,
                    resource_templates=resource_templates,
                    tools=tools,
                )

    return await _check_server()


async def check_server(
    server_config: StdioServer | RemoteServer,
    timeout: int,
    traffic_capture: TrafficCapture | None = None,
    token: TokenAndClientInfo | None = None,
    enable_oauth: bool = False,
    oauth_client_id: str | None = None,
) -> tuple[ServerSignature, StdioServer | RemoteServer]:
    logger.debug("Checking server with timeout: %s seconds", timeout)

    if not isinstance(server_config, RemoteServer):
        result = await asyncio.wait_for(
            _check_server_pass(
                server_config,
                timeout,
                traffic_capture,
                enable_oauth=enable_oauth,
                oauth_client_id=oauth_client_id,
            ),
            timeout,
        )
        logger.debug("Server check completed within timeout")
        return result, server_config
    else:
        logger.debug(f"Remote server with url: {server_config.url}, type: {server_config.type or 'none'}")
        strategy: list[tuple[Literal["sse", "http"], str]] = []
        url_path = urlparse(server_config.url).path
        if url_path.endswith("/sse"):
            url_with_sse = server_config.url
            url_without_end = server_config.url.replace("/sse", "")
            url_with_mcp = server_config.url.replace("/sse", "/mcp")
        elif url_path.endswith("/mcp"):
            url_with_mcp = server_config.url
            url_without_end = server_config.url.replace("/mcp", "")
            url_with_sse = server_config.url.replace("/mcp", "/sse")
        else:
            url_without_end = server_config.url
            url_with_mcp = server_config.url + "/mcp"
            url_with_sse = server_config.url + "/sse"

        if server_config.type == "http" or server_config.type is None:
            strategy.append(("http", url_with_mcp))
            strategy.append(("http", url_without_end))
            strategy.append(("sse", url_with_mcp))
            strategy.append(("sse", url_without_end))
            strategy.append(("http", url_with_sse))
            strategy.append(("sse", url_with_sse))
        else:
            strategy.append(("sse", url_with_mcp))
            strategy.append(("sse", url_without_end))
            strategy.append(("http", url_with_mcp))
            strategy.append(("http", url_without_end))
            strategy.append(("sse", url_with_sse))
            strategy.append(("http", url_with_sse))

        exceptions: list[Exception] = []
        for protocol, url in strategy:
            try:
                server_config.type = protocol
                server_config.url = url
                logger.debug(f"Trying {protocol} with url: {url}")
                result = await asyncio.wait_for(
                    _check_server_pass(
                        server_config,
                        timeout,
                        traffic_capture,
                        token,
                        enable_oauth=enable_oauth,
                        oauth_client_id=oauth_client_id,
                    ),
                    timeout,
                )
                logger.debug("Server check completed within timeout")
                return result, server_config
            except asyncio.TimeoutError as e:
                logger.debug("Server check timed out")
                exceptions.append(e)
                continue
            except Exception as e:
                logger.debug("Server check failed")
                exceptions.append(e)
                continue

        # if python 3.11 or higher, use ExceptionGroup
        if sys.version_info >= (3, 11):
            raise ExceptionGroup("Could not connect to remote server", exceptions)  # noqa: F821
        else:
            raise Exception("Could not connect to remote server.") from exceptions[0]


async def scan_mcp_config_file(path: str) -> MCPConfig:
    logger.info("Scanning MCP config file: %s", path)
    path = os.path.expanduser(path)
    logger.debug("Expanded path: %s", path)

    def parse_and_validate(config: dict) -> MCPConfig:
        logger.debug("Parsing and validating config")
        models: list[type[MCPConfig]] = [
            ClaudeCodeConfigFile,  # used by claude code .claude.json
            ClaudeConfigFile,  # used by most clients
            VSCodeConfigFile,  # used by vscode settings.json
            VSCodeMCPConfig,  # used by vscode mcp.json
            UnknownMCPConfig,  # used by unknown config files
            ConfigWithoutMCP,  # used by config files without MCP
        ]
        for model in models:
            try:
                logger.debug("Trying to validate with model: %s", model.__name__)
                return model.model_validate(config)
            except Exception:
                logger.debug("Validation with %s failed", model.__name__)
        error_msg = "Could not parse config file as any of " + str([model.__name__ for model in models])
        raise Exception(error_msg)

    try:
        logger.debug("Opening config file")
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            content = f.read()
        logger.debug("Config file read successfully")

        # if content is empty, return an empty MCPConfig
        if content is None or content.strip() == "" or not content:
            logger.warning("Config file is empty")
            return parse_and_validate({})

        # use json5 to support comments as in vscode
        config = pyjson5.loads(content)
        logger.debug("Config JSON parsed successfully")

        # try to parse model
        result = parse_and_validate(config)
        logger.info("Config file parsed and validated successfully")
        return result
    except Exception:
        logger.exception("Error processing config file")
        raise
