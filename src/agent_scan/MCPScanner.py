import asyncio
import logging
import os
import re
import time
import traceback
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from httpx import HTTPStatusError
from pydantic import ValidationError

from agent_scan.direct_scanner import direct_scan, is_direct_scan
from agent_scan.mcp_client import check_server, scan_mcp_config_file
from agent_scan.models import (
    Issue,
    RemoteServer,
    ScanError,
    ScanPathResult,
    ServerScanResult,
    TokenAndClientInfo,
    TokenAndClientInfoList,
    UnknownMCPConfig,
)
from agent_scan.redact import redact_scan_result
from agent_scan.signed_binary import check_signed_binary
from agent_scan.Storage import Storage
from agent_scan.traffic_capture import TrafficCapture
from agent_scan.utils import get_push_key
from agent_scan.verify_api import analyze_machine
from agent_scan.well_known_clients import get_builtin_tools

# Set up logger for this module
logger = logging.getLogger(__name__)


class ContextManager:
    def __init__(
        self,
    ):
        logger.debug("Initializing ContextManager")
        self.enabled = True
        self.callbacks = defaultdict(list)
        self.running = []

    def enable(self):
        logger.debug("Enabling ContextManager")
        self.enabled = True

    def disable(self):
        logger.debug("Disabling ContextManager")
        self.enabled = False

    def hook(self, signal: str, async_callback: Callable[[str, Any], None]):
        logger.debug("Registering hook for signal: %s", signal)
        self.callbacks[signal].append(async_callback)

    async def emit(self, signal: str, data: Any):
        if self.enabled:
            logger.debug("Emitting signal: %s", signal)
            for callback in self.callbacks[signal]:
                self.running.append(callback(signal, data))

    async def wait(self):
        logger.debug("Waiting for %d running tasks to complete", len(self.running))
        await asyncio.gather(*self.running)


class MCPScanner:
    def __init__(
        self,
        files: list[str] | None = None,
        analysis_url: str = "https://mcp.invariantlabs.ai/api/v1/public/mcp-analysis",
        checks_per_server: int = 1,
        storage_file: str = "~/.mcp-scan",
        server_timeout: int = 10,
        suppress_mcpserver_io: bool = True,
        opt_out: bool = False,
        include_built_in: bool = False,
        verbose: bool = False,
        additional_headers: dict | None = None,
        control_servers: list | None = None,
        skip_ssl_verify: bool = False,
        scan_context: dict | None = None,
        mcp_oauth_tokens_path: str | None = None,
        **kwargs: Any,
    ):
        logger.info("Initializing MCPScanner")
        self.paths = files or []
        logger.debug("Paths to scan: %s", self.paths)
        self.analysis_url = analysis_url
        self.additional_headers = additional_headers or {}
        self.checks_per_server = checks_per_server
        self.storage_file_path = os.path.expanduser(storage_file)
        logger.debug("Storage file path: %s", self.storage_file_path)
        self.storage_file = Storage(self.storage_file_path)
        self.server_timeout = server_timeout
        self.suppress_mcpserver_io = suppress_mcpserver_io
        self.context_manager = None
        self.opt_out_of_identity = opt_out
        self.include_built_in = include_built_in
        self.control_servers = control_servers
        self.verbose = verbose
        self.skip_ssl_verify = skip_ssl_verify
        self.scan_context = scan_context if scan_context is not None else {}
        logger.debug(
            "MCPScanner initialized with timeout: %d, checks_per_server: %d", server_timeout, checks_per_server
        )
        self.mcp_oauth_tokens_path = mcp_oauth_tokens_path
        if self.mcp_oauth_tokens_path:
            if os.path.exists(self.mcp_oauth_tokens_path):
                with open(self.mcp_oauth_tokens_path) as f:
                    try:
                        self.mcp_oauth_tokens = TokenAndClientInfoList.model_validate_json(f.read()).root
                    except ValidationError as e:
                        logger.error(f"Error loading MCP OAuth tokens from {self.mcp_oauth_tokens_path}: {e}")
                        self.mcp_oauth_tokens = None
            else:
                logger.error(f"MCP OAuth tokens file {self.mcp_oauth_tokens_path} does not exist. Skipping MCP OAuth")
                self.mcp_oauth_tokens = None
        else:
            self.mcp_oauth_tokens = None

    def __enter__(self):
        logger.debug("Entering MCPScanner context")
        if self.context_manager is None:
            self.context_manager = ContextManager()
        return self

    async def __aenter__(self):
        logger.debug("Entering MCPScanner async context")
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        logger.debug("Exiting MCPScanner async context")
        if self.context_manager is not None:
            await self.context_manager.wait()
            self.context_manager = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.debug("Exiting MCPScanner context")
        if self.context_manager is not None:
            asyncio.run(self.context_manager.wait())
            self.context_manager = None

    def hook(self, signal: str, async_callback: Callable[[str, Any], None]):
        logger.debug("Registering hook for signal: %s", signal)
        if self.context_manager is not None:
            self.context_manager.hook(signal, async_callback)
        else:
            error_msg = "Context manager not initialized"
            logger.exception(error_msg)
            raise RuntimeError(error_msg)

    async def get_servers_from_path(self, path: str) -> ScanPathResult:
        logger.info("Getting servers from path: %s", path)
        result = ScanPathResult(path=path)
        try:
            if not os.path.exists(path) and is_direct_scan(path):
                servers = (await direct_scan(path)).get_servers()
            else:
                mcp_config = await scan_mcp_config_file(path)
                if isinstance(mcp_config, UnknownMCPConfig):
                    result.error = ScanError(
                        message=f"Unknown MCP config: {path}",
                        is_failure=False,
                        category="unknown_config",
                    )
                servers = mcp_config.get_servers()
            logger.debug("Found %d servers in path: %s", len(servers), path)
            result.servers = [
                ServerScanResult(name=server_name, server=server) for server_name, server in servers.items()
            ]
        except FileNotFoundError as e:
            error_msg = f"resource {path} not found" if is_direct_scan(path) else f"file {path} does not exist"
            logger.exception("%s: %s", error_msg, path)
            # This is a non failing error, so we set is_failure to False.
            result.error = ScanError(
                message=error_msg,
                exception=e,
                traceback=traceback.format_exc(),
                is_failure=False,
                category="file_not_found",
            )
        except Exception as e:
            error_msg = f"could not scan {path}" if is_direct_scan(path) else f"could not parse file {path}"
            logger.exception("%s: %s", error_msg, path)
            result.error = ScanError(
                message=error_msg,
                exception=e,
                traceback=traceback.format_exc(),
                is_failure=True,
                category="parse_error",
            )
        return result

    def check_server_changed(self, path_result: ScanPathResult) -> list[Issue]:
        logger.debug("Checking server changed: %s", path_result.path)
        issues: list[Issue] = []
        if path_result.servers is None:
            return issues
        for server_idx, server in enumerate(path_result.servers):
            logger.debug(
                "Checking for changes in server %d/%d: %s", server_idx + 1, len(path_result.servers), server.name
            )
            for entity_idx, entity in enumerate(server.entities):
                c, messages = self.storage_file.check_and_update(server.name or "", entity)
                if c:
                    logger.info("Entity %s in server %s has changed", entity.name, server.name)
                    message = "Entity has changed. " + ", ".join(messages)
                    issues.append(
                        Issue(
                            code="W003",
                            message=message,
                            reference=(server_idx, entity_idx),
                            title="Entity has changed",
                            severity="info",
                            description=message,
                        )
                    )
        return issues

    async def emit(self, signal: str, data: Any):
        logger.debug("Emitting signal: %s", signal)
        if self.context_manager is not None:
            await self.context_manager.emit(signal, data)

    async def scan_server(self, server: ServerScanResult, token: TokenAndClientInfo | None = None) -> ServerScanResult:
        logger.info("Scanning server: %s", server.name)
        result = server.clone()
        # Capture all MCP traffic for debugging
        traffic_capture = TrafficCapture()
        try:
            result.signature, result.server = await check_server(
                server.server, self.server_timeout, traffic_capture, token
            )
            logger.debug(
                "Server %s has %d prompts, %d resources, %d resouce templates,  %d tools",
                server.name,
                len(result.signature.prompts),
                len(result.signature.resources),
                len(result.signature.resource_templates),
                len(result.signature.tools),
            )
        except HTTPStatusError as e:
            error_msg = "server returned HTTP status code"
            logger.exception("%s: %s", error_msg, server.name)
            result.error = ScanError(
                message=error_msg,
                exception=e,
                traceback=traceback.format_exc(),
                is_failure=True,
                category="server_http_error",
                server_output=traffic_capture.get_traffic_log(),
            )
        except Exception as e:
            # Default to http if the server type is not set, and we could not run the server.
            if result.server.type is None and isinstance(server.server, RemoteServer):
                result.server.type = "http"
            error_msg = "could not start server"
            logger.exception("%s: %s", error_msg, server.name)
            result.error = ScanError(
                message=error_msg,
                exception=e,
                traceback=traceback.format_exc(),
                is_failure=True,
                category="server_startup",
                server_output=traffic_capture.get_traffic_log(),
            )
        await self.emit("server_scanned", result)
        return result

    async def scan_path(
        self, path: str, inspect_only: bool = False, mcp_oauth_tokens: list[TokenAndClientInfo] | None = None
    ) -> ScanPathResult:
        logger.info("Scanning path: %s, inspect_only: %s", path, inspect_only)
        path_result = await self.get_servers_from_path(path)

        if path_result.servers is not None:
            for i, server in enumerate(path_result.servers):
                if server.server.type == "stdio":
                    full_command = server.server.command + " " + " ".join(server.server.args or [])
                    # check if pattern is contained in full_command
                    if re.search(r"mcp[-_]scan.*mcp-server", full_command):
                        logger.info("Skipping scan of server %d/%d: %s", i + 1, len(path_result.servers), server.name)
                        continue
                logger.debug("Scanning server %d/%d: %s", i + 1, len(path_result.servers), server.name)
                token = next((token for token in mcp_oauth_tokens or [] if token.server_name == server.name), None)

                path_result.servers[i] = await self.scan_server(server, token)

        # add built-in tools
        if self.include_built_in:
            path_result = get_builtin_tools(path_result)

        if not inspect_only:
            path_result = await self.check_path(path_result)
        return path_result

    async def check_path(self, path_result: ScanPathResult) -> ScanPathResult:
        logger.debug(f"Check changed: {path_result.path}, {path_result.path is None}")
        path_result.issues += self.check_server_changed(path_result)
        await self.emit("path_scanned", path_result)
        return path_result

    async def scan(self) -> list[ScanPathResult]:
        logger.info("Starting scan of %d paths", len(self.paths))
        scan_start_time = time.perf_counter()
        if self.context_manager is not None:
            self.context_manager.disable()

        result_awaited = []
        for i in range(self.checks_per_server):
            logger.debug("Scan iteration %d/%d", i + 1, self.checks_per_server)
            # intentionally overwrite and only report the last scan
            if i == self.checks_per_server - 1 and self.context_manager is not None:
                logger.debug("Enabling context manager for final iteration")
                self.context_manager.enable()  # only print on last run
            result = [self.scan_path(path) for path in self.paths]
            result_awaited = await asyncio.gather(*result)

        logger.debug("Checking signed binary")
        result_verified = await check_signed_binary(result_awaited)

        logger.debug("Redacting secrets")
        result_verified = [redact_scan_result(rv) for rv in result_verified]

        logger.debug("Calling Backend")
        result_verified = await analyze_machine(
            result_verified,
            analysis_url=self.analysis_url,
            identifier=None,
            additional_headers=self.additional_headers,
            opt_out_of_identity=self.opt_out_of_identity,
            skip_pushing=bool(self.control_servers),
            push_key=get_push_key(self.control_servers) if self.control_servers is not None else None,  # type: ignore[arg-type]
            verbose=self.verbose,
            skip_ssl_verify=self.skip_ssl_verify,
            scan_context=self.scan_context,
        )
        self.scan_context["scan_time_milliseconds"] = (time.perf_counter() - scan_start_time) * 1000

        logger.debug("Result verified: %s", result_verified)
        logger.debug("Saving storage file")
        self.storage_file.save()
        logger.info("Scan completed successfully")
        return result_verified

    async def inspect(self) -> list[ScanPathResult]:
        logger.info("Starting inspection of %d paths", len(self.paths))
        result = [
            self.scan_path(path, inspect_only=True, mcp_oauth_tokens=self.mcp_oauth_tokens) for path in self.paths
        ]
        result_awaited = await asyncio.gather(*result)
        logger.debug("Saving storage file")
        self.storage_file.save()
        logger.info("Inspection completed successfully")
        return result_awaited
