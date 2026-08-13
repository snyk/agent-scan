import asyncio
import getpass
import gzip
import logging
import os
import ssl
import traceback
from typing import Any

import aiohttp
import certifi
import rich
from mcp.types import Prompt, Resource, ResourceTemplate, Tool

from agent_scan.models.api.common import ScanUserInfo
from agent_scan.models.api.v20260710 import (
    McpEntitySummary,
    McpServerRequest,
    McpServerRiskResponse,
    ScanPathResponse,
    ScanRequest,
    ScanResponse,
    SkillFileSummary,
    SkillRequest,
    SkillRiskResponse,
)
from agent_scan.models.errors import ScanError
from agent_scan.models.inspect import InspectedPath
from agent_scan.models.mcp import Entity
from agent_scan.utils import get_environment, get_relative_path
from agent_scan.well_known_clients import get_client_from_path

logger = logging.getLogger(__name__)


def build_scan_request(
    inspected_paths: list[InspectedPath],
    scan_user_info: ScanUserInfo | None = None,
    scan_metadata: dict[str, Any] | None = None,
) -> ScanRequest:
    """Convert inspection results into a v2026-07-10 scan request.

    The versioned API models own the structural conversion from inspection-domain
    models to wire models. This transport boundary additionally makes each top-level
    path home-relative. Per-component ``config_path`` and ``installation_path``
    remain absolute because the backend forwards them to Maverick as the asset
    location.

    ``analyze_machine`` sends this request directly to the v2026-07-10 API.
    """
    request = ScanRequest.from_inspected_paths(
        inspected_paths,
        scan_user_info=scan_user_info,
        scan_metadata=scan_metadata,
    )
    for inspected_path, path_request in zip(inspected_paths, request.scan_path_requests, strict=True):
        path_request.client = get_client_from_path(inspected_path.path) or path_request.client or inspected_path.path
        path_request.path = get_relative_path(path_request.path)
    return request


class SnykTokenError(Exception):
    """Raised when SNYK_TOKEN is required but not set. Handled at top level to exit without traceback."""


# Sync push-key endpoint suffix and its async counterpart.
_SYNC_ANALYSIS_PATH = "/hidden/mcp-scan/analysis-machine"
_ASYNC_ANALYSIS_PATH = "/hidden/agent-scan/async/analysis"
_AGENT_SCAN_CONFIG_PATH = "/hidden/agent-scan/config"


async def _async_analysis_enabled(
    config_url: str,
    push_key: str,
    trace_configs: list | None,
    skip_ssl_verify: bool,
) -> bool:
    """Ask the backend whether this push-key's tenant routes to async analysis.

    Returns False on any error or non-200 response so the caller uses the
    synchronous path.
    """
    try:
        async with _analysis_client_session(trace_configs, skip_ssl_verify) as session:
            async with session.get(
                config_url,
                headers={"X-Push-Key": push_key},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as response:
                if response.status != 200:
                    logger.warning(
                        "Agent Scan config request returned %s; using synchronous analysis.", response.status
                    )
                    return False
                data = await response.json()
                return bool(data.get("async_analysis_enabled", False))
    except (TimeoutError, aiohttp.ClientError) as e:
        logger.warning("Agent Scan config request failed (%s); using synchronous analysis.", e)
        return False


async def _submit_async_analysis(
    async_url: str,
    payload: ScanRequest,
    base_headers: dict[str, str],
    identifier: str | None,
    trace_configs: list | None,
    skip_ssl_verify: bool,
) -> None:
    """Stream the gzipped payload to the async accept endpoint"""
    body = gzip.compress(payload.model_dump_json().encode("utf-8"))
    headers = {
        **base_headers,
        "Content-Type": "application/json",
        "Content-Encoding": "gzip",
    }
    if identifier:
        headers["X-Scan-User-Id"] = identifier
    try:
        async with _analysis_client_session(trace_configs, skip_ssl_verify) as session:
            async with session.post(
                async_url,
                data=body,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=75),
            ) as response:
                if response.status == 202:
                    logger.info("Scan accepted for asynchronous analysis.")
                else:
                    logger.warning("Async analysis returned status %s.", response.status)
    except (TimeoutError, aiohttp.ClientError) as e:
        logger.warning("Async analysis request failed: %s", e)


def _entity_summary(entity: Entity) -> McpEntitySummary:
    if isinstance(entity, Tool):
        entity_type = "tool"
    elif isinstance(entity, Prompt):
        entity_type = "prompt"
    elif isinstance(entity, Resource):
        entity_type = "resource"
    elif isinstance(entity, ResourceTemplate):
        entity_type = "resource_template"
    else:
        raise ValueError(f"Unknown entity type: {type(entity)}")
    return McpEntitySummary(name=entity.name, type=entity_type)


def _skill_file_summary(path: str) -> SkillFileSummary:
    lowered = path.lower()
    if lowered.endswith(".md"):
        file_type = "instruction"
    elif lowered.rsplit(".", 1)[-1] in ("py", "js", "ts", "sh"):
        file_type = "script"
    else:
        file_type = "asset"
    return SkillFileSummary(name=path, type=file_type)


def _accepted_server_response(server: McpServerRequest) -> McpServerRiskResponse:
    return McpServerRiskResponse(
        name=server.name,
        entities=[_entity_summary(entity) for entity in server.signature.entities] if server.signature else [],
        error=server.error.model_copy(deep=True) if server.error else None,
    )


def _accepted_skill_response(skill: SkillRequest) -> SkillRiskResponse:
    return SkillRiskResponse(
        name=skill.name,
        files=[_skill_file_summary(file.path) for file in skill.files],
        error=skill.error.model_copy(deep=True) if skill.error else None,
    )


def _accepted_async_response(request: ScanRequest) -> ScanResponse:
    """Represent paths accepted for async analysis without fabricating risks."""

    return ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                client=path.client,
                path=path.path,
                server_risks=[_accepted_server_response(server) for server in path.servers],
                skill_risks=[_accepted_skill_response(skill) for skill in path.skills],
                error=path.error.model_copy(deep=True) if path.error else None,
            )
            for path in request.scan_path_requests
        ]
    )


def get_hostname() -> str:
    ci_hostname = os.getenv("AGENT_SCAN_CI_HOSTNAME")
    if get_environment() == "ci" and ci_hostname:
        return ci_hostname
    else:
        try:
            return os.uname().nodename
        except Exception:
            return "unknown"


def get_username() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def setup_aiohttp_debug_logging(verbose: bool) -> list[aiohttp.TraceConfig]:
    """Setup detailed aiohttp logging and tracing for debugging purposes."""
    # Enable aiohttp internal logging
    aiohttp_logger = logging.getLogger("aiohttp")
    aiohttp_logger.setLevel(logging.DEBUG)
    aiohttp_client_logger = logging.getLogger("aiohttp.client")
    aiohttp_client_logger.setLevel(logging.DEBUG)

    # Create trace config for detailed aiohttp logging
    trace_config = aiohttp.TraceConfig()

    if verbose:
        return []

    async def on_request_start(session, trace_config_ctx, params):
        logger.debug("aiohttp: Starting request %s %s", params.method, params.url)

    async def on_request_end(session, trace_config_ctx, params):
        logger.debug("aiohttp: Request completed %s %s -> %s", params.method, params.url, params.response.status)

    async def on_connection_create_start(session, trace_config_ctx, params):
        logger.debug("aiohttp: Creating connection")

    async def on_connection_create_end(session, trace_config_ctx, params):
        logger.debug("aiohttp: Connection created")

    async def on_dns_resolvehost_start(session, trace_config_ctx, params):
        logger.debug("aiohttp: Starting DNS resolution for %s", params.host)

    async def on_dns_resolvehost_end(session, trace_config_ctx, params):
        logger.debug("aiohttp: DNS resolution completed for %s", params.host)

    async def on_connection_queued_start(session, trace_config_ctx, params):
        logger.debug("aiohttp: Connection queued")

    async def on_connection_queued_end(session, trace_config_ctx, params):
        logger.debug("aiohttp: Connection dequeued")

    async def on_request_exception(session, trace_config_ctx, params):
        logger.error("aiohttp: Request exception for %s %s: %s", params.method, params.url, params.exception)
        # Check if it's an SSL-related exception
        if hasattr(params.exception, "__class__"):
            exc_name = params.exception.__class__.__name__
            if "ssl" in exc_name.lower() or "certificate" in str(params.exception).lower():
                logger.error("aiohttp: SSL/Certificate error detected: %s", params.exception)

    async def on_request_redirect(session, trace_config_ctx, params):
        logger.debug(
            "aiohttp: Request redirected from %s %s to %s",
            params.method,
            params.url,
            params.response.headers.get("Location", "unknown"),
        )

    trace_config.on_request_start.append(on_request_start)
    trace_config.on_request_end.append(on_request_end)
    trace_config.on_connection_create_start.append(on_connection_create_start)
    trace_config.on_connection_create_end.append(on_connection_create_end)
    trace_config.on_dns_resolvehost_start.append(on_dns_resolvehost_start)
    trace_config.on_dns_resolvehost_end.append(on_dns_resolvehost_end)
    trace_config.on_connection_queued_start.append(on_connection_queued_start)
    trace_config.on_connection_queued_end.append(on_connection_queued_end)
    trace_config.on_request_exception.append(on_request_exception)
    trace_config.on_request_redirect.append(on_request_redirect)

    return [trace_config]


# Environment variables that may point to an additional CA certificate (or bundle)
# to trust. The Snyk CLI runs agent-scan behind a local authenticating reverse proxy
# and exports these variables pointing at the proxy's self-signed certificate. Loading
# them lets proxied TLS calls succeed without requiring --skip-ssl-verify.
_CA_CERT_ENV_VARS = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")


def load_extra_ca_certs(ssl_context: ssl.SSLContext) -> None:
    """Trust additional CA certificates referenced by environment variables.

    Certificates are added on top of the existing (certifi) trust store rather than
    replacing it, so both public endpoints and the Snyk CLI's proxy are trusted.
    Missing or invalid files are logged and skipped rather than raising.
    """
    loaded: set[str] = set()
    for env_var in _CA_CERT_ENV_VARS:
        cert_path = os.environ.get(env_var)
        if not cert_path:
            continue
        real_path = os.path.realpath(cert_path)
        if real_path in loaded:
            continue
        if not os.path.isfile(real_path):
            logger.warning("Ignoring %s: certificate file not found at %s", env_var, cert_path)
            continue
        try:
            ssl_context.load_verify_locations(cafile=real_path)
            loaded.add(real_path)
            logger.debug("Loaded extra CA certificate from %s (%s)", env_var, cert_path)
        except (ssl.SSLError, OSError) as exc:
            logger.warning("Failed to load CA certificate from %s (%s): %s", env_var, cert_path, exc)


def setup_tcp_connector(skip_ssl_verify: bool = False) -> aiohttp.TCPConnector:
    """
    Setup a TCP connector with SSL settings.

    When skip_ssl_verify is True, disable SSL verification and hostname checking.
    Otherwise, use a secure default SSL context with certifi CA and TLSv1.2+, extended
    with any additional CA certificates referenced by the environment (see
    load_extra_ca_certs) so calls proxied through the Snyk CLI are trusted.
    """
    if skip_ssl_verify:
        # Disable SSL verification at the connector level
        return aiohttp.TCPConnector(ssl=False, enable_cleanup_closed=True)

    ssl_context = ssl.create_default_context(cafile=certifi.where())
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    load_extra_ca_certs(ssl_context)
    connector = aiohttp.TCPConnector(ssl=ssl_context, enable_cleanup_closed=True)
    return connector


def _analysis_client_session(trace_configs: list | None, skip_ssl_verify: bool) -> aiohttp.ClientSession:
    """Build a ClientSession with the shared connector, tracing and proxy settings."""
    return aiohttp.ClientSession(
        trace_configs=trace_configs,
        connector=setup_tcp_connector(skip_ssl_verify=skip_ssl_verify),
        trust_env=True,
    )


async def analyze_machine(
    inspected_paths: list[InspectedPath],
    analysis_url: str,
    identifier: str | None,
    additional_headers: dict | None = None,
    verbose: bool = False,
    skip_pushing: bool = False,
    push_key: str | None = None,
    max_retries: int = 3,
    skip_ssl_verify: bool = False,
    raise_on_error: bool = False,
    scan_context: dict | None = None,
    scanned_usernames: list[str] | None = None,
) -> ScanResponse:
    """
    Analyze the scan paths with the analysis server.

    Args:
        inspected_paths: Local MCP server and skill inspection results to analyze
        analysis_url: URL of the analysis server
        identifier: Identifier for the user
        additional_headers: Additional headers to send to the analysis server
        verbose: Whether to enable verbose logging
        skip_pushing: Whether to skip pushing the scan to the platform
        max_retries: Maximum number of retry attempts
        skip_ssl_verify: Whether to skip SSL verification
        scan_context: Optional dict containing scan metadata to include in the request
    """
    logger.debug(f"Analyzing scan path with URL: {analysis_url}")

    # for analysis server we never push personal information
    user_info = ScanUserInfo(
        hostname=get_hostname(),
        username=scanned_usernames if scanned_usernames else [get_username()],
        identifier=identifier,
        ip_address=None,
        anonymous_identifier=None,
    )

    payload = build_scan_request(
        inspected_paths,
        scan_user_info=user_info,
        scan_metadata=scan_context if scan_context else None,
    )
    logger.debug("Payload: %s", payload.model_dump_json())
    trace_configs = setup_aiohttp_debug_logging(verbose=verbose)
    headers = {
        "Content-Type": "application/json",
        "X-Environment": os.getenv("AGENT_SCAN_ENVIRONMENT", "production"),
    }

    if additional_headers:
        headers.update(additional_headers)
    if skip_pushing:
        headers["X-Push"] = "skip"

    snyk_token = os.getenv("SNYK_TOKEN")
    if push_key:
        # Enterprise MDM mode with push key
        # The analysis_url in this case has authentication through push_key (not on api-gateway)
        headers["X-Push-Key"] = push_key
        config_url = analysis_url.replace(_SYNC_ANALYSIS_PATH, _AGENT_SCAN_CONFIG_PATH)
        if await _async_analysis_enabled(config_url, push_key, trace_configs, skip_ssl_verify):
            async_url = analysis_url.replace(_SYNC_ANALYSIS_PATH, _ASYNC_ANALYSIS_PATH)
            await _submit_async_analysis(async_url, payload, headers, identifier, trace_configs, skip_ssl_verify)
            return _accepted_async_response(payload)
    elif snyk_token:
        # CLI mode with SNYK_TOKEN environment variable for authentication
        analysis_url = analysis_url.replace(
            "/hidden/mcp-scan/analysis-machine", "/hidden/mcp-scan/cli/analysis-machine"
        )
        headers["Authorization"] = f"token {snyk_token}"
    elif os.getenv("SNYK_CLI_USE", "false").lower() == "true":
        # Snyk CLI mode with authentication through the proxy
        # Update the analysis_url to use the use the api gateway authenticated endpoint
        analysis_url = analysis_url.replace(
            "/hidden/mcp-scan/analysis-machine", "/hidden/mcp-scan/cli/analysis-machine"
        )
    else:
        rich.print(
            "[bold red]To use Agent Scan, set the SNYK_TOKEN environment variable. "
            "To get a token, go to https://app.snyk.io/account (API Token -> KEY -> click to show).[/bold red]"
        )
        raise SnykTokenError("SNYK_TOKEN environment variable not set")

    for attempt in range(max_retries):
        try:
            async with _analysis_client_session(trace_configs, skip_ssl_verify) as session:
                async with session.post(
                    analysis_url,
                    data=payload.model_dump_json(),
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=75),
                ) as response:
                    response.raise_for_status()
                    if response.status == 200:
                        response_data = ScanResponse.model_validate_json(await response.text())
                        logger.info("Successfully analyzed scan results.")
                        return response_data

        except TimeoutError as e:
            logger.warning(f"API timeout while scanning discovered servers (attempt {attempt + 1}/{max_retries}): {e}.")
            error_text = f"API timeout while scanning discovered servers: {e}"

        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                error_text = "Unauthorized. Please check your SNYK_TOKEN environment variable or your push key."
            elif e.status == 413:
                error_text = "Analysis scope too large (e.g. too many or very large MCP servers/skills). Please consider scanning individual MCP servers or skill directories."
            elif e.status == 429:
                error_text = "Daily usage limit reached for the public version of Agent-Scan. Unlock higher limits and enterprise features by contacting us at https://evo.ai.snyk.io/#contact-us."
            elif 400 <= e.status < 500:
                error_text = f"The analysis server returned an error for your request: {e.status} - {e.message}"
            else:
                error_text = f"Could not reach analysis server: {e.status} - {e.message}"

            logger.warning(error_text)
            return _analysis_error_response(payload, error_text, e)

        except RuntimeError as e:
            logger.warning(f"Network error while uploading (attempt {attempt + 1}/{max_retries}): {e}")
            raise

        except Exception as e:
            logger.error(f"Unexpected error while uploading scan results (attempt {attempt + 1}/{max_retries}): {e}")
            raise e

        # If not the last attempt, wait before retrying (exponential backoff)
        if attempt < max_retries - 1:
            backoff_time = 2**attempt  # 1s, 2s, 4s
            logger.info(f"Retrying in {backoff_time} seconds...")
            await asyncio.sleep(backoff_time)

    if raise_on_error:
        raise RuntimeError(
            f"Tried calling verification api {max_retries} times. Could not reach analysis server. Last error: {error_text}"
        )
    # Failed even after all retries.
    return _analysis_error_response(
        payload,
        f"Tried calling verification api {max_retries} times. Could not reach analysis server. Last error: {error_text}",
    )


def _analysis_error_response(
    request: ScanRequest,
    message: str,
    exception: Exception | None = None,
) -> ScanResponse:
    """Return one analysis failure response for every inspected path."""
    return ScanResponse(
        scan_path_responses=[
            ScanPathResponse(
                client=path_request.client,
                path=path_request.path,
                error=ScanError(
                    message=message,
                    exception=exception,
                    traceback=traceback.format_exc(),
                    is_failure=True,
                    category="analysis_error",
                ),
            )
            for path_request in request.scan_path_requests
        ]
    )
