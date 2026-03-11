import asyncio
import getpass
import logging
import os
import ssl
import traceback

import aiohttp
import certifi
import rich

from agent_scan.models import (
    ScanError,
    ScanPathResult,
    ScanPathResultsCreate,
    ScanUserInfo,
)
from agent_scan.utils import get_environment
from agent_scan.well_known_clients import get_client_from_path

logger = logging.getLogger(__name__)


class SnykTokenError(Exception):
    """Raised when SNYK_TOKEN is required but not set. Handled at top level to exit without traceback."""


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


def setup_tcp_connector(skip_ssl_verify: bool = False) -> aiohttp.TCPConnector:
    """
    Setup a TCP connector with SSL settings.

    When skip_ssl_verify is True, disable SSL verification and hostname checking.
    Otherwise, use a secure default SSL context with certifi CA and TLSv1.2+.
    """
    if skip_ssl_verify:
        # Disable SSL verification at the connector level
        return aiohttp.TCPConnector(ssl=False, enable_cleanup_closed=True)

    ssl_context = ssl.create_default_context(cafile=certifi.where())
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    connector = aiohttp.TCPConnector(ssl=ssl_context, enable_cleanup_closed=True)
    return connector


async def analyze_machine(
    scan_paths: list[ScanPathResult],
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
) -> list[ScanPathResult]:
    """
    Analyze the scan paths with the analysis server.

    Args:
        scan_paths: List of scan path results to analyze
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
        hostname=None,
        username=None,
        identifier=identifier,
        ip_address=None,
        anonymous_identifier=None,
    )

    for result in scan_paths:
        result.client = get_client_from_path(result.path) or result.client or result.path

    payload = ScanPathResultsCreate(
        scan_path_results=scan_paths,
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
    if snyk_token:
        # CLI mode with SNYK_TOKEN environment variable for authentication
        analysis_url = analysis_url.replace(
            "/hidden/mcp-scan/analysis-machine", "/hidden/mcp-scan/cli/analysis-machine"
        )
        headers["Authorization"] = f"token {snyk_token}"
    elif push_key:
        # Enterprise MDM mode with push key
        # The analysis_url in this case has authentication through push_key (not on api-gateway)
        headers["X-Push-Key"] = push_key
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
            async with aiohttp.ClientSession(
                trace_configs=trace_configs,
                connector=setup_tcp_connector(skip_ssl_verify=skip_ssl_verify),
                trust_env=True,
            ) as session:
                async with session.post(
                    analysis_url,
                    data=payload.model_dump_json(),
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as response:
                    response.raise_for_status()
                    if response.status == 200:
                        response_data = ScanPathResultsCreate.model_validate_json(await response.text())
                        logger.info("Successfully analyzed scan results.")
                        for sent_scan_path_result, response_scan_path_result in zip(
                            scan_paths, response_data.scan_path_results, strict=True
                        ):
                            sent_scan_path_result.issues = response_scan_path_result.issues
                            sent_scan_path_result.labels = response_scan_path_result.labels
                            for server_given, server_received in zip(
                                sent_scan_path_result.servers or [],
                                response_scan_path_result.servers or [],
                                strict=True,
                            ):
                                if server_given.signature is None:
                                    server_given.signature = server_received.signature
                        return scan_paths  # Success - exit the function

        except TimeoutError as e:
            logger.warning(f"API timeout while scanning discovered servers (attempt {attempt + 1}/{max_retries}): {e}.")
            error_text = f"API timeout while scanning discovered servers: {e}"

        except aiohttp.ClientResponseError as e:
            if 400 <= e.status < 500:
                if e.status == 413:  # Request Entity Too Large (large skill payloads or MCP server signatures)
                    error_text = "Analysis scope too large (e.g. too many or very large MCP servers/skills). Please consider scanning individual MCP servers or skill directories."
                else:  # Other 400 errors (e.g. invalid JSON, missing required fields, etc.)
                    error_text = f"The analysis server returned an error for your request: {e.status} - {e.message}"
                logger.warning(error_text)
                for scan_path in scan_paths:
                    if scan_path.servers is not None and scan_path.error is None:
                        scan_path.error = ScanError(
                            message=error_text,
                            exception=e,
                            traceback=traceback.format_exc(),
                            is_failure=True,
                            category="analysis_error",
                        )
                        return scan_paths
            else:  # 500 errors (e.g. server error, service unavailable, etc.)
                error_text = f"Could not reach analysis server: {e.status} - {e.message}"
                logger.warning(error_text)
                for scan_path in scan_paths:
                    if scan_path.servers is not None and scan_path.error is None:
                        scan_path.error = ScanError(
                            message=error_text,
                            exception=e,
                            traceback=traceback.format_exc(),
                            is_failure=True,
                            category="analysis_error",
                        )
                return scan_paths

        except RuntimeError as e:
            logger.warning(f"Network error while uploading (attempt {attempt + 1}/{max_retries}): {e}")
            raise RuntimeError(error_text) from e

        except Exception as e:
            logger.error(f"Unexpected error while uploading scan results (attempt {attempt + 1}/{max_retries}): {e}")
            # For unexpected errors, don't retry
            rich.print(f"❌ Unexpected error while uploading scan results: {e}")
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
    # failed even after all retries
    for scan_path in scan_paths:
        if scan_path.servers is not None and scan_path.error is None:
            scan_path.error = ScanError(
                message=f"Tried calling verification api {max_retries} times. Could not reach analysis server. Last error: {error_text}",
                exception=None,
                traceback=traceback.format_exc(),
                is_failure=True,
                category="analysis_error",
            )
    return scan_paths
