# fix ssl certificates if custom certificates (i.e. ZScaler) are used
# as this needs to occur at the beginning of the file, we need to disable the ruff rule
# ruff: noqa: E402
from typing import Literal

import truststore

truststore.inject_into_ssl()

import argparse
import asyncio
import json
import logging
import sys

import aiohttp
import psutil
import rich
from rich.logging import RichHandler

from agent_scan.models import ControlServer, ScanPathResult, TokenAndClientInfo, TokenAndClientInfoList
from agent_scan.pipelines import AnalyzeArgs, InspectArgs, PushArgs, inspect_analyze_push_pipeline, inspect_pipeline
from agent_scan.printer import print_scan_result
from agent_scan.upload import get_hostname
from agent_scan.utils import ensure_unicode_console, parse_headers, suppress_stdout
from agent_scan.verify_api import setup_aiohttp_debug_logging, setup_tcp_connector
from agent_scan.version import version_info

# Configure logging to suppress all output by default
logging.getLogger().setLevel(logging.CRITICAL + 1)  # Higher than any standard level
# Add null handler to prevent "No handler found" warnings
logging.getLogger().addHandler(logging.NullHandler())


def setup_logging(verbose=False, log_to_stderr=False):
    """Configure logging based on the verbose flag."""
    if verbose:
        # Configure the root logger
        root_logger = logging.getLogger()
        # Remove any existing handlers (including the NullHandler)
        for hdlr in root_logger.handlers:
            root_logger.removeHandler(hdlr)
        if log_to_stderr:
            # stderr logging
            stderr_console = rich.console.Console(stderr=True)
            logging.basicConfig(
                format="%(message)s",
                datefmt="[%X]",
                force=True,
                level=logging.DEBUG,
                handlers=[RichHandler(markup=True, rich_tracebacks=True, console=stderr_console)],
            )
            root_logger.debug("Verbose mode enabled, logging initialized to stderr")
        else:  # stdout logging
            logging.basicConfig(
                format="%(message)s",
                datefmt="[%X]",
                force=True,
                level=logging.DEBUG,
                handlers=[RichHandler(markup=True, rich_tracebacks=True)],
            )
            root_logger.debug("Logging initialized to stdout")
        root_logger.debug("Logging initialized")


def get_invoking_name():
    try:
        parent = psutil.Process().parent()
        cmd = parent.cmdline()
        argv = sys.argv[1:]
        # remove args that are in argv from cmd
        for i in range(len(argv)):
            if cmd[-1] == argv[-i]:
                cmd = cmd[:-1]
            else:
                break
        cmd = " ".join(cmd)
    except Exception:
        cmd = "agent-scan"
    return cmd


def str2bool(v: str) -> bool:
    return v.lower() in ("true", "1", "t", "y", "yes")


def parse_control_servers(argv):
    """
    Parse control server arguments from sys.argv.
    Returns a list of control server configurations, where each config is a dict with:
    - url: the control server URL
    - headers: list of additional headers
    - identifier: the control identifier (or None)
    """
    control_servers = []
    current_server = None

    i = 0
    while i < len(argv):
        arg = argv[i]

        if arg == "--control-server":
            # Save previous server if exists
            if current_server is not None:
                control_servers.append(current_server)

            # Start new server config
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                current_server = {
                    "url": argv[i + 1],
                    "headers": [],
                    "identifier": None,
                }
                i += 1  # Skip the URL value
            else:
                current_server = None

        elif current_server is not None:
            if arg == "--control-server-H":
                if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                    current_server["headers"].append(argv[i + 1])
                    i += 1

            elif arg == "--control-identifier" and i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                current_server["identifier"] = argv[i + 1]
                i += 1

        i += 1

    # Don't forget the last server
    if current_server is not None:
        control_servers.append(current_server)

    return control_servers


def add_common_arguments(parser):
    """Add arguments that are common to multiple commands."""
    parser.add_argument(
        "--storage-file",
        type=str,
        default="~/.mcp-scan",
        help="Path to store scan results and scanner state",
        metavar="FILE",
    )
    parser.add_argument(
        "--analysis-url",
        type=str,
        default="https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2025-09-02",
        help="URL endpoint for the verification server",
        metavar="URL",
    )
    parser.add_argument(
        "--verification-H",
        action="append",
        help="Additional headers for the verification server",
    )
    parser.add_argument(
        "--mcp-oauth-tokens-path",
        type=str,
        help="Path of the file where the MCP OAuth tokens are stored.",
    )
    parser.add_argument(
        "--verbose",
        default=False,
        action="store_true",
        help="Enable detailed logging output",
    )
    parser.add_argument(
        "--print-errors",
        default=False,
        action="store_true",
        help="Show error details and tracebacks",
    )
    parser.add_argument(
        "--print-full-descriptions",
        default=False,
        action="store_true",
        help="Show error details and tracebacks",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results in JSON format instead of rich text",
    )
    parser.add_argument(
        "--skip-ssl-verify",
        default=False,
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--skills",
        default=False,
        action="store_true",
        help="Scan skills beyond mcp servers.",
    )
    parser.add_argument(
        "--scan-all-users",
        default=False,
        action="store_true",
        help="Scan all users on the machine.",
    )


def add_server_arguments(parser):
    """Add arguments related to MCP server connections."""
    server_group = parser.add_argument_group("MCP Server Options")
    server_group.add_argument(
        "--server-timeout",
        type=float,
        default=10,
        help="Seconds to wait before timing out server connections (default: 10)",
        metavar="SECONDS",
    )
    server_group.add_argument(
        "--suppress-mcpserver-io",
        default=True,
        type=str2bool,
        help="Suppress stdout/stderr from MCP servers (default: True)",
        metavar="BOOL",
    )


def add_scan_arguments(scan_parser):
    scan_parser.add_argument(
        "--checks-per-server",
        type=int,
        default=1,
        help="Number of times to check each server (default: 1)",
        metavar="NUM",
    )
    scan_parser.add_argument(
        "--control-server",
        action="append",
        help="Upload the scan results to the provided control server URL. Can be specified multiple times for multiple control servers.",
    )
    scan_parser.add_argument(
        "--control-server-H",
        action="append",
        help="Additional headers for the preceding control server",
    )
    scan_parser.add_argument(
        "--control-identifier",
        action="append",
        help="Non-anonymous identifier used to identify the user to the preceding control server, e.g. email or serial number",
    )


def setup_scan_parser(scan_parser, add_files=True):
    if add_files:
        scan_parser.add_argument(
            "files",
            nargs="*",
            default=[],
            help="Path(s) to MCP config file(s). If not provided, well-known paths will be checked",
            metavar="CONFIG_FILE",
        )
    add_common_arguments(scan_parser)
    add_server_arguments(scan_parser)
    add_scan_arguments(scan_parser)


def main():
    ensure_unicode_console()
    # Create main parser with description
    program_name = get_invoking_name()
    parser = argparse.ArgumentParser(
        prog=program_name,
        description="Snyk Agent Scan: Security scanner for Model Context Protocol servers and tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            f"  {program_name}                     # Scan all known MCP configs\n"
            f"  {program_name} ~/custom/config.json # Scan a specific config file\n"
            f"  {program_name} inspect             # Just inspect tools without verification\n"
            f"  {program_name} --skills            # Scan skills beyond mcp servers.\n"
            f"  {program_name} --verbose           # Enable detailed logging output\n"
            f"  {program_name} --print-errors      # Show error details and tracebacks\n"
            f"  {program_name} --json              # Output results in JSON format\n\n"
            f"  # Multiple control servers with individual options:\n"
            f'  {program_name} --control-server https://server1.com --control-server-H "Auth: token1" \\\n'
            f"    --control-identifier user@example.com \\\n"
            f'    --control-server https://server2.com --control-server-H "Auth: token2" \\\n'
            f"    --control-identifier serial-123\n"
        ),
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(
        dest="command",
        title="Commands",
        description="Available commands (default: scan)",
        metavar="COMMAND",
    )
    # SCAN command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan one or more MCP config files [default]",
        description=(
            "Scan one or more MCP configuration files for security issues. "
            "If no files are specified, well-known config locations will be checked."
        ),
    )
    setup_scan_parser(scan_parser)

    # INSPECT command
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Print descriptions of tools, prompts, and resources without verification",
        description="Inspect and display MCP tools, prompts, and resources without security verification.",
    )
    add_common_arguments(inspect_parser)
    add_server_arguments(inspect_parser)
    inspect_parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=[],
        help="Configuration files to inspect (default: known MCP config locations)",
        metavar="CONFIG_FILE",
    )

    # install
    install_autoscan_parser = subparsers.add_parser(
        "install-mcp-server", help="Install itself as a MCP server for automatic scanning (experimental)"
    )
    install_autoscan_parser.add_argument("file", type=str, default=None, help="File to install the MCP server in")
    install_autoscan_parser.add_argument(
        "--tool", action="store_true", default=False, help="Expose a tool for scanning"
    )
    install_autoscan_parser.add_argument(
        "--background", action="store_true", default=False, help="Periodically run the scan in the background"
    )
    install_autoscan_parser.add_argument(
        "--scan-interval",
        type=int,
        default=60 * 30,
        help="Scan interval in seconds (default: 1800 seconds = 30 minutes)",
    )
    install_autoscan_parser.add_argument(
        "--client-name", type=str, default=None, help="Name of the client issuing the scan"
    )
    setup_scan_parser(install_autoscan_parser, add_files=False)

    # mcp server mode
    mcp_server_parser = subparsers.add_parser("mcp-server", help="Start an MCP server (experimental)")
    mcp_server_parser.add_argument("--tool", action="store_true", default=False, help="Expose a tool for scanning")
    mcp_server_parser.add_argument(
        "--background", action="store_true", default=False, help="Periodically run the scan in the background"
    )
    mcp_server_parser.add_argument(
        "--scan-interval",
        type=int,
        default=60 * 30,
        help="Scan interval in seconds (default: 1800 seconds = 30 minutes)",
    )
    mcp_server_parser.add_argument("--client-name", type=str, default=None, help="Name of the client issuing the scan")
    setup_scan_parser(mcp_server_parser)

    # HELP command
    help_parser = subparsers.add_parser(  # noqa: F841
        "help",
        help="Show detailed help information",
        description="Display detailed help information and examples.",
    )

    # EVO command
    evo_parser = subparsers.add_parser("evo", help="Push scan results to Snyk Evo")

    # use the same parser as scan
    setup_scan_parser(evo_parser)

    # Parse arguments (default to 'scan' if no command provided)
    if (len(sys.argv) == 1 or sys.argv[1] not in subparsers.choices) and (
        not (len(sys.argv) == 2 and sys.argv[1] == "--help")
    ):
        sys.argv.insert(1, "scan")

    # Parse control servers before argparse to preserve their grouping
    control_servers = parse_control_servers(sys.argv)

    args = parser.parse_args()

    # Attach parsed control servers to args
    args.control_servers = control_servers

    # Display version banner
    if not ((hasattr(args, "json") and args.json) or (args.command == "mcp-server")):
        rich.print(f"[bold blue]Snyk Agent Scan v{version_info}[/bold blue]\n")

    # Set up logging if verbose flag is enabled
    do_log = hasattr(args, "verbose") and args.verbose
    setup_logging(do_log, log_to_stderr=(args.command != "mcp-server"))

    # Handle commands
    if args.command == "help" or (args.command is None and hasattr(args, "help") and args.help):
        parser.print_help()
        sys.exit(0)
    elif args.command == "inspect":
        asyncio.run(print_scan_inspect(mode="inspect", args=args))
        sys.exit(0)
    elif args.command == "scan" or args.command is None:  # default to scan
        asyncio.run(print_scan_inspect(args=args))
        sys.exit(0)
    elif args.command == "mcp-server":
        from agent_scan.mcp_server import mcp_server

        sys.exit(mcp_server(args))
    elif args.command == "install-mcp-server":
        from agent_scan.mcp_server import install_mcp_server

        sys.exit(install_mcp_server(args))
    elif args.command == "evo":
        asyncio.run(evo(args))
        sys.exit(0)

    else:
        # This shouldn't happen due to argparse's handling
        rich.print(f"[bold red]Unknown command: {args.command}[/bold red]")
        parser.print_help()
        sys.exit(1)


async def evo(args):
    """
    Pushes the scan results to the Evo API.

    1. Creates a client_id (shared secret)
    2. Pushes scan results to the Evo API
    3. Revokes the client_id
    """
    rich.print(
        "Go to https://app.snyk.io and select the tenant on the left nav bar. Copy the Tenant ID from the URL and paste it here: "
    )
    tenant_id = input().strip()
    rich.print("Paste the Authorization token from https://app.snyk.io/account (API Token -> KEY -> click to show): ")
    token = input().strip()

    push_key_url = f"https://api.snyk.io/hidden/tenants/{tenant_id}/mcp-scan/push-key?version=2025-08-28"
    push_scan_url = "https://api.snyk.io/hidden/mcp-scan/push?version=2025-08-28"

    # create a client_id (shared secret)
    client_id = None
    skip_ssl_verify = getattr(args, "skip_ssl_verify", False)
    trace_configs = setup_aiohttp_debug_logging(verbose=False)
    try:
        async with aiohttp.ClientSession(
            trace_configs=trace_configs,
            connector=setup_tcp_connector(skip_ssl_verify=skip_ssl_verify),
            trust_env=True,
        ) as session:
            async with session.post(
                push_key_url, data="", headers={"Content-Type": "application/json", "Authorization": f"token {token}"}
            ) as resp:
                if resp.status not in (200, 201):
                    text = await resp.text()
                    rich.print(f"[bold red]Request failed[/bold red]: HTTP {resp.status} - {text}")
                    return
                data = await resp.json()
                client_id = data.get("client_id")
                if not client_id:
                    rich.print(f"[bold red]Unexpected response[/bold red]: {data}")
                    return
                rich.print("Client ID created")
    except Exception as e:
        rich.print(f"[bold red]Error calling Snyk API[/bold red]: {e}")
        return

    # Update the default scan args
    args.control_servers = [
        {
            "url": push_scan_url,
            "identifier": get_hostname() or None,
            "headers": [f"x-client-id:{client_id}"],
        }
    ]
    await run_scan(args, mode="scan")

    # revoke the created client_id
    del_headers = {
        "Content-Type": "application/json",
        "Authorization": f"token {token}",
        "x-client-id": client_id,
    }
    try:
        async with aiohttp.ClientSession(
            trace_configs=trace_configs,
            connector=setup_tcp_connector(skip_ssl_verify=skip_ssl_verify),
            trust_env=True,
        ) as session:
            async with session.delete(push_key_url, headers=del_headers) as del_resp:
                if del_resp.status not in (200, 204):
                    text = await del_resp.text()
                    rich.print(f"[bold red]Failed to revoke client_id[/bold red]: HTTP {del_resp.status} - {text}")
                rich.print("Client ID revoked")
    except Exception as e:
        rich.print(f"[bold red]Error revoking client_id[/bold red]: {e}")


async def run_scan(args, mode: Literal["scan", "inspect"] = "scan") -> list[ScanPathResult]:
    """
    Run the scan/inspect pipeline and return results.
    """
    verbose: bool = hasattr(args, "verbose") and args.verbose
    scan_all_users: bool = hasattr(args, "scan_all_users") and args.scan_all_users

    server_timeout: int = args.server_timeout if hasattr(args, "server_timeout") else 10
    files: list[str] | None = args.files if hasattr(args, "files") else None
    scan_skills: bool = hasattr(args, "skills") and args.skills
    tokens: list[TokenAndClientInfo] = []
    if hasattr(args, "mcp_oauth_tokens_path") and args.mcp_oauth_tokens_path:
        with open(args.mcp_oauth_tokens_path) as f:
            tokens = TokenAndClientInfoList.model_validate_json(f.read()).root

    inspect_args = InspectArgs(
        timeout=server_timeout,
        tokens=tokens,
        paths=files,
        all_users=scan_all_users,
        scan_skills=scan_skills,
    )

    if mode == "scan":
        skip_ssl_verify: bool = bool(hasattr(args, "skip_ssl_verify") and args.skip_ssl_verify)

        control_servers: list[ControlServer] = [
            ControlServer(
                url=server_config["url"],
                headers=parse_headers(server_config["headers"]),
                identifier=server_config["identifier"],
            )
            for server_config in args.control_servers
        ]
        analyze_args = AnalyzeArgs(
            analysis_url=args.analysis_url,
            identifier=None,
            additional_headers=parse_headers(args.verification_H),
            max_retries=3,
            skip_ssl_verify=skip_ssl_verify,
        )
        push_args = PushArgs(
            control_servers=control_servers,
            skip_ssl_verify=skip_ssl_verify,
            version=version_info,
        )
        return await inspect_analyze_push_pipeline(inspect_args, analyze_args, push_args, verbose=verbose)
    elif mode == "inspect":
        return await inspect_pipeline(inspect_args)
    else:
        raise ValueError(f"Unknown mode: {mode}, expected 'scan' or 'inspect'")


async def print_scan_inspect(mode="scan", args=None):
    json_output: bool = hasattr(args, "json") and args.json
    print_errors: bool = hasattr(args, "print_errors") and args.print_errors
    full_description: bool = hasattr(args, "print_full_descriptions") and args.print_full_descriptions
    verbose: bool = hasattr(args, "verbose") and args.verbose

    if json_output:
        with suppress_stdout():
            result = await run_scan(args, mode=mode)
            result_dict = {r.path: r.model_dump(mode="json") for r in result}
        print(json.dumps(result_dict, indent=2))
    else:
        result = await run_scan(args, mode=mode)
        print_scan_result(
            result,
            print_errors,
            inspect_mode=mode == "inspect",
            internal_issues=verbose,
            full_description=full_description,
        )


if __name__ == "__main__":
    main()
