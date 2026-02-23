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

from mcp_scan.MCPScanner import MCPScanner
from mcp_scan.models import ControlServer, TokenAndClientInfo, TokenAndClientInfoList
from mcp_scan.pipelines import AnalyzeArgs, InspectArgs, PushArgs, inspect_analyze_push_pipeline, inspect_pipeline
from mcp_scan.printer import print_scan_result
from mcp_scan.Storage import Storage
from mcp_scan.upload import get_hostname, upload
from mcp_scan.utils import ensure_unicode_console, parse_headers, suppress_stdout
from mcp_scan.verify_api import setup_aiohttp_debug_logging, setup_tcp_connector
from mcp_scan.version import version_info
from mcp_scan.well_known_clients import WELL_KNOWN_MCP_PATHS, client_shorthands_to_paths

# Proxy-related imports (require [proxy] extra)
_PROXY_AVAILABLE = None


def check_proxy_dependencies():
    """Check if proxy dependencies are installed and return True if available."""
    global _PROXY_AVAILABLE
    if _PROXY_AVAILABLE is not None:
        return _PROXY_AVAILABLE

    try:
        import invariant  # noqa: F401
        import invariant_sdk  # noqa: F401

        _PROXY_AVAILABLE = True
        return True
    except ImportError:
        _PROXY_AVAILABLE = False
        return False


def require_proxy_dependencies(command_name: str):
    """
    Raise an error if proxy dependencies are not installed.

    Args:
        command_name: Name of the command that requires proxy dependencies
    """
    if not check_proxy_dependencies():
        rich.print(f"[bold red]Error:[/bold red] The '{command_name}' command requires proxy dependencies.")
        rich.print("Please use the optional [bold cyan][proxy][/bold cyan] extra to install the dependencies.")
        sys.exit(1)


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
        cmd = "mcp-scan"
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
    - opt_out: boolean indicating if opt-out is enabled
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
                    "opt_out": False,
                }
                i += 1  # Skip the URL value
            else:
                current_server = None

        elif current_server is not None:
            if arg == "--control-server-H":
                if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                    current_server["headers"].append(argv[i + 1])
                    i += 1

            elif arg == "--control-identifier":
                if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                    current_server["identifier"] = argv[i + 1]
                    i += 1

            elif arg == "--opt-out":
                current_server["opt_out"] = True

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
        help="Path to store scan results and whitelist information",
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
    server_group.add_argument(
        "--pretty",
        type=str,
        default="compact",
        choices=["oneline", "compact", "full", "none"],
        help="Pretty print the output (default: compact)",
    )
    server_group.add_argument(
        "--install-extras",
        nargs="+",
        default=None,
        help="Install extras for the Invariant Gateway - use 'all' or a space-separated list of extras",
        metavar="EXTRA",
    )


def add_install_arguments(parser):
    parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=WELL_KNOWN_MCP_PATHS,
        help=(
            "Different file locations to scan. "
            "This can include custom file locations as long as "
            "they are in an expected format, including Claude, "
            "Cursor or VSCode format."
        ),
    )
    parser.add_argument(
        "--project_name",
        type=str,
        default="mcp-gateway",
        help="Project name for the Invariant Gateway",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        help="API key for the Invariant Gateway",
    )
    parser.add_argument(
        "--local-only",
        default=False,
        action="store_true",
        help="Prevent pushing traces to the explorer.",
    )
    parser.add_argument(
        "--gateway-dir",
        type=str,
        help="Source directory for the Invariant Gateway. Set this, if you want to install a custom gateway implementation. (default: the published package is used).",
        default=None,
    )
    parser.add_argument(
        "--mcp-scan-server-port",
        type=int,
        default=8129,
        help="MCP scan server port (default: 8129).",
        metavar="PORT",
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
        "--full-toxic-flows",
        default=False,
        action="store_true",
        help="Show all tools in the toxic flows, by default only the first 3 are shown.",
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
    scan_parser.add_argument(
        "--opt-out",
        action="append_const",
        const=True,
        help="Opts out of sending a unique user identifier with every scan to the preceding control server.",
    )
    scan_parser.add_argument(
        "--include-built-in",
        default=False,
        action="store_true",
        help="Also include built-in IDE tools.",
    )


def add_uninstall_arguments(parser):
    parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=WELL_KNOWN_MCP_PATHS,
        help=(
            "Different file locations to scan. "
            "This can include custom file locations as long as "
            "they are in an expected format, including Claude, Cursor or VSCode format."
        ),
    )


def check_install_args(args):
    if args.command == "install" and not args.local_only and not args.api_key:
        # prompt for api key
        print(
            "To install mcp-scan with remote logging, you need an Invariant API key (https://explorer.invariantlabs.ai/settings).\n"
        )
        args.api_key = input("API key (or just press enter to install with --local-only): ")
        if not args.api_key:
            args.local_only = True


def install_extras(args):
    if hasattr(args, "install_extras") and args.install_extras:
        require_proxy_dependencies("install_extras")
        from invariant.__main__ import add_extra

        add_extra(*args.install_extras, "-y")


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
        description="MCP-scan: Security scanner for Model Context Protocol servers and tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            f"  {program_name}                     # Scan all known MCP configs\n"
            f"  {program_name} ~/custom/config.json # Scan a specific config file\n"
            f"  {program_name} inspect             # Just inspect tools without verification\n"
            f"  {program_name} whitelist           # View whitelisted tools\n"
            f'  {program_name} whitelist tool "add" "a1b2c3..." # Whitelist the \'add\' tool\n'
            f"  {program_name} --skills            # Scan skills beyond mcp servers.\n"
            f"  {program_name} --verbose           # Enable detailed logging output\n"
            f"  {program_name} --print-errors      # Show error details and tracebacks\n"
            f"  {program_name} --json              # Output results in JSON format\n"
            f"  # Multiple control servers with individual options:\n"
            f'  {program_name} --control-server https://server1.com --control-server-H "Auth: token1" \\\n'
            f"    --control-identifier user@example.com --opt-out \\\n"
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

    # WHITELIST command
    whitelist_parser = subparsers.add_parser(
        "whitelist",
        help="Manage the whitelist of approved entities",
        description=(
            "View, add, or reset whitelisted entities. Whitelisted entities bypass security checks during scans."
        ),
    )
    add_common_arguments(whitelist_parser)

    whitelist_group = whitelist_parser.add_argument_group("Whitelist Options")
    whitelist_group.add_argument(
        "--reset",
        default=False,
        action="store_true",
        help="Reset the entire whitelist",
    )
    whitelist_group.add_argument(
        "--local-only",
        default=False,
        action="store_true",
        help="Only update local whitelist, don't contribute to global whitelist",
    )

    whitelist_parser.add_argument(
        "type",
        type=str,
        choices=["tool", "prompt", "resource"],
        default="tool",
        nargs="?",
        help="Type of entity to whitelist (default: tool)",
        metavar="TYPE",
    )
    whitelist_parser.add_argument(
        "name",
        type=str,
        default=None,
        nargs="?",
        help="Name of the entity to whitelist",
        metavar="NAME",
    )
    whitelist_parser.add_argument(
        "hash",
        type=str,
        default=None,
        nargs="?",
        help="Hash of the entity to whitelist",
        metavar="HASH",
    )
    # install
    install_parser = subparsers.add_parser("install", help="Install Invariant Gateway (deprecated)")
    add_install_arguments(install_parser)
    install_parser = subparsers.add_parser("install-proxy", help="Install Invariant Gateway")
    add_install_arguments(install_parser)

    # uninstall
    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall Invariant Gateway (deprecated)")
    add_uninstall_arguments(uninstall_parser)
    uninstall_parser = subparsers.add_parser("uninstall-proxy", help="Uninstall Invariant Gateway")
    add_uninstall_arguments(uninstall_parser)

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

    # SERVER command
    server_parser = subparsers.add_parser("server", help="Start the MCP scan server")
    server_parser.add_argument(
        "--port",
        type=int,
        default=8129,
        help="Port to run the server on (default: 8129)",
        metavar="PORT",
    )
    add_common_arguments(server_parser)
    add_server_arguments(server_parser)

    # PROXY command
    proxy_parser = subparsers.add_parser("proxy", help="Installs and proxies MCP requests, uninstalls on exit")
    proxy_parser.add_argument(
        "--port",
        type=int,
        default=8129,
        help="Port to run the server on (default: 8129)",
        metavar="PORT",
    )
    add_common_arguments(proxy_parser)
    add_server_arguments(proxy_parser)
    add_install_arguments(proxy_parser)

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

    # postprocess the files argument (if shorthands are used)
    if hasattr(args, "files") and args.files is None:
        args.files = client_shorthands_to_paths(args.files)

    # Attach parsed control servers to args
    args.control_servers = control_servers

    # Display version banner
    if not ((hasattr(args, "json") and args.json) or (args.command == "mcp-server")):
        rich.print(f"[bold blue]Invariant MCP-scan v{version_info}[/bold blue]\n")

    async def install():
        require_proxy_dependencies("install-proxy")
        from mcp_scan.gateway import MCPGatewayConfig, MCPGatewayInstaller

        try:
            check_install_args(args)
        except argparse.ArgumentError as e:
            parser.error(e)

        invariant_api_url = (
            f"http://localhost:{args.mcp_scan_server_port}" if args.local_only else "https://explorer.invariantlabs.ai"
        )
        installer = MCPGatewayInstaller(paths=args.files, invariant_api_url=invariant_api_url)
        await installer.install(
            gateway_config=MCPGatewayConfig(
                project_name=args.project_name,
                push_explorer=True,
                api_key=args.api_key or "",
                source_dir=args.gateway_dir,
            ),
            verbose=True,
        )

    async def uninstall():
        require_proxy_dependencies("uninstall-proxy")
        from mcp_scan.gateway import MCPGatewayInstaller

        installer = MCPGatewayInstaller(paths=args.files)
        await installer.uninstall(verbose=True)

    def server(on_exit=None):
        from mcp_scan_server.server import MCPScanServer  # type: ignore

        sf = Storage(args.storage_file)
        guardrails_config_path = sf.create_guardrails_config()
        mcp_scan_server = MCPScanServer(
            port=args.port, config_file_path=guardrails_config_path, on_exit=on_exit, pretty=args.pretty
        )
        mcp_scan_server.run()

    # Set up logging if verbose flag is enabled
    do_log = hasattr(args, "verbose") and args.verbose
    setup_logging(do_log, log_to_stderr=(args.command != "mcp-server"))

    # Handle commands
    if args.command == "help" or (args.command is None and hasattr(args, "help") and args.help):
        parser.print_help()
        sys.exit(0)
    elif args.command == "whitelist":
        sf = Storage(args.storage_file)
        if args.reset:
            sf.reset_whitelist()
            rich.print("[bold]Whitelist reset[/bold]")
            sys.exit(0)
        elif all(x is None for x in [args.type, args.name, args.hash]):  # no args
            sf.print_whitelist()
            sys.exit(0)
        elif all(x is not None for x in [args.type, args.name, args.hash]):
            sf.add_to_whitelist(args.type, args.name, args.hash)
            sf.print_whitelist()
            sys.exit(0)
        else:
            rich.print("[bold red]Please provide all three parameters: type, name, and hash.[/bold red]")
            whitelist_parser.print_help()
            sys.exit(1)
    elif args.command == "inspect":
        asyncio.run(print_scan_inspect(mode="inspect", args=args))
        sys.exit(0)
    elif args.command == "install-proxy" or args.command == "install":
        asyncio.run(install())
        sys.exit(0)
    elif args.command == "uninstall-proxy" or args.command == "uninstall":
        asyncio.run(uninstall())
        sys.exit(0)
    elif args.command == "scan" or args.command is None:  # default to scan
        asyncio.run(print_scan_inspect(args=args))
        sys.exit(0)
    elif args.command == "server":
        install_extras(args)
        server()
        sys.exit(0)
    elif args.command == "proxy":
        require_proxy_dependencies("proxy")
        args.local_only = True
        install_extras(args)
        asyncio.run(install())
        rich.print("[Proxy installed, you may need to restart/reload your MCP clients to use it]")
        server(on_exit=uninstall)
        sys.exit(0)
    elif args.command == "mcp-server":
        from mcp_scan.mcp_server import mcp_server

        sys.exit(mcp_server(args))
    elif args.command == "install-mcp-server":
        from mcp_scan.mcp_server import install_mcp_server

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
    if not args.files:
        args.files = WELL_KNOWN_MCP_PATHS

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
            async with session.post(push_key_url, data="", headers={"Authorization": f"token {token}"}) as resp:
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
            "opt_out": False,
            "headers": [f"x-client-id:{client_id}"],
        }
    ]
    await run_scan_inspect(mode="scan", args=args)

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


async def scan_with_skills(args, mode: Literal["scan", "inspect"]):
    """
    Scan the machine with skills. Eventually this should replace run_scan_inspect
    """
    # collecting common args
    verbose: bool = hasattr(args, "verbose") and args.verbose
    json_output: bool = hasattr(args, "json") and args.json
    print_errors: bool = hasattr(args, "print_errors") and args.print_errors
    full_toxic_flows: bool = hasattr(args, "full_toxic_flows") and args.full_toxic_flows
    full_description: bool = hasattr(args, "print_full_descriptions") and args.print_full_descriptions

    # collect inspect args
    server_timeout: int = args.server_timeout if hasattr(args, "server_timeout") else 10
    files: list[str] | None = args.files
    tokens: list[TokenAndClientInfo] = []
    if args.mcp_oauth_tokens_path:
        with open(args.mcp_oauth_tokens_path) as f:
            tokens = TokenAndClientInfoList.model_validate_json(f.read()).root

    inspect_args = InspectArgs(
        timeout=server_timeout,
        tokens=tokens,
        paths=files,
    )

    if mode == "scan":
        # collect analyze args
        analysis_url: str = args.analysis_url
        opt_out_of_identity: bool = bool(hasattr(args, "opt_out_of_identity") and args.opt_out_of_identity)
        skip_ssl_verify: bool = bool(hasattr(args, "skip_ssl_verify") and args.skip_ssl_verify)
        additional_headers: dict | None = parse_headers(args.verification_H)
        identifier: None = None

        control_servers: list[ControlServer] = [
            ControlServer(
                url=server_config["url"],
                headers=parse_headers(server_config["headers"]),
                identifier=server_config["identifier"],
                opt_out=server_config["opt_out"],
            )
            for server_config in args.control_servers
        ]
        analyze_args = AnalyzeArgs(
            analysis_url=analysis_url,
            identifier=identifier,
            additional_headers=additional_headers,
            opt_out_of_identity=opt_out_of_identity,
            control_servers=control_servers,
            max_retries=3,
            skip_ssl_verify=skip_ssl_verify,
        )

        # collect push args
        push_args = PushArgs(
            control_servers=control_servers,
            skip_ssl_verify=skip_ssl_verify,
            version=version_info,
        )
        task = inspect_analyze_push_pipeline(inspect_args, analyze_args, push_args, verbose=verbose)
    elif mode == "inspect":
        task = inspect_pipeline(inspect_args)
    else:
        raise ValueError(f"Unknown mode: {mode}, expected 'scan' or 'inspect'")

    if json_output:
        with suppress_stdout():
            result = await task
            result_dict = {r.path: r.model_dump(mode="json") for r in result}
        print(json.dumps(result_dict, indent=2))
    else:
        result = await task
        print_scan_result(
            result,
            print_errors,
            full_toxic_flows,
            inspect_mode=mode == "inspect",
            internal_issues=verbose,
            full_description=full_description,
        )


async def run_scan_inspect(mode="scan", args=None):
    # Initialize scan_context dict that can be populated during scanning
    scan_context = {"cli_version": version_info}

    async with MCPScanner(
        additional_headers=parse_headers(args.verification_H), scan_context=scan_context, **vars(args)
    ) as scanner:
        if mode == "scan":
            result = await scanner.scan()
        elif mode == "inspect":
            result = await scanner.inspect()
        else:
            raise ValueError(f"Unknown mode: {mode}, expected 'scan' or 'inspect'")
    # upload scan result to control servers if specified
    if hasattr(args, "control_servers") and args.control_servers:
        for server_config in args.control_servers:
            await upload(
                result,
                server_config["url"],
                server_config["identifier"],
                server_config["opt_out"],
                verbose=getattr(args, "verbose", False),
                additional_headers=parse_headers(server_config["headers"]),
                skip_ssl_verify=getattr(args, "skip_ssl_verify", False),
                scan_context=scan_context,
            )
    return result


async def print_scan_inspect(mode="scan", args=None):
    # With --json enabled, we suppress all stdout
    # to ensure we produce a valid JSON output.
    if args.skills:
        await scan_with_skills(args, mode=mode)
        return

    if not args.files:
        args.files = WELL_KNOWN_MCP_PATHS

    if args.json:
        with suppress_stdout():
            result = await run_scan_inspect(mode, args)
        result = {r.path: r.model_dump(mode="json") for r in result}
        print(json.dumps(result, indent=2))
    else:
        result = await run_scan_inspect(mode, args)
        print_scan_result(
            result,
            args.print_errors,
            args.full_toxic_flows if hasattr(args, "full_toxic_flows") else False,
            mode == "inspect",
            args.verbose,
        )


if __name__ == "__main__":
    main()
