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

import psutil
import rich
from rich.logging import RichHandler

from agent_scan.consent import collect_consent
from agent_scan.models import (
    FAILURE_CATEGORY_TO_CODE,
    ControlServer,
    ScanPathResult,
    TokenAndClientInfo,
    TokenAndClientInfoList,
)
from agent_scan.pipelines import (
    AnalyzeArgs,
    InspectArgs,
    PushArgs,
    discover_clients_to_inspect,
    inspect_analyze_push_pipeline,
    inspect_pipeline,
)
from agent_scan.printer import print_scan_result
from agent_scan.upload import get_hostname
from agent_scan.utils import ensure_unicode_console, get_push_key, parse_headers, suppress_stdout
from agent_scan.version import version_info

# Configure logging to suppress all output by default
logging.getLogger().setLevel(logging.CRITICAL + 1)  # Higher than any standard level
# Add null handler to prevent "No handler found" warnings
logging.getLogger().addHandler(logging.NullHandler())


class MissingIdentifierError(Exception):
    """Raised when a control server is missing an identifier."""

    pass


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


def parse_control_servers(argv) -> list[ControlServer]:
    """
    Parse control server arguments from sys.argv.
    Returns a list of ControlServer instances.
    Raises ValueError if any control server is missing an identifier.
    """
    server_starts = [i for i, arg in enumerate(argv) if arg == "--control-server"]

    control_servers: list[ControlServer] = []
    for idx, start in enumerate(server_starts):
        end = server_starts[idx + 1] if idx + 1 < len(server_starts) else len(argv)
        block = argv[start:end]

        if len(block) < 2 or block[1].startswith("--"):
            continue

        url = block[1]
        headers: list[str] = []
        identifier: str | None = None

        i = 2
        while i < len(block):
            if block[i] == "--control-server-H" and i + 1 < len(block) and not block[i + 1].startswith("--"):
                headers.append(block[i + 1])
                i += 2
            elif block[i] == "--control-identifier" and i + 1 < len(block) and not block[i + 1].startswith("--"):
                identifier = block[i + 1]
                i += 2
            else:
                i += 1

        if identifier is None:
            rich.print(f"[bold red]Control server {url} is missing a --control-identifier[/bold red]")
            raise MissingIdentifierError(f"Control server {url} is missing a --control-identifier")

        control_servers.append(
            ControlServer(
                url=url,
                headers=parse_headers(headers),
                identifier=identifier,
            )
        )

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
    parser.add_argument(
        "--ci",
        action="store_true",
        default=False,
        help="Exit with a non-zero code when there are analysis findings or runtime failures. Requires --dangerously-run-mcp-servers.",
    )
    parser.add_argument(
        "--ignore-issues-codes",
        type=str,
        default=None,
        help="Comma-separated list of issue codes to ignore (e.g. W001,W015)",
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
    # Only stdio MCP server stderr is relayed; stdout is reserved for the
    # JSON-RPC protocol and is always consumed by the MCP client, never shown.
    # Default is None so we can distinguish three cases:
    #   1. None  -> unset. resolve_server_io_default() picks based on
    #               interactivity of the command.
    #   2. True  -> explicit override to silence MCP server stderr.
    #   3. False -> explicit override to stream MCP server stderr.
    server_group.add_argument(
        "--suppress-mcpserver-io",
        default=None,
        type=str2bool,
        help=(
            "Suppress stderr from stdio MCP servers (stdout carries the "
            "JSON-RPC protocol and is never shown). "
            "Default: False for interactive runs (stderr is streamed with a "
            "[server-name] prefix), True otherwise."
        ),
        metavar="BOOL",
    )
    server_group.add_argument(
        "--dangerously-run-mcp-servers",
        default=False,
        action="store_true",
        help=("Skip the interactive consent prompt and start every stdio MCP server listed in the scanned configs."),
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
        help=(
            "Upload scan results to this control server URL. "
            "Must be paired with a --control-identifier for that same server block. "
            "Can be specified multiple times."
        ),
    )
    scan_parser.add_argument(
        "--control-server-H",
        action="append",
        help="Additional header for the current --control-server block (repeatable)",
    )
    scan_parser.add_argument(
        "--control-identifier",
        action="append",
        help=(
            "Required per --control-server block. "
            "Non-anonymous identifier for that control server (for example: email, hostname, serial number)."
        ),
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


def is_interactive_run(args) -> bool:
    """
    True when the run is a manual, interactive invocation by a human who can
    answer yes or no consent prompts.
    """
    command = getattr(args, "command", None)
    if command in ("evo", "inspect"):
        return True
    # If the scan is run with a push key, skip consent prompts.
    has_push_key = bool(get_push_key(getattr(args, "control_servers", []) or []))
    return not has_push_key


def resolve_server_io_default(args) -> None:
    """
    Fill in a value for --suppress-mcpserver-io when the user didn't pass
    it explicitly: False for interactive runs, else True.
    """
    if getattr(args, "suppress_mcpserver_io", None) is None:
        args.suppress_mcpserver_io = not is_interactive_run(args)


def enforce_consent_requirements(args) -> None:
    """
    --ci must opt into starting subprocesses explicitly, because CI runs
    cannot answer the interactive per-server consent prompt.
    """
    dangerous = getattr(args, "dangerously_run_mcp_servers", False)
    ci_mode = getattr(args, "ci", False)

    if ci_mode and not dangerous:
        rich.print(
            "[bold red]Running with --ci requires --dangerously-run-mcp-servers.[/bold red]\n"
            "Agent Scan starts subprocesses for every stdio MCP server it "
            "scans, so CI runs must confirm trust explicitly.",
            file=sys.stderr,
        )
        sys.exit(2)


def main():
    ensure_unicode_console()
    # Create main parser with description
    program_name = get_invoking_name()
    parser = argparse.ArgumentParser(
        prog=program_name,
        description="Snyk Agent Scan: Security scanner for Model Context Protocol servers, agents, skills and tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            f"  {program_name}                     # Scan all known MCP configs\n"
            f"  {program_name} ~/custom/config.json # Scan a specific config file\n"
            f"  {program_name} inspect             # Just inspect tools without verification\n"
            f"  {program_name} --skills            # Scan skills beyond mcp servers.\n"
            f"  {program_name} --verbose           # Enable detailed logging output\n"
            f"  {program_name} --print-errors      # Show error details and tracebacks\n"
            f"  {program_name} --json              # Output results in JSON format\n"
            f"  {program_name} --ci                # With --ci, exit with a non-zero code when there are analysis findings or runtime failures\n\n"
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

    # GUARD command
    guard_parser = subparsers.add_parser(
        "guard",
        help="Install, uninstall, or check status of Agent Guard hooks",
        description="Manage Agent Guard hooks for Claude Code and Cursor.",
    )
    guard_subparsers = guard_parser.add_subparsers(
        dest="guard_command",
        title="Guard commands",
        description="Available guard commands (default: show status)",
        metavar="GUARD_COMMAND",
    )

    guard_install_parser = guard_subparsers.add_parser(
        "install",
        help="Install Agent Guard hooks for a client",
    )
    guard_install_parser.add_argument(
        "client",
        choices=["claude", "cursor"],
        help="Client to install hooks for",
    )
    guard_install_parser.add_argument(
        "--url",
        type=str,
        default="https://api.snyk.io",
        help="Remote hooks base URL (default: https://api.snyk.io)",
    )
    guard_install_parser.add_argument(
        "--tenant-id",
        type=str,
        default=None,
        dest="tenant_id",
        help="Snyk tenant ID (required when minting a push key; not needed if PUSH_KEY is set)",
    )
    guard_install_parser.add_argument(
        "--test",
        action="store_true",
        default=False,
        help="Send a test event to verify connectivity before installing hooks",
    )
    guard_install_parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Override the config file path (default: client-specific well-known path)",
    )
    guard_install_parser.add_argument(
        "--managed",
        action="store_true",
        default=False,
        help="Install hooks to the managed (admin/MDM) config path instead of the user-level path",
    )

    guard_uninstall_parser = guard_subparsers.add_parser(
        "uninstall",
        help="Remove Agent Guard hooks for a client",
    )
    guard_uninstall_parser.add_argument(
        "client",
        choices=["claude", "cursor"],
        help="Client to uninstall hooks from",
    )
    guard_uninstall_parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Override the config file path (default: client-specific well-known path)",
    )
    guard_uninstall_parser.add_argument(
        "--managed",
        action="store_true",
        default=False,
        help="Uninstall hooks from the managed (admin/MDM) config path instead of the user-level path",
    )

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

    # Resolve deferred defaults and enforce safety rules before dispatching.
    resolve_server_io_default(args)
    enforce_consent_requirements(args)

    # Display version banner
    if not (hasattr(args, "json") and args.json):
        rich.print(f"[bold blue]Snyk Agent Scan v{version_info}[/bold blue]\n")

    # Set up logging if verbose flag is enabled
    do_log = hasattr(args, "verbose") and args.verbose
    setup_logging(do_log, log_to_stderr=True)

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
    elif args.command == "evo":
        asyncio.run(evo(args))
        sys.exit(0)
    elif args.command == "guard":
        from agent_scan.guard import run_guard

        sys.exit(run_guard(args))

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
    from agent_scan.pushkeys import mint_push_key, revoke_push_key

    rich.print(
        "Go to https://app.snyk.io and select the tenant on the left nav bar. "
        "Copy the Tenant ID from the URL and paste it here: "
    )
    tenant_id = input().strip()
    rich.print("Paste the Authorization token from https://app.snyk.io/account (API Token -> KEY -> click to show): ")
    token = input().strip()

    base_url = "https://api.snyk.io"
    push_scan_url = f"{base_url}/hidden/mcp-scan/push?version=2025-08-28"

    # Mint a push key
    try:
        client_id = mint_push_key(base_url, tenant_id, token)
        rich.print("Client ID created")
    except RuntimeError as e:
        rich.print(f"[bold red]Error calling Snyk API[/bold red]: {e}")
        return

    # Run scan with the push key
    args.control_servers = [
        ControlServer(
            url=push_scan_url,
            identifier=get_hostname() or None,
            headers=parse_headers([f"x-client-id:{client_id}"]),
        )
    ]
    await run_scan(args, mode="scan")

    # Revoke the push key
    try:
        revoke_push_key(base_url, tenant_id, token, client_id)
        rich.print("Client ID revoked")
    except RuntimeError as e:
        rich.print(f"[bold red]Error revoking client_id[/bold red]: {e}")


async def run_scan(args, mode: Literal["scan", "inspect"] = "scan") -> list[ScanPathResult]:
    """
    Run the scan/inspect pipeline and return results.

    Flow:
    1. Build InspectArgs from CLI args.
    2. Discover the clients/configs that would be inspected.
    3. If interactive and --dangerously-run-mcp-servers is not set, prompt
       the user per stdio server for consent. Declined servers are recorded as
       user_declined errors and never started.
    4. Run the existing inspect / analyze / push pipeline with the filtered
       plan and optional live stderr streaming.
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

    # Resolve the MCP server IO flag and the consent flag.
    if getattr(args, "suppress_mcpserver_io", None) is None:
        args.suppress_mcpserver_io = not is_interactive_run(args)
    suppress_io: bool = bool(args.suppress_mcpserver_io)
    stream_stderr: bool = not suppress_io
    dangerous: bool = bool(getattr(args, "dangerously_run_mcp_servers", False))

    # Step 1: Discover everything we would inspect without starting any server.
    clients_to_inspect, precomputed_scan_path_results, scanned_usernames = await discover_clients_to_inspect(
        inspect_args
    )

    # Step 2: Collect consent per stdio server when running interactively.
    declined_servers: set[tuple[str, str]] = set()
    if is_interactive_run(args) and not dangerous:
        declined_servers = collect_consent(clients_to_inspect)
    elif dangerous and is_interactive_run(args):
        message = (
            "[bold red]--dangerously-run-mcp-servers is set: starting every "
            "stdio MCP server listed in the scanned configs without "
            "prompting.[/bold red]\n"
        )
        if not suppress_io:
            message += "Tip: set --suppress-mcpserver-io=true to hide server stderr output.\n"
        rich.print(message)

    if mode == "scan":
        skip_ssl_verify: bool = bool(hasattr(args, "skip_ssl_verify") and args.skip_ssl_verify)

        control_servers: list[ControlServer] = args.control_servers if hasattr(args, "control_servers") else []
        # For the analysis backend, pick the first identifier from control_servers
        identifier: str | None = next((s.identifier for s in control_servers), None)
        analyze_args = AnalyzeArgs(
            analysis_url=args.analysis_url,
            identifier=identifier,
            additional_headers=parse_headers(args.verification_H),
            max_retries=3,
            skip_ssl_verify=skip_ssl_verify,
        )
        push_args = PushArgs(
            control_servers=control_servers,
            skip_ssl_verify=skip_ssl_verify,
            version=version_info,
        )
        return await inspect_analyze_push_pipeline(
            inspect_args,
            analyze_args,
            push_args,
            verbose=verbose,
            clients_to_inspect=clients_to_inspect,
            precomputed_scan_path_results=precomputed_scan_path_results,
            scanned_usernames=scanned_usernames,
            stream_stderr=stream_stderr,
            declined_servers=declined_servers,
        )
    elif mode == "inspect":
        scan_path_results, _scanned_usernames = await inspect_pipeline(
            inspect_args,
            clients_to_inspect=clients_to_inspect,
            precomputed_scan_path_results=precomputed_scan_path_results,
            scanned_usernames=scanned_usernames,
            stream_stderr=stream_stderr,
            declined_servers=declined_servers,
        )
        return scan_path_results
    else:
        raise ValueError(f"Unknown mode: {mode}, expected 'scan' or 'inspect'")


def _parse_ignore_codes(args, ci_mode: bool) -> set[str]:
    """Parse --ignore-issues-codes and validate it is only used with --ci."""
    ignore_codes_raw = getattr(args, "ignore_issues_codes", None)
    ignore_codes: set[str] = (
        {c.strip() for c in ignore_codes_raw.split(",") if c.strip()} if ignore_codes_raw else set()
    )
    if ignore_codes and not ci_mode:
        rich.print(
            "[bold red]Error: --ignore-issues-codes can only be used with --ci.[/bold red]",
            file=sys.stderr,
        )
        sys.exit(2)
    return ignore_codes


def _collect_failure_codes(result: list[ScanPathResult]) -> set[str]:
    """Collect X00x codes from ScanError failures on paths and servers."""
    codes: set[str] = set()
    for r in result:
        if r.error and r.error.is_failure:
            codes.add(FAILURE_CATEGORY_TO_CODE.get(r.error.category, FAILURE_CATEGORY_TO_CODE[None]))
        for s in r.servers or []:
            if s.error and s.error.is_failure:
                codes.add(FAILURE_CATEGORY_TO_CODE.get(s.error.category, FAILURE_CATEGORY_TO_CODE[None]))
    return codes


def _apply_ignore_codes(result: list[ScanPathResult], ignore_codes: set[str]) -> None:
    """Remove issues whose code is in the ignore set from each scan result."""
    for scan_result in result:
        scan_result.issues = [i for i in scan_result.issues if i.code not in ignore_codes]


def _handle_ci_exit(result: list[ScanPathResult], json_output: bool, ignore_codes: set[str]) -> None:
    """In CI mode, exit with code 1 if any issues or unignored failures remain."""
    has_issues = any(scan_result.issues for scan_result in result)
    failure_codes = _collect_failure_codes(result) - ignore_codes
    if not has_issues and not failure_codes:
        return

    if not json_output:
        issue_codes = {issue.code for scan_result in result for issue in scan_result.issues if issue.code}
        all_codes = sorted(issue_codes | failure_codes)
        codes_part = ", ".join(all_codes) if all_codes else "none"
        rich.print(
            f"[bold red]CI (--ci): exiting with code 1 (issue codes: {codes_part}).[/bold red]",
            file=sys.stderr,
        )
    sys.exit(1)


async def print_scan_inspect(mode="scan", args=None):
    json_output: bool = hasattr(args, "json") and args.json
    print_errors: bool = hasattr(args, "print_errors") and args.print_errors
    full_description: bool = hasattr(args, "print_full_descriptions") and args.print_full_descriptions
    verbose: bool = hasattr(args, "verbose") and args.verbose
    ci_mode: bool = hasattr(args, "ci") and args.ci
    ignore_codes = _parse_ignore_codes(args, ci_mode)

    if json_output:
        with suppress_stdout():
            result = await run_scan(args, mode=mode)
    else:
        result = await run_scan(args, mode=mode)

    if ci_mode and ignore_codes:
        _apply_ignore_codes(result, ignore_codes)

    if json_output:
        result_dict = {r.path: r.model_dump(mode="json") for r in result}
        print(json.dumps(result_dict, indent=2))
    else:
        print_scan_result(
            result,
            print_errors,
            inspect_mode=mode == "inspect",
            internal_issues=verbose,
            full_description=full_description,
            args=args,
        )

    if ci_mode:
        _handle_ci_exit(result, json_output, ignore_codes)


if __name__ == "__main__":
    main()
