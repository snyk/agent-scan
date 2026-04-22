"""
Interactive consent for starting stdio MCP servers.
"""

from __future__ import annotations

import shlex
import sys

from rich.console import Console
from rich.markup import escape

from agent_scan.models import (
    ClientToInspect,
    CouldNotParseMCPConfig,
    FileNotFoundConfig,
    RemoteServer,
    StdioServer,
    UnknownConfigFormat,
)

# The consent UI is diagnostic chrome, not scan output, so it is rendered on stderr.
_stderr_console = Console(stderr=True)


def _render_command(server: StdioServer) -> str:
    parts = [server.command, *(server.args or [])]
    return " ".join(shlex.quote(p) for p in parts)


def _render_env_redacted(server: StdioServer) -> str | None:
    """Render env as ``KEY=***``. Values are never echoed back to the terminal."""
    if not server.env:
        return None
    return ", ".join(f"{k}=***" for k in sorted(server.env.keys()))


def _read_yes_no(prompt: str) -> bool:
    """
    Prompt on stderr and read a line from stdin. Accepts ``Y``, ``y``, ``yes``
    (case insensitive) as allow; everything else (including empty / EOF) is
    deny.

    The prompt is written to stderr (not stdout).
    """
    sys.stderr.write(prompt)
    sys.stderr.flush()
    try:
        answer = sys.stdin.readline()
    except KeyboardInterrupt:
        # Treat Ctrl-C during a consent prompt as an unambiguous abort.
        _stderr_console.print("\n[bold red]Aborted by user.[/bold red]")
        raise
    if not answer:  # EOF
        return False
    return answer.strip().lower() in ("y", "yes")


def collect_consent(
    clients_to_inspect: list[ClientToInspect],
) -> set[tuple[str, str]]:
    """
    Prompt the user per stdio MCP server before any subprocess is started and
    return the set of (mcp_config_path, server_name) pairs the user
    declined.
    """
    # First, enumerate everything we'd run, so the user sees the full plan.
    stdio_items: list[tuple[str, str, StdioServer]] = []  # (config_path, name, server)
    remote_items: list[tuple[str, str, RemoteServer]] = []

    for client in clients_to_inspect:
        for config_path, mcp_configs in client.mcp_configs.items():
            if isinstance(mcp_configs, FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig):
                continue
            for server_name, server in mcp_configs:
                if isinstance(server, StdioServer):
                    stdio_items.append((config_path, server_name, server))
                elif isinstance(server, RemoteServer):
                    remote_items.append((config_path, server_name, server))

    if not stdio_items and not remote_items:
        return set()

    _stderr_console.print(
        "[bold]Agent Scan will launch stdio MCP servers as subprocesses to "
        "inspect their tools.[/bold]\n"
        "Review each command below and confirm whether Agent Scan may start it.\n"
        "Tip: pass --dangerously-run-mcp-servers to skip these prompts, or "
        "set --suppress-mcpserver-io=true to hide server stderr output.\n"
    )

    declined: set[tuple[str, str]] = set()

    if stdio_items:
        _stderr_console.print("[bold]Stdio MCP servers (require consent):[/bold]")
        for idx, (config_path, server_name, server) in enumerate(stdio_items, start=1):
            _stderr_console.print(f"\n  [{idx}] [cyan]{escape(server_name)}[/cyan]")
            _stderr_console.print(f"      config : {escape(config_path)}")
            _stderr_console.print(f"      command: [yellow]{escape(_render_command(server))}[/yellow]")
            env_str = _render_env_redacted(server)
            if env_str:
                _stderr_console.print(f"      env    : {escape(env_str)}")
            # [Y/N] — explicit case + default is deny on empty Enter.
            prompt = f"      Allow Agent Scan to start '{server_name}'? [y/N]: "
            allowed = _read_yes_no(prompt)
            if not allowed:
                declined.add((config_path, server_name))
                _stderr_console.print(f"      [yellow]Declined: '{escape(server_name)}' will not be started.[/yellow]")
            else:
                _stderr_console.print(f"      [green]Allowed: '{escape(server_name)}' will be started.[/green]")

    if remote_items:
        _stderr_console.print("\n[bold]Remote MCP servers (no subprocess — auto-allowed):[/bold]")
        for config_path, server_name, server in remote_items:
            type_str = server.type or "http"
            _stderr_console.print(
                f"  - [cyan]{escape(server_name)}[/cyan] ({type_str}, {escape(server.url)}) {escape(config_path)}"
            )

    allowed_count = len(stdio_items) - len(declined)
    _stderr_console.print(
        f"\n[bold]Proceeding with {allowed_count} of {len(stdio_items)} stdio servers.[/bold]"
        + (f" Skipped: {len(declined)}." if declined else "")
        + "\n"
    )
    if declined:
        _stderr_console.print(
            "Note: declined servers will not be started on this machine. "
            "Agent Scan may still show analysis results for them if Snyk recognizes the "
            "server from prior scans — these results are not based on your "
            "own machine's behavior.\n"
        )
    return declined
