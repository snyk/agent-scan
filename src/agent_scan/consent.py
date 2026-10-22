"""Interactive consent for contacting MCP servers."""

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
from agent_scan.utils import _ENV_VAR_PATTERN

# The consent UI is diagnostic chrome, not scan output, so it is rendered on stderr.
_stderr_console = Console(stderr=True)


def _render_command(server: StdioServer) -> str:
    parts = [server.command, *(server.args or [])]
    return " ".join(shlex.quote(p) for p in parts)


def _render_value_redacted(value: str) -> str:
    """Mask a config value, but keep its ``${NAME}`` references visible.

    The scan substitutes each ``${NAME}`` with the scanner's own environment
    variable before connecting, so the reference is what the user needs to see
    to know which of their variables a server is about to read. The reference
    itself is a variable name, not a secret. Literal text around it may be a
    real secret, so every run of it is replaced by ``***``:
    ``Bearer ${TOKEN}`` -> ``***${TOKEN}``, ``${A}${B}`` -> ``${A}${B}``,
    ``sk-literal`` -> ``***``.
    """
    parts: list[str] = []
    position = 0
    for match in _ENV_VAR_PATTERN.finditer(value):
        if match.start() > position:
            parts.append("***")
        parts.append(match.group(0))
        position = match.end()
    if position < len(value) or not parts:
        parts.append("***")
    return "".join(parts)


def _render_env_redacted(server: StdioServer) -> str | None:
    """Render env as ``KEY=<value>`` with literal text masked and ``${NAME}`` references shown."""
    if not server.env:
        return None
    return ", ".join(f"{k}={_render_value_redacted(v)}" for k, v in sorted(server.env.items()))


def _render_headers_redacted(server: RemoteServer) -> str | None:
    """Render headers as ``Name=<value>`` with literal text masked and ``${NAME}`` references shown.

    The scan expands those references from the scanner's environment and sends the result to the
    server, so they must be visible here for the consent decision to be an informed one.
    """
    if not server.headers:
        return None
    return ", ".join(f"{key}={_render_value_redacted(value)}" for key, value in sorted(server.headers.items()))


def _render_url_redacted(url: str) -> str:
    destination, fragment_separator, fragment = url.partition("#")
    base, query_separator, query = destination.partition("?")
    if not query_separator:
        return url
    redacted_query = "&".join(f"{part.partition('=')[0]}=***" if part else "" for part in query.split("&"))
    return f"{base}{query_separator}{redacted_query}{fragment_separator}{fragment}"


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
    Prompt before starting or connecting to each MCP server and return the
    set of (mcp_config_path, server_name) pairs the user declined.
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
        "[bold]Agent Scan must contact MCP servers to inspect their tools.[/bold]\n"
        "Stdio servers launch local subprocesses; remote servers make outbound network requests.\n"
        "Review each server below and confirm whether Agent Scan may contact it.\n"
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
        _stderr_console.print("\n[bold]Remote MCP servers (require consent):[/bold]")
        for idx, (config_path, server_name, server) in enumerate(remote_items, start=1):
            type_str = server.type or "http"
            _stderr_console.print(f"\n  [{idx}] [cyan]{escape(server_name)}[/cyan]")
            _stderr_console.print(f"      config : {escape(config_path)}")
            _stderr_console.print(f"      URL    : [yellow]{escape(_render_url_redacted(server.url))}[/yellow]")
            _stderr_console.print(f"      type   : {escape(type_str)}")
            headers_str = _render_headers_redacted(server)
            if headers_str:
                _stderr_console.print(f"      headers: {escape(headers_str)}")
            prompt = f"      Allow Agent Scan to connect to '{server_name}'? [y/N]: "
            allowed = _read_yes_no(prompt)
            if not allowed:
                declined.add((config_path, server_name))
                _stderr_console.print(
                    f"      [yellow]Declined: '{escape(server_name)}' will not be contacted.[/yellow]"
                )
            else:
                _stderr_console.print(f"      [green]Allowed: '{escape(server_name)}' will be contacted.[/green]")

    allowed_count = len(stdio_items) + len(remote_items) - len(declined)
    total_count = len(stdio_items) + len(remote_items)
    _stderr_console.print(
        f"\n[bold]Proceeding with {allowed_count} of {total_count} MCP servers.[/bold]"
        + (f" Skipped: {len(declined)}." if declined else "")
        + "\n"
    )
    if declined:
        _stderr_console.print(
            "Note: declined servers will not be contacted by Agent Scan. "
            "Agent Scan may still show analysis results for them if Snyk recognizes the "
            "server from prior scans — these results are not based on your "
            "own machine's behavior.\n"
        )
    return declined
