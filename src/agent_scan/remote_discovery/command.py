"""``inspect-remote``: run backend discovery, optionally diff it against legacy."""

import argparse
import json
import os
import sys

import rich

from agent_scan.remote_discovery.builder import build_clients
from agent_scan.remote_discovery.client import RemoteDiscoveryError, run_remote_discovery
from agent_scan.remote_discovery.compare import comparable, diff, legacy_clients


def add_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "inspect-remote",
        allow_abbrev=False,
        help=argparse.SUPPRESS,
        description="Discover agents through the discovery backend (experimental).",
    )
    parser.add_argument("--backend-url", default=os.environ.get("AGENT_DISCOVERY_URL", "http://localhost:8887"))
    parser.add_argument("--push-key", default=os.environ.get("PUSH_KEY"))
    parser.add_argument("--agent", action="append", default=[], help="Limit to this agent (repeatable)")
    parser.add_argument("--scope", choices=["servers", "skills", "all"], default="all")
    parser.add_argument("--compare", action="store_true", help="Diff against legacy discovery")
    parser.add_argument(
        "--scan-all-users",
        action="store_true",
        help="Scan every readable home, like inspect --scan-all-users (WSL homes on Windows)",
    )
    parser.add_argument("--json", action="store_true", help="Print discovered clients as JSON")
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Print each backend request and response to stderr (file contents and server configs redacted)",
    )


async def run(args: argparse.Namespace, cli_version: str | None) -> int:
    try:
        remote = await run_remote_discovery(
            args.backend_url,
            scope=args.scope,
            agents=args.agent,
            push_key=args.push_key,
            cli_version=cli_version,
            all_users=args.scan_all_users,
            trace=args.trace,
        )
    except (RemoteDiscoveryError, OSError) as exc:
        rich.print(f"[bold red]Remote discovery failed:[/bold red] {exc}", file=sys.stderr)
        return 2

    clients = build_clients(remote.found)
    print(
        f"remote: {remote.rounds} rounds, {remote.ops} ops, {remote.bytes_sent} bytes sent, "
        f"{remote.duration_s:.2f}s, partial={remote.partial}, agents={remote.supported_agents}",
        file=sys.stderr,
    )
    if args.json:
        print(json.dumps(comparable(clients), indent=2))

    if not args.compare:
        return 0
    legacy, legacy_s = await legacy_clients(args.scope, remote.supported_agents, args.scan_all_users)
    print(f"legacy: {legacy_s:.2f}s", file=sys.stderr)
    differences = diff(comparable(legacy), comparable(clients))
    if differences.expected:
        rich.print(
            f"[bold yellow]EXPECTED[/bold yellow] {len(differences.expected)} backend-only (legacy misses these)"
        )
        for line in differences.expected:
            print(line)
    if not differences.unexpected:
        n_mcp = sum(len(c.mcp_configs) for c in clients)
        n_skills = sum(len(c.skills_dirs) for c in clients)
        rich.print(
            f"[bold green]IDENTICAL[/bold green] {len(clients)} clients, {n_mcp} mcp configs, {n_skills} skills dirs"
            + (" (apart from the expected extras above)" if differences.expected else "")
        )
        return 0
    rich.print("[bold red]DIFFERENT[/bold red]")
    for line in differences.unexpected:
        print(line)
    return 1
