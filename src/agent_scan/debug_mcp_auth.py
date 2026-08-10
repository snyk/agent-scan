from __future__ import annotations

import json
import logging
import sys

import rich

from agent_scan.oauth_flow import AuthResult, authenticate_server
from agent_scan.oauth_store import OAuthTokenStore, normalize_server_url

logger = logging.getLogger(__name__)


async def run_debug_auth(
    *,
    url: str,
    server_name: str,
    store: OAuthTokenStore | None = None,
    timeout: float = 300.0,
    verbose: bool = False,
    print_details: bool = False,
) -> AuthResult:
    """Run a one-off auth attempt and print structured diagnostics.

    This helper is intentionally small and safe to use while debugging the
    interactive OAuth flow. It does not mutate the CLI behavior; it simply
    exercises the same authentication path with extra reporting.
    """
    effective_store = store or OAuthTokenStore()
    normalized_url = normalize_server_url(url)
    entry = effective_store.get(normalized_url)

    if verbose:
        rich.print(f"[bold]Debug auth for[/bold] {server_name} ({normalized_url})")

    if entry is not None:
        if print_details:
            # safe_summary(), never model_dump(): the latter includes the access
            # token, refresh token and client secret, which must not reach stdout.
            rich.print(json.dumps(entry.safe_summary(), indent=2))
        if verbose:
            rich.print("[green]Found existing stored auth entry[/green]")
    else:
        if verbose:
            rich.print("[yellow]No existing auth entry found[/yellow]")

    result = await authenticate_server(
        url,
        server_name,
        effective_store,
        timeout=timeout,
    )

    if print_details:
        rich.print(json.dumps({"ok": result.ok, "server_url": result.server_url, "message": result.message}, indent=2))

    if not result.ok and verbose:
        rich.print(f"[red]{result.message}[/red]")

    return result


async def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        rich.print("Usage: debug_mcp_auth.py <server-url> [server-name]")
        return 2

    url = argv[0]
    server_name = argv[1] if len(argv) > 1 else url
    store = OAuthTokenStore()
    result = await run_debug_auth(url=url, server_name=server_name, store=store, print_details=True, verbose=True)
    return 0 if result.ok else 1


if __name__ == "__main__":
    import asyncio

    raise SystemExit(asyncio.run(main()))
