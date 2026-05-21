"""Regression tests for the ordering of mint_push_key vs bootstrap in `cli.evo`.

Bootstrap correlates startup metadata with the eventual push via the
`x-client-id` header. For `evo`, that header value is minted at runtime by
`mint_push_key` — so bootstrap MUST run AFTER mint, otherwise the bootstrap
request would either ship no `x-client-id` (and the backend would 422 it)
or ship a stale value from a prior run. These tests pin that ordering.
"""

from argparse import Namespace
from unittest.mock import patch

import pytest

from agent_scan import cli


@pytest.mark.asyncio
async def test_evo_bootstrap_runs_after_mint_with_freshly_minted_client_id():
    """Bootstrap receives the control_servers list AFTER mint_push_key populates it.

    The freshly minted client_id must appear in the `x-client-id` header of
    the ControlServer passed to `bootstrap_first_control_server`. If the
    ordering ever flips, this test fails because the control_servers list
    will be empty (or carry whatever was on `args` going in) at bootstrap time.
    """
    call_log: list[str] = []
    minted_client_id = "minted-client-id-abc123"
    captured_control_servers: list = []

    def fake_mint(base_url, tenant_id, token):
        call_log.append("mint")
        return minted_client_id

    def fake_revoke(base_url, tenant_id, token, client_id):
        call_log.append("revoke")

    async def fake_bootstrap(control_servers, command, subcommand, control_identifier, argv, no_bootstrap, **_kw):
        call_log.append("bootstrap")
        captured_control_servers.extend(control_servers)
        # Return a default RuntimeConfig so cli.bootstrap_runtime_config's
        # set_runtime_config call has something valid to store.
        from agent_scan.runtime_config import RuntimeConfig

        return RuntimeConfig()

    async def fake_run_scan(args, mode="scan"):
        call_log.append("run_scan")
        return []

    args = Namespace(
        control_servers=None,
        no_bootstrap=False,
        json=False,
        print_errors=False,
        verbose=False,
    )

    with (
        patch("agent_scan.pushkeys.mint_push_key", side_effect=fake_mint),
        patch("agent_scan.pushkeys.revoke_push_key", side_effect=fake_revoke),
        patch("agent_scan.cli.bootstrap_first_control_server", side_effect=fake_bootstrap),
        patch("agent_scan.cli.run_scan", side_effect=fake_run_scan),
        patch("builtins.input", side_effect=["tenant-id", "auth-token"]),
        patch("agent_scan.cli.rich.print"),
    ):
        await cli.evo(args)

    # Ordering: mint MUST precede bootstrap; run_scan and revoke follow.
    assert call_log == ["mint", "bootstrap", "run_scan", "revoke"], (
        f"Expected mint -> bootstrap -> run_scan -> revoke, got {call_log!r}"
    )

    # The control server reaching bootstrap must carry the freshly minted id.
    assert len(captured_control_servers) == 1, (
        f"Expected exactly one control server at bootstrap time, got {len(captured_control_servers)}"
    )
    headers = captured_control_servers[0].headers
    # Header key casing follows parse_headers; match case-insensitively.
    client_id_values = [v for k, v in headers.items() if k.lower() == "x-client-id"]
    assert client_id_values == [minted_client_id], (
        f"Bootstrap saw x-client-id={client_id_values!r}, expected [{minted_client_id!r}]"
    )


@pytest.mark.asyncio
async def test_evo_skips_bootstrap_and_scan_when_mint_fails():
    """If mint_push_key raises, evo bails out before bootstrap or run_scan.

    Sibling regression: the ordering guarantee only makes sense if mint
    failures short-circuit. Otherwise bootstrap would still fire with stale
    or empty control_servers, defeating the correlation.
    """
    call_log: list[str] = []

    def fake_mint_failing(base_url, tenant_id, token):
        call_log.append("mint")
        raise RuntimeError("mint failed")

    async def fake_bootstrap(*args, **kwargs):
        call_log.append("bootstrap")
        from agent_scan.runtime_config import RuntimeConfig

        return RuntimeConfig()

    async def fake_run_scan(args, mode="scan"):
        call_log.append("run_scan")
        return []

    args = Namespace(control_servers=None, no_bootstrap=False, json=False, print_errors=False, verbose=False)

    with (
        patch("agent_scan.pushkeys.mint_push_key", side_effect=fake_mint_failing),
        patch("agent_scan.pushkeys.revoke_push_key", side_effect=lambda *_: call_log.append("revoke")),
        patch("agent_scan.cli.bootstrap_first_control_server", side_effect=fake_bootstrap),
        patch("agent_scan.cli.run_scan", side_effect=fake_run_scan),
        patch("builtins.input", side_effect=["tenant-id", "auth-token"]),
        patch("agent_scan.cli.rich.print"),
    ):
        await cli.evo(args)

    assert call_log == ["mint"], f"Expected only mint to fire, got {call_log!r}"
