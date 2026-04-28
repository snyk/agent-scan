"""
When --control-server carries a push key (x-client-id), the run is non-interactive
and the per-stdio consent flow must not run — even if the config lists stdio servers.
"""

from __future__ import annotations

from argparse import Namespace
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import run_scan
from agent_scan.models import ClientToInspect, ControlServer, ScanPathResult, StdioServer


def _push_key_scan_args(**overrides) -> Namespace:
    """Namespace mirroring: scan with push-key control server + custom analysis URL."""
    base = {
        "command": "scan",
        "control_servers": [
            ControlServer(
                url="https://some.control.server.com",
                headers={"x-client-id": "some-user-push-key"},
                identifier="some-machine-id-dh7g62dyug7d",
            )
        ],
        "analysis_url": "https://some.analysis.endpoint.com/hidden/mcp-scan/analysis-machine?version=2025-09-02",
        "verification_H": None,
        "skip_ssl_verify": True,
        "verbose": False,
        "scan_all_users": False,
        "server_timeout": 10,
        "files": [],
        "mcp_oauth_tokens_path": None,
        "skills": False,
        "dangerously_run_mcp_servers": False,
        "suppress_mcpserver_io": None,
    }
    base.update(overrides)
    return Namespace(**base)


def _fake_client_with_stdio() -> list[ClientToInspect]:
    """A client that would normally trigger the consent UI if the run were interactive."""
    return [
        ClientToInspect(
            name="e2e-test",
            client_path="/fake/client",
            mcp_configs={
                "/fake/mcp.json": [
                    (
                        "Math",
                        StdioServer(command="python", args=["-c", "print(1)"]),
                    ),
                ],
            },
            skills_dirs={},
        ),
    ]


@pytest.mark.asyncio
class TestControlServerPushKeySkipsConsent:
    async def test_collect_consent_not_called_and_http_layer_mocked(
        self,
    ):
        """
        push-key scan: ``collect_consent`` is never invoked; ``analyze_machine`` and
        ``upload`` are the only code paths that would perform outbound HTTP — they are
        mocked so ``aiohttp.ClientSession`` is never used in those modules.
        """
        args = _push_key_scan_args()
        path_result = ScanPathResult(path="/fake/mcp.json", servers=[])

        mock_analyze = AsyncMock(side_effect=lambda paths, **kw: paths)
        mock_upload = AsyncMock()
        mock_inspect = AsyncMock(return_value=([path_result], ["testuser"]))

        with (
            patch("agent_scan.cli.collect_consent") as mock_consent,
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new=AsyncMock(return_value=(_fake_client_with_stdio(), [], [])),
            ),
            patch("agent_scan.pipelines.inspect_pipeline", new=mock_inspect),
            patch("agent_scan.pipelines.analyze_machine", new=mock_analyze),
            patch("agent_scan.pipelines.upload", new=mock_upload),
        ):
            await run_scan(args, mode="scan")

        mock_consent.assert_not_called()
        mock_analyze.assert_awaited()
        mock_upload.assert_awaited()
        # Inspect ran with empty declined set (consent not collected)
        call_kw = mock_inspect.call_args.kwargs
        assert call_kw.get("declined_servers") == set()

    async def test_collect_consent_not_called_when_explicit_suppress_and_dangerous_off(
        self,
    ):
        """
        Ensure push-key still skips consent with explicit I/O and dangerous flags; consent
        must not depend on those flags for MDM mode.
        """
        args = _push_key_scan_args(
            suppress_mcpserver_io=True,
            dangerously_run_mcp_servers=False,
        )
        path_result = ScanPathResult(path="/fake/mcp.json", servers=[])

        with (
            patch("agent_scan.cli.collect_consent") as mock_consent,
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new=AsyncMock(return_value=(_fake_client_with_stdio(), [], [])),
            ),
            patch(
                "agent_scan.pipelines.inspect_pipeline",
                new=AsyncMock(return_value=([path_result], [])),
            ),
            patch("agent_scan.pipelines.analyze_machine", new=AsyncMock(side_effect=lambda p, **kw: p)),
            patch("agent_scan.pipelines.upload", new=AsyncMock()),
        ):
            await run_scan(args, mode="scan")

        mock_consent.assert_not_called()
