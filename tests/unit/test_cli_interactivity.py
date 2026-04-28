"""Tests for is_interactive_run, enforce_consent_requirements, resolve_server_io_default,
str2bool, and the consent / stream_stderr wiring in run_scan."""

from argparse import Namespace
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import (
    enforce_consent_requirements,
    is_interactive_run,
    resolve_server_io_default,
    run_scan,
    str2bool,
)
from agent_scan.models import ControlServer, ScanPathResult


def _ns(**kwargs) -> Namespace:
    """Build an argparse-like Namespace with sensible defaults for CLI attrs."""
    defaults: dict = {
        "command": "scan",
        "control_servers": [],
        "ci": False,
        "json": False,
        "dangerously_run_mcp_servers": False,
        "suppress_mcpserver_io": None,
    }
    defaults.update(kwargs)
    return Namespace(**defaults)


def _control_server_with_push_key() -> ControlServer:
    return ControlServer(
        url="https://mdm.example.com",
        headers={"x-client-id": "push-key-abc123"},
        identifier="mdm-device-01",
    )


def _control_server_without_push_key() -> ControlServer:
    return ControlServer(
        url="https://example.com",
        headers={"Authorization": "Bearer t"},
        identifier="user@example.com",
    )


class TestIsInteractiveRun:
    @pytest.mark.parametrize("command", ["mcp-server", "install-mcp-server"])
    def test_daemon_commands_are_non_interactive(self, command):
        """mcp-server and install-mcp-server run as daemons / background threads."""
        assert is_interactive_run(_ns(command=command)) is False

    @pytest.mark.parametrize("command", ["evo", "inspect"])
    def test_evo_and_inspect_are_always_interactive(self, command):
        """
        evo always prompts for tenant + token; inspect has no auth requirement
        so every invocation is treated as human-driven regardless of control
        servers.
        """
        assert is_interactive_run(_ns(command=command)) is True

    def test_inspect_is_interactive_even_with_push_key(self):
        """
        inspect ignores push-key provisioning since it doesn't require auth.
        """
        args = _ns(
            command="inspect",
            control_servers=[_control_server_with_push_key()],
        )
        assert is_interactive_run(args) is True

    def test_scan_without_control_servers_is_interactive(self):
        assert is_interactive_run(_ns(command="scan", control_servers=[])) is True

    def test_scan_without_push_key_is_interactive(self):
        """A plain user-token control server does not mark the run as MDM."""
        args = _ns(
            command="scan",
            control_servers=[_control_server_without_push_key()],
        )
        assert is_interactive_run(args) is True

    def test_scan_with_push_key_is_non_interactive(self):
        """MDM-provisioned scan carries x-client-id header and must not prompt."""
        args = _ns(
            command="scan",
            control_servers=[_control_server_with_push_key()],
        )
        assert is_interactive_run(args) is False

    def test_scan_with_mixed_control_servers_is_non_interactive_if_any_has_push_key(self):
        """Any x-client-id header is enough to flip the run to non-interactive."""
        args = _ns(
            command="scan",
            control_servers=[
                _control_server_without_push_key(),
                _control_server_with_push_key(),
            ],
        )
        assert is_interactive_run(args) is False

    def test_missing_command_attribute_falls_through_to_push_key_check(self):
        """getattr default is None; treated like scan with no push key -> True."""
        args = Namespace(control_servers=[])
        assert is_interactive_run(args) is True

    def test_missing_control_servers_attribute_is_safe(self):
        """get_push_key tolerates missing attribute."""
        args = Namespace(command="scan")
        assert is_interactive_run(args) is True


class TestEnforceConsentRequirements:
    def test_non_ci_run_is_not_gated(self):
        """Without --ci the enforcement is a no-op."""
        enforce_consent_requirements(_ns(ci=False))  # does not raise / exit

    def test_ci_without_dangerous_flag_exits(self, capsys):
        args = _ns(ci=True, dangerously_run_mcp_servers=False)
        with pytest.raises(SystemExit) as excinfo:
            enforce_consent_requirements(args)
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "--ci requires --dangerously-run-mcp-servers" in captured.err

    def test_ci_with_dangerous_passes_regardless_of_suppress_io(self):
        """--ci only requires --dangerously-run-mcp-servers; IO flag is independent."""
        for suppress in (True, False, None):
            args = _ns(ci=True, dangerously_run_mcp_servers=True, suppress_mcpserver_io=suppress)
            enforce_consent_requirements(args)  # does not raise / exit

    def test_json_alone_is_not_gated(self):
        """
        --json on its own does not require --dangerously-run-mcp-servers: the
        consent prompt is written to stderr while JSON is written to stdout,
        so the channels do not collide.
        """
        args = _ns(json=True, dangerously_run_mcp_servers=False)
        enforce_consent_requirements(args)  # does not raise / exit

    def test_json_with_ci_still_needs_dangerous_flag(self, capsys):
        """--ci's rules apply even when combined with --json."""
        args = _ns(
            ci=True,
            json=True,
            dangerously_run_mcp_servers=False,
        )
        with pytest.raises(SystemExit) as excinfo:
            enforce_consent_requirements(args)
        assert excinfo.value.code == 2
        captured = capsys.readouterr()
        assert "--ci requires" in captured.err

    def test_missing_attributes_default_to_safe_values(self):
        """getattr fallbacks keep the function total for non-scan Namespaces."""
        enforce_consent_requirements(Namespace())  # does not raise / exit


class TestStr2Bool:
    """The argparse type used by --suppress-mcpserver-io must accept the documented spellings."""

    @pytest.mark.parametrize("value", ["true", "TRUE", "True", "1", "t", "y", "yes", "YES", "Yes"])
    def test_truthy_values(self, value: str):
        assert str2bool(value) is True

    @pytest.mark.parametrize("value", ["false", "FALSE", "0", "n", "no", "off", "", "garbage", "2"])
    def test_falsy_or_unknown_values(self, value: str):
        """Anything outside the truthy set falls back to False (no exception)."""
        assert str2bool(value) is False


class TestResolveServerIoDefault:
    """resolve_server_io_default fills in --suppress-mcpserver-io when unset."""

    def test_unset_on_interactive_run_resolves_to_false(self):
        """Interactive (default scan, no push key) → stream stderr → suppress=False."""
        args = _ns(suppress_mcpserver_io=None)
        resolve_server_io_default(args)
        assert args.suppress_mcpserver_io is False

    def test_unset_on_non_interactive_run_resolves_to_true(self):
        """Push-key scan is non-interactive → suppress=True (silence subprocess noise)."""
        args = _ns(
            command="scan",
            control_servers=[_control_server_with_push_key()],
            suppress_mcpserver_io=None,
        )
        resolve_server_io_default(args)
        assert args.suppress_mcpserver_io is True

    def test_unset_on_daemon_command_resolves_to_true(self):
        """mcp-server / install-mcp-server are non-interactive even without push key."""
        args = _ns(command="mcp-server", suppress_mcpserver_io=None)
        resolve_server_io_default(args)
        assert args.suppress_mcpserver_io is True

    def test_unset_on_evo_resolves_to_false(self):
        """evo is always interactive, so default is to stream stderr."""
        args = _ns(command="evo", suppress_mcpserver_io=None)
        resolve_server_io_default(args)
        assert args.suppress_mcpserver_io is False

    def test_unset_on_inspect_resolves_to_false(self):
        args = _ns(command="inspect", suppress_mcpserver_io=None)
        resolve_server_io_default(args)
        assert args.suppress_mcpserver_io is False

    @pytest.mark.parametrize("explicit", [True, False])
    def test_explicit_true_or_false_is_preserved(self, explicit: bool):
        """An explicit user choice is never overwritten."""
        args = _ns(suppress_mcpserver_io=explicit)
        resolve_server_io_default(args)
        assert args.suppress_mcpserver_io is explicit

    def test_explicit_value_preserved_even_when_non_interactive(self):
        """User can force stream_stderr=True even on a push-key (non-interactive) run."""
        args = _ns(
            command="scan",
            control_servers=[_control_server_with_push_key()],
            suppress_mcpserver_io=False,
        )
        resolve_server_io_default(args)
        assert args.suppress_mcpserver_io is False

    def test_missing_attribute_is_treated_as_unset(self):
        """getattr default of None applies even when the attribute isn't on the namespace."""
        args = Namespace(command="scan", control_servers=[])
        resolve_server_io_default(args)
        assert args.suppress_mcpserver_io is False


class TestRunScanConsentAndStreamStderrWiring:
    """
    run_scan has three orthogonal switches that affect behavior:
      - is_interactive_run(args)
      - args.dangerously_run_mcp_servers
      - args.suppress_mcpserver_io
    These tests mock the discovery + pipeline layers and assert the right
    flags are forwarded.
    """

    @staticmethod
    def _scan_args(**overrides) -> Namespace:
        defaults = {
            "command": "scan",
            "control_servers": [],
            "verbose": False,
            "scan_all_users": False,
            "server_timeout": 10,
            "files": [],
            "mcp_oauth_tokens_path": None,
            "skills": False,
            "analysis_url": "https://example.com/analysis",
            "verification_H": None,
            "skip_ssl_verify": False,
            "dangerously_run_mcp_servers": False,
            "suppress_mcpserver_io": None,
        }
        defaults.update(overrides)
        return Namespace(**defaults)

    @pytest.mark.asyncio
    async def test_interactive_no_dangerous_collects_consent(self):
        """Default interactive scan: collect_consent is called and its result is forwarded."""
        args = self._scan_args(suppress_mcpserver_io=False)
        declined = {("/cfg.json", "srv-a")}

        with (
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new_callable=AsyncMock,
                return_value=([], [], []),
            ),
            patch("agent_scan.cli.collect_consent", return_value=declined) as mock_consent,
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline",
                new_callable=AsyncMock,
                return_value=[ScanPathResult(path="/cfg.json")],
            ) as mock_pipeline,
        ):
            await run_scan(args, mode="scan")

        mock_consent.assert_called_once()
        kwargs = mock_pipeline.call_args.kwargs
        assert kwargs["declined_servers"] == declined
        assert kwargs["stream_stderr"] is True

    @pytest.mark.asyncio
    async def test_interactive_with_dangerous_skips_consent(self, capsys):
        """--dangerously-run-mcp-servers prints warning and skips consent."""
        args = self._scan_args(dangerously_run_mcp_servers=True, suppress_mcpserver_io=False)

        with (
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new_callable=AsyncMock,
                return_value=([], [], []),
            ),
            patch("agent_scan.cli.collect_consent") as mock_consent,
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline",
                new_callable=AsyncMock,
                return_value=[],
            ) as mock_pipeline,
        ):
            await run_scan(args, mode="scan")

        mock_consent.assert_not_called()
        kwargs = mock_pipeline.call_args.kwargs
        assert kwargs["declined_servers"] == set()
        captured = capsys.readouterr()
        assert "--dangerously-run-mcp-servers is set" in captured.out

    @pytest.mark.asyncio
    async def test_dangerous_with_stream_stderr_shows_suppress_tip(self, capsys):
        """The hide-stderr tip should appear only when stderr is being streamed."""
        args = self._scan_args(dangerously_run_mcp_servers=True, suppress_mcpserver_io=False)
        with (
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new_callable=AsyncMock,
                return_value=([], [], []),
            ),
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            await run_scan(args, mode="scan")
        assert "--suppress-mcpserver-io=true" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_dangerous_with_suppress_io_omits_tip(self, capsys):
        """When stderr is already suppressed, the tip is irrelevant and must not appear."""
        args = self._scan_args(dangerously_run_mcp_servers=True, suppress_mcpserver_io=True)
        with (
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new_callable=AsyncMock,
                return_value=([], [], []),
            ),
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            await run_scan(args, mode="scan")
        out = capsys.readouterr().out
        assert "--dangerously-run-mcp-servers is set" in out
        assert "--suppress-mcpserver-io=true" not in out

    @pytest.mark.asyncio
    async def test_non_interactive_skips_consent_and_warning(self, capsys):
        """Push-key (non-interactive) run: no prompt, no dangerous warning."""
        args = self._scan_args(
            control_servers=[_control_server_with_push_key()],
            suppress_mcpserver_io=True,
        )

        with (
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new_callable=AsyncMock,
                return_value=([], [], []),
            ),
            patch("agent_scan.cli.collect_consent") as mock_consent,
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline",
                new_callable=AsyncMock,
                return_value=[],
            ) as mock_pipeline,
        ):
            await run_scan(args, mode="scan")

        mock_consent.assert_not_called()
        kwargs = mock_pipeline.call_args.kwargs
        assert kwargs["declined_servers"] == set()
        assert kwargs["stream_stderr"] is False
        assert "--dangerously-run-mcp-servers is set" not in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_suppress_io_unset_resolves_inside_run_scan(self):
        """run_scan resolves suppress_mcpserver_io=None to a concrete bool before running."""
        args = self._scan_args(suppress_mcpserver_io=None)  # interactive scan → should default to False

        with (
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new_callable=AsyncMock,
                return_value=([], [], []),
            ),
            patch("agent_scan.cli.collect_consent", return_value=set()),
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline",
                new_callable=AsyncMock,
                return_value=[],
            ) as mock_pipeline,
        ):
            await run_scan(args, mode="scan")

        assert args.suppress_mcpserver_io is False
        assert mock_pipeline.call_args.kwargs["stream_stderr"] is True

    @pytest.mark.asyncio
    async def test_inspect_mode_forwards_consent_and_stream_stderr(self):
        """inspect mode goes through inspect_pipeline and must receive the same flags."""
        args = self._scan_args(command="inspect", suppress_mcpserver_io=False)
        declined = {("/cfg.json", "srv-x")}

        with (
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new_callable=AsyncMock,
                return_value=([], [], []),
            ),
            patch("agent_scan.cli.collect_consent", return_value=declined),
            patch(
                "agent_scan.cli.inspect_pipeline",
                new_callable=AsyncMock,
                return_value=([], []),
            ) as mock_inspect_pipeline,
        ):
            await run_scan(args, mode="inspect")

        kwargs = mock_inspect_pipeline.call_args.kwargs
        assert kwargs["declined_servers"] == declined
        assert kwargs["stream_stderr"] is True

    @pytest.mark.asyncio
    async def test_unknown_mode_raises(self):
        args = self._scan_args()
        with (
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new_callable=AsyncMock,
                return_value=([], [], []),
            ),
            patch("agent_scan.cli.collect_consent", return_value=set()),
            pytest.raises(ValueError, match="Unknown mode"),
        ):
            await run_scan(args, mode="bogus")  # type: ignore[arg-type]
