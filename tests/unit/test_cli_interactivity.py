"""Tests for is_interactive_run and enforce_consent_requirements in cli.py."""

from argparse import Namespace

import pytest

from agent_scan.cli import enforce_consent_requirements, is_interactive_run
from agent_scan.models import ControlServer


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
