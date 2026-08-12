"""Tests for is_interactive_run, enforce_consent_requirements, resolve_server_io_default,
str2bool, and the consent / stream_stderr wiring in run_scan."""

from argparse import Namespace
from typing import ClassVar
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import (
    HandshakeDecision,
    decide_handshake,
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
    def test_inspect_is_always_interactive(self):
        """
        inspect has no upload step, so every invocation is treated as
        human-driven regardless of control-server contents.
        """
        assert is_interactive_run(_ns(command="inspect")) is True

    def test_inspect_is_interactive_even_with_push_key(self):
        """
        inspect ignores push-key provisioning since it doesn't require auth
        and still handshakes stdio servers locally.
        """
        args = _ns(
            command="inspect",
            control_servers=[_control_server_with_push_key()],
        )
        assert is_interactive_run(args) is True

    def test_evo_without_push_key_in_args_is_interactive(self):
        """
        At ``main()``-time, ``args.control_servers`` for evo is whatever the
        user passed (typically empty). The fallthrough then reports the run
        as interactive, which is correct for the upfront tenant/token
        prompts. ``evo()`` later mints a push key into
        ``args.control_servers`` before calling ``run_scan``, which flips
        the predicate to False at that downstream call site.
        """
        assert is_interactive_run(_ns(command="evo")) is True
        assert is_interactive_run(_ns(command="evo", control_servers=[])) is True

    def test_evo_with_push_key_in_args_is_not_interactive(self):
        """
        Once ``evo()`` has minted and injected a push key into
        ``args.control_servers``, ``is_interactive_run`` correctly reports
        False — matching the push-key semantics and ensuring no consent
        prompt or dangerous-flag warning would fire even if the consent
        gate's push-key short-circuit were ever removed.
        """
        args = _ns(command="evo", control_servers=[_control_server_with_push_key()])
        assert is_interactive_run(args) is False

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


class TestIsInteractiveRunMatrix:
    """
    Pins the full truth table for ``is_interactive_run`` across every
    (command, has_push_key) combination so a future change cannot
    silently flip the consent / suppress_io defaults.
    """

    # (command, has_push_key, expected_interactive)
    _CASES: ClassVar[list[tuple[str | None, bool, bool]]] = [
        # scan: classic interactive run.
        ("scan", False, True),
        # scan + push key (CI/MDM): non-interactive upload.
        ("scan", True, False),
        # evo at ``main()``-time (control_servers empty): interactive — the
        # user types tenant/token at startup. Push key is only injected by
        # ``evo()`` before ``run_scan``, so the fallthrough sees no
        # push-key here.
        ("evo", False, True),
        # evo at ``run_scan``-time (push key minted into control_servers
        # already): fallthrough correctly reports False — matching the
        # push-key semantics at that downstream call site.
        ("evo", True, False),
        # inspect: always interactive (special-case), even if a push key
        # somehow appears in args.
        ("inspect", False, True),
        ("inspect", True, True),
        # Missing / unknown command (e.g. ``guard``, ``help``, ``None``)
        # falls through the same way ``scan`` does.
        (None, False, True),
        (None, True, False),
    ]

    @pytest.mark.parametrize("command,has_push_key,expected_interactive", _CASES)
    def test_is_interactive_run_truth_table(
        self,
        command: str | None,
        has_push_key: bool,
        expected_interactive: bool,
    ):
        control_servers = [_control_server_with_push_key()] if has_push_key else []
        args = _ns(command=command, control_servers=control_servers)
        assert is_interactive_run(args) is expected_interactive, (
            f"is_interactive_run({command=}, {has_push_key=}) returned the wrong value"
        )


class TestDecideHandshake:
    """
    Pins ``decide_handshake`` — the single function that decides
    whether ``run_scan`` will start stdio MCP server subprocesses,
    collect interactive consent, and/or print the dangerous-flag
    warning. Returns a frozen ``HandshakeDecision`` struct that the
    action layer in ``run_scan`` dispatches on without re-checking
    flag combinations.

    The function is **allowlist-first**: only commands explicitly
    listed in ``_LOCAL_SCAN_COMMANDS`` (currently ``scan``, ``inspect``,
    and the ``None`` fallback) may handshake. Anything else — ``evo``,
    ``guard``, ``help``, or any future command — defaults to no
    handshake, no consent, no warning. ``--dangerously-run-mcp-servers``
    is the universal explicit opt-in override.

    The decision combines four dimensions:

    * ``command`` (``scan`` / ``evo`` / ``inspect`` / other)
    * push-key in ``args.control_servers``
    * ``--ci``  (only matters via ``enforce_consent_requirements``,
      not this function)
    * ``--dangerously-run-mcp-servers``
    """

    # -- inspect: always handshakes, always interactive -------------------

    def test_inspect_always_handshakes(self):
        for control_servers in (
            [],
            [_control_server_without_push_key()],
            [_control_server_with_push_key()],
        ):
            for ci in (False, True):
                for dangerous in (False, True):
                    args = _ns(
                        command="inspect",
                        control_servers=control_servers,
                        ci=ci,
                        dangerously_run_mcp_servers=dangerous,
                    )
                    decision = decide_handshake(args)
                    assert decision.do_stdio_handshake is True, (
                        f"inspect must always handshake; got False for "
                        f"control_servers={control_servers}, ci={ci}, dangerous={dangerous}"
                    )
                    # Inspect is always at the terminal, so consent is
                    # collected unless ``--dangerously`` was set. (The
                    # dangerous-flag banner is tested in
                    # ``TestRunScanConsentAndStreamStderrWiring`` via
                    # captured stdout — see ``decide_handshake``'s class
                    # docstring for why it isn't a field here.)
                    assert decision.collect_consent is (not dangerous)

    # -- scan without push key: always handshakes -------------------------

    @pytest.mark.parametrize("ci", [True, False])
    @pytest.mark.parametrize("dangerous", [True, False])
    def test_scan_without_push_key_always_handshakes(self, ci: bool, dangerous: bool):
        for control_servers in ([], [_control_server_without_push_key()]):
            args = _ns(
                command="scan",
                control_servers=control_servers,
                ci=ci,
                dangerously_run_mcp_servers=dangerous,
            )
            decision = decide_handshake(args)
            assert decision.do_stdio_handshake is True
            # Interactive local scan: dangerous decides consent vs the
            # informational banner (banner is asserted via stdout in
            # ``TestRunScanConsentAndStreamStderrWiring``).
            assert decision.collect_consent is (not dangerous)

    # -- scan with push key: skips by default, override = --dangerously ---

    @pytest.mark.parametrize("ci", [True, False])
    @pytest.mark.parametrize("dangerous", [True, False])
    def test_scan_with_push_key_handshake_depends_on_dangerous_override(self, ci: bool, dangerous: bool):
        """
        ``--dangerously-run-mcp-servers`` alone overrides the push-key
        stdio-handshake skip. ``--ci`` is orthogonal here (the gate in
        ``enforce_consent_requirements`` independently couples them, but
        the predicate itself only consults ``dangerous``).

        Consent is never collected on the push-key path — there is no
        human at the terminal to prompt.
        """
        args = _ns(
            command="scan",
            control_servers=[_control_server_with_push_key()],
            ci=ci,
            dangerously_run_mcp_servers=dangerous,
        )
        decision = decide_handshake(args)
        assert decision.do_stdio_handshake is dangerous
        assert decision.collect_consent is False

    def test_scan_with_push_key_in_mixed_servers_still_skips_handshake(self):
        args = _ns(
            command="scan",
            control_servers=[_control_server_without_push_key(), _control_server_with_push_key()],
        )
        decision = decide_handshake(args)
        assert decision.do_stdio_handshake is False
        assert decision.collect_consent is False

    # -- evo: outside _LOCAL_SCAN_COMMANDS, same dangerous override -------

    @pytest.mark.parametrize("ci", [True, False])
    @pytest.mark.parametrize("dangerous", [True, False])
    def test_evo_handshake_depends_on_dangerous_override(self, ci: bool, dangerous: bool):
        """
        evo is not in the local-scan allowlist (it uploads via a minted
        push key), so it defaults to no handshake regardless of
        ``control_servers`` contents. The only thing that flips the
        handshake decision is ``--dangerously-run-mcp-servers``. As on
        every other unattended path, consent / warning are silent.
        """
        for control_servers in (
            [],
            [_control_server_with_push_key()],
        ):
            args = _ns(
                command="evo",
                control_servers=control_servers,
                ci=ci,
                dangerously_run_mcp_servers=dangerous,
            )
            decision = decide_handshake(args)
            assert decision.do_stdio_handshake is dangerous
            assert decision.collect_consent is False

    # -- override granularity: --dangerously is the load-bearing flag -----

    def test_dangerous_alone_enables_handshake_on_push_key(self):
        """
        ``--dangerously`` alone (no ``--ci``) is enough to override the
        push-key skip. The flag itself is the explicit "I want to spawn
        stdio MCP server subprocesses" opt-in — its effect doesn't
        depend on ``--ci``.
        """
        args = _ns(
            command="scan",
            control_servers=[_control_server_with_push_key()],
            ci=False,
            dangerously_run_mcp_servers=True,
        )
        assert decide_handshake(args).do_stdio_handshake is True

    def test_ci_alone_does_not_enable_handshake_on_push_key(self):
        """
        ``--ci`` alone does *not* override the push-key skip. (And
        ``enforce_consent_requirements`` rejects it at startup anyway —
        ``--ci`` requires ``--dangerously``.) This test pins that the
        predicate doesn't accidentally treat ``--ci`` as the trigger.
        """
        args = _ns(
            command="scan",
            control_servers=[_control_server_with_push_key()],
            ci=True,
            dangerously_run_mcp_servers=False,
        )
        assert decide_handshake(args).do_stdio_handshake is False

    def test_ci_and_dangerous_together_enable_handshake_on_push_key(self):
        """The typical CI invocation (both flags set) handshakes — same
        outcome as ``--dangerously`` alone since ``--dangerously`` is the
        sole trigger; ``--ci`` is along for the ride to satisfy
        ``enforce_consent_requirements``."""
        args = _ns(
            command="scan",
            control_servers=[_control_server_with_push_key()],
            ci=True,
            dangerously_run_mcp_servers=True,
        )
        assert decide_handshake(args).do_stdio_handshake is True

    # -- safe default for unknown / future commands -----------------------

    @pytest.mark.parametrize("future_command", ["verify", "report", "audit", "guard", "help"])
    def test_unknown_or_future_command_defaults_to_no_handshake(self, future_command: str):
        """
        Forward-compat safety contract: any command not in
        ``_LOCAL_SCAN_COMMANDS`` defaults to no handshake / no consent /
        no warning. Adding a new subcommand to argparse must NOT
        accidentally start spawning stdio MCP server subprocesses on
        the user's machine — opting a command into handshakes requires
        a deliberate edit of ``_LOCAL_SCAN_COMMANDS``.
        """
        for control_servers in ([], [_control_server_without_push_key()], [_control_server_with_push_key()]):
            args = _ns(command=future_command, control_servers=control_servers)
            decision = decide_handshake(args)
            assert decision.do_stdio_handshake is False, (
                f"future command {future_command!r} must default to no handshake (control_servers={control_servers})"
            )
            assert decision.collect_consent is False

    def test_unknown_command_still_honors_dangerous_override(self):
        """The ``--dangerously`` override applies universally, even to
        unknown commands — it's the only universal escape hatch."""
        args = _ns(command="some_new_future_command", dangerously_run_mcp_servers=True)
        assert decide_handshake(args).do_stdio_handshake is True

    # -- decision struct is a frozen dataclass ----------------------------

    def test_decision_is_immutable(self):
        """``HandshakeDecision`` is frozen — the action layer can't
        mutate the decision after computing it."""
        decision = decide_handshake(_ns(command="scan"))
        with pytest.raises(AttributeError):
            decision.do_stdio_handshake = False  # type: ignore[misc]

    def test_decision_returns_handshake_decision_type(self):
        decision = decide_handshake(_ns(command="scan"))
        assert isinstance(decision, HandshakeDecision)

    # -- missing-attribute robustness --------------------------------------

    def test_missing_command_falls_through_to_scan_logic(self):
        """No ``command`` attribute → treated like ``scan`` (None is in
        the allowlist as the argparse-no-subcommand fallback)."""
        decision_no_push_key = decide_handshake(Namespace(control_servers=[]))
        assert decision_no_push_key.do_stdio_handshake is True

        decision_with_push_key = decide_handshake(Namespace(control_servers=[_control_server_with_push_key()]))
        assert decision_with_push_key.do_stdio_handshake is False

    def test_missing_control_servers_attribute_is_safe(self):
        """getattr fallbacks keep the function total for any Namespace."""
        # scan with no control_servers attr → no push key → handshake.
        assert decide_handshake(Namespace(command="scan")).do_stdio_handshake is True
        # inspect always handshakes.
        assert decide_handshake(Namespace(command="inspect")).do_stdio_handshake is True
        # evo is outside the allowlist → safe-default skip.
        assert decide_handshake(Namespace(command="evo")).do_stdio_handshake is False


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

    def test_ci_with_push_key_still_requires_dangerous_flag(self, capsys):
        """
        ``--ci`` unconditionally requires ``--dangerously-run-mcp-servers``,
        even on the push-key path. The pair together is the explicit
        opt-in that overrides the default push-key stdio handshake skip
        (see ``run_scan``'s ``do_stdio_handshake`` derivation): the
        whole point of allowing it is that the CI run *will* spawn stdio
        subprocesses, so ``--dangerously`` is mandatory to make that
        intent visible.
        """
        args = _ns(
            command="scan",
            ci=True,
            dangerously_run_mcp_servers=False,
            control_servers=[_control_server_with_push_key()],
        )
        with pytest.raises(SystemExit) as excinfo:
            enforce_consent_requirements(args)
        assert excinfo.value.code == 2
        assert "--ci requires --dangerously-run-mcp-servers" in capsys.readouterr().err

    def test_ci_with_evo_still_requires_dangerous_flag(self, capsys):
        """
        Same rule for evo: ``--ci`` always requires ``--dangerously``, even
        though evo is always a push-key run. (Combining ``--ci`` with evo
        is unusual in practice — evo prompts for tenant+token — but the
        gate must be consistent across commands so a future CI invocation
        of evo cannot silently switch behaviour.)
        """
        args = _ns(command="evo", ci=True, dangerously_run_mcp_servers=False)
        with pytest.raises(SystemExit) as excinfo:
            enforce_consent_requirements(args)
        assert excinfo.value.code == 2
        assert "--ci requires --dangerously-run-mcp-servers" in capsys.readouterr().err

    def test_ci_with_scan_and_no_push_key_still_requires_dangerous_flag(self, capsys):
        """
        A non-push-key ``scan --ci`` without ``--dangerously`` must exit
        2 — we would otherwise spawn stdio subprocesses in CI with no
        consent prompt to gate them. This is the original ``--ci`` rule.
        """
        args = _ns(
            command="scan",
            ci=True,
            dangerously_run_mcp_servers=False,
            control_servers=[_control_server_without_push_key()],
        )
        with pytest.raises(SystemExit) as excinfo:
            enforce_consent_requirements(args)
        assert excinfo.value.code == 2
        assert "--ci requires --dangerously-run-mcp-servers" in capsys.readouterr().err

    def test_ci_with_inspect_still_requires_dangerous_flag(self, capsys):
        """
        inspect is not a push-key run (no upload step), but the ``--ci``
        rule applies uniformly: inspect ``--ci`` without ``--dangerously``
        exits 2.
        """
        args = _ns(
            command="inspect",
            ci=True,
            dangerously_run_mcp_servers=False,
            control_servers=[_control_server_with_push_key()],
        )
        with pytest.raises(SystemExit) as excinfo:
            enforce_consent_requirements(args)
        assert excinfo.value.code == 2
        assert "--ci requires --dangerously-run-mcp-servers" in capsys.readouterr().err


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

    def test_unset_on_evo_resolves_to_false(self):
        """
        ``resolve_server_io_default`` runs in ``main()`` *before* ``evo()``
        mints a push key, so at this point ``args.control_servers`` is
        empty and ``is_interactive_run`` returns True via the fallthrough.
        The default is therefore "stream stderr", which is right for the
        upfront tenant/token prompts. (Note: stream_stderr is later moot
        in ``run_scan`` since ``do_stdio_handshake`` returns False on this
        path → no stdio subprocess ever produces stderr — harmless
        dead-code path on this
        run type.)
        """
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
        assert kwargs["do_stdio_handshake"] is True

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
        """Push-key (non-interactive) run: no prompt, no dangerous warning,
        stdio handshakes suppressed."""
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
        # Push-key path must suppress stdio MCP server handshakes.
        assert kwargs["do_stdio_handshake"] is False
        assert "--dangerously-run-mcp-servers is set" not in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_push_key_with_dangerous_flag_handshakes_silently(self, capsys):
        """``--dangerously-run-mcp-servers`` overrides the push-key
        stdio-handshake skip — the flag is the universal explicit
        opt-in. The dangerous-flag warning still does not print because
        the push-key path is non-interactive, but the handshake itself
        proceeds.
        """
        args = self._scan_args(
            control_servers=[_control_server_with_push_key()],
            dangerously_run_mcp_servers=True,
            suppress_mcpserver_io=True,
        )

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
            ) as mock_pipeline,
        ):
            await run_scan(args, mode="scan")

        assert mock_pipeline.call_args.kwargs["do_stdio_handshake"] is True
        assert "--dangerously-run-mcp-servers is set" not in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_evo_skips_consent_and_stdio_handshake(self, capsys):
        """evo is a push-key run: stdio handshakes are skipped and the
        consent prompt is not shown — there are no stdio subprocesses for
        the user to allow."""
        args = self._scan_args(command="evo", control_servers=[_control_server_with_push_key()])

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
        assert kwargs["do_stdio_handshake"] is False
        assert kwargs["declined_servers"] == set()
        assert "--dangerously-run-mcp-servers is set" not in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_evo_with_dangerous_flag_handshakes_silently(self, capsys):
        """
        evo + ``--dangerously-run-mcp-servers`` → do_stdio_handshake
        becomes True (the flag is the universal explicit opt-in for
        stdio subprocesses). No consent prompt or dangerous-flag warning
        fires because evo's push-key state makes the run non-interactive
        at the consent gate.
        """
        args = self._scan_args(
            command="evo",
            control_servers=[_control_server_with_push_key()],
            dangerously_run_mcp_servers=True,
            suppress_mcpserver_io=False,
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
        assert kwargs["do_stdio_handshake"] is True
        out = capsys.readouterr().out
        assert "--dangerously-run-mcp-servers is set" not in out

    @pytest.mark.asyncio
    async def test_evo_preserves_explicit_suppress_io(self):
        """
        evo overlaps the two predicates (interactive + push-key). Even
        though the suppress_io flag has no practical effect when stdio
        handshakes are skipped, an explicit user choice must still be
        preserved verbatim — this guards the
        ``suppress_io is None ? default : keep`` branch from being
        accidentally re-resolved based on the wrong predicate.
        """
        args_true = self._scan_args(
            command="evo",
            control_servers=[_control_server_with_push_key()],
            suppress_mcpserver_io=True,
        )
        args_false = self._scan_args(
            command="evo",
            control_servers=[_control_server_with_push_key()],
            suppress_mcpserver_io=False,
        )

        for args, expected_stream_stderr in ((args_true, False), (args_false, True)):
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
                ) as mock_pipeline,
            ):
                await run_scan(args, mode="scan")

            kwargs = mock_pipeline.call_args.kwargs
            assert kwargs["stream_stderr"] is expected_stream_stderr
            assert kwargs["do_stdio_handshake"] is False

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
        # inspect is always interactive, even when control_servers carry a push key.
        assert kwargs["do_stdio_handshake"] is True

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


class TestStdioHandshakeInvariants:
    """
    Pins the cross-command rules for when stdio MCP server handshakes
    happen. These invariants are the load-bearing guarantees behind the
    consent + push-key + CI flag interactions; together they answer
    "when do we ever spawn an stdio subprocess?":

    * ``inspect`` — *never* runs with a push key. A push key in args is
      ignored. Stdio handshakes always happen, and consent is always
      collected (no upload step exists for the push key to govern).
    * ``evo`` — *always* a push-key run (``evo()`` mints one). Stdio
      handshakes are skipped on this path *unless* the explicit
      ``--ci --dangerously-run-mcp-servers`` override is set, in which
      case they happen.
    * ``scan`` + push-key — stdio handshakes are skipped by default. The
      same ``--ci --dangerously-run-mcp-servers`` override re-enables
      them. ``--json`` alone has no effect.
    * ``scan`` without push-key — stdio handshakes happen, gated by the
      consent prompt (or bypassed with ``--dangerously``).
    * ``--ci`` always requires ``--dangerously-run-mcp-servers``; the
      gate makes no exemption for push-key. The pair is the only way to
      override the push-key stdio skip — the explicit requirement makes
      the override intentional and visible.

    These tests are intentionally separate from the wiring tests in
    ``TestRunScanConsentAndStreamStderrWiring``: those check that the
    flags propagate; these check that the *semantic invariants* hold
    across the full flag matrix.
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
            "ci": False,
            "json": False,
            "dangerously_run_mcp_servers": False,
            "suppress_mcpserver_io": None,
        }
        defaults.update(overrides)
        return Namespace(**defaults)

    # -- inspect invariants ------------------------------------------------

    @pytest.mark.asyncio
    async def test_inspect_handshakes_stdio_even_with_push_key_in_args(self):
        """
        Pushing a push key into inspect's ``--control-server-H`` does not
        flip it onto the push-key path: inspect has no upload step, so the
        push key is ignored, stdio handshakes still happen, and the
        consent flow still runs.
        """
        args = self._scan_args(
            command="inspect",
            control_servers=[_control_server_with_push_key()],
            suppress_mcpserver_io=False,
        )
        declined = {("/cfg.json", "srv-x")}

        with (
            patch(
                "agent_scan.cli.discover_clients_to_inspect",
                new_callable=AsyncMock,
                return_value=([], [], []),
            ),
            patch("agent_scan.cli.collect_consent", return_value=declined) as mock_consent,
            patch(
                "agent_scan.cli.inspect_pipeline",
                new_callable=AsyncMock,
                return_value=([], []),
            ) as mock_pipeline,
        ):
            await run_scan(args, mode="inspect")

        mock_consent.assert_called_once()
        kwargs = mock_pipeline.call_args.kwargs
        assert kwargs["do_stdio_handshake"] is True
        assert kwargs["declined_servers"] == declined

    # -- evo invariants ----------------------------------------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dangerous", [True, False])
    @pytest.mark.parametrize("ci", [True, False])
    @pytest.mark.parametrize("json_flag", [True, False])
    async def test_evo_stdio_handshake_skip_depends_on_dangerous_override(
        self, dangerous: bool, ci: bool, json_flag: bool
    ):
        """
        evo skips stdio handshakes by default (push-key path). The
        exception is ``--dangerously-run-mcp-servers``, which re-enables
        handshakes. ``--ci`` and ``--json`` are orthogonal.
        """
        args = self._scan_args(
            command="evo",
            control_servers=[_control_server_with_push_key()],
            ci=ci,
            json=json_flag,
            dangerously_run_mcp_servers=dangerous,
        )
        # ``--dangerously`` alone overrides the push-key handshake skip
        # (see ``do_stdio_handshake``); ``--ci`` and ``--json`` are
        # orthogonal here.
        expected_do_handshake = dangerous

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

        # On push-key paths the consent prompt never runs regardless of the
        # handshake override — the user is unattended so there is no one to
        # prompt. ``--dangerously`` bypassing consent only matters on the
        # interactive (non-push-key) path.
        mock_consent.assert_not_called()
        assert mock_pipeline.call_args.kwargs["do_stdio_handshake"] is expected_do_handshake

    # -- scan + push-key + --ci / --json invariants ------------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("dangerous", [True, False])
    @pytest.mark.parametrize("ci", [True, False])
    @pytest.mark.parametrize("json_flag", [True, False])
    async def test_scan_push_key_stdio_handshake_skip_depends_on_dangerous_override(
        self, dangerous: bool, ci: bool, json_flag: bool
    ):
        """
        A push-key scan skips stdio handshakes by default. The
        ``--dangerously-run-mcp-servers`` flag re-enables them — the
        explicit user opt-in for spawning stdio MCP server subprocesses
        (e.g., to scan first-party servers in CI that aren't in the
        analysis backend's catalog). ``--ci`` and ``--json`` are
        orthogonal here; ``--ci`` happens to be required to satisfy
        ``enforce_consent_requirements``, but it does not itself drive
        the handshake decision.
        """
        args = self._scan_args(
            control_servers=[_control_server_with_push_key()],
            ci=ci,
            json=json_flag,
            dangerously_run_mcp_servers=dangerous,
        )
        # ``--dangerously`` alone overrides the push-key handshake skip
        # (see ``do_stdio_handshake``); ``--ci`` and ``--json`` are
        # orthogonal here.
        expected_do_handshake = dangerous

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

        # Same reasoning as the evo test above: push-key path is always
        # unattended, so consent is never collected regardless of the
        # handshake outcome.
        mock_consent.assert_not_called()
        kwargs = mock_pipeline.call_args.kwargs
        assert kwargs["do_stdio_handshake"] is expected_do_handshake
        assert kwargs["declined_servers"] == set()

    # -- scan without push-key still requires consent ---------------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("json_flag", [True, False])
    async def test_scan_no_push_key_with_ci_dangerous_runs_handshake_without_consent_prompt(
        self, json_flag: bool, capsys
    ):
        """
        ``scan`` without a push key + ``--ci`` + ``--dangerously``: the
        consent prompt is bypassed (dangerous), stdio handshakes proceed
        (no push key to skip them), and the dangerous-flag warning is
        printed. ``--json`` does not change any of this.
        """
        args = self._scan_args(
            ci=True,
            json=json_flag,
            dangerously_run_mcp_servers=True,
            suppress_mcpserver_io=False,
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
        assert kwargs["do_stdio_handshake"] is True
        assert kwargs["declined_servers"] == set()
        assert "--dangerously-run-mcp-servers is set" in capsys.readouterr().out

    # -- enforce_consent_requirements: the --ci / --json / push-key grid --

    @pytest.mark.parametrize("json_flag", [True, False])
    def test_enforce_consent_requirements_rejects_ci_plus_push_key_without_dangerous(self, json_flag: bool, capsys):
        """
        ``--ci`` requires ``--dangerously-run-mcp-servers`` *unconditionally*,
        including on the push-key path. The pair is the only way to
        override the default push-key stdio skip, and the explicit
        requirement makes that override intentional.
        """
        args = _ns(
            command="scan",
            ci=True,
            json=json_flag,
            dangerously_run_mcp_servers=False,
            control_servers=[_control_server_with_push_key()],
        )
        with pytest.raises(SystemExit) as excinfo:
            enforce_consent_requirements(args)
        assert excinfo.value.code == 2
        assert "--ci requires --dangerously-run-mcp-servers" in capsys.readouterr().err

    @pytest.mark.parametrize("json_flag", [True, False])
    def test_enforce_consent_requirements_rejects_ci_plus_evo_without_dangerous(self, json_flag: bool, capsys):
        """
        Same rule for evo, which is always a push-key run: ``--ci`` still
        demands ``--dangerously``.
        """
        args = _ns(
            command="evo",
            ci=True,
            json=json_flag,
            dangerously_run_mcp_servers=False,
        )
        with pytest.raises(SystemExit) as excinfo:
            enforce_consent_requirements(args)
        assert excinfo.value.code == 2
        assert "--ci requires --dangerously-run-mcp-servers" in capsys.readouterr().err

    @pytest.mark.parametrize("json_flag", [True, False])
    def test_enforce_consent_requirements_rejects_ci_plus_inspect_without_dangerous(self, json_flag: bool, capsys):
        """
        Same rule for inspect — the gate is uniform across commands.
        """
        args = _ns(
            command="inspect",
            ci=True,
            json=json_flag,
            dangerously_run_mcp_servers=False,
            control_servers=[_control_server_with_push_key()],
        )
        with pytest.raises(SystemExit) as excinfo:
            enforce_consent_requirements(args)
        assert excinfo.value.code == 2
        assert "--ci requires --dangerously-run-mcp-servers" in capsys.readouterr().err

    # -- explicit override coverage ----------------------------------------

    @pytest.mark.asyncio
    async def test_scan_push_key_ci_dangerous_overrides_stdio_skip(self):
        """
        The typical CI invocation path: ``scan --ci --dangerously`` with
        a push-key in args runs stdio handshakes locally despite the
        push-key normally skipping them. This is the ADP/first-party use
        case — scanning stdio MCP servers in CI that aren't in the
        analysis backend's catalog. The override is actually driven by
        ``--dangerously`` alone (see ``do_stdio_handshake``); ``--ci``
        is along for the ride to satisfy ``enforce_consent_requirements``.
        No consent prompt fires because the run is unattended (push-key
        path).
        """
        args = self._scan_args(
            control_servers=[_control_server_with_push_key()],
            ci=True,
            dangerously_run_mcp_servers=True,
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
        assert mock_pipeline.call_args.kwargs["do_stdio_handshake"] is True

    @pytest.mark.asyncio
    async def test_scan_push_key_dangerous_alone_overrides_stdio_skip(self):
        """
        ``--dangerously`` *alone* (no ``--ci``) overrides the push-key
        stdio skip — the flag is the universal explicit opt-in for
        spawning stdio MCP server subprocesses. ``--ci`` is a separate
        concern handled by ``enforce_consent_requirements``.

        The consent prompt still does not fire because the push-key path
        is unattended (``is_interactive_run`` returns False).
        """
        args = self._scan_args(
            control_servers=[_control_server_with_push_key()],
            ci=False,
            dangerously_run_mcp_servers=True,
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
        assert mock_pipeline.call_args.kwargs["do_stdio_handshake"] is True

    @pytest.mark.asyncio
    async def test_scan_push_key_ci_alone_does_not_override_stdio_skip(self):
        """
        ``--ci`` without ``--dangerously`` is rejected by the gate before
        it ever reaches ``run_scan``, but for completeness this test calls
        ``run_scan`` directly with ``ci=True`` and ``dangerous=False`` to
        confirm the override trigger is ``--dangerously`` (not ``--ci``).
        """
        args = self._scan_args(
            control_servers=[_control_server_with_push_key()],
            ci=True,
            dangerously_run_mcp_servers=False,
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
        assert mock_pipeline.call_args.kwargs["do_stdio_handshake"] is False

    @pytest.mark.asyncio
    async def test_evo_ci_dangerous_overrides_stdio_skip(self):
        """
        The override applies to evo too: ``evo --ci --dangerously`` runs
        stdio handshakes despite evo always being a push-key path. As
        with the scan case, the override is actually driven by
        ``--dangerously`` alone.
        """
        args = self._scan_args(
            command="evo",
            control_servers=[_control_server_with_push_key()],
            ci=True,
            dangerously_run_mcp_servers=True,
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
        assert mock_pipeline.call_args.kwargs["do_stdio_handshake"] is True

    @pytest.mark.asyncio
    async def test_evo_dangerous_alone_overrides_stdio_skip(self):
        """Symmetric to the scan case: ``evo --dangerously`` (no
        ``--ci``) also overrides the push-key stdio skip. The override
        is the dangerous flag, not the pair."""
        args = self._scan_args(
            command="evo",
            control_servers=[_control_server_with_push_key()],
            ci=False,
            dangerously_run_mcp_servers=True,
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
        assert mock_pipeline.call_args.kwargs["do_stdio_handshake"] is True
