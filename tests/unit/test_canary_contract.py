"""Executor-interface contract: every ``Scope`` subclass emits well-formed ``SeedCommand``s.

The backoffice executor (agent-scan-backoffice ``canary.run_canary``) is a *generic interpreter*: it
calls ``scope.commands(ctx)`` for every scope and runs each returned
:class:`~agent_scan.canary.base.SeedCommand` as a subprocess, reading ``argv`` / ``run_in_project`` /
``timeout`` / ``non_fatal``. This test pins that contract from the agent-scan side — every concrete
:class:`~agent_scan.canary.base.Scope` subclass must be exercised by a real canary and must emit commands
the executor can actually run (non-empty string ``argv``, sane flags and a positive ``timeout``). A new
Scope subclass that returns malformed commands — or that no canary uses — fails HERE, before the executor
ever sees it. Companion guard on the executor side: agent-scan-backoffice ``tests/unit/test_canary_dispatch.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_scan.canary import CANARIES, CanaryContext, Scope, SeedCommand

# A purely synthetic context: no path is touched and no command is run — commands() is pure.
CTX = CanaryContext(home=Path("/canary/home"), project=Path("/canary/home/proj"), bin="claude")

_CANARIES = list(CANARIES.values())


def _concrete_scope_subclasses() -> set[type[Scope]]:
    """Every loaded concrete subclass of ``Scope`` (importing ``agent_scan.canary`` registers them all)."""
    seen: set[type[Scope]] = set()
    stack = list(Scope.__subclasses__())
    while stack:
        cls = stack.pop()
        if cls not in seen:
            seen.add(cls)
            stack.extend(cls.__subclasses__())
    return seen


def _assert_well_formed(cmd: object, where: str) -> None:
    """A SeedCommand the executor can hand to ``subprocess.run`` without choking."""
    assert isinstance(cmd, SeedCommand), f"{where}: expected SeedCommand, got {type(cmd).__name__}"
    assert isinstance(cmd.argv, tuple), f"{where}: argv must be a tuple, got {type(cmd.argv).__name__}"
    assert cmd.argv, f"{where}: argv is empty — nothing for the executor to run"
    assert all(isinstance(a, str) and a for a in cmd.argv), f"{where}: argv has a non-string/empty token: {cmd.argv!r}"
    assert isinstance(cmd.run_in_project, bool), f"{where}: run_in_project must be bool"
    assert isinstance(cmd.non_fatal, bool), f"{where}: non_fatal must be bool"
    # bool is a subclass of int, so reject it explicitly — a stray True/False must not pose as a timeout.
    assert isinstance(cmd.timeout, int) and not isinstance(cmd.timeout, bool) and cmd.timeout > 0, (
        f"{where}: timeout must be a positive int, got {cmd.timeout!r}"
    )


@pytest.mark.parametrize("canary", _CANARIES, ids=lambda c: c.name)
def test_every_scope_emits_well_formed_seed_commands(canary):
    scopes = canary.scopes
    assert isinstance(scopes, list) and scopes, f"{canary.name}: .scopes must be a non-empty list"
    for scope in scopes:
        cmds = scope.commands(CTX)
        assert isinstance(cmds, list), f"{canary.name} [{scope.label}]: .commands() must return a list"
        for i, cmd in enumerate(cmds):
            _assert_well_formed(cmd, f"{canary.name} [{scope.label}] cmd#{i}")


def test_every_concrete_scope_subclass_is_exercised_by_a_canary():
    # The well-formedness checks above only bite subclasses some canary actually instantiates. Pin that
    # EVERY concrete Scope subclass is used by a real canary, so a newly-added subclass can't dodge the
    # contract by simply never appearing in CANARIES (and so the executor never meets an untested shape).
    used = {type(scope) for canary in _CANARIES for scope in canary.scopes}
    unexercised = sorted(cls.__name__ for cls in _concrete_scope_subclasses() - used)
    assert not unexercised, f"Scope subclasses defined but exercised by no canary (use or remove them): {unexercised}"
