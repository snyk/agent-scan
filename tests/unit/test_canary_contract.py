"""Executor-interface contract: every ``Scope`` subclass emits well-formed ``SeedCommand``s and
``FixtureFile``s.

The backoffice executor (agent-scan-backoffice ``canary.run_canary``) is a *generic interpreter* with two
primitives: it calls ``scope.commands(ctx)`` and runs each :class:`~canary_test_supported_agents.base.SeedCommand` as
a subprocess (reading ``argv`` / ``run_in_project`` / ``timeout`` / ``non_fatal``), and it calls
``scope.files()`` and copies each :class:`~canary_test_supported_agents.base.FixtureFile` into the project (reading
``src`` / ``dest``). This test pins that contract from the agent-scan side — every concrete
:class:`~canary_test_supported_agents.base.Scope` subclass must be exercised by a real canary and must emit commands
the executor can run (non-empty string ``argv``, sane flags, positive ``timeout``) and fixtures the executor
can copy (non-empty *relative* ``src``/``dest``, no ``..`` escape). A new Scope subclass that returns
malformed commands/files — or that no canary uses — fails HERE, before the executor ever sees it. Companion
guard on the executor side: agent-scan-backoffice ``tests/unit/test_canary_dispatch.py``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from canary_test_supported_agents import CANARIES, CanaryContext, FixtureFile, Scope, SeedCommand

# A purely synthetic context: no path is touched and no command is run — commands() is pure.
CTX = CanaryContext(home=Path("/canary/home"), project=Path("/canary/home/proj"), bin="claude")

_CANARIES = list(CANARIES.values())


def _concrete_scope_subclasses() -> set[type[Scope]]:
    """Every loaded concrete subclass of ``Scope`` (importing ``canary_test_supported_agents`` registers them all)."""
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


def _assert_file_well_formed(f: object, where: str) -> None:
    """A FixtureFile the executor can resolve under the package and copy into the project safely."""
    assert isinstance(f, FixtureFile), f"{where}: expected FixtureFile, got {type(f).__name__}"
    for field in ("src", "dest"):
        val = getattr(f, field)
        assert isinstance(val, str) and val, f"{where}: {field} must be a non-empty string, got {val!r}"
        assert not os.path.isabs(val), f"{where}: {field} must be relative, got absolute {val!r}"
        assert ".." not in val.split("/"), f"{where}: {field} must not escape with '..': {val!r}"


@pytest.mark.parametrize("canary", _CANARIES, ids=lambda c: c.name)
def test_every_scope_emits_well_formed_seed_commands(canary):
    scopes = canary.scopes
    assert isinstance(scopes, list) and scopes, f"{canary.name}: .scopes must be a non-empty list"
    for scope in scopes:
        cmds = scope.commands(CTX)
        assert isinstance(cmds, list), f"{canary.name} [{scope.label}]: .commands() must return a list"
        for i, cmd in enumerate(cmds):
            _assert_well_formed(cmd, f"{canary.name} [{scope.label}] cmd#{i}")


@pytest.mark.parametrize("canary", _CANARIES, ids=lambda c: c.name)
def test_every_scope_emits_well_formed_fixture_files(canary):
    for scope in canary.scopes:
        fixtures = scope.files()
        assert isinstance(fixtures, list), f"{canary.name} [{scope.label}]: .files() must return a list"
        for i, f in enumerate(fixtures):
            _assert_file_well_formed(f, f"{canary.name} [{scope.label}] file#{i}")


def test_every_concrete_scope_subclass_is_exercised_by_a_canary():
    # The well-formedness checks above only bite subclasses some canary actually instantiates. Pin that
    # EVERY concrete Scope subclass is used by a real canary, so a newly-added subclass can't dodge the
    # contract by simply never appearing in CANARIES (and so the executor never meets an untested shape).
    used = {type(scope) for canary in _CANARIES for scope in canary.scopes}
    unexercised = sorted(cls.__name__ for cls in _concrete_scope_subclasses() - used)
    assert not unexercised, f"Scope subclasses defined but exercised by no canary (use or remove them): {unexercised}"
