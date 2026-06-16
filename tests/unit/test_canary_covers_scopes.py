"""Anti-drift guarantee: every scope-producing ``_discover_*`` method has a canary Scope (and vice-versa).

Adding a discovery scope without its canary fails HERE, in the same repo/PR as the discoverer — so the
canary cannot fall behind the discoverers. Scope methods are identified by their RETURN TYPE
(``McpConfigsResult`` / ``SkillsDirsResult``) among the methods defined directly on the discoverer class,
so helpers (``_discover_*_folders`` returning ``list[Path]``, inherited base helpers) are excluded without
matching method-name patterns.
"""

from __future__ import annotations

import typing

import pytest

from agent_scan.agents import DISCOVERERS
from agent_scan.agents.base import McpConfigsResult, SkillsDirsResult
from agent_scan.canary import CANARIES

_SCOPE_RETURNS = {McpConfigsResult, SkillsDirsResult}
_CANARIES = list(CANARIES.values())


def _scope_methods(discoverer_cls) -> set:
    """The scope-producing ``_discover_*`` methods defined directly on *discoverer_cls* (by return type).

    Annotations are resolved via ``typing.get_type_hints`` rather than read raw from ``__annotations__``,
    so the check survives ``from __future__ import annotations`` (PEP 563) in a discoverer module — which
    would otherwise stringize every return annotation and silently make all scope methods invisible here.
    """
    return {
        fn
        for name, fn in vars(discoverer_cls).items()
        if name.startswith("_discover_") and callable(fn) and typing.get_type_hints(fn).get("return") in _SCOPE_RETURNS
    }


@pytest.mark.parametrize("canary", _CANARIES, ids=lambda c: c.name)
def test_canary_covers_every_scope_method(canary):
    methods = _scope_methods(canary.discoverer)
    covered = {fn for scope in canary.scopes for fn in scope.mirrors}

    uncovered = sorted(fn.__name__ for fn in methods - covered)
    assert not uncovered, f"{canary.name}: scope-methods with no canary Scope/Gap: {uncovered}"

    stale = sorted(fn.__name__ for fn in covered - methods)
    assert not stale, f"{canary.name}: canary mirrors methods that aren't scope-producers: {stale}"


@pytest.mark.parametrize("canary", _CANARIES, ids=lambda c: c.name)
def test_canary_is_registered_to_its_discoverer(canary):
    assert canary.name in DISCOVERERS
    assert canary.discoverer is DISCOVERERS[canary.name]


def test_claude_code_canary_has_a_scope_for_all_twelve_methods():
    # Concrete lock for the one canary that exists today: claude code has 12 scope-producing methods.
    from agent_scan.agents.claude_code import ClaudeCodeDiscoverer

    assert len(_scope_methods(ClaudeCodeDiscoverer)) == 12
