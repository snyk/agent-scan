"""Anti-drift guarantee: every scope-producing ``_discover_*`` method has a canary Scope (and vice-versa).

Adding a discovery scope without its canary fails HERE, in the same repo/PR as the discoverer — so the
canary cannot fall behind the discoverers. Scope methods are identified by their RETURN TYPE
(``McpConfigsResult`` / ``SkillsDirsResult``) among the ``_discover_*`` methods reachable on the discoverer
(its own and any intermediate base's, but not ``AgentDiscoverer``'s), so helpers (``_discover_*_folders``
returning ``list[Path]`` and ``AgentDiscoverer``'s base helpers) are excluded without matching method-name
patterns.
"""

from __future__ import annotations

import typing
import warnings

import pytest
from canary_test_supported_agents import CANARIES

from agent_scan.agents import DISCOVERERS
from agent_scan.agents.base import McpConfigsResult, SkillsDirsResult

_SCOPE_RETURNS = {McpConfigsResult, SkillsDirsResult}
_CANARIES = list(CANARIES.values())


def _scope_methods(discoverer_cls) -> set:
    """The scope-producing ``_discover_*`` methods reachable from *discoverer_cls* (by return type).

    Walks the MRO from the most-derived class up to (but not including) ``AgentDiscoverer``,
    so scope methods inherited from an intermediate base are included rather than making the
    coverage check vacuously pass for subclasses.

    Annotations are resolved via ``typing.get_type_hints`` rather than read raw from ``__annotations__``,
    so the check survives ``from __future__ import annotations`` (PEP 563) in a discoverer module — which
    would otherwise stringize every return annotation and silently make all scope methods invisible here.
    Resolution is defensive: a method whose hints can't be resolved (e.g. a future ``_discover_*`` with a
    ``TYPE_CHECKING``-only annotation) is skipped with a loud warning rather than crashing collection —
    silently dropping it would let a real scope method evade coverage (see ``_return_type``).
    """
    from agent_scan.agents.base import AgentDiscoverer

    intermediate = [c for c in type.mro(discoverer_cls) if c not in (AgentDiscoverer, object)]
    candidate_names = {name for cls in intermediate for name in vars(cls) if name.startswith("_discover_")}

    def _return_type(fn):
        try:
            return typing.get_type_hints(fn).get("return")
        except Exception as exc:
            # Don't crash on an unresolvable annotation — but warn, because skipping a method silently
            # could hide a genuine scope method (its canary coverage would then go unenforced).
            warnings.warn(
                f"_scope_methods: could not resolve type hints for {fn.__qualname__} ({exc!r}); "
                "treating it as a non-scope method. If it IS a scope method, annotate its return type so "
                "it resolves at runtime, or its canary coverage will not be enforced.",
                stacklevel=2,
            )
            return None

    return {
        fn
        for name in candidate_names
        if callable(fn := getattr(discoverer_cls, name)) and _return_type(fn) in _SCOPE_RETURNS
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


def test_claude_code_canary_has_a_scope_for_all_nine_methods():
    # Concrete lock for the one canary that exists today: claude code has 9 scope-producing methods.
    from agent_scan.agents.claude_code import ClaudeCodeDiscoverer

    assert len(_scope_methods(ClaudeCodeDiscoverer)) == 9
