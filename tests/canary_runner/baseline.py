"""Diff a live inventory against the expected detection set.

The expected set is the canary's own ``canary.expected()`` (``agent_scan.canary.ExpectedItem`` objects).
A *missing* expected item means agent-scan stopped detecting a scope it used to (the primary drift
signal). An *extra* item (something detected the canary doesn't expect) is informational — agent-scan
may have gained detection.

:func:`compare` reads only the ``kind`` / ``name`` / ``scope`` / ``path_contains`` attributes of each
expected item, so it stays decoupled from the concrete spec type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_scan.canary import ExpectedItem

    from .normalize import InventoryItem


@dataclass
class ComparisonResult:
    matched: list[ExpectedItem] = field(default_factory=list)
    missing: list[ExpectedItem] = field(default_factory=list)
    extras: list[InventoryItem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        # A *missing* item is the drift regression we must fail on. *Extras* mean agent-scan gained
        # detection (a new release) — informational, surfaced in the report but not a failure.
        return not self.missing


def _matches(expected: ExpectedItem, item: InventoryItem) -> bool:
    if item.kind != expected.kind or item.name != expected.name:
        return False
    return all(item.path and needle in item.path for needle in expected.path_contains)


def compare(expected: list[ExpectedItem], inventory: list[InventoryItem]) -> ComparisonResult:
    result = ComparisonResult()
    for exp in expected:
        if any(_matches(exp, item) for item in inventory):
            result.matched.append(exp)
        else:
            result.missing.append(exp)
    expected_names = {(e.kind, e.name) for e in expected}
    result.extras = [item for item in inventory if (item.kind, item.name) not in expected_names]
    return result


def format_report(result: ComparisonResult) -> str:
    total = len(result.matched) + len(result.missing)
    lines: list[str] = []
    if result.missing:
        lines.append(
            f"FAIL — {len(result.missing)} of {total} expected items missing ({len(result.matched)} detected)."
        )
    else:
        lines.append(f"PASS — all {len(result.matched)} expected items detected.")
    for m in result.missing:
        lines.append(f"  MISSING [{m.scope}] {m.kind}:{m.name}")
    if result.extras:
        lines.append(
            f"  note: {len(result.extras)} unexpected item(s) detected — informational; "
            "agent-scan may have gained detection:"
        )
        for e in result.extras:
            suffix = f" ({e.path})" if e.path else ""
            lines.append(f"    EXTRA {e.kind}:{e.name}{suffix}")
    return "\n".join(lines)
