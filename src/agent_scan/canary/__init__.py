"""Live-test ("canary") specs, co-located with the discoverers in the ``agent_scan`` package.

For each ``AgentDiscoverer`` there is an :class:`~agent_scan.canary.base.AgentCanary` that declares one
:class:`~agent_scan.canary.base.Scope` per scope-producing ``_discover_*`` method — how to drive the real
agent binary to write that scope and what ``inspect`` must then detect. The specs are declarative and
runner-agnostic; an external executor (the agent-scan-backoffice canary) imports :data:`CANARIES` and
runs the commands against the real binary in an isolated home.

This is a real importable subpackage (``agent_scan.canary``), shipped with the wheel, so both
agent-scan's own tests and the backoffice executor import it by name — ``from agent_scan.canary import
CANARIES`` — sharing the same dataclasses (no PYTHONPATH gymnastics, no duck-typed re-declaration). The
committed fixtures live alongside as package data under ``fixtures/``. The module is import-light
(dataclasses + discoverer-method references) and is never imported on a normal product scan. Because
the canary lives in the same repo as the discoverers it cannot drift from them —
``tests/unit/test_canary_covers_scopes.py`` enforces that every scope-producing method has a canary scope.
"""

from .base import (
    AgentCanary,
    CanaryContext,
    CommandScope,
    ExpectedItem,
    FixtureFile,
    FixtureScope,
    Gap,
    LifecycleStep,
    McpScope,
    PluginScope,
    Scope,
    SeedCommand,
)
from .claude_code import ClaudeCodeCanary
from .vscode_family import (
    AntigravityCanary,
    CursorCanary,
    KiroCanary,
    VSCodeCanary,
    WindsurfCanary,
)

# Registry of the available canaries, keyed by the discoverer name (matches agents.DISCOVERERS keys).
# Only discoverers with a built canary appear here; the others are added as their canaries land.
CANARIES: dict[str, AgentCanary] = {
    c.name: c
    for c in (
        ClaudeCodeCanary(),
        VSCodeCanary(),
        CursorCanary(),
        KiroCanary(),
        WindsurfCanary(),
        AntigravityCanary(),
    )
}

__all__ = [
    "CANARIES",
    "AgentCanary",
    "AntigravityCanary",
    "CanaryContext",
    "ClaudeCodeCanary",
    "CommandScope",
    "CursorCanary",
    "ExpectedItem",
    "FixtureFile",
    "FixtureScope",
    "Gap",
    "KiroCanary",
    "LifecycleStep",
    "McpScope",
    "PluginScope",
    "Scope",
    "SeedCommand",
    "VSCodeCanary",
    "WindsurfCanary",
]
