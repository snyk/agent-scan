"""Live-test ("canary") specs, co-located with the discoverers under ``tests/``.

For each ``AgentDiscoverer`` there is an :class:`~canary_test_supported_agents.base.AgentCanary` that declares one
:class:`~canary_test_supported_agents.base.Scope` per scope-producing ``_discover_*`` method — how to drive the real
agent binary to write that scope and what ``inspect`` must then detect. The specs are declarative and
runner-agnostic; an external executor (the agent-scan-backoffice canary) imports :data:`CANARIES` and
runs the commands against the real binary in an isolated home.

These specs are test support, not part of the shipped ``agent_scan`` package: they live under
``tests/canary_specs/canary_test_supported_agents`` (not in the wheel). agent-scan's own tests import
them via ``pythonpath = ["tests/canary_specs"]``; the backoffice executor clones this repo and imports
them from the source tree with ``PYTHONPATH=<clone>/tests/canary_specs``. Because the canary still lives
in the same repo as the discoverers, it cannot drift from them — ``tests/unit/test_canary_covers_scopes.py``
enforces that every scope-producing method has a canary scope.
"""

from .base import (
    AgentCanary,
    CanaryContext,
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

# Registry of the available canaries, keyed by the discoverer name (matches agents.DISCOVERERS keys).
# Only discoverers with a built canary appear here; the others are added as their canaries land.
CANARIES: dict[str, AgentCanary] = {c.name: c for c in (ClaudeCodeCanary(),)}

__all__ = [
    "CANARIES",
    "AgentCanary",
    "CanaryContext",
    "ClaudeCodeCanary",
    "ExpectedItem",
    "FixtureFile",
    "FixtureScope",
    "Gap",
    "LifecycleStep",
    "McpScope",
    "PluginScope",
    "Scope",
    "SeedCommand",
]
