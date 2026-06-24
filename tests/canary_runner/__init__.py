"""Generic canary executor (test/CI tooling), co-located with the ``agent_scan.canary`` specs.

Imported by agent-scan's own tests and by the agent-scan-backoffice canary (which clones this repo and
runs with ``PYTHONPATH=<clone>/tests``). See :mod:`canary_runner.runner`.
"""

from .baseline import ComparisonResult, compare, format_report
from .normalize import InventoryItem, build_inventory
from .runner import (
    CANARY_AGENT_SCAN_NAME,
    SUPPORTED_AGENTS,
    SeedError,
    evaluate,
    resolve_agent_bin,
    resolve_scan_cmd,
    run_agent,
    run_scan,
)

__all__ = [
    "CANARY_AGENT_SCAN_NAME",
    "SUPPORTED_AGENTS",
    "ComparisonResult",
    "InventoryItem",
    "SeedError",
    "build_inventory",
    "compare",
    "evaluate",
    "format_report",
    "resolve_agent_bin",
    "resolve_scan_cmd",
    "run_agent",
    "run_scan",
]
