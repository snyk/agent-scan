"""Per-agent discoverers.

Public API: the ``AgentDiscoverer`` abstract base, the concrete discoverers, the
``DISCOVERERS`` registry (agent name -> discoverer class), and
``find_discoverers`` (construct + filter to installed agents for one home).
"""

import logging
from pathlib import Path

from agent_scan.agents.base import AgentDiscoverer
from agent_scan.agents.claude_code import ClaudeCodeDiscoverer
from agent_scan.agents.claude_desktop import ClaudeDesktopDiscoverer
from agent_scan.agents.codex import CodexDiscoverer
from agent_scan.agents.vscode import (
    AntigravityDiscoverer,
    CursorDiscoverer,
    KiroDiscoverer,
    VSCodeDiscoverer,
    VSCodeFamilyDiscoverer,
    WindsurfDiscoverer,
)

logger = logging.getLogger(__name__)

DISCOVERERS: dict[str, type[AgentDiscoverer]] = {
    ClaudeCodeDiscoverer.name: ClaudeCodeDiscoverer,
    ClaudeDesktopDiscoverer.name: ClaudeDesktopDiscoverer,
    VSCodeDiscoverer.name: VSCodeDiscoverer,
    CursorDiscoverer.name: CursorDiscoverer,
    WindsurfDiscoverer.name: WindsurfDiscoverer,
    KiroDiscoverer.name: KiroDiscoverer,
    AntigravityDiscoverer.name: AntigravityDiscoverer,
    CodexDiscoverer.name: CodexDiscoverer,
}


def find_discoverers(home_directory: Path | None) -> list[AgentDiscoverer]:
    """Construct one instance per registered discoverer with the given home, and
    return only those whose ``client_exists()`` confirms the agent is installed.
    Each returned instance is home-bound; the caller just runs
    ``d.discover()`` on each.

    A discoverer whose ``client_exists()`` raises is skipped (and logged) so a
    single buggy subclass cannot abort discovery for the whole machine.
    """
    found: list[AgentDiscoverer] = []
    for cls in DISCOVERERS.values():
        discoverer = cls(home_directory)
        try:
            exists = discoverer.client_exists() is not None
        except Exception:
            logger.exception("Discoverer %s.client_exists() raised; skipping", cls.__name__)
            continue
        if exists:
            found.append(discoverer)
    return found


__all__ = [
    "DISCOVERERS",
    "AgentDiscoverer",
    "AntigravityDiscoverer",
    "ClaudeCodeDiscoverer",
    "ClaudeDesktopDiscoverer",
    "CodexDiscoverer",
    "CursorDiscoverer",
    "KiroDiscoverer",
    "VSCodeDiscoverer",
    "VSCodeFamilyDiscoverer",
    "WindsurfDiscoverer",
    "find_discoverers",
]
