"""Per-agent discoverers.

Public API: the ``AgentDiscoverer`` abstract base, the concrete discoverers, the
``DISCOVERERS`` registry (agent name -> discoverer class), and
``find_discoverers`` (construct + filter to installed agents for one home).
"""

import logging
import os
from pathlib import Path

from agent_scan.agents.base import AgentDiscoverer
from agent_scan.agents.claude_code import ClaudeCodeDiscoverer
from agent_scan.agents.claude_desktop import ClaudeDesktopDiscoverer
from agent_scan.agents.codex import CodexDiscoverer
from agent_scan.agents.partial import (
    AmazonQDiscoverer,
    AmpDiscoverer,
    GeminiCliDiscoverer,
    OpenclawDiscoverer,
    OpencodeDiscoverer,
    PartialDiscoverer,
)
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
    # Dedicated discoverers: agents with rich, multi-scope layouts.
    ClaudeCodeDiscoverer.name: ClaudeCodeDiscoverer,
    ClaudeDesktopDiscoverer.name: ClaudeDesktopDiscoverer,
    VSCodeDiscoverer.name: VSCodeDiscoverer,
    CursorDiscoverer.name: CursorDiscoverer,
    WindsurfDiscoverer.name: WindsurfDiscoverer,
    KiroDiscoverer.name: KiroDiscoverer,
    AntigravityDiscoverer.name: AntigravityDiscoverer,
    CodexDiscoverer.name: CodexDiscoverer,
    # Partial discoverers: simple static-path agents (see agents/partial/).
    GeminiCliDiscoverer.name: GeminiCliDiscoverer,
    AmpDiscoverer.name: AmpDiscoverer,
    OpencodeDiscoverer.name: OpencodeDiscoverer,
    OpenclawDiscoverer.name: OpenclawDiscoverer,
    AmazonQDiscoverer.name: AmazonQDiscoverer,
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


def get_client_from_path(path: str) -> str | None:
    """Best-effort: name the agent that owns the MCP config file at ``path``.

    Matches the realpath of ``path`` against each registered discoverer's
    documented static MCP config files (``static_mcp_config_paths``, expanded
    against the scanning user's own home). Returns the owning agent ``name`` on a
    match, else ``None``.

    Used to label explicitly-scanned paths (``--paths`` mode); discovery-mode
    results already carry the agent name, so callers fall back to that. The
    discoverer registry is the single source of truth for this mapping.
    """
    target = os.path.realpath(os.path.expanduser(path))
    for cls in DISCOVERERS.values():
        try:
            known = cls(None).static_mcp_config_paths()
        except Exception:
            logger.exception("static_mcp_config_paths for %s raised; skipping", cls.__name__)
            continue
        for candidate in known:
            if os.path.realpath(os.path.expanduser(candidate)) == target:
                return cls.name
    return None


__all__ = [
    "DISCOVERERS",
    "AgentDiscoverer",
    "AmazonQDiscoverer",
    "AmpDiscoverer",
    "AntigravityDiscoverer",
    "ClaudeCodeDiscoverer",
    "ClaudeDesktopDiscoverer",
    "CodexDiscoverer",
    "CursorDiscoverer",
    "GeminiCliDiscoverer",
    "KiroDiscoverer",
    "OpenclawDiscoverer",
    "OpencodeDiscoverer",
    "PartialDiscoverer",
    "VSCodeDiscoverer",
    "VSCodeFamilyDiscoverer",
    "WindsurfDiscoverer",
    "find_discoverers",
    "get_client_from_path",
]
