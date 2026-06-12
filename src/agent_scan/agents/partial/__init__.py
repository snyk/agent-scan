"""Discoverers for ``partial`` agents -- simple, statically-known config layouts.

Each such agent gets its own registered discoverer sharing :class:`PartialDiscoverer`,
which turns a few declared path tuples into the standard discovery outputs.
"""

from agent_scan.agents.partial.amazon_q import AmazonQDiscoverer
from agent_scan.agents.partial.amp import AmpDiscoverer
from agent_scan.agents.partial.base import PartialDiscoverer
from agent_scan.agents.partial.gemini_cli import GeminiCliDiscoverer
from agent_scan.agents.partial.openclaw import OpenclawDiscoverer
from agent_scan.agents.partial.opencode import OpencodeDiscoverer

__all__ = [
    "AmazonQDiscoverer",
    "AmpDiscoverer",
    "GeminiCliDiscoverer",
    "OpenclawDiscoverer",
    "OpencodeDiscoverer",
    "PartialDiscoverer",
]
