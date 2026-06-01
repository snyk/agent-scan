"""VSCode-family discoverers (VSCode, Cursor, Windsurf, Kiro, Antigravity)."""

from agent_scan.agents.vscode.antigravity import AntigravityDiscoverer
from agent_scan.agents.vscode.base import VSCodeFamilyDiscoverer
from agent_scan.agents.vscode.cursor import CursorDiscoverer
from agent_scan.agents.vscode.kiro import KiroDiscoverer
from agent_scan.agents.vscode.vscode import VSCodeDiscoverer
from agent_scan.agents.vscode.windsurf import WindsurfDiscoverer

__all__ = [
    "AntigravityDiscoverer",
    "CursorDiscoverer",
    "KiroDiscoverer",
    "VSCodeDiscoverer",
    "VSCodeFamilyDiscoverer",
    "WindsurfDiscoverer",
]
