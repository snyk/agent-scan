"""Shared hook-management primitives for Agent Guard.

Hook event lists, hook-object builders, hook-command construction, and bundled-script copy/remove
helpers used by BOTH the install command (:mod:`agent_scan.guard`) and the ``guard run`` launcher
(:mod:`agent_scan.guard_launch`). This is a dependency-free leaf module (nothing here imports
``guard`` or ``guard_launch``) so both can import it without forming an import cycle.
"""

from __future__ import annotations

import stat
import sys
from importlib import resources as importlib_resources
from pathlib import Path

import rich

from agent_scan.version import version_info

IS_WINDOWS = sys.platform == "win32"

DEFAULT_REMOTE_URL = "https://api.snyk.io"

CLAUDE_HOOK_EVENTS = [
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "UserPromptSubmit",
    "Stop",
    "SessionStart",
    "SessionEnd",
    "SubagentStart",
    "SubagentStop",
]
CLAUDE_EVENTS_WITH_MATCHER = {"PreToolUse", "PostToolUse", "PostToolUseFailure"}

CODEX_HOOK_EVENTS = [
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "UserPromptSubmit",
    "Stop",
    "SessionStart",
]

CURSOR_HOOK_EVENTS = [
    "beforeSubmitPrompt",
    "beforeShellExecution",
    "afterShellExecution",
    "beforeMCPExecution",
    "afterMCPExecution",
    "beforeReadFile",
    "afterFileEdit",
    "afterAgentResponse",
    "afterAgentThought",
    "stop",
    "preToolUse",
    "postToolUse",
    "postToolUseFailure",
    "sessionStart",
    "sessionEnd",
    "subagentStart",
    "subagentStop",
]

_HOOK_CLIENT_NAMES = {"claude": "claude-code", "cursor": "cursor", "codex": "codex"}


def _hook_client_name(client: str) -> str:
    """Endpoint slug used on the agent-monitor side (and --client in the hook script)."""
    return _HOOK_CLIENT_NAMES.get(client, client)


def build_claude_hooks(command: str) -> dict:
    """Build the Claude ``hooks`` object for a single command (no existing-config merge)."""
    hooks: dict = {}
    for event in CLAUDE_HOOK_EVENTS:
        entry = {"type": "command", "command": command}
        if IS_WINDOWS:
            entry["shell"] = "powershell"
        group: dict = {"hooks": [entry]}
        if event in CLAUDE_EVENTS_WITH_MATCHER:
            group["matcher"] = "*"
        hooks[event] = [group]
    return hooks


def build_codex_hooks(command: str) -> dict:
    """Build the Codex ``hooks`` object for a single command."""
    return {event: [{"hooks": [{"type": "command", "command": command}]}] for event in CODEX_HOOK_EVENTS}


def build_cursor_hooks(command: str) -> dict:
    """Build the Cursor ``hooks`` object for a single command."""
    return {event: [{"command": command}] for event in CURSOR_HOOK_EVENTS}


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _build_hook_command(push_key: str, url: str, script_path: Path, hook_client: str, *, tenant_id: str = "") -> str:
    if IS_WINDOWS:
        return _build_hook_command_powershell(push_key, url, script_path, hook_client, tenant_id=tenant_id)
    parts = [
        f"PUSH_KEY={_shell_quote(push_key)}",
        f"REMOTE_HOOKS_BASE_URL={_shell_quote(url)}",
    ]
    if tenant_id:
        parts.append(f"TENANT_ID={_shell_quote(tenant_id)}")
    parts.append(f"bash {_shell_quote(script_path.as_posix())}")
    parts.append(f"--client {hook_client}")
    return " ".join(parts)


def _build_hook_command_powershell(
    push_key: str, url: str, script_path: Path, hook_client: str, *, tenant_id: str = ""
) -> str:
    return f"powershell -File '{script_path}' -Client {hook_client} -PushKey '{push_key}' -RemoteUrl '{url}'"


def _copy_hook_script(client: str, config_path: Path) -> tuple[Path, bool, bool]:
    """Copy bundled hook script to a hooks/ dir next to the config file.

    Returns (path, already_existed, was_updated).
    """
    dest_dir = config_path.parent / "hooks"

    dest_dir.mkdir(parents=True, exist_ok=True)
    script_name = "snyk-agent-guard.ps1" if IS_WINDOWS else "snyk-agent-guard.sh"
    dest = dest_dir / script_name
    existed = dest.exists()

    hook_pkg = importlib_resources.files("agent_scan.hooks")
    source = hook_pkg.joinpath(script_name)
    new_content = source.read_bytes().replace(b"__AGENT_SCAN_VERSION__", version_info.encode())

    if existed and dest.read_bytes() == new_content:
        return dest, existed, False

    dest.write_bytes(new_content)
    dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    rich.print(f"[green]✓[/green]  Copied hook script to [dim]{dest}[/dim]")
    return dest, existed, True


def _remove_hook_script(client: str, config_path: Path) -> None:
    dest_dir = config_path.parent / "hooks"
    script_name = "snyk-agent-guard.ps1" if IS_WINDOWS else "snyk-agent-guard.sh"
    dest = dest_dir / script_name
    if dest.exists():
        dest.unlink()
        rich.print(f"[green]✓[/green]  Removed hook script [dim]{dest}[/dim]")
