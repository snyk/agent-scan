"""Agent Guard hook management for Claude Code and Cursor."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
from importlib import resources as importlib_resources
from pathlib import Path
from urllib.parse import urlparse

import rich

from agent_scan.pushkeys import (
    GuardEnabledAccessDeniedError,
    _is_localhost,
    fetch_guard_enabled,
    mint_push_key,
    revoke_push_key,
)

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_REMOTE_URL = "https://api.snyk.io"
DETECTION_MARKER = "snyk-agent-guard"
_PERMISSION_DENIED = "__permission_denied__"

CLAUDE_SETTINGS_PATH = Path.home() / ".claude" / "settings.json"
CURSOR_HOOKS_PATH = Path.home() / ".cursor" / "hooks.json"

# Managed (MDM / admin-deployed) config paths — OS-specific
if sys.platform == "darwin":
    CLAUDE_MANAGED_SETTINGS_PATH = Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    CURSOR_MANAGED_HOOKS_PATH = Path("/Library/Application Support/Cursor/hooks.json")
elif sys.platform == "win32":
    CLAUDE_MANAGED_SETTINGS_PATH = Path("C:/Program Files/ClaudeCode/managed-settings.json")
    CURSOR_MANAGED_HOOKS_PATH = Path("C:/ProgramData/Cursor/hooks.json")
else:  # Linux and others
    CLAUDE_MANAGED_SETTINGS_PATH = Path("/etc/claude-code/managed-settings.json")
    CURSOR_MANAGED_HOOKS_PATH = Path("/etc/cursor/hooks.json")

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

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_guard(args) -> int:
    try:
        guard_command = getattr(args, "guard_command", None)
        if guard_command == "install":
            _run_install(args)
        elif guard_command == "uninstall":
            _run_uninstall(args)
        else:
            _run_status()
        return 0
    except json.JSONDecodeError as e:
        rich.print(f"[bold red]Error:[/bold red] Invalid JSON in config file: {e}")
        return 1
    except PermissionError as e:
        rich.print(f"[bold red]Error:[/bold red] Permission denied: {e}")
        return 1


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------


def _get_machine_description(client: str) -> str:
    from agent_scan.upload import get_hostname

    hostname = get_hostname()
    label = _client_label(client)
    return f"agent-guard ({hostname}) {label}"


def _ensure_guard_enabled_for_tenant(url: str, tenant_id: str, snyk_token: str) -> None:
    """Exit with a clear message if agent-monitor reports Agent Guard is off for the tenant."""
    if not tenant_id:
        return
    if not _is_localhost(url) and not (snyk_token or "").strip():
        rich.print(
            "[bold red]Error:[/bold red] SNYK_TOKEN is required to verify that Agent Guard is enabled "
            "for your tenant. Set SNYK_TOKEN and retry, or omit TENANT_ID / --tenant-id if you are only "
            "testing against a local server."
        )
        sys.exit(1)
    rich.print("[dim]Checking whether Agent Guard is enabled for your tenant...[/dim]")
    try:
        enabled = fetch_guard_enabled(url, tenant_id, snyk_token)
    except GuardEnabledAccessDeniedError:
        rich.print()
        rich.print(
            "[bold red]Access denied:[/bold red] your Snyk account is not eligible to use the "
            f"tenant [bold]{tenant_id}[/bold]."
        )
        rich.print()
        sys.exit(1)
    except RuntimeError as e:
        rich.print(f"[bold red]Error:[/bold red] Could not verify Agent Guard status for your tenant: {e}")
        rich.print(
            "[yellow]Ensure --url points to the Snyk API for your environment (for example "
            "[bold]https://api.snyk.io[/bold] for Snyk US 1), that "
            "your token has access to this tenant, and that network access is allowed.[/yellow]"
        )
        sys.exit(1)
    if not enabled:
        rich.print()
        rich.print("[bold red]Agent Guard is not enabled for this Snyk tenant.[/bold red]")
        rich.print()
        rich.print("Please reach out to your Snyk administrators if you believe this is a mistake.")
        rich.print()
        sys.exit(1)


def _run_install(args) -> None:
    client: str = args.client
    url: str = args.url
    push_key = os.environ.get("PUSH_KEY", "")
    headless = bool(push_key)
    tenant_id: str = (getattr(args, "tenant_id", None) or "").strip()
    if not tenant_id:
        tenant_id = (os.environ.get("TENANT_ID", "") or "").strip()
    managed: bool = getattr(args, "managed", False)

    label = _client_label(client)
    scope = "managed" if managed else "user"
    snyk_token = ""

    if not headless:
        # Interactive flow — mint a push key
        rich.print(f"Installing [bold magenta]Agent Guard[/bold magenta] {scope} hooks for [bold]{label}[/bold]")
        rich.print()

        snyk_token = os.environ.get("SNYK_TOKEN", "")
        if not snyk_token:
            rich.print("Paste your Snyk API token ( from https://app.snyk.io/account ):")
            snyk_token = input().strip()
        if not snyk_token:
            rich.print("[bold red]Error:[/bold red] SNYK_TOKEN is required to mint a push key.")
            sys.exit(1)

        if not tenant_id:
            rich.print("Enter your Snyk Tenant ID ( from the URL at https://app.snyk.io ):")
            tenant_id = input().strip()
        if not tenant_id:
            rich.print("[bold red]Error:[/bold red] Tenant ID is required to mint a push key.")
            sys.exit(1)

        _ensure_guard_enabled_for_tenant(url, tenant_id, snyk_token)

        # Preflight: verify target directory is writable before minting
        config_path = _config_path(client, getattr(args, "file", None), managed=managed)
        _preflight_writable(config_path)

        description = _get_machine_description(client)
        rich.print(f"[dim]Minting push key for {description}...[/dim]")
        try:
            push_key = mint_push_key(url, tenant_id, snyk_token, description=description)
        except RuntimeError as e:
            rich.print(f"[bold red]Error:[/bold red] {e}")
            if "403" in str(e):
                rich.print(
                    f"[yellow]Please ensure you have access to tenant [bold]{tenant_id}[/bold] and access to Evo Agent Guard.[/yellow]"
                )
            sys.exit(1)
        rich.print(f"[green]\u2713[/green]  Push key minted  [yellow]{_mask_key(push_key)}[/yellow]")

    hook_client = "claude-code" if client == "claude" else "cursor"
    minted = not headless  # True if we minted the key in this run
    config_path = _config_path(client, getattr(args, "file", None), managed=managed)

    try:
        _install_hooks(
            args, client, hook_client, push_key, url, config_path, scope, label, minted, tenant_id, snyk_token
        )
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException:
        if minted:
            _revoke_after_failure(url, tenant_id, snyk_token, push_key)
        raise


def _install_hooks(
    args,
    client: str,
    hook_client: str,
    push_key: str,
    url: str,
    config_path: Path,
    scope: str,
    label: str,
    minted: bool,
    tenant_id: str,
    snyk_token: str,
) -> None:
    """Post-mint install steps.  Extracted so _run_install can revoke on failure."""
    # Copy hook script first so we can use it for the test event
    dest_path, script_existed, script_updated = _copy_hook_script(client, config_path)

    first_install = not config_path.exists() or not script_existed
    run_test = first_install or minted or getattr(args, "test", False)

    # Verify connectivity by invoking the actual hook script
    if run_test and not _send_test_event(push_key, url, hook_client, dest_path):
        # Clean up copied script only if it didn't exist before
        if not script_existed:
            dest_path.unlink(missing_ok=True)
        if minted:
            _revoke_after_failure(url, tenant_id, snyk_token, push_key)
        rich.print("[bold red]Aborting install — test event failed.[/bold red]")
        raise SystemExit(1)

    # Build command string and edit client config
    command = _build_hook_command(push_key, url, dest_path, hook_client, tenant_id=tenant_id)

    if client == "claude":
        config_changed = _install_claude(command, config_path)
    elif client == "cursor":
        config_changed = _install_cursor(command, config_path)

    if script_updated or config_changed or minted:
        rich.print(f"[green]\u2713[/green]  {scope.title()} hooks installed for [bold]{label}[/bold]")
    else:
        rich.print(f"[green]\u2713[/green]  {label} {scope} hook integration up to date")
    rich.print(f"   Config:     [dim]{config_path}[/dim]")
    rich.print(f"   Script:     [dim]{dest_path}[/dim]")
    rich.print(f"   Remote URL: [dim]{url}[/dim]")
    rich.print(f"   Push Key:   [yellow]{_mask_key(push_key)}[/yellow]")
    rich.print()


def _install_claude(command: str, path: Path) -> bool:
    """Install Claude hooks. Returns True if the file was changed."""
    settings = _read_json_or_empty(path)
    hooks = settings.get("hooks", {})

    preserved = _count_non_agent_scan_claude(hooks)
    hooks = _filter_claude_hooks(hooks)

    for event in CLAUDE_HOOK_EVENTS:
        entry = {"type": "command", "command": command}
        if IS_WINDOWS:
            entry["shell"] = "powershell"
        group: dict = {"hooks": [entry]}
        if event in CLAUDE_EVENTS_WITH_MATCHER:
            group["matcher"] = "*"
        existing = hooks.get(event, [])
        existing.append(group)
        hooks[event] = existing

    settings["hooks"] = hooks

    if not _write_json_if_changed(path, settings):
        return False
    note = _preserved_note(preserved)
    rich.print(f"[green]\u2713[/green]  Written [dim]{path}[/dim]{note}")
    return True


def _install_cursor(command: str, path: Path) -> bool:
    """Install Cursor hooks. Returns True if the file was changed."""
    data = _read_json_or_empty(path)
    if "version" not in data:
        data["version"] = 1
    hooks = data.get("hooks", {})

    preserved = _count_non_agent_scan_cursor(hooks)
    hooks = _filter_cursor_hooks(hooks)

    for event in CURSOR_HOOK_EVENTS:
        existing = hooks.get(event, [])
        existing.append({"command": command})
        hooks[event] = existing

    data["hooks"] = hooks

    if not _write_json_if_changed(path, data):
        return False
    note = _preserved_note(preserved)
    rich.print(f"[green]\u2713[/green]  Written [dim]{path}[/dim]{note}")
    return True


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------


def _run_uninstall(args) -> None:
    client: str = args.client
    managed: bool = getattr(args, "managed", False)
    label = _client_label(client)
    scope = "managed" if managed else "user"
    config_path = _config_path(client, getattr(args, "file", None), managed=managed)

    rich.print(f"Removing [bold magenta]Agent Guard[/bold magenta] {scope} hooks from [bold]{label}[/bold]")
    rich.print("[dim]Other hooks in the file will be preserved.[/dim]")
    rich.print()

    # Detect the installed command to extract push key + tenant for revocation
    info = _detect_claude_install(config_path) if client == "claude" else _detect_cursor_install(config_path)

    # Remove hooks from config
    if client == "claude":
        _uninstall_claude(config_path)
    elif client == "cursor":
        _uninstall_cursor(config_path)

    # Remove hook script
    _remove_hook_script(client, config_path)

    # Try to revoke the push key
    if info and info.get("auth_value"):
        _try_revoke_push_key(info, label)

    rich.print()


def _try_revoke_push_key(info: dict, label: str) -> None:
    push_key = info.get("auth_value", "")
    tenant_id = info.get("tenant_id", "")
    url = info.get("url", DEFAULT_REMOTE_URL)
    snyk_token = os.environ.get("SNYK_TOKEN", "")

    if not tenant_id or not snyk_token:
        rich.print(
            f"[dim]   Push key {_mask_key(push_key)} was not revoked (set SNYK_TOKEN to revoke on uninstall).[/dim]"
        )
        return

    try:
        revoke_push_key(url, tenant_id, snyk_token, push_key)
        rich.print(f"[green]\u2713[/green]  Push key {_mask_key(push_key)} revoked")
    except RuntimeError as e:
        rich.print(f"[yellow]Warning:[/yellow] Could not revoke push key: {e}")


def _uninstall_claude(path: Path) -> None:
    if not path.exists():
        rich.print("[dim]No settings.json found. Nothing to uninstall.[/dim]")
        return

    settings = _read_json_or_empty(path)
    hooks = settings.get("hooks", {})

    total_before = sum(len(groups) for groups in hooks.values())
    filtered = _filter_claude_hooks(hooks)
    total_after = sum(len(groups) for groups in filtered.values())

    removed = total_before - total_after
    if removed == 0:
        rich.print("[dim]No Agent Guard hooks found.[/dim]")
        return

    _backup_file(path)
    if filtered:
        settings["hooks"] = filtered
    else:
        settings.pop("hooks", None)
    _write_json(path, settings)
    rich.print(f"[green]\u2713[/green]  Removed {removed} Agent Guard hook(s){_preserved_note(total_after)}")


def _uninstall_cursor(path: Path) -> None:
    if not path.exists():
        rich.print("[dim]No hooks.json found. Nothing to uninstall.[/dim]")
        return

    data = _read_json_or_empty(path)
    hooks = data.get("hooks", {})

    total_before = sum(len(entries) for entries in hooks.values())
    filtered = _filter_cursor_hooks(hooks)
    total_after = sum(len(entries) for entries in filtered.values())

    removed = total_before - total_after
    if removed == 0:
        rich.print("[dim]No Agent Guard hooks found.[/dim]")
        return

    _backup_file(path)
    data["hooks"] = filtered
    _write_json(path, data)
    rich.print(f"[green]\u2713[/green]  Removed {removed} Agent Guard hook(s){_preserved_note(total_after)}")


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def _run_status() -> None:
    rich.print("[bold]User-level hooks:[/bold]")
    _print_client_status("Claude Code", CLAUDE_SETTINGS_PATH, _detect_claude_install())
    rich.print()
    _print_client_status("Cursor", CURSOR_HOOKS_PATH, _detect_cursor_install())
    rich.print()

    rich.print("[bold]Managed hooks:[/bold]")
    claude_managed_info: dict | str | None
    try:
        claude_managed_info = _detect_claude_install(CLAUDE_MANAGED_SETTINGS_PATH)
    except PermissionError:
        claude_managed_info = _PERMISSION_DENIED
    _print_client_status("Claude Code", CLAUDE_MANAGED_SETTINGS_PATH, claude_managed_info)
    rich.print()
    cursor_managed_info: dict | str | None
    try:
        cursor_managed_info = _detect_cursor_install(CURSOR_MANAGED_HOOKS_PATH)
    except PermissionError:
        cursor_managed_info = _PERMISSION_DENIED
    _print_client_status("Cursor", CURSOR_MANAGED_HOOKS_PATH, cursor_managed_info)
    rich.print()

    rich.print("[dim]# interactive flow (user-level)[/dim]")
    rich.print("[dim]snyk-agent-scan guard install <client>[/dim]")
    rich.print()
    rich.print("[dim]# managed flow[/dim]")
    rich.print("[dim]snyk-agent-scan guard install <client> --managed[/dim]")
    rich.print()
    rich.print("[dim]# headless flow (MDM)[/dim]")
    rich.print("[dim]PUSH_KEY=<YOUR_PUSH_KEY> snyk-agent-scan guard install <client> [--managed][/dim]")
    rich.print()
    rich.print(
        "[dim]If hooks are already installed and up to date, install commands are no-ops. To uninstall use 'snyk-agent-scan guard uninstall <client>'[/dim]"
    )


def _print_client_status(label: str, path: Path, info: dict | str | None) -> None:
    rich.print(f"[bold white]{label}[/bold white]   [dim]{path}[/dim]")
    if isinstance(info, str):
        rich.print("    [yellow]UNREADABLE (permission denied)[/yellow]")
        return
    if info is None:
        rich.print("    [dim]NOT INSTALLED[/dim]")
        return

    auth_label = f"[yellow]\\[Push Key: {_mask_key(info['auth_value'])}][/yellow]"
    hooks_suffix = _compact_events(info["events"])
    rich.print(
        f"    [bold green]INSTALLED[/bold green]   "
        f"[bold white]\\[{info['host']}][/bold white]   "
        f"{auth_label}   "
        f"[dim]{hooks_suffix}[/dim]"
    )


def _detect_claude_install(path: Path = CLAUDE_SETTINGS_PATH) -> dict | None:
    if not path.exists():
        return None
    settings = _read_json_or_empty(path)
    hooks = settings.get("hooks", {})

    events = []
    found_cmd = None
    for event in CLAUDE_HOOK_EVENTS:
        for group in hooks.get(event, []):
            for h in group.get("hooks", []):
                if _is_agent_scan_command(h.get("command", "")):
                    events.append(event)
                    if found_cmd is None:
                        found_cmd = h["command"]
                    break
            else:
                continue
            break

    if not events or found_cmd is None:
        return None
    return _parse_command_info(found_cmd, events)


def _detect_cursor_install(path: Path = CURSOR_HOOKS_PATH) -> dict | None:
    if not path.exists():
        return None
    data = _read_json_or_empty(path)
    hooks = data.get("hooks", {})

    events = []
    found_cmd = None
    for event in CURSOR_HOOK_EVENTS:
        for entry in hooks.get(event, []):
            if _is_agent_scan_command(entry.get("command", "")):
                events.append(event)
                if found_cmd is None:
                    found_cmd = entry["command"]
                break

    if not events or found_cmd is None:
        return None
    return _parse_command_info(found_cmd, events)


# ---------------------------------------------------------------------------
# Test event
# ---------------------------------------------------------------------------


def _send_test_event(push_key: str, url: str, hook_client: str, script_path: Path) -> bool:
    """Send a test hooksConfigured event by invoking the hook script. Returns True on success."""
    import subprocess

    if hook_client == "claude-code":
        payload = '{"hook_event_name":"hooksConfigured","session_id":"hooks-setup"}'
    else:
        payload = '{"hook_event_name":"hooksConfigured","conversation_id":"hooks-setup"}'

    if IS_WINDOWS:
        cmd = [
            "powershell",
            "-File",
            str(script_path),
            "-Client",
            hook_client,
            "-PushKey",
            push_key,
            "-RemoteUrl",
            url,
        ]
        env = None  # inherit current env
    else:
        cmd = ["bash", str(script_path), "--client", hook_client]
        env = {
            **os.environ,
            "PUSH_KEY": push_key,
            "REMOTE_HOOKS_BASE_URL": url,
        }

    try:
        result = subprocess.run(
            cmd,
            input=payload,
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )
        if result.returncode == 0:
            rich.print("[green]\u2713[/green]  Test event sent  [green]\u2192 OK[/green]")
            return True
        stderr = result.stderr.strip()
        rich.print(f"[red]\u2717[/red]  Test event failed: {stderr or f'exit code {result.returncode}'}")
        return False
    except subprocess.TimeoutExpired:
        rich.print("[red]\u2717[/red]  Test event failed: timeout")
        return False
    except Exception as e:
        rich.print(f"[red]\u2717[/red]  Test event failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Detection / filtering
# ---------------------------------------------------------------------------


def _is_agent_scan_command(cmd: str) -> bool:
    return DETECTION_MARKER in cmd


def _filter_claude_hooks(hooks: dict) -> dict:
    result = {}
    for event, groups in hooks.items():
        filtered = [
            g for g in groups if not any(_is_agent_scan_command(h.get("command", "")) for h in g.get("hooks", []))
        ]
        if filtered:
            result[event] = filtered
    return result


def _filter_cursor_hooks(hooks: dict) -> dict:
    result = {}
    for event, entries in hooks.items():
        filtered = [e for e in entries if not _is_agent_scan_command(e.get("command", ""))]
        if filtered:
            result[event] = filtered
    return result


def _count_non_agent_scan_claude(hooks: dict) -> int:
    n = 0
    for groups in hooks.values():
        for g in groups:
            if not any(_is_agent_scan_command(h.get("command", "")) for h in g.get("hooks", [])):
                n += 1
    return n


def _count_non_agent_scan_cursor(hooks: dict) -> int:
    n = 0
    for entries in hooks.values():
        for e in entries:
            if not _is_agent_scan_command(e.get("command", "")):
                n += 1
    return n


# ---------------------------------------------------------------------------
# Command parsing
# ---------------------------------------------------------------------------


def _parse_command_info(cmd: str, events: list[str]) -> dict:
    url = _extract_env_from_cmd(cmd, "REMOTE_HOOKS_BASE_URL")
    push_key = _extract_env_from_cmd(cmd, "PUSH_KEY")
    tenant_id = _extract_env_from_cmd(cmd, "TENANT_ID")
    host = urlparse(url).netloc if url else "unknown"

    return {
        "host": host,
        "auth_type": "pushkey",
        "auth_value": push_key or "",
        "tenant_id": tenant_id,
        "url": url or DEFAULT_REMOTE_URL,
        "events": events,
    }


_PS_PARAM_MAP = {
    "PUSH_KEY": "PushKey",
    "REMOTE_HOOKS_BASE_URL": "RemoteUrl",
}


def _extract_env_from_cmd(cmd: str, key: str) -> str:
    # Try PowerShell -ParamName 'value' form
    ps_name = _PS_PARAM_MAP.get(key)
    if ps_name:
        m = re.search(rf"-{re.escape(ps_name)}\s+'([^']*)'", cmd)
        if m:
            return m.group(1)
    # Try KEY='...' form
    m = re.search(rf"(?:^| ){re.escape(key)}='([^']*)'", cmd)
    if m:
        return m.group(1)
    # Try KEY=value (no quotes)
    m = re.search(rf"(?:^| ){re.escape(key)}=(\S+)", cmd)
    if m:
        return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _client_label(client: str) -> str:
    return "Claude Code" if client == "claude" else "Cursor"


def _config_path(client: str, override: str | None = None, managed: bool = False) -> Path:
    """Resolve the config file path for a client, with optional override."""
    if override:
        return Path(override)
    if managed:
        return CLAUDE_MANAGED_SETTINGS_PATH if client == "claude" else CURSOR_MANAGED_HOOKS_PATH
    return CLAUDE_SETTINGS_PATH if client == "claude" else CURSOR_HOOKS_PATH


def _preflight_writable(config_path: Path) -> None:
    """Verify that the config file's parent directory is writable.

    Raises PermissionError early (before minting a push key) so we don't
    leave orphaned credentials when the filesystem operation would fail.
    """
    parent = config_path.parent
    if parent.exists() and not os.access(parent, os.W_OK):
        raise PermissionError(f"Directory not writable: {parent}")


def _revoke_after_failure(url: str, tenant_id: str, snyk_token: str, push_key: str) -> None:
    """Best-effort revocation of a push key after a failed install."""
    rich.print("[dim]Revoking minted push key...[/dim]")
    try:
        revoke_push_key(url, tenant_id, snyk_token, push_key)
        rich.print("[green]\u2713[/green]  Push key revoked")
    except RuntimeError as e:
        rich.print(f"[yellow]Warning:[/yellow] Could not revoke push key: {e}")


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


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _mask_key(k: str) -> str:
    if len(k) <= 8:
        return k
    return k[:4] + "..." + k[-4:]


def _compact_events(events: list[str]) -> str:
    if not events:
        return "(no hooks)"
    show = 2
    if len(events) <= show:
        return "(" + ", ".join(events) + ")"
    return f"({', '.join(events[:show])} + {len(events) - show} more)"


def _copy_hook_script(client: str, config_path: Path) -> tuple[Path, bool, bool]:
    """Copy bundled hook script to a hooks/ dir next to the config file.

    Returns (path, already_existed, was_updated).
    """
    dest_dir = config_path.parent / "hooks"

    dest_dir.mkdir(parents=True, exist_ok=True)
    script_name = "snyk-agent-guard.ps1" if IS_WINDOWS else "snyk-agent-guard.sh"
    dest = dest_dir / script_name
    existed = dest.exists()

    from agent_scan.version import version_info

    hook_pkg = importlib_resources.files("agent_scan.hooks")
    source = hook_pkg.joinpath(script_name)
    new_content = source.read_bytes().replace(b"__AGENT_SCAN_VERSION__", version_info.encode())

    if existed and dest.read_bytes() == new_content:
        return dest, existed, False

    dest.write_bytes(new_content)
    dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    rich.print(f"[green]\u2713[/green]  Copied hook script to [dim]{dest}[/dim]")
    return dest, existed, True


def _remove_hook_script(client: str, config_path: Path) -> None:
    dest_dir = config_path.parent / "hooks"
    script_name = "snyk-agent-guard.ps1" if IS_WINDOWS else "snyk-agent-guard.sh"
    dest = dest_dir / script_name
    if dest.exists():
        dest.unlink()
        rich.print(f"[green]\u2713[/green]  Removed hook script [dim]{dest}[/dim]")


def _backup_file(path: Path) -> None:
    if path.exists():
        backup = Path(str(path) + ".backup")
        shutil.copy2(path, backup)
        rich.print(f"[green]\u2713[/green]  Backed up [dim]{path}[/dim] \u2192 [dim]{backup}[/dim]")


def _read_json_or_empty(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path) as f:
        return json.load(f)


def _write_json_if_changed(path: Path, data: dict) -> bool:
    """Write JSON to path only if content differs. Backs up before writing. Returns True if written."""
    new_content = json.dumps(data, indent=2) + "\n"
    if path.exists():
        old_content = path.read_text()
        if old_content == new_content:
            return False
        _backup_file(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new_content)
    return True


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def _preserved_note(count: int) -> str:
    if count == 0:
        return ""
    return f"  [dim]({count} other hook(s) preserved)[/dim]"
