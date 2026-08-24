"""Agent Guard hook management for Claude Code, Cursor, and Codex."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import time
from importlib import resources as importlib_resources
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, TypeVar
from urllib.parse import urlparse

import rich

from agent_scan.pushkeys import (
    GuardEnabledAccessDeniedError,
    _is_localhost,
    fetch_guard_enabled,
    mint_push_key,
    revoke_push_key,
)
from agent_scan.redact import redact_push_keys, redact_push_keys_in_data

if TYPE_CHECKING:
    from collections.abc import Callable

    from agent_scan.models import ClientToInspect

IS_WINDOWS = sys.platform == "win32"
_T = TypeVar("_T")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALL_CLIENTS = ["claude", "cursor", "codex"]
_HOOK_CLIENT_PROJECT_FOLDER_FIELDS = {
    "claude-code": "cwd",
    "cursor": "workspace_roots",
    "codex": "cwd",
}
_HOOK_CLIENT_SESSION_FIELDS = {
    "claude-code": "session_id",
    "cursor": "conversation_id",
    "codex": "session_id",
}
DEFAULT_REMOTE_URL = "https://api.snyk.io"
_DETECTION_RE = re.compile(
    r"PUSH_KEY=.*snyk-agent-guard"
    r"|snyk-agent-guard.*-PushKey\b"
)
_PERMISSION_DENIED = "__permission_denied__"
_STDIN_READ_TIMEOUT_SECONDS = 5.0
_DEFAULT_DISCOVERY_TIMEOUT_SECONDS = 60.0

CLAUDE_SETTINGS_PATH = Path.home() / ".claude" / "settings.json"
CURSOR_HOOKS_PATH = Path.home() / ".cursor" / "hooks.json"
CODEX_HOOKS_PATH = Path.home() / ".codex" / "hooks.json"

# Managed (MDM / admin-deployed) config paths — OS-specific
# Codex managed hooks use a requirements.toml file at a system location
# (see https://developers.openai.com/codex/hooks#managed-hooks-from-requirementstoml).
if sys.platform == "darwin":
    CLAUDE_MANAGED_SETTINGS_PATH = Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    CURSOR_MANAGED_HOOKS_PATH = Path("/Library/Application Support/Cursor/hooks.json")
    CODEX_MANAGED_HOOKS_PATH = Path("/etc/codex/requirements.toml")
elif sys.platform == "win32":
    CLAUDE_MANAGED_SETTINGS_PATH = Path("C:/Program Files/ClaudeCode/managed-settings.json")
    CURSOR_MANAGED_HOOKS_PATH = Path("C:/ProgramData/Cursor/hooks.json")
    CODEX_MANAGED_HOOKS_PATH = Path("C:/ProgramData/OpenAI/Codex/requirements.toml")
else:  # Linux and others
    CLAUDE_MANAGED_SETTINGS_PATH = Path("/etc/claude-code/managed-settings.json")
    CURSOR_MANAGED_HOOKS_PATH = Path("/etc/cursor/hooks.json")
    CODEX_MANAGED_HOOKS_PATH = Path("/etc/codex/requirements.toml")

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

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_guard(args) -> int:
    try:
        guard_command = getattr(args, "guard_command", None)
        if guard_command == "install":
            _run_install(args)
        elif guard_command == "discover":
            return _run_discover(args)
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


def _get_machine_description(clients: list[str]) -> str:
    from agent_scan.utils import get_hostname

    hostname = get_hostname()
    label = ", ".join(_client_label(c) for c in clients)
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
    machine_id = (getattr(args, "machine_id", None) or os.environ.get("MACHINE_ID", "") or "").strip()

    clients = ALL_CLIENTS if client == "all" else [client]

    if client == "all" and getattr(args, "file", None):
        rich.print("[bold red]Error:[/bold red] --file cannot be used with client 'all'.")
        sys.exit(1)

    # Filter out clients whose agent is not installed on this machine.
    # Skip this check when --file is explicitly provided (the caller knows where to write).
    if not getattr(args, "file", None):
        skipped = [c for c in clients if not _is_client_installed(c)]
        clients = [c for c in clients if _is_client_installed(c)]
        for c in skipped:
            rich.print(
                f"[yellow]Warning:[/yellow] {_client_label(c)} is not installed on this machine. "
                f"Skipping hook installation for {_client_label(c)}."
            )
        if not clients:
            rich.print("[yellow]Warning:[/yellow] No installed agents found. Nothing to install.")
            return

    scope = "managed" if managed else "user"
    snyk_token = ""

    if not headless:
        # Interactive flow — mint a push key
        label = ", ".join(_client_label(c) for c in clients)
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

        # Preflight: verify target directories are writable before minting
        for c in clients:
            _preflight_writable(_config_path(c, getattr(args, "file", None), managed=managed))

        description = _get_machine_description(clients)
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

    minted = not headless  # True if we minted the key in this run

    installed_any = False
    first_installed: tuple[str, Path] | None = None
    try:
        for c in clients:
            dest_path = _install_hooks(
                c,
                _hook_client_name(c),
                push_key,
                url,
                _config_path(c, getattr(args, "file", None), managed=managed),
                scope,
                _client_label(c),
                minted,
                tenant_id,
                snyk_token,
                machine_id,
            )
            if first_installed is None:
                first_installed = (_hook_client_name(c), dest_path)
            installed_any = True
    except BaseException:
        if minted:
            if installed_any:
                rich.print(
                    "[yellow]Warning:[/yellow] Installation partially completed. "
                    "The push key is still active for already-configured clients. "
                    "Run [bold]uninstall[/bold] to clean up if needed."
                )
            else:
                _revoke_after_failure(url, tenant_id, snyk_token, push_key)
        raise

    if first_installed is not None:
        _send_servers_discovered_event(push_key, url, *first_installed, machine_id)


def _run_with_timeout(func: Callable[[], _T], timeout: float) -> _T:
    """Run ``func`` on a daemon thread; raise ``TimeoutError`` if it outlives ``timeout``."""
    import threading

    result: list[_T] = []
    error: list[BaseException] = []

    def run() -> None:
        try:
            result.append(func())
        except BaseException as e:
            error.append(e)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"timed out after {timeout:g}s")
    if error:
        raise error[0]
    return result[0]


def _discovery_timeout_seconds() -> float:
    try:
        value = float(os.environ.get("AGENT_SCAN_DISCOVERY_TIMEOUT_SECONDS", ""))
    except ValueError:
        return _DEFAULT_DISCOVERY_TIMEOUT_SECONDS
    return value if value > 0 else _DEFAULT_DISCOVERY_TIMEOUT_SECONDS


def _read_hook_payload() -> str:
    """Read hook JSON from stdin without allowing an open stream to hang discovery."""
    stream = sys.stdin
    try:
        if stream is None or stream.isatty():
            return ""
        return _run_with_timeout(lambda: stream.read(1024 * 1024), _STDIN_READ_TIMEOUT_SECONDS)
    except Exception:
        return ""


def _run_discover(args) -> int:
    push_key = os.environ.get("PUSH_KEY", "")
    if not push_key:
        rich.print("[bold red]Error:[/bold red] PUSH_KEY is required to run guard discovery.")
        return 1

    url = getattr(args, "url", None) or os.environ.get("REMOTE_HOOKS_BASE_URL") or DEFAULT_REMOTE_URL
    machine_id = (os.environ.get("MACHINE_ID", "") or "").strip()
    config_path = Path(getattr(args, "file", None) or CLAUDE_SETTINGS_PATH)
    script_name = "snyk-agent-guard.ps1" if IS_WINDOWS else "snyk-agent-guard.sh"
    script_path = config_path.parent / "hooks" / script_name
    if not script_path.exists():
        rich.print(
            f"[bold red]Error:[/bold red] Agent Guard forwarding script not found: {script_path}. "
            "Run guard install first."
        )
        return 1

    project_folders: list[str] = []
    session_id = ""
    hook_client = getattr(args, "client", None)
    project_folder_payload_field = _HOOK_CLIENT_PROJECT_FOLDER_FIELDS.get(hook_client) if hook_client else None
    session_payload_field = _HOOK_CLIENT_SESSION_FIELDS.get(hook_client) if hook_client else None
    if project_folder_payload_field or session_payload_field:
        try:
            hook_payload = json.loads(_read_hook_payload())
            project_folder = (
                hook_payload.get(project_folder_payload_field)
                if isinstance(hook_payload, dict) and project_folder_payload_field
                else None
            )
            if isinstance(project_folder, str) and project_folder:
                project_folders.append(project_folder)
            elif isinstance(project_folder, list):
                project_folders.extend(folder for folder in project_folder if isinstance(folder, str) and folder)
            raw_session_id = (
                hook_payload.get(session_payload_field)
                if isinstance(hook_payload, dict) and session_payload_field
                else None
            )
            if isinstance(raw_session_id, str) and raw_session_id:
                session_id = raw_session_id
        except Exception:
            pass

    success = _send_servers_discovered_event(
        push_key,
        url,
        hook_client or "claude-code",
        script_path,
        machine_id,
        event_name="SessionStartServerDiscovery",
        session_marker=session_id or "session-start-server-discovery",
        project_folders=project_folders,
    )
    return 0 if success else 1


def _prepare_client_config(
    client: str,
    command: str,
    config_path: Path,
    *,
    discover_command: str | None = None,
) -> tuple[dict | None, str | None, dict, int]:
    """Dispatch to the client-specific config preparation function.

    Returns (prepared_config, prepared_content, hooks_diff, preserved).
    """
    prepared_content: str | None = None
    prepared_config: dict | None = None
    preserved = 0
    if client == "claude":
        prepared_config, hooks_diff, preserved = _prepare_claude_config(
            command, config_path, discover_command=discover_command
        )
    elif client == "cursor":
        prepared_config, hooks_diff, preserved = _prepare_cursor_config(
            command, config_path, discover_command=discover_command
        )
    elif client == "codex":
        if _is_codex_requirements_toml(config_path):
            prepared_content, hooks_diff = _prepare_codex_managed_config(command, config_path)
        else:
            prepared_config, hooks_diff, preserved = _prepare_codex_config(
                command, config_path, discover_command=discover_command
            )
    else:
        raise ValueError(f"Unknown client: {client}")
    return prepared_config, prepared_content, hooks_diff, preserved


def _write_client_config(
    client: str,
    config_path: Path,
    prepared_config: dict | None,
    prepared_content: str | None,
    preserved: int,
) -> bool:
    """Dispatch to the client-specific config writing function."""
    if client == "claude":
        assert prepared_config is not None
        return _write_claude_config(prepared_config, config_path, preserved)
    if client == "cursor":
        assert prepared_config is not None
        return _write_cursor_config(prepared_config, config_path, preserved)
    if client == "codex":
        if _is_codex_requirements_toml(config_path):
            assert prepared_content is not None
            return _write_codex_managed_config(prepared_content, config_path)
        assert prepared_config is not None
        return _write_codex_config(prepared_config, config_path, preserved)
    raise ValueError(f"Unknown client: {client}")


def _detect_existing_install(client: str, config_path: Path) -> dict | None:
    """Return the existing install info for *client*, or None if not installed."""
    if client == "claude":
        return _detect_claude_install(config_path)
    if client == "cursor":
        return _detect_cursor_install(config_path)
    return _detect_codex_install(config_path)


def _install_hooks(
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
    machine_id: str,
) -> Path:
    """Post-mint install steps.  Extracted so _run_install can revoke on failure."""
    existing_info = _detect_existing_install(client, config_path)
    old_push_key = existing_info.get("auth_value", "") if existing_info else ""
    push_key_changed = bool(old_push_key) and old_push_key != push_key

    is_codex_requirements = _is_codex_requirements_toml(config_path)
    discover_script_name = "snyk-agent-guard-discover.ps1" if IS_WINDOWS else "snyk-agent-guard-discover.sh"
    discover_script_path = config_path.parent / "hooks" / discover_script_name
    discover_script_existed = discover_script_path.exists()
    (
        dest_path,
        script_existed,
        script_updated,
        current_checksum,
        new_checksum,
        discover_current_checksum,
        discover_new_checksum,
    ) = _copy_hook_script(config_path, include_discover=not is_codex_requirements)
    command = _build_hook_command(
        push_key,
        url,
        dest_path,
        hook_client,
        tenant_id=tenant_id,
        machine_id=machine_id,
    )
    discover_command = None
    if not is_codex_requirements:
        installed_discover_script_path = dest_path.with_name(discover_script_name)
        discover_command = _build_discover_hook_command(
            push_key,
            url,
            installed_discover_script_path,
            tenant_id=tenant_id,
            machine_id=machine_id,
            hook_client=hook_client,
            config_path=config_path,
        )
    prepared_config, prepared_content, hooks_diff, preserved = _prepare_client_config(
        client,
        command,
        config_path,
        discover_command=discover_command,
    )

    first_install = not script_existed
    config_changed = bool(hooks_diff["added"] or hooks_diff["modified"] or hooks_diff["removed"])

    if not _send_test_event(
        push_key,
        url,
        hook_client,
        dest_path,
        first_install=first_install,
        config_changed=config_changed,
        hooks_diff=hooks_diff,
        push_key_changed=push_key_changed,
        current_checksum=current_checksum,
        new_checksum=new_checksum,
        discover_current_checksum=discover_current_checksum,
        discover_new_checksum=discover_new_checksum,
        machine_id=machine_id,
    ):
        if not script_existed:
            dest_path.unlink(missing_ok=True)
        if not discover_script_existed:
            discover_script_path.unlink(missing_ok=True)
        rich.print("[bold red]Aborting install \u2014 test event failed.[/bold red]")
        raise SystemExit(1)

    config_written = _write_client_config(client, config_path, prepared_config, prepared_content, preserved)

    if script_updated or config_written or minted:
        rich.print(f"[green]\u2713[/green]  {scope.title()} hooks installed for [bold]{label}[/bold]")
    else:
        rich.print(f"[green]\u2713[/green]  {label} {scope} hook integration up to date")
    rich.print(f"   Config:     [dim]{config_path}[/dim]")
    rich.print(f"   Script:     [dim]{dest_path}[/dim]")
    rich.print(f"   Remote URL: [dim]{url}[/dim]")
    rich.print(f"   Push Key:   [yellow]{_mask_key(push_key)}[/yellow]")
    rich.print()
    return dest_path


def _prepare_claude_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
) -> tuple[dict, dict, int]:
    """Build new Claude settings with hooks and compute diff, without writing.

    Returns (new_settings, hooks_diff, preserved_count).
    """
    settings = _read_json_or_empty(path)
    old_hooks = settings.get("hooks", {})

    filtered = _filter_claude_hooks(old_hooks)
    preserved = sum(len(filtered.get(event, [])) for event in CLAUDE_HOOK_EVENTS)
    hooks = {}

    for event in CLAUDE_HOOK_EVENTS:
        entry = {"type": "command", "command": command}
        if IS_WINDOWS:
            entry["shell"] = "powershell"
        group: dict = {"hooks": [entry]}
        if event in CLAUDE_EVENTS_WITH_MATCHER:
            group["matcher"] = "*"
        existing = list(filtered.get(event, []))
        existing.append(group)
        hooks[event] = existing

    if discover_command:
        # Claude supports async hooks; keep session start independent of the discovery scan.
        discover_entry: dict = {
            "type": "command",
            "command": discover_command,
            "async": True,
        }
        if IS_WINDOWS:
            discover_entry["shell"] = "powershell"
        hooks["SessionStart"].append({"hooks": [discover_entry]})

    for event, groups in filtered.items():
        if event not in hooks:
            hooks[event] = groups

    settings["hooks"] = hooks
    diff = _compute_hooks_diff(old_hooks, hooks)
    return settings, diff, preserved


def _write_claude_config(settings: dict, path: Path, preserved: int) -> bool:
    """Write Claude settings to disk. Returns True if file changed."""
    if not _write_json_if_changed(path, settings):
        return False
    note = _preserved_note(preserved)
    rich.print(f"[green]\u2713[/green]  Written [dim]{path}[/dim]{note}")
    return True


def _prepare_cursor_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
) -> tuple[dict, dict, int]:
    """Build new Cursor config with hooks and compute diff, without writing.

    Returns (new_data, hooks_diff, preserved_count).
    """
    data = _read_json_or_empty(path)
    if "version" not in data:
        data["version"] = 1
    old_hooks = data.get("hooks", {})

    filtered = _filter_cursor_hooks(old_hooks)
    preserved = sum(len(filtered.get(event, [])) for event in CURSOR_HOOK_EVENTS)
    hooks = {}

    for event in CURSOR_HOOK_EVENTS:
        existing = list(filtered.get(event, []))
        existing.append({"command": command})
        hooks[event] = existing

    if discover_command:
        # Cursor sessionStart hooks are fire-and-forget without an explicit async marker.
        hooks["sessionStart"].append({"command": discover_command})

    for event, entries in filtered.items():
        if event not in hooks:
            hooks[event] = entries

    data["hooks"] = hooks
    diff = _compute_hooks_diff(old_hooks, hooks)
    return data, diff, preserved


def _write_cursor_config(data: dict, path: Path, preserved: int) -> bool:
    """Write Cursor config to disk. Returns True if file changed."""
    if not _write_json_if_changed(path, data):
        return False
    note = _preserved_note(preserved)
    rich.print(f"[green]\u2713[/green]  Written [dim]{path}[/dim]{note}")
    return True


def _prepare_codex_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
) -> tuple[dict, dict, int]:
    """Build new Codex config with hooks and compute diff, without writing.

    Returns (new_data, hooks_diff, preserved_count).
    Codex uses the same hooks.json shape as Claude Code.
    """
    data = _read_json_or_empty(path)
    old_hooks = data.get("hooks", {})

    filtered = _filter_claude_hooks(old_hooks)
    preserved = sum(len(filtered.get(event, [])) for event in CODEX_HOOK_EVENTS)
    hooks = {}

    for event in CODEX_HOOK_EVENTS:
        entry = {"type": "command", "command": command}
        existing = list(filtered.get(event, []))
        existing.append({"hooks": [entry]})
        hooks[event] = existing

    if discover_command:
        # Codex supports async hooks; keep session start independent of the discovery scan.
        hooks["SessionStart"].append({"hooks": [{"type": "command", "command": discover_command, "async": True}]})

    for event, groups in filtered.items():
        if event not in hooks:
            hooks[event] = groups

    data["hooks"] = hooks
    diff = _compute_hooks_diff(old_hooks, hooks)
    return data, diff, preserved


def _write_codex_config(data: dict, path: Path, preserved: int) -> bool:
    """Write Codex config to disk. Returns True if file changed."""
    if not _write_json_if_changed(path, data):
        return False
    note = _preserved_note(preserved)
    rich.print(f"[green]✓[/green]  Written [dim]{path}[/dim]{note}")
    return True


def _is_codex_requirements_toml(path: Path) -> bool:
    return path.suffix.lower() == ".toml"


def _codex_managed_dirs(config_path: Path) -> tuple[str, str]:
    """Return (managed_dir, windows_managed_dir) values to embed in requirements.toml.

    The current platform's value is derived from the config_path so the script
    location stays consistent with where _copy_hook_script writes it. The
    other-platform value uses the canonical Codex system path.
    """
    hooks_dir = (config_path.parent / "hooks").as_posix()
    if IS_WINDOWS:
        windows_managed_dir = str(config_path.parent / "hooks")
        managed_dir = "/etc/codex/hooks"
        return managed_dir, windows_managed_dir
    managed_dir = hooks_dir
    windows_managed_dir = r"C:\ProgramData\OpenAI\Codex\hooks"
    return managed_dir, windows_managed_dir


def _render_codex_requirements_toml(command: str, config_path: Path) -> str:
    """Generate the requirements.toml content for managed Codex hooks."""
    managed_dir, windows_managed_dir = _codex_managed_dirs(config_path)
    lines = [
        "[features]",
        "hooks = true",
        "",
        "[hooks]",
        f'managed_dir = "{managed_dir}"',
        f"windows_managed_dir = '{windows_managed_dir}'",
        "",
    ]
    escaped = command.replace("\\", "\\\\").replace('"', '\\"')
    for event in CODEX_HOOK_EVENTS:
        lines.append(f"[[hooks.{event}]]")
        lines.append(f"[[hooks.{event}.hooks]]")
        lines.append('type = "command"')
        lines.append(f'command = "{escaped}"')
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _prepare_codex_managed_config(command: str, path: Path) -> tuple[str, dict]:
    """Build new Codex managed TOML content and compute diff, without writing.

    Returns (new_content, hooks_diff).
    """
    new_content = _render_codex_requirements_toml(command, path)

    old_events: list[str] = []
    old_cmd: str | None = None
    if path.exists():
        old_text = path.read_text()
        with contextlib.suppress(UnicodeDecodeError, ValueError):
            old_events, old_cmd = _parse_codex_requirements_toml(old_text)

    old_event_set = set(old_events)
    new_event_set = set(CODEX_HOOK_EVENTS)

    removed = {e: [{"type": "command", "command": command}] for e in sorted(new_event_set - old_event_set)}
    added = {e: [{"type": "command", "command": old_cmd or ""}] for e in sorted(old_event_set - new_event_set)}
    modified = {}
    if old_cmd is not None and old_cmd != command:
        expected = [{"type": "command", "command": command}]
        actual = [{"type": "command", "command": old_cmd}]
        modified = {
            e: {"expected_value": expected, "actual_value": actual} for e in sorted(old_event_set & new_event_set)
        }

    diff = {"added": added, "modified": modified, "removed": removed}
    return new_content, diff


def _write_codex_managed_config(content: str, path: Path) -> bool:
    """Write Codex managed TOML to disk. Returns True if file changed."""
    if path.exists() and path.read_text() == content:
        return False
    if path.exists():
        _backup_file(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    rich.print(f"[green]✓[/green]  Written [dim]{path}[/dim]")
    return True


def _parse_codex_requirements_toml(text: str) -> tuple[list[str], str | None]:
    """Extract Snyk Agent Guard events and the first matching command from requirements.toml.

    Returns (events, command). Only scans hook command lines containing the
    agent-guard detection marker.
    """
    events: list[str] = []
    found_cmd: str | None = None
    current_event: str | None = None
    header_re = re.compile(r"^\[\[hooks\.([A-Za-z]+)(?:\.hooks)?\]\]\s*$")
    command_re = re.compile(r'^command\s*=\s*"((?:[^"\\]|\\.)*)"\s*$')
    for raw in text.splitlines():
        line = raw.strip()
        m = header_re.match(line)
        if m:
            current_event = m.group(1)
            continue
        m = command_re.match(line)
        if m and current_event:
            cmd = m.group(1).replace("\\\\", "\0").replace('\\"', '"').replace("\0", "\\")
            if _is_agent_scan_command(cmd) and current_event not in events:
                events.append(current_event)
                if found_cmd is None:
                    found_cmd = cmd
    return events, found_cmd


def _detect_codex_managed_install(path: Path) -> dict | None:
    text = path.read_text()
    events, found_cmd = _parse_codex_requirements_toml(text)
    if not events or found_cmd is None:
        return None
    return _parse_command_info(found_cmd, events)


def _uninstall_codex_managed(path: Path) -> None:
    if not path.exists():
        rich.print("[dim]No requirements.toml found. Nothing to uninstall.[/dim]")
        return
    text = path.read_text()
    events, _ = _parse_codex_requirements_toml(text)
    if not events:
        rich.print("[dim]No Agent Guard hooks found.[/dim]")
        return
    _backup_file(path)
    path.unlink()
    rich.print(f"[green]✓[/green]  Removed {len(events)} Agent Guard hook(s) (deleted [dim]{path}[/dim])")


# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------


def _run_uninstall(args) -> None:
    client: str = args.client
    managed: bool = getattr(args, "managed", False)

    if client == "all" and getattr(args, "file", None):
        rich.print("[bold red]Error:[/bold red] --file cannot be used with client 'all'.")
        sys.exit(1)

    clients = ALL_CLIENTS if client == "all" else [client]

    for c in clients:
        _uninstall_single_client(c, args, managed)


def _uninstall_single_client(client: str, args, managed: bool) -> None:
    label = _client_label(client)
    scope = "managed" if managed else "user"
    config_path = _config_path(client, getattr(args, "file", None), managed=managed)

    rich.print(f"Removing [bold magenta]Agent Guard[/bold magenta] {scope} hooks from [bold]{label}[/bold]")
    rich.print("[dim]Other hooks in the file will be preserved.[/dim]")
    rich.print()

    info = _detect_existing_install(client, config_path)

    # Remove hooks from config
    if client == "claude":
        _uninstall_claude(config_path)
    elif client == "cursor":
        _uninstall_cursor(config_path)
    elif client == "codex":
        if _is_codex_requirements_toml(config_path):
            _uninstall_codex_managed(config_path)
        else:
            _uninstall_codex(config_path)

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


def _uninstall_codex(path: Path) -> None:
    """Codex uses the Claude-shaped hooks.json, so reuse the Claude filter."""
    if not path.exists():
        rich.print("[dim]No hooks.json found. Nothing to uninstall.[/dim]")
        return

    data = _read_json_or_empty(path)
    hooks = data.get("hooks", {})

    total_before = sum(len(groups) for groups in hooks.values())
    filtered = _filter_claude_hooks(hooks)
    total_after = sum(len(groups) for groups in filtered.values())

    removed = total_before - total_after
    if removed == 0:
        rich.print("[dim]No Agent Guard hooks found.[/dim]")
        return

    _backup_file(path)
    if filtered:
        data["hooks"] = filtered
    else:
        data.pop("hooks", None)
    _write_json(path, data)
    rich.print(f"[green]✓[/green]  Removed {removed} Agent Guard hook(s){_preserved_note(total_after)}")


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
    _print_client_status("Codex", CODEX_HOOKS_PATH, _detect_codex_install())
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
    codex_managed_info: dict | str | None
    try:
        codex_managed_info = _detect_codex_install(CODEX_MANAGED_HOOKS_PATH)
    except PermissionError:
        codex_managed_info = _PERMISSION_DENIED
    _print_client_status("Codex", CODEX_MANAGED_HOOKS_PATH, codex_managed_info)
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


def _detect_codex_install(path: Path = CODEX_HOOKS_PATH) -> dict | None:
    if not path.exists():
        return None
    if _is_codex_requirements_toml(path):
        return _detect_codex_managed_install(path)
    data = _read_json_or_empty(path)
    hooks = data.get("hooks", {})

    events = []
    found_cmd = None
    for event in CODEX_HOOK_EVENTS:
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
# Hook events
# ---------------------------------------------------------------------------


def _servers_discovered_entries(clients_to_inspect: list[ClientToInspect]) -> list[dict]:
    """Serialize discovered clients exactly as ``scan`` serializes them for analysis."""
    from agent_scan.inspect import (
        _config_error_to_scan_error,
        _inspection_component_name,
        _join_scan_errors,
    )
    from agent_scan.models import InspectedPath, InspectedServer, ScanError
    from agent_scan.models.errors import CouldNotParseMCPConfig, FileNotFoundConfig, UnknownConfigFormat
    from agent_scan.verify_api import build_scan_request

    inspected_paths: list[InspectedPath] = []
    for client in clients_to_inspect:
        servers: list[InspectedServer] = []
        config_errors: list[ScanError] = []
        for config_path, discovered in client.mcp_configs.items():
            if isinstance(discovered, FileNotFoundConfig | UnknownConfigFormat | CouldNotParseMCPConfig):
                config_errors.append(_config_error_to_scan_error(discovered))
                continue
            servers.extend(
                InspectedServer(
                    name=_inspection_component_name(name, "server", config_path),
                    config_path=config_path,
                    server=server,
                )
                for name, server in discovered
            )
        inspected_paths.append(
            InspectedPath(
                client=client.name,
                path=client.client_path,
                servers=servers,
                error=_join_scan_errors(config_errors),
            )
        )
    return [request.model_dump(mode="json") for request in build_scan_request(inspected_paths).scan_path_requests]


def _discover_servers_payload(project_folders: list[str] | None = None) -> list[dict]:
    import asyncio

    from agent_scan import pipelines

    # Discovery only parses config files; timeout is unused because no server is started.
    inspect_args = pipelines.InspectArgs(
        timeout=0,
        tokens=[],
        paths=[],
        project_folders=project_folders or [],
    )
    clients_to_inspect, _, _ = _run_with_timeout(
        lambda: asyncio.run(pipelines.discover_clients_to_inspect(inspect_args)),
        _discovery_timeout_seconds(),
    )
    return _servers_discovered_entries(clients_to_inspect)


def _invoke_hook_script(
    script_path: Path,
    hook_client: str,
    push_key: str,
    url: str,
    payload: str,
    machine_id: str = "",
) -> tuple[bool, str]:
    import subprocess

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
        if machine_id:
            cmd.extend(["-MachineId", machine_id])
        env = None
    else:
        cmd = ["bash", str(script_path), "--client", hook_client]
        env = {
            **os.environ,
            "PUSH_KEY": push_key,
            "REMOTE_HOOKS_BASE_URL": url,
        }
        if machine_id:
            env["MACHINE_ID"] = machine_id

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
            return True, ""
        return False, result.stderr.strip() or f"exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def _send_test_event(
    push_key: str,
    url: str,
    hook_client: str,
    script_path: Path,
    *,
    first_install: bool = False,
    config_changed: bool = False,
    hooks_diff: dict | None = None,
    push_key_changed: bool = False,
    current_checksum: str | None = None,
    new_checksum: str | None = None,
    discover_current_checksum: str | None = None,
    discover_new_checksum: str | None = None,
    machine_id: str = "",
) -> bool:
    """Send a test hooksConfigured event by invoking the hook script. Returns True on success."""
    payload_dict: dict = {"hook_event_name": "hooksConfigured"}
    if hook_client == "claude-code" or hook_client == "codex":
        payload_dict["session_id"] = "hooks-setup"
    else:
        payload_dict["conversation_id"] = "hooks-setup"
    payload_dict["first_install"] = first_install
    payload_dict["push_key_changed"] = push_key_changed
    if not first_install:
        payload_dict["config_changed"] = config_changed
        if hooks_diff:
            payload_dict["added"] = hooks_diff.get("added", {})
            payload_dict["modified"] = hooks_diff.get("modified", {})
            payload_dict["removed"] = hooks_diff.get("removed", {})
    hooks_script: dict[str, str] = {}
    if current_checksum is not None:
        hooks_script["current_checksum"] = current_checksum
    if new_checksum is not None:
        hooks_script["new_checksum"] = new_checksum
    if discover_current_checksum is not None:
        hooks_script["discover_current_checksum"] = discover_current_checksum
    if discover_new_checksum is not None:
        hooks_script["discover_new_checksum"] = discover_new_checksum
    if hooks_script:
        payload_dict["hooks_script"] = hooks_script
    redact_push_keys_in_data(payload_dict)
    payload = json.dumps(payload_dict)

    ok, detail = _invoke_hook_script(script_path, hook_client, push_key, url, payload, machine_id)
    if ok:
        rich.print("[green]\u2713[/green]  Test event sent  [green]\u2192 OK[/green]")
        return True
    rich.print(f"[red]\u2717[/red]  Test event failed: {detail}")
    return False


def _send_servers_discovered_event(
    push_key: str,
    url: str,
    hook_client: str,
    script_path: Path,
    machine_id: str,
    *,
    event_name: str = "serversDiscovered",
    session_marker: str = "hooks-setup",
    project_folders: list[str] | None = None,
) -> bool:
    rich.print("[dim]Discovering MCP servers...[/dim]")
    started = time.monotonic()
    try:
        servers = _discover_servers_payload(project_folders)
    except Exception as e:
        rich.print(f"[yellow]Warning:[/yellow] Could not discover MCP servers: {e}")
        return False
    duration_ms = round((time.monotonic() - started) * 1000)

    payload_dict: dict = {
        "hook_event_name": event_name,
        "servers": servers,
        "discovery_duration_ms": duration_ms,
    }
    if hook_client == "claude-code" or hook_client == "codex":
        payload_dict["session_id"] = session_marker
    else:
        payload_dict["conversation_id"] = session_marker
    redact_push_keys_in_data(payload_dict)
    payload = json.dumps(payload_dict)

    ok, detail = _invoke_hook_script(script_path, hook_client, push_key, url, payload, machine_id)
    if ok:
        server_count = sum(len(entry.get("servers", [])) for entry in servers)
        noun = "server" if server_count == 1 else "servers"
        rich.print(f"[green]\u2713[/green]  Discovered {server_count} MCP {noun}  [green]\u2192 OK[/green]")
        return True
    rich.print(f"[yellow]Warning:[/yellow] Could not send discovered MCP servers: {detail}")
    return False


# ---------------------------------------------------------------------------
# Detection / filtering
# ---------------------------------------------------------------------------


def _normalize_push_keys(value: object) -> object:
    """Replace push-key UUIDs with a placeholder for comparison purposes."""
    if isinstance(value, str):
        return redact_push_keys(value, "<PUSH_KEY>")
    if isinstance(value, dict):
        return {k: _normalize_push_keys(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_push_keys(item) for item in value]
    return value


def _extract_guard_hooks(entries: list) -> list:
    """Extract only guard (agent-scan) hooks from a list of hook entries/groups."""
    result = []
    for item in entries:
        if isinstance(item, dict) and "hooks" in item:
            if any(_is_agent_scan_command(h.get("command", "")) for h in item.get("hooks", [])):
                result.append(item)
        elif isinstance(item, dict) and _is_agent_scan_command(item.get("command", "")):
            result.append(item)
    return result


def _compute_hooks_diff(old_hooks: dict, new_hooks: dict) -> dict:
    """Compare existing hooks (old) against expected hooks (new).

    Only guard (agent-scan) hooks are compared; customer hooks are ignored.

    The diff reflects what someone changed in the existing config relative to
    what we expect:
    - "removed": expected keys missing from the existing config
    - "added": unexpected keys present in the existing config
    - "modified": keys present in both but with different values
      (each entry has "expected_value" and "actual_value")

    Differences that consist solely of a push-key change are ignored.
    """
    added = {}
    modified = {}
    removed = {}
    for key in set(old_hooks) | set(new_hooks):
        old_guard = _extract_guard_hooks(old_hooks.get(key, []) if isinstance(old_hooks.get(key), list) else [])
        new_guard = _extract_guard_hooks(new_hooks.get(key, []) if isinstance(new_hooks.get(key), list) else [])

        if not old_guard and not new_guard:
            continue
        if not old_guard and new_guard:
            removed[key] = copy.deepcopy(new_guard)
        elif old_guard and not new_guard:
            added[key] = copy.deepcopy(old_guard)
        else:
            old_norm = _normalize_push_keys(copy.deepcopy(old_guard))
            new_norm = _normalize_push_keys(copy.deepcopy(new_guard))
            if old_norm != new_norm:
                modified[key] = {
                    "expected_value": copy.deepcopy(new_guard),
                    "actual_value": copy.deepcopy(old_guard),
                }
    return {"added": added, "modified": modified, "removed": removed}


def _is_agent_scan_command(cmd: str) -> bool:
    return bool(_DETECTION_RE.search(cmd))


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


_CLIENT_LABELS = {"claude": "Claude Code", "cursor": "Cursor", "codex": "Codex"}
_HOOK_CLIENT_NAMES = {"claude": "claude-code", "cursor": "cursor", "codex": "codex"}


_CLIENT_INSTALL_PATHS = {
    "claude": Path.home() / ".claude",
    "cursor": Path.home() / ".cursor",
    "codex": Path.home() / ".codex",
}


def _is_client_installed(client: str) -> bool:
    """Check whether the agent is installed on this machine by looking for its config directory."""
    path = _CLIENT_INSTALL_PATHS.get(client)
    if path is None:
        return True
    try:
        return path.is_dir()
    except PermissionError:
        return False


def _client_label(client: str) -> str:
    return _CLIENT_LABELS.get(client, client)


def _hook_client_name(client: str) -> str:
    """Endpoint slug used on the agent-monitor side (and --client in the hook script)."""
    return _HOOK_CLIENT_NAMES.get(client, client)


def _config_path(client: str, override: str | None = None, managed: bool = False) -> Path:
    """Resolve the config file path for a client, with optional override."""
    if override:
        return Path(override)
    if managed:
        if client == "claude":
            return CLAUDE_MANAGED_SETTINGS_PATH
        if client == "cursor":
            return CURSOR_MANAGED_HOOKS_PATH
        return CODEX_MANAGED_HOOKS_PATH
    if client == "claude":
        return CLAUDE_SETTINGS_PATH
    if client == "cursor":
        return CURSOR_HOOKS_PATH
    return CODEX_HOOKS_PATH


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


def _build_hook_command(
    push_key: str,
    url: str,
    script_path: Path,
    hook_client: str,
    *,
    tenant_id: str = "",
    machine_id: str = "",
) -> str:
    if IS_WINDOWS:
        return _build_hook_command_powershell(
            push_key,
            url,
            script_path,
            hook_client,
            tenant_id=tenant_id,
            machine_id=machine_id,
        )
    parts = [
        f"PUSH_KEY={_shell_quote(push_key)}",
        f"REMOTE_HOOKS_BASE_URL={_shell_quote(url)}",
    ]
    if tenant_id:
        parts.append(f"TENANT_ID={_shell_quote(tenant_id)}")
    if machine_id:
        parts.append(f"MACHINE_ID={_shell_quote(machine_id)}")
    parts.append(f"bash {_shell_quote(script_path.as_posix())}")
    parts.append(f"--client {hook_client}")
    return " ".join(parts)


def _agent_scan_bin() -> str | None:
    if "AGENT_SCAN_BIN" in os.environ:
        return os.environ["AGENT_SCAN_BIN"]
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve())

    names = ("snyk-agent-scan.exe", "snyk-agent-scan") if IS_WINDOWS else ("snyk-agent-scan",)
    invoked_path = Path(sys.argv[0])
    if invoked_path.name in names and invoked_path.is_file() and os.access(invoked_path, os.X_OK):
        return str(invoked_path.resolve())

    for name in names:
        console_script = Path(sys.executable).parent / name
        if console_script.is_file() and os.access(console_script, os.X_OK):
            return str(console_script.resolve())
    return None


def _build_discover_hook_command(
    push_key: str,
    url: str,
    script_path: Path,
    hook_client: str,
    *,
    config_path: Path,
    tenant_id: str = "",
    machine_id: str = "",
) -> str:
    if IS_WINDOWS:
        return _build_discover_hook_command_powershell(
            push_key,
            url,
            script_path,
            hook_client,
            config_path=config_path,
            tenant_id=tenant_id,
            machine_id=machine_id,
        )
    parts = [
        f"PUSH_KEY={_shell_quote(push_key)}",
        f"REMOTE_HOOKS_BASE_URL={_shell_quote(url)}",
    ]
    if tenant_id:
        parts.append(f"TENANT_ID={_shell_quote(tenant_id)}")
    if machine_id:
        parts.append(f"MACHINE_ID={_shell_quote(machine_id)}")
    agent_scan_bin = _agent_scan_bin()
    if agent_scan_bin is not None:
        parts.append(f"AGENT_SCAN_BIN={_shell_quote(agent_scan_bin)}")
    parts.append(f"bash {_shell_quote(script_path.as_posix())}")
    parts.append(f"--client {_shell_quote(hook_client)}")
    parts.append(f"--file {_shell_quote(config_path.as_posix())}")
    return " ".join(parts)


def _build_discover_hook_command_powershell(
    push_key: str,
    url: str,
    script_path: Path,
    hook_client: str,
    *,
    config_path: Path,
    tenant_id: str = "",
    machine_id: str = "",
) -> str:
    command = (
        f"powershell -File {_ps_quote(str(script_path))} -Client {hook_client} "
        f"-PushKey {_ps_quote(push_key)} -RemoteUrl {_ps_quote(url)}"
    )
    if machine_id:
        command += f" -MachineId {_ps_quote(machine_id)}"
    command += f" -ConfigFile {_ps_quote(str(config_path))}"
    agent_scan_bin = _agent_scan_bin()
    if agent_scan_bin is not None:
        command += f" -AgentScanBin {_ps_quote(agent_scan_bin)}"
    return command


def _build_hook_command_powershell(
    push_key: str,
    url: str,
    script_path: Path,
    hook_client: str,
    *,
    tenant_id: str = "",
    machine_id: str = "",
) -> str:
    command = (
        f"powershell -File {_ps_quote(str(script_path))} -Client {hook_client} "
        f"-PushKey {_ps_quote(push_key)} -RemoteUrl {_ps_quote(url)}"
    )
    if machine_id:
        command += f" -MachineId {_ps_quote(machine_id)}"
    return command


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _ps_quote(s: str) -> str:
    """Quote a value for a PowerShell single-quoted literal."""
    return "'" + s.replace("'", "''") + "'"


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


class _HookScripts(NamedTuple):
    path: Path
    existed: bool
    updated: bool
    current_checksum: str | None
    new_checksum: str
    discover_current_checksum: str | None = None
    discover_new_checksum: str | None = None


def _copy_hook_script(config_path: Path, *, include_discover: bool = True) -> _HookScripts:
    """Copy bundled hook scripts to a hooks/ dir next to the config file.

    Checksums describe both the forwarding script and, when requested, the
    session-start discovery trampoline.
    """
    dest_dir = config_path.parent / "hooks"

    dest_dir.mkdir(parents=True, exist_ok=True)
    script_name = "snyk-agent-guard.ps1" if IS_WINDOWS else "snyk-agent-guard.sh"
    dest = dest_dir / script_name
    existed = dest.exists()

    current_checksum: str | None = None
    if existed:
        current_checksum = hashlib.sha256(dest.read_bytes()).hexdigest()

    from agent_scan.version import version_info

    hook_pkg = importlib_resources.files("agent_scan.hooks")
    source = hook_pkg.joinpath(script_name)
    new_content = source.read_bytes().replace(b"__AGENT_SCAN_VERSION__", version_info.encode())
    new_checksum = hashlib.sha256(new_content).hexdigest()

    discover_current_checksum: str | None = None
    discover_new_checksum: str | None = None
    discover_updated = False
    if include_discover:
        discover_name = "snyk-agent-guard-discover.ps1" if IS_WINDOWS else "snyk-agent-guard-discover.sh"
        discover_source = hook_pkg.joinpath(discover_name)
        discover_dest = dest_dir / discover_name
        discover_content = discover_source.read_bytes()
        discover_new_checksum = hashlib.sha256(discover_content).hexdigest()
        discover_existing_content: bytes | None = None
        if discover_dest.exists():
            discover_existing_content = discover_dest.read_bytes()
            discover_current_checksum = hashlib.sha256(discover_existing_content).hexdigest()
        if discover_existing_content != discover_content:
            discover_dest.write_bytes(discover_content)
            rich.print(f"[green]\u2713[/green]  Copied hook script to [dim]{discover_dest}[/dim]")
            discover_updated = True
        if not IS_WINDOWS:
            discover_dest.chmod(discover_dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    if existed and current_checksum == new_checksum:
        return _HookScripts(
            dest,
            existed,
            discover_updated,
            current_checksum,
            new_checksum,
            discover_current_checksum,
            discover_new_checksum,
        )

    dest.write_bytes(new_content)
    dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    rich.print(f"[green]\u2713[/green]  Copied hook script to [dim]{dest}[/dim]")
    return _HookScripts(
        dest,
        existed,
        True,
        current_checksum,
        new_checksum,
        discover_current_checksum,
        discover_new_checksum,
    )


def _remove_hook_script(client: str, config_path: Path) -> None:
    dest_dir = config_path.parent / "hooks"
    script_names = (
        ["snyk-agent-guard.ps1", "snyk-agent-guard-discover.ps1"]
        if IS_WINDOWS
        else [
            "snyk-agent-guard.sh",
            "snyk-agent-guard-discover.sh",
        ]
    )
    for script_name in script_names:
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
