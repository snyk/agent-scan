"""Agent Guard hook management for Claude Code, Cursor, and Codex."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import threading
import time
from importlib import resources as importlib_resources
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple, TypeVar
from urllib.parse import urlparse

import rich

# ``tomllib`` is stdlib from 3.11; fall back to the ``tomli`` backport on 3.10,
# else skip the generated TOML self-check rather than failing import.
try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 lacks stdlib TOML
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

from agent_scan.agents import DiscoveryScope
from agent_scan.hook_events import HOOK_CLIENTS, send_hook_event
from agent_scan.pushkeys import (
    GuardEnabledAccessDeniedError,
    _is_localhost,
    fetch_guard_enabled,
    mint_push_key,
    revoke_push_key,
)
from agent_scan.redact import redact_push_keys, redact_push_keys_in_data
from agent_scan.utils import toml_escape, toml_unescape

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from agent_scan.models import ClientToInspect

IS_WINDOWS = sys.platform == "win32"
_T = TypeVar("_T")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALL_CLIENTS = ["claude", "cursor", "codex"]
DEFAULT_REMOTE_URL = "https://api.snyk.io"
_DETECTION_RE = re.compile(
    r"PUSH_KEY=.*snyk-agent-guard"
    r"|snyk-agent-guard.*-PushKey\b",
    re.DOTALL,
)
_PERMISSION_DENIED = "__permission_denied__"
_STDIN_READ_TIMEOUT_SECONDS = 5.0
_DISCOVERY_TIMEOUT_SECONDS = 60.0
DEFAULT_INSTALLATION_ID = "primary"
_INSTALLATION_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9_-])?$")
_WINDOWS_DEVICE_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}

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
    except ValueError as e:
        rich.print(f"[bold red]Error:[/bold red] {e}")
        return 1


def _validate_installation_id(installation_id: str) -> str:
    """Validate and return an Agent Guard installation ID."""
    if not _INSTALLATION_ID_RE.fullmatch(installation_id):
        raise ValueError(
            "installation ID must be 1-64 lowercase characters containing only letters, numbers, '.', '_', or '-'"
        )
    if installation_id == "default":
        raise ValueError("installation ID 'default' is reserved")
    if installation_id.split(".", 1)[0] in _WINDOWS_DEVICE_NAMES:
        raise ValueError(f"installation ID '{installation_id}' uses a reserved Windows device name")
    return installation_id


def _selected_installation_id(args) -> str:
    """Resolve the optional CLI value only after argparse handles remove-all."""
    return _validate_installation_id(getattr(args, "installation_id", None) or DEFAULT_INSTALLATION_ID)


def _installation_scope(managed: bool) -> str:
    return "managed" if managed else "user"


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
    installation_id = _selected_installation_id(args)
    named_cli = hasattr(args, "installation_id")
    push_key = os.environ.get("PUSH_KEY", "")
    headless = bool(push_key)
    tenant_id: str = (getattr(args, "tenant_id", None) or "").strip()
    if not tenant_id:
        tenant_id = (os.environ.get("TENANT_ID", "") or "").strip()
    managed: bool = getattr(args, "managed", False)
    machine_id = (getattr(args, "machine_id", None) or os.environ.get("MACHINE_ID", "") or "").strip()
    if not machine_id:
        # Temporary compatibility fallback until ADS Installer supplies MACHINE_ID.
        from agent_scan.utils import get_hostname

        machine_id = get_hostname()
        rich.print(
            "[yellow]Warning:[/yellow] MACHINE_ID is not set; temporarily using the hostname. "
            "MACHINE_ID will become mandatory once ADS Installer is updated."
        )

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

    scope = _installation_scope(managed)
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

    first_installed_client: str | None = None
    try:
        for c in clients:
            install_kwargs = {"installation_id": installation_id} if named_cli else {}
            _install_hooks(
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
                **install_kwargs,
            )
            if first_installed_client is None:
                first_installed_client = _hook_client_name(c)
    except BaseException:
        if minted:
            if first_installed_client is not None:
                rich.print(
                    "[yellow]Warning:[/yellow] Installation partially completed. "
                    "The push key is still active for already-configured clients. "
                    "Run [bold]uninstall[/bold] to clean up if needed."
                )
            else:
                _revoke_after_failure(url, tenant_id, snyk_token, push_key)
        raise

    if first_installed_client is not None:
        installation_kwargs = {"installation_id": installation_id, "installation_scope": scope} if named_cli else {}
        _send_servers_discovered_event(
            push_key,
            url,
            first_installed_client,
            machine_id,
            discovery_scope=DiscoveryScope.SERVERS,
            max_retries=2,
            **installation_kwargs,
        )


def _run_with_timeout(
    func: Callable[[], _T],
    timeout: float,
) -> _T:
    """Run ``func`` on a daemon thread and abandon the worker on timeout.

    Discovery can block inside a recursive glob, ``open()`` on a FIFO, ``codesign``,
    or ``stat()`` on a dead mount. Those operations cannot be interrupted
    cooperatively, so the daemon worker is deliberately abandoned after the deadline.
    """
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


def _read_hook_payload() -> str:
    """Read hook JSON with a timeout; a blocked stdin read cannot be interrupted cooperatively."""
    stream = sys.stdin
    try:
        if stream is None or stream.isatty():
            return ""
        return _run_with_timeout(lambda: stream.read(1024 * 1024), _STDIN_READ_TIMEOUT_SECONDS)
    except Exception:
        return ""


def _run_discover(args) -> int:
    installation_id = _validate_installation_id(
        getattr(args, "installation_id", None)
        or os.environ.get("AGENT_GUARD_INSTALLATION_ID", "")
        or DEFAULT_INSTALLATION_ID
    )
    installation_scope = getattr(args, "installation_scope", None) or os.environ.get(
        "AGENT_GUARD_INSTALLATION_SCOPE", "user"
    )
    if installation_scope not in {"user", "managed"}:
        rich.print("[bold red]Error:[/bold red] installation scope must be 'user' or 'managed'.")
        return 1
    push_key = os.environ.get("PUSH_KEY", "")
    if not push_key:
        rich.print("[bold red]Error:[/bold red] PUSH_KEY is required to run guard discovery.")
        return 1

    url = getattr(args, "url", None) or os.environ.get("REMOTE_HOOKS_BASE_URL") or DEFAULT_REMOTE_URL
    hook_client = getattr(args, "client", None)
    if not hook_client:
        rich.print("[bold red]Error:[/bold red] --client is required to run guard discovery.")
        return 1
    machine_id = (os.environ.get("MACHINE_ID", "") or "").strip()
    if not machine_id:
        rich.print("[bold red]Error:[/bold red] MACHINE_ID is required to run guard discovery.")
        return 1

    target_folders: list[str] = []
    session_id = ""
    client = HOOK_CLIENTS[hook_client]
    try:
        hook_payload = json.loads(_read_hook_payload())
        target_folder = hook_payload.get(client.target_folder_field) if isinstance(hook_payload, dict) else None
        if isinstance(target_folder, str) and target_folder:
            target_folders.append(target_folder)
        elif isinstance(target_folder, list):
            target_folders.extend(folder for folder in target_folder if isinstance(folder, str) and folder)
        raw_session_id = hook_payload.get(client.session_field) if isinstance(hook_payload, dict) else None
        if isinstance(raw_session_id, str) and raw_session_id:
            session_id = raw_session_id
    except Exception:
        pass

    success = _send_servers_discovered_event(
        push_key,
        url,
        hook_client,
        machine_id,
        event_name="sessionStartServerDiscovery",
        session_marker=session_id or "session-start-server-discovery",
        target_folders=target_folders,
        discovery_scope=getattr(args, "scope", DiscoveryScope.ALL),
        installation_id=installation_id,
        installation_scope=installation_scope,
    )
    return 0 if success else 1


def _prepare_client_config(
    client: str,
    command: str,
    config_path: Path,
    *,
    discover_command: str | None = None,
    installation_id: str | None = DEFAULT_INSTALLATION_ID,
) -> tuple[dict | None, str | None, dict, int]:
    """Dispatch to the client-specific config preparation function.

    Returns (prepared_config, prepared_content, hooks_diff, preserved).
    """
    prepared_content: str | None = None
    prepared_config: dict | None = None
    preserved = 0
    if client == "claude":
        prepared_config, hooks_diff, preserved = _prepare_claude_config(
            command, config_path, discover_command=discover_command, installation_id=installation_id
        )
    elif client == "cursor":
        prepared_config, hooks_diff, preserved = _prepare_cursor_config(
            command, config_path, discover_command=discover_command, installation_id=installation_id
        )
    elif client == "codex":
        if _is_codex_requirements_toml(config_path):
            managed_kwargs = {"installation_id": installation_id} if installation_id is not None else {}
            prepared_content, hooks_diff = _prepare_codex_managed_config(
                command,
                config_path,
                discover_command=discover_command,
                **managed_kwargs,
            )
        else:
            prepared_config, hooks_diff, preserved = _prepare_codex_config(
                command, config_path, discover_command=discover_command, installation_id=installation_id
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
    """Write prepared config using JSON, except for managed Codex TOML."""
    if client not in ALL_CLIENTS:
        raise ValueError(f"Unknown client: {client}")
    if client == "codex" and _is_codex_requirements_toml(config_path):
        assert prepared_content is not None
        return _write_codex_managed_config(prepared_content, config_path)
    assert prepared_config is not None
    return _write_config(prepared_config, config_path, preserved)


def _detect_existing_installations(client: str, config_path: Path, *, scope: str = "user") -> list[dict]:
    """Return every existing install for *client* in a known config scope."""
    if client == "claude":
        return _detect_claude_installations(config_path, scope=scope)
    if client == "cursor":
        return _detect_cursor_installations(config_path, scope=scope)
    return _detect_codex_installations(config_path, scope=scope)


def _detect_existing_install(
    client: str,
    config_path: Path,
    *,
    installation_id: str = DEFAULT_INSTALLATION_ID,
    scope: str = "user",
) -> dict | None:
    """Compatibility wrapper returning one selected installation."""
    return next(
        (
            info
            for info in _detect_existing_installations(client, config_path, scope=scope)
            if info["installation_id"] == installation_id
        ),
        None,
    )


def _hooks_dir(config_path: Path) -> Path:
    return config_path.parent / "hooks"


def _forwarder_script_path(config_path: Path, installation_id: str | None = None) -> Path:
    name = "snyk-agent-guard.ps1" if IS_WINDOWS else "snyk-agent-guard.sh"
    return _hooks_dir(config_path) / installation_id / name if installation_id else _hooks_dir(config_path) / name


def _discover_script_path(config_path: Path, installation_id: str | None = None) -> Path:
    name = "snyk-agent-guard-discover.ps1" if IS_WINDOWS else "snyk-agent-guard-discover.sh"
    return _hooks_dir(config_path) / installation_id / name if installation_id else _hooks_dir(config_path) / name


def _legacy_script_paths(config_path: Path) -> tuple[Path, Path]:
    hooks_dir = _hooks_dir(config_path)
    main_name = "snyk-agent-guard.ps1" if IS_WINDOWS else "snyk-agent-guard.sh"
    discover_name = "snyk-agent-guard-discover.ps1" if IS_WINDOWS else "snyk-agent-guard-discover.sh"
    return hooks_dir / main_name, hooks_dir / discover_name


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
    installation_id: str | None = None,
) -> None:
    """Post-mint install steps.  Extracted so _run_install can revoke on failure."""
    named_installation = installation_id is not None
    effective_installation_id = installation_id or DEFAULT_INSTALLATION_ID
    existing_info = _detect_existing_install(
        client,
        config_path,
        installation_id=effective_installation_id,
        scope=scope,
    )
    old_push_key = existing_info.get("auth_value", "") if existing_info else ""
    push_key_changed = bool(old_push_key) and old_push_key != push_key

    configured_agent_scan_command = os.environ.get("AGENT_SCAN_COMMAND", "").strip()
    agent_scan_command = _agent_scan_command()
    install_discovery = agent_scan_command is not None
    if not configured_agent_scan_command and agent_scan_command is not None:
        rich.print(
            "[yellow]Warning:[/yellow] AGENT_SCAN_COMMAND is not set; temporarily using the current "
            "Agent Scan executable. AGENT_SCAN_COMMAND will become mandatory once ADS Installer is updated."
        )
    elif agent_scan_command is None:
        rich.print(
            "[yellow]Warning:[/yellow] AGENT_SCAN_COMMAND is not set; "
            "the session-start discovery hook will not be installed"
        )
    if named_installation:
        discover_script_path = _discover_script_path(config_path, effective_installation_id)
        forwarder_script_path = _forwarder_script_path(config_path, effective_installation_id)
    else:
        forwarder_script_path, discover_script_path = _legacy_script_paths(config_path)
    discover_script_existed = discover_script_path.exists()

    main_script = _copy_hook_script(forwarder_script_path)
    discover_script = _copy_hook_script(discover_script_path) if install_discovery else None

    dest_path = main_script.path
    script_updated = main_script.updated or bool(discover_script and discover_script.updated)
    command = _build_hook_command(
        push_key,
        url,
        dest_path,
        hook_client,
        tenant_id=tenant_id,
        machine_id=machine_id,
        installation_id=effective_installation_id if named_installation else "",
        installation_scope=scope if named_installation else "",
    )
    discover_command = None
    if install_discovery:
        assert agent_scan_command is not None
        discover_installation_kwargs = (
            {"installation_id": effective_installation_id, "installation_scope": scope} if named_installation else {}
        )
        discover_command = _build_discover_hook_command(
            push_key,
            url,
            discover_script_path,
            agent_scan_command=agent_scan_command,
            tenant_id=tenant_id,
            machine_id=machine_id,
            hook_client=hook_client,
            **discover_installation_kwargs,
        )
    prepared_config, prepared_content, hooks_diff, preserved = _prepare_client_config(
        client,
        command,
        config_path,
        discover_command=discover_command,
        installation_id=effective_installation_id if named_installation else None,
    )

    first_install = existing_info is None and not main_script.existed if named_installation else not main_script.existed
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
        current_checksum=main_script.current_checksum,
        new_checksum=main_script.new_checksum,
        discover_current_checksum=discover_script.current_checksum if discover_script else None,
        discover_new_checksum=discover_script.new_checksum if discover_script else None,
        machine_id=machine_id,
        **({"installation_id": effective_installation_id, "installation_scope": scope} if named_installation else {}),
    ):
        if not main_script.existed:
            dest_path.unlink(missing_ok=True)
        if not discover_script_existed:
            discover_script_path.unlink(missing_ok=True)
        rich.print("[bold red]Aborting install \u2014 test event failed.[/bold red]")
        raise SystemExit(1)

    config_written = _write_client_config(client, config_path, prepared_config, prepared_content, preserved)
    if not install_discovery and discover_script_path.exists():
        discover_script_path.unlink()
        rich.print(f"[green]✓[/green]  Removed stale hook script [dim]{discover_script_path}[/dim]")

    if named_installation and effective_installation_id == DEFAULT_INSTALLATION_ID:
        for legacy_path in _legacy_script_paths(config_path):
            if legacy_path.exists():
                legacy_path.unlink()
                rich.print(f"[green]✓[/green]  Removed legacy hook script [dim]{legacy_path}[/dim]")

    if script_updated or config_written or minted:
        rich.print(f"[green]\u2713[/green]  {scope.title()} hooks installed for [bold]{label}[/bold]")
    else:
        rich.print(f"[green]\u2713[/green]  {label} {scope} hook integration up to date")
    rich.print(f"   Config:     [dim]{config_path}[/dim]")
    rich.print(f"   Script:     [dim]{dest_path}[/dim]")
    rich.print(f"   Remote URL: [dim]{url}[/dim]")
    rich.print(f"   Push Key:   [yellow]{_mask_key(push_key)}[/yellow]")
    if named_installation:
        rich.print(f"   Installation: [bold]{effective_installation_id}[/bold] ({scope})")
    rich.print()


def _prepare_claude_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
    installation_id: str | None = None,
) -> tuple[dict, dict, int]:
    """Build new Claude settings with hooks and compute diff, without writing.

    Returns (new_settings, hooks_diff, preserved_count).
    """
    settings = _read_json_or_empty(path)
    old_hooks = settings.get("hooks", {})

    filtered = _filter_claude_hooks(old_hooks, installation_id=installation_id)
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
    diff = _compute_hooks_diff(old_hooks, hooks, installation_id=installation_id)
    return settings, diff, preserved


def _write_config(config: dict, path: Path, preserved: int) -> bool:
    """Write a client config to disk. Returns True if the file changed."""
    if not _write_json_if_changed(path, config):
        return False
    rich.print(f"[green]\u2713[/green]  Written [dim]{path}[/dim]{_preserved_note(preserved)}")
    return True


def _prepare_cursor_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
    installation_id: str | None = None,
) -> tuple[dict, dict, int]:
    """Build new Cursor config with hooks and compute diff, without writing.

    Returns (new_data, hooks_diff, preserved_count).
    """
    data = _read_json_or_empty(path)
    if "version" not in data:
        data["version"] = 1
    old_hooks = data.get("hooks", {})

    filtered = _filter_cursor_hooks(old_hooks, installation_id=installation_id)
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
    diff = _compute_hooks_diff(old_hooks, hooks, installation_id=installation_id)
    return data, diff, preserved


def _prepare_codex_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
    installation_id: str | None = None,
) -> tuple[dict, dict, int]:
    """Build new Codex config with hooks and compute diff, without writing.

    Returns (new_data, hooks_diff, preserved_count).
    Codex uses the same hooks.json shape as Claude Code.
    """
    data = _read_json_or_empty(path)
    old_hooks = data.get("hooks", {})

    filtered = _filter_claude_hooks(old_hooks, installation_id=installation_id)
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
    diff = _compute_hooks_diff(old_hooks, hooks, installation_id=installation_id)
    return data, diff, preserved


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


def _render_codex_requirements_toml(
    command: str,
    config_path: Path,
    *,
    discover_command: str | None = None,
) -> str:
    """Generate the requirements.toml content for managed Codex hooks."""
    managed_dir, windows_managed_dir = _codex_managed_dirs(config_path)
    lines = [
        "[features]",
        "hooks = true",
        "",
        "[hooks]",
        f"managed_dir = {toml_escape(managed_dir)}",
        f"windows_managed_dir = {toml_escape(windows_managed_dir)}",
        "",
    ]
    lines.extend(_render_codex_guard_groups({DEFAULT_INSTALLATION_ID: (command, discover_command)}))
    content = "\n".join(lines).rstrip("\n") + "\n"
    if tomllib is not None:  # pragma: no branch - available on supported installs
        try:
            tomllib.loads(content)
        except ValueError as exc:
            raise ValueError("Generated requirements.toml is invalid") from exc
    return content


def _installation_sort_key(installation_id: str) -> tuple[bool, str]:
    return installation_id != DEFAULT_INSTALLATION_ID, installation_id


def _render_codex_guard_groups(installations: dict[str, tuple[str, str | None]]) -> list[str]:
    """Render only Agent Guard-owned managed Codex hook groups."""
    lines: list[str] = []
    for installation_id in sorted(installations, key=_installation_sort_key):
        command, discover_command = installations[installation_id]
        for event in CODEX_HOOK_EVENTS:
            lines.append(f"[[hooks.{event}]]")
            lines.append(f"[[hooks.{event}.hooks]]")
            lines.append('type = "command"')
            lines.append(f"command = {toml_escape(command)}")
            lines.append("")
        if discover_command:
            lines.append("[[hooks.SessionStart]]")
            lines.append("[[hooks.SessionStart.hooks]]")
            lines.append('type = "command"')
            lines.append(f"command = {toml_escape(discover_command)}")
            lines.append("async = true")
            lines.append("")
    return lines


def _strip_codex_guard_groups(text: str) -> str:
    """Remove complete Agent Guard hook groups while preserving unrelated TOML."""
    lines = text.splitlines()
    parent_re = re.compile(r"^\s*\[\[hooks\.([A-Za-z]+)\]\]\s*$")
    child_re = re.compile(r"^\s*\[\[hooks\.([A-Za-z]+)\.hooks\]\]\s*$")
    kept: list[str] = []
    index = 0
    while index < len(lines):
        parent = parent_re.match(lines[index])
        if not parent:
            kept.append(lines[index])
            index += 1
            continue
        event = parent.group(1)
        end = index + 1
        while end < len(lines):
            if parent_re.match(lines[end]):
                break
            if lines[end].lstrip().startswith("["):
                child = child_re.match(lines[end])
                if not child or child.group(1) != event:
                    break
            end += 1
        group = "\n".join(lines[index:end])
        if not any(_is_agent_scan_command(command) for command in _toml_group_commands(group)):
            kept.extend(lines[index:end])
        index = end
    return "\n".join(kept).rstrip()


def _toml_group_commands(text: str) -> list[str]:
    command_re = re.compile(r'^\s*command\s*=\s*"((?:[^"\\]|\\.)*)"\s*$')
    return [toml_unescape(match.group(1)) for line in text.splitlines() if (match := command_re.match(line))]


def _upsert_toml_table_keys(text: str, table: str, values: dict[str, str]) -> str:
    """Set owned scalar keys in one TOML table without disturbing unrelated keys."""
    lines = text.splitlines()
    header = f"[{table}]"
    try:
        start = next(index for index, line in enumerate(lines) if line.strip() == header)
    except StopIteration:
        block = [header, *(f"{key} = {value}" for key, value in values.items()), ""]
        return "\n".join([*block, *lines]).rstrip()

    end = start + 1
    while end < len(lines) and not lines[end].lstrip().startswith("["):
        end += 1
    for key, value in values.items():
        key_re = re.compile(rf"^\s*{re.escape(key)}\s*=")
        existing = next((index for index in range(start + 1, end) if key_re.match(lines[index])), None)
        new_line = f"{key} = {value}"
        if existing is None:
            lines.insert(end, new_line)
            end += 1
        else:
            lines[existing] = new_line
    return "\n".join(lines).rstrip()


def _ensure_codex_managed_prelude(text: str, config_path: Path) -> str:
    managed_dir, windows_managed_dir = _codex_managed_dirs(config_path)
    text = _upsert_toml_table_keys(text, "features", {"hooks": "true"})
    return _upsert_toml_table_keys(
        text,
        "hooks",
        {
            "managed_dir": toml_escape(managed_dir),
            "windows_managed_dir": toml_escape(windows_managed_dir),
        },
    )


def _prepare_codex_managed_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
    installation_id: str = DEFAULT_INSTALLATION_ID,
) -> tuple[str, dict]:
    """Build new Codex managed TOML content and compute diff, without writing.

    Returns (new_content, hooks_diff).

    Existing Agent Guard groups are replaced as a set so they can be rendered in
    deterministic installation order; unrelated TOML remains byte-for-byte in
    its existing relative order.
    """
    old_text = ""
    if path.exists():
        old_text = path.read_text()
        if tomllib is not None:
            try:
                tomllib.loads(old_text)
            except ValueError:
                old_text = ""
    old_installations = _parse_codex_requirements_installations(old_text)
    commands = {info["installation_id"]: (info["command"], info.get("discover_command")) for info in old_installations}
    commands[installation_id] = (command, discover_command)

    if old_text:
        preserved = _ensure_codex_managed_prelude(_strip_codex_guard_groups(old_text), path)
        rendered_groups = "\n".join(_render_codex_guard_groups(commands)).rstrip()
        new_content = f"{preserved}\n\n{rendered_groups}\n" if preserved else f"{rendered_groups}\n"
    else:
        new_content = _render_codex_requirements_toml(command, path, discover_command=discover_command)

    if tomllib is not None:
        try:
            tomllib.loads(new_content)
        except ValueError as exc:
            raise ValueError("Generated requirements.toml is invalid") from exc

    old_hooks = _codex_managed_hooks_for_diff(old_installations)
    new_installations = _parse_codex_requirements_installations(new_content)
    new_hooks = _codex_managed_hooks_for_diff(new_installations)
    diff = _compute_hooks_diff(old_hooks, new_hooks, installation_id=installation_id)
    return new_content, diff


def _codex_managed_hooks_for_diff(installations: list[dict]) -> dict:
    hooks: dict[str, list[dict]] = {}
    for info in installations:
        for event in info["events"]:
            hooks.setdefault(event, []).append({"type": "command", "command": info["command"]})
        discover_command = info.get("discover_command")
        if discover_command:
            hooks.setdefault("SessionStart", []).append({"type": "command", "command": discover_command, "async": True})
    return hooks


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


def _is_discover_hook_command(command: str) -> bool:
    return bool(re.search(r"\bsnyk-agent-guard-discover(?:\.(?:sh|ps1))?\b", command, re.IGNORECASE))


def _parse_codex_requirements_toml(text: str) -> tuple[list[str], str | None, str | None]:
    """Extract Snyk Agent Guard events, guard command, and discovery command.

    Only scans hook command lines containing the agent-guard detection marker.
    """
    installations = _parse_codex_requirements_installations(text)
    if not installations:
        return [], None, None
    info = next(
        (item for item in installations if item["installation_id"] == DEFAULT_INSTALLATION_ID),
        installations[0],
    )
    return info["events"], info["command"], info.get("discover_command")


def _parse_codex_requirements_installations(text: str, *, scope: str = "managed") -> list[dict]:
    """Extract every Agent Guard installation from managed Codex TOML."""
    records: dict[str, dict] = {}
    current_event: str | None = None
    header_re = re.compile(r"^\[\[hooks\.([A-Za-z]+)(?:\.hooks)?\]\]\s*$")
    command_re = re.compile(r'^command\s*=\s*"((?:[^"\\]|\\.)*)"\s*$')
    for raw in text.splitlines():
        line = raw.strip()
        m = header_re.match(line)
        if m:
            current_event = m.group(1)
            continue
        if line.startswith("["):
            current_event = None
            continue
        m = command_re.match(line)
        if m and current_event:
            cmd = toml_unescape(m.group(1))
            if not _is_agent_scan_command(cmd):
                continue
            installation_id = _command_installation_id(cmd)
            record = records.setdefault(
                installation_id,
                {
                    "installation_id": installation_id,
                    "installation_scope": _command_installation_scope(cmd, scope),
                    "events": [],
                    "command": "",
                    "discover_command": None,
                },
            )
            if _is_discover_hook_command(cmd):
                if record["discover_command"] is None:
                    record["discover_command"] = cmd
            else:
                if current_event not in record["events"]:
                    record["events"].append(current_event)
                if not record["command"]:
                    record["command"] = cmd
    result = [record for record in records.values() if record["command"]]
    for record in result:
        record.update(_parse_command_info(record["command"], record["events"], scope=scope))
        record["discover_command"] = records[record["installation_id"]]["discover_command"]
        record["command"] = records[record["installation_id"]]["command"]
    return sorted(result, key=lambda item: _installation_sort_key(item["installation_id"]))


def _detect_codex_managed_install(path: Path) -> dict | None:
    installations = _detect_codex_managed_installations(path)
    return installations[0] if installations else None


def _detect_codex_managed_installations(path: Path, *, scope: str = "managed") -> list[dict]:
    return _parse_codex_requirements_installations(path.read_text(), scope=scope)


def _uninstall_codex_managed(path: Path, *, installation_id: str | None = None) -> None:
    if not path.exists():
        rich.print("[dim]No requirements.toml found. Nothing to uninstall.[/dim]")
        return
    text = path.read_text()
    installations = _parse_codex_requirements_installations(text)
    selected = [info for info in installations if installation_id is None or info["installation_id"] == installation_id]
    if not selected:
        rich.print("[dim]No Agent Guard hooks found.[/dim]")
        return
    remaining = [info for info in installations if info not in selected]
    preserved = _strip_codex_guard_groups(text)
    if remaining:
        commands = {info["installation_id"]: (info["command"], info.get("discover_command")) for info in remaining}
        rendered = "\n".join(_render_codex_guard_groups(commands)).rstrip()
        new_content = f"{preserved}\n\n{rendered}\n" if preserved else f"{rendered}\n"
    else:
        managed_dir, windows_managed_dir = _codex_managed_dirs(path)
        owned_prelude = "\n".join(
            [
                "[features]",
                "hooks = true",
                "",
                "[hooks]",
                f"managed_dir = {toml_escape(managed_dir)}",
                f"windows_managed_dir = {toml_escape(windows_managed_dir)}",
            ]
        )
        new_content = "" if preserved.strip() == owned_prelude.strip() else f"{preserved.rstrip()}\n"
    _backup_file(path)
    if new_content:
        path.write_text(new_content)
        rich.print(f"[green]✓[/green]  Removed Agent Guard installation(s) from [dim]{path}[/dim]")
    else:
        path.unlink()
        rich.print(f"[green]✓[/green]  Removed Agent Guard installation(s) (deleted [dim]{path}[/dim])")


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

    # Preserve the legacy helper-call behavior used by integrations that predate
    # named installations. CLI-parsed arguments always have both attributes.
    if not hasattr(args, "installation_id") and not hasattr(args, "all_installations_ids"):
        for c in clients:
            _uninstall_single_client(c, args, managed)
        return

    remove_all = bool(getattr(args, "all_installations_ids", False))
    selected_id = None if remove_all else _selected_installation_id(args)
    scope = _installation_scope(managed)
    inventory: list[dict] = []
    selected_by_client: dict[str, set[str]] = {}

    # Inventory every affected config and credential before the first mutation.
    for c in clients:
        config_path = _config_path(c, getattr(args, "file", None), managed=managed)
        installations = _detect_existing_installations(c, config_path, scope=scope)
        selected_ids = {
            info["installation_id"]
            for info in installations
            if selected_id is None or info["installation_id"] == selected_id
        }
        if selected_id is not None:
            selected_ids.add(selected_id)
        if remove_all and any(path.exists() for path in _legacy_script_paths(config_path)):
            selected_ids.add(DEFAULT_INSTALLATION_ID)
        selected_by_client[c] = selected_ids
        inventory.extend({**info, "client": c} for info in installations if info["installation_id"] in selected_ids)

    for c in clients:
        _uninstall_single_client(
            c,
            args,
            managed,
            installation_ids=selected_by_client[c],
            remove_all=remove_all,
        )

    remaining_credentials = _remaining_guard_credentials(clients, args, managed)
    if remaining_credentials is None:
        rich.print("[yellow]Warning:[/yellow] Could not inventory all remaining hooks; push keys were not revoked.")
        return
    revoked: set[tuple[str, str, str]] = set()
    for info in inventory:
        credential = _credential_identity(info)
        if not credential[2] or credential in revoked or credential in remaining_credentials:
            continue
        _try_revoke_push_key(info, _client_label(info["client"]))
        revoked.add(credential)


def _uninstall_single_client(
    client: str,
    args,
    managed: bool,
    *,
    installation_ids: set[str] | None = None,
    remove_all: bool = False,
) -> None:
    label = _client_label(client)
    scope = _installation_scope(managed)
    config_path = _config_path(client, getattr(args, "file", None), managed=managed)

    rich.print(f"Removing [bold magenta]Agent Guard[/bold magenta] {scope} hooks from [bold]{label}[/bold]")
    rich.print("[dim]Other hooks in the file will be preserved.[/dim]")
    rich.print()

    legacy_call = installation_ids is None
    info = _detect_existing_install(client, config_path, scope=scope) if legacy_call else None
    if installation_ids is None:
        installation_ids = {DEFAULT_INSTALLATION_ID}

    filter_installation_id = (
        None if remove_all or legacy_call else next(iter(installation_ids), DEFAULT_INSTALLATION_ID)
    )

    # Remove hooks from config
    if client == "codex" and _is_codex_requirements_toml(config_path):
        if legacy_call:
            _uninstall_codex_managed(config_path)
        elif remove_all:
            _uninstall_codex_managed(config_path, installation_id=None)
        else:
            _uninstall_codex_managed(config_path, installation_id=filter_installation_id)
    elif client in ALL_CLIENTS:
        _uninstall_hooks(
            config_path,
            filter_hooks=_filter_cursor_hooks if client == "cursor" else _filter_claude_hooks,
            prune_empty_hooks=client != "cursor",
            installation_id=filter_installation_id,
        )

    for installation_id in installation_ids:
        _remove_hook_script(config_path, installation_id, include_legacy=installation_id == DEFAULT_INSTALLATION_ID)

    if legacy_call and info and info.get("auth_value"):
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


def _credential_identity(info: dict) -> tuple[str, str, str]:
    return info.get("url", DEFAULT_REMOTE_URL), info.get("tenant_id", ""), info.get("auth_value", "")


def _remaining_guard_credentials(clients: list[str], args, managed: bool) -> set[tuple[str, str, str]] | None:
    """Collect credentials still referenced after uninstall, including the opposite known scope."""
    remaining: set[tuple[str, str, str]] = set()
    file_override = getattr(args, "file", None)
    checks = [
        (client, _config_path(client, managed=use_managed), _installation_scope(use_managed))
        for use_managed in (False, True)
        for client in ALL_CLIENTS
    ]
    if file_override is not None:
        checks.extend((client, Path(file_override), _installation_scope(managed)) for client in clients)
    seen: set[tuple[str, Path]] = set()
    for client, path, scope in checks:
        if (client, path) in seen:
            continue
        seen.add((client, path))
        try:
            remaining.update(
                _credential_identity(info)
                for info in _detect_existing_installations(client, path, scope=scope)
                if info.get("auth_value")
            )
        except (PermissionError, json.JSONDecodeError, UnicodeDecodeError):
            # If a config cannot be inventoried, conservatively avoid revoking.
            return None
    return remaining


def _uninstall_hooks(
    path: Path,
    *,
    filter_hooks: Callable[[dict], dict],
    prune_empty_hooks: bool,
    installation_id: str | None = None,
) -> None:
    if not path.exists():
        rich.print(f"[dim]No {path.name} found. Nothing to uninstall.[/dim]")
        return

    data = _read_json_or_empty(path)
    hooks = data.get("hooks", {})

    total_before = sum(len(groups) for groups in hooks.values())
    filtered = filter_hooks(hooks) if installation_id is None else filter_hooks(hooks, installation_id=installation_id)
    total_after = sum(len(groups) for groups in filtered.values())

    removed = total_before - total_after
    if removed == 0:
        rich.print("[dim]No Agent Guard hooks found.[/dim]")
        return

    _backup_file(path)
    if filtered or not prune_empty_hooks:
        data["hooks"] = filtered
    else:
        data.pop("hooks", None)
    _write_json(path, data)
    rich.print(f"[green]\u2713[/green]  Removed {removed} Agent Guard hook(s){_preserved_note(total_after)}")


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def _run_status() -> None:
    clients = (
        ("Claude Code", CLAUDE_SETTINGS_PATH, CLAUDE_MANAGED_SETTINGS_PATH, _detect_claude_installations),
        ("Cursor", CURSOR_HOOKS_PATH, CURSOR_MANAGED_HOOKS_PATH, _detect_cursor_installations),
        ("Codex", CODEX_HOOKS_PATH, CODEX_MANAGED_HOOKS_PATH, _detect_codex_installations),
    )

    rich.print("[bold]User-level hooks:[/bold]")
    for label, user_path, _, detect in clients:
        _print_client_status(label, user_path, detect(user_path, scope="user"))
        rich.print()

    rich.print("[bold]Managed hooks:[/bold]")
    for label, _, managed_path, detect in clients:
        info: dict | str | None
        try:
            info = detect(managed_path, scope="managed")
        except PermissionError:
            info = _PERMISSION_DENIED
        _print_client_status(label, managed_path, info)
        rich.print()

    rich.print("[dim]# interactive flow (user-level)[/dim]")
    rich.print("[dim]snyk-agent-scan guard install <client> --machine-id <machine-id>[/dim]")
    rich.print()
    rich.print("[dim]# managed flow[/dim]")
    rich.print("[dim]snyk-agent-scan guard install <client> --managed --machine-id <machine-id>[/dim]")
    rich.print()
    rich.print("[dim]# headless flow (MDM)[/dim]")
    rich.print(
        "[dim]PUSH_KEY=<YOUR_PUSH_KEY> snyk-agent-scan guard install <client> "
        "[--managed] --machine-id <machine-id>[/dim]"
    )
    rich.print()
    rich.print(
        "[dim]If hooks are already installed and up to date, install commands are no-ops. To uninstall use 'snyk-agent-scan guard uninstall <client>'[/dim]"
    )


def _print_client_status(label: str, path: Path, info: dict | list[dict] | str | None) -> None:
    rich.print(f"[bold white]{label}[/bold white]   [dim]{path}[/dim]")
    if isinstance(info, str):
        rich.print("    [yellow]UNREADABLE (permission denied)[/yellow]")
        return
    if info is None or info == []:
        rich.print("    [dim]NOT INSTALLED[/dim]")
        return

    installations = [info] if isinstance(info, dict) else info
    for installation in installations:
        auth_label = f"[yellow]\\[Push Key: {_mask_key(installation['auth_value'])}][/yellow]"
        hooks_suffix = _compact_events(installation["events"])
        rich.print(
            f"    [bold green]INSTALLED[/bold green]   "
            f"[bold cyan]\\[ID: {installation.get('installation_id', DEFAULT_INSTALLATION_ID)}][/bold cyan]   "
            f"[magenta]\\[Scope: {installation.get('installation_scope', 'user')}][/magenta]   "
            f"[bold white]\\[{installation['host']}][/bold white]   "
            f"{auth_label}   "
            f"[dim]{hooks_suffix}[/dim]"
        )


def _detect_claude_install(path: Path = CLAUDE_SETTINGS_PATH) -> dict | None:
    installations = _detect_claude_installations(path)
    return installations[0] if installations else None


def _detect_claude_installations(path: Path = CLAUDE_SETTINGS_PATH, *, scope: str = "user") -> list[dict]:
    return _detect_installations(path, CLAUDE_HOOK_EVENTS, _grouped_hook_commands, scope=scope)


def _detect_codex_install(path: Path = CODEX_HOOKS_PATH) -> dict | None:
    installations = _detect_codex_installations(path)
    return installations[0] if installations else None


def _detect_codex_installations(path: Path = CODEX_HOOKS_PATH, *, scope: str = "user") -> list[dict]:
    if _is_codex_requirements_toml(path):
        if not path.exists():
            return []
        return _detect_codex_managed_installations(path, scope=scope)
    return _detect_installations(path, CODEX_HOOK_EVENTS, _grouped_hook_commands, scope=scope)


def _detect_cursor_install(path: Path = CURSOR_HOOKS_PATH) -> dict | None:
    installations = _detect_cursor_installations(path)
    return installations[0] if installations else None


def _detect_cursor_installations(path: Path = CURSOR_HOOKS_PATH, *, scope: str = "user") -> list[dict]:
    return _detect_installations(path, CURSOR_HOOK_EVENTS, _flat_hook_commands, scope=scope)


def _grouped_hook_commands(group: dict) -> Iterable[str]:
    return (hook.get("command", "") for hook in group.get("hooks", []))


def _flat_hook_commands(entry: dict) -> Iterable[str]:
    return (entry.get("command", ""),)


def _detect_install(path: Path, events: list[str], commands: Callable[[dict], Iterable[str]]) -> dict | None:
    installations = _detect_installations(path, events, commands)
    return installations[0] if installations else None


def _detect_installations(
    path: Path,
    events: list[str],
    commands: Callable[[dict], Iterable[str]],
    *,
    scope: str = "user",
) -> list[dict]:
    if not path.exists():
        return []
    data = _read_json_or_empty(path)
    hooks = data.get("hooks", {})

    records: dict[str, dict] = {}
    for event in events:
        for entry in hooks.get(event, []):
            for command in commands(entry):
                if not _is_agent_scan_command(command):
                    continue
                installation_id = _command_installation_id(command)
                record = records.setdefault(installation_id, {"events": [], "command": ""})
                if not _is_discover_hook_command(command):
                    if event not in record["events"]:
                        record["events"].append(event)
                    if not record["command"]:
                        record["command"] = command

    result = [
        _parse_command_info(record["command"], record["events"], scope=scope)
        for record in records.values()
        if record["command"]
    ]
    return sorted(result, key=lambda item: _installation_sort_key(item["installation_id"]))


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


def _discover_servers_payload(
    target_folders: list[str] | None = None,
    *,
    discovery_scope: DiscoveryScope = DiscoveryScope.ALL,
) -> list[dict]:
    import asyncio

    from agent_scan import pipelines

    # Discovery only parses config files; timeout is unused because no server is started.
    inspect_args = pipelines.InspectArgs(
        timeout=0,
        tokens=[],
        paths=[],
        discovery_scope=discovery_scope,
        target_folders=target_folders or [],
    )
    clients_to_inspect, _, _ = _run_with_timeout(
        lambda: asyncio.run(pipelines.discover_clients_to_inspect(inspect_args)),
        _DISCOVERY_TIMEOUT_SECONDS,
    )
    return _servers_discovered_entries(clients_to_inspect)


def _invoke_hook_script(
    script_path: Path,
    hook_client: str,
    push_key: str,
    url: str,
    payload: str,
    *,
    machine_id: str,
    installation_id: str = "",
    installation_scope: str = "",
) -> tuple[bool, str]:
    import subprocess

    if not machine_id.strip():
        raise ValueError("machine ID is required")

    cmd, env = _render_argv(
        _HookInvocation(
            script_path=script_path,
            hook_client=hook_client,
            push_key=push_key,
            url=url,
            machine_id=machine_id,
            installation_id=installation_id,
            installation_scope=installation_scope,
        )
    )

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
    machine_id: str,
    installation_id: str = "",
    installation_scope: str = "",
) -> bool:
    """Send a test hooksConfigured event by invoking the hook script. Returns True on success."""
    if not machine_id.strip():
        raise ValueError("machine ID is required")
    payload_dict: dict = {"hook_event_name": "hooksConfigured"}
    payload_dict[HOOK_CLIENTS[hook_client].session_field] = "hooks-setup"
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

    ok, detail = _invoke_hook_script(
        script_path,
        hook_client,
        push_key,
        url,
        payload,
        machine_id=machine_id,
        installation_id=installation_id,
        installation_scope=installation_scope,
    )
    if ok:
        rich.print("[green]\u2713[/green]  Test event sent  [green]\u2192 OK[/green]")
        return True
    rich.print(f"[red]\u2717[/red]  Test event failed: {detail}")
    return False


def _send_servers_discovered_event(
    push_key: str,
    url: str,
    hook_client: str,
    machine_id: str,
    *,
    event_name: str = "hooksConfiguredServerDiscovery",
    session_marker: str = "hooks-setup",
    target_folders: list[str] | None = None,
    discovery_scope: DiscoveryScope = DiscoveryScope.ALL,
    max_retries: int = 1,
    installation_id: str = DEFAULT_INSTALLATION_ID,
    installation_scope: str = "user",
) -> bool:
    """Discover MCP servers and send an install- or session-scoped discovery event.

    The default event follows ``hooksConfigured`` during installation. Session-start
    callers override it with ``sessionStartServerDiscovery``.
    """
    rich.print("[dim]Discovering MCP servers...[/dim]")
    started = time.monotonic()
    try:
        servers = _discover_servers_payload(target_folders, discovery_scope=discovery_scope)
    except Exception as e:
        rich.print(f"[yellow]Warning:[/yellow] Could not discover MCP servers: {e}")
        return False
    duration_ms = round((time.monotonic() - started) * 1000)

    payload_dict: dict = {
        "hook_event_name": event_name,
        "servers": servers,
        "discovery_duration_ms": duration_ms,
    }
    payload_dict[HOOK_CLIENTS[hook_client].session_field] = session_marker
    redact_push_keys_in_data(payload_dict)
    payload = json.dumps(payload_dict)

    ok, detail = send_hook_event(
        url,
        hook_client,
        push_key,
        payload,
        machine_id,
        max_retries=max_retries,
        installation_id=installation_id,
        installation_scope=installation_scope,
    )
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


def _extract_guard_hooks(entries: list, *, installation_id: str | None = None) -> list:
    """Extract only guard (agent-scan) hooks from a list of hook entries/groups."""
    result = []
    for item in entries:
        if isinstance(item, dict) and "hooks" in item:
            if any(_command_matches_installation(h.get("command", ""), installation_id) for h in item.get("hooks", [])):
                result.append(item)
        elif isinstance(item, dict) and _command_matches_installation(item.get("command", ""), installation_id):
            result.append(item)
    return result


def _compute_hooks_diff(old_hooks: dict, new_hooks: dict, *, installation_id: str | None = None) -> dict:
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
        old_guard = _extract_guard_hooks(
            old_hooks.get(key, []) if isinstance(old_hooks.get(key), list) else [],
            installation_id=installation_id,
        )
        new_guard = _extract_guard_hooks(
            new_hooks.get(key, []) if isinstance(new_hooks.get(key), list) else [],
            installation_id=installation_id,
        )

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


def _command_installation_id(command: str) -> str:
    return _extract_env_from_cmd(command, "AGENT_GUARD_INSTALLATION_ID") or DEFAULT_INSTALLATION_ID


def _command_installation_scope(command: str, fallback: str) -> str:
    return _extract_env_from_cmd(command, "AGENT_GUARD_INSTALLATION_SCOPE") or fallback


def _command_matches_installation(command: str, installation_id: str | None) -> bool:
    if not _is_agent_scan_command(command):
        return False
    return installation_id is None or _command_installation_id(command) == installation_id


def _filter_claude_hooks(hooks: dict, *, installation_id: str | None = None) -> dict:
    result = {}
    for event, groups in hooks.items():
        filtered = [
            g
            for g in groups
            if not any(_command_matches_installation(h.get("command", ""), installation_id) for h in g.get("hooks", []))
        ]
        if filtered:
            result[event] = filtered
    return result


def _filter_cursor_hooks(hooks: dict, *, installation_id: str | None = None) -> dict:
    result = {}
    for event, entries in hooks.items():
        filtered = [e for e in entries if not _command_matches_installation(e.get("command", ""), installation_id)]
        if filtered:
            result[event] = filtered
    return result


# ---------------------------------------------------------------------------
# Command parsing
# ---------------------------------------------------------------------------


def _parse_command_info(cmd: str, events: list[str], *, scope: str = "user") -> dict:
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
        "installation_id": _command_installation_id(cmd),
        "installation_scope": _command_installation_scope(cmd, scope),
    }


_PS_PARAM_MAP = {
    "PUSH_KEY": "PushKey",
    "REMOTE_HOOKS_BASE_URL": "RemoteUrl",
    "TENANT_ID": "TenantId",
    "AGENT_GUARD_INSTALLATION_ID": "InstallationId",
    "AGENT_GUARD_INSTALLATION_SCOPE": "InstallationScope",
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


class _HookInvocation(NamedTuple):
    """What a hook script needs, independent of how the values are handed over."""

    script_path: Path
    hook_client: str
    push_key: str
    url: str
    machine_id: str = ""
    tenant_id: str = ""
    agent_scan_command: str = ""
    scope: str = ""
    quote_client: bool = False
    installation_id: str = ""
    installation_scope: str = ""


def _render_posix_command(invocation: _HookInvocation) -> str:
    parts = [
        f"PUSH_KEY={_shell_quote(invocation.push_key)}",
        f"REMOTE_HOOKS_BASE_URL={_shell_quote(invocation.url)}",
    ]
    if invocation.installation_id:
        parts.append(f"AGENT_GUARD_INSTALLATION_ID={_shell_quote(invocation.installation_id)}")
    if invocation.installation_scope:
        parts.append(f"AGENT_GUARD_INSTALLATION_SCOPE={_shell_quote(invocation.installation_scope)}")
    if invocation.tenant_id:
        parts.append(f"TENANT_ID={_shell_quote(invocation.tenant_id)}")
    if invocation.machine_id:
        parts.append(f"MACHINE_ID={_shell_quote(invocation.machine_id)}")
    if invocation.agent_scan_command:
        parts.append(f"AGENT_SCAN_COMMAND={_shell_quote(invocation.agent_scan_command)}")
    parts.append(f"bash {_shell_quote(invocation.script_path.as_posix())}")
    client = _shell_quote(invocation.hook_client) if invocation.quote_client else invocation.hook_client
    parts.append(f"--client {client}")
    if invocation.scope:
        parts.append(f"--scope {invocation.scope}")
    return " ".join(parts)


def _render_powershell_command(invocation: _HookInvocation) -> str:
    parts = [
        "powershell",
        "-File",
        _ps_quote(str(invocation.script_path)),
        "-Client",
        invocation.hook_client,
        "-PushKey",
        _ps_quote(invocation.push_key),
        "-RemoteUrl",
        _ps_quote(invocation.url),
    ]
    if invocation.installation_id:
        parts.extend(["-InstallationId", _ps_quote(invocation.installation_id)])
    if invocation.installation_scope:
        parts.extend(["-InstallationScope", _ps_quote(invocation.installation_scope)])
    if invocation.tenant_id and invocation.installation_id:
        parts.extend(["-TenantId", _ps_quote(invocation.tenant_id)])
    if invocation.machine_id:
        parts.extend(["-MachineId", _ps_quote(invocation.machine_id)])
    if invocation.agent_scan_command:
        parts.extend(["-AgentScanCommand", _ps_quote(invocation.agent_scan_command)])
    if invocation.scope:
        parts.extend(["-Scope", invocation.scope])
    return " ".join(parts)


def _render_argv(invocation: _HookInvocation) -> tuple[list[str], dict[str, str] | None]:
    if IS_WINDOWS:
        argv = [
            "powershell",
            "-File",
            str(invocation.script_path),
            "-Client",
            invocation.hook_client,
            "-PushKey",
            invocation.push_key,
            "-RemoteUrl",
            invocation.url,
        ]
        if invocation.installation_id:
            argv.extend(["-InstallationId", invocation.installation_id])
        if invocation.installation_scope:
            argv.extend(["-InstallationScope", invocation.installation_scope])
        if invocation.tenant_id and invocation.installation_id:
            argv.extend(["-TenantId", invocation.tenant_id])
        if invocation.machine_id:
            argv.extend(["-MachineId", invocation.machine_id])
        if invocation.agent_scan_command:
            argv.extend(["-AgentScanCommand", invocation.agent_scan_command])
        if invocation.scope:
            argv.extend(["-Scope", invocation.scope])
        return argv, None

    env = {
        **os.environ,
        "PUSH_KEY": invocation.push_key,
        "REMOTE_HOOKS_BASE_URL": invocation.url,
    }
    if invocation.installation_id:
        env["AGENT_GUARD_INSTALLATION_ID"] = invocation.installation_id
    if invocation.installation_scope:
        env["AGENT_GUARD_INSTALLATION_SCOPE"] = invocation.installation_scope
    if invocation.tenant_id:
        env["TENANT_ID"] = invocation.tenant_id
    if invocation.machine_id:
        env["MACHINE_ID"] = invocation.machine_id
    if invocation.agent_scan_command:
        env["AGENT_SCAN_COMMAND"] = invocation.agent_scan_command
    argv = ["bash", str(invocation.script_path), "--client", invocation.hook_client]
    if invocation.scope:
        argv.extend(["--scope", invocation.scope])
    return argv, env


def _build_hook_command(
    push_key: str,
    url: str,
    script_path: Path,
    hook_client: str,
    *,
    tenant_id: str = "",
    machine_id: str = "",
    installation_id: str = "",
    installation_scope: str = "",
) -> str:
    invocation = _HookInvocation(
        script_path=script_path,
        hook_client=hook_client,
        push_key=push_key,
        url=url,
        machine_id=machine_id,
        tenant_id=tenant_id,
        installation_id=installation_id,
        installation_scope=installation_scope,
    )
    if IS_WINDOWS:
        return _render_powershell_command(invocation)
    return _render_posix_command(invocation)


def _agent_scan_command() -> str | None:
    """Return the configured command or infer this Agent Scan executable."""
    configured = os.environ.get("AGENT_SCAN_COMMAND", "").strip()
    if configured:
        return configured

    # Temporary compatibility fallback until ADS Installer supplies AGENT_SCAN_COMMAND.
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).absolute())

    executable_name = "snyk-agent-scan.exe" if IS_WINDOWS else "snyk-agent-scan"
    console_script = Path(sys.executable).parent / executable_name
    if console_script.is_file() and os.access(console_script, os.X_OK):
        return str(console_script.absolute())
    return None


def _build_discover_hook_command(
    push_key: str,
    url: str,
    script_path: Path,
    hook_client: str,
    *,
    agent_scan_command: str,
    tenant_id: str = "",
    machine_id: str = "",
    installation_id: str = "",
    installation_scope: str = "",
) -> str:
    invocation = _HookInvocation(
        script_path=script_path,
        hook_client=hook_client,
        push_key=push_key,
        url=url,
        machine_id=machine_id,
        agent_scan_command=agent_scan_command,
        scope="servers",
        quote_client=True,
        installation_id=installation_id,
        installation_scope=installation_scope,
    )
    if IS_WINDOWS:
        return _render_powershell_command(invocation)
    return _render_posix_command(invocation)


def _build_hook_command_powershell(
    push_key: str,
    url: str,
    script_path: Path,
    hook_client: str,
    *,
    tenant_id: str = "",
    machine_id: str = "",
    installation_id: str = "",
    installation_scope: str = "",
) -> str:
    return _render_powershell_command(
        _HookInvocation(
            script_path=script_path,
            hook_client=hook_client,
            push_key=push_key,
            url=url,
            machine_id=machine_id,
            tenant_id=tenant_id,
            installation_id=installation_id,
            installation_scope=installation_scope,
        )
    )


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


class _CopiedScript(NamedTuple):
    path: Path
    existed: bool
    updated: bool
    current_checksum: str | None
    new_checksum: str


def _copy_hook_script(dest: Path) -> _CopiedScript:
    """Copy the bundled hook script named ``dest.name`` to *dest*.

    Handles both the forwarding hook and the session-start discovery trampoline;
    the bundled resource and the destination share a basename.
    """
    from agent_scan.version import version_info

    dest.parent.mkdir(parents=True, exist_ok=True)

    source = importlib_resources.files("agent_scan.hooks").joinpath(dest.name)
    new_content = source.read_bytes().replace(b"__AGENT_SCAN_VERSION__", version_info.encode())
    new_checksum = hashlib.sha256(new_content).hexdigest()

    current_content = dest.read_bytes() if dest.exists() else None
    current_checksum = None if current_content is None else hashlib.sha256(current_content).hexdigest()

    updated = current_content != new_content
    if updated:
        dest.write_bytes(new_content)
        rich.print(f"[green]\u2713[/green]  Copied hook script to [dim]{dest}[/dim]")
    if not IS_WINDOWS:
        dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    return _CopiedScript(dest, current_content is not None, updated, current_checksum, new_checksum)


def _remove_hook_script(
    config_path: Path | str,
    installation_id: str | Path = DEFAULT_INSTALLATION_ID,
    *,
    include_legacy: bool = False,
) -> None:
    # Compatibility with the former ``(client, config_path)`` helper shape.
    if isinstance(installation_id, Path):
        config_path = installation_id
        installation_id = DEFAULT_INSTALLATION_ID
        include_legacy = True
    config_path = Path(config_path)
    paths = [
        _forwarder_script_path(config_path, installation_id),
        _discover_script_path(config_path, installation_id),
    ]
    if include_legacy:
        paths.extend(_legacy_script_paths(config_path))
    for dest in paths:
        if dest.exists():
            dest.unlink()
            rich.print(f"[green]\u2713[/green]  Removed hook script [dim]{dest}[/dim]")
    installation_dir = _hooks_dir(config_path) / installation_id
    if installation_dir.is_dir() and not any(installation_dir.iterdir()):
        installation_dir.rmdir()


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
