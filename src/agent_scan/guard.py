"""Agent Guard hook management for Claude Code, Cursor, Codex, and GitHub Copilot."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import threading
import time
from importlib import resources as importlib_resources
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, TypeVar
from urllib.parse import urlparse

import rich
from rich.markup import escape

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
from agent_scan.agents.claude_desktop import ClaudeDesktopDiscoverer
from agent_scan.hook_events import (
    HOOK_CLIENTS,
    INSTALL_RETRY_POLICY,
    RetryPolicy,
    classify_failure_detail,
    next_retry_delay,
    send_hook_event,
)
from agent_scan.machine_auth import TOKEN_COMMAND_TIMEOUT_S, MachineAuth, MachineAuthError, fetch_access_token
from agent_scan.pushkeys import (
    GuardEnabledAccessDeniedError,
    _is_localhost,
    fetch_guard_enabled,
    mint_push_key,
    revoke_push_key,
)
from agent_scan.redact import redact_push_keys, redact_push_keys_in_data
from agent_scan.utils import get_readable_home_directories, toml_escape, toml_unescape

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping

    from agent_scan.models import ClientToInspect

IS_WINDOWS = sys.platform == "win32"
_T = TypeVar("_T")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALL_CLIENTS = ["claude", "cursor", "codex", "github-copilot"]
DEFAULT_REMOTE_URL = "https://api.snyk.io"
# Matches our hook commands by script name, so it recognises both the current commands,
# which carry no values, and those written by earlier versions, which prefixed the script
# with PUSH_KEY=... assignments (POSIX) or followed it with -PushKey ... (PowerShell).
_DETECTION_RE = re.compile(r"""(?:^|[/\\'"\s])snyk-agent-guard(?:-discover)?\.(?:sh|ps1)(?:['"\s]|$)""")
# Installation configuration read by the hook scripts, next to them in the hooks directory.
# Not a .json file: Copilot loads every *.json file in ~/.copilot/hooks as a hook config.
GUARD_CONFIG_NAME = "snyk-agent-guard.conf"
_GUARD_CONFIG_KEYS = (
    "PUSH_KEY",
    "ADS_TOKEN_COMMAND",
    "REMOTE_HOOKS_BASE_URL",
    "TENANT_ID",
    "MACHINE_ID",
    "MACHINE_SERIAL",
    "AGENT_SCAN_COMMAND",
)
# Tenant ids are UUIDs. The hook scripts put the id in the URL path unescaped, so install refuses
# one that would need escaping there.
_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
# The Windows hook passes the base URL to the token command in a hand-quoted argument string, so
# install refuses one that would need escaping there.
_BASE_URL_UNSAFE_RE = re.compile(r'["\\\s]')
# The bash hook puts the token in a double-quoted curl config line and refuses one with quotes,
# backslashes or control characters, so the Python fetch refuses the same tokens.
_TOKEN_UNSAFE_RE = re.compile(r'["\\\x00-\x1f\x7f]')
_PERMISSION_DENIED = "__permission_denied__"
# Install backs up a config file to ``<file>`` + this suffix. The name is Guard's own
# (unlike a plain ``<file>.backup``, which other tools also write), so uninstall can
# delete it without reading it.
_GUARD_BACKUP_SUFFIX = ".snyk-agent-guard.backup"
# What install adds to a JSON config besides its hooks; see _uninstall_hooks.
_GUARD_JSON_SCAFFOLDING: dict[str, tuple[dict, ...]] = {
    "claude": ({}, {"hooks": {}}),
    "codex": ({}, {"hooks": {}}),
    "cursor": ({"version": 1}, {"version": 1, "hooks": {}}),
    "github-copilot": ({"version": 1}, {"version": 1, "hooks": {}}),
}
_STDIN_READ_TIMEOUT_SECONDS = 5.0
_DISCOVERY_TIMEOUT_SECONDS = 60.0
# guard discover runs inside an agent hook (about 60 s) that also covers discovery, so its token
# fetch gets a short limit instead of the scan's TOKEN_COMMAND_TIMEOUT_S.
_DISCOVER_TOKEN_TIMEOUT_SECONDS = 10.0
_HOOK_SCRIPT_TIMEOUT_SECONDS = 15.0
# Extra time the forwarder subprocess gets beyond the install budget (interpreter startup, teardown).
_HOOK_SCRIPT_OVERHEAD_SECONDS = 2.0

CLAUDE_SETTINGS_PATH = Path.home() / ".claude" / "settings.json"
CURSOR_HOOKS_PATH = Path.home() / ".cursor" / "hooks.json"
CODEX_HOOKS_PATH = Path.home() / ".codex" / "hooks.json"
COPILOT_HOOKS_DIR = Path.home() / ".copilot" / "hooks"
COPILOT_HOOKS_PATH = COPILOT_HOOKS_DIR / "snyk-agent-guard.json"

# Managed (MDM / admin-deployed) config paths — OS-specific
# Codex managed hooks use a requirements.toml file at a system location
# (see https://developers.openai.com/codex/hooks#managed-hooks-from-requirementstoml).
if sys.platform == "darwin":
    CLAUDE_MANAGED_SETTINGS_PATH = Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    CURSOR_MANAGED_HOOKS_PATH = Path("/Library/Application Support/Cursor/hooks.json")
    CODEX_MANAGED_HOOKS_PATH = Path("/etc/codex/requirements.toml")
    COPILOT_MANAGED_HOOKS_PATH = Path("/etc/github-copilot/policy.d/snyk-agent-guard.json")
elif sys.platform == "win32":
    CLAUDE_MANAGED_SETTINGS_PATH = Path("C:/Program Files/ClaudeCode/managed-settings.json")
    CURSOR_MANAGED_HOOKS_PATH = Path("C:/ProgramData/Cursor/hooks.json")
    CODEX_MANAGED_HOOKS_PATH = Path("C:/ProgramData/OpenAI/Codex/requirements.toml")
    COPILOT_MANAGED_HOOKS_PATH = Path("C:/ProgramData/GitHub/Copilot/policy.d/snyk-agent-guard.json")
else:  # Linux and others
    CLAUDE_MANAGED_SETTINGS_PATH = Path("/etc/claude-code/managed-settings.json")
    CURSOR_MANAGED_HOOKS_PATH = Path("/etc/cursor/hooks.json")
    CODEX_MANAGED_HOOKS_PATH = Path("/etc/codex/requirements.toml")
    COPILOT_MANAGED_HOOKS_PATH = Path("/etc/github-copilot/policy.d/snyk-agent-guard.json")

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
    "SubagentStart",
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

COPILOT_HOOK_EVENTS = [
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "PreCompact",
    "SubagentStart",
    "SubagentStop",
    "Stop",
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
    except CodexRequirementsError as e:
        rich.print(f"[bold red]Error:[/bold red] {e}")
        return 1
    except MachineAuthError as e:
        rich.print(f"[bold red]Error:[/bold red] {escape(str(e))}")
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


class _MachineIdentity(NamedTuple):
    """What the ADS installer passes so the hooks authenticate as the enrolled machine.

    ``"<token_command>" token --base-url <base_url>`` prints a machine access token; the hooks
    call the tenant routes for ``tenant_id`` on ``base_url`` with it, never the push key.
    ``base_url`` is the install's ``--url`` (``REMOTE_HOOKS_BASE_URL`` in the hooks); the token
    command refuses any API other than the one the machine enrolled with.
    """

    token_command: str
    tenant_id: str
    base_url: str


def _machine_identity_from_env(tenant_id: str, base_url: str) -> _MachineIdentity | None:
    """ADS_TOKEN_COMMAND with ``tenant_id`` on ``base_url``, or None for push-key mode.

    Machine identity needs both ADS_TOKEN_COMMAND and TENANT_ID, as in ``scan``. TENANT_ID alone
    is the push-key flow's tenant. ADS_TOKEN_COMMAND without TENANT_ID prints a warning and
    uses the push key. ``base_url`` is the Guard URL (``--url`` / REMOTE_HOOKS_BASE_URL);
    ADS_BASE_URL is not used.
    """
    token_command = os.environ.get("ADS_TOKEN_COMMAND", "").strip()
    if not token_command:
        return None
    tenant_id = tenant_id.strip()
    if not tenant_id:
        rich.print(
            "[yellow]Warning:[/yellow] Machine identity needs ADS_TOKEN_COMMAND and TENANT_ID; "
            "TENANT_ID is not set, so Guard uses the push key."
        )
        return None
    return _MachineIdentity(token_command=token_command, tenant_id=tenant_id, base_url=base_url.strip())


def _fetch_machine_auth(identity: _MachineIdentity, *, timeout: float = TOKEN_COMMAND_TIMEOUT_S) -> MachineAuth:
    """Run the token command once and return the token for the Python-sent events.

    Raises MachineAuthError when the command is not an absolute path or fails; there is no
    push-key fallback.
    """
    if not os.path.isabs(identity.token_command):
        # A bare name is looked up in the hook's PATH, and on Windows in the current directory too.
        raise MachineAuthError("The token command must be an absolute path.")
    token = fetch_access_token(identity.token_command, identity.base_url, timeout=timeout)
    if _TOKEN_UNSAFE_RE.search(token):
        raise MachineAuthError(
            "The token command printed a token with quotes, backslashes or control characters, "
            "which the hook scripts cannot send."
        )
    return MachineAuth(base_url=identity.base_url, tenant_id=identity.tenant_id, access_token=token)


def _fresh_machine_auth(identity: _MachineIdentity, event: str) -> MachineAuth | None:
    """A token for a best-effort event sent late in the install, or None when the command fails now.

    An install for several clients can run for minutes after the install-time check, so each such
    event runs the token command again (it returns its cached token while that is still valid).
    """
    try:
        return _fetch_machine_auth(identity)
    except MachineAuthError as e:
        rich.print(f"[dim]Could not send the {event}: {escape(str(e))}[/dim]")
        return None


def _env_placeholders_from_args(
    args, headless: bool, push_key: str, url: str, machine_id: str, machine_serial: str
) -> dict[str, str] | None:
    """``--no-config-file`` / ``--env-placeholder``: None for a config-file install, else the
    placeholders. Exits on invalid input, before anything is minted or written."""
    items = getattr(args, "env_placeholder", None) or []
    if not getattr(args, "no_config_file", False):
        if items:
            rich.print("[bold red]Error:[/bold red] --env-placeholder needs --no-config-file.")
            sys.exit(1)
        return None
    if not headless:
        rich.print(
            "[bold red]Error:[/bold red] --no-config-file needs PUSH_KEY set: the hooks read the push key "
            "from their environment, so a key minted here would reach none of them."
        )
        sys.exit(1)
    try:
        placeholders = _parse_env_placeholders(items)
        values = {
            "PUSH_KEY": push_key,
            "REMOTE_HOOKS_BASE_URL": url,
            "MACHINE_ID": machine_id,
            "MACHINE_SERIAL": machine_serial,
            "AGENT_SCAN_COMMAND": _agent_scan_command() or "",
        }
        _check_env_mode(values, placeholders)
    except ValueError as e:
        rich.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
    return placeholders


def _run_install(args) -> None:
    client: str = args.client
    url: str = args.url
    push_key = os.environ.get("PUSH_KEY", "")
    headless = bool(push_key)
    tenant_id: str = (getattr(args, "tenant_id", None) or "").strip()
    if not tenant_id:
        tenant_id = (os.environ.get("TENANT_ID", "") or "").strip()
    managed: bool = getattr(args, "managed", False)
    machine_identity = _machine_identity_from_env(tenant_id, url)
    if machine_identity is not None:
        if managed:
            rich.print(
                "[bold red]Error:[/bold red] Managed installs use a push key; ADS_TOKEN_COMMAND "
                "(machine identity) is only for user installs. Unset it, or drop --managed."
            )
            sys.exit(1)
        if getattr(args, "no_config_file", False):
            # --no-config-file keeps the push key out of files; machine identity has none.
            rich.print(
                "[bold red]Error:[/bold red] Machine identity installs write snyk-agent-guard.conf; "
                "--no-config-file is only for push-key installs. Drop --no-config-file, or unset ADS_TOKEN_COMMAND."
            )
            sys.exit(1)
        if not _TENANT_ID_RE.match(machine_identity.tenant_id):
            rich.print("[bold red]Error:[/bold red] Machine identity: TENANT_ID is not a valid tenant id.")
            sys.exit(1)
        if _BASE_URL_UNSAFE_RE.search(machine_identity.base_url):
            rich.print(
                "[bold red]Error:[/bold red] Machine identity: --url must not contain quotes, "
                "backslashes or whitespace."
            )
            sys.exit(1)
        # Machine identity never uses a push key, so ignore any PUSH_KEY in the environment.
        push_key = ""
        headless = True
    machine_serial = os.environ.get("MACHINE_SERIAL", "").strip()
    machine_id = (getattr(args, "machine_id", None) or os.environ.get("MACHINE_ID", "") or "").strip()
    if not machine_id:
        # Temporary compatibility fallback until ADS Installer supplies MACHINE_ID.
        from agent_scan.utils import get_hostname

        machine_id = get_hostname()
        rich.print(
            "[yellow]Warning:[/yellow] MACHINE_ID is not set; temporarily using the hostname. "
            "MACHINE_ID will become mandatory once ADS Installer is updated."
        )

    env_placeholders = _env_placeholders_from_args(args, headless, push_key, url, machine_id, machine_serial)

    clients = ALL_CLIENTS if client == "all" else [client]

    if client == "all" and getattr(args, "file", None):
        rich.print("[bold red]Error:[/bold red] --file cannot be used with client 'all'.")
        sys.exit(1)

    # Filter out clients whose agent is not installed on this machine.
    # Skipped when --file is explicitly provided (the caller knows where to write).
    # A managed install writes to a system-wide path, so it is only checked when
    # --check-installed is set; the agent then counts as installed when any user's home
    # has it. Non-managed installs always check the invoking user's home.
    if not getattr(args, "file", None) and (not managed or getattr(args, "check_installed", False)):
        home_dirs = [home for home, _username in get_readable_home_directories(all_users=managed)]
        if not home_dirs:
            # get_readable_home_directories swallows enumeration errors and returns [],
            # which would otherwise skip every client and silently install nothing.
            rich.print("[bold red]Error:[/bold red] Could not find any readable user home directory.")
            sys.exit(1)
        installed_by_client = {c: _is_client_installed(c, home_dirs) for c in clients}
        skipped = [c for c in clients if not installed_by_client[c]]
        clients = [c for c in clients if installed_by_client[c]]
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

    if machine_identity is not None:
        # Check the token command once before touching any config. A failure fails the install:
        # there is no fallback to the push key.
        rich.print("[dim]Checking the machine identity token command...[/dim]")
        try:
            _fetch_machine_auth(machine_identity)
        except MachineAuthError as e:
            rich.print(
                f"[bold red]Error:[/bold red] Machine identity check failed: {escape(str(e))} "
                "No hooks were installed; machine identity never falls back to the push key."
            )
            sys.exit(1)
        rich.print("[green]\u2713[/green]  Machine identity token command works")

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
    failed_clients: list[str] = []
    try:
        for c in clients:
            try:
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
                    machine_serial,
                    machine_identity=machine_identity,
                    env_placeholders=env_placeholders,
                )
            except (SystemExit, Exception) as e:
                # With client=all one client's failure must not block the others.
                if client != "all":
                    raise
                failed_clients.append(c)
                if not isinstance(e, SystemExit):
                    rich.print(f"[bold red]Error:[/bold red] {_client_label(c)}: {e}")
                rich.print(f"[yellow]Warning:[/yellow] Installation failed for {_client_label(c)}; continuing.")
                continue
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

    if failed_clients and first_installed_client is None and minted:
        _revoke_after_failure(url, tenant_id, snyk_token, push_key)

    if first_installed_client is not None:
        machine_auth = (
            _fresh_machine_auth(machine_identity, "discovered MCP servers") if machine_identity is not None else None
        )
        if machine_identity is None or machine_auth is not None:
            _send_servers_discovered_event(
                push_key,
                url,
                first_installed_client,
                machine_id,
                discovery_scope=DiscoveryScope.SERVERS,
                retry_policy=INSTALL_RETRY_POLICY,
                machine_serial=machine_serial,
                machine_auth=machine_auth,
            )

    if failed_clients:
        names = ", ".join(_client_label(c) for c in failed_clients)
        rich.print(f"[bold red]Error:[/bold red] Installation failed for: {names}.")
        sys.exit(1)


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
    # A push key wins, as in the hook scripts: an ADS_TOKEN_COMMAND in the agent's environment
    # must not change a push-key hook. Machine identity hooks set PUSH_KEY empty.
    push_key = os.environ.get("PUSH_KEY", "")
    url = getattr(args, "url", None) or os.environ.get("REMOTE_HOOKS_BASE_URL") or DEFAULT_REMOTE_URL
    machine_identity = None if push_key else _machine_identity_from_env(os.environ.get("TENANT_ID", ""), url)
    if machine_identity is None and not push_key:
        rich.print("[bold red]Error:[/bold red] PUSH_KEY is required to run guard discovery.")
        return 1

    hook_client = getattr(args, "client", None)
    if not hook_client:
        rich.print("[bold red]Error:[/bold red] --client is required to run guard discovery.")
        return 1
    machine_serial = os.environ.get("MACHINE_SERIAL", "").strip()
    machine_id = (os.environ.get("MACHINE_ID", "") or "").strip()
    if not machine_id:
        rich.print("[bold red]Error:[/bold red] MACHINE_ID is required to run guard discovery.")
        return 1
    machine_auth: MachineAuth | None = None
    if machine_identity is not None:
        try:
            machine_auth = _fetch_machine_auth(machine_identity, timeout=_DISCOVER_TOKEN_TIMEOUT_SECONDS)
        except MachineAuthError as e:
            # Like an unreachable API: one line, no event, and never the push key.
            rich.print(f"[yellow]Warning:[/yellow] Could not send discovered MCP servers: {escape(str(e))}")
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
        machine_serial=machine_serial,
        event_name="sessionStartServerDiscovery",
        session_marker=session_id or "session-start-server-discovery",
        target_folders=target_folders,
        discovery_scope=getattr(args, "scope", DiscoveryScope.ALL),
        machine_auth=machine_auth,
    )
    return 0 if success else 1


def _prepare_client_config(
    client: str,
    command: str,
    config_path: Path,
    *,
    discover_command: str | None = None,
    config_values: Mapping[str, str] | None = None,
) -> tuple[dict | None, str | None, dict, int]:
    """Dispatch to the client-specific config preparation function.

    Returns (prepared_config, prepared_content, hooks_diff, preserved).
    """
    prepared_content: str | None = None
    prepared_config: dict | None = None
    preserved = 0
    if client == "claude":
        prepared_config, hooks_diff, preserved = _prepare_claude_config(
            command, config_path, discover_command=discover_command, config_values=config_values
        )
    elif client == "cursor":
        prepared_config, hooks_diff, preserved = _prepare_cursor_config(
            command, config_path, discover_command=discover_command, config_values=config_values
        )
    elif client == "github-copilot":
        prepared_config, hooks_diff, preserved = _prepare_copilot_config(
            command, config_path, discover_command=discover_command, config_values=config_values
        )
    elif client == "codex":
        if _is_codex_requirements_toml(config_path):
            prepared_content, hooks_diff = _prepare_codex_managed_config(
                command,
                config_path,
                discover_command=discover_command,
                config_values=config_values,
            )
        else:
            prepared_config, hooks_diff, preserved = _prepare_codex_config(
                command, config_path, discover_command=discover_command, config_values=config_values
            )
    else:
        raise ValueError(f"Unknown client: {client}")
    return prepared_config, prepared_content, hooks_diff, preserved


def _is_copilot_policy_path(path: Path) -> bool:
    """Whether *path* is a Copilot policy (managed) config rather than a user-level one.

    Keyed on the directory name rather than an equality check against
    COPILOT_MANAGED_HOOKS_PATH so that a ``--file`` override pointing into a policy.d
    directory is hardened too.
    """
    return path.parent.name == "policy.d"


def _harden_policy_file(path: Path) -> None:
    """Make a written file satisfy Copilot's policy-file requirements.

    GitHub refuses to load a POSIX policy file that is group- or world-writable (and
    requires root ownership, which follows from installing under sudo). The default
    umask usually produces an acceptable mode already, but a permissive umask would
    otherwise yield a silently ignored policy — so clear those bits explicitly rather
    than depending on the caller's environment.
    """
    if IS_WINDOWS:
        return
    try:
        mode = path.stat().st_mode
        path.chmod(mode & ~(stat.S_IWGRP | stat.S_IWOTH))
    except OSError as exc:
        rich.print(f"[yellow]Warning:[/yellow] Could not tighten permissions on {path}: {exc}")


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
        changed = _write_codex_managed_config(prepared_content, config_path)
        _remove_legacy_guard_backup(config_path)
        return changed
    assert prepared_config is not None
    changed = _write_config(prepared_config, config_path, preserved, client=client)
    _remove_legacy_guard_backup(config_path)
    if _is_copilot_policy_path(config_path):
        # Applied whether or not the config changed: an already-present file may have
        # been written with a permissive umask, in which case Copilot ignores it.
        _harden_policy_file(config_path)
        for script in sorted(_hooks_dir(config_path).glob("snyk-agent-guard*")):
            _harden_policy_file(script)
    return changed


def _detect_existing_install(client: str, config_path: Path) -> dict | None:
    """Return the existing install info for *client*, or None if not installed."""
    if client == "claude":
        return _detect_claude_install(config_path)
    if client == "cursor":
        return _detect_cursor_install(config_path)
    if client == "github-copilot":
        return _detect_copilot_install(config_path)
    return _detect_codex_install(config_path)


def _hooks_dir(config_path: Path) -> Path:
    # Copilot's user-level config file already lives inside a directory literally named
    # "hooks" (see COPILOT_HOOKS_DIR); avoid nesting another "hooks" folder inside it.
    # The managed policy.d file does not, so the script lands in policy.d/hooks — a
    # subdirectory, which Copilot's ``policy.d/*.json`` glob ignores.
    if config_path.parent.name == "hooks":
        return config_path.parent
    return config_path.parent / "hooks"


def _forwarder_script_path(config_path: Path) -> Path:
    name = "snyk-agent-guard.ps1" if IS_WINDOWS else "snyk-agent-guard.sh"
    return _hooks_dir(config_path) / name


def _discover_script_path(config_path: Path) -> Path:
    name = "snyk-agent-guard-discover.ps1" if IS_WINDOWS else "snyk-agent-guard-discover.sh"
    return _hooks_dir(config_path) / name


def _guard_config_path(config_path: Path) -> Path:
    return _hooks_dir(config_path) / GUARD_CONFIG_NAME


def _render_guard_config(values: dict[str, str]) -> bytes:
    """Render the hook scripts' configuration file: one ``KEY=value`` line per set value.

    The scripts split each line on the first ``=`` and take the rest verbatim, so values
    need no quoting; only line breaks and NUL, which would end or corrupt a line, are
    rejected. Raises ValueError before anything is written.
    """
    lines = ["# Snyk Agent Guard configuration. Written by `snyk-agent-scan guard install`."]
    for key in _GUARD_CONFIG_KEYS:
        value = values.get(key, "")
        if not value:
            continue
        if any(c in value for c in "\n\r\0"):
            raise ValueError(f"{key} must not contain line breaks or NUL characters")
        lines.append(f"{key}={value}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _parse_guard_config(text: str) -> dict[str, str]:
    """Parse guard configuration the way the hook scripts do: split on the first ``=``."""
    values: dict[str, str] = {}
    # Lines end at "\n" only, with a trailing "\r" dropped, as in the scripts. str.splitlines()
    # would also split on \f, \x1c-\x1e and \x85, which a value (e.g. a serial) may hold.
    for line in text.split("\n"):
        key, sep, value = line.removesuffix("\r").partition("=")
        if sep and key in _GUARD_CONFIG_KEYS:
            values[key] = value
    return values


def _read_guard_config(path: Path) -> dict[str, str]:
    """Read the guard configuration file; {} if it is missing or unreadable."""
    try:
        return _parse_guard_config(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError):
        return {}


def _write_guard_config(path: Path, content: bytes, *, managed: bool) -> bool:
    """Write the guard configuration file atomically. Returns True if it changed.

    The file holds the push key. A user install writes it private (0600); a managed
    install is root-owned and must be readable by every user whose agent runs the
    hooks, hence 0644. A file that already has this content and mode is left alone.
    """
    mode = 0o644 if managed else 0o600
    try:
        unchanged = path.read_bytes() == content and (IS_WINDOWS or stat.S_IMODE(path.stat().st_mode) == mode)
    except OSError:
        unchanged = False
    if unchanged:
        return False
    _atomic_write_text(path, content.decode("utf-8"), mode=mode, newline="")
    rich.print(f"[green]\u2713[/green]  Wrote guard configuration to [dim]{path}[/dim]")
    return True


# Env mode (guard install --no-config-file): the hook commands set the values in their
# environment, from placeholders such as PUSH_KEY="$SNYK_PUSH_KEY" or as literals, in this order.
_ENV_MODE_KEYS = ("PUSH_KEY", "REMOTE_HOOKS_BASE_URL", "MACHINE_ID", "MACHINE_SERIAL", "AGENT_SCAN_COMMAND")
_ENV_MODE_FORWARDER_KEYS = _ENV_MODE_KEYS[:4]
_ENV_VAR_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# The endpoints the hook scripts accept from their environment (ENV_URL_RE in the .sh,
# $EnvUrlPattern in the .ps1): https to snyk.io, snykgov.io or a subdomain, or localhost.
_ENV_MODE_URL_RE = re.compile(
    r"(https://([A-Za-z0-9-]+\.)*(snyk|snykgov)\.io|https?://(localhost|127\.0\.0\.1))(:[0-9]+)?(/.*)?"
)
_FROM_ENV_RE = re.compile(r"(?:^|\s)(?:--from-env|-FromEnv)(?:\s|$)")
_PLACEHOLDER_VALUE_RE = re.compile(r'"\$([A-Za-z_][A-Za-z0-9_]*)"')


def _parse_env_placeholders(items: Iterable[str]) -> dict[str, str]:
    """Parse ``--env-placeholder NAME=VAR`` arguments into ``{NAME: VAR}``. Raises ValueError."""
    placeholders: dict[str, str] = {}
    for item in items:
        name, sep, var = item.partition("=")
        if not sep or name not in _ENV_MODE_KEYS:
            raise ValueError(f"--env-placeholder takes NAME=VAR with NAME one of {', '.join(_ENV_MODE_KEYS)}: {item}")
        if not _ENV_VAR_NAME_RE.fullmatch(var):
            raise ValueError(f"--env-placeholder {name}: {var!r} is not an environment variable name")
        placeholders[name] = var
    return placeholders


def _check_env_mode(values: Mapping[str, str], placeholders: Mapping[str, str]) -> None:
    """Refuse an env-mode install whose hooks would not work or would carry the push key."""
    if "PUSH_KEY" not in placeholders:
        raise ValueError(
            "--no-config-file needs --env-placeholder PUSH_KEY=<VAR>: the push key is never written into a hook command"
        )
    if not _ENV_MODE_URL_RE.fullmatch(values["REMOTE_HOOKS_BASE_URL"]):
        raise ValueError(
            "--no-config-file needs a Snyk --url (https to snyk.io or snykgov.io): "
            "the hook scripts accept no other endpoint from their environment"
        )
    if IS_WINDOWS:
        # `powershell -File` cannot set environment variables, so the hooks can only read
        # each value from a variable of its own name.
        renamed = sorted(name for name, var in placeholders.items() if name != var)
        missing = sorted(name for name in _ENV_MODE_KEYS if values.get(name) and name not in placeholders)
        if renamed or missing:
            raise ValueError(
                "on Windows, --no-config-file needs every value as --env-placeholder NAME=NAME "
                f"(renamed: {', '.join(renamed) or 'none'}; missing: {', '.join(missing) or 'none'})"
            )


def _env_mode_prefix(
    values: Mapping[str, str], placeholders: Mapping[str, str], keys: Iterable[str]
) -> tuple[str, ...]:
    """The POSIX assignments an env-mode hook command starts with."""
    if IS_WINDOWS:
        return ()
    parts = []
    for key in keys:
        if key in placeholders:
            parts.append(f'{key}="${placeholders[key]}"')
        elif values.get(key):
            parts.append(f"{key}={_shell_quote(values[key])}")
    return tuple(parts)


def _env_mode_test_environment(values: Mapping[str, str]) -> dict[str, str]:
    """The environment the install's test event gives an env-mode script: the values being
    installed under their own names, as the hook commands will set them."""
    env = {k: v for k, v in os.environ.items() if k not in (*_ENV_MODE_KEYS, "PUSHKEY")}
    env.update({k: values[k] for k in _ENV_MODE_FORWARDER_KEYS if values.get(k)})
    return env


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
    machine_serial: str,
    *,
    machine_identity: _MachineIdentity | None = None,
    env_placeholders: Mapping[str, str] | None = None,
) -> None:
    """Post-mint install steps.  Extracted so _run_install can revoke on failure.

    With ``machine_identity`` the configuration file holds it instead of the push key
    (``push_key`` is empty), and the events sent from here authenticate with a machine token.

    With *env_placeholders* (``guard install --no-config-file``) no guard configuration
    file is written: the hook commands pass ``--from-env`` and set the values in their
    environment, from those placeholders or as literals.
    """
    if client == "codex" and _is_codex_requirements_toml(config_path):
        # Check the edit before any hook script is written.
        _preflight_codex_requirements(config_path)
    existing_info = _detect_existing_install(client, config_path)
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
    if not machine_id.strip():
        raise ValueError("machine ID is required")
    forwarder_script_path = _forwarder_script_path(config_path)
    discover_script_path = _discover_script_path(config_path)
    guard_config_path = _guard_config_path(config_path)
    config_values = {
        "PUSH_KEY": push_key,
        "REMOTE_HOOKS_BASE_URL": url,
        "TENANT_ID": tenant_id,
        "MACHINE_ID": machine_id,
        # Empty is left out of the file; the scripts then send no serial and never take one
        # from their environment.
        "MACHINE_SERIAL": machine_serial,
        "AGENT_SCAN_COMMAND": agent_scan_command or "",
    }
    if machine_identity is not None:
        # The scripts use machine identity when the file holds ADS_TOKEN_COMMAND and no push key.
        config_values.update(
            {
                "PUSH_KEY": "",
                "ADS_TOKEN_COMMAND": machine_identity.token_command,
                "REMOTE_HOOKS_BASE_URL": machine_identity.base_url,
                "TENANT_ID": machine_identity.tenant_id,
            }
        )
    env_mode = env_placeholders is not None
    if env_placeholders is not None:
        _check_env_mode(config_values, env_placeholders)
    # Rendered (and validated) before any file is touched.
    guard_config = _render_guard_config(config_values)

    # The configuration file holds the hook values and is written before the test event,
    # which runs the installed script against it. If the install fails before the agent
    # config is written (the test event is rejected, or anything raises), the previous file
    # and scripts are put back so hooks that are already installed keep working, including
    # commands written by an earlier version, which need its scripts.
    previous_config = guard_config_path.read_bytes() if guard_config_path.is_file() else None
    # Checksummed like the scripts: agent-monitor compares the current checksum with the
    # new one the previous install reported, so an edit made between installs is caught
    # while a value this install legitimately changes (e.g. a rotated push key) is not.
    config_current_checksum = None if previous_config is None else hashlib.sha256(previous_config).hexdigest()
    config_new_checksum = None if env_mode else hashlib.sha256(guard_config).hexdigest()
    # The configuration goes first: a script that finds none refuses to run, so the
    # new scripts must never be live before the file they read is in place.
    main_script: _CopiedScript | None = None
    discover_script: _CopiedScript | None = None
    try:
        if env_mode:
            # A configuration file would win over the environment, so none may be left.
            guard_config_updated = previous_config is not None
            guard_config_path.unlink(missing_ok=True)
        else:
            guard_config_updated = _write_guard_config(guard_config_path, guard_config, managed=scope == "managed")
        main_script = _copy_hook_script(forwarder_script_path)
        discover_script = _copy_hook_script(discover_script_path) if install_discovery else None

        dest_path = main_script.path
        script_updated = main_script.updated or bool(discover_script and discover_script.updated)
        # Env mode only: the commands set the values and pass --from-env.
        forwarder_env: dict = {}
        discover_env: dict = {}
        if env_placeholders is not None:
            forwarder_env = {
                "prefix": _env_mode_prefix(config_values, env_placeholders, _ENV_MODE_FORWARDER_KEYS),
                "from_env": True,
            }
            discover_env = {
                "prefix": _env_mode_prefix(config_values, env_placeholders, _ENV_MODE_KEYS),
                "from_env": True,
            }
        command = _build_hook_command(dest_path, hook_client, **forwarder_env)
        discover_command = (
            _build_discover_hook_command(discover_script_path, hook_client, **discover_env)
            if install_discovery
            else None
        )
        prepared_config, prepared_content, hooks_diff, preserved = _prepare_client_config(
            client,
            command,
            config_path,
            discover_command=discover_command,
            config_values=config_values,
        )

        first_install = not main_script.existed
        config_changed = bool(hooks_diff["added"] or hooks_diff["modified"] or hooks_diff["removed"])

        test_event = _send_test_event(
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
            config_current_checksum=config_current_checksum,
            config_new_checksum=config_new_checksum,
            **({"env": _env_mode_test_environment(config_values)} if env_mode else {}),
        )
        if test_event.status == "rejected":
            rich.print("[bold red]Aborting install \u2014 test event failed.[/bold red]")
            raise SystemExit(1)
        if test_event.status == "unconfirmed":
            _warn_test_event_unconfirmed(test_event)
            machine_auth = (
                _fresh_machine_auth(machine_identity, "unconfirmed test event report")
                if machine_identity is not None
                else None
            )
            if machine_identity is None or machine_auth is not None:
                _report_test_event_unconfirmed(
                    push_key,
                    url,
                    hook_client,
                    machine_id,
                    test_event,
                    machine_serial=machine_serial,
                    machine_auth=machine_auth,
                )

        config_written = _write_client_config(client, config_path, prepared_config, prepared_content, preserved)
    except BaseException:
        # Nothing is live until the agent config is written: put back what was there before.
        if previous_config is None:
            guard_config_path.unlink(missing_ok=True)
        else:
            _write_guard_config(guard_config_path, previous_config, managed=scope == "managed")
        for script in (main_script, discover_script):
            if script is not None:
                _restore_hook_script(script)
        raise
    if not install_discovery and discover_script_path.exists():
        discover_script_path.unlink()
        rich.print(f"[green]✓[/green]  Removed stale hook script [dim]{discover_script_path}[/dim]")

    if script_updated or guard_config_updated or config_written or minted:
        rich.print(f"[green]\u2713[/green]  {scope.title()} hooks installed for [bold]{label}[/bold]")
    else:
        rich.print(f"[green]\u2713[/green]  {label} {scope} hook integration up to date")
    rich.print(f"   Config:     [dim]{config_path}[/dim]")
    rich.print(f"   Script:     [dim]{dest_path}[/dim]")
    if machine_identity is not None:
        rich.print(f"   Remote URL: [dim]{machine_identity.base_url}[/dim]")
        rich.print(f"   Auth:       [yellow]Machine identity (tenant {machine_identity.tenant_id})[/yellow]")
        if old_push_key:
            # Revoking needs a Snyk API token, which a machine identity install does not have.
            rich.print(
                f"[yellow]Warning:[/yellow] The previous push key {_mask_key(old_push_key)} is no longer "
                "used by these hooks but stays active. Revoke it in Snyk if nothing else uses it."
            )
    else:
        rich.print(f"   Remote URL: [dim]{url}[/dim]")
        rich.print(f"   Push Key:   [yellow]{_mask_key(push_key)}[/yellow]")
    if env_placeholders is not None:
        needed = ", ".join(sorted(set(env_placeholders.values())))
        rich.print(
            f"   Values:     [dim]from the hooks' environment; it must provide {needed} "
            "(install cannot check that)[/dim]"
        )
    rich.print()


def _warn_test_event_unconfirmed(result: _TestEventResult) -> None:
    rich.print(
        f"[yellow]Warning:[/yellow] Test event was not confirmed after {result.attempts} "
        f"attempt{'s' if result.attempts != 1 else ''} over {result.elapsed:.0f}s. "
        f"Last error: [bold]{result.error}[/bold] \u2014 {_describe_error(result.error)}. "
        "Continuing the installation; hooks will report once the service is reachable."
    )


def _report_test_event_unconfirmed(
    push_key: str,
    url: str,
    hook_client: str,
    machine_id: str,
    result: _TestEventResult,
    *,
    machine_serial: str,
    machine_auth: MachineAuth | None = None,
) -> None:
    """Best-effort telemetry: the install continued although the test event never got through."""
    payload_dict = {
        "hook_event_name": "hooksConfiguredTestEventUnconfirmed",
        HOOK_CLIENTS[hook_client].session_field: "hooks-setup",
        "test_event_attempts": result.attempts,
        "test_event_elapsed_ms": round(result.elapsed * 1000),
        "test_event_last_error": result.error,
    }
    ok, detail = send_hook_event(
        url,
        hook_client,
        push_key,
        json.dumps(payload_dict),
        machine_id,
        machine_serial=machine_serial,
        machine_auth=machine_auth,
    )
    if not ok:
        rich.print(f"[dim]Could not report the unconfirmed test event: {detail}[/dim]")


def _prepare_claude_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
    config_values: Mapping[str, str] | None = None,
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
    diff = _compute_hooks_diff(old_hooks, hooks, config_values=config_values)
    return settings, diff, preserved


def _write_config(config: dict, path: Path, preserved: int, *, client: str) -> bool:
    """Write *client*'s JSON config to disk. Returns True if the file changed."""
    if not _write_json_if_changed(path, config, client=client):
        return False
    rich.print(f"[green]\u2713[/green]  Written [dim]{path}[/dim]{_preserved_note(preserved)}")
    return True


def _prepare_cursor_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
    config_values: Mapping[str, str] | None = None,
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
    diff = _compute_hooks_diff(old_hooks, hooks, config_values=config_values)
    return data, diff, preserved


def _prepare_copilot_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
    config_values: Mapping[str, str] | None = None,
) -> tuple[dict, dict, int]:
    """Build new GitHub Copilot hooks config and compute diff, without writing.

    Returns (new_data, hooks_diff, preserved_count).
    Copilot uses a flat hooks.json shape like Cursor's, but each entry needs an
    explicit ``"type": "command"`` per its hooks schema. The same shape serves the
    user-level file and the managed policy.d file; only the path differs.
    """
    data = _read_json_or_empty(path)
    if "version" not in data:
        data["version"] = 1
    old_hooks = data.get("hooks", {})

    filtered = _filter_copilot_hooks(old_hooks)
    preserved = sum(len(filtered.get(event, [])) for event in COPILOT_HOOK_EVENTS)
    hooks = {}

    for event in COPILOT_HOOK_EVENTS:
        existing = list(filtered.get(event, []))
        existing.append(_copilot_command_entry(command))
        hooks[event] = existing

    if discover_command:
        hooks["SessionStart"].append(_copilot_command_entry(discover_command))

    for event, entries in filtered.items():
        if event not in hooks:
            hooks[event] = entries

    data["hooks"] = hooks
    diff = _compute_hooks_diff(old_hooks, hooks, config_values=config_values)
    return data, diff, preserved


def _prepare_codex_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
    config_values: Mapping[str, str] | None = None,
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
    diff = _compute_hooks_diff(old_hooks, hooks, config_values=config_values)
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


class CodexRequirementsError(ValueError):
    """requirements.toml can't be edited safely. The file is left untouched."""


def _codex_guard_hook_blocks(command: str, *, discover_command: str | None = None) -> list[str]:
    """Guard's ``[[hooks.<Event>]]`` groups, one newline-terminated block each."""
    blocks = [
        f'[[hooks.{event}]]\n[[hooks.{event}.hooks]]\ntype = "command"\ncommand = {toml_escape(command)}\n'
        for event in CODEX_HOOK_EVENTS
    ]
    if discover_command:
        blocks.append(
            "[[hooks.SessionStart]]\n"
            "[[hooks.SessionStart.hooks]]\n"
            'type = "command"\n'
            f"command = {toml_escape(discover_command)}\n"
            "async = true\n"
        )
    return blocks


def _codex_hooks_dir_lines(keys_and_values: Iterable[tuple[str, str]]) -> str:
    return "".join(f"{key} = {toml_escape(value)}\n" for key, value in keys_and_values)


def _render_codex_requirements_toml(
    command: str,
    config_path: Path,
    *,
    discover_command: str | None = None,
) -> str:
    """Generate the requirements.toml content for managed Codex hooks (used when no file exists yet)."""
    managed_dir, windows_managed_dir = _codex_managed_dirs(config_path)
    chunks = [
        "[features]\nhooks = true\n",
        "[hooks]\n"
        + _codex_hooks_dir_lines([("managed_dir", managed_dir), ("windows_managed_dir", windows_managed_dir)]),
        *_codex_guard_hook_blocks(command, discover_command=discover_command),
    ]
    content = "\n".join(chunks)
    if tomllib is not None:  # pragma: no branch - available on supported installs
        try:
            tomllib.loads(content)
        except ValueError as exc:
            raise ValueError("Generated requirements.toml is invalid") from exc
    return content


# --- In-place editing of requirements.toml ----------------------------------
#
# requirements.toml is the admin's system-wide Codex policy file, so Guard edits
# it in place: lines it does not own are kept byte for byte (comments, blank
# lines, key order, quoting, line endings). There is no TOML round-trip library
# in our dependencies, so the edit is line based: the file is cut into sections
# at table headers, and only these forms are recognised:
#
# - ``[[hooks.<Event>]]`` groups followed by ``[[hooks.<Event>.hooks]]`` entries.
#   An entry is Guard's when its ``command`` matches _is_agent_scan_command.
#   A group whose entries are all Guard's is removed whole; from a mixed group
#   only Guard's entries are removed.
# - ``managed_dir`` / ``windows_managed_dir`` lines under a ``[hooks]`` header.
# - a ``hooks`` line under a ``[features]`` header.
#
# Anything else (inline tables/arrays, quoted keys, dotted keys) is left alone.
# Every edit is checked against tomllib: the old file must parse, and the new
# file must parse to exactly the old data plus/minus Guard's entries. If the
# line model got the layout wrong, the edit is refused instead of written.

_GUARD_DIR_KEYS = ("managed_dir", "windows_managed_dir")
_TOML_HEADER_RE = re.compile(r"^\s*(\[\[?)\s*([^\[\]]+?)\s*(\]\]?)\s*(?:#.*)?$")
_TOML_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class _TomlHeader(NamedTuple):
    line: int
    is_array: bool
    # Dotted path of bare keys, or None when the header uses quoted keys.
    path: tuple[str, ...] | None


def _split_toml_lines(text: str) -> list[str]:
    """Split on LF only (TOML's newline), keeping each line's ending (``\\n`` or ``\\r\\n``)."""
    parts = text.split("\n")
    lines = [part + "\n" for part in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


def _toml_headers(lines: list[str]) -> list[_TomlHeader]:
    headers = []
    for index, line in enumerate(lines):
        m = _TOML_HEADER_RE.match(line)
        if not m or len(m.group(1)) != len(m.group(3)):
            continue
        parts = tuple(part.strip() for part in m.group(2).split("."))
        path = parts if all(_TOML_BARE_KEY_RE.match(part) for part in parts) else None
        headers.append(_TomlHeader(index, len(m.group(1)) == 2, path))
    return headers


def _is_toml_content_line(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


def _last_toml_content_line(lines: list[str], start: int, end: int) -> int:
    """Index of the last key/value line in ``lines[start:end]``, or ``start`` (the header)."""
    for index in range(end - 1, start, -1):
        if _is_toml_content_line(lines[index]):
            return index
    return start


def _find_toml_table(lines: list[str], path: tuple[str, ...]) -> tuple[int, int] | None:
    """(header line, section end) of the standard table ``[path]``, if it has a header."""
    headers = _toml_headers(lines)
    for n, header in enumerate(headers):
        if not header.is_array and header.path == path:
            end = headers[n + 1].line if n + 1 < len(headers) else len(lines)
            return header.line, end
    return None


def _find_toml_key_line(lines: list[str], start: int, end: int, key: str) -> int | None:
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*=")
    for index in range(start + 1, end):
        if key_re.match(lines[index]):
            return index
    return None


def _toml_key_line_value(line: str, key: str) -> object:
    """Value of a single-line ``key = value`` (any quoting, unescaped), or None."""
    try:
        return tomllib.loads(line.strip()).get(key)
    except ValueError:
        return None


def _delete_toml_lines(lines: list[str], start: int, end: int) -> None:
    """Delete ``lines[start:end + 1]`` with one adjacent blank separator.

    Guard appends each block after a blank line, so dropping the blank line in
    front of a removed block (when the block is followed by a blank line or the
    end of the file) undoes an install exactly.
    """
    after = end + 1
    next_blank_or_eof = after >= len(lines) or not lines[after].strip()
    if start > 0 and not lines[start - 1].strip() and next_blank_or_eof:
        start -= 1
    elif start == 0 and after < len(lines) and not lines[after].strip():
        end += 1
    del lines[start : end + 1]


def _is_guard_hook_body(body: list[str]) -> bool:
    try:
        entry = tomllib.loads("".join(body))
    except ValueError:
        return False
    command = entry.get("command")
    return isinstance(command, str) and _is_agent_scan_command(command)


def _remove_guard_hook_groups(lines: list[str]) -> list[tuple]:
    """Delete Guard's hook groups/entries from ``lines`` in place.

    Returns what was removed, as ``("group", event, group_index)`` and
    ``("entry", event, group_index, entry_index)`` records, indexed the way
    tomllib sees the arrays, so the edit can be checked against the parsed data.
    """
    headers = _toml_headers(lines)
    spans: list[tuple[int, int]] = []
    removals: list[tuple] = []
    group_counts: dict[str, int] = {}
    n = 0
    while n < len(headers):
        header = headers[n]
        path = header.path
        if not (header.is_array and path is not None and len(path) == 2 and path[0] == "hooks"):
            n += 1
            continue
        event = path[1]
        group_index = group_counts.get(event, 0)
        group_counts[event] = group_index + 1
        entries: list[int] = []
        unknown_layout = False
        m = n + 1
        while m < len(headers):
            sub = headers[m]
            if sub.path is None or len(sub.path) <= 2 or sub.path[:2] != ("hooks", event):
                break
            if sub.is_array and sub.path == ("hooks", event, "hooks"):
                entries.append(m)
            else:
                unknown_layout = True
            m += 1
        group_end = headers[m].line if m < len(headers) else len(lines)
        n = m
        if unknown_layout or not entries:
            continue

        def _entry_span(k: int) -> tuple[int, int]:
            start = headers[k].line
            end = headers[k + 1].line if k + 1 < len(headers) else len(lines)
            return start, end

        is_guard = [_is_guard_hook_body(lines[s + 1 : e]) for s, e in map(_entry_span, entries)]
        if all(is_guard):
            spans.append((header.line, _last_toml_content_line(lines, header.line, group_end)))
            removals.append(("group", event, group_index))
            continue
        for entry_index, (k, guard) in enumerate(zip(entries, is_guard, strict=True)):
            if guard:
                start, end = _entry_span(k)
                spans.append((start, _last_toml_content_line(lines, start, end)))
                removals.append(("entry", event, group_index, entry_index))
    for start, end in sorted(spans, reverse=True):
        _delete_toml_lines(lines, start, end)
    return removals


def _load_codex_requirements(text: str) -> dict:
    if tomllib is None:  # pragma: no cover - tomli is a dependency on Python 3.10
        raise CodexRequirementsError("cannot check TOML on this Python (tomllib/tomli missing); not modifying it")
    try:
        data = tomllib.loads(text)
    except ValueError as exc:
        raise CodexRequirementsError(
            f"not valid TOML ({exc}); Agent Guard will not modify it. Fix the file and run the command again."
        ) from exc
    for table in ("features", "hooks"):
        if not isinstance(data.get(table, {}), dict):
            raise CodexRequirementsError(f"'{table}' is not a table; Agent Guard will not modify the file")
    return data


def _apply_guard_removals(data: dict, removals: list[tuple]) -> dict:
    """The parsed data with the recorded Guard groups/entries removed."""
    result = copy.deepcopy(data)
    dropped_groups = {(r[1], r[2]) for r in removals if r[0] == "group"}
    dropped_entries = {(r[1], r[2], r[3]) for r in removals if r[0] == "entry"}
    try:
        hooks = result.get("hooks", {})
        for event in {r[1] for r in removals}:
            kept = []
            for group_index, group in enumerate(hooks[event]):
                if (event, group_index) in dropped_groups:
                    continue
                if any((event, group_index, i) in dropped_entries for i in range(len(group.get("hooks", [])))):
                    group["hooks"] = [
                        entry
                        for i, entry in enumerate(group["hooks"])
                        if (event, group_index, i) not in dropped_entries
                    ]
                kept.append(group)
            hooks[event] = kept
    except (AttributeError, KeyError, TypeError) as exc:
        raise CodexRequirementsError("layout not understood; Agent Guard will not modify it") from exc
    if _contains_guard_command(result.get("hooks")):
        # A Guard hook in a layout the line editor skips: re-install would duplicate it
        # and uninstall would leave it behind.
        raise CodexRequirementsError(
            "Agent Guard hooks found in a layout Agent Guard cannot edit; remove them manually"
        )
    return result


def _contains_guard_command(value: object) -> bool:
    if isinstance(value, str):
        return _is_agent_scan_command(value)
    if isinstance(value, dict):
        return any(_contains_guard_command(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_guard_command(item) for item in value)
    return False


def _prune_empty(value: object) -> object:
    """Drop empty tables/arrays, which a removed header may or may not leave behind."""
    if isinstance(value, dict):
        pruned = {key: _prune_empty(item) for key, item in value.items()}
        return {key: item for key, item in pruned.items() if item != {} and item != []}
    if isinstance(value, list):
        return [_prune_empty(item) for item in value]
    return value


def _check_codex_requirements_edit(new_text: str, expected: dict) -> None:
    """Refuse the edit unless ``new_text`` parses to exactly ``expected``."""
    try:
        actual = tomllib.loads(new_text)
    except ValueError as exc:
        raise CodexRequirementsError(
            f"layout not supported (the edit would produce invalid TOML: {exc}); "
            "Agent Guard will not modify it. Edit the file manually."
        ) from exc
    if _prune_empty(actual) != _prune_empty(expected):
        raise CodexRequirementsError(
            "layout not supported (the edit would change entries Agent Guard does not own); "
            "Agent Guard will not modify it. Edit the file manually."
        )


def _strip_guard_from_codex_requirements(text: str, config_path: Path = CODEX_MANAGED_HOOKS_PATH) -> str:
    """Return requirements.toml ``text`` with every Agent Guard entry removed.

    Pure (no I/O). Removes Guard's hook groups/entries, then, if it removed any,
    ``managed_dir`` / ``windows_managed_dir`` under ``[hooks]`` when they equal the
    values Guard writes for ``config_path`` and no other hooks remain, then a ``[hooks]``
    header left with nothing under it. Everything else is kept byte for byte.

    ``[features] hooks = true`` is kept: the admin may have set it before Guard
    did, and Guard cannot tell. Leaving it on is harmless with no hooks.

    Raises CodexRequirementsError if ``text`` is not valid TOML or the edit
    cannot be verified; the caller must then leave the file untouched.
    """
    data = _load_codex_requirements(text)
    lines = _split_toml_lines(text)
    removals = _remove_guard_hook_groups(lines)
    expected = _apply_guard_removals(data, removals)

    hooks = expected.get("hooks")
    other_hooks = isinstance(hooks, dict) and any(
        key not in _GUARD_DIR_KEYS and value not in ({}, []) for key, value in hooks.items()
    )
    # Only together with Guard's hooks: a file without them never had Guard's dirs added.
    if removals and isinstance(hooks, dict) and not other_hooks:
        table = _find_toml_table(lines, ("hooks",))
        if table is not None:
            header, end = table
            removed_any = False
            for key, guard_value in zip(_GUARD_DIR_KEYS, _codex_managed_dirs(config_path), strict=True):
                index = _find_toml_key_line(lines, header, end, key)
                if index is not None and _toml_key_line_value(lines[index], key) == guard_value == hooks.get(key):
                    del lines[index]
                    end -= 1
                    del hooks[key]
                    removed_any = True
            if removed_any and not any(line.strip() for line in lines[header + 1 : end]):
                _delete_toml_lines(lines, header, header)

    new_text = "".join(lines)
    if new_text != text:
        _check_codex_requirements_edit(new_text, expected)
    return new_text


def _merge_guard_into_codex_requirements(
    text: str,
    command: str,
    config_path: Path,
    *,
    discover_command: str | None = None,
) -> tuple[str, list[str]]:
    """Return (``text`` with Guard's entries merged in, warnings). Pure (no I/O).

    Existing Guard hooks are removed and Guard's blocks appended at the end, in
    the same shape as _render_codex_requirements_toml. ``[features] hooks`` is
    set to true and Guard's ``managed_dir`` / ``windows_managed_dir`` are added
    when missing. Nothing else changes.

    If the file already sets ``managed_dir`` or ``windows_managed_dir``, both are
    left exactly as they are (none added, none changed), even when they differ
    from Guard's: Codex only uses it to label where managed
    hooks come from (hook IDs and messages), not to find or run them, and
    Guard's hook commands use absolute script paths. Codex allows a single
    value per platform across all requirement sources, so Guard has no
    reason to replace the admin's value.

    Raises CodexRequirementsError, before anything is written, if ``text`` is
    not valid TOML or if the edit cannot be verified.
    """
    data = _load_codex_requirements(text)
    features: dict = data.get("features", {})
    hooks_data: dict = data.get("hooks", {})
    guard_dirs = dict(zip(_GUARD_DIR_KEYS, _codex_managed_dirs(config_path), strict=True))

    lines = _split_toml_lines(text)
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    expected = _apply_guard_removals(data, _remove_guard_hook_groups(lines))
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += newline
    warnings: list[str] = []
    appended: list[str] = []

    if features.get("hooks") is not True:
        table = _find_toml_table(lines, ("features",))
        index = _find_toml_key_line(lines, *table, "hooks") if table is not None else None
        if "hooks" in features:
            warnings.append(
                f"[features] hooks was {features['hooks']!r}; setting it to true, which Codex needs "
                "to run Agent Guard's managed hooks. Uninstall leaves it set to true."
            )
        if index is not None:
            line = lines[index]
            indent = line[: len(line) - len(line.lstrip())]
            ending = "\r\n" if line.endswith("\r\n") else "\n"
            lines[index] = f"{indent}hooks = true{ending}"
        elif table is not None:
            position = _last_toml_content_line(lines, *table) + 1
            lines.insert(position, f"hooks = true{newline}")
        else:
            appended.append("[features]\nhooks = true\n")
        expected.setdefault("features", {})["hooks"] = True

    # Guard adds its directory keys only to a file that sets neither; an admin's
    # value for either platform means the admin owns this setting.
    has_dirs = any(key in hooks_data for key in _GUARD_DIR_KEYS)
    missing_dirs = [] if has_dirs else list(guard_dirs.items())
    if missing_dirs:
        table = _find_toml_table(lines, ("hooks",))
        if table is not None:
            position = _last_toml_content_line(lines, *table) + 1
            lines[position:position] = _split_toml_lines(_codex_hooks_dir_lines(missing_dirs).replace("\n", newline))
        else:
            appended.append("[hooks]\n" + _codex_hooks_dir_lines(missing_dirs))
        expected.setdefault("hooks", {}).update(missing_dirs)

    blocks = _codex_guard_hook_blocks(command, discover_command=discover_command)
    for block in blocks:
        for event, groups in tomllib.loads(block)["hooks"].items():
            expected.setdefault("hooks", {}).setdefault(event, []).extend(groups)
    appended.extend(blocks)

    base = "".join(lines)
    tail = "\n".join(appended)
    if base:
        tail = "\n" + tail
    new_text = base + tail.replace("\n", newline)
    _check_codex_requirements_edit(new_text, expected)
    return new_text, warnings


def _read_codex_requirements_text(path: Path) -> str:
    """Read requirements.toml with its line endings exactly as on disk.

    It is written back with ``newline=""`` (no translation), so untouched lines keep
    their bytes on every platform, including LF-only or mixed files on Windows.
    """
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CodexRequirementsError(f"{path}: not valid UTF-8; Agent Guard will not modify it") from exc


def _preflight_codex_requirements(path: Path) -> None:
    """Fail before any file is written if Guard cannot merge into an existing requirements.toml."""
    if not path.exists():
        return
    text = _read_codex_requirements_text(path)
    try:
        _merge_guard_into_codex_requirements(text, "", path)
    except CodexRequirementsError as exc:
        raise CodexRequirementsError(f"{path}: {exc}") from exc


def _prepare_codex_managed_config(
    command: str,
    path: Path,
    *,
    discover_command: str | None = None,
    config_values: Mapping[str, str] | None = None,
) -> tuple[str, dict]:
    """Build new Codex managed TOML content and compute diff, without writing.

    Returns (new_content, hooks_diff).

    A missing file is rendered from scratch. An existing file is edited in
    place (see _merge_guard_into_codex_requirements): admin policy, comments,
    other tables and non-Guard hooks are kept byte for byte, so the content is
    unchanged when Guard is already installed with the same commands. The diff
    only covers Guard commands, because _parse_codex_requirements_toml only
    reports commands that match _is_agent_scan_command.

    Raises CodexRequirementsError if the existing file is not valid TOML or
    cannot be edited safely.
    """
    old_events: list[str] = []
    old_guard_command: str | None = None
    old_discover_command: str | None = None
    if path.exists():
        old_text = _read_codex_requirements_text(path)
        try:
            new_content, warnings = _merge_guard_into_codex_requirements(
                old_text, command, path, discover_command=discover_command
            )
        except CodexRequirementsError as exc:
            raise CodexRequirementsError(f"{path}: {exc}") from exc
        for warning in warnings:
            rich.print(f"[yellow]Warning:[/yellow] {path}: {warning}")
        old_events, old_guard_command, old_discover_command = _parse_codex_requirements_toml(old_text)
    else:
        new_content = _render_codex_requirements_toml(command, path, discover_command=discover_command)

    old_event_set = set(old_events)
    new_event_set = set(CODEX_HOOK_EVENTS)

    def _entries(event: str, guard: str | None, discover: str | None) -> list[dict]:
        entries: list[dict] = []
        if guard is not None:
            entries.append({"type": "command", "command": guard})
        if event == "SessionStart" and discover is not None:
            entries.append({"type": "command", "command": discover, "async": True})
        return entries

    values = config_values or {}
    added = {}
    modified = {}
    removed = {}
    for event in sorted(old_event_set | new_event_set):
        expected = _entries(event, command, discover_command) if event in new_event_set else []
        actual = _entries(event, old_guard_command, old_discover_command) if event in old_event_set else []
        if not actual and expected:
            removed[event] = expected
        elif actual and not expected:
            added[event] = actual
        elif _normalize_guard_hooks(actual, values) != _normalize_guard_hooks(expected, values):
            modified[event] = {
                "expected_value": expected,
                "actual_value": actual,
            }

    diff = {"added": added, "modified": modified, "removed": removed}
    return new_content, diff


def _write_codex_managed_config(content: str, path: Path) -> bool:
    """Write Codex managed TOML to disk. Returns True if file changed."""
    if path.exists() and _read_codex_requirements_text(path) == content:
        return False
    if path.exists():
        _backup_file(path, lambda: _codex_requirements_without_guard(path), newline="")
    _atomic_write_text(path, content, newline="")
    rich.print(f"[green]✓[/green]  Written [dim]{path}[/dim]")
    return True


def _codex_requirements_without_guard(path: Path) -> str | None:
    """requirements.toml at ``path`` without Agent Guard, or None if it has no Guard entries."""
    text = _read_codex_requirements_text(path)
    stripped = _strip_guard_from_codex_requirements(text, path)
    return None if stripped == text else stripped


def _is_discover_hook_command(command: str) -> bool:
    return bool(re.search(r"\bsnyk-agent-guard-discover(?:\.(?:sh|ps1))?\b", command, re.IGNORECASE))


def _parse_codex_requirements_toml(text: str) -> tuple[list[str], str | None, str | None]:
    """Extract Snyk Agent Guard events, guard command, and discovery command.

    Only scans hook command lines containing the agent-guard detection marker.
    """
    events: list[str] = []
    guard_command: str | None = None
    discover_command: str | None = None
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
            cmd = toml_unescape(m.group(1))
            if not _is_agent_scan_command(cmd):
                continue
            if current_event not in events:
                events.append(current_event)
            if _is_discover_hook_command(cmd):
                if discover_command is None:
                    discover_command = cmd
            elif guard_command is None:
                guard_command = cmd
    return events, guard_command, discover_command


def _detect_codex_managed_install(path: Path) -> dict | None:
    text = path.read_text()
    events, guard_command, _ = _parse_codex_requirements_toml(text)
    if not events or guard_command is None:
        return None
    return _parse_command_info(guard_command, events, path)


def _uninstall_codex_managed(path: Path) -> None:
    """Remove Agent Guard's entries from requirements.toml at ``path``, then Guard's backups of it.

    The backups are removed only once the file is free of Guard entries; if
    anything raises first, they are left in place.
    """
    if not path.exists():
        rich.print("[dim]No requirements.toml found. Nothing to uninstall.[/dim]")
        _remove_guard_backups(path)
        return
    text = _read_codex_requirements_text(path)
    # Any line, so hooks written with another TOML string form are found too.
    if not any(_is_agent_scan_command(line) for line in text.splitlines()):
        rich.print("[dim]No Agent Guard hooks found.[/dim]")
        _remove_guard_backups(path)
        return
    events, _, _ = _parse_codex_requirements_toml(text)
    try:
        new_text = _strip_guard_from_codex_requirements(text, path)
    except CodexRequirementsError as exc:
        raise CodexRequirementsError(f"{path}: {exc}") from exc
    if new_text == text:
        raise CodexRequirementsError(
            f"{path}: Agent Guard hooks found in a layout Agent Guard cannot edit; remove them manually."
        )
    # Edited in place and never deleted: the file is the admin's Codex policy, not ours.
    _atomic_write_text(path, new_text, newline="")
    removed = f"{len(events)} Agent Guard hook(s)" if events else "Agent Guard hooks"
    rich.print(f"[green]✓[/green]  Removed {removed} from [dim]{path}[/dim]")
    _remove_guard_backups(path)


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
    if client == "codex" and _is_codex_requirements_toml(config_path):
        _uninstall_codex_managed(config_path)
    elif client in ALL_CLIENTS:
        _uninstall_hooks(config_path, client=client)

    # Remove hook script
    _remove_hook_script(client, config_path)

    # Try to revoke the push key
    if info and info.get("env_mode"):
        # The key came from the hooks' environment. Install never minted it, and in cloud-agent
        # or plugin setups every machine usually shares it, so revoking it here would break them.
        rich.print(
            "[dim]   Push key was not revoked: these hooks read it from their environment, "
            "where it is usually shared. Revoke it in Snyk if nothing else uses it.[/dim]"
        )
    elif info and info.get("auth_value"):
        _try_revoke_push_key(info, label)
    elif info and info.get("auth_type") != "machine":
        # A machine identity install has no push key to revoke.
        rich.print("[dim]   Push key was not revoked: no push key was found for this install.[/dim]")

    rich.print()


def _try_revoke_push_key(info: dict, label: str) -> None:
    push_key = info.get("auth_value", "")
    tenant_id = info.get("tenant_id", "") or os.environ.get("TENANT_ID", "").strip()
    url = info.get("url", DEFAULT_REMOTE_URL)
    snyk_token = os.environ.get("SNYK_TOKEN", "")

    if not tenant_id:
        rich.print(
            f"[dim]   Push key {_mask_key(push_key)} was not revoked "
            "(Tenant ID not found in the installed hook; set TENANT_ID to revoke on uninstall).[/dim]"
        )
        return
    if not snyk_token:
        rich.print(
            f"[dim]   Push key {_mask_key(push_key)} was not revoked (set SNYK_TOKEN to revoke on uninstall).[/dim]"
        )
        return

    try:
        revoke_push_key(url, tenant_id, snyk_token, push_key)
        rich.print(f"[green]\u2713[/green]  Push key {_mask_key(push_key)} revoked")
    except RuntimeError as e:
        rich.print(f"[yellow]Warning:[/yellow] Could not revoke push key: {e}")


def _strip_guard_from_json_config(data: dict, client: str) -> dict:
    """Return *client*'s JSON config ``data`` with every Agent Guard hook removed.

    Pure: ``data`` is not modified. This is exactly what uninstall leaves in the
    file, and what the install backup holds when the file already has Guard hooks.
    Hook entries are matched by _uninstall_filter_for(client). When nothing is
    removed, the result equals ``data``. When the last hook goes,
    the ``hooks`` key is dropped, except for Cursor, which keeps ``"hooks": {}``.

    Raises AttributeError/TypeError if ``hooks`` or its entries have an
    unexpected shape.
    """
    hooks = data.get("hooks", {})
    filtered = _uninstall_filter_for(client)(hooks)
    if _count_hook_groups(filtered) == _count_hook_groups(hooks):
        # The filters only drop whole entries (and the event lists they empty),
        # so equal counts mean no Guard hook was found.
        return data
    result = dict(data)
    if filtered or client == "cursor":
        result["hooks"] = filtered
    else:
        del result["hooks"]
    return result


def _count_hook_groups(hooks: dict) -> int:
    return sum(len(groups) for groups in hooks.values())


def _uninstall_hooks(path: Path, *, client: str) -> None:
    """Remove Agent Guard's hooks from *client*'s JSON config at ``path``, then Guard's backups of it.

    If removing Guard's hooks leaves nothing but the scaffolding install adds
    (_GUARD_JSON_SCAFFOLDING, e.g. ``{}`` or Cursor's/Copilot's ``{"version": 1}``), the
    file is deleted instead of rewritten, so a file that install created does
    not outlive Guard. The rule looks only at the content: a file that held
    just ``{}`` before install is deleted too, which every agent treats the
    same as no file. A symlinked config is always rewritten, never deleted.

    The backups are removed only once the file is free of Guard hooks; if
    anything raises first (e.g. invalid JSON), they are left in place.
    """
    if not path.exists():
        rich.print(f"[dim]No {path.name} found. Nothing to uninstall.[/dim]")
        _remove_guard_backups(path)
        return

    data = _read_json_or_empty(path)
    stripped = _strip_guard_from_json_config(data, client)
    if stripped == data:
        rich.print("[dim]No Agent Guard hooks found.[/dim]")
        _remove_guard_backups(path)
        return

    total_after = _count_hook_groups(stripped.get("hooks", {}))
    removed = _count_hook_groups(data.get("hooks", {})) - total_after
    if stripped in _GUARD_JSON_SCAFFOLDING.get(client, ()) and not path.is_symlink():
        path.unlink()
        rich.print(f"[green]\u2713[/green]  Removed {removed} Agent Guard hook(s)")
        rich.print(f"[dim]Removed {path} (nothing else was left in it)[/dim]")
    else:
        _write_json(path, stripped)
        rich.print(f"[green]\u2713[/green]  Removed {removed} Agent Guard hook(s){_preserved_note(total_after)}")
    _remove_guard_backups(path)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def _run_status() -> None:
    clients = (
        ("Claude Code", CLAUDE_SETTINGS_PATH, CLAUDE_MANAGED_SETTINGS_PATH, _detect_claude_install),
        ("Cursor", CURSOR_HOOKS_PATH, CURSOR_MANAGED_HOOKS_PATH, _detect_cursor_install),
        ("Codex", CODEX_HOOKS_PATH, CODEX_MANAGED_HOOKS_PATH, _detect_codex_install),
        ("GitHub Copilot", COPILOT_HOOKS_PATH, COPILOT_MANAGED_HOOKS_PATH, _detect_copilot_install),
    )

    rich.print("[bold]User-level hooks:[/bold]")
    for label, user_path, _, detect in clients:
        _print_client_status(label, user_path, detect())
        rich.print()

    rich.print("[bold]Managed hooks:[/bold]")
    for label, _, managed_path, detect in clients:
        info: dict | str | None
        try:
            info = detect(managed_path)
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
    rich.print("[dim]# machine identity flow (ADS installer, user-level)[/dim]")
    rich.print(
        "[dim]ADS_TOKEN_COMMAND=<command> TENANT_ID=<tenant-id> "
        "snyk-agent-scan guard install <client> --url <api-url> --machine-id <machine-id>[/dim]"
    )
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


def _print_client_status(label: str, path: Path, info: dict | str | None) -> None:
    rich.print(f"[bold white]{label}[/bold white]   [dim]{path}[/dim]")
    if isinstance(info, str):
        rich.print("    [yellow]UNREADABLE (permission denied)[/yellow]")
        return
    if info is None:
        rich.print("    [dim]NOT INSTALLED[/dim]")
        return

    if info.get("auth_type") == "machine":
        auth_label = "[yellow]\\[Machine identity][/yellow]"
    else:
        auth_label = f"[yellow]\\[Push Key: {_mask_key(info['auth_value'])}][/yellow]"
    hooks_suffix = _compact_events(info["events"])
    rich.print(
        f"    [bold green]INSTALLED[/bold green]   "
        f"[bold white]\\[{info['host']}][/bold white]   "
        f"{auth_label}   "
        f"[dim]{hooks_suffix}[/dim]"
    )


def _detect_claude_install(path: Path = CLAUDE_SETTINGS_PATH) -> dict | None:
    return _detect_install(path, CLAUDE_HOOK_EVENTS, _grouped_hook_commands)


def _detect_codex_install(path: Path = CODEX_HOOKS_PATH) -> dict | None:
    if _is_codex_requirements_toml(path):
        if not path.exists():
            return None
        return _detect_codex_managed_install(path)
    return _detect_install(path, CODEX_HOOK_EVENTS, _grouped_hook_commands)


def _detect_cursor_install(path: Path = CURSOR_HOOKS_PATH) -> dict | None:
    return _detect_install(path, CURSOR_HOOK_EVENTS, _flat_hook_commands)


def _detect_copilot_install(path: Path = COPILOT_HOOKS_PATH) -> dict | None:
    return _detect_install(path, COPILOT_HOOK_EVENTS, _copilot_hook_commands)


def _grouped_hook_commands(group: dict) -> Iterable[str]:
    return (hook.get("command", "") for hook in group.get("hooks", []))


def _flat_hook_commands(entry: dict) -> Iterable[str]:
    return (entry.get("command", ""),)


def _detect_install(path: Path, events: list[str], commands: Callable[[dict], Iterable[str]]) -> dict | None:
    if not path.exists():
        return None
    data = _read_json_or_empty(path)
    hooks = data.get("hooks", {})

    installed_events = []
    found_cmd = None
    for event in events:
        for entry in hooks.get(event, []):
            for command in commands(entry):
                if _is_agent_scan_command(command):
                    installed_events.append(event)
                    if found_cmd is None:
                        found_cmd = command
                    break
            else:
                continue
            break

    if not installed_events or found_cmd is None:
        return None
    return _parse_command_info(found_cmd, installed_events, path)


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


def _discover_logged_connectors() -> dict[str, list[dict]]:
    """Collect Claude Desktop connectors into a fresh dict, safe to abandon on timeout."""
    logged_servers: dict[str, list[dict]] = {}
    # Match InspectArgs.all_users=False in _discover_servers_payload.
    for home_directory, _username in get_readable_home_directories(all_users=False):
        for org, entries in ClaudeDesktopDiscoverer(home_directory).discover_logged_mcp_servers().items():
            logged_servers.setdefault(org, []).extend(entries)
    return logged_servers


def _has_success_payload(stdout: str | None) -> bool:
    try:
        body = json.loads(stdout or "")
    except ValueError:
        return False
    return isinstance(body, dict) and body.get("success") is True


def _invoke_hook_script(
    script_path: Path,
    hook_client: str,
    payload: str,
    *,
    require_success_payload: bool = False,
    timeout: float = _HOOK_SCRIPT_TIMEOUT_SECONDS,
    env: Mapping[str, str] | None = None,
) -> tuple[bool, str]:
    """Run the hook script with ``payload`` on stdin. Returns ``(ok, detail)``.

    By default a zero exit code is success. With ``require_success_payload`` the script's
    stdout must additionally be a JSON object containing ``"success": true``, because the
    server answers HTTP 200 even when it rejects the request (e.g. an invalid push key).
    """
    import subprocess

    # No values are passed on the command line: the script reads them from the guard
    # configuration file, so the handshake also checks that the installed configuration
    # works. Without one (env mode), *env* holds them, the way the hook's environment will.
    cmd = _render_argv(_HookInvocation(script_path=script_path, hook_client=hook_client, from_env=env is not None))
    # Without *env* the script inherits this process's environment, as before.
    env_kwargs: dict[str, Any] = {} if env is None else {"env": dict(env)}

    try:
        result = subprocess.run(
            cmd,
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout,
            **env_kwargs,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or f"exit code {result.returncode}"
        if require_success_payload and not _has_success_payload(result.stdout):
            # The forwarders fail open on transport and HTTP errors (exit 0, empty stdout, a
            # diagnostic on stderr), so when there is a reason it lives on stderr.
            diagnostic = "; ".join(line.strip() for line in (result.stderr or "").splitlines() if line.strip())
            if diagnostic:
                return False, f"response did not confirm success: {diagnostic}"
            return False, "response did not confirm success (push key may be invalid)"
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


# What a failed-to-confirm test event means, keyed by error label, shown in the install warning.
_ERROR_MEANINGS = {
    "timeout": "the Agent Guard service did not answer in time",
    "dns_failure": "the Agent Guard host name could not be resolved (network or DNS problem)",
    "connection_refused": "the connection to the Agent Guard service was refused",
    "connection_reset": "the connection to the Agent Guard service was dropped",
}


class _TestEventResult(NamedTuple):
    status: str  # "sent", "rejected" (persistent, abort) or "unconfirmed" (outage outlasted retries)
    attempts: int
    elapsed: float
    error: str  # short label such as dns_failure, timeout, http_error_503
    detail: str


def _describe_error(error: str) -> str:
    if error.startswith("http_error_"):
        return f"the Agent Guard service answered with HTTP {error.removeprefix('http_error_')}, a server-side failure"
    return _ERROR_MEANINGS.get(error, "the test event could not be delivered")


def _send_test_event(
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
    config_current_checksum: str | None = None,
    config_new_checksum: str | None = None,
    env: Mapping[str, str] | None = None,
) -> _TestEventResult:
    """Send a test hooksConfigured event by invoking the hook script, retrying outages.

    The script reads the installed configuration, so with machine identity it runs exactly like
    the installed hooks: the token command, then the tenant route.

    Timeouts, DNS failures, connection resets and HTTP 5xx are retried with backoff inside
    ``INSTALL_RETRY_POLICY``'s time limit (the same rule as the install-time discovery event).
    Anything else (API rejection, HTTP 4xx, a script error) is persistent and returned at once.
    """
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
    if config_current_checksum is not None:
        hooks_script["config_current_checksum"] = config_current_checksum
    if config_new_checksum is not None:
        hooks_script["config_new_checksum"] = config_new_checksum
    if hooks_script:
        payload_dict["hooks_script"] = hooks_script
    redact_push_keys_in_data(payload_dict)
    payload = json.dumps(payload_dict)

    policy = INSTALL_RETRY_POLICY
    started = time.monotonic()
    attempts = 0
    while True:
        attempts += 1
        ok, detail = _invoke_hook_script(
            script_path,
            hook_client,
            payload,
            require_success_payload=True,
            # A healthy but slow answer (up to the forwarder's own 60 s cap) must be able to finish,
            # so each attempt gets what is left of the install budget, not the 15 s default.
            timeout=max(policy.time_limit - (time.monotonic() - started), 0.0) + _HOOK_SCRIPT_OVERHEAD_SECONDS,
            **({} if env is None else {"env": env}),
        )
        elapsed = time.monotonic() - started
        if ok:
            rich.print("[green]\u2713[/green]  Test event sent  [green]\u2192 OK[/green]")
            return _TestEventResult("sent", attempts, elapsed, "", "")
        failure = classify_failure_detail(detail)
        if not failure.retryable:
            rich.print(f"[red]\u2717[/red]  Test event failed: {detail}")
            return _TestEventResult("rejected", attempts, elapsed, failure.label, detail)
        delay = next_retry_delay(policy, attempts, started)
        if delay is None:
            return _TestEventResult("unconfirmed", attempts, elapsed, failure.label, detail)
        rich.print(
            f"[yellow]![/yellow]  Test event attempt {attempts} failed ({failure.label}); retrying in {delay:g}s..."
        )
        time.sleep(delay)


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
    retry_policy: RetryPolicy | None = None,
    machine_serial: str,
    machine_auth: MachineAuth | None = None,
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
    payload_dict: dict = {
        "hook_event_name": event_name,
        "servers": servers,
    }
    if hook_client == "claude-code" and discovery_scope in (DiscoveryScope.SERVERS, DiscoveryScope.ALL):
        try:
            # Share the discovery deadline so a stalled Desktop directory cannot hang the hook.
            remaining = _DISCOVERY_TIMEOUT_SECONDS - (time.monotonic() - started)
            logged_servers = _run_with_timeout(_discover_logged_connectors, remaining)
            if logged_servers:
                payload_dict["claudeLoggedMcpServers"] = logged_servers
        except Exception as e:
            rich.print(f"[yellow]Warning:[/yellow] Could not discover Claude Desktop connectors: {e}")
    payload_dict["discovery_duration_ms"] = round((time.monotonic() - started) * 1000)
    payload_dict[HOOK_CLIENTS[hook_client].session_field] = session_marker
    redact_push_keys_in_data(payload_dict)
    payload = json.dumps(payload_dict)

    ok, detail = send_hook_event(
        url,
        hook_client,
        push_key,
        payload,
        machine_id,
        retry_policy=retry_policy,
        machine_serial=machine_serial,
        machine_auth=machine_auth,
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


# The values hook commands carried before they moved into the guard configuration file, as
# earlier versions rendered them: a leading run of single-quoted POSIX assignments, and
# single-quoted PowerShell parameters.
_POSIX_EMBEDDED_QUOTE = "'\"'\"'"  # how _shell_quote writes a ' inside a single-quoted value
_LEGACY_POSIX_VALUE_RE = re.compile(
    r"(PUSH_KEY|PUSHKEY|ADS_TOKEN_COMMAND|REMOTE_HOOKS_BASE_URL|TENANT_ID|MACHINE_ID|MACHINE_SERIAL|AGENT_SCAN_COMMAND)='((?:[^']|"
    + re.escape(_POSIX_EMBEDDED_QUOTE)
    + r")*)' "
)
_LEGACY_POWERSHELL_VALUE_RE = re.compile(
    r" -(PushKey|TokenCommand|RemoteUrl|TenantId|MachineId|MachineSerial|AgentScanCommand) '((?:[^']|'')*)'(?= |\Z)"
)
_LEGACY_POWERSHELL_KEYS = {
    "PushKey": "PUSH_KEY",
    "TokenCommand": "ADS_TOKEN_COMMAND",
    "RemoteUrl": "REMOTE_HOOKS_BASE_URL",
    "TenantId": "TENANT_ID",
    "MachineId": "MACHINE_ID",
    "MachineSerial": "MACHINE_SERIAL",
    "AgentScanCommand": "AGENT_SCAN_COMMAND",
}
_PUSH_KEY_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _is_installed_legacy_value(key: str, value: str, config_values: Mapping[str, str]) -> bool:
    """Whether a value on a legacy hook command is one this install writes anyway.

    A push key only has to be a well-formed UUID, since a changed key is reported as
    ``push_key_changed`` rather than as a hook change. An empty value matches only for
    the serial, which earlier versions wrote even when empty, and for ``PUSH_KEY`` /
    ``PUSHKEY`` when this install has no push key: machine identity commands cleared both.
    """
    if key in ("PUSH_KEY", "PUSHKEY") and not value:
        return not config_values.get("PUSH_KEY", "")
    if value == config_values.get(key, "") and (value or key == "MACHINE_SERIAL"):
        return True
    return key == "PUSH_KEY" and _PUSH_KEY_UUID_RE.fullmatch(value) is not None


def _strip_legacy_command_values(command: str, config_values: Mapping[str, str]) -> str:
    """Drop the values a hook command written by an earlier version carried, where they
    match *config_values*, the values this install writes to the guard configuration file.

    The hook scripts ignore them -- they read their values only from the hook
    configuration file -- so a command carrying them runs exactly as one without them.
    A value that differs is kept, so a redirected URL or a command that only parses as
    a value under one shell's quoting rules is still reported as a change.
    """
    pos = 0
    while (m := _LEGACY_POSIX_VALUE_RE.match(command, pos)) is not None:
        if not _is_installed_legacy_value(m[1], m[2].replace(_POSIX_EMBEDDED_QUOTE, "'"), config_values):
            break
        pos = m.end()
    command = command[pos:]

    def drop(m: re.Match[str]) -> str:
        key = _LEGACY_POWERSHELL_KEYS[m[1]]
        return "" if _is_installed_legacy_value(key, m[2].replace("''", "'"), config_values) else m[0]

    return _LEGACY_POWERSHELL_VALUE_RE.sub(drop, command)


def _normalize_guard_hooks(value: object, config_values: Mapping[str, str]) -> object:
    """Normalize guard hook entries for comparison.

    Push-key UUIDs are replaced with a placeholder, and the values earlier versions
    carried on the hook command are dropped where they match *config_values*, so
    upgrading from such a version is not reported as a configuration change.
    """
    if isinstance(value, str):
        if _is_agent_scan_command(value):
            value = _strip_legacy_command_values(value, config_values)
        return redact_push_keys(value, "<PUSH_KEY>")
    if isinstance(value, dict):
        return {k: _normalize_guard_hooks(v, config_values) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize_guard_hooks(item, config_values) for item in value]
    return value


def _uninstall_filter_for(client: str) -> Callable[[dict], dict]:
    """The hook filter that recognises *client*'s own entry shape."""
    if client == "github-copilot":
        return _filter_copilot_hooks
    if client == "cursor":
        return _filter_cursor_hooks
    return _filter_claude_hooks


def _extract_guard_hooks(entries: list) -> list:
    """Extract only guard (agent-scan) hooks from a list of hook entries/groups.

    Flat entries are matched under any of the script keys a client may use, so a Copilot
    diff sees our hooks whichever form they were written in. Clients that only ever use
    `command` are unaffected — the extra keys are simply absent.
    """
    result = []
    for item in entries:
        if isinstance(item, dict) and "hooks" in item:
            if any(_is_agent_scan_command(h.get("command", "")) for h in item.get("hooks", [])):
                result.append(item)
        elif isinstance(item, dict) and any(_is_agent_scan_command(c) for c in _copilot_hook_commands(item)):
            result.append(item)
    return result


def _compute_hooks_diff(old_hooks: dict, new_hooks: dict, *, config_values: Mapping[str, str] | None = None) -> dict:
    """Compare existing hooks (old) against expected hooks (new).

    Only guard (agent-scan) hooks are compared; customer hooks are ignored.

    The diff reflects what someone changed in the existing config relative to
    what we expect:
    - "removed": expected keys missing from the existing config
    - "added": unexpected keys present in the existing config
    - "modified": keys present in both but with different values
      (each entry has "expected_value" and "actual_value")

    Differences that consist solely of a push-key change, or of the values earlier
    versions carried on the hook command where they match *config_values* (the values
    being installed), are ignored.
    """
    config_values = config_values or {}
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
            old_norm = _normalize_guard_hooks(copy.deepcopy(old_guard), config_values)
            new_norm = _normalize_guard_hooks(copy.deepcopy(new_guard), config_values)
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


# A Copilot command hook names its script under exactly one of these, per its config
# schema: `bash` for Unix, `powershell` for Windows, or `command` as a cross-platform
# fallback. All three are read on the way in — a config may hold any of them, including
# ones a user wrote by hand — while the writer emits the platform-specific key, because
# the command it renders is already platform-specific (a `bash …` line on POSIX, a
# `powershell -File '…'` line on Windows, whose single-quoted paths are PowerShell
# syntax rather than cmd's). `exec`/`args` is a fourth form we never write; its push key
# lives in `env`, so it is not command text and nothing here needs to match it.
_COPILOT_SCRIPT_KEYS = ("bash", "powershell", "command")


def _copilot_command_entry(command: str) -> dict:
    """Build a Copilot command-hook entry for this platform."""
    return {"type": "command", "powershell" if IS_WINDOWS else "bash": command}


def _copilot_hook_commands(entry: dict) -> Iterable[str]:
    """Every command string a Copilot hook entry could carry."""
    return tuple(str(entry.get(key, "")) for key in _COPILOT_SCRIPT_KEYS)


def _filter_copilot_hooks(hooks: dict) -> dict:
    """Drop our own hooks, whichever script key they were written under."""
    result = {}
    for event, entries in hooks.items():
        filtered = [e for e in entries if not any(_is_agent_scan_command(c) for c in _copilot_hook_commands(e))]
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


def _parse_command_info(cmd: str, events: list[str], config_path: Path) -> dict:
    """Describe an installed hook from the guard configuration file, which is what the scripts
    use. An install made by an earlier version has none; its values are on the hook command."""
    guard_config_path = _guard_config_path(config_path)
    # Env mode: no configuration file, and the command opts in with --from-env.
    env_mode = False
    if guard_config_path.is_file():
        values = _read_guard_config(guard_config_path)
    else:
        values = {key: _resolve_placeholder(_extract_env_from_cmd(cmd, key)) for key in _PS_PARAM_MAP}
        env_mode = _FROM_ENV_RE.search(cmd) is not None
        if env_mode:
            # An env-mode hook reads a value the command doesn't assign from the variable of
            # its own name (on Windows the command assigns none), so look there too.
            for key in values:
                if not re.search(rf"(?:^| ){key}=", cmd):
                    values[key] = os.environ.get(key, "") or (
                        os.environ.get("PUSHKEY", "") if key == "PUSH_KEY" else ""
                    )
    url = values.get("REMOTE_HOOKS_BASE_URL", "")
    push_key = values.get("PUSH_KEY", "")
    # A push key wins, as in the scripts. A machine identity hook has no push key, so
    # uninstall has nothing to revoke. A command that assigns PUSH_KEY a placeholder is a
    # push-key install even when the placeholder is unset here: --no-config-file installs
    # never use machine identity, so an ADS_TOKEN_COMMAND in this environment must not turn
    # one into it (that would skip revoking the key, and the note saying so).
    assigns_push_key = re.search(r'(?:^| )PUSH_KEY="\$', cmd) is not None
    machine_identity = not push_key and not assigns_push_key and bool(values.get("ADS_TOKEN_COMMAND", ""))
    host = urlparse(url).netloc if url else "unknown"

    return {
        "host": host,
        "auth_type": "machine" if machine_identity else "pushkey",
        "auth_value": push_key,
        "tenant_id": values.get("TENANT_ID", ""),
        "url": url or DEFAULT_REMOTE_URL,
        "events": events,
        "env_mode": env_mode,
    }


def _resolve_placeholder(value: str) -> str:
    """An env-mode command's ``"$VAR"`` placeholder, resolved from this process's environment."""
    m = _PLACEHOLDER_VALUE_RE.fullmatch(value)
    return os.environ.get(m[1], "") if m else value


_PS_PARAM_MAP = {
    "PUSH_KEY": "PushKey",
    "REMOTE_HOOKS_BASE_URL": "RemoteUrl",
    "TENANT_ID": "TenantId",
    "ADS_TOKEN_COMMAND": "TokenCommand",
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


_CLIENT_LABELS = {
    "claude": "Claude Code",
    "cursor": "Cursor",
    "codex": "Codex",
    "github-copilot": "GitHub Copilot",
}
_HOOK_CLIENT_NAMES = {
    "claude": "claude-code",
    "cursor": "cursor",
    "codex": "codex",
    "github-copilot": "github-copilot",
}


_CLIENT_INSTALL_DIRS = {
    "claude": ".claude",
    "cursor": ".cursor",
    "codex": ".codex",
    "github-copilot": ".copilot",
}


def _is_client_installed(client: str, home_dirs: Iterable[Path]) -> bool:
    """Check whether the agent is installed under at least one of *home_dirs* by looking for its config directory."""
    rel_dir = _CLIENT_INSTALL_DIRS.get(client)
    if rel_dir is None:
        return True
    for home in home_dirs:
        try:
            if (home / rel_dir).is_dir():
                return True
        except PermissionError:
            continue
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
        if client == "github-copilot":
            return COPILOT_MANAGED_HOOKS_PATH
        return CODEX_MANAGED_HOOKS_PATH
    if client == "claude":
        return CLAUDE_SETTINGS_PATH
    if client == "cursor":
        return CURSOR_HOOKS_PATH
    if client == "github-copilot":
        return COPILOT_HOOKS_PATH
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
    """How a hook script is invoked. Its values come from the guard configuration file or,
    with ``from_env``, from the environment, which a POSIX ``prefix`` of assignments sets."""

    script_path: Path
    hook_client: str
    scope: str = ""
    quote_client: bool = False
    prefix: tuple[str, ...] = ()
    from_env: bool = False


def _render_posix_command(invocation: _HookInvocation) -> str:
    client = _shell_quote(invocation.hook_client) if invocation.quote_client else invocation.hook_client
    parts = [*invocation.prefix, f"bash {_shell_quote(invocation.script_path.as_posix())}", f"--client {client}"]
    if invocation.scope:
        parts.append(f"--scope {invocation.scope}")
    if invocation.from_env:
        parts.append("--from-env")
    return " ".join(parts)


def _render_powershell_command(invocation: _HookInvocation) -> str:
    parts = ["powershell", "-File", _ps_quote(str(invocation.script_path)), "-Client", invocation.hook_client]
    if invocation.scope:
        parts.extend(["-Scope", invocation.scope])
    if invocation.from_env:
        parts.append("-FromEnv")
    return " ".join(parts)


def _render_argv(invocation: _HookInvocation) -> list[str]:
    if IS_WINDOWS:
        argv = ["powershell", "-File", str(invocation.script_path), "-Client", invocation.hook_client]
        if invocation.scope:
            argv.extend(["-Scope", invocation.scope])
        if invocation.from_env:
            argv.append("-FromEnv")
        return argv
    argv = ["bash", str(invocation.script_path), "--client", invocation.hook_client]
    if invocation.scope:
        argv.extend(["--scope", invocation.scope])
    if invocation.from_env:
        argv.append("--from-env")
    return argv


def _build_hook_command(
    script_path: Path, hook_client: str, *, prefix: tuple[str, ...] = (), from_env: bool = False
) -> str:
    invocation = _HookInvocation(script_path=script_path, hook_client=hook_client, prefix=prefix, from_env=from_env)
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
    script_path: Path, hook_client: str, *, prefix: tuple[str, ...] = (), from_env: bool = False
) -> str:
    invocation = _HookInvocation(
        script_path=script_path,
        hook_client=hook_client,
        scope="servers",
        quote_client=True,
        prefix=prefix,
        from_env=from_env,
    )
    if IS_WINDOWS:
        return _render_powershell_command(invocation)
    return _render_posix_command(invocation)


def _build_hook_command_powershell(script_path: Path, hook_client: str) -> str:
    return _render_powershell_command(_HookInvocation(script_path=script_path, hook_client=hook_client))


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
    # The file's content before the copy, for _restore_hook_script; None if there was none.
    previous: bytes | None = None


def _copy_hook_script(dest: Path) -> _CopiedScript:
    """Copy the bundled hook script named ``dest.name`` to *dest*.

    Handles both the forwarding hook and the session-start discovery trampoline;
    the bundled resource and the destination share a basename.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)

    source = importlib_resources.files("agent_scan.hooks").joinpath(dest.name)
    new_content = source.read_bytes()
    new_checksum = hashlib.sha256(new_content).hexdigest()

    current_content = dest.read_bytes() if dest.exists() else None
    current_checksum = None if current_content is None else hashlib.sha256(current_content).hexdigest()

    copied = _CopiedScript(
        dest,
        current_content is not None,
        current_content != new_content,
        current_checksum,
        new_checksum,
        current_content,
    )
    try:
        if copied.updated:
            dest.write_bytes(new_content)
            rich.print(f"[green]\u2713[/green]  Copied hook script to [dim]{dest}[/dim]")
        if not IS_WINDOWS:
            dest.chmod(dest.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except BaseException:
        # The caller gets no _CopiedScript to restore from, so undo the copy here.
        _restore_hook_script(copied)
        raise
    return copied


def _restore_hook_script(script: _CopiedScript) -> None:
    """Undo _copy_hook_script: put the previous script back, or remove the one it created."""
    if not script.existed:
        script.path.unlink(missing_ok=True)
    elif script.updated and script.previous is not None:
        script.path.write_bytes(script.previous)  # the file is kept, and with it its mode


def _remove_hook_script(client: str, config_path: Path) -> None:
    """Delete Guard's hook scripts and configuration file, then their directory if that left it empty."""
    removed_any = False
    for dest in (
        _forwarder_script_path(config_path),
        _discover_script_path(config_path),
        _guard_config_path(config_path),
    ):
        if dest.exists():
            dest.unlink()
            rich.print(f"[green]\u2713[/green]  Removed hook script [dim]{dest}[/dim]")
            removed_any = True
    if removed_any:
        _remove_dir_if_empty(_hooks_dir(config_path))


def _remove_dir_if_empty(path: Path) -> None:
    """Remove directory ``path`` if it is empty; leave it (silently) otherwise or on any error."""
    try:
        os.rmdir(path)
    except OSError:
        return
    rich.print(f"[dim]Removed empty directory {path}[/dim]")


def _guard_backup_path(path: Path) -> Path:
    """Where install backs up ``path``: ``<path>.snyk-agent-guard.backup``."""
    return Path(str(path) + _GUARD_BACKUP_SUFFIX)


def _remove_guard_backups(path: Path) -> None:
    """Delete Guard's backups of ``path``. Call only once ``path`` is free of Agent Guard config.

    Removes ``<path>.snyk-agent-guard.backup`` (Guard's by name) and a legacy
    ``<path>.backup`` that holds a Guard hook command (see _remove_legacy_guard_backup).
    """
    backup = _guard_backup_path(path)
    if backup.is_file() and _unlink_backup(backup):
        rich.print(f"[dim]Removed Agent Guard backup {backup}[/dim]")
    _remove_legacy_guard_backup(path)


def _unlink_backup(backup: Path) -> bool:
    """Delete ``backup``; on failure warn and carry on, since the config itself is already done."""
    try:
        backup.unlink()
    except OSError as exc:
        rich.print(f"[yellow]Warning:[/yellow] Could not remove {backup} ({exc}); delete it manually.")
        return False
    return True


def _remove_legacy_guard_backup(path: Path) -> None:
    """Delete ``<path>.backup`` if it holds an Agent Guard hook command.

    Older Guard versions backed up to ``<path>.backup``, and a copy taken while
    Guard was installed carries its PUSH_KEY. The name is not Guard's own (other
    tools and users write it too), so the file is deleted only if a line of it
    matches _is_agent_scan_command; this works for JSON and TOML alike. Anything
    else, including a file that cannot be read or decoded as UTF-8, is left alone.
    """
    legacy = Path(str(path) + ".backup")
    if not legacy.is_file():
        return
    try:
        text = legacy.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return
    if not any(_is_agent_scan_command(line) for line in text.splitlines()):
        return
    if _unlink_backup(legacy):
        rich.print(f"[dim]Removed old Agent Guard backup {legacy} (it contained the Agent Guard hook command)[/dim]")


def _backup_file(path: Path, guard_free_content: Callable[[], str | None], *, newline: str | None = None) -> None:
    """Back up ``path`` to ``<path>.snyk-agent-guard.backup`` before install rewrites it.

    The backup never holds Agent Guard config (its PUSH_KEY in particular):

    - ``guard_free_content()`` returns None when the file has no Guard entries:
      the backup is a byte copy of the file.
    - It returns the file's content with Guard removed (what uninstall would
      leave) when the file has Guard entries, e.g. on a re-install: that text is
      written atomically, with the live file's permission bits (and ``newline``, see
      _atomic_write_text).
    - If it raises ValueError (including CodexRequirementsError and JSON/UTF-8
      decode errors), TypeError or AttributeError, no backup is written, any
      existing backup is left as is, and a warning is printed.
    """
    if not path.exists():
        return
    backup = _guard_backup_path(path)
    try:
        content = guard_free_content()
    except (ValueError, TypeError, AttributeError) as exc:
        rich.print(
            f"[yellow]Warning:[/yellow] Not backing up {path}: could not remove the Agent Guard "
            f"config from the copy ({exc}). Any existing {backup.name} is left unchanged."
        )
        return
    if content is None:
        shutil.copy2(path, backup)
    else:
        _atomic_write_text(backup, content, mode=stat.S_IMODE(path.stat().st_mode), newline=newline)
    rich.print(f"[green]\u2713[/green]  Backed up [dim]{path}[/dim] \u2192 [dim]{backup}[/dim]")


def _create_sibling_temp_file(target: Path, mode: int) -> tuple[int, Path]:
    """Exclusively create a hidden temp file next to ``target``; return (fd, path).

    Unlike ``tempfile.mkstemp`` (always 0600), ``mode`` is passed to ``os.open``
    so the process umask applies, exactly as for ``open(path, "w")``, without
    the thread-unsafe ``os.umask`` read-and-restore dance.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    for _ in range(100):
        tmp = target.with_name(f".{target.name}.{secrets.token_hex(6)}.tmp")
        try:
            return os.open(tmp, flags, mode), tmp
        except FileExistsError:
            continue
    raise FileExistsError(f"Could not create a temporary file next to {target}")


def _atomic_write_text(path: Path, content: str, *, mode: int | None = None, newline: str | None = None) -> None:
    """Replace ``path`` with ``content`` (UTF-8) atomically.

    The content goes to a temp file in the target's directory, is fsynced, and
    is then moved over the target with ``os.replace``, so a crash, kill or full
    disk leaves either the old file or the new one, never a truncated one.

    - Symlinks are resolved first: a symlinked config stays a symlink and its
      target is updated.
    - Missing parent directories are created.
    - Newlines are written in text mode (``\\n`` becomes ``os.linesep``), the same
      as the ``open(path, "w")`` / ``Path.write_text`` calls this replaces.
      ``newline=""`` writes ``content`` as is.
    - An existing target keeps its permission bits (POSIX) and, when running
      as root, its owner and group (best effort). A new file gets the usual
      umask-based permissions. ``mode``, if given, sets the permission bits
      instead (POSIX); the content is never readable beyond them, even briefly.
    - Limitation: nothing else carries over, because the target becomes a new
      file. ACLs, extended attributes (e.g. a hand-set SELinux label) and file
      flags are lost, the file gets its directory's inherited ACL, and other
      hard links keep the old content. Copying these differs per OS, so it is
      documented instead (docs/cli-reference.md, ``guard install``).
    - On any failure the temp file is removed and the exception re-raised.
    """
    target = path.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing: os.stat_result | None = target.stat()
    except FileNotFoundError:
        existing = None

    # Start private when replacing an existing file or setting a mode; the chmod below sets the bits.
    private = existing is not None or mode is not None
    fd, tmp = _create_sibling_temp_file(target, 0o600 if private else 0o666)
    try:
        if not IS_WINDOWS:
            # On Windows chmod only toggles the read-only flag; copying it would
            # make the temp file impossible to clean up if os.replace fails.
            if mode is not None:
                os.chmod(tmp, mode)
            elif existing is not None:
                shutil.copymode(target, tmp)
            if existing is not None and hasattr(os, "geteuid") and os.geteuid() == 0:
                with contextlib.suppress(OSError):
                    os.chown(tmp, existing.st_uid, existing.st_gid)
        with os.fdopen(fd, "w", encoding="utf-8", newline=newline) as f:
            fd = -1  # now owned (and closed) by f
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        if fd != -1:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise

    if not IS_WINDOWS:
        # Persist the rename itself; best effort, not all filesystems allow it.
        with contextlib.suppress(OSError):
            dir_fd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)


_LONE_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _dump_config_json(data: dict) -> str:
    """Serialise a user's agent config for writing back to disk.

    Non-ASCII characters are written as-is, so a user's ``"café ☕"`` stays
    readable after install/uninstall instead of becoming ``\\u`` escapes.

    The one exception is a lone surrogate: ``json.load`` accepts ``"\\ud800"``,
    but the resulting character cannot be encoded as UTF-8, so the write would
    fail. Such characters are re-escaped (they can only occur inside JSON
    strings), which keeps the file valid UTF-8 and loads back to the same value.
    """
    content = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    return _LONE_SURROGATE_RE.sub(lambda m: f"\\u{ord(m.group()):04x}", content)


def _read_json_or_empty(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json_if_changed(path: Path, data: dict, *, client: str) -> bool:
    """Write *client*'s JSON config to path only if content differs. Returns True if written.

    The current file is backed up first, without any Agent Guard hooks (see _backup_file).
    """
    new_content = _dump_config_json(data)
    if path.exists():
        old_content = path.read_text(encoding="utf-8")
        if old_content == new_content:
            return False
        _backup_file(path, lambda: _json_config_without_guard(path, client))
    _atomic_write_text(path, new_content)
    return True


def _json_config_without_guard(path: Path, client: str) -> str | None:
    """*client*'s JSON config at ``path`` without Agent Guard, or None if it has no Guard hooks."""
    data = _read_json_or_empty(path)
    stripped = _strip_guard_from_json_config(data, client)
    return None if stripped == data else _dump_config_json(stripped)


def _write_json(path: Path, data: dict) -> None:
    _atomic_write_text(path, _dump_config_json(data))


def _preserved_note(count: int) -> str:
    if count == 0:
        return ""
    return f"  [dim]({count} other hook(s) preserved)[/dim]"
