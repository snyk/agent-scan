"""Option B: ``guard run <client>`` — launch a coding agent under a guard-owned sandbox profile.

Each (client, profile) gets its own artifacts under
``~/.config/snyk-agent-guard/profiles/<client>/<profile>/`` so different sessions can run
different profiles concurrently without clobbering one another.

To keep the user's real environment (theme, auth, completed onboarding) we do NOT hand the
agent a blank config dir. Instead we layer hooks + sandbox on top of the user's own config:

* **Claude** — ``claude --settings <profile>/settings.json``. The CLI merges this over
  ~/.claude/settings.json for the session: our ``hooks``/``sandbox`` keys win, everything else
  (theme, auth, MCP servers) is inherited.
* **Codex** — ``CODEX_HOME=<profile>`` seeded from the user's ~/.codex (auth, session history, MCP
  servers). config.toml is merged (user's model/providers/profiles preserved, sandbox keys replaced)
  with our sandbox block prepended; our hooks are written in.

Identity comes from ``guard login`` (or PUSH_KEY/TENANT_ID env). CLI-only by design.
"""

from __future__ import annotations

import datetime
import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

import rich

from agent_scan import identity
from agent_scan import sandbox as sb
from agent_scan.hook_common import (
    DEFAULT_REMOTE_URL,
    _build_hook_command,
    _copy_hook_script,
    _hook_client_name,
    build_claude_hooks,
    build_codex_hooks,
)

IS_WINDOWS = sys.platform == "win32"

_BINARIES = {"claude": "claude", "codex": "codex"}
_PROFILES_ROOT = Path.home() / ".config" / "snyk-agent-guard" / "profiles"

# Codex seeds via symlinks (like Claude). These names are never linked into the profile:
# files guard materializes itself (config.toml/hooks*), plus bulky/volatile data codex re-creates
# on demand. config.toml is omitted so guard can re-render it minus our sandbox keys (see
# ``_seed_codex_config``) and prepend its block without TOML duplicate-key errors. Session state
# (sessions/, archived_sessions/, history.jsonl) is intentionally NOT skipped: symlinking it into
# CODEX_HOME lets ``codex resume`` find prior sessions and writes new ones back to the real ~/.codex.
_CODEX_SKIP_SEED = {
    "config.toml",
    "hooks.json",
    "hooks.json.backup",
    "log",
    "logs",
    "tmp",
    ".tmp",
    "tui",
}

# Top-level config.toml keys guard owns; stripped from the user's config before our block is
# prepended, so the merge can't produce a duplicate key. (``features.network_proxy`` is handled
# separately as a nested key.) This is the Codex analog of Claude's ``base.pop("sandbox")``.
_CODEX_SANDBOX_KEYS = ("approval_policy", "sandbox_mode", "sandbox_workspace_write")


def _resolve_identity(args) -> dict | None:
    ident = identity.load_identity()
    if ident and ident.get("push_key"):
        return ident
    push_key = os.environ.get("PUSH_KEY", "").strip()
    if push_key:
        return {
            "push_key": push_key,
            "tenant_id": os.environ.get("TENANT_ID", "").strip(),
            "url": getattr(args, "url", None) or DEFAULT_REMOTE_URL,
            "default_profile": sb.DEFAULT_PROFILE,
        }
    return None


def run_launch(args) -> int:
    client: str | None = getattr(args, "run_command", None)
    if client is None:
        rich.print(
            "[bold red]Error:[/bold red] specify an agent to run, e.g. "
            "[bold]snyk-agent-scan guard run claude[/bold]."
        )
        return 1
    ident = _resolve_identity(args)
    if ident is None:
        rich.print(
            "[bold red]Error:[/bold red] not logged in. Run "
            "[bold]snyk-agent-scan guard login[/bold] first (or set PUSH_KEY)."
        )
        return 1

    binary_path = shutil.which(_BINARIES[client])
    if not binary_path:
        rich.print(f"[bold red]Error:[/bold red] could not find the [bold]{_BINARIES[client]}[/bold] binary on PATH.")
        return 1

    profile_name = (getattr(args, "profile", None) or ident.get("default_profile") or sb.DEFAULT_PROFILE).strip()
    try:
        profile = sb.get_profile(profile_name)
    except ValueError as e:
        rich.print(f"[bold red]Error:[/bold red] {e}")
        return 1

    push_key = ident["push_key"]
    url = ident.get("url") or DEFAULT_REMOTE_URL
    tenant_id = ident.get("tenant_id") or ""

    profile_dir = _PROFILES_ROOT / client / profile_name
    profile_dir.mkdir(parents=True, exist_ok=True)

    hook_client = _hook_client_name(client)
    compiled = sb.compile_for(client, profile)

    cmd: list[str]
    env = dict(os.environ)

    if client == "claude":
        cmd = _prepare_claude(profile_dir, push_key, url, tenant_id, hook_client, compiled, env)
    else:  # codex
        cmd = _prepare_codex(profile_dir, push_key, url, tenant_id, hook_client, compiled, env)

    passthrough, removed = _sanitize_passthrough(client, list(getattr(args, "agent_args", None) or []))

    rich.print(
        f"[bold magenta]Agent Guard[/bold magenta] launching [bold]{_BINARIES[client]}[/bold] "
        f"under profile [bold]{profile_name}[/bold]"
    )
    for note in compiled.notes:
        rich.print(f"   [dim]• {note}[/dim]")
    for flag in removed:
        rich.print(f"   [yellow]• Dropped [bold]{flag}[/bold] — it would weaken the guard sandbox/session.[/yellow]")
    rich.print()
    # The agent is the interactive foreground app and owns Ctrl-C (e.g. "Press Ctrl-C again to
    # exit"). Both it and this launcher share the terminal's foreground process group, so SIGINT
    # reaches both. Ignore it in the launcher while the child runs so the child handles Ctrl-C
    # and we don't unwind with a KeyboardInterrupt traceback. subprocess resets the child's SIGINT
    # to default before exec, and the agent installs its own handler.
    prev_sigint = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        return subprocess.run([*cmd, *passthrough], env=env).returncode
    finally:
        signal.signal(signal.SIGINT, prev_sigint)


# ---------------------------------------------------------------------------
# Per-client preparation
# ---------------------------------------------------------------------------


def _write_hook_script(client: str, profile_dir: Path, push_key: str, url: str, tenant_id: str, hook_client: str) -> str:
    """Copy the hook script into the profile dir and return the hook command string."""
    anchor = profile_dir / "settings.json"  # only used to locate the hooks/ subdir
    dest_script, _, _ = _copy_hook_script(client, anchor)
    return _build_hook_command(push_key, url, dest_script, hook_client, tenant_id=tenant_id)


def _prepare_claude(profile_dir, push_key, url, tenant_id, hook_client, compiled, env):
    """Point Claude at a guard-owned CLAUDE_CONFIG_DIR whose settings.json is authoritative.

    Why not ``--settings``: Claude MERGES array keys like ``sandbox.network.allowedDomains``
    across every settings scope (managed/user/--settings) and never replaces them, so a strict
    profile's empty allowlist can't remove domains the user already has in ~/.claude/settings.json.
    A separate CLAUDE_CONFIG_DIR means ~/.claude/settings.json isn't read at all, so our
    settings.json defines the sandbox. We seed the dir with symlinks to the user's other config
    (~/.claude.json for auth/onboarding, plugins, skills, ...) so nothing re-prompts.
    """
    home_claude = Path.home() / ".claude"
    home_claude_json = Path.home() / ".claude.json"

    _reset_dir(profile_dir)
    # Seed everything except the files we own (settings + hooks).
    if home_claude.exists():
        for entry in home_claude.iterdir():
            if entry.name in ("settings.json", "settings.local.json", "hooks"):
                continue
            _symlink(entry, profile_dir / entry.name)
    if home_claude_json.exists():
        _symlink(home_claude_json, profile_dir / ".claude.json")

    command = _write_hook_script("claude", profile_dir, push_key, url, tenant_id, hook_client)

    # Inherit the user's non-sandbox settings, then REPLACE hooks + sandbox with the profile's.
    base: dict = {}
    user_settings = home_claude / "settings.json"
    if user_settings.exists():
        try:
            base = json.loads(user_settings.read_text())
        except (json.JSONDecodeError, OSError):
            base = {}
    base.pop("sandbox", None)
    base["hooks"] = build_claude_hooks(command)
    base.update(compiled.config)  # compiled.config == {"sandbox": {...}}
    (profile_dir / "settings.json").write_text(json.dumps(base, indent=2) + "\n")

    env["CLAUDE_CONFIG_DIR"] = str(profile_dir)
    return [shutil.which("claude")]


def _prepare_codex(profile_dir, push_key, url, tenant_id, hook_client, compiled, env):
    """Point Codex at a guard-owned CODEX_HOME, seeded with symlinks to the user's ~/.codex.

    We symlink rather than copy (the old approach choked on ~/.codex's git repos, multi-MB sqlite
    logs, dangling skill links, and read-only pack files). Auth, session history, MCP servers, etc.
    carry over via the links; guard materializes config.toml and hooks.json, which are never linked.

    config.toml is MERGED (like Claude's settings.json): the user's config has guard's sandbox keys
    overlaid onto it and is rendered once. This preserves model choice, providers, and profiles —
    which a sandbox-only config would silently drop.
    """
    home_codex = Path.home() / ".codex"
    _reset_dir(profile_dir)
    if home_codex.exists():
        for entry in home_codex.iterdir():
            if entry.name in _CODEX_SKIP_SEED or entry.name.endswith(".log"):
                continue
            _symlink(entry, profile_dir / entry.name)
    command = _write_hook_script("codex", profile_dir, push_key, url, tenant_id, hook_client)
    # Hooks
    (profile_dir / "hooks.json").write_text(json.dumps({"hooks": build_codex_hooks(command)}, indent=2) + "\n")
    # config.toml: overlay guard's sandbox config onto the user's and render once (see _write_codex_config).
    _write_codex_config(home_codex / "config.toml", profile_dir / "config.toml", compiled.config)
    env["CODEX_HOME"] = str(profile_dir)
    return [shutil.which("codex")]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_dir(d: Path) -> None:
    """Recreate an empty dir, dropping stale symlinks/files from a previous launch.

    rmtree unlinks symlinks rather than following them, so the user's real files are never touched.
    """
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True, exist_ok=True)


def _symlink(src: Path, dst: Path) -> None:
    """Symlink src -> dst, falling back to a copy where symlinks aren't permitted."""
    try:
        dst.symlink_to(src, target_is_directory=src.is_dir())
    except OSError:
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)


def _toml_key(k: str) -> str:
    """Render a TOML key: bare for [A-Za-z0-9_-], otherwise a quoted basic string."""
    return k if k and all(c.isalnum() or c in "_-" for c in k) else '"' + k.replace('"', '\\"') + '"'


def _toml_value(v: object) -> str:
    """Render any tomllib-parsed value as TOML, using inline tables/arrays for dicts/lists."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    if isinstance(v, (datetime.datetime, datetime.date, datetime.time)):
        return v.isoformat()
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{_toml_key(k)} = {_toml_value(x)}" for k, x in v.items()) + " }"
    raise TypeError(f"Unsupported TOML value: {v!r}")


def _toml_dumps(data: dict) -> str:
    """Serialize a dict to TOML as top-level ``key = <inline value>`` lines (no [section] headers).

    Inlining every nested table/array as one line per top-level key guarantees each key is written
    exactly once — which is what keeps a merged ``features`` (user flags + guard's network_proxy)
    from becoming a TOML duplicate key. Comments and key order from the source file are not
    preserved (only the values are).
    """
    return "".join(f"{_toml_key(k)} = {_toml_value(v)}\n" for k, v in data.items())


def _write_codex_config(home_config: Path, dest: Path, guard_config: dict) -> None:
    """Render the user's config.toml with guard's sandbox config overlaid, into ``dest``.

    The Codex analog of Claude's settings merge: model, providers, profiles, and MCP servers carry
    over while guard owns the sandbox. We first drop the keys guard owns
    (``approval_policy``/``sandbox_mode``/``sandbox_workspace_write`` and the nested
    ``features.network_proxy``) so no stale user value lingers where guard doesn't set one, then
    overlay ``guard_config``. ``features`` is merged one level deep: guard's ``network_proxy`` and
    the user's other feature flags must share a single ``features`` key, because rendering both a
    user ``features = {...}`` and a guard ``features.network_proxy = ...`` is a TOML duplicate-key
    error (the bug this replaced). The whole dict is rendered once, so every key appears exactly
    once. An unreadable user config falls back to guard's keys alone.
    """
    data: dict = {}
    if home_config.exists():
        try:
            data = tomllib.loads(home_config.read_text())
        except (tomllib.TOMLDecodeError, OSError, ValueError):
            data = {}
    for key in _CODEX_SANDBOX_KEYS:
        data.pop(key, None)
    features = data.get("features")
    if isinstance(features, dict):
        features.pop("network_proxy", None)
        if not features:
            data.pop("features", None)
    for key, val in guard_config.items():
        if key == "features" and isinstance(data.get("features"), dict) and isinstance(val, dict):
            data["features"] = {**data["features"], **val}
        else:
            data[key] = val
    dest.write_text(_toml_dumps(data))


# Boolean flags that would bypass the sandbox the guard session exists to enforce.
# NOTE: Claude's --dangerously-skip-permissions is intentionally NOT listed: per the Claude Code
# docs it only suppresses the permission-prompt layer — hooks (PreToolUse can still block) and the
# OS sandbox (Seatbelt/bubblewrap) both compose independently and remain enforced. We let it through
# so users can drop prompts without losing the guard's real defenses. Codex's --yolo /
# --dangerously-bypass-approvals-and-sandbox DO disable the sandbox too, so they stay denied; the
# sandbox-preserving codex equivalent (--full-auto / -a never) is not a bypass and is left alone.
_BYPASS_BOOL = {
    "claude": set(),
    "codex": {"--dangerously-bypass-approvals-and-sandbox", "--yolo"},
}
# Value flags whose dangerous value disables the sandbox (token, dangerous-value).
_BYPASS_VALUE = {
    "codex": {("--sandbox", "danger-full-access"), ("-s", "danger-full-access")},
}


def _sanitize_passthrough(client: str, toks: list[str]) -> tuple[list[str], list[str]]:
    """Drop forwarded flags that would undermine the guard session. Returns (clean, removed).

    Removed: per-client bypass/yolo flags, sandbox-off value flags, and — for Claude — any
    user-supplied ``--settings`` (we inject our own profile settings and a later one would win).
    """
    bool_deny = _BYPASS_BOOL.get(client, set())
    value_deny = _BYPASS_VALUE.get(client, set())
    out: list[str] = []
    removed: list[str] = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        # Claude: never let a forwarded --settings override the one we inject.
        if client == "claude" and (tok == "--settings" or tok.startswith("--settings=")):
            if tok == "--settings" and nxt is not None:
                removed.append(f"{tok} {nxt}")
                i += 2
            else:
                removed.append(tok)
                i += 1
            continue
        if tok in bool_deny:
            removed.append(tok)
            i += 1
            continue
        if nxt is not None and (tok, nxt) in value_deny:
            removed.append(f"{tok} {nxt}")
            i += 2
            continue
        if "=" in tok and (tok.split("=", 1)[0], tok.split("=", 1)[1]) in value_deny:
            removed.append(tok)
            i += 1
            continue
        out.append(tok)
        i += 1
    return out, removed
