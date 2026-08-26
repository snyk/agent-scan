"""Runtime resolution of user-level client configuration directories."""

from __future__ import annotations

import os
from pathlib import Path

_CLIENT_DIR_SETTINGS: dict[str, tuple[str | None, str]] = {
    "claude": ("CLAUDE_CONFIG_DIR", ".claude"),
    "cursor": (None, ".cursor"),
    "codex": ("CODEX_HOME", ".codex"),
}


def user_client_dir_override(client: str) -> Path | None:
    """Return a non-empty environment path with its user marker expanded."""
    try:
        env_var, _ = _CLIENT_DIR_SETTINGS[client]
    except KeyError as exc:
        raise ValueError(f"Unknown client: {client}") from exc
    if env_var is None:
        return None
    value = os.environ.get(env_var)
    if not value:
        return None
    if value == "~":
        return Path(os.environ.get("HOME") or Path.home())
    if value.startswith(("~/", "~\\")) and os.environ.get("HOME"):
        return Path(os.environ["HOME"]) / value[2:]
    return Path(value).expanduser()


def resolve_user_client_dir(
    client: str,
    *,
    home_directory: Path | None = None,
    honor_environment: bool = True,
) -> Path:
    """Resolve a client's user-level configuration directory at call time.

    ``home_directory`` supports discovery of a specific user's default directory.
    Environment overrides describe only the current process's user, so callers
    scanning another user's home must pass ``honor_environment=False``.
    """
    try:
        env_var, default_dir = _CLIENT_DIR_SETTINGS[client]
    except KeyError as exc:
        raise ValueError(f"Unknown client: {client}") from exc

    if honor_environment and env_var:
        configured = user_client_dir_override(client)
        if configured is not None:
            return configured

    home = Path.home() if home_directory is None else home_directory
    return home / default_dir
