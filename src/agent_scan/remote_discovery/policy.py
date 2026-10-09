"""Local policy: the hard limit on what the backend may ask this machine to read.

The backend can't widen it. Anything outside it is answered with DENIED_BY_POLICY.
"""

import posixpath
import re

# Env vars often hold API keys, so only path-like names may be sent.
ENV_NAMES = frozenset(
    {
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "CLAUDE_CONFIG_DIR",
        "CODEX_HOME",
        "COPILOT_HOME",
        "OPENCODE_CONFIG",
        "OPENCODE_CONFIG_DIR",
        "OPENCODE_DB",
        "VSCODE_PORTABLE",
    }
)
ENV_NAME_PATTERN = re.compile(r"XDG_[A-Z_]+_(HOME|DIRS)")

INLINE_FILE_NAMES = frozenset({"mcp.json", ".mcp.json", "settings.json", "workspace.json", "extensions.json"})
FIND_NAMES = frozenset({"mcp.json", ".mcp.json", "skills"})
UPLOAD_DIR_NAMES = frozenset({"skills", "skills-cursor"})

MAX_INLINE_FILE_BYTES = 5 * 1024 * 1024
MAX_UPLOAD_FILE_BYTES = 1024 * 1024
MAX_UPLOAD_FILES_PER_DIR = 2000
MAX_GLOB_MATCHES = 500
MAX_FIND_MATCHES = 2000
MAX_FIND_DEPTH = 12
MAX_UPLOAD_DEPTH = 6
PRUNE_DIRS = frozenset({".git", "node_modules", "__pycache__"})


class PolicyError(ValueError):
    pass


def env_name_allowed(name: str) -> bool:
    return name in ENV_NAMES or ENV_NAME_PATTERN.fullmatch(name) is not None


def check_abs(path: str) -> None:
    if not path.startswith("/") or "\0" in path:
        raise PolicyError("path must be absolute")
    if ".." in path.split("/"):
        raise PolicyError("path must not contain '..'")


def check_inline_file(path: str) -> None:
    check_abs(path)
    if posixpath.basename(path) not in INLINE_FILE_NAMES:
        raise PolicyError(f"file name not allowed: {posixpath.basename(path)}")


def check_glob(pattern: str) -> None:
    check_abs(pattern)
    if "**" in pattern:
        raise PolicyError("recursive glob not allowed")
    # The file name must be literal, so a glob can only hit allowed names.
    check_inline_file(pattern)


def check_find(roots: list[str], names: list[str], max_depth: int) -> None:
    for root in roots:
        check_abs(root)
    bad = set(names) - FIND_NAMES
    if bad:
        raise PolicyError(f"find names not allowed: {sorted(bad)}")
    if not 0 < max_depth <= MAX_FIND_DEPTH:
        raise PolicyError(f"max_depth must be 1..{MAX_FIND_DEPTH}")


def check_upload_dir(path: str) -> None:
    check_abs(path)
    if posixpath.basename(path.rstrip("/")) not in UPLOAD_DIR_NAMES:
        raise PolicyError(f"upload dir not allowed: {posixpath.basename(path)}")
