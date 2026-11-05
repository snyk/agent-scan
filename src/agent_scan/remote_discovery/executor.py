"""Run backend ops on the local filesystem. Ops are run literally; contents are never
interpreted here.

``find`` mirrors legacy's ``os.walk(followlinks=False)`` walks with depth pruning.

Paths use ``/`` both ways, also on Windows (``C:/Users/me``), which the OS accepts.
"""

import base64
import logging
import os
import posixpath
import stat as stat_module
from typing import Any

logger = logging.getLogger(__name__)

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_FIND_MATCHES = 10_000
MAX_FIND_READ_BYTES = 50 * 1024 * 1024
CAPABILITIES = ["stat", "read", "find"]


def to_wire(path: str) -> str:
    """Native path -> ``/`` separators. A backslash is a valid name character off Windows."""
    return path.replace("\\", "/") if os.name == "nt" else path


def _realpath(path: str) -> str | None:
    try:
        return to_wire(os.path.realpath(path))
    except (OSError, ValueError):
        return None


def _stat(op: dict[str, Any]) -> dict[str, Any]:
    entries = []
    for path in op["paths"]:
        try:
            entries.append(
                {
                    "path": path,
                    "exists": os.path.exists(path),
                    "is_dir": os.path.isdir(path),
                    "is_file": os.path.isfile(path),
                    "is_symlink": os.path.islink(path),
                    "realpath": _realpath(path),
                }
            )
        except (OSError, ValueError):
            entries.append({"path": path, "exists": False})
    return {"entries": entries}


def _read(op: dict[str, Any]) -> dict[str, Any]:
    files, missing, skipped = [], [], []
    for path in op["paths"]:
        try:
            if not os.path.exists(path):
                missing.append(path)
                continue
            info = os.stat(path)
            if not stat_module.S_ISREG(info.st_mode):
                skipped.append({"path": path, "reason": "not_regular_file", "realpath": _realpath(path)})
                continue
            if info.st_size > MAX_FILE_BYTES:
                skipped.append({"path": path, "reason": "too_large", "realpath": _realpath(path)})
                continue
            with open(path, "rb") as f:
                data = f.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                skipped.append({"path": path, "reason": "too_large", "realpath": _realpath(path)})
                continue
        except (OSError, ValueError):
            skipped.append({"path": path, "reason": "unreadable", "realpath": _realpath(path)})
            continue
        files.append(
            {
                "path": path,
                "realpath": _realpath(path),
                "size": len(data),
                "content_b64": base64.b64encode(data).decode("ascii"),
            }
        )
    return {"files": files, "missing": missing, "skipped": skipped}


def _root_status(root: str) -> str:
    try:
        if not os.path.exists(root):
            return "missing"
        if not os.path.isdir(root):
            return "not_dir"
        with os.scandir(root):
            return "dir"
    except (OSError, ValueError):
        return "unreadable"


def _find(op: dict[str, Any]) -> dict[str, Any]:
    fold = str.lower if op.get("ignore_case") else (lambda s: s)
    file_names = {fold(n) for n in op.get("file_names", ())}
    dir_names = {fold(n) for n in op.get("dir_names", ())}
    max_depth = op["max_depth"]
    follow_child_links = op.get("follow_child_links", False)
    roots, matches = [], []
    truncated = False

    def walk(root: str, dirpath: str, depth: int) -> None:
        nonlocal truncated
        try:
            with os.scandir(dirpath) as it:
                entries = list(it)
        except (OSError, ValueError):
            # os.walk ignores unreadable folders.
            return
        descend = []
        for entry in entries:
            try:
                is_dir = entry.is_dir()
            except OSError:
                is_dir = False
            try:
                is_symlink = entry.is_symlink()
            except OSError:
                is_symlink = False
            name = fold(entry.name)
            path = posixpath.join(dirpath, entry.name)
            hit = name in (dir_names if is_dir else file_names)
            if hit:
                if len(matches) >= MAX_FIND_MATCHES:
                    truncated = True
                    return
                try:
                    is_file = entry.is_file()
                except OSError:
                    is_file = False
                matches.append(
                    {
                        "path": path,
                        "root": root,
                        "depth": depth + 1,
                        "is_dir": is_dir,
                        "is_file": is_file,
                        "is_symlink": is_symlink,
                    }
                )
            if is_dir and depth + 1 < max_depth and (not is_symlink or (follow_child_links and depth == 0)):
                descend.append(path)
        for child in descend:
            walk(root, child, depth + 1)

    for root in op["roots"]:
        status = _root_status(root)
        roots.append({"path": root, "status": status, "realpath": _realpath(root)})
        if status == "dir":
            walk(root, root, 0)
    out = {"roots": roots, "matches": matches, "truncated": truncated}
    if op.get("read"):
        out.update(_read_matches([m["path"] for m in matches if not m["is_dir"]]))
    return out


def _read_matches(paths: list[str]) -> dict[str, Any]:
    """``read`` for find hits, with a total size cap per op."""
    result = _read({"paths": paths})
    files, total = [], 0
    for f in result["files"]:
        total += f["size"]
        if total > MAX_FIND_READ_BYTES:
            result["skipped"].append({"path": f["path"], "reason": "too_large", "realpath": f["realpath"]})
        else:
            files.append(f)
    result["files"] = files
    return result


_RUNNERS = {"stat": _stat, "read": _read, "find": _find}


def run_op(op: dict[str, Any]) -> dict[str, Any]:
    kind = op.get("kind")
    base = {"op_id": op["op_id"], "kind": kind}
    runner = _RUNNERS.get(kind)
    if runner is None:
        return {**base, "status": "unsupported"}
    try:
        return {**base, "status": "ok", **runner(op)}
    except Exception:
        logger.exception("Discovery op %s failed", kind)
        return {**base, "status": "error"}
