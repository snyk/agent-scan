"""Runs backend ops on the local filesystem, under the local policy."""

import base64
import glob
import hashlib
import os
from pathlib import Path
from typing import Any

from agent_scan.remote_discovery import policy
from agent_scan.remote_discovery.upload import MockFileUploadApi, MockRevision, revision_path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def manifest_sha256(files: list[tuple[str, str]]) -> str:
    """Hash of (relative path, sha256) pairs. Must match the backend's rule."""
    lines = "".join(f"{path}\0{sha}\n" for path, sha in sorted(files))
    return hashlib.sha256(lines.encode()).hexdigest()


def _read_regular(path: str, cap: int) -> bytes | str:
    """File bytes, or a skip reason. Follows symlinks like agent-scan's local reads."""
    p = Path(path)
    try:
        if not p.exists():
            return "missing"
        if not p.is_file():
            return "not a regular file"
        if p.stat().st_size > cap:
            return f"larger than {cap} bytes"
        return p.read_bytes()
    except OSError as exc:
        return f"unreadable: {exc.strerror or type(exc).__name__}"


class Executor:
    def __init__(self, uploader: MockFileUploadApi, revision: MockRevision) -> None:
        self.uploader = uploader
        self.revision = revision
        # (handler, path) -> sha256 already sent inline this scan.
        self.sent: dict[tuple[str, str], str] = {}
        # revision path -> sha256 already uploaded this scan.
        self.uploaded: dict[str, str] = {}

    def run(self, op: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {"op_id": op["op_id"], "ctx": op["ctx"]}
        runner = {
            "env": self._env,
            "read": self._read,
            "glob": self._glob,
            "find": self._find,
            "upload_tree": self._upload_tree,
        }.get(op["kind"])
        if runner is None:
            return {**result, "status": "UNSUPPORTED", "error": f"unknown op kind {op['kind']}"}
        try:
            return {**result, **runner(op)}
        except policy.PolicyError as exc:
            return {**result, "status": "DENIED_BY_POLICY", "error": str(exc)}

    # env: values of allowed names only

    def _env(self, op: dict[str, Any]) -> dict[str, Any]:
        names = op.get("names") or []
        env = {n: os.environ.get(n) for n in names if policy.env_name_allowed(n)}
        denied = [n for n in names if not policy.env_name_allowed(n)]
        return {"env": env, **({"denied": denied} if denied else {})}

    # read / glob: inline bytes

    def _inline(self, handler: str, paths: list[str]) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        missing: list[str] = []
        unchanged: list[str] = []
        skipped: list[dict[str, str]] = []
        for path in paths:
            data = _read_regular(path, policy.MAX_INLINE_FILE_BYTES)
            if data == "missing":
                missing.append(path)
                continue
            if isinstance(data, str):
                skipped.append({"path": path, "reason": data})
                continue
            digest = _sha256(data)
            if self.sent.get((handler, path)) == digest:
                unchanged.append(path)
                continue
            self.sent[(handler, path)] = digest
            files.append(
                {
                    "path": path,
                    "sha256": digest,
                    "size": len(data),
                    "bytes_b64": base64.b64encode(data).decode(),
                }
            )
        out: dict[str, Any] = {"files": files}
        for key, value in (("missing", missing), ("unchanged", unchanged), ("skipped", skipped)):
            if value:
                out[key] = value
        return out

    def _read(self, op: dict[str, Any]) -> dict[str, Any]:
        paths = op.get("paths") or []
        for path in paths:
            policy.check_inline_file(path)
        return self._inline(op["handler"], paths)

    def _glob(self, op: dict[str, Any]) -> dict[str, Any]:
        matches: list[str] = []
        for pattern in op.get("patterns") or []:
            policy.check_glob(pattern)
            matches.extend(sorted(glob.glob(pattern)))
        return self._inline(op["handler"], matches[: policy.MAX_GLOB_MATCHES])

    # find: listing only, no bytes

    def _find(self, op: dict[str, Any]) -> dict[str, Any]:
        roots = op.get("roots") or []
        file_names = set(op.get("file_names") or [])
        dir_names = set(op.get("dir_names") or [])
        max_depth = int(op.get("max_depth") or 0)
        policy.check_find(roots, [*file_names, *dir_names], max_depth)
        matches: list[dict[str, str]] = []
        for root in roots:
            if not os.path.isdir(root):
                continue
            # os.walk does not follow directory symlinks.
            for cur, dirs, files in os.walk(root):
                depth = len(Path(cur).relative_to(root).parts)
                matches.extend({"path": f"{cur}/{n}", "kind": "file"} for n in sorted(files) if n in file_names)
                matches.extend({"path": f"{cur}/{n}", "kind": "dir"} for n in sorted(dirs) if n in dir_names)
                if depth + 1 >= max_depth:
                    dirs.clear()
                if len(matches) >= policy.MAX_FIND_MATCHES:
                    break
        return {"matches": matches[: policy.MAX_FIND_MATCHES]}

    # upload_tree: bytes to the revision; only a count and manifest hash to the backend

    def _upload_tree(self, op: dict[str, Any]) -> dict[str, Any]:
        dirs = op.get("dirs") or []
        max_depth = min(int(op.get("max_depth") or policy.MAX_UPLOAD_DEPTH), policy.MAX_UPLOAD_DEPTH)
        for d in dirs:
            policy.check_upload_dir(d)
        listings: list[dict[str, Any]] = []
        skipped: list[dict[str, str]] = []
        to_upload: list[tuple[str, bytes]] = []
        for d in dirs:
            if not os.path.isdir(d):
                listings.append({"path": d, "status": "NOT_FOUND"})
                continue
            listed: list[tuple[str, str]] = []
            for cur, subdirs, files in os.walk(d):
                rel_dir = Path(cur).relative_to(d)
                subdirs[:] = sorted(s for s in subdirs if s not in policy.PRUNE_DIRS)
                if len(rel_dir.parts) + 1 >= max_depth:
                    subdirs.clear()
                for name in sorted(files):
                    full = f"{cur}/{name}"
                    if os.path.islink(full):
                        skipped.append({"path": full, "reason": "symlink"})
                        continue
                    data = _read_regular(full, policy.MAX_UPLOAD_FILE_BYTES)
                    if isinstance(data, str):
                        skipped.append({"path": full, "reason": data})
                        continue
                    digest = _sha256(data)
                    listed.append(((rel_dir / name).as_posix(), digest))
                    rpath = revision_path(full)
                    if self.uploaded.get(rpath) != digest:
                        self.uploaded[rpath] = digest
                        to_upload.append((rpath, data))
                    if len(listed) >= policy.MAX_UPLOAD_FILES_PER_DIR:
                        break
                if len(listed) >= policy.MAX_UPLOAD_FILES_PER_DIR:
                    break
            listings.append(
                {"path": d, "status": "OK", "file_count": len(listed), "manifest_sha256": manifest_sha256(listed)}
            )
        if to_upload:
            self.uploader.upload_files(self.revision, to_upload)
        out: dict[str, Any] = {"dirs": listings}
        if skipped:
            out["skipped"] = skipped
        return out
