"""Mock of the Snyk file upload API (hidden, 2024-10-15~beta).

No network calls. Shapes and limits follow the workspace-service spec
(src/testSupport/fileUploadApiClient/apiSpecs/hidden/versions/2024-10-15/spec.yaml)
and scm-bundle-store config, so the real client can drop in later.
"""

import hashlib
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

API_VERSION = "2024-10-15~beta"
MAX_REQUEST_BYTES = 50 * 1024 * 1024
MAX_PATH_CHARS = 256
MAX_PARTS = 210

Printer = Callable[[str, str, str, Any, int, Any], None]


class UploadError(RuntimeError):
    pass


def revision_path(abs_path: str) -> str:
    """Path inside the revision. Over-long paths get a hashed stand-in."""
    rel = abs_path.lstrip("/")
    if len(rel) <= MAX_PATH_CHARS:
        return rel
    digest = hashlib.sha256(rel.encode()).hexdigest()[:32]
    return f"_long/{digest}/{rel.rsplit('/', 1)[-1]}"[:MAX_PATH_CHARS]


@dataclass
class MockRevision:
    id: str
    sealed: bool = False
    parts: int = 0
    files: dict[str, str] = field(default_factory=dict)  # revision path -> sha256


class MockFileUploadApi:
    def __init__(self, org_id: str, printer: Printer, base_url: str = "https://api.snyk.io") -> None:
        self.org_id = org_id
        self.base = f"{base_url}/hidden/orgs/{org_id}/upload_revisions"
        self._print = printer

    def create_revision(self) -> MockRevision:
        body = {"data": {"attributes": {"revision_type": "snapshot"}, "type": "upload_revision"}}
        rev = MockRevision(id=str(uuid.uuid4()))
        resp = {
            "data": {
                "attributes": {"revision_type": "snapshot", "sealed": False},
                "id": rev.id,
                "type": "upload_revision",
            },
            "jsonapi": {"version": "1.0"},
        }
        self._print("MOCK file upload API", "POST", f"{self.base}?version={API_VERSION}", body, 201, resp)
        return rev

    def upload_files(self, rev: MockRevision, files: list[tuple[str, bytes]]) -> None:
        """One multipart request per <=50 MB batch. Part name = revision path."""
        if rev.sealed:
            raise UploadError("revision is sealed (ErrRevisionNotWritable)")
        batch: list[tuple[str, bytes]] = []
        size = 0
        for path, data in files:
            if batch and size + len(data) > MAX_REQUEST_BYTES:
                self._send(rev, batch)
                batch, size = [], 0
            batch.append((path, data))
            size += len(data)
        if batch:
            self._send(rev, batch)

    def _send(self, rev: MockRevision, batch: list[tuple[str, bytes]]) -> None:
        if rev.parts >= MAX_PARTS:
            raise UploadError(f"revision part limit reached ({MAX_PARTS})")
        rev.parts += 1
        for path, data in batch:
            rev.files[path] = hashlib.sha256(data).hexdigest()
        body = {
            "content-type": "multipart/form-data",
            "content-encoding": "gzip",
            "part_count": len(batch),
            "total_bytes": sum(len(data) for _, data in batch),
            "parts": [{"name": path, "bytes": len(data)} for path, data in batch],
        }
        self._print(
            "MOCK file upload API",
            "POST",
            f"{self.base}/{rev.id}/files?version={API_VERSION}",
            body,
            204,
            None,
        )

    def seal(self, rev: MockRevision) -> None:
        body = {"data": {"attributes": {"sealed": True}, "id": rev.id, "type": "upload_revision"}}
        rev.sealed = True
        resp = {
            "data": {
                "attributes": {"revision_type": "snapshot", "sealed": True},
                "id": rev.id,
                "type": "upload_revision",
            },
            "jsonapi": {"version": "1.0"},
        }
        self._print("MOCK file upload API", "PATCH", f"{self.base}/{rev.id}?version={API_VERSION}", body, 200, resp)
