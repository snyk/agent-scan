"""Local identity store for ``guard login``.

``guard login`` binds this machine to a push key (the enrollment token a security engineer
issues from Evo) and a default profile. The ``guard run <client>`` launcher reads this to attach
identity to the events the hooks emit. v0 stores *who* (the push key), not yet *what* — the
profile bodies remain hardcoded in :mod:`agent_scan.sandbox`. This file is the seam through
which Evo will later serve per-role profiles without a CLI release.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

IDENTITY_PATH = Path.home() / ".config" / "snyk-agent-guard" / "identity.json"


def save_identity(
    push_key: str,
    tenant_id: str,
    url: str,
    default_profile: str,
    hostname: str,
    path: Path | None = None,
) -> Path:
    """Persist identity to a 0600 JSON file. Returns the path written."""
    path = path or IDENTITY_PATH
    data = {
        "push_key": push_key,
        "tenant_id": tenant_id,
        "url": url,
        "default_profile": default_profile,
        "hostname": hostname,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def load_identity(path: Path | None = None) -> dict | None:
    """Return stored identity, or None if the user hasn't run ``guard login``."""
    path = path or IDENTITY_PATH
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
