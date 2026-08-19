"""Docker orchestration for the execution sandbox."""

from __future__ import annotations

import subprocess
from pathlib import Path

SANDBOX_IMAGE = "agent-scan-sandbox:local"
PROXY_IMAGE = "agent-scan-sandbox-proxy:local"
PROXY_PORT = 8888

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]


def build_images(repo_root: Path = DEFAULT_REPO_ROOT) -> None:
    # The sandbox image installs `snyk-agent-scan` from this checkout, so its build
    # context must be the repo root (not sandbox/) in order to COPY pyproject.toml,
    # uv.lock, README.md, and src/ into the image.
    subprocess.run(
        ["docker", "build", "-f", str(repo_root / "sandbox" / "Dockerfile"), "-t", SANDBOX_IMAGE, str(repo_root)],
        check=True,
    )
    subprocess.run(
        ["docker", "build", "-t", PROXY_IMAGE, str(repo_root / "sandbox" / "proxy")],
        check=True,
    )
