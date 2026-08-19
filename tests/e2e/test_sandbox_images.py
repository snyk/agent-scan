"""Docker-gated tests that the sandbox images build and run."""

import subprocess

from agent_scan.sandbox_runner import DEFAULT_REPO_ROOT, SANDBOX_IMAGE
from tests.e2e.conftest import requires_docker


@requires_docker
def test_sandbox_image_runs_agent_scan():
    # Build context must be the repo root (not sandbox/) so the Dockerfile can COPY
    # pyproject.toml, uv.lock, README.md, and src/ from this checkout into the image.
    subprocess.run(
        [
            "docker",
            "build",
            "-f",
            str(DEFAULT_REPO_ROOT / "sandbox" / "Dockerfile"),
            "-t",
            SANDBOX_IMAGE,
            str(DEFAULT_REPO_ROOT),
        ],
        check=True,
    )
    proc = subprocess.run(
        ["docker", "run", "--rm", SANDBOX_IMAGE, "snyk-agent-scan", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "Snyk Agent Scan" in proc.stdout
