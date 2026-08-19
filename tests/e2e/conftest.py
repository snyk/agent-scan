"""Shared fixtures for Docker-gated end-to-end tests."""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=10)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False
    return True


requires_docker = pytest.mark.skipif(not docker_available(), reason="docker daemon not available")


@pytest.fixture(scope="session")
def sandbox_images():
    """Build the sandbox + proxy images once per test session."""
    if not docker_available():
        pytest.skip("docker daemon not available")
    from agent_scan.sandbox_runner import build_images

    build_images(REPO_ROOT)
