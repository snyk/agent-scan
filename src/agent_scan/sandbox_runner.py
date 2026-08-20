"""Docker orchestration for the execution sandbox."""

from __future__ import annotations

import json
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from agent_scan.sandbox_config import build_sandbox_config

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


@dataclass
class SandboxScanResult:
    exit_code: int
    stdout: str
    stderr: str
    results: dict | None


def run_sandboxed_scan(
    target: str,
    input_dir: Path | None = None,
    extra_args: list[str] | None = None,
) -> SandboxScanResult:
    """Resolve ``target`` and scan it inside the two-container sandbox.

    ``target`` is either a direct-scan prefixed string (``npm:...``,
    ``pypi:...``) or a path relative to ``input_dir`` pointing at the
    client-supplied config file. Both containers and the per-scan network
    are torn down unconditionally, whether or not the scan succeeds.
    """
    run_id = uuid.uuid4().hex[:8]
    network = f"agent-scan-sandbox-net-{run_id}"
    proxy_name = f"agent-scan-sandbox-proxy-{run_id}"
    proxy_url = f"http://{proxy_name}:{PROXY_PORT}"

    config = build_sandbox_config(target, proxy_url, input_dir=input_dir)

    subprocess.run(["docker", "network", "create", network, "--internal"], check=True, capture_output=True)
    try:
        subprocess.run(
            ["docker", "run", "-d", "--name", proxy_name, "--network", "bridge", PROXY_IMAGE],
            check=True,
            capture_output=True,
        )
        subprocess.run(["docker", "network", "connect", network, proxy_name], check=True, capture_output=True)

        with tempfile.TemporaryDirectory() as scratch:
            config_path = Path(scratch) / "mcp.generated.json"
            config_path.write_text(json.dumps(config))

            run_args = [
                "docker",
                "run",
                "--rm",
                "--network",
                network,
                "-v",
                f"{scratch}:/scan-config:ro",
            ]
            if input_dir is not None:
                run_args += ["-v", f"{input_dir}:/scan-input:ro"]
            run_args += [
                SANDBOX_IMAGE,
                "snyk-agent-scan",
                "scan",
                "/scan-config/mcp.generated.json",
                "--dangerously-run-mcp-servers",
                "--json",
            ]
            run_args += list(extra_args or [])

            proc = subprocess.run(run_args, capture_output=True, text=True)
    finally:
        subprocess.run(["docker", "rm", "-f", proxy_name], capture_output=True)
        subprocess.run(["docker", "network", "rm", network], capture_output=True)

    try:
        results = json.loads(proc.stdout)
    except json.JSONDecodeError:
        results = None
    return SandboxScanResult(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr, results=results)
