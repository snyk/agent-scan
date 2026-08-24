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

# Generous ceiling on the scan container's own run: this is the one place that
# executes untrusted, scanned-server code, so a hang here must not hang the CLI
# forever.
SCAN_CONTAINER_TIMEOUT_SECONDS = 300


def _run_checked(args: list[str]) -> subprocess.CompletedProcess:
    """Run a Docker orchestration command, surfacing Docker's own stderr on failure.

    ``subprocess.CalledProcessError.__str__()`` does not include captured stderr, so
    a bare ``check=True`` failure hides the actual Docker error behind an unhelpful
    "returned non-zero exit status N".
    """
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"command {args!r} failed (exit {e.returncode}): {e.stderr}") from e


def build_images(repo_root: Path = DEFAULT_REPO_ROOT) -> None:
    # The sandbox image installs `snyk-agent-scan` from this checkout, so its build
    # context must be the repo root (not sandbox/) in order to COPY pyproject.toml,
    # uv.lock, README.md, and src/ into the image.
    dockerfile = repo_root / "sandbox" / "Dockerfile"
    if not dockerfile.is_file():
        raise RuntimeError(
            f"sandbox-scan --build requires a source checkout of agent-scan; "
            f"sandbox/Dockerfile not found at {dockerfile}. This isn't supported from a "
            f"pip install or the packaged binary yet."
        )
    _run_checked(["docker", "build", "-f", str(dockerfile), "-t", SANDBOX_IMAGE, str(repo_root)])
    _run_checked(["docker", "build", "-t", PROXY_IMAGE, str(repo_root / "sandbox" / "proxy")])


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
    extra_env: dict[str, str] | None = None,
) -> SandboxScanResult:
    """Resolve ``target`` and scan it inside the two-container sandbox.

    ``target`` is either a direct-scan prefixed string (``npm:...``,
    ``pypi:...``) or a path relative to ``input_dir`` pointing at the
    client-supplied config file. ``extra_env`` is merged into the scanned
    server's own env (e.g. credentials it needs), not the sandbox container's
    environment -- see ``build_sandbox_config``. Both containers and the
    per-scan network are torn down unconditionally, whether or not the scan
    succeeds.
    """
    run_id = uuid.uuid4().hex[:8]
    network = f"agent-scan-sandbox-net-{run_id}"
    proxy_name = f"agent-scan-sandbox-proxy-{run_id}"
    proxy_url = f"http://{proxy_name}:{PROXY_PORT}"

    config = build_sandbox_config(target, proxy_url, input_dir=input_dir, extra_env=extra_env)

    _run_checked(["docker", "network", "create", network, "--internal"])
    try:
        _run_checked(["docker", "run", "-d", "--name", proxy_name, "--network", "bridge", PROXY_IMAGE])
        _run_checked(["docker", "network", "connect", network, proxy_name])

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
                "inspect",
                "/scan-config/mcp.generated.json",
                "--dangerously-run-mcp-servers",
                "--json",
            ]
            run_args += list(extra_args or [])

            proc = subprocess.run(run_args, capture_output=True, text=True, timeout=SCAN_CONTAINER_TIMEOUT_SECONDS)
    finally:
        subprocess.run(["docker", "rm", "-f", proxy_name], capture_output=True)
        subprocess.run(["docker", "network", "rm", network], capture_output=True)

    try:
        results = json.loads(proc.stdout)
    except json.JSONDecodeError:
        results = None
    return SandboxScanResult(exit_code=proc.returncode, stdout=proc.stdout, stderr=proc.stderr, results=results)
