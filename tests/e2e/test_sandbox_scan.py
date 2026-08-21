"""Docker-gated end-to-end tests for the execution sandbox.

``run_sandboxed_scan()`` invokes ``snyk-agent-scan inspect --json`` (not ``scan``)
inside the sandbox: ``inspect`` mode only does discovery and an MCP handshake/
``list_tools`` call, never a full analysis run, so it needs no ``SNYK_TOKEN`` or
route to Snyk's analysis backend -- see ``src/agent_scan/cli.py``'s
``print_scan_inspect()``, which for ``mode="inspect"`` prints
``{p.path: p.model_dump(mode="json") for p in inspected_paths}`` (a dict keyed by
the path passed to ``inspect``, i.e. ``/scan-config/mcp.generated.json`` in this
sandbox), not the ``scan --json`` ``ScanResponse`` envelope.
"""

import json
import subprocess
import sys
import uuid

import pytest

from agent_scan.sandbox_runner import PROXY_IMAGE, SANDBOX_IMAGE, run_sandboxed_scan
from tests.e2e.conftest import REPO_ROOT, requires_docker

pytestmark = pytest.mark.sandbox

CONFIG_MOUNT_PATH = "/scan-config/mcp.generated.json"


@requires_docker
def test_client_mounted_source_scans_successfully(sandbox_images, tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "Math": {
                        "command": "python3",
                        "args": ["/scan-input/math_server.py"],
                    }
                }
            }
        )
    )
    math_server_src = (REPO_ROOT / "tests" / "mcp_servers" / "math_server.py").read_text()
    (tmp_path / "math_server.py").write_text(math_server_src)

    result = run_sandboxed_scan("mcp.json", input_dir=tmp_path)

    assert result.results is not None, f"stdout was not JSON: {result.stdout!r}, stderr: {result.stderr!r}"
    inspected_path = result.results[CONFIG_MOUNT_PATH]
    assert inspected_path.get("error") is None, f"unexpected top-level error: {inspected_path.get('error')!r}"
    server_result = inspected_path["servers"][0]
    assert server_result["name"] == "Math"
    assert server_result.get("error") is None, f"unexpected server error: {server_result.get('error')!r}"
    tool_names = {tool["name"] for tool in server_result["signature"]["tools"]}
    assert {"add", "subtract", "multiply", "divide"} <= tool_names


@requires_docker
def test_scan_container_has_no_direct_network_egress_without_proxy(sandbox_images):
    """Prove the sandbox's ``--internal`` network blocks egress on its own.

    ``run_sandboxed_scan()`` contains a malicious MCP server behind two layers:
    (1) a Docker network created with ``--internal`` (no route to the internet at
    all), and (2) an egress-allowlisting proxy container bridged onto both the
    internal network and the default bridge network, which spawned MCP servers are
    pointed at via ``HTTP_PROXY``/``HTTPS_PROXY`` (``sandbox_config.py``'s
    ``_inject_proxy_env``).

    ``tests/e2e/test_sandbox_images.py::test_proxy_allows_allowlisted_host_and_blocks_others``
    (Task 2) already proves layer (2) -- the proxy's allow/deny filtering -- works
    correctly for both plain HTTP and CONNECT/HTTPS, by talking to the proxy
    container directly. What that test does *not* cover is layer (1): whether a
    server that ignores its ``HTTP_PROXY`` env entirely (maliciously, or via a bug)
    and just opens a raw socket can reach the internet directly from inside the
    real two-container topology ``run_sandboxed_scan()`` wires up.

    We deliberately do not try to prove this by routing an MCP-shaped probe server
    through ``snyk-agent-scan inspect``: ``inspect`` mode only performs a
    ``list_tools``-equivalent MCP handshake and never invokes a tool, so it never
    exercises a server's runtime network calls. A probe script that isn't a valid
    MCP server to begin with would fail identically whether the network was
    blocked or not (both look like "the handshake never completed"), so that
    angle can't actually distinguish the property we care about -- see the
    superseded design this test replaces, described in
    ``.superpowers/sdd/2026-08-19-execution-sandbox-tier-a/task-5-report.md``.

    Instead this replicates the relevant slice of ``run_sandboxed_scan()``'s
    topology directly (its per-run network name is internal and never returned to
    callers, so it can't be reused as-is) and runs the scan image itself, with its
    entrypoint overridden to attempt a raw, unproxied network fetch.
    """
    run_id = uuid.uuid4().hex[:8]
    network = f"agent-scan-sandbox-net-egress-test-{run_id}"
    proxy_name = f"agent-scan-sandbox-proxy-egress-test-{run_id}"

    subprocess.run(["docker", "network", "create", network, "--internal"], check=True, capture_output=True)
    try:
        # The proxy container is attached exactly as run_sandboxed_scan() attaches it
        # (started on the default bridge network, then connected onto the internal
        # network) so it is reachable from the scan container -- proving any failure
        # below is due to the scan container skipping the proxy, not the proxy being
        # absent from the topology.
        subprocess.run(
            ["docker", "run", "-d", "--name", proxy_name, "--network", "bridge", PROXY_IMAGE],
            check=True,
            capture_output=True,
        )
        subprocess.run(["docker", "network", "connect", network, proxy_name], check=True, capture_output=True)

        # Probe both a DNS-based fetch (proves DNS is blocked) and a raw socket
        # connection to a hardcoded IP literal (proves IP-level connectivity is
        # ALSO blocked, not just DNS resolution). A malicious server could hardcode
        # an IP to bypass DNS entirely, so DNS failure alone doesn't prove
        # containment -- both must fail for the ``--internal`` network property to
        # actually hold.
        probe_script = (
            "import socket, sys, urllib.request\n"
            "dns_error = None\n"
            "ip_error = None\n"
            "try:\n"
            "    urllib.request.urlopen('http://example.com', timeout=5)\n"
            "except Exception as e:\n"
            "    dns_error = repr(e)\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 443), timeout=5)\n"
            "except Exception as e:\n"
            "    ip_error = repr(e)\n"
            "print('DNS_ERROR=' + str(dns_error))\n"
            "print('IP_ERROR=' + str(ip_error))\n"
            "sys.exit(0 if (dns_error and ip_error) else 1)\n"
        )
        proc = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                network,
                "--entrypoint",
                "python3",
                SANDBOX_IMAGE,
                "-c",
                probe_script,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        subprocess.run(["docker", "rm", "-f", proxy_name], capture_output=True)
        subprocess.run(["docker", "network", "rm", network], capture_output=True)

    assert proc.returncode == 0, (
        f"expected both the unproxied DNS-based fetch and the raw IP-literal connection "
        f"to fail because the internal network has no direct route out, but at least one "
        f"succeeded. stdout: {proc.stdout!r}, stderr: {proc.stderr!r}"
    )
    assert "Temporary failure in name resolution" in proc.stdout, (
        f"expected a DNS-resolution failure (the signature of an --internal network "
        f"with no egress route), got: {proc.stdout!r}"
    )
    assert "DNS_ERROR=None" not in proc.stdout, f"expected the DNS-based fetch to fail: {proc.stdout!r}"
    assert "IP_ERROR=None" not in proc.stdout, (
        f"expected the raw IP-literal connection to also fail (not just DNS), got: {proc.stdout!r}"
    )


@requires_docker
def test_sandbox_scan_cli_end_to_end(sandbox_images, tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"mcpServers": {"Math": {"command": "python3", "args": ["/scan-input/math_server.py"]}}})
    )
    math_server_src = (REPO_ROOT / "tests" / "mcp_servers" / "math_server.py").read_text()
    (tmp_path / "math_server.py").write_text(math_server_src)

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_scan.run",
            "sandbox-scan",
            "mcp.json",
            "--input-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert proc.returncode == 0, proc.stderr
    parsed = json.loads(proc.stdout)
    server_result = parsed["/scan-config/mcp.generated.json"]["servers"][0]
    assert server_result["name"] == "Math"
