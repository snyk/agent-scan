"""Docker-gated tests that the sandbox images build and run."""

import subprocess
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from agent_scan.sandbox_runner import PROXY_IMAGE, PROXY_PORT, SANDBOX_IMAGE
from tests.e2e.conftest import requires_docker


@requires_docker
def test_sandbox_image_runs_agent_scan(sandbox_images):
    proc = subprocess.run(
        ["docker", "run", "--rm", SANDBOX_IMAGE, "snyk-agent-scan", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "Snyk Agent Scan" in proc.stdout


class _EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"hello from {self.server.server_address[1]}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test noise
        pass


@requires_docker
def test_proxy_allows_allowlisted_host_and_blocks_others(sandbox_images):
    allowed_server = HTTPServer(("0.0.0.0", 0), _EchoHandler)
    denied_server = HTTPServer(("0.0.0.0", 0), _EchoHandler)
    threading.Thread(target=allowed_server.serve_forever, daemon=True).start()
    threading.Thread(target=denied_server.serve_forever, daemon=True).start()
    allowed_port = allowed_server.server_address[1]
    denied_port = denied_server.server_address[1]

    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            "agent-scan-sandbox-proxy-test",
            "-p",
            "127.0.0.1::8888",
            "--add-host",
            "registry.npmjs.org:host-gateway",
            "--add-host",
            "denied.test:host-gateway",
            PROXY_IMAGE,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    try:
        port_out = subprocess.run(
            ["docker", "port", "agent-scan-sandbox-proxy-test", str(PROXY_PORT)],
            capture_output=True,
            text=True,
            check=True,
        )
        host_port = port_out.stdout.strip().rsplit(":", 1)[-1]
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{host_port}"}))

        allowed_resp = opener.open(f"http://registry.npmjs.org:{allowed_port}/", timeout=10)
        assert allowed_resp.status == 200

        try:
            opener.open(f"http://denied.test:{denied_port}/", timeout=10)
            raise AssertionError("expected the proxy to block a non-allowlisted host")
        except urllib.error.HTTPError as e:
            assert e.code == 403
    finally:
        subprocess.run(["docker", "rm", "-f", "agent-scan-sandbox-proxy-test"], capture_output=True)
        allowed_server.shutdown()
        denied_server.shutdown()
