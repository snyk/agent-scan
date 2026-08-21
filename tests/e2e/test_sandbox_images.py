"""Docker-gated tests that the sandbox images build and run."""

import socket
import subprocess
import threading
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agent_scan.sandbox_runner import PROXY_IMAGE, PROXY_PORT, SANDBOX_IMAGE
from tests.e2e.conftest import requires_docker

pytestmark = pytest.mark.sandbox


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


def _connect_status(proxy_port: str, target_host_port: str) -> int:
    """Send a raw CONNECT request to the proxy and return the numeric status code.

    tinyproxy's allow/deny decision for HTTPS traffic happens on the `CONNECT
    host:port` request line itself, before any tunnel or TLS handshake begins, so
    this only needs a bare socket -- no TLS involved.
    """
    with socket.create_connection(("127.0.0.1", int(proxy_port)), timeout=10) as s:
        request = f"CONNECT {target_host_port} HTTP/1.1\r\nHost: {target_host_port}\r\n\r\n"
        s.sendall(request.encode())
        status_line = s.recv(4096).split(b"\r\n", 1)[0].decode()
        # tinyproxy replies "HTTP/1.0 200 Connection established" for an allowed
        # CONNECT target but "HTTP/1.1 403 Filtered" for a denied one -- the HTTP
        # version in the status line differs between the two, so parse out just
        # the status code rather than assuming a fixed version prefix.
        return int(status_line.split(" ")[1])


@requires_docker
def test_proxy_allows_allowlisted_host_and_blocks_others(sandbox_images):
    allowed_server = HTTPServer(("0.0.0.0", 0), _EchoHandler)
    denied_server = HTTPServer(("0.0.0.0", 0), _EchoHandler)
    threading.Thread(target=allowed_server.serve_forever, daemon=True).start()
    threading.Thread(target=denied_server.serve_forever, daemon=True).start()
    allowed_port = allowed_server.server_address[1]
    denied_port = denied_server.server_address[1]

    # Suffixed with a random ID so two concurrent test runs (or a leftover container
    # from a crashed prior run) on the same host don't collide on a fixed name.
    container_name = f"agent-scan-sandbox-proxy-test-{uuid.uuid4().hex[:8]}"

    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            container_name,
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
            ["docker", "port", container_name, str(PROXY_PORT)],
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

        # Every real target this proxy gates (api.snyk.io, registry.npmjs.org,
        # pypi.org, files.pythonhosted.org) is HTTPS-only, which tinyproxy handles
        # via CONNECT tunneling rather than plain GETs. Prove the same allow/deny
        # filter decision applies to a raw CONNECT request line, not just GET.
        assert _connect_status(host_port, f"registry.npmjs.org:{allowed_port}") == 200
        assert _connect_status(host_port, f"denied.test:{denied_port}") == 403
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], capture_output=True)
        allowed_server.shutdown()
        denied_server.shutdown()
