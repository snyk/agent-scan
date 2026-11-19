"""Fixtures shared by the guard e2e tests."""

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest


class _FakeHookServer(BaseHTTPRequestHandler):
    """Accepts any POST and returns 200 — enough for the test-event handshake."""

    requests: ClassVar[list[dict]] = []
    deletes: ClassVar[list[dict]] = []

    def do_DELETE(self):
        _FakeHookServer.deletes.append({"method": "DELETE", "path": self.path, "headers": dict(self.headers)})
        self.send_response(204)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        _FakeHookServer.requests.append(
            {
                "body": json.loads(base64.b64decode(body.removeprefix("base64:"))),
                "headers": dict(self.headers),
            }
        )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"success":true}')

    def log_message(self, format, *args):
        pass


@pytest.fixture()
def fake_hook_server():
    server = HTTPServer(("127.0.0.1", 0), _FakeHookServer)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    _FakeHookServer.requests = []
    _FakeHookServer.deletes = []
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
