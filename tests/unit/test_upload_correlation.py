from uuid import uuid4

import pytest
from aiohttp import web

from agent_scan.runtime_config import RuntimeConfig, set_runtime_config
from agent_scan.upload import upload


class _RecordingServer:
    def __init__(self) -> None:
        self.headers: list[dict[str, str]] = []
        self.runner: web.AppRunner | None = None
        self.url = ""

    async def __aenter__(self):
        app = web.Application()
        app.router.add_post("/upload", self._handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        socket = site._server.sockets[0]
        self.url = f"http://127.0.0.1:{socket.getsockname()[1]}/upload"
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.runner is not None:
            await self.runner.cleanup()

    async def _handle(self, request: web.Request) -> web.Response:
        self.headers.append(dict(request.headers))
        return web.json_response([])


@pytest.mark.asyncio
async def test_upload_includes_scan_event_id_after_successful_bootstrap():
    scan_event_id = uuid4()
    set_runtime_config(RuntimeConfig(scan_event_id=scan_event_id, source="bootstrap"))

    async with _RecordingServer() as server:
        await upload([], server.url, identifier="machine-1", additional_headers={"x-client-id": str(uuid4())})

    assert server.headers[0]["X-Scan-Event-ID"] == str(scan_event_id)


@pytest.mark.asyncio
async def test_upload_omits_scan_event_id_after_default_runtime_config():
    set_runtime_config(RuntimeConfig())

    async with _RecordingServer() as server:
        await upload([], server.url, identifier="machine-1", additional_headers={"x-client-id": str(uuid4())})

    assert "X-Scan-Event-ID" not in server.headers[0]
