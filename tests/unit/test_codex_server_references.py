import json
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.agents.codex import CodexDiscoverer
from agent_scan.inspect import _inspect_server
from agent_scan.models import InspectedServer, ServerReference


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return path


@pytest.fixture
def discovery(tmp_path):
    return CodexDiscoverer(tmp_path)


@pytest.mark.parametrize(
    "files,app_path",
    [
        pytest.param({".app.json": {"apps": {"label": {"id": "app-slack"}}}}, ".app.json", id="declaration"),
        pytest.param(
            {
                ".codex-plugin/plugin.json": {"apps": "./config/apps.json"},
                "config/apps.json": {"apps": {"a": {"id": "app-slack"}, "b": {"id": "app-slack"}, "invalid": {}}},
            },
            "config/apps.json",
            id="manifest-and-duplicate-ids",
        ),
    ],
)
def test_server_reference_discovery(discovery, files, app_path):
    root = discovery._codex_home() / "plugins/cache/market/plugin/1"
    for path, data in files.items():
        write_json(root / path, data)
    assert discovery._discover_server_references() == {
        str(root / app_path): [("app-slack", ServerReference(provider="codex_apps", id="app-slack"))]
    }


@pytest.mark.asyncio
async def test_inspection_preserves_server_reference_without_connecting():
    reference = ServerReference(provider="codex_apps", id="app-slack")
    path = "/plugins/slack/.app.json"
    with patch("agent_scan.inspect.check_server", new_callable=AsyncMock) as connect:
        inspected = await _inspect_server(
            "app-slack",
            reference,
            path,
            timeout=0,
            tokens=[],
            stream_stderr=False,
            declined=False,
            do_stdio_handshake=True,
        )
    assert inspected == InspectedServer(name="app-slack", config_path=path, server=reference)
    connect.assert_not_called()
