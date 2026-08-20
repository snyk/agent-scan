import json

import pytest

from agent_scan.sandbox_config import build_sandbox_config


def test_npm_target_injects_proxy_env():
    config = build_sandbox_config("npm:some-mcp-server@1.2.3", "http://proxy:8888")

    server = config["mcpServers"]["some-mcp-server"]
    assert server["command"] == "npx"
    assert server["args"] == ["-y", "some-mcp-server@1.2.3"]
    assert server["env"]["HTTP_PROXY"] == "http://proxy:8888"
    assert server["env"]["HTTPS_PROXY"] == "http://proxy:8888"
    assert server["env"]["NO_PROXY"] == "localhost,127.0.0.1"


def test_pypi_target_injects_proxy_env():
    config = build_sandbox_config("pypi:some-mcp-server@1.2.3", "http://proxy:8888")

    server = config["mcpServers"]["some-mcp-server"]
    assert server["command"] == "uvx"
    assert server["args"] == ["some-mcp-server@1.2.3"]
    assert server["env"]["HTTPS_PROXY"] == "http://proxy:8888"


def test_client_config_file_gets_proxy_env_merged_into_existing_env(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "Custom": {
                        "command": "uv run python",
                        "args": ["server.py"],
                        "env": {"MY_VAR": "keep-me"},
                    }
                }
            }
        )
    )

    config = build_sandbox_config("mcp.json", "http://proxy:8888", input_dir=tmp_path)

    server = config["mcpServers"]["Custom"]
    assert server["env"]["MY_VAR"] == "keep-me"
    assert server["env"]["HTTP_PROXY"] == "http://proxy:8888"


def test_client_config_file_without_input_dir_raises():
    with pytest.raises(ValueError, match="input_dir"):
        build_sandbox_config("mcp.json", "http://proxy:8888")


def test_remote_server_entry_is_left_untouched(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"mcpServers": {"Remote": {"url": "https://example.com/mcp", "type": "http"}}})
    )

    config = build_sandbox_config("mcp.json", "http://proxy:8888", input_dir=tmp_path)

    assert config["mcpServers"]["Remote"] == {"url": "https://example.com/mcp", "type": "http"}
