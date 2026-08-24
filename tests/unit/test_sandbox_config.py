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


def test_client_supplied_proxy_env_is_overridden_by_injected_value(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "Custom": {
                        "command": "uv run python",
                        "args": ["server.py"],
                        "env": {
                            "HTTP_PROXY": "http://attacker.example:9999",
                            "HTTPS_PROXY": "http://attacker.example:9999",
                            "NO_PROXY": "*",
                            "MY_VAR": "keep-me",
                        },
                    }
                }
            }
        )
    )

    config = build_sandbox_config("mcp.json", "http://proxy:8888", input_dir=tmp_path)

    server = config["mcpServers"]["Custom"]
    assert server["env"]["HTTP_PROXY"] == "http://proxy:8888"
    assert server["env"]["HTTPS_PROXY"] == "http://proxy:8888"
    assert server["env"]["NO_PROXY"] == "localhost,127.0.0.1"
    assert server["env"]["MY_VAR"] == "keep-me"


def test_target_escaping_input_dir_via_absolute_path_is_rejected(tmp_path):
    outside = tmp_path.parent / "outside.json"
    outside.write_text(json.dumps({"mcpServers": {}}))
    input_dir = tmp_path / "scan-input"
    input_dir.mkdir()

    with pytest.raises(ValueError, match="target must resolve to a path inside input_dir"):
        build_sandbox_config(str(outside), "http://proxy:8888", input_dir=input_dir)


def test_target_escaping_input_dir_via_traversal_is_rejected(tmp_path):
    input_dir = tmp_path / "scan-input"
    input_dir.mkdir()
    (tmp_path / "secret.json").write_text(json.dumps({"mcpServers": {}}))

    with pytest.raises(ValueError, match="target must resolve to a path inside input_dir"):
        build_sandbox_config("../secret.json", "http://proxy:8888", input_dir=input_dir)


def test_missing_config_file_raises_clear_value_error(tmp_path):
    with pytest.raises(ValueError, match="could not read config"):
        build_sandbox_config("does-not-exist.json", "http://proxy:8888", input_dir=tmp_path)


def test_malformed_config_json_raises_clear_value_error(tmp_path):
    (tmp_path / "bad.json").write_text("{not valid json")

    with pytest.raises(ValueError, match="could not read config"):
        build_sandbox_config("bad.json", "http://proxy:8888", input_dir=tmp_path)


@pytest.mark.parametrize("prefix", ["oci:some-image", "nuget:some-pkg@1.0.0", "mcpb:some-bundle"])
def test_unsupported_direct_scan_prefixes_are_rejected(prefix):
    with pytest.raises(ValueError, match="supported by sandbox-scan yet"):
        build_sandbox_config(prefix, "http://proxy:8888")


def test_extra_env_is_merged_into_direct_scan_target():
    config = build_sandbox_config(
        "npm:some-mcp-server@1.2.3",
        "http://proxy:8888",
        extra_env={"API_TOKEN": "secret-value"},
    )

    server = config["mcpServers"]["some-mcp-server"]
    assert server["env"]["API_TOKEN"] == "secret-value"
    assert server["env"]["HTTP_PROXY"] == "http://proxy:8888"


def test_extra_env_is_merged_into_client_config_file(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps({"mcpServers": {"Custom": {"command": "python3", "args": ["server.py"]}}})
    )

    config = build_sandbox_config(
        "mcp.json", "http://proxy:8888", input_dir=tmp_path, extra_env={"API_TOKEN": "secret-value"}
    )

    server = config["mcpServers"]["Custom"]
    assert server["env"]["API_TOKEN"] == "secret-value"


def test_extra_env_overrides_client_configs_own_env(tmp_path):
    (tmp_path / "mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "Custom": {
                        "command": "python3",
                        "args": ["server.py"],
                        "env": {"API_TOKEN": "stale-value-from-config-file"},
                    }
                }
            }
        )
    )

    config = build_sandbox_config(
        "mcp.json", "http://proxy:8888", input_dir=tmp_path, extra_env={"API_TOKEN": "fresh-value-from-cli"}
    )

    assert config["mcpServers"]["Custom"]["env"]["API_TOKEN"] == "fresh-value-from-cli"


def test_extra_env_cannot_override_injected_proxy_vars():
    config = build_sandbox_config(
        "npm:some-mcp-server@1.2.3",
        "http://proxy:8888",
        extra_env={"HTTP_PROXY": "http://attacker.example:9999"},
    )

    assert config["mcpServers"]["some-mcp-server"]["env"]["HTTP_PROXY"] == "http://proxy:8888"
