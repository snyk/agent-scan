"""Global pytest fixtures for agent-scan tests."""

import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_scan.utils import TempFile, ensure_unicode_console

# Repository root (parent of tests/)
REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session", autouse=True)
def _ensure_unicode_console():
    """Reconfigure stdout/stderr to UTF-8 on Windows so tests can print Unicode (e.g. emoji) without UnicodeEncodeError."""
    ensure_unicode_console()


def _get_binary_path() -> Path:
    """Path to the PyInstaller-built mcp-scan binary."""
    return REPO_ROOT / "dist" / ("agent-scan.exe" if sys.platform == "win32" else "agent-scan")


def _build_binary() -> None:
    """Run the same steps as `make binary` (works on Windows without make)."""
    steps = [
        (["uv", "sync"], "uv sync"),
        (["uv", "pip", "install", "-e", ".[dev]"], "uv pip install -e .[dev]"),
        (
            ["uv", "run", "pyinstaller", "--onefile", "--name", "mcp-scan", "src/agent_scan/run.py"],
            "pyinstaller",
        ),
    ]
    for cmd, name in steps:
        result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"{name} failed: {result.stderr or result.stdout}")


def _skip_binary(reason: str) -> None:
    """Skip binary tests and log reason (visible with pytest -s on Windows)."""
    print(f"[agent_scan_binary] {reason}", flush=True)
    pytest.skip(reason)


@pytest.fixture(scope="session")
def agent_scan_binary():
    """Build the CLI binary and return its path. Uses `make binary` on Unix; builds directly on Windows. Skips if build fails."""
    binary_path = _get_binary_path()
    if binary_path.is_file():
        return str(binary_path)
    if sys.platform == "win32":
        try:
            _build_binary()
        except RuntimeError as e:
            _skip_binary(f"Could not build binary: {e}")
    else:
        result = subprocess.run(
            ["make", "binary"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            _skip_binary(f"Could not build binary (make binary failed): {result.stderr or result.stdout}")
    if not binary_path.is_file():
        _skip_binary(f"Binary was not produced at {binary_path}")
    return str(binary_path)


@pytest.fixture
def agent_scan_cmd(request):
    """CLI invocation: either 'uv run -m src.agent_scan.run' or the built binary. Use with @pytest.mark.parametrize('agent_scan_cmd', ['uv', 'binary'], indirect=True). Build runs only when 'binary' is requested."""
    if request.param == "uv":
        return ["uv", "run", "-m", "src.agent_scan.run"]
    if request.param == "binary":
        binary = request.getfixturevalue("agent_scan_binary")
        return [binary]
    raise ValueError(f"Unknown agent_scan_cmd param: {request.param}")


@pytest.fixture
def claudestyle_config():
    """Sample Claude-style MCP config."""
    return """{
    "mcpServers": {
        "claude": {
            "command": "mcp",
            "args": ["--server", "http://localhost:8000"],
        }
    }
}"""


@pytest.fixture
def claudestyle_config_file(claudestyle_config):
    with TempFile(mode="w") as temp_file:
        temp_file.write(claudestyle_config)
        temp_file.flush()
        yield temp_file.name


@pytest.fixture
def vscode_mcp_config():
    """Sample VSCode MCP config with inputs."""
    return """{
  // Inputs are prompted on first server start, then stored securely by VS Code.
  "inputs": [
    {
      "type": "promptString",
      "id": "perplexity-key",
      "description": "Perplexity API Key",
      "password": true
    }
  ],
  "servers": {
    // https://github.com/ppl-ai/modelcontextprotocol/
    "Perplexity": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-perplexity-ask"],
      "env": {
        "PERPLEXITY_API_KEY": "ASDF"
      }
    }
  }
}
"""


@pytest.fixture
def vscode_mcp_config_file(vscode_mcp_config):
    with TempFile(mode="w") as temp_file:
        temp_file.write(vscode_mcp_config)
        temp_file.flush()
        yield temp_file.name


@pytest.fixture
def vscode_config():
    """Sample VSCode settings.json with MCP config."""
    return """// settings.json
{
  "mcp": {
    "servers": {
      "my-mcp-server": {
        "type": "stdio",
        "command": "my-command",
        "args": []
      }
    }
  }
}"""


@pytest.fixture
def vscode_config_file(vscode_config):
    with TempFile(mode="w") as temp_file:
        temp_file.write(vscode_config)
        temp_file.flush()
        yield temp_file.name


@pytest.fixture
def vscode_settings_with_empty_mcp():
    """Sample VSCode settings.json with MCP config."""
    return """// settings.json
{
    "chat.mcp.gallery.enabled": true,
    "chat.mcp.serverSampling": {
    },
    "mcp": {
    }
}"""


@pytest.fixture
def vscode_settings_file_with_empty_mcp(vscode_settings_with_empty_mcp):
    with TempFile(mode="w") as temp_file:
        temp_file.write(vscode_settings_with_empty_mcp)
        temp_file.flush()
        yield temp_file.name


@pytest.fixture
def vscode_settings_without_mcp():
    """Sample VSCode settings.json with MCP config."""
    return """// settings.json
{
    "chat.mcp.gallery.enabled": true,
    "chat.mcp.serverSampling": {
    }
}"""


@pytest.fixture
def vscode_settings_file_without_mcp(vscode_settings_without_mcp):
    with TempFile(mode="w") as temp_file:
        temp_file.write(vscode_settings_without_mcp)
        temp_file.flush()
        yield temp_file.name


@pytest.fixture
def sse_transport_config():
    """Sample settings.json with multiple sse MCP server."""
    return """{
    "mcp": {
        "servers": {
            "sse_server": {
                "type": "sse",
                "url": "http://localhost:8123/sse"
            }
        }
    }
}

"""


@pytest.fixture
def sse_transport_config_file(sse_transport_config):
    with TempFile(mode="w") as temp_file:
        process = subprocess.Popen(
            [
                "uv",
                "run",
                "python",
                "tests/mcp_servers/multiple_transport_server.py",
                "--transport",
                "sse",
                "--port",
                "8123",
            ],
        )
        time.sleep(1)  # Wait for the server to start
        temp_file.write(sse_transport_config)
        temp_file.flush()
        yield temp_file.name
        process.terminate()
        process.wait()


@pytest.fixture
def streamable_http_transport_config():
    """Sample settings.json with streamable_http MCP server."""
    return """{
    "mcp": {
        "servers": {
            "http_server": {
                "type": "http",
                "url": "http://localhost:8124/mcp"
            }
        }
    }
}

"""


@pytest.fixture
def streamable_http_transport_config_file(streamable_http_transport_config):
    with TempFile(mode="w") as temp_file:
        process = subprocess.Popen(
            [
                "uv",
                "run",
                "python",
                "tests/mcp_servers/multiple_transport_server.py",
                "--transport",
                "streamable-http",
                "--port",
                "8124",
            ],
        )
        time.sleep(1)  # Wait for the server to start
        temp_file.write(streamable_http_transport_config)
        temp_file.flush()
        yield temp_file.name
        process.terminate()
        process.wait()


@pytest.fixture
def toy_server_add():
    """Example toy server from the mcp docs."""
    return """
from mcp.server.fastmcp import FastMCP

# Create an MCP server
mcp = FastMCP("Demo")

# Add an addition tool
@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b
"""


@pytest.fixture
def toy_server_add_file(toy_server_add):
    with TempFile(mode="w", suffix=".py") as temp_file:
        temp_file.write(toy_server_add)
        temp_file.flush()
        yield temp_file.name.replace("\\", "/")

    # filename = "tmp_toy_server_" + str(uuid.uuid4()) + ".py"
    # # create the file
    # with open(filename, "w") as temp_file:
    #     temp_file.write(toy_server_add)
    #     temp_file.flush()
    #     temp_file.seek(0)

    # # run tests
    # yield filename.replace("\\", "/")
    # # cleanup
    # import os

    # os.remove(filename)


@pytest.fixture
def toy_server_add_config(toy_server_add_file):
    return f"""
    {{
    "mcpServers": {{
        "toy": {{
            "command": "mcp",
            "args": ["run", "{toy_server_add_file}"]
        }}
    }}
    }}
    """


@pytest.fixture
def toy_server_add_config_file(toy_server_add_config):
    with TempFile(mode="w", suffix=".json") as temp_file:
        temp_file.write(toy_server_add_config)
        temp_file.flush()
        yield temp_file.name.replace("\\", "/")


@pytest.fixture
def math_server_config_path():
    return "tests/mcp_servers/mcp_config.json"
