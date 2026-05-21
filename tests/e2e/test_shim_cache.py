"""End-to-end tests for the shim cache feature.

Simulates the real usage: a client (Cursor, Claude Desktop, etc.) runs
MCP servers through the shim during normal use.  The shim passively
captures tool signatures to /tmp.  Later, the scanner reads the cache
with --use-shim-cache and never needs to start the servers itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import glob
import json
import os
import subprocess
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_scan.shim_installer import SHIM_MARKER, SHIM_SCRIPT_UNIX
from agent_scan.utils import TempFile

SHIM_PATH = str(SHIM_SCRIPT_UNIX.resolve())
MATH_SERVER_PATH = str(Path("tests/mcp_servers/math_server.py").resolve())
WEATHER_SERVER_PATH = str(Path("tests/mcp_servers/weather_server.py").resolve())


def _cleanup_shim_logs():
    for f in glob.glob("/tmp/snyk_mcp_stdio_local_proxy.*"):
        with contextlib.suppress(OSError):
            os.remove(f)


@pytest.fixture(autouse=True)
def _clean_shim_logs():
    _cleanup_shim_logs()
    yield
    _cleanup_shim_logs()


async def _run_server_through_shim(command: str, args: list[str]) -> None:
    """Simulate a client running an MCP server through the shim.

    Performs the full MCP handshake (initialize -> tools/list, prompts/list,
    resources/list) so the shim captures all responses to /tmp.
    """
    params = StdioServerParameters(
        command=SHIM_PATH,
        args=[command, *args],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            with contextlib.suppress(Exception):
                await session.list_tools()
            with contextlib.suppress(Exception):
                await session.list_prompts()
            with contextlib.suppress(Exception):
                await session.list_resources()
            with contextlib.suppress(Exception):
                await session.list_resource_templates()


class TestShimCacheE2E:
    @pytest.mark.parametrize("agent_scan_cmd", ["uv"], indirect=True)
    def test_shim_cache_returns_tools(self, agent_scan_cmd):
        """Client runs server through shim, then scanner reads cache."""
        # Step 1: Simulate a client running the server through the shim
        asyncio.run(_run_server_through_shim("uv", ["run", "python", MATH_SERVER_PATH]))

        # Verify shim log files were created and non-empty
        shim_logs = glob.glob("/tmp/snyk_mcp_stdio_local_proxy.*")
        assert len(shim_logs) > 0, "No shim log files found"
        non_empty = [f for f in shim_logs if os.path.getsize(f) > 0]
        assert len(non_empty) > 0, "All shim log files are empty"

        # Step 2: Create an unshimmed config and scan with --use-shim-cache
        config = {
            "mcpServers": {
                "Math": {
                    "command": "uv",
                    "args": ["run", "python", MATH_SERVER_PATH],
                }
            }
        }
        with TempFile(mode="w", suffix=".json") as f:
            json.dump(config, f)
            f.flush()
            result = subprocess.run(
                [
                    *agent_scan_cmd,
                    "inspect",
                    "--json",
                    "--dangerously-run-mcp-servers",
                    "--use-shim-cache",
                    f.name,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

        assert result.returncode == 0, f"Inspect failed: {result.stderr}"
        output = json.loads(result.stdout)
        entry = next(iter(output.values()))
        assert entry["error"] is None, f"Scan error: {entry['error']}"
        assert len(entry["servers"]) == 1

        tools = {t["name"] for t in entry["servers"][0]["signature"]["tools"]}
        assert "add" in tools
        assert "subtract" in tools
        assert "multiply" in tools
        assert "divide" in tools

    @pytest.mark.parametrize("agent_scan_cmd", ["uv"], indirect=True)
    def test_shim_cache_with_multiple_servers(self, agent_scan_cmd):
        """Cache works when multiple servers were run through the shim."""
        # Simulate client running both servers
        asyncio.run(_run_server_through_shim("uv", ["run", "python", MATH_SERVER_PATH]))
        asyncio.run(_run_server_through_shim("uv", ["run", "python", WEATHER_SERVER_PATH]))

        config = {
            "mcpServers": {
                "Math": {
                    "command": "uv",
                    "args": ["run", "python", MATH_SERVER_PATH],
                },
                "Weather": {
                    "command": "uv",
                    "args": ["run", "python", WEATHER_SERVER_PATH],
                },
            }
        }
        with TempFile(mode="w", suffix=".json") as f:
            json.dump(config, f)
            f.flush()
            result = subprocess.run(
                [
                    *agent_scan_cmd,
                    "inspect",
                    "--json",
                    "--dangerously-run-mcp-servers",
                    "--use-shim-cache",
                    f.name,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

        assert result.returncode == 0, f"Inspect failed: {result.stderr}"
        output = json.loads(result.stdout)
        entry = next(iter(output.values()))

        by_name = {s["name"]: s for s in entry["servers"]}
        assert "Math" in by_name
        assert "Weather" in by_name

        math_tools = {t["name"] for t in by_name["Math"]["signature"]["tools"]}
        assert "add" in math_tools

        weather_tools = {t["name"] for t in by_name["Weather"]["signature"]["tools"]}
        assert "weather" in weather_tools

    @pytest.mark.parametrize("agent_scan_cmd", ["uv"], indirect=True)
    def test_shim_cache_miss_falls_back_to_live_scan(self, agent_scan_cmd):
        """No cache exists — --use-shim-cache falls back to starting the server."""
        config = {
            "mcpServers": {
                "Math": {
                    "command": "uv",
                    "args": ["run", "python", MATH_SERVER_PATH],
                }
            }
        }
        with TempFile(mode="w", suffix=".json") as f:
            json.dump(config, f)
            f.flush()
            result = subprocess.run(
                [
                    *agent_scan_cmd,
                    "inspect",
                    "--json",
                    "--dangerously-run-mcp-servers",
                    "--use-shim-cache",
                    f.name,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

        assert result.returncode == 0, f"Inspect failed: {result.stderr}"
        output = json.loads(result.stdout)
        entry = next(iter(output.values()))
        assert entry["error"] is None
        tools = {t["name"] for t in entry["servers"][0]["signature"]["tools"]}
        assert "add" in tools

    @pytest.mark.parametrize("agent_scan_cmd", ["uv"], indirect=True)
    def test_shimmed_config_uses_cache(self, agent_scan_cmd):
        """Config still has the shim installed — scanner should use cache, not double-wrap."""
        # Populate cache
        asyncio.run(_run_server_through_shim("uv", ["run", "python", MATH_SERVER_PATH]))

        # Config points to the shim (as a real client config would)
        config = {
            "mcpServers": {
                "Math": {
                    "command": SHIM_PATH,
                    "args": ["uv", "run", "python", MATH_SERVER_PATH],
                }
            }
        }
        with TempFile(mode="w", suffix=".json") as f:
            json.dump(config, f)
            f.flush()
            result = subprocess.run(
                [
                    *agent_scan_cmd,
                    "inspect",
                    "--json",
                    "--dangerously-run-mcp-servers",
                    "--use-shim-cache",
                    f.name,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

        assert result.returncode == 0, f"Inspect failed: {result.stderr}"
        output = json.loads(result.stdout)
        entry = next(iter(output.values()))
        assert entry["error"] is None
        tools = {t["name"] for t in entry["servers"][0]["signature"]["tools"]}
        assert "add" in tools
        assert "subtract" in tools

    @pytest.mark.parametrize("agent_scan_cmd", ["uv"], indirect=True)
    def test_removed_server_cache_not_used(self, agent_scan_cmd):
        """Cache for a removed server should not appear in scan results."""
        # Populate cache for both servers
        asyncio.run(_run_server_through_shim("uv", ["run", "python", MATH_SERVER_PATH]))
        asyncio.run(_run_server_through_shim("uv", ["run", "python", WEATHER_SERVER_PATH]))

        # Config only has Weather — Math was removed
        config = {
            "mcpServers": {
                "Weather": {
                    "command": "uv",
                    "args": ["run", "python", WEATHER_SERVER_PATH],
                }
            }
        }
        with TempFile(mode="w", suffix=".json") as f:
            json.dump(config, f)
            f.flush()
            result = subprocess.run(
                [
                    *agent_scan_cmd,
                    "inspect",
                    "--json",
                    "--dangerously-run-mcp-servers",
                    "--use-shim-cache",
                    f.name,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

        assert result.returncode == 0, f"Inspect failed: {result.stderr}"
        output = json.loads(result.stdout)
        entry = next(iter(output.values()))
        assert entry["error"] is None

        assert len(entry["servers"]) == 1
        assert entry["servers"][0]["name"] == "Weather"
        weather_tools = {t["name"] for t in entry["servers"][0]["signature"]["tools"]}
        assert "weather" in weather_tools
        # Math should not appear anywhere in the results
        server_names = {s["name"] for s in entry["servers"]}
        assert "Math" not in server_names


class TestShimRepairE2E:
    @pytest.mark.parametrize("agent_scan_cmd", ["uv"], indirect=True)
    def test_broken_shim_repaired_on_scan(self, agent_scan_cmd, tmp_path):
        """Config has shimmed servers pointing to a missing shim — scan repairs and succeeds."""
        missing_shim = f"/nonexistent/path/{SHIM_MARKER}.sh"
        config = {
            "mcpServers": {
                "Math": {
                    "command": missing_shim,
                    "args": ["uv", "run", "python", MATH_SERVER_PATH],
                }
            }
        }
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text(json.dumps(config, indent=2))

        result = subprocess.run(
            [
                *agent_scan_cmd,
                "inspect",
                "--json",
                "--dangerously-run-mcp-servers",
                str(cfg_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"Inspect failed: {result.stderr}"
        output = json.loads(result.stdout)
        entry = next(iter(output.values()))
        assert entry["error"] is None, f"Scan error: {entry['error']}"

        tools = {t["name"] for t in entry["servers"][0]["signature"]["tools"]}
        assert "add" in tools
        assert "subtract" in tools

        repaired_config = json.loads(cfg_path.read_text())
        math = repaired_config["mcpServers"]["Math"]
        assert SHIM_MARKER not in math["command"]
        assert math["command"] == "uv"
        assert math["args"] == ["run", "python", MATH_SERVER_PATH]

    @pytest.mark.parametrize("agent_scan_cmd", ["uv"], indirect=True)
    def test_broken_shim_repairs_multiple_servers(self, agent_scan_cmd, tmp_path):
        """Multiple shimmed servers with missing shim all get repaired."""
        missing_shim = f"/nonexistent/path/{SHIM_MARKER}.sh"
        config = {
            "mcpServers": {
                "Math": {
                    "command": missing_shim,
                    "args": ["uv", "run", "python", MATH_SERVER_PATH],
                },
                "Weather": {
                    "command": missing_shim,
                    "args": ["uv", "run", "python", WEATHER_SERVER_PATH],
                },
            }
        }
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text(json.dumps(config, indent=2))

        result = subprocess.run(
            [
                *agent_scan_cmd,
                "inspect",
                "--json",
                "--dangerously-run-mcp-servers",
                str(cfg_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"Inspect failed: {result.stderr}"
        output = json.loads(result.stdout)
        entry = next(iter(output.values()))
        assert entry["error"] is None, f"Scan error: {entry['error']}"

        by_name = {s["name"]: s for s in entry["servers"]}
        assert "Math" in by_name
        assert "Weather" in by_name

        math_tools = {t["name"] for t in by_name["Math"]["signature"]["tools"]}
        assert "add" in math_tools

        weather_tools = {t["name"] for t in by_name["Weather"]["signature"]["tools"]}
        assert "weather" in weather_tools

        repaired_config = json.loads(cfg_path.read_text())
        for name in ("Math", "Weather"):
            assert SHIM_MARKER not in repaired_config["mcpServers"][name]["command"]

    @pytest.mark.parametrize("agent_scan_cmd", ["uv"], indirect=True)
    def test_valid_shim_not_repaired(self, agent_scan_cmd):
        """Config shimmed with a valid shim path should NOT be repaired."""
        config = {
            "mcpServers": {
                "Math": {
                    "command": SHIM_PATH,
                    "args": ["uv", "run", "python", MATH_SERVER_PATH],
                }
            }
        }
        with TempFile(mode="w", suffix=".json") as f:
            json.dump(config, f)
            f.flush()
            result = subprocess.run(
                [
                    *agent_scan_cmd,
                    "inspect",
                    "--json",
                    "--dangerously-run-mcp-servers",
                    f.name,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

        assert result.returncode == 0, f"Inspect failed: {result.stderr}"
        output = json.loads(result.stdout)
        entry = next(iter(output.values()))
        assert entry["error"] is None
        tools = {t["name"] for t in entry["servers"][0]["signature"]["tools"]}
        assert "add" in tools
