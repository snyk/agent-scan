"""End-to-end tests for the shim lifecycle policy in ``run_scan``.

The runtime_config flag ``enable-local-stdio-proxy`` controls whether the
stdio shim is installed (flag present) or explicitly uninstalled (flag
absent).  These tests call ``run_scan`` with real config files on disk and
verify that shims are correctly installed / uninstalled before the scan
inspects the configs.
"""

from __future__ import annotations

import json
from argparse import Namespace
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

if TYPE_CHECKING:
    from pathlib import Path

import pytest

from agent_scan.cli import run_scan
from agent_scan.models import ClientToInspect, ScanPathResult, StdioServer
from agent_scan.runtime_config import RuntimeConfig, get_runtime_config, set_runtime_config
from agent_scan.shim_installer import (
    RUNTIME_CONFIG_SHIM_FLAG,
    SHIM_MARKER,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path, config: dict, name: str = "mcp.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return p


def _read_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _scan_args(files: list[str], **overrides) -> Namespace:
    """Minimal Namespace for ``run_scan`` with sensible defaults."""
    base = {
        "command": "scan",
        "control_servers": [],
        "analysis_url": "https://example.com/analysis",
        "verification_H": None,
        "skip_ssl_verify": False,
        "verbose": False,
        "scan_all_users": False,
        "server_timeout": 10,
        "files": files,
        "mcp_oauth_tokens_path": None,
        "skills": False,
        "dangerously_run_mcp_servers": True,
        "suppress_mcpserver_io": True,
        "use_shim_cache": False,
    }
    base.update(overrides)
    return Namespace(**base)


def _fake_clients(cfg_path: str) -> list[ClientToInspect]:
    """A single client pointing at the given config path."""
    return [
        ClientToInspect(
            name="test-client",
            client_path="/fake/client",
            mcp_configs={
                cfg_path: [
                    ("srv", StdioServer(command="uv", args=["run", "server.py"])),
                ],
            },
            skills_dirs={},
        ),
    ]


def _mock_scan_pipeline():
    """Patches that prevent any real HTTP or server startup from ``run_scan``."""
    path_result = ScanPathResult(path="/fake/mcp.json", servers=[])
    return (
        patch(
            "agent_scan.pipelines.inspect_pipeline",
            new=AsyncMock(return_value=([path_result], ["testuser"])),
        ),
        patch("agent_scan.pipelines.analyze_machine", new=AsyncMock(side_effect=lambda p, **kw: p)),
        patch("agent_scan.pipelines.upload", new=AsyncMock()),
    )


def _shim_path_fixture(tmp_path: Path) -> Path:
    fake_shim = tmp_path / "snyk_mcp_stdio_local_proxy.sh"
    fake_shim.write_text('#!/bin/sh\nexec "$@"')
    return fake_shim


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestShimPolicyInRunScan:
    async def test_flag_true_installs_shims_into_config(self, tmp_path):
        """When the bootstrap returns enable-local-stdio-proxy=true, run_scan
        installs the shim into the config file before the scan runs."""
        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: True}, source="bootstrap"))

        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "server.py"]}}}
        cfg_path = _write_config(tmp_path, config)

        fake_shim = _shim_path_fixture(tmp_path)
        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with (
            p1,
            p2,
            p3,
            patch("agent_scan.shim_installer._get_shim_path", return_value=fake_shim),
            patch(
                "agent_scan.shim_installer._get_stdio_server_names",
                new_callable=AsyncMock,
                return_value={"srv"},
            ),
        ):
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert SHIM_MARKER in result["mcpServers"]["srv"]["command"]
        assert result["mcpServers"]["srv"]["args"][0] == "uv"

    async def test_flag_false_uninstalls_shims_from_config(self, tmp_path):
        """When the bootstrap returns enable-local-stdio-proxy=false, run_scan
        removes any existing shim from the config file."""
        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: False}, source="bootstrap"))

        config = {
            "mcpServers": {
                "srv": {
                    "command": f"/old/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "server.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"
        assert result["mcpServers"]["srv"]["args"] == ["run", "server.py"]

    async def test_flag_absent_uninstalls_shims(self, tmp_path):
        """When the bootstrap response has no shim flag at all, existing shims
        are cleaned up (safe default)."""
        set_runtime_config(RuntimeConfig(config={}, source="bootstrap"))

        config = {
            "mcpServers": {
                "srv": {
                    "command": f"/old/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "server.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"

    async def test_bootstrap_failure_still_uninstalls_shims(self, tmp_path):
        """When bootstrap failed (source=default, empty config), stale shims
        are still cleaned up."""
        # This is the state after bootstrap_runtime_config catches an exception
        set_runtime_config(RuntimeConfig())
        assert get_runtime_config().source == "default"

        config = {
            "mcpServers": {
                "srv": {
                    "command": f"/old/path/{SHIM_MARKER}.sh",
                    "args": ["uv", "run", "server.py"],
                }
            }
        }
        cfg_path = _write_config(tmp_path, config)

        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"
        assert result["mcpServers"]["srv"]["args"] == ["run", "server.py"]

    async def test_flag_true_enables_shim_cache(self, tmp_path):
        """When the flag is set, use_shim_cache is forced to True regardless
        of the CLI flag."""
        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: True}, source="bootstrap"))

        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "server.py"]}}}
        cfg_path = _write_config(tmp_path, config)

        fake_shim = _shim_path_fixture(tmp_path)
        args = _scan_args(files=[str(cfg_path)], use_shim_cache=False)

        captured_inspect_args = {}

        async def capture_inspect(inspect_args, **kwargs):
            captured_inspect_args.update(inspect_args.model_dump())
            return [ScanPathResult(path=str(cfg_path), servers=[])], ["testuser"]

        with (
            patch("agent_scan.pipelines.inspect_pipeline", new=AsyncMock(side_effect=capture_inspect)),
            patch("agent_scan.pipelines.analyze_machine", new=AsyncMock(side_effect=lambda p, **kw: p)),
            patch("agent_scan.pipelines.upload", new=AsyncMock()),
            patch("agent_scan.shim_installer._get_shim_path", return_value=fake_shim),
            patch(
                "agent_scan.shim_installer._get_stdio_server_names",
                new_callable=AsyncMock,
                return_value={"srv"},
            ),
        ):
            await run_scan(args, mode="scan")

        assert captured_inspect_args["use_shim_cache"] is True

    async def test_unshimmed_config_stays_clean_when_flag_absent(self, tmp_path):
        """When configs have no shim and the flag is absent, configs are not
        modified (no unnecessary writes)."""
        set_runtime_config(RuntimeConfig(config={}, source="bootstrap"))

        config = {"mcpServers": {"srv": {"command": "uv", "args": ["run", "server.py"]}}}
        cfg_path = _write_config(tmp_path, config)
        mtime_before = cfg_path.stat().st_mtime

        args = _scan_args(files=[str(cfg_path)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        result = _read_config(cfg_path)
        assert result["mcpServers"]["srv"]["command"] == "uv"
        assert cfg_path.stat().st_mtime == mtime_before

    async def test_multiple_configs_all_shimmed(self, tmp_path):
        """Shim policy applies to all discovered config files, not just the first."""
        set_runtime_config(RuntimeConfig(config={RUNTIME_CONFIG_SHIM_FLAG: True}, source="bootstrap"))

        config1 = {"mcpServers": {"a": {"command": "cmd_a", "args": ["--flag"]}}}
        config2 = {"mcpServers": {"b": {"command": "cmd_b", "args": []}}}
        path1 = _write_config(tmp_path, config1, "config1.json")
        path2 = _write_config(tmp_path, config2, "config2.json")

        fake_shim = _shim_path_fixture(tmp_path)
        args = _scan_args(files=[str(path1), str(path2)])

        p1, p2, p3 = _mock_scan_pipeline()
        with (
            p1,
            p2,
            p3,
            patch("agent_scan.shim_installer._get_shim_path", return_value=fake_shim),
            patch(
                "agent_scan.shim_installer._get_stdio_server_names",
                new_callable=AsyncMock,
                return_value={"a", "b"},
            ),
        ):
            await run_scan(args, mode="scan")

        assert SHIM_MARKER in _read_config(path1)["mcpServers"]["a"]["command"]
        assert SHIM_MARKER in _read_config(path2)["mcpServers"]["b"]["command"]

    async def test_multiple_configs_all_unshimmed(self, tmp_path):
        """When flag is absent, all configs get their shims removed."""
        set_runtime_config(RuntimeConfig(config={}, source="bootstrap"))

        config1 = {"mcpServers": {"a": {"command": f"/old/{SHIM_MARKER}.sh", "args": ["cmd_a", "--flag"]}}}
        config2 = {"mcpServers": {"b": {"command": f"/old/{SHIM_MARKER}.sh", "args": ["cmd_b"]}}}
        path1 = _write_config(tmp_path, config1, "config1.json")
        path2 = _write_config(tmp_path, config2, "config2.json")

        args = _scan_args(files=[str(path1), str(path2)])

        p1, p2, p3 = _mock_scan_pipeline()
        with p1, p2, p3:
            await run_scan(args, mode="scan")

        assert _read_config(path1)["mcpServers"]["a"]["command"] == "cmd_a"
        assert _read_config(path2)["mcpServers"]["b"]["command"] == "cmd_b"
