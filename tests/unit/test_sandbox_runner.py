import contextlib
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from agent_scan.sandbox_runner import PROXY_IMAGE, SANDBOX_IMAGE, build_images, run_sandboxed_scan


def _fake_completed_process(returncode=0, stdout="", stderr=""):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_creates_internal_network_and_connects_proxy(mock_run):
    mock_run.return_value = _fake_completed_process(stdout=json.dumps({"ok": True}))

    run_sandboxed_scan("npm:some-mcp-server@1.0.0")

    calls = [call.args[0] for call in mock_run.call_args_list]
    network_create = next(c for c in calls if c[:3] == ["docker", "network", "create"])
    assert "--internal" in network_create

    proxy_run = next(c for c in calls if c[:2] == ["docker", "run"] and PROXY_IMAGE in c)
    assert "--network" in proxy_run and "bridge" in proxy_run

    network_connect = next(c for c in calls if c[:3] == ["docker", "network", "connect"])
    assert network_connect[3] == network_create[3]  # same network name
    assert network_connect[4].startswith("agent-scan-sandbox-proxy-")


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_runs_container_with_generated_config_and_no_input_mount(mock_run):
    mock_run.return_value = _fake_completed_process(stdout=json.dumps({"ok": True}))

    run_sandboxed_scan("npm:some-mcp-server@1.0.0")

    calls = [call.args[0] for call in mock_run.call_args_list]
    scan_run = next(c for c in calls if SANDBOX_IMAGE in c)
    assert "--rm" in scan_run
    assert "/scan-config:ro" in " ".join(scan_run)
    assert "/scan-input:ro" not in " ".join(scan_run)
    assert scan_run[-4:] == ["inspect", "/scan-config/mcp.generated.json", "--dangerously-run-mcp-servers", "--json"]


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_mounts_input_dir_when_given(mock_run, tmp_path):
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {}}))
    mock_run.return_value = _fake_completed_process(stdout=json.dumps({"ok": True}))

    run_sandboxed_scan("mcp.json", input_dir=tmp_path)

    calls = [call.args[0] for call in mock_run.call_args_list]
    scan_run = next(c for c in calls if SANDBOX_IMAGE in c)
    assert f"{tmp_path}:/scan-input:ro" in scan_run


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_tears_down_proxy_and_network_on_success(mock_run):
    mock_run.return_value = _fake_completed_process(stdout=json.dumps({"ok": True}))

    run_sandboxed_scan("npm:some-mcp-server@1.0.0")

    calls = [call.args[0] for call in mock_run.call_args_list]
    assert any(c[:3] == ["docker", "rm", "-f"] for c in calls)
    assert any(c[:3] == ["docker", "network", "rm"] for c in calls)


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_tears_down_even_if_scan_container_fails(mock_run):
    def side_effect(args, **kwargs):
        if SANDBOX_IMAGE in args:
            raise RuntimeError("scan container crashed")
        return _fake_completed_process()

    mock_run.side_effect = side_effect

    with contextlib.suppress(RuntimeError):
        run_sandboxed_scan("npm:some-mcp-server@1.0.0")

    calls = [call.args[0] for call in mock_run.call_args_list]
    assert any(c[:3] == ["docker", "rm", "-f"] for c in calls)
    assert any(c[:3] == ["docker", "network", "rm"] for c in calls)


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_parses_json_stdout_into_results(mock_run):
    mock_run.return_value = _fake_completed_process(stdout=json.dumps({"some": "result"}), returncode=0)

    result = run_sandboxed_scan("npm:some-mcp-server@1.0.0")

    assert result.exit_code == 0
    assert result.results == {"some": "result"}


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_handles_non_json_stdout(mock_run):
    mock_run.return_value = _fake_completed_process(stdout="not json", returncode=1)

    result = run_sandboxed_scan("npm:some-mcp-server@1.0.0")

    assert result.exit_code == 1
    assert result.results is None
    assert result.stdout == "not json"


def test_build_images_outside_source_checkout_raises_clear_error(tmp_path):
    with pytest.raises(RuntimeError, match="requires a source checkout of agent-scan"):
        build_images(tmp_path)


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_build_images_surfaces_docker_stderr_on_failure(mock_run, tmp_path):
    (tmp_path / "sandbox").mkdir()
    (tmp_path / "sandbox" / "Dockerfile").write_text("FROM scratch\n")
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=1, cmd=["docker", "build"], output="", stderr="no space left on device"
    )

    with pytest.raises(RuntimeError, match="no space left on device"):
        build_images(tmp_path)


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_surfaces_docker_stderr_on_setup_failure(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=1, cmd=["docker", "network", "create"], output="", stderr="network already exists"
    )

    with pytest.raises(RuntimeError, match="network already exists"):
        run_sandboxed_scan("npm:some-mcp-server@1.0.0")


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_passes_timeout_to_scan_container(mock_run):
    mock_run.return_value = _fake_completed_process(stdout=json.dumps({"ok": True}))

    run_sandboxed_scan("npm:some-mcp-server@1.0.0")

    scan_call = next(call for call in mock_run.call_args_list if SANDBOX_IMAGE in call.args[0])
    assert scan_call.kwargs.get("timeout") == 300


@patch("agent_scan.sandbox_runner.subprocess.run")
def test_run_sandboxed_scan_writes_extra_env_into_generated_config(mock_run):
    captured_config = {}

    def side_effect(args, **kwargs):
        if SANDBOX_IMAGE in args:
            mount_arg = next(a for a in args if a.endswith(":/scan-config:ro"))
            scratch_dir = mount_arg.split(":/scan-config:ro")[0]
            config_path = f"{scratch_dir}/mcp.generated.json"
            with open(config_path) as f:
                captured_config.update(json.load(f))
        return _fake_completed_process(stdout=json.dumps({"ok": True}))

    mock_run.side_effect = side_effect

    run_sandboxed_scan("npm:some-mcp-server@1.0.0", extra_env={"API_TOKEN": "secret-value"})

    server_env = captured_config["mcpServers"]["some-mcp-server"]["env"]
    assert server_env["API_TOKEN"] == "secret-value"
