import contextlib
import json
from unittest.mock import MagicMock, patch

from agent_scan.sandbox_runner import PROXY_IMAGE, SANDBOX_IMAGE, run_sandboxed_scan


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
