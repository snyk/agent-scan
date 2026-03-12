"""End-to-end tests for complete MCP scanning workflow."""

import json
import subprocess
from pathlib import PurePosixPath, PureWindowsPath

import pytest
from pytest_lazy_fixtures import lf


def posix(path: str) -> str:
    """Normalize a path to forward slashes so it matches the scanner's JSON output keys."""
    return PurePosixPath(PureWindowsPath(path)).as_posix()


class TestFullScanFlow:
    """Test cases for end-to-end scanning workflows."""

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "sample_config_file",
        [
            lf("claudestyle_config_file"),
            lf("vscode_mcp_config_file"),
            lf("vscode_config_file"),
            lf("streamable_http_transport_config_file"),
            lf("sse_transport_config_file"),
        ],
    )
    def test_basic(self, agent_scan_cmd, sample_config_file):
        """Test a basic complete scan workflow from CLI to results. This does not mean that the results are correct or the servers can be run."""
        # Run mcp-scan with JSON output mode
        result = subprocess.run(
            [*agent_scan_cmd, "scan", "--json", sample_config_file],
            capture_output=True,
            text=True,
        )

        # Check that the command executed successfully
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"

        print(result.stdout)
        print(result.stderr)

        # Try to parse the output as JSON
        try:
            output = json.loads(result.stdout)
            assert posix(sample_config_file) in output
        except json.JSONDecodeError:
            print(result.stdout)
            pytest.fail("Failed to parse JSON output")

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "sample_config_file",
        [
            lf("streamable_http_transport_config_file"),
            lf("sse_transport_config_file"),
        ],
    )
    def test_scan_sse_http(self, agent_scan_cmd, sample_config_file):
        """Test scanning with SSE and HTTP transport configurations."""
        result = subprocess.run(
            [*agent_scan_cmd, "scan", "--json", sample_config_file],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        assert {tool["name"] for tool in output[posix(sample_config_file)]["servers"][0]["signature"]["tools"]} == {
            "is_prime",
            "gcd",
            "lcm",
        }, "Tools in signature do not match expected values"
        print(output)

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "path, server_names",
        [
            ("tests/mcp_servers/configs_files/weather_config.json", ["Weather"]),
            ("tests/mcp_servers/configs_files/math_config.json", ["Math"]),
            ("tests/mcp_servers/configs_files/all_config.json", ["Weather", "Math"]),
        ],
    )
    def test_scan(self, agent_scan_cmd, path, server_names):
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--json",
                path,
                "--analysis-url",
                "https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2025-09-07",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)

        for server in output[path]["servers"]:
            server["signature"]["metadata"]["serverInfo"]["version"] = (
                "mcp_version"  # swap actual version with placeholder
            )

            with open(f"tests/mcp_servers/signatures/{server['name'].lower()}_server_signature.json") as f:
                assert server["signature"] == json.load(f), f"Signature mismatch for {server['name']} server"

        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        path = next(iter(output.keys()))
        errors = output[path]["error"]
        assert errors is None, f"Error should not be present, found: {errors}"
        issues = output[path]["issues"]

        issue_set = {issue["code"] for issue in issues}
        if set(server_names) == {"Weather", "Math"}:
            allowed_issue_sets = [{"W001", "W003", "TF001", "TF002"}, {"W001", "W003", "TF002"}, {"W001", "W003"}]
        elif set(server_names) == {"Weather"}:
            allowed_issue_sets = [{"W003"}, {"W003", "TF001"}, set()]
        elif set(server_names) == {"Math"}:
            allowed_issue_sets = [{"W001", "W003"}, {"W001", "W003", "TF002"}]
        else:
            raise ValueError(f"Invalid server names: {server_names}")
        # call list for better error message
        assert any(issue_set == ais for ais in allowed_issue_sets), (
            f"Issues codes {issue_set} do not match expected values {allowed_issue_sets}"
        )

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "skill_path",
        [
            "tests/mcp_servers/.test-client/skills",
            "tests/mcp_servers/.test-client/skills/test-skill",
            "tests/mcp_servers/.test-client/skills/test-skill/SKILL.md",
        ],
        ids=["skills_parent_dir", "skill_folder", "skill_md_file"],
    )
    def test_scan_skills_without_flag(self, agent_scan_cmd, skill_path):
        """Test that scanning skill paths does NOT produce skill results without --skills flag."""
        result = subprocess.run(
            [*agent_scan_cmd, "scan", "--json", skill_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        all_servers = [server for entry in output.values() for server in entry["servers"]]
        skill_servers = [s for s in all_servers if s["server"]["type"] == "skill"]
        assert len(skill_servers) == 0, (
            f"Expected no skill servers without --skills flag, got: {[s['name'] for s in skill_servers]}"
        )
