"""End-to-end tests for complete MCP scanning workflow."""

import json
import subprocess

import pytest
from pytest_lazy_fixtures import lf

from mcp_scan.utils import TempFile


class TestFullScanFlow:
    """Test cases for end-to-end scanning workflows."""

    @pytest.mark.parametrize("mcp_scan_cmd", ["uv", "binary"], indirect=True)
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
    def test_basic(self, mcp_scan_cmd, sample_config_file):
        """Test a basic complete scan workflow from CLI to results. This does not mean that the results are correct or the servers can be run."""
        # Run mcp-scan with JSON output mode
        result = subprocess.run(
            [*mcp_scan_cmd, "scan", "--json", sample_config_file],
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
            assert sample_config_file in output
        except json.JSONDecodeError:
            print(result.stdout)
            pytest.fail("Failed to parse JSON output")

    @pytest.mark.parametrize("mcp_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "sample_config_file",
        [
            lf("streamable_http_transport_config_file"),
            lf("sse_transport_config_file"),
        ],
    )
    def test_scan_sse_http(self, mcp_scan_cmd, sample_config_file):
        """Test scanning with SSE and HTTP transport configurations."""
        result = subprocess.run(
            [*mcp_scan_cmd, "scan", "--json", sample_config_file],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        assert {tool["name"] for tool in output[sample_config_file]["servers"][0]["signature"]["tools"]} == {
            "is_prime",
            "gcd",
            "lcm",
        }, "Tools in signature do not match expected values"
        print(output)

    @pytest.mark.parametrize("mcp_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "sample_config_file, transport, port",
        [
            (lf("streamable_http_transport_config_file"), "http", 8124),
            (lf("sse_transport_config_file"), "sse", 8123),
        ],
    )
    def test_infer_transport(self, mcp_scan_cmd, sample_config_file, transport, port):
        """Test inferring the transport from the config file."""
        config = {"mcp": {"servers": {"http_server": {"url": f"http://localhost:{port}"}}}}
        file_name: str
        with TempFile(mode="w") as temp_file:
            file_name = temp_file.name
            temp_file.write(json.dumps(config))
            temp_file.flush()
            result = subprocess.run(
                [*mcp_scan_cmd, "scan", "--json", file_name],
                capture_output=True,
                text=True,
            )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        url = f"http://localhost:{port}/sse" if transport == "sse" else f"http://localhost:{port}/mcp"
        assert output[file_name]["servers"][0]["server"]["type"] == transport, json.dumps(output, indent=4)
        assert output[file_name]["servers"][0]["server"]["url"] == url, json.dumps(output, indent=4)

    @pytest.mark.parametrize("mcp_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "config, transport",
        [
            (
                json.dumps(
                    {"mcp": {"servers": {"http_server": {"url": "http://www.mcp-scan.com/mcp", "type": "http"}}}}
                ),
                "http",
            ),
            (
                json.dumps(
                    {"mcp": {"servers": {"http_server": {"url": "http://www.mcp-scan.com/sse", "type": "sse"}}}}
                ),
                "sse",
            ),
            (
                json.dumps({"mcp": {"servers": {"http_server": {"url": "http://www.mcp-scan.com/mcp"}}}}),
                "http",
            ),  # default to http
        ],
    )
    def test_infer_transport_server_not_working(self, mcp_scan_cmd, config: str, transport: str | None):
        """Test that the server not working is detected."""
        file_name: str
        with TempFile(mode="w") as temp_file:
            file_name = temp_file.name
            temp_file.write(config)
            temp_file.flush()
            result = subprocess.run(
                [*mcp_scan_cmd, "scan", "--json", file_name],
                capture_output=True,
                text=True,
            )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        assert output[file_name]["servers"][0]["server"]["type"] == transport, json.dumps(output, indent=4)

    @pytest.mark.parametrize("mcp_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "path, server_names",
        [
            ("tests/mcp_servers/configs_files/weather_config.json", ["Weather"]),
            ("tests/mcp_servers/configs_files/math_config.json", ["Math"]),
            ("tests/mcp_servers/configs_files/all_config.json", ["Weather", "Math"]),
        ],
    )
    def test_scan(self, mcp_scan_cmd, path, server_names):
        result = subprocess.run(
            [
                *mcp_scan_cmd,
                "scan",
                "--json",
                path,
                "--analysis-url",
                "https://api.dev.snyk.io/hidden/mcp-scan/analysis-machine?version=2025-09-07",
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
            allowed_issue_sets = [{"W003", "TF001"}, set()]
        elif set(server_names) == {"Math"}:
            allowed_issue_sets = [{"W001", "W003"}, {"W001", "W003", "TF002"}]
        else:
            raise ValueError(f"Invalid server names: {server_names}")
        # call list for better error message
        assert any(issue_set == ais for ais in allowed_issue_sets), (
            f"Issues codes {issue_set} do not match expected values {allowed_issue_sets}"
        )

    @pytest.mark.parametrize("mcp_scan_cmd", ["uv", "binary"], indirect=True)
    def test_inspect(self, mcp_scan_cmd):
        path = "tests/mcp_servers/configs_files/all_config.json"
        result = subprocess.run(
            [*mcp_scan_cmd, "inspect", "--json", path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)

        assert path in output
        for server in output[path]["servers"]:
            server["signature"]["metadata"]["serverInfo"]["version"] = (
                "mcp_version"  # swap actual version with placeholder
            )
            with open(f"tests/mcp_servers/signatures/{server['name'].lower()}_server_signature.json") as f:
                assert server["signature"] == json.load(f), f"Signature mismatch for {server['name']} server"

    @pytest.fixture
    def vscode_settings_no_mcp_file(self):
        settings = {
            "[javascript]": {},
            "github.copilot.advanced": {},
            "github.copilot.chat.agent.thinkingTool": {},
            "github.copilot.chat.codesearch.enabled": {},
            "github.copilot.chat.languageContext.typescript.enabled": {},
            "github.copilot.chat.welcomeMessage": {},
            "github.copilot.enable": {},
            "github.copilot.preferredAccount": {},
            "settingsSync.ignoredExtensions": {},
            "tabnine.experimentalAutoImports": {},
            "workbench.colorTheme": {},
            "workbench.startupEditor": {},
        }
        with TempFile(mode="w") as temp_file:
            json.dump(settings, temp_file)
            temp_file.flush()
            yield temp_file.name

    @pytest.mark.parametrize("mcp_scan_cmd", ["uv", "binary"], indirect=True)
    def test_vscode_settings_no_mcp(self, mcp_scan_cmd, vscode_settings_no_mcp_file):
        """Test scanning VSCode settings with no MCP configurations."""
        result = subprocess.run(
            [*mcp_scan_cmd, "scan", "--json", vscode_settings_no_mcp_file],
            capture_output=True,
            text=True,
        )

        # Check that the command executed successfully
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"

        # Try to parse the output as JSON
        try:
            output = json.loads(result.stdout)
            assert vscode_settings_no_mcp_file in output
        except json.JSONDecodeError:
            pytest.fail("Failed to parse JSON output")
