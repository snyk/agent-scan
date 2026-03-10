"""End-to-end tests for complete MCP scanning workflow."""

import json
import subprocess
from pathlib import PurePosixPath, PureWindowsPath

import pytest
from pytest_lazy_fixtures import lf

from agent_scan.utils import TempFile


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
        "sample_config_file, transport, port",
        [
            (lf("streamable_http_transport_config_file"), "http", 8124),
            (lf("sse_transport_config_file"), "sse", 8123),
        ],
    )
    def test_infer_transport(self, agent_scan_cmd, sample_config_file, transport, port):
        """Test inferring the transport from the config file."""
        config = {"mcp": {"servers": {"http_server": {"url": f"http://localhost:{port}"}}}}
        file_name: str
        with TempFile(mode="w") as temp_file:
            file_name = temp_file.name
            temp_file.write(json.dumps(config))
            temp_file.flush()
            result = subprocess.run(
                [*agent_scan_cmd, "scan", "--json", file_name],
                capture_output=True,
                text=True,
            )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        url = f"http://localhost:{port}/sse" if transport == "sse" else f"http://localhost:{port}/mcp"
        assert output[posix(file_name)]["servers"][0]["server"]["type"] == transport, json.dumps(output, indent=4)
        assert output[posix(file_name)]["servers"][0]["server"]["url"] == url, json.dumps(output, indent=4)

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
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
    def test_infer_transport_server_not_working(self, agent_scan_cmd, config: str, transport: str | None):
        """Test that the server not working is detected."""
        file_name: str
        with TempFile(mode="w") as temp_file:
            file_name = temp_file.name
            temp_file.write(config)
            temp_file.flush()
            result = subprocess.run(
                [*agent_scan_cmd, "scan", "--json", file_name],
                capture_output=True,
                text=True,
            )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        assert output[posix(file_name)]["servers"][0]["server"]["type"] == transport, json.dumps(output, indent=4)

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
    def test_inspect(self, agent_scan_cmd):
        path = "tests/mcp_servers/configs_files/all_config.json"
        result = subprocess.run(
            [*agent_scan_cmd, "inspect", "--json", path],
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
    def test_scan_skills_with_flag(self, agent_scan_cmd, skill_path):
        """Test that scanning skill paths works when --skills flag is provided."""
        result = subprocess.run(
            [*agent_scan_cmd, "scan", "--json", "--skills", skill_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) >= 1, "Output should contain at least one entry"
        all_servers = [server for entry in output.values() for server in entry["servers"]]
        skill_servers = [s for s in all_servers if s["server"]["type"] == "skill"]
        assert len(skill_servers) >= 1, f"Expected at least one skill server, got: {output}"
        assert any(s["name"] == "test-skill" for s in skill_servers), (
            f"Expected a skill server named 'test-skill', got: {[s['name'] for s in skill_servers]}"
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

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "direct_scan_path, expected_server_name",
        [
            ("streamable-http:localhost:8124/mcp", "http-mcp-server"),
            ("sse:http://localhost:8123/sse", "sse-mcp-server"),
        ],
        ids=["streamable_http", "sse"],
    )
    def test_direct_scan(self, agent_scan_cmd, direct_scan_path, expected_server_name):
        """Test scanning MCP servers via direct scan paths (e.g. streamable-http:host:port/path)."""
        transport = "streamable-http" if "streamable-http" in direct_scan_path else "sse"
        port = "8124" if transport == "streamable-http" else "8123"
        process = subprocess.Popen(
            [
                "uv",
                "run",
                "python",
                "tests/mcp_servers/multiple_transport_server.py",
                "--transport",
                transport,
                "--port",
                port,
            ],
        )
        try:
            import time

            time.sleep(1)
            result = subprocess.run(
                [*agent_scan_cmd, "inspect", "--json", direct_scan_path],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, f"Command failed with error: {result.stderr}"
            output = json.loads(result.stdout)
            assert direct_scan_path in output, (
                f"Expected key '{direct_scan_path}' in output, got: {list(output.keys())}"
            )
            entry = output[direct_scan_path]
            assert entry["error"] is None, f"Unexpected error: {entry['error']}"
            assert len(entry["servers"]) == 1, f"Expected 1 server, got {len(entry['servers'])}"
            server = entry["servers"][0]
            assert server["name"] == expected_server_name
            tool_names = {t["name"] for t in server["signature"]["tools"]}
            assert tool_names == {"is_prime", "gcd", "lcm"}, f"Unexpected tools: {tool_names}"
        finally:
            process.terminate()
            process.wait()

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "direct_scan_path, expected_server_name, expected_command, expected_args",
        [
            (
                "npm:@modelcontextprotocol/server-test",
                "@modelcontextprotocol/server-test",
                "npx",
                ["-y", "@modelcontextprotocol/server-test@latest"],
            ),
            ("npm:some-pkg@1.2.3", "some-pkg", "npx", ["-y", "some-pkg@1.2.3"]),
            ("pypi:mcp-server-test", "mcp-server-test", "uvx", ["mcp-server-test@latest"]),
            ("pypi:mcp-server-test@0.5.0", "mcp-server-test", "uvx", ["mcp-server-test@0.5.0"]),
            (
                "oci:ghcr.io/example/server",
                "ghcr.io/example/server",
                "docker",
                ["run", "-i", "--rm", "ghcr.io/example/server"],
            ),
        ],
        ids=["npm_latest", "npm_versioned", "pypi_latest", "pypi_versioned", "oci"],
    )
    def test_direct_scan_stdio_servers(
        self, agent_scan_cmd, direct_scan_path, expected_server_name, expected_command, expected_args
    ):
        """Test that stdio-based direct scan paths produce the correct server configs (these servers won't actually start)."""
        result = subprocess.run(
            [*agent_scan_cmd, "inspect", "--json", direct_scan_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert direct_scan_path in output, f"Expected key '{direct_scan_path}' in output, got: {list(output.keys())}"
        entry = output[direct_scan_path]
        assert len(entry["servers"]) == 1, f"Expected 1 server, got {len(entry['servers'])}"
        server = entry["servers"][0]
        assert server["name"] == expected_server_name
        assert server["server"]["command"] == expected_command
        assert server["server"]["args"] == expected_args
        assert server["error"] is not None, "Expected an error since the server binary doesn't exist"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_vscode_settings_no_mcp(self, agent_scan_cmd, vscode_settings_no_mcp_file):
        """Test scanning VSCode settings with no MCP configurations."""
        result = subprocess.run(
            [*agent_scan_cmd, "scan", "--json", vscode_settings_no_mcp_file],
            capture_output=True,
            text=True,
        )

        # Check that the command executed successfully
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"

        # Try to parse the output as JSON
        try:
            output = json.loads(result.stdout)
            assert posix(vscode_settings_no_mcp_file) in output
        except json.JSONDecodeError:
            pytest.fail("Failed to parse JSON output")
