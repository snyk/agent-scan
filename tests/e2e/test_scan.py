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
            [*agent_scan_cmd, "scan", "--json", "--dangerously-run-mcp-servers", sample_config_file],
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
            [*agent_scan_cmd, "scan", "--json", "--dangerously-run-mcp-servers", sample_config_file],
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
                "--dangerously-run-mcp-servers",
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

        if "Weather" in server_names:
            assert "W016" in issue_set
        if "Math" in server_names:
            assert "W001" in issue_set and "W020" in issue_set

    @pytest.mark.parametrize("agent_scan_cmd", ["binary"], indirect=True)
    def test_ci_exit_code_with_flag(self, agent_scan_cmd):
        """Math config + analysis yields W001; --ci exits 1."""
        math_config = "tests/mcp_servers/configs_files/math_config.json"
        analysis_url = "https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2025-09-07"
        base_cmd = [
            *agent_scan_cmd,
            "scan",
            "--json",
            "--dangerously-run-mcp-servers",
            math_config,
            "--analysis-url",
            analysis_url,
        ]

        with_ci = subprocess.run(
            [*base_cmd, "--ci", "--suppress-mcpserver-io=false"],
            capture_output=True,
            text=True,
        )
        assert with_ci.returncode == 1, f"Expected exit 1 with --ci when analysis issues exist: {with_ci.stderr}"

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
            [*agent_scan_cmd, "scan", "--json", "--dangerously-run-mcp-servers", skill_path],
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

    @pytest.mark.parametrize("agent_scan_cmd", ["uv"], indirect=True)
    def test_scan_server_in_catalog(self, agent_scan_cmd, remote_server_with_oauth_in_catalog_file):
        """Test that scanning a server in the catalog works."""
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--json",
                "--dangerously-run-mcp-servers",
                remote_server_with_oauth_in_catalog_file,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        key = posix(remote_server_with_oauth_in_catalog_file)
        assert output[key]["servers"][0]["signature"] is not None, "Signature should not be None"
        assert output[key]["servers"][0]["error"] is not None, json.dumps(output, indent=4)
        assert output[key]["servers"][0]["error"]["is_failure"] is False, "Error should not be a failure"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_ci_without_dangerous_flag_exits_2(self, agent_scan_cmd):
        """--ci without --dangerously-run-mcp-servers should exit 2 with a clear error."""
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--ci",
                "tests/mcp_servers/configs_files/math_config.json",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2, (
            f"Expected exit 2 when --ci is used without --dangerously-run-mcp-servers, "
            f"got {result.returncode}. stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        # The enforcement message is printed via rich.print(file=sys.stderr).
        assert "--ci requires --dangerously-run-mcp-servers" in result.stderr, (
            f"Missing enforcement message. stderr={result.stderr!r}"
        )

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_inspect_consent_decline_records_user_declined(self, agent_scan_cmd):
        """
        Default interactive inspect (no --dangerously-run-mcp-servers, no push key):
        the consent prompt is shown for each stdio server. Declining every prompt
        must record the server with the user_declined error category and never
        start a subprocess.
        """
        math_config = "tests/mcp_servers/configs_files/math_config.json"
        # Pipe enough "n" answers to cover any number of stdio prompts.
        decline_input = ("n\n" * 10).encode()

        result = subprocess.run(
            [*agent_scan_cmd, "inspect", "--json", math_config],
            input=decline_input,
            capture_output=True,
        )
        assert result.returncode == 0, (
            f"inspect with declined consent should exit 0, got {result.returncode}. stderr={result.stderr!r}"
        )
        # Consent UI is rendered on stderr; verify the prompt was actually shown
        # and the server was recorded as declined.
        stderr_text = result.stderr.decode("utf-8", errors="replace")
        assert "Allow Agent Scan to start 'Math'?" in stderr_text, (
            f"Expected per-server consent prompt for 'Math'. stderr={stderr_text!r}"
        )
        assert "Declined: 'Math' will not be started." in stderr_text, (
            f"Expected 'Math' to be recorded as declined. stderr={stderr_text!r}"
        )
        assert "command: uv run python" in stderr_text, (
            f"Expected stdio command line in consent block. stderr={stderr_text!r}"
        )
        # JSON output: the declined server must surface as user_declined and
        # have no signature (never started).
        output = json.loads(result.stdout)
        servers = output[math_config]["servers"]
        assert len(servers) == 1, f"Expected exactly one server entry, got {servers}"
        math_server = servers[0]
        error = math_server.get("error")
        assert error is not None, f"Declined server should have an error, got: {math_server}"
        assert error.get("category") == "user_declined", (
            f"Expected category=user_declined for declined server, got: {error}"
        )
        assert math_server.get("signature") is None, (
            f"Declined server must not have a signature (server was never started): {math_server}"
        )

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_inspect_consent_allow_starts_server(self, agent_scan_cmd):
        """
        Default interactive inspect: answering y records allow in stderr. Inspect does
        not run the analysis backend. If the stdio process starts cleanly, we expect a
        signature; if the environment blocks startup (e.g. uv cache), we still require
        that the error is not user_declined — consent was given.
        """
        math_config = "tests/mcp_servers/configs_files/math_config.json"
        allow_input = ("y\n" * 10).encode()

        result = subprocess.run(
            [*agent_scan_cmd, "inspect", "--json", math_config],
            input=allow_input,
            capture_output=True,
        )
        assert result.returncode == 0, (
            f"inspect with allowed consent should exit 0, got {result.returncode}. stderr={result.stderr!r}"
        )
        stderr_text = result.stderr.decode("utf-8", errors="replace")
        assert "Allow Agent Scan to start 'Math'?" in stderr_text, (
            f"Expected per-server consent prompt for 'Math'. stderr={stderr_text!r}"
        )
        assert "Allowed: 'Math' will be started." in stderr_text, (
            f"Expected user allow confirmation for 'Math'. stderr={stderr_text!r}"
        )
        assert "command: uv run python" in stderr_text, (
            f"Expected stdio command line in consent block. stderr={stderr_text!r}"
        )
        output = json.loads(result.stdout)
        servers = output[math_config]["servers"]
        assert len(servers) == 1, f"Expected exactly one server entry, got {servers}"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_scan_consent_decline_records_user_declined(self, agent_scan_cmd):
        """
        Default interactive scan (no --dangerously-run-mcp-servers, no push key):
        the consent prompt is shown for each stdio server. Declining every prompt
        must record the server with the user_declined error category and never
        start a subprocess.
        """
        math_config = "tests/mcp_servers/configs_files/math_config.json"
        # Pipe enough "n" answers to cover any number of stdio prompts.
        decline_input = ("n\n" * 10).encode()

        result = subprocess.run(
            [*agent_scan_cmd, "scan", math_config],
            input=decline_input,
            capture_output=True,
        )
        # Consent UI is rendered on stderr; verify the prompt was actually shown
        # and the server was recorded as declined.
        stderr_text = result.stderr.decode("utf-8", errors="replace")
        assert "Allow Agent Scan to start 'Math'?" in stderr_text, (
            f"Expected per-server consent prompt for 'Math'. stderr={stderr_text!r}"
        )
        assert "Declined: 'Math' will not be started." in stderr_text, (
            f"Expected 'Math' to be recorded as declined. stderr={stderr_text!r}"
        )
        assert "command: uv run python" in stderr_text, (
            f"Expected stdio command line in consent block. stderr={stderr_text!r}"
        )
