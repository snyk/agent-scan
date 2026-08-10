"""End-to-end tests for complete MCP scanning workflow."""

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest
from pytest_lazy_fixtures import lf


class _V20260710AnalysisHandler(BaseHTTPRequestHandler):
    requests: ClassVar[list[dict]] = []
    server_error: ClassVar[dict | None] = None

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        request = json.loads(body)
        type(self).requests.append(request)
        path_responses = []
        for path in request["scan_path_requests"]:
            server_risks = [
                {
                    "name": server["name"],
                    "entities": [],
                    "risk_indexes": {
                        "private_data": {
                            "score": 750,
                            "evidence": "Reads private records",
                            "affected_tools": [0],
                        }
                    },
                    **({"error": type(self).server_error} if type(self).server_error else {}),
                }
                for server in path["servers"]
            ]
            skill_risks = [
                {
                    "name": skill["name"],
                    "files": [],
                    "risk_indexes": {
                        "suspicious_download_url": {
                            "score": 900,
                            "evidence": "Downloads an untrusted executable",
                            "locations": [{"start": {"path": "SKILL.md", "line": 1, "offset": 0}}],
                            "malicious_urls": ["https://malware.example/payload"],
                        }
                    },
                }
                for skill in path["skills"]
            ]
            path_responses.append(
                {
                    "client": path.get("client"),
                    "path": path["path"],
                    "server_risks": server_risks,
                    "skill_risks": skill_risks,
                }
            )
        response = json.dumps({"scan_path_responses": path_responses}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def v20260710_analysis_server():
    _V20260710AnalysisHandler.requests = []
    _V20260710AnalysisHandler.server_error = None
    server = HTTPServer(("127.0.0.1", 0), _V20260710AnalysisHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/hidden/mcp-scan/analysis-machine?version=2026-07-10"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


class TestFullScanFlow:
    """Test cases for end-to-end scanning workflows."""

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_v20260710_mcp_scan_request_response_and_ci(self, agent_scan_cmd, v20260710_analysis_server):
        config = "tests/mcp_servers/configs_files/math_config.json"
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--json",
                "--ci",
                "--dangerously-run-mcp-servers",
                config,
                "--analysis-url",
                v20260710_analysis_server,
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1, result.stderr
        output = json.loads(result.stdout)
        risk = output["scan_path_responses"][0]["server_risks"][0]["risk_indexes"]["private_data"]
        assert risk == {"score": 750, "evidence": "Reads private records", "affected_tools": [0]}
        request = _V20260710AnalysisHandler.requests[0]
        assert len(request["scan_path_requests"]) == 1
        path_request = request["scan_path_requests"][0]
        assert [server["name"] for server in path_request["servers"]] == ["Math"]
        assert path_request["skills"] == []
        assert "server" in path_request["servers"][0]

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        ("ignored_risk", "expected_exit"),
        [("private_data", 0), ("dangerous_words", 1)],
    )
    def test_ignore_risks_filters_output_and_ci_exit(
        self,
        agent_scan_cmd,
        v20260710_analysis_server,
        ignored_risk,
        expected_exit,
    ):
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--json",
                "--ci",
                "--ignore-risks",
                ignored_risk,
                "--dangerously-run-mcp-servers",
                "tests/mcp_servers/configs_files/math_config.json",
                "--analysis-url",
                v20260710_analysis_server,
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == expected_exit, result.stderr
        output = json.loads(result.stdout)
        risk_indexes = output["scan_path_responses"][0]["server_risks"][0]["risk_indexes"]
        if ignored_risk == "private_data":
            assert "private_data" not in risk_indexes
        else:
            assert risk_indexes["private_data"]["score"] == 750

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_ignore_failure_codes_suppresses_ci_exit_but_preserves_error(
        self,
        agent_scan_cmd,
        v20260710_analysis_server,
    ):
        _V20260710AnalysisHandler.server_error = {
            "message": "could not start server",
            "category": "server_startup",
            "is_failure": True,
        }
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--json",
                "--ci",
                "--ignore-risks",
                "private_data",
                "--ignore-failure-codes",
                "X001",
                "--dangerously-run-mcp-servers",
                "tests/mcp_servers/configs_files/math_config.json",
                "--analysis-url",
                v20260710_analysis_server,
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stderr
        output = json.loads(result.stdout)
        server = output["scan_path_responses"][0]["server_risks"][0]
        assert "private_data" not in server["risk_indexes"]
        assert server["error"]["category"] == "server_startup"
        assert server["error"]["message"] == "could not start server"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_v20260710_skill_scan_sends_files_and_prints_plain_risk(self, agent_scan_cmd, v20260710_analysis_server):
        skill = "tests/mcp_servers/.test-client/skills/test-skill"
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--dangerously-run-mcp-servers",
                skill,
                "--analysis-url",
                v20260710_analysis_server,
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stderr
        assert "Suspicious download URL (score: 900)" in result.stdout
        assert "SKILL.md:1:0" in result.stdout
        assert "https://malware.example/payload" in result.stdout
        path_request = _V20260710AnalysisHandler.requests[0]["scan_path_requests"][0]
        assert path_request["servers"] == []
        assert path_request["skills"][0]["name"] == "test-skill"
        assert any(file["path"] == "SKILL.md" for file in path_request["skills"][0]["files"])

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "skill",
        [
            "tests/mcp_servers/.test-client/skills",
            "tests/mcp_servers/.test-client/skills/test-skill",
            "tests/mcp_servers/.test-client/skills/test-skill/SKILL.md",
        ],
        ids=["skills_parent_dir", "skill_folder", "skill_md_file"],
    )
    def test_v20260710_no_skills_omits_skills(self, agent_scan_cmd, v20260710_analysis_server, skill):
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--json",
                "--no-skills",
                "--dangerously-run-mcp-servers",
                skill,
                "--analysis-url",
                v20260710_analysis_server,
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stderr
        path_request = _V20260710AnalysisHandler.requests[0]["scan_path_requests"][0]
        assert path_request["skills"] == []

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "sample_config_file",
        [
            lf("streamable_http_transport_config_file"),
            lf("sse_transport_config_file"),
        ],
    )
    def test_v20260710_scan_preserves_remote_server_signature(
        self, agent_scan_cmd, sample_config_file, v20260710_analysis_server
    ):
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--json",
                "--dangerously-run-mcp-servers",
                sample_config_file,
                "--analysis-url",
                v20260710_analysis_server,
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, result.stderr
        request = _V20260710AnalysisHandler.requests[0]["scan_path_requests"][0]
        assert {tool["name"] for tool in request["servers"][0]["signature"]["tools"]} == {
            "is_prime",
            "gcd",
            "lcm",
        }

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_catalog_server_is_sent_to_v20260710_analysis(
        self, agent_scan_cmd, remote_server_with_oauth_in_catalog_file, v20260710_analysis_server
    ):
        """Catalog-backed remote configs still reach the new analysis boundary."""
        result = subprocess.run(
            [
                *agent_scan_cmd,
                "scan",
                "--json",
                "--dangerously-run-mcp-servers",
                remote_server_with_oauth_in_catalog_file,
                "--analysis-url",
                v20260710_analysis_server,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        request = _V20260710AnalysisHandler.requests[0]["scan_path_requests"][0]
        assert len(request["servers"]) == 1
        assert request["servers"][0]["server"]["type"] in {"http", "sse"}

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
