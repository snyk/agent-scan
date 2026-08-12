"""End-to-end tests for complete MCP scanning workflow."""

import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import PurePosixPath, PureWindowsPath

import pytest
from pytest_lazy_fixtures import lf

from agent_scan.utils import TempFile


def posix(path: str) -> str:
    """Normalize a path to forward slashes so it matches the scanner's JSON output keys."""
    return PurePosixPath(PureWindowsPath(path)).as_posix()


def inspect_json(agent_scan_cmd, *args: str, input_text: str | None = None) -> tuple[subprocess.CompletedProcess, dict]:
    result = subprocess.run(
        [*agent_scan_cmd, "inspect", "--json", *args],
        input=input_text,
        capture_output=True,
        text=True,
    )
    output = json.loads(result.stdout) if result.stdout.strip() else {}
    return result, output


def only_result(output: dict) -> dict:
    assert len(output) == 1, f"Expected exactly one inspected path, got: {output}"
    return next(iter(output.values()))


class _ErrorResponseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(500)
        self.end_headers()

    def do_POST(self):
        self.send_response(500)
        self.end_headers()

    def log_message(self, _format, *args):
        pass


class _SlowResponseHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(2)
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        time.sleep(2)
        self.send_response(200)
        self.end_headers()

    def log_message(self, _format, *args):
        pass


@pytest.fixture
def http_error_server():
    server = HTTPServer(("127.0.0.1", 0), _ErrorResponseHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/mcp"
    finally:
        server.shutdown()
        thread.join()


@pytest.fixture
def slow_http_server():
    server = HTTPServer(("127.0.0.1", 0), _SlowResponseHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/mcp"
    finally:
        server.shutdown()
        thread.join()


class TestInspect:
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
                [*agent_scan_cmd, "inspect", "--json", "--dangerously-run-mcp-servers", file_name],
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
                [*agent_scan_cmd, "inspect", "--json", "--dangerously-run-mcp-servers", file_name],
                capture_output=True,
                text=True,
            )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) == 1, "Output should contain exactly one entry for the config file"
        assert output[posix(file_name)]["servers"][0]["server"]["type"] == transport, json.dumps(output, indent=4)

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_inspect(self, agent_scan_cmd):
        path = "tests/mcp_servers/configs_files/all_config.json"
        result = subprocess.run(
            [*agent_scan_cmd, "inspect", "--json", "--dangerously-run-mcp-servers", path],
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
    def test_inspect_skills_with_flag(self, agent_scan_cmd, skill_path):
        """Test that scanning skill paths works when --skills flag is provided."""
        result = subprocess.run(
            [*agent_scan_cmd, "inspect", "--json", "--dangerously-run-mcp-servers", "--skills", skill_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        assert len(output) >= 1, "Output should contain at least one entry"
        all_skills = [skill for entry in output.values() for skill in entry["skills"]]
        assert len(all_skills) >= 1, f"Expected at least one skill, got: {output}"
        assert any(s["name"] == "test-skill" for s in all_skills), (
            f"Expected a skill named 'test-skill', got: {[s['name'] for s in all_skills]}"
        )
        test_skill = next(s for s in all_skills if s["name"] == "test-skill")
        assert [file["path"] for file in test_skill["files"]] == ["SKILL.md"]
        assert "# Test skill" in test_skill["files"][0]["content"]
        assert test_skill["error"] is None

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
    def test_inspect_skills_with_negative_flag(self, agent_scan_cmd, skill_path):
        """Test that scanning skill paths does NOT produce skill results without --skills flag."""
        result = subprocess.run(
            [*agent_scan_cmd, "inspect", "--json", "--dangerously-run-mcp-servers", "--no-skills", skill_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"Command failed with error: {result.stderr}"
        output = json.loads(result.stdout)
        all_skills = [skill for entry in output.values() for skill in entry["skills"]]
        assert len(all_skills) == 0, f"Expected no skills without --skills flag, got: {[s['name'] for s in all_skills]}"

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
                [*agent_scan_cmd, "inspect", "--json", "--dangerously-run-mcp-servers", direct_scan_path],
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
            [*agent_scan_cmd, "inspect", "--json", "--dangerously-run-mcp-servers", direct_scan_path],
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
            [*agent_scan_cmd, "inspect", "--json", "--dangerously-run-mcp-servers", vscode_settings_no_mcp_file],
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


class TestInspectBehaviorContract:
    """Black-box coverage for inspect output, errors, exit codes, and flags."""

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_missing_path_is_non_failing_file_not_found(self, agent_scan_cmd, tmp_path):
        missing = tmp_path / "missing.json"

        result, output = inspect_json(agent_scan_cmd, "--dangerously-run-mcp-servers", str(missing))

        assert result.returncode == 0
        error = only_result(output)["error"]
        assert error["category"] == "file_not_found"
        assert error["is_failure"] is False

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_malformed_config_is_parse_error(self, agent_scan_cmd, tmp_path):
        malformed = tmp_path / "malformed.json"
        malformed.write_text('{"mcpServers": {')

        result, output = inspect_json(agent_scan_cmd, "--dangerously-run-mcp-servers", str(malformed))

        assert result.returncode == 0
        error = only_result(output)["error"]
        assert error["category"] == "parse_error"
        assert error["is_failure"] is True

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_unknown_config_is_non_failing(self, agent_scan_cmd, tmp_path):
        unknown = tmp_path / "unknown.json"
        unknown.write_text('{"mcp": []}')

        result, output = inspect_json(agent_scan_cmd, "--dangerously-run-mcp-servers", str(unknown))

        assert result.returncode == 0
        error = only_result(output)["error"]
        assert error["category"] == "unknown_config"
        assert error["is_failure"] is False

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_server_startup_failure_is_attached_to_server(self, agent_scan_cmd, tmp_path):
        config = tmp_path / "broken.json"
        config.write_text(json.dumps({"mcpServers": {"broken": {"command": "/definitely/not/a/server"}}}))

        result, output = inspect_json(agent_scan_cmd, "--dangerously-run-mcp-servers", str(config))

        assert result.returncode == 0
        inspected = only_result(output)
        assert inspected["error"] is None
        assert inspected["servers"][0]["error"]["category"] == "server_startup"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_http_failure_is_reported_as_server_startup(self, agent_scan_cmd, tmp_path, http_error_server):
        config = tmp_path / "http-error.json"
        config.write_text(json.dumps({"mcp": {"servers": {"broken-http": {"type": "http", "url": http_error_server}}}}))

        result, output = inspect_json(agent_scan_cmd, "--dangerously-run-mcp-servers", str(config))

        assert result.returncode == 0
        # check_server tries several transport/URL strategies and aggregates
        # their HTTP errors, so the established CLI category is server_startup.
        assert only_result(output)["servers"][0]["error"]["category"] == "server_startup"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_server_timeout_is_reported_without_aborting_inspect(self, agent_scan_cmd, tmp_path, slow_http_server):
        config = tmp_path / "slow.json"
        config.write_text(json.dumps({"mcp": {"servers": {"slow-http": {"type": "http", "url": slow_http_server}}}}))

        result, output = inspect_json(
            agent_scan_cmd,
            "--dangerously-run-mcp-servers",
            "--server-timeout",
            "1",
            str(config),
        )

        assert result.returncode == 0
        assert only_result(output)["servers"][0]["error"]["category"] == "server_startup"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize(
        "config_content, expected_code",
        [
            ('{"mcpServers": {', "X005"),
            (json.dumps({"mcpServers": {"broken": {"command": "/definitely/not/a/server"}}}), "X001"),
        ],
        ids=["parse_error", "server_startup"],
    )
    def test_ci_fails_for_operational_errors(self, agent_scan_cmd, tmp_path, config_content, expected_code):
        config = tmp_path / "failure.json"
        config.write_text(config_content)

        failed, _ = inspect_json(
            agent_scan_cmd,
            "--ci",
            "--dangerously-run-mcp-servers",
            str(config),
        )
        assert failed.returncode == 1, f"Expected {expected_code} to fail CI: {failed.stderr}"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_rich_ci_prints_failure_code_before_exit(self, agent_scan_cmd, tmp_path):
        config = tmp_path / "broken.json"
        config.write_text(json.dumps({"mcpServers": {"broken": {"command": "/definitely/not/a/server"}}}))

        result = subprocess.run(
            [
                *agent_scan_cmd,
                "inspect",
                "--ci",
                "--dangerously-run-mcp-servers",
                str(config),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "broken" in result.stdout
        assert "CI (--ci): exiting with code 1" in result.stderr
        assert "X001" in result.stderr

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize("kind", ["missing", "unknown"])
    def test_ci_does_not_fail_for_non_failure_discovery_results(self, agent_scan_cmd, tmp_path, kind):
        path = tmp_path / "config.json"
        if kind == "unknown":
            path.write_text('{"mcp": []}')

        result, _ = inspect_json(
            agent_scan_cmd,
            "--ci",
            "--dangerously-run-mcp-servers",
            str(path),
        )

        assert result.returncode == 0

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_ci_requires_dangerous_flag(self, agent_scan_cmd, tmp_path):
        config = tmp_path / "config.json"
        config.write_text('{"unrelated": true}')

        result, _ = inspect_json(agent_scan_cmd, "--ci", str(config))

        assert result.returncode == 2
        assert "--ci requires --dangerously-run-mcp-servers" in result.stderr

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_removed_ignore_issues_codes_flag_is_rejected(self, agent_scan_cmd, tmp_path):
        config = tmp_path / "config.json"
        config.write_text('{"unrelated": true}')

        result, _ = inspect_json(
            agent_scan_cmd,
            "--ignore-issues-codes",
            "X001",
            "--dangerously-run-mcp-servers",
            str(config),
        )

        assert result.returncode == 2
        assert "unrecognized arguments: --ignore-issues-codes" in result.stderr

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_skill_failure_is_reported_and_obeys_ci(self, agent_scan_cmd, tmp_path):
        skill = tmp_path / "broken-skill"
        skill.mkdir()
        (skill / "SKILL.md").write_bytes(b"\xff\xfeinvalid utf-8")

        normal, output = inspect_json(
            agent_scan_cmd,
            "--skills",
            "--dangerously-run-mcp-servers",
            str(skill),
        )
        failed, _ = inspect_json(
            agent_scan_cmd,
            "--skills",
            "--ci",
            "--dangerously-run-mcp-servers",
            str(skill),
        )
        assert normal.returncode == 0
        skill_result = only_result(output)["skills"][0]
        assert skill_result["error"]["category"] == "skill_scan_error"
        assert failed.returncode == 1

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_symlinked_skill_file_is_reported_as_skill_error(self, agent_scan_cmd, tmp_path):
        outside = tmp_path / "outside.txt"
        outside.write_text("must not be collected")
        skill = tmp_path / "skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text("---\nname: safe-skill\ndescription: safe\n---\n# Safe instructions")
        (skill / "outside.txt").symlink_to(outside)

        result, output = inspect_json(
            agent_scan_cmd,
            "--skills",
            "--dangerously-run-mcp-servers",
            str(skill),
        )

        assert result.returncode == 0
        inspected_skill = only_result(output)["skills"][0]
        assert inspected_skill["files"] == []
        assert inspected_skill["error"]["category"] == "skill_scan_error"
        assert "must not contain symbolic links" in inspected_skill["error"]["exception"]
        assert "ValueError: Skill directory must not contain symbolic links" in inspected_skill["error"]["traceback"]

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_multiple_paths_preserve_success_and_failure_results(self, agent_scan_cmd, tmp_path):
        unknown = tmp_path / "unknown.json"
        unknown.write_text('{"mcp": []}')
        missing = tmp_path / "missing.json"

        result, output = inspect_json(
            agent_scan_cmd,
            "--dangerously-run-mcp-servers",
            str(unknown),
            str(missing),
        )

        assert result.returncode == 0
        assert set(output) == {posix(str(unknown)), posix(str(missing))}
        assert output[posix(str(unknown))]["error"]["category"] == "unknown_config"
        assert output[posix(str(missing))]["error"]["category"] == "file_not_found"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_rich_output_and_print_errors(self, agent_scan_cmd, tmp_path):
        config = tmp_path / "broken.json"
        config.write_text(json.dumps({"mcpServers": {"broken": {"command": "/definitely/not/a/server"}}}))

        concise = subprocess.run(
            [*agent_scan_cmd, "inspect", "--dangerously-run-mcp-servers", str(config)],
            capture_output=True,
            text=True,
        )
        detailed = subprocess.run(
            [
                *agent_scan_cmd,
                "inspect",
                "--dangerously-run-mcp-servers",
                "--print-errors",
                "--print-full-descriptions",
                str(config),
            ],
            capture_output=True,
            text=True,
        )

        assert concise.returncode == detailed.returncode == 0
        assert "broken" in concise.stdout
        assert "Traceback" not in concise.stdout
        assert "Exception when scanning broken" in detailed.stdout
        assert "Traceback" in detailed.stdout

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize("suppress, expect_tip", [("true", False), ("false", True)])
    def test_suppress_mcpserver_io_controls_dangerous_warning(self, agent_scan_cmd, tmp_path, suppress, expect_tip):
        config = tmp_path / "config.json"
        config.write_text('{"unrelated": true}')

        result = subprocess.run(
            [
                *agent_scan_cmd,
                "inspect",
                "--dangerously-run-mcp-servers",
                f"--suppress-mcpserver-io={suppress}",
                str(config),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "Snyk Agent Scan" in result.stdout
        assert ("Tip: set --suppress-mcpserver-io=true" in result.stdout) is expect_tip

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_json_remains_machine_readable_with_verbose_logging(self, agent_scan_cmd, tmp_path):
        config = tmp_path / "config.json"
        config.write_text('{"mcp": []}')

        result, output = inspect_json(
            agent_scan_cmd,
            "--verbose",
            "--dangerously-run-mcp-servers",
            str(config),
        )

        assert result.returncode == 0
        assert output
        assert "Verbose mode enabled" in result.stderr

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_inspect_accepts_shared_noop_flags_and_valid_oauth_file(self, agent_scan_cmd, tmp_path):
        config = tmp_path / "config.json"
        config.write_text('{"mcp": []}')
        tokens = tmp_path / "tokens.json"
        tokens.write_text("[]")

        result, output = inspect_json(
            agent_scan_cmd,
            "--storage-file",
            str(tmp_path / "unused-storage"),
            "--analysis-url",
            "https://unused.invalid/analysis",
            "--verification-H",
            "X-Unused: value",
            "--mcp-oauth-tokens-path",
            str(tokens),
            "--skip-ssl-verify",
            "--no-bootstrap",
            "--scan-all-users",
            "--server-timeout",
            "1",
            "--control-server",
            "https://unused.invalid/control",
            "--control-server-H",
            "X-Control: value",
            "--control-identifier",
            "test-machine",
            "--dangerously-run-mcp-servers",
            str(config),
        )

        assert result.returncode == 0
        assert only_result(output)["error"]["category"] == "unknown_config"

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_missing_control_identifier_fails_before_inspection(self, agent_scan_cmd, tmp_path):
        config = tmp_path / "config.json"
        config.write_text('{"unrelated": true}')

        result = subprocess.run(
            [
                *agent_scan_cmd,
                "inspect",
                "--json",
                "--control-server",
                "https://unused.invalid/control",
                "--dangerously-run-mcp-servers",
                str(config),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "missing a --control-identifier" in result.stdout

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    def test_help_lists_inspect_specific_and_shared_flags(self, agent_scan_cmd):
        result = subprocess.run(
            [*agent_scan_cmd, "inspect", "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        for flag in (
            "--json",
            "--skills",
            "--ci",
            "--server-timeout",
            "--suppress-mcpserver-io",
            "--dangerously-run-mcp-servers",
        ):
            assert flag in result.stdout
        assert "--ignore-issues-codes" not in result.stdout

    @pytest.mark.parametrize("agent_scan_cmd", ["uv", "binary"], indirect=True)
    @pytest.mark.parametrize("oauth_content", [None, "not-json"], ids=["missing", "malformed"])
    def test_invalid_oauth_token_file_fails(self, agent_scan_cmd, tmp_path, oauth_content):
        config = tmp_path / "config.json"
        config.write_text('{"unrelated": true}')
        tokens = tmp_path / "tokens.json"
        if oauth_content is not None:
            tokens.write_text(oauth_content)

        result, _ = inspect_json(
            agent_scan_cmd,
            "--mcp-oauth-tokens-path",
            str(tokens),
            "--dangerously-run-mcp-servers",
            str(config),
        )

        assert result.returncode == 1
