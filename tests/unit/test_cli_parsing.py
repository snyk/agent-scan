"""Tests for CLI argument parsing, especially multiple control servers."""

import argparse
import sys
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import (
    MissingIdentifierError,
    add_common_arguments,
    add_server_arguments,
    parse_control_servers,
    setup_scan_parser,
)
from agent_scan.models import ControlServer, Issue, ScanPathResult


class TestControlServerParsing:
    """Test suite for parsing multiple control servers with individual options."""

    @pytest.mark.parametrize(
        "argv, expected",
        [
            pytest.param(
                [
                    "--control-server",
                    "https://server1.com",
                    "--control-server-H",
                    "Auth: token1",
                    "--control-identifier",
                    "user@example.com",
                    "--opt-out",
                ],
                [ControlServer(url="https://server1.com", headers={"Auth": " token1"}, identifier="user@example.com")],
                id="single_server_with_all_options",
            ),
            pytest.param(
                [
                    "--control-server",
                    "https://server1.com",
                    "--control-server-H",
                    "Auth: token1",
                    "--control-identifier",
                    "user@example.com",
                    "--control-server",
                    "https://server2.com",
                    "--control-server-H",
                    "Auth: token2",
                    "--control-identifier",
                    "serial-123",
                ],
                [
                    ControlServer(
                        url="https://server1.com", headers={"Auth": " token1"}, identifier="user@example.com"
                    ),
                    ControlServer(url="https://server2.com", headers={"Auth": " token2"}, identifier="serial-123"),
                ],
                id="multiple_servers_with_individual_options",
            ),
            pytest.param(
                [
                    "--control-identifier",
                    "should-be-ignored",
                    "--control-server",
                    "https://server1.com",
                    "--control-identifier",
                    "user1",
                ],
                [ControlServer(url="https://server1.com", headers={}, identifier="user1")],
                id="options_before_first_server_ignored",
            ),
            pytest.param(
                ["scan", "--verbose", "--json"],
                [],
                id="no_control_servers",
            ),
            pytest.param(
                ["--control-server", "--verbose"],
                [],
                id="control_server_without_url",
            ),
            pytest.param(
                ["--control-server", "--some-other-arg", "value"],
                [],
                id="url_starts_with_dash",
            ),
            pytest.param(
                [
                    "scan",
                    "--verbose",
                    "--control-server",
                    "https://server1.com",
                    "--control-identifier",
                    "user1",
                    "--json",
                    "--control-server",
                    "https://server2.com",
                    "--control-identifier",
                    "id2",
                    "--storage-file",
                    "~/.mcp-scan",
                ],
                [
                    ControlServer(url="https://server1.com", headers={}, identifier="user1"),
                    ControlServer(url="https://server2.com", headers={}, identifier="id2"),
                ],
                id="with_other_cli_args",
            ),
            pytest.param(
                [
                    "--control-server",
                    "https://server1.com",
                    "--control-server-H",
                    "Auth: token1",
                    "--control-server-H",
                    "X-Custom: value1",
                    "--control-identifier",
                    "id1",
                ],
                [
                    ControlServer(
                        url="https://server1.com", headers={"Auth": " token1", "X-Custom": " value1"}, identifier="id1"
                    )
                ],
                id="single_server_with_multiple_headers",
            ),
        ],
    )
    def test_parse_control_servers(self, argv: list[str], expected: list[ControlServer]):
        result = parse_control_servers(argv)
        assert result == expected

    @pytest.mark.parametrize(
        "argv",
        [
            pytest.param(
                ["--control-server", "https://server1.com"],
                id="single_server_no_identifier",
            ),
            pytest.param(
                [
                    "--control-server",
                    "https://server1.com",
                    "--control-server-H",
                    "Auth: token1",
                    "--control-server-H",
                    "X-Custom: value1",
                ],
                id="single_server_headers_only_no_identifier",
            ),
            pytest.param(
                [
                    "--control-server",
                    "https://server1.com",
                    "--control-identifier",
                    "user1",
                    "--control-server",
                    "https://server2.com",
                    "--control-server",
                    "https://server3.com",
                    "--control-server-H",
                    "Auth: token3",
                    "--control-identifier",
                    "user3",
                ],
                id="multiple_servers_one_missing_identifier",
            ),
            pytest.param(
                [
                    "--control-server",
                    "https://server1.com",
                    "--control-identifier",
                    "user1",
                    "--control-server",
                    "https://server2.com",
                    "--control-server",
                    "https://server3.com",
                    "--control-identifier",
                    "user3",
                ],
                id="options_only_apply_to_preceding_server",
            ),
        ],
    )
    def test_parse_control_servers_missing_identifier(self, argv: list[str]):
        with pytest.raises(MissingIdentifierError, match="missing a --control-identifier"):
            parse_control_servers(argv)


class TestCLIArgumentParsing:
    """Test suite for overall CLI argument parsing with control servers."""

    def test_scan_with_multiple_control_servers_parses_correctly(self):
        """Test that multiple control servers are parsed correctly."""
        test_argv = [
            "mcp-scan",
            "scan",
            "--control-server",
            "https://server1.com",
            "--control-server-H",
            "Auth: token1",
            "--control-identifier",
            "user1@example.com",
            "--opt-out",
            "--control-server",
            "https://server2.com",
            "--control-server-H",
            "Auth: token2",
            "--control-identifier",
            "serial-123",
        ]

        control_servers = parse_control_servers(test_argv)

        assert len(control_servers) == 2
        assert control_servers[0].url == "https://server1.com"
        assert control_servers[0].identifier == "user1@example.com"
        assert control_servers[1].url == "https://server2.com"
        assert control_servers[1].identifier == "serial-123"


class TestControlServerHeaderParsing:
    """Test suite for header parsing in control servers."""

    def test_parse_headers_single_header(self):
        """Test parsing a single header."""
        from agent_scan.utils import parse_headers

        headers = ["Auth: token123"]
        result = parse_headers(headers)

        assert result == {"Auth": " token123"}

    def test_parse_headers_multiple_headers(self):
        """Test parsing multiple headers."""
        from agent_scan.utils import parse_headers

        headers = ["Auth: token123", "X-Custom: value456"]
        result = parse_headers(headers)

        assert result == {"Auth": " token123", "X-Custom": " value456"}

    def test_parse_headers_none_input(self):
        """Test parsing None returns empty dict."""
        from agent_scan.utils import parse_headers

        result = parse_headers(None)

        assert result == {}

    def test_parse_headers_empty_list(self):
        """Test parsing empty list returns empty dict."""
        from agent_scan.utils import parse_headers

        result = parse_headers([])

        assert result == {}

    def test_parse_headers_invalid_format_raises_error(self):
        """Test that invalid header format raises ValueError."""
        from agent_scan.utils import parse_headers

        headers = ["InvalidHeaderWithoutColon"]

        with pytest.raises(ValueError, match="Invalid header"):
            parse_headers(headers)


class TestControlServerUploadIntegration:
    """Integration tests for control server arguments passed to the pipeline."""

    @pytest.mark.asyncio
    async def test_control_servers_passed_to_pipeline(self):
        """Test that run_scan passes control servers to the pipeline correctly."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = ScanPathResult(path="/test/path")

        with patch(
            "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
        ) as mock_pipeline:
            args = Namespace(
                verification_H=None,
                verbose=False,
                scan_all_users=False,
                server_timeout=10,
                files=[],
                mcp_oauth_tokens_path=None,
                analysis_url="https://test.com/analysis",
                skip_ssl_verify=False,
                control_servers=[
                    ControlServer(url="https://server1.com", headers={"Auth": " token1"}, identifier="user1"),
                    ControlServer(
                        url="https://server2.com", headers={"Auth": " token2", "X-Custom": " value"}, identifier="user2"
                    ),
                ],
            )

            await run_scan(args, mode="scan")

            mock_pipeline.assert_called_once()
            push_args = mock_pipeline.call_args[0][2]
            assert len(push_args.control_servers) == 2
            assert push_args.control_servers[0].url == "https://server1.com"
            assert push_args.control_servers[0].identifier == "user1"
            assert push_args.control_servers[1].url == "https://server2.com"
            assert push_args.control_servers[1].identifier == "user2"

    @pytest.mark.asyncio
    async def test_no_control_servers_passed_to_pipeline(self):
        """Test that an empty control servers list is passed when none are specified."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = ScanPathResult(path="/test/path")

        with patch(
            "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
        ) as mock_pipeline:
            args = Namespace(
                verification_H=None,
                verbose=False,
                scan_all_users=False,
                server_timeout=10,
                files=[],
                mcp_oauth_tokens_path=None,
                analysis_url="https://test.com/analysis",
                skip_ssl_verify=False,
                control_servers=[],
            )

            await run_scan(args, mode="scan")

            mock_pipeline.assert_called_once()
            push_args = mock_pipeline.call_args[0][2]
            assert len(push_args.control_servers) == 0

    @pytest.mark.asyncio
    async def test_skip_ssl_verify_passed_to_pipeline(self):
        """Test that skip_ssl_verify is correctly passed to the pipeline."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = ScanPathResult(path="/test/path")

        with patch(
            "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
        ) as mock_pipeline:
            args_without = Namespace(
                verification_H=None,
                verbose=False,
                scan_all_users=False,
                server_timeout=10,
                files=[],
                mcp_oauth_tokens_path=None,
                analysis_url="https://test.com/analysis",
                control_servers=[ControlServer(url="https://server1.com", headers={}, identifier="host1")],
            )

            await run_scan(args_without, mode="scan")
            push_args = mock_pipeline.call_args[0][2]
            analyze_args = mock_pipeline.call_args[0][1]
            assert push_args.skip_ssl_verify is False
            assert analyze_args.skip_ssl_verify is False

        with patch(
            "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
        ) as mock_pipeline:
            args_with = Namespace(
                verification_H=None,
                verbose=False,
                scan_all_users=False,
                server_timeout=10,
                files=[],
                mcp_oauth_tokens_path=None,
                analysis_url="https://test.com/analysis",
                skip_ssl_verify=True,
                control_servers=[ControlServer(url="https://server1.com", headers={}, identifier="host1")],
            )

            await run_scan(args_with, mode="scan")
            push_args = mock_pipeline.call_args[0][2]
            analyze_args = mock_pipeline.call_args[0][1]
            assert push_args.skip_ssl_verify is True
            assert analyze_args.skip_ssl_verify is True


class TestCIMode:
    """Tests for --ci exit status (non-zero when any issues are present)."""

    @pytest.mark.parametrize("code", ["E001", "X002", "X007"])
    @pytest.mark.asyncio
    async def test_ci_exits_1_when_any_issue(self, code: str):
        """With --ci, sys.exit(1) for any issue regardless of code (analysis or operational)."""
        from argparse import Namespace

        from agent_scan.cli import print_scan_inspect

        mock_result = ScanPathResult(
            path="/test/path",
            issues=[Issue(code=code, message="issue", reference=None)],
        )

        with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=[mock_result]):
            args = Namespace(
                json=True,
                print_errors=False,
                print_full_descriptions=False,
                verbose=False,
                ci=True,
            )
            with pytest.raises(SystemExit) as exc_info:
                await print_scan_inspect(mode="scan", args=args)
            assert exc_info.value.code == 1

    @pytest.mark.asyncio
    async def test_ci_no_exit_when_no_issues(self):
        """With --ci and empty issues, the scan completes without SystemExit."""
        from argparse import Namespace

        from agent_scan.cli import print_scan_inspect

        mock_result = ScanPathResult(path="/test/path", issues=[])

        with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=[mock_result]):
            args = Namespace(
                json=True,
                print_errors=False,
                print_full_descriptions=False,
                verbose=False,
                ci=True,
            )
            await print_scan_inspect(mode="scan", args=args)

    @pytest.mark.asyncio
    async def test_non_ci_no_exit_with_analysis_issues(self):
        """Without --ci, analysis findings do not call sys.exit."""
        from argparse import Namespace

        from agent_scan.cli import print_scan_inspect

        mock_result = ScanPathResult(
            path="/test/path",
            issues=[Issue(code="E001", message="analysis finding", reference=None)],
        )

        with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=[mock_result]):
            args = Namespace(
                json=True,
                print_errors=False,
                print_full_descriptions=False,
                verbose=False,
                ci=False,
            )
            await print_scan_inspect(mode="scan", args=args)


class TestJSONOutput:
    """Test suite for JSON output functionality."""

    @pytest.mark.asyncio
    async def test_json_output_suppresses_stdout_during_scan(self):
        """Test that when --json is enabled, stdout is suppressed during scan."""
        import io
        import json
        from argparse import Namespace

        from agent_scan.cli import print_scan_inspect
        from agent_scan.models import ScanPathResult

        mock_result = ScanPathResult(path="/test/path.json")

        with patch("agent_scan.cli.run_scan", new_callable=AsyncMock, return_value=[mock_result]):
            args = Namespace(
                json=True,
                print_errors=False,
                print_full_descriptions=False,
                verbose=False,
            )

            captured_output = io.StringIO()
            original_stdout = sys.stdout

            try:
                sys.stdout = captured_output
                await print_scan_inspect(mode="scan", args=args)
            finally:
                sys.stdout = original_stdout

            output = captured_output.getvalue()
            assert output.strip()
            parsed = json.loads(output)
            assert isinstance(parsed, dict)
            assert "/test/path.json" in parsed

    @pytest.mark.asyncio
    async def test_json_output_only_contains_json(self):
        """Test that JSON output mode only outputs JSON, no rich.print messages."""
        import io
        import json
        from argparse import Namespace

        from agent_scan.cli import print_scan_inspect
        from agent_scan.models import ScanPathResult

        mock_result = ScanPathResult(path="/test/path.json")

        async def mock_run_scan_with_print(*args, **kwargs):
            import rich

            rich.print("Successfully uploaded scan results")
            return [mock_result]

        with patch("agent_scan.cli.run_scan", side_effect=mock_run_scan_with_print):
            args = Namespace(
                json=True,
                print_errors=False,
                print_full_descriptions=False,
                verbose=False,
            )

            captured_output = io.StringIO()
            original_stdout = sys.stdout

            try:
                sys.stdout = captured_output
                await print_scan_inspect(mode="scan", args=args)
            finally:
                sys.stdout = original_stdout

            output = captured_output.getvalue()
            assert "Successfully uploaded scan results" not in output

            parsed = json.loads(output)
            assert isinstance(parsed, dict)


def _make_scan_parser():
    """Helper: build a scan subcommand parser identical to the one in main()."""
    parser = argparse.ArgumentParser(prog="agent-scan")
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan")
    setup_scan_parser(scan_parser)
    return parser


def _make_inspect_parser():
    """Helper: build an inspect subcommand parser identical to the one in main()."""
    parser = argparse.ArgumentParser(prog="agent-scan")
    subparsers = parser.add_subparsers(dest="command")
    inspect_parser = subparsers.add_parser("inspect")
    add_common_arguments(inspect_parser)
    add_server_arguments(inspect_parser)
    inspect_parser.add_argument("files", type=str, nargs="*", default=[])
    return parser


class TestEnableOAuthFlag:
    """Tests for the --enable-oauth CLI flag."""

    def test_enable_oauth_flag_default_false(self):
        """Parsing args for scan without --enable-oauth should default to False."""
        parser = _make_scan_parser()
        args = parser.parse_args(["scan"])
        assert args.enable_oauth is False

    def test_enable_oauth_flag_set_true(self):
        """Parsing args with --enable-oauth should set enable_oauth to True."""
        parser = _make_scan_parser()
        args = parser.parse_args(["scan", "--enable-oauth"])
        assert args.enable_oauth is True

    def test_enable_oauth_flag_available_on_inspect_command(self):
        """The --enable-oauth flag should be available on the inspect command."""
        parser = _make_inspect_parser()
        args = parser.parse_args(["inspect", "--enable-oauth"])
        assert args.enable_oauth is True


class TestOAuthClientIdFlags:
    """Tests for the --oauth-client-id and --oauth-client-secret CLI flags."""

    def test_oauth_client_id_default_none(self):
        """Parsing args without --oauth-client-id should default to None."""
        parser = _make_scan_parser()
        args = parser.parse_args(["scan", "somefile.json"])
        assert args.oauth_client_id is None

    def test_oauth_client_id_set(self):
        """Parsing args with --oauth-client-id should set the value."""
        parser = _make_scan_parser()
        args = parser.parse_args(["scan", "--oauth-client-id", "my-client-id", "somefile.json"])
        assert args.oauth_client_id == "my-client-id"

    def test_oauth_client_id_available_on_inspect_command(self):
        """The --oauth-client-id flag should be available on the inspect command."""
        parser = _make_inspect_parser()
        args = parser.parse_args(["inspect", "--oauth-client-id", "id123", "somefile.json"])
        assert args.oauth_client_id == "id123"

    @pytest.mark.asyncio
    async def test_oauth_client_id_auto_implies_enable_oauth(self):
        """Setting --oauth-client-id should auto-imply enable_oauth=True in InspectArgs."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = ScanPathResult(path="/test/path")

        with patch(
            "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
        ) as mock_pipeline:
            args = Namespace(
                verification_H=None,
                verbose=False,
                scan_all_users=False,
                server_timeout=10,
                files=[],
                mcp_oauth_tokens_path=None,
                analysis_url="https://test.com/analysis",
                skip_ssl_verify=False,
                control_servers=[],
                enable_oauth=False,
                oauth_client_id="my-id",
            )

            await run_scan(args, mode="scan")

            mock_pipeline.assert_called_once()
            inspect_args = mock_pipeline.call_args[0][0]
            assert inspect_args.enable_oauth is True
            assert inspect_args.oauth_client_id == "my-id"

    @pytest.mark.asyncio
    async def test_oauth_client_id_none_does_not_imply_enable_oauth(self):
        """When oauth_client_id is None and enable_oauth is False, enable_oauth should stay False."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = ScanPathResult(path="/test/path")

        with patch(
            "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
        ) as mock_pipeline:
            args = Namespace(
                verification_H=None,
                verbose=False,
                scan_all_users=False,
                server_timeout=10,
                files=[],
                mcp_oauth_tokens_path=None,
                analysis_url="https://test.com/analysis",
                skip_ssl_verify=False,
                control_servers=[],
                enable_oauth=False,
                oauth_client_id=None,
            )

            await run_scan(args, mode="scan")

            mock_pipeline.assert_called_once()
            inspect_args = mock_pipeline.call_args[0][0]
            assert inspect_args.enable_oauth is False
