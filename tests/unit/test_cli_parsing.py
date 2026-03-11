"""Tests for CLI argument parsing, especially multiple control servers."""

import sys
from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import parse_control_servers
from agent_scan.models import ScanPathResult


class TestControlServerParsing:
    """Test suite for parsing multiple control servers with individual options."""

    def test_parse_single_control_server_no_options(self):
        """Test parsing a single control server without any options."""
        argv = ["--control-server", "https://server1.com"]
        result = parse_control_servers(argv)

        assert len(result) == 1
        assert result[0]["url"] == "https://server1.com"
        assert result[0]["headers"] == []
        assert result[0]["identifier"] is None

    def test_parse_single_control_server_with_all_options(self):
        """Test parsing a single control server with all options."""
        argv = [
            "--control-server",
            "https://server1.com",
            "--control-server-H",
            "Auth: token1",
            "--control-identifier",
            "user@example.com",
            "--opt-out",
        ]
        result = parse_control_servers(argv)

        assert len(result) == 1
        assert result[0]["url"] == "https://server1.com"
        assert result[0]["headers"] == ["Auth: token1"]
        assert result[0]["identifier"] == "user@example.com"

    def test_parse_single_control_server_with_multiple_headers(self):
        """Test parsing a single control server with multiple headers."""
        argv = [
            "--control-server",
            "https://server1.com",
            "--control-server-H",
            "Auth: token1",
            "--control-server-H",
            "X-Custom: value1",
        ]
        result = parse_control_servers(argv)

        assert len(result) == 1
        assert result[0]["url"] == "https://server1.com"
        assert result[0]["headers"] == ["Auth: token1", "X-Custom: value1"]

    def test_parse_multiple_control_servers_with_individual_options(self):
        """Test parsing multiple control servers with their own options."""
        argv = [
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
        ]
        result = parse_control_servers(argv)

        assert len(result) == 2

        # First server
        assert result[0]["url"] == "https://server1.com"
        assert result[0]["headers"] == ["Auth: token1"]
        assert result[0]["identifier"] == "user@example.com"

        # Second server
        assert result[1]["url"] == "https://server2.com"
        assert result[1]["headers"] == ["Auth: token2"]
        assert result[1]["identifier"] == "serial-123"

    def test_parse_multiple_control_servers_mixed_options(self):
        """Test parsing multiple servers where some have certain options and others don't."""
        argv = [
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
            "--control-server-H",
            "X-Custom: value3",
        ]
        result = parse_control_servers(argv)

        assert len(result) == 3

        # First server: only identifier
        assert result[0]["url"] == "https://server1.com"
        assert result[0]["identifier"] == "user1"
        assert result[0]["headers"] == []

        # Second server: only opt-out
        assert result[1]["url"] == "https://server2.com"
        assert result[1]["identifier"] is None
        assert result[1]["headers"] == []

        # Third server: only headers
        assert result[2]["url"] == "https://server3.com"
        assert result[2]["headers"] == ["Auth: token3", "X-Custom: value3"]
        assert result[2]["identifier"] is None

    def test_parse_control_servers_with_other_cli_args(self):
        """Test that control server parsing doesn't interfere with other CLI arguments."""
        argv = [
            "scan",
            "--verbose",
            "--control-server",
            "https://server1.com",
            "--control-identifier",
            "user1",
            "--json",
            "--control-server",
            "https://server2.com",
            "--storage-file",
            "~/.mcp-scan",
        ]
        result = parse_control_servers(argv)

        assert len(result) == 2
        assert result[0]["url"] == "https://server1.com"
        assert result[0]["identifier"] == "user1"
        assert result[1]["url"] == "https://server2.com"

    def test_parse_no_control_servers(self):
        """Test parsing when no control servers are specified."""
        argv = ["scan", "--verbose", "--json"]
        result = parse_control_servers(argv)

        assert len(result) == 0

    def test_parse_control_servers_options_before_first_server_ignored(self):
        """Test that control server options before the first --control-server are ignored."""
        argv = [
            "--control-identifier",
            "should-be-ignored",
            "--control-server",
            "https://server1.com",
            "--control-identifier",
            "user1",
        ]
        result = parse_control_servers(argv)

        assert len(result) == 1
        assert result[0]["url"] == "https://server1.com"
        assert result[0]["identifier"] == "user1"  # Should use the one after --control-server

    def test_parse_control_server_options_only_apply_to_preceding_server(self):
        """Test that options only apply to their immediately preceding server."""
        argv = [
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
        ]
        result = parse_control_servers(argv)

        assert len(result) == 3
        assert result[0]["identifier"] == "user1"
        assert result[1]["identifier"] is None  # No identifier for server2
        assert result[2]["identifier"] == "user3"

    def test_parse_control_server_without_url(self):
        """Test parsing when --control-server is provided without a URL."""
        argv = [
            "--control-server",  # No URL follows
            "--verbose",
        ]
        result = parse_control_servers(argv)

        # Should not create a server entry when URL is missing
        assert len(result) == 0

    def test_parse_control_server_url_starts_with_dash(self):
        """Test parsing when what looks like a URL actually starts with --."""
        argv = ["--control-server", "--some-other-arg", "value"]
        result = parse_control_servers(argv)

        # Should not create a server when the next arg is another flag
        assert len(result) == 0


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
        assert control_servers[0]["url"] == "https://server1.com"
        assert control_servers[0]["identifier"] == "user1@example.com"
        assert control_servers[1]["url"] == "https://server2.com"
        assert control_servers[1]["identifier"] == "serial-123"


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
                    {"url": "https://server1.com", "headers": ["Auth: token1"], "identifier": "user1"},
                    {
                        "url": "https://server2.com",
                        "headers": ["Auth: token2", "X-Custom: value"],
                        "identifier": "user2",
                    },
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
                control_servers=[{"url": "https://server1.com", "headers": [], "identifier": None}],
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
                control_servers=[{"url": "https://server1.com", "headers": [], "identifier": None}],
            )

            await run_scan(args_with, mode="scan")
            push_args = mock_pipeline.call_args[0][2]
            analyze_args = mock_pipeline.call_args[0][1]
            assert push_args.skip_ssl_verify is True
            assert analyze_args.skip_ssl_verify is True


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
