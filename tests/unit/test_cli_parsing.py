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
        assert result[0]["opt_out"] is False

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
        assert result[0]["opt_out"] is True

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
            "--opt-out",
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
        assert result[0]["opt_out"] is True

        # Second server
        assert result[1]["url"] == "https://server2.com"
        assert result[1]["headers"] == ["Auth: token2"]
        assert result[1]["identifier"] == "serial-123"
        assert result[1]["opt_out"] is False

    def test_parse_multiple_control_servers_mixed_options(self):
        """Test parsing multiple servers where some have certain options and others don't."""
        argv = [
            "--control-server",
            "https://server1.com",
            "--control-identifier",
            "user1",
            "--control-server",
            "https://server2.com",
            "--opt-out",
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
        assert result[0]["opt_out"] is False

        # Second server: only opt-out
        assert result[1]["url"] == "https://server2.com"
        assert result[1]["opt_out"] is True
        assert result[1]["identifier"] is None
        assert result[1]["headers"] == []

        # Third server: only headers
        assert result[2]["url"] == "https://server3.com"
        assert result[2]["headers"] == ["Auth: token3", "X-Custom: value3"]
        assert result[2]["identifier"] is None
        assert result[2]["opt_out"] is False

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
            "--opt-out",
            "--storage-file",
            "~/.mcp-scan",
        ]
        result = parse_control_servers(argv)

        assert len(result) == 2
        assert result[0]["url"] == "https://server1.com"
        assert result[0]["identifier"] == "user1"
        assert result[1]["url"] == "https://server2.com"
        assert result[1]["opt_out"] is True

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
            "--opt-out",
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

    @pytest.mark.asyncio
    async def test_scan_with_multiple_control_servers_uploads_to_all(self):
        """Test that scanning with multiple control servers uploads to all of them."""
        mock_result = ScanPathResult(path="/test/path")

        with (
            patch("agent_scan.cli.MCPScanner") as MockScanner,
            patch("agent_scan.cli.upload") as mock_upload,
            patch("agent_scan.cli.print_scan_result"),
        ):
            # Setup scanner mock
            mock_scanner_instance = AsyncMock()
            mock_scanner_instance.scan = AsyncMock(return_value=[mock_result])
            mock_scanner_instance.__aenter__ = AsyncMock(return_value=mock_scanner_instance)
            mock_scanner_instance.__aexit__ = AsyncMock(return_value=None)
            MockScanner.return_value = mock_scanner_instance

            # Setup upload mock
            mock_upload.return_value = None

            # Simulate CLI with multiple control servers
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

            with patch.object(sys, "argv", test_argv):
                # Import and run the relevant parts
                from agent_scan.cli import parse_control_servers

                control_servers = parse_control_servers(test_argv)

                # Verify parsing
                assert len(control_servers) == 2
                assert control_servers[0]["url"] == "https://server1.com"
                assert control_servers[0]["identifier"] == "user1@example.com"
                assert control_servers[0]["opt_out"] is True
                assert control_servers[1]["url"] == "https://server2.com"
                assert control_servers[1]["identifier"] == "serial-123"
                assert control_servers[1]["opt_out"] is False


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
    """Integration tests for uploading to multiple control servers."""

    @pytest.mark.asyncio
    async def test_upload_called_for_each_control_server(self):
        """Test that upload is called once for each control server."""
        from argparse import Namespace

        from agent_scan.cli import run_scan_inspect

        mock_result = ScanPathResult(path="/test/path")

        with patch("agent_scan.cli.MCPScanner") as MockScanner, patch("agent_scan.cli.upload") as mock_upload:
            # Setup scanner mock
            mock_scanner_instance = AsyncMock()
            mock_scanner_instance.scan = AsyncMock(return_value=[mock_result])
            mock_scanner_instance.__aenter__ = AsyncMock(return_value=mock_scanner_instance)
            mock_scanner_instance.__aexit__ = AsyncMock(return_value=None)
            MockScanner.return_value = mock_scanner_instance

            # Setup upload mock
            mock_upload.return_value = None

            # Create args with multiple control servers
            args = Namespace(
                verification_H=None,
                control_servers=[
                    {"url": "https://server1.com", "headers": ["Auth: token1"], "identifier": "user1", "opt_out": True},
                    {
                        "url": "https://server2.com",
                        "headers": ["Auth: token2", "X-Custom: value"],
                        "identifier": "user2",
                        "opt_out": False,
                    },
                ],
            )

            # Run the scan
            await run_scan_inspect(mode="scan", args=args)

            # Verify upload was called twice
            assert mock_upload.call_count == 2

            # Verify first upload call
            first_call = mock_upload.call_args_list[0]
            assert first_call[0][1] == "https://server1.com"  # URL
            assert first_call[0][2] == "user1"  # identifier
            assert first_call[0][3] is True  # opt_out

            # Verify second upload call
            second_call = mock_upload.call_args_list[1]
            assert second_call[0][1] == "https://server2.com"  # URL
            assert second_call[0][2] == "user2"  # identifier
            assert second_call[0][3] is False  # opt_out

    @pytest.mark.asyncio
    async def test_no_upload_when_no_control_servers(self):
        """Test that upload is not called when no control servers are specified."""
        from argparse import Namespace

        from agent_scan.cli import run_scan_inspect

        mock_result = ScanPathResult(path="/test/path")

        with patch("agent_scan.cli.MCPScanner") as MockScanner, patch("agent_scan.cli.upload") as mock_upload:
            # Setup scanner mock
            mock_scanner_instance = AsyncMock()
            mock_scanner_instance.scan = AsyncMock(return_value=[mock_result])
            mock_scanner_instance.__aenter__ = AsyncMock(return_value=mock_scanner_instance)
            mock_scanner_instance.__aexit__ = AsyncMock(return_value=None)
            MockScanner.return_value = mock_scanner_instance

            # Setup upload mock
            mock_upload.return_value = None

            # Create args with no control servers
            args = Namespace(verification_H=None, control_servers=[])

            # Run the scan
            await run_scan_inspect(mode="scan", args=args)

            # Verify upload was not called
            mock_upload.assert_not_called()

    @pytest.mark.asyncio
    async def test_upload_with_skip_ssl_verify(self):
        """Test that upload is called with skip_ssl_verify option."""
        from argparse import Namespace

        from agent_scan.cli import run_scan_inspect

        mock_result = ScanPathResult(path="/test/path")

        with patch("agent_scan.cli.MCPScanner") as MockScanner, patch("agent_scan.cli.upload") as mock_upload:
            # Setup scanner mock
            mock_scanner_instance = AsyncMock()
            mock_scanner_instance.scan = AsyncMock(return_value=[mock_result])
            mock_scanner_instance.__aenter__ = AsyncMock(return_value=mock_scanner_instance)
            mock_scanner_instance.__aexit__ = AsyncMock(return_value=None)
            MockScanner.return_value = mock_scanner_instance

            # Setup upload mock
            mock_upload.return_value = None

            # Create args with a control server and without the skip_ssl_verify option
            args_without_skip_ssl_verify = Namespace(
                verification_H=None,
                control_servers=[{"url": "https://server1.com", "headers": [], "identifier": None, "opt_out": False}],
            )

            # Run the scan
            await run_scan_inspect(mode="scan", args=args_without_skip_ssl_verify)

            # Verify upload was called and skip_ssl_verify was not propagated
            _, kwargs = mock_upload.call_args
            assert kwargs.get("skip_ssl_verify") is False

            # Create args with a control server and skip_ssl_verify option
            args_with_skip_ssl_verify = Namespace(
                verification_H=None,
                control_servers=[{"url": "https://server1.com", "headers": [], "identifier": None, "opt_out": False}],
                skip_ssl_verify=True,
            )

            # Run the scan
            await run_scan_inspect(mode="scan", args=args_with_skip_ssl_verify)

            # Verify upload was called and skip_ssl_verify was propagated
            assert mock_upload.call_count == 2
            _, kwargs = mock_upload.call_args
            assert kwargs.get("skip_ssl_verify") is True


class TestJSONOutput:
    """Test suite for JSON output functionality."""

    @pytest.mark.asyncio
    async def test_json_output_suppresses_stdout_during_scan(self):
        """Test that when --json is enabled, stdout is suppressed during scan."""
        import io
        import json
        import sys
        from argparse import Namespace

        from agent_scan.cli import scan_with_skills
        from agent_scan.models import ScanPathResult

        mock_result = ScanPathResult(path="/test/path.json")

        with patch("agent_scan.cli.MCPScanner") as MockScanner, patch("agent_scan.cli.upload"):
            # Setup scanner mock
            mock_scanner_instance = AsyncMock()
            mock_scanner_instance.scan = AsyncMock(return_value=[mock_result])
            mock_scanner_instance.__aenter__ = AsyncMock(return_value=mock_scanner_instance)
            mock_scanner_instance.__aexit__ = AsyncMock(return_value=None)
            MockScanner.return_value = mock_scanner_instance

            # Create args with json enabled
            args = Namespace(
                json=True,
                verification_H=None,
                control_servers=[],
                print_errors=False,
                full_toxic_flows=False,
                verbose=False,
                skills=False,
                files=[],
            )

            captured_output = io.StringIO()
            original_stdout = sys.stdout

            try:
                sys.stdout = captured_output
                await scan_with_skills(mode="scan", args=args)
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
        import sys
        from argparse import Namespace

        from agent_scan.cli import scan_with_skills
        from agent_scan.models import ScanPathResult

        mock_result = ScanPathResult(path="/test/path.json")

        with patch("agent_scan.cli.MCPScanner") as MockScanner, patch("agent_scan.cli.upload") as mock_upload:
            # Setup scanner mock
            mock_scanner_instance = AsyncMock()
            mock_scanner_instance.scan = AsyncMock(return_value=[mock_result])
            mock_scanner_instance.__aenter__ = AsyncMock(return_value=mock_scanner_instance)
            mock_scanner_instance.__aexit__ = AsyncMock(return_value=None)
            MockScanner.return_value = mock_scanner_instance

            # Setup upload to print (which should be suppressed)
            def mock_upload_with_print(*args, **kwargs):
                import rich

                rich.print("Successfully uploaded scan results")

            mock_upload.side_effect = mock_upload_with_print

            args = Namespace(
                json=True,
                verification_H=None,
                control_servers=[{"url": "https://test.com", "headers": [], "identifier": None, "opt_out": False}],
                print_errors=False,
                full_toxic_flows=False,
                verbose=False,
                skills=False,
                files=[],
            )

            # Capture stdout
            captured_output = io.StringIO()
            original_stdout = sys.stdout

            try:
                sys.stdout = captured_output
                await scan_with_skills(mode="scan", args=args)
            finally:
                sys.stdout = original_stdout

            output = captured_output.getvalue()
            assert "Successfully uploaded scan results" not in output

            parsed = json.loads(output)
            assert isinstance(parsed, dict)
