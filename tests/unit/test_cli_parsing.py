"""Tests for CLI argument parsing, especially multiple control servers."""

from unittest.mock import AsyncMock, patch

import pytest

from agent_scan.cli import MissingIdentifierError, parse_control_servers, warn_deprecated_control_flags
from agent_scan.models import ControlServer, InspectedPath


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

    def test_equals_syntax_is_parsed(self):
        """`--control-server=URL` (and the other block flags) must parse like the space form."""
        argv = [
            "scan",
            "--control-server=https://server1.com?version=2",
            "--control-server-H=Auth: token1",
            "--control-identifier=user1@example.com",
        ]

        control_servers = parse_control_servers(argv)

        assert len(control_servers) == 1
        assert control_servers[0].url == "https://server1.com?version=2"  # '=' inside the URL is preserved
        assert control_servers[0].identifier == "user1@example.com"
        assert control_servers[0].headers == {"Auth": " token1"}


class TestSkillsFlag:
    """--skills is on by default; --no-skills opts out; --skills is still accepted."""

    def _parse(self, extra_argv: list[str]) -> bool:
        import argparse

        from agent_scan.cli import add_common_arguments

        parser = argparse.ArgumentParser()
        add_common_arguments(parser)
        return parser.parse_args(extra_argv).skills

    def test_skills_default_is_true(self):
        assert self._parse([]) is True

    def test_skills_flag_keeps_true(self):
        assert self._parse(["--skills"]) is True

    def test_no_skills_disables(self):
        assert self._parse(["--no-skills"]) is False

    def test_no_skills_then_skills_re_enables(self):
        assert self._parse(["--no-skills", "--skills"]) is True


class TestPushKeyMachineIdArguments:
    """--push-key / --machine-id: standalone replacements for
    --control-server-H's x-client-id header and --control-identifier."""

    def _parse(self, extra_argv: list[str]) -> object:
        import argparse

        from agent_scan.cli import add_control_server_arguments

        parser = argparse.ArgumentParser()
        add_control_server_arguments(parser)
        return parser.parse_args(extra_argv)

    def test_push_key_alone_parses(self):
        args = self._parse(["--push-key", "my-secret-key"])
        assert args.push_key == "my-secret-key"
        assert args.machine_id is None

    def test_machine_id_alone_parses(self):
        args = self._parse(["--machine-id", "host-42"])
        assert args.machine_id == "host-42"
        assert args.push_key is None

    def test_push_key_and_machine_id_together_parse_independently(self):
        args = self._parse(["--push-key", "my-secret-key", "--machine-id", "host-42"])
        assert args.push_key == "my-secret-key"
        assert args.machine_id == "host-42"

    def test_neither_flag_defaults_to_none(self):
        args = self._parse([])
        assert args.push_key is None
        assert args.machine_id is None
        assert args.control_server_H is None
        assert args.control_identifier is None


class TestEffectiveValueResolution:
    """_effective_push_key / _effective_identifier resolve the new flag over
    the deprecated one, using an explicit `is not None` check rather than
    truthiness so an explicitly-passed empty string is honored as-is
    instead of silently falling back to the legacy value."""

    def test_explicit_empty_push_key_does_not_fall_back_to_legacy_header(self):
        from argparse import Namespace

        from agent_scan.cli import _effective_push_key

        args = Namespace(
            command="scan",
            push_key="",
            control_servers=[
                ControlServer(url="https://s.com", headers={"x-client-id": "legacy-key"}, identifier="id1")
            ],
        )
        assert _effective_push_key(args) == ""

    def test_explicit_empty_machine_id_does_not_fall_back_to_legacy_identifier(self):
        from argparse import Namespace

        from agent_scan.cli import _effective_identifier

        args = Namespace(
            machine_id="",
            control_servers=[ControlServer(url="https://s.com", headers={}, identifier="legacy-id")],
        )
        assert _effective_identifier(args) == ""

    def test_missing_push_key_falls_back_to_legacy_header(self):
        from argparse import Namespace

        from agent_scan.cli import _effective_push_key

        args = Namespace(
            command="scan",
            control_servers=[
                ControlServer(url="https://s.com", headers={"x-client-id": "legacy-key"}, identifier="id1")
            ],
        )
        assert _effective_push_key(args) == "legacy-key"


class TestDeprecationWarnings:
    """Old --control-server-H / --control-identifier still work, but emit a
    one-time-per-invocation stderr warning pointing at --push-key /
    --machine-id. --control-server-H only warns when it's actually used for
    the deprecated x-client-id push-key trick, since it's otherwise a
    generic "additional header" flag; --control-identifier warns on any
    use."""

    def _parse(self, extra_argv: list[str]) -> object:
        import argparse

        from agent_scan.cli import add_control_server_arguments, parse_control_servers

        parser = argparse.ArgumentParser()
        add_control_server_arguments(parser)
        args = parser.parse_args(extra_argv)
        # Mirrors main(): control_servers is attached from the raw argv
        # before warn_deprecated_control_flags is called.
        args.control_servers = parse_control_servers(extra_argv)
        return args

    def test_control_server_h_alone_warns_only_about_push_key(self, capsys):
        args = self._parse(["--control-server-H", "x-client-id:abc"])
        warn_deprecated_control_flags(args)
        captured = capsys.readouterr()
        assert "--control-server-H" in captured.err
        assert "--push-key" in captured.err
        assert "--control-identifier" not in captured.err
        assert "--machine-id" not in captured.err

    def test_control_identifier_alone_warns_only_about_machine_id(self, capsys):
        args = self._parse(["--control-identifier", "user1"])
        warn_deprecated_control_flags(args)
        captured = capsys.readouterr()
        assert "--control-identifier" in captured.err
        assert "--machine-id" in captured.err
        assert "--control-server-H" not in captured.err
        assert "--push-key" not in captured.err

    def test_both_old_flags_together_emit_both_warnings(self, capsys):
        args = self._parse(["--control-server-H", "x-client-id:abc", "--control-identifier", "user1"])
        warn_deprecated_control_flags(args)
        captured = capsys.readouterr()
        assert "--control-server-H" in captured.err
        assert "--push-key" in captured.err
        assert "--control-identifier" in captured.err
        assert "--machine-id" in captured.err

    def test_new_flags_alone_emit_no_warning(self, capsys):
        args = self._parse(["--push-key", "key", "--machine-id", "id"])
        warn_deprecated_control_flags(args)
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_neither_old_nor_new_flag_emits_no_warning(self, capsys):
        args = self._parse([])
        warn_deprecated_control_flags(args)
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_old_and_new_together_still_warns(self, capsys):
        """Using --push-key doesn't suppress the warning for a still-present old flag."""
        args = self._parse(["--control-server-H", "x-client-id:abc", "--push-key", "new-key"])
        warn_deprecated_control_flags(args)
        captured = capsys.readouterr()
        assert "--control-server-H" in captured.err
        assert "--control-identifier" not in captured.err

    def test_control_server_h_with_unrelated_header_emits_no_warning(self, capsys):
        """--control-server-H is a generic 'additional header' flag; using it
        for a header unrelated to the x-client-id push-key trick must not
        trigger the --push-key deprecation warning."""
        args = self._parse(
            [
                "--control-server",
                "https://s1.com",
                "--control-server-H",
                "X-Custom: value",
                "--control-identifier",
                "id1",
            ]
        )
        warn_deprecated_control_flags(args)
        captured = capsys.readouterr()
        assert "--control-server-H" not in captured.err
        assert "--push-key" not in captured.err

    def test_control_identifier_with_multiple_control_servers_still_warns(self, capsys):
        """--control-identifier warns on any use, even in a legitimate
        multi-control-server setup where --machine-id (a single scalar
        value) couldn't actually replace the distinct per-server
        identifiers -- the warning is a nudge for the common single-server
        case, not a precise migration guarantee."""
        args = self._parse(
            [
                "--control-server",
                "https://s1.com",
                "--control-identifier",
                "id1",
                "--control-server",
                "https://s2.com",
                "--control-identifier",
                "id2",
            ]
        )
        warn_deprecated_control_flags(args)
        captured = capsys.readouterr()
        assert "--control-identifier" in captured.err
        assert "--machine-id" in captured.err


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

        mock_result = InspectedPath(path="/test/path")

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
                    ControlServer(url="https://server1.com", headers={"x-client-id": "push-key-1"}, identifier="user1"),
                    ControlServer(url="https://server2.com", headers={"x-client-id": "push-key-2"}, identifier="user2"),
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

        mock_result = InspectedPath(path="/test/path")

        with (
            patch("agent_scan.cli.collect_consent", return_value=set()),
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
            ) as mock_pipeline,
        ):
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
    async def test_push_key_flag_alone_passed_to_push_args(self):
        """--push-key alone (no --control-server) reaches PushArgs.push_key."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = InspectedPath(path="/test/path")

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
                push_key="direct-push-key",
            )

            await run_scan(args, mode="scan")

            push_args = mock_pipeline.call_args[0][2]
            assert push_args.control_servers == []
            assert push_args.push_key == "direct-push-key"

    @pytest.mark.asyncio
    async def test_machine_id_flag_alone_passed_to_analyze_args_identifier(self):
        """--machine-id alone (no --control-server) reaches AnalyzeArgs.identifier."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = InspectedPath(path="/test/path")

        with (
            patch("agent_scan.cli.collect_consent", return_value=set()),
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
            ) as mock_pipeline,
        ):
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
                machine_id="host-42",
            )

            await run_scan(args, mode="scan")

            analyze_args = mock_pipeline.call_args[0][1]
            assert analyze_args.identifier == "host-42"

    @pytest.mark.asyncio
    async def test_old_control_server_flags_still_work_without_new_flags(self):
        """Old --control-server-H / --control-identifier still function unchanged
        when --push-key / --machine-id are absent from args entirely.
        push_key is now resolved once in run_scan (via _effective_push_key)
        and lands on PushArgs already resolved, so it carries the header-
        derived value rather than None."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = InspectedPath(path="/test/path")

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
                    ControlServer(
                        url="https://server1.com", headers={"x-client-id": "old-push-key"}, identifier="old-id"
                    )
                ],
            )

            await run_scan(args, mode="scan")

            push_args = mock_pipeline.call_args[0][2]
            analyze_args = mock_pipeline.call_args[0][1]
            assert push_args.push_key == "old-push-key"
            assert analyze_args.identifier == "old-id"

    @pytest.mark.asyncio
    async def test_new_flags_take_precedence_over_old_when_both_given(self):
        """When both old and new flags are supplied for the same concept, the
        new flag's value wins."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = InspectedPath(path="/test/path")

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
                    ControlServer(
                        url="https://server1.com", headers={"x-client-id": "old-push-key"}, identifier="old-id"
                    )
                ],
                push_key="new-push-key",
                machine_id="new-id",
            )

            await run_scan(args, mode="scan")

            push_args = mock_pipeline.call_args[0][2]
            analyze_args = mock_pipeline.call_args[0][1]
            assert push_args.push_key == "new-push-key"
            assert analyze_args.identifier == "new-id"

    @pytest.mark.asyncio
    async def test_evo_command_push_key_flag_is_ignored_in_favor_of_control_servers(self):
        """On the evo command, run_scan must never let an externally-supplied
        --push-key override the key evo minted and injected into
        args.control_servers — _effective_push_key ignores args.push_key
        entirely for command == 'evo'."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = InspectedPath(path="/test/path")

        with (
            patch("agent_scan.cli.collect_consent", return_value=set()),
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
            ) as mock_pipeline,
        ):
            args = Namespace(
                command="evo",
                verification_H=None,
                verbose=False,
                scan_all_users=False,
                server_timeout=10,
                files=[],
                mcp_oauth_tokens_path=None,
                analysis_url="https://test.com/analysis",
                skip_ssl_verify=False,
                control_servers=[
                    ControlServer(
                        url="https://push.example/scan", headers={"x-client-id": "minted-key"}, identifier="host1"
                    )
                ],
                push_key="attacker-or-stale-key",
            )

            await run_scan(args, mode="scan")

            push_args = mock_pipeline.call_args[0][2]
            assert push_args.push_key == "minted-key"

    @pytest.mark.asyncio
    async def test_evo_mints_and_uses_its_own_push_key_end_to_end(self):
        """evo() mints its own client_id and must use it for the scan even
        if the caller separately supplied --push-key; the externally
        supplied key must never reach PushArgs.push_key."""
        from argparse import Namespace

        from agent_scan.cli import evo

        mock_result = InspectedPath(path="/test/path")
        args = Namespace(
            command="evo",
            push_key="attacker-or-stale-key",
            verification_H=None,
            verbose=False,
            scan_all_users=False,
            server_timeout=10,
            files=[],
            mcp_oauth_tokens_path=None,
            analysis_url="https://test.com/analysis",
            skip_ssl_verify=False,
            dangerously_run_mcp_servers=False,
            suppress_mcpserver_io=None,
            ci=False,
        )

        with (
            patch("builtins.input", side_effect=["tenant-1", "token-1"]),
            patch("agent_scan.pushkeys.mint_push_key", return_value="minted-key"),
            patch("agent_scan.pushkeys.revoke_push_key") as mock_revoke,
            patch("agent_scan.cli.discover_clients_to_inspect", new_callable=AsyncMock, return_value=([], [], [])),
            patch("agent_scan.cli.collect_consent", return_value=set()),
            patch(
                "agent_scan.cli.inspect_analyze_push_pipeline", new_callable=AsyncMock, return_value=[mock_result]
            ) as mock_pipeline,
        ):
            await evo(args)

        push_args = mock_pipeline.call_args[0][2]
        assert push_args.push_key == "minted-key"
        mock_revoke.assert_called_once()

    @pytest.mark.asyncio
    async def test_skip_ssl_verify_passed_to_pipeline(self):
        """Test that skip_ssl_verify is correctly passed to the pipeline."""
        from argparse import Namespace

        from agent_scan.cli import run_scan

        mock_result = InspectedPath(path="/test/path")

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
                control_servers=[
                    ControlServer(url="https://server1.com", headers={"x-client-id": "push-key"}, identifier="host1")
                ],
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
                control_servers=[
                    ControlServer(url="https://server1.com", headers={"x-client-id": "push-key"}, identifier="host1")
                ],
            )

            await run_scan(args_with, mode="scan")
            push_args = mock_pipeline.call_args[0][2]
            analyze_args = mock_pipeline.call_args[0][1]
            assert push_args.skip_ssl_verify is True
            assert analyze_args.skip_ssl_verify is True


class TestTargetArgumentParsing:
    """add_target_arguments defines the shared --server/--url/--server-type surface.

    Exercised against a bare parser because cli.main() builds its parser inline
    and does not expose it for construction in isolation.
    """

    @staticmethod
    def _parser(*, positional, include_type):
        import argparse

        from agent_scan.cli import add_target_arguments

        parser = argparse.ArgumentParser(prog="test")
        add_target_arguments(parser, positional=positional, include_type=include_type)
        return parser

    def test_scan_style_uses_flags_and_exposes_server_type(self):
        args = self._parser(positional=False, include_type=True).parse_args(
            ["--server", "snyk", "--server-type", "http"]
        )

        assert args.server == "snyk"
        assert args.server_type == "http"

    def test_url_and_server_may_be_combined(self):
        """--url is the target; --server is only the display name, matching mcp-auth."""
        args = self._parser(positional=False, include_type=True).parse_args(
            ["--url", "https://a.test/mcp", "--server", "label"]
        )

        assert args.url == "https://a.test/mcp"
        assert args.server == "label"

    def test_defaults_are_none_so_ordinary_scans_are_unaffected(self):
        args = self._parser(positional=False, include_type=True).parse_args([])

        assert args.server is None
        assert args.url is None
        assert args.server_type is None

    def test_unknown_transport_is_rejected(self):
        with pytest.raises(SystemExit):
            self._parser(positional=False, include_type=True).parse_args(["--server-type", "websocket"])

    def test_mcp_auth_style_takes_the_server_name_positionally(self):
        args = self._parser(positional=True, include_type=False).parse_args(["MY_SERVER", "--url", "https://a.test"])

        assert args.server == "MY_SERVER"
        assert args.url == "https://a.test"

    def test_mcp_auth_style_omits_server_type(self):
        with pytest.raises(SystemExit):
            self._parser(positional=True, include_type=False).parse_args(["MY_SERVER", "--server-type", "http"])

    def test_mcp_auth_server_name_stays_optional(self):
        args = self._parser(positional=True, include_type=False).parse_args([])

        assert args.server is None
