"""Tests for --config-file: loading YAML, the precedence cascade, and
complete-replacement semantics for block/list arguments."""

import argparse

import pytest

from agent_scan.cli import (
    _coerce_config_value,
    _effective_identifier,
    _effective_push_key,
    apply_config_file,
    control_servers_from_config,
    explicitly_provided_dests,
    load_config_file,
    parse_control_servers,
    setup_scan_parser,
)
from agent_scan.models import ControlServer


def _build_parser() -> argparse.ArgumentParser:
    """Build a parser mirroring the real ``scan`` subparser used in main().

    ``allow_abbrev=False`` matches main() so prefix abbreviations (e.g. ``--verb``)
    are rejected rather than silently expanded — this keeps
    ``explicitly_provided_dests`` (which matches full option strings) exact.
    """
    parser = argparse.ArgumentParser(allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser("scan", allow_abbrev=False)
    setup_scan_parser(scan_parser)
    return parser


def _parse(argv: list[str]) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Parse ``argv`` (as sys.argv[1:]) and attach control_servers like main() does."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    args.control_servers = parse_control_servers(argv)
    return parser, args


def _write_yaml(tmp_path, text: str) -> str:
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return str(path)


class TestLoadConfigFile:
    def test_loads_valid_mapping(self, tmp_path):
        path = _write_yaml(tmp_path, "server_timeout: 30\nverbose: true\n")
        assert load_config_file(path) == {"server_timeout": 30, "verbose": True}

    def test_empty_file_returns_empty_dict(self, tmp_path):
        path = _write_yaml(tmp_path, "")
        assert load_config_file(path) == {}

    def test_missing_file_exits_2(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            load_config_file(str(tmp_path / "does-not-exist.yaml"))
        assert exc.value.code == 2

    def test_invalid_yaml_exits_2(self, tmp_path):
        path = _write_yaml(tmp_path, "key: [unclosed\n")
        with pytest.raises(SystemExit) as exc:
            load_config_file(path)
        assert exc.value.code == 2

    def test_non_mapping_top_level_exits_2(self, tmp_path):
        path = _write_yaml(tmp_path, "- just\n- a\n- list\n")
        with pytest.raises(SystemExit) as exc:
            load_config_file(path)
        assert exc.value.code == 2


class TestExplicitlyProvidedDests:
    def test_detects_passed_flags_only(self):
        parser = _build_parser()
        provided = explicitly_provided_dests(parser, ["scan", "--server-timeout", "5", "--json"])
        assert "server_timeout" in provided
        assert "json" in provided
        assert "verbose" not in provided

    def test_detects_equals_form(self):
        parser = _build_parser()
        provided = explicitly_provided_dests(parser, ["scan", "--server-timeout=5"])
        assert "server_timeout" in provided

    def test_boolean_optional_both_spellings_map_to_same_dest(self):
        parser = _build_parser()
        assert "skills" in explicitly_provided_dests(parser, ["scan", "--no-skills"])
        assert "skills" in explicitly_provided_dests(parser, ["scan", "--skills"])

    def test_uses_destination_from_active_subparser_when_option_aliases_collide(self):
        parser = _build_parser()
        subparsers = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
        guard_parser = subparsers.add_parser("guard", allow_abbrev=False)
        guard_subparsers = guard_parser.add_subparsers(dest="guard_command")
        guard_install_parser = guard_subparsers.add_parser("install", allow_abbrev=False)
        guard_install_parser.add_argument("--machine-id", "--control-identifier", dest="machine_id", default=None)

        provided = explicitly_provided_dests(
            parser,
            ["scan", "--control-server", "https://example.com", "--control-identifier", "legacy-id"],
        )

        assert "control_identifier" in provided
        assert "machine_id" not in provided

    def test_root_option_value_is_not_mistaken_for_subcommand(self):
        parser = argparse.ArgumentParser(allow_abbrev=False)
        parser.add_argument("--config-file")
        subparsers = parser.add_subparsers(dest="command")
        scan_parser = subparsers.add_parser("scan", allow_abbrev=False)
        scan_parser.add_argument("--control-identifier")
        guard_parser = subparsers.add_parser("guard", allow_abbrev=False)
        guard_subparsers = guard_parser.add_subparsers(dest="guard_command")
        guard_subparsers.add_parser("install", allow_abbrev=False)

        provided = explicitly_provided_dests(
            parser,
            ["--config-file", "guard", "scan", "--control-identifier", "x"],
        )

        assert "control_identifier" in provided


class TestAbbreviationDisabled:
    """main() sets allow_abbrev=False so prefix abbreviations are rejected, which
    keeps explicit-flag detection exact (an abbreviation would otherwise slip past
    the full-option-string match in explicitly_provided_dests)."""

    def test_abbreviated_flag_is_rejected(self):
        parser = _build_parser()
        # --verb is an unambiguous prefix of --verbose but must NOT be accepted.
        with pytest.raises(SystemExit):
            parser.parse_args(["scan", "--verb"])

    def test_full_flag_still_works(self):
        parser = _build_parser()
        assert parser.parse_args(["scan", "--verbose"]).verbose is True

    def test_config_merge_respects_explicit_full_flag(self, tmp_path):
        # With the full flag, the CLI value wins over YAML (regression guard for the
        # abbreviation gap: the merge must see verbose as explicitly provided).
        path = _write_yaml(tmp_path, "verbose: false\n")
        argv = ["scan", "--config-file", path, "--verbose"]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.verbose is True


class TestControlServersFromConfig:
    def test_builds_with_headers_mapping(self):
        raw = [{"url": "https://s1.com", "identifier": "user1", "headers": {"Auth": "token1"}}]
        assert control_servers_from_config(raw) == [
            ControlServer(url="https://s1.com", headers={"Auth": "token1"}, identifier="user1")
        ]

    def test_builds_with_headers_list(self):
        raw = [{"url": "https://s1.com", "identifier": "user1", "headers": ["Auth: token1"]}]
        assert control_servers_from_config(raw) == [
            ControlServer(url="https://s1.com", headers={"Auth": " token1"}, identifier="user1")
        ]

    def test_missing_identifier_exits_2(self):
        # Config path emits a concise message and exits 2 (no traceback).
        with pytest.raises(SystemExit) as exc:
            control_servers_from_config([{"url": "https://s1.com"}])
        assert exc.value.code == 2

    def test_non_list_exits_2(self):
        with pytest.raises(SystemExit) as exc:
            control_servers_from_config({"url": "https://s1.com"})
        assert exc.value.code == 2

    def test_entry_not_mapping_exits_2(self):
        with pytest.raises(SystemExit) as exc:
            control_servers_from_config(["not-a-mapping"])
        assert exc.value.code == 2

    def test_missing_url_exits_2(self):
        with pytest.raises(SystemExit) as exc:
            control_servers_from_config([{"identifier": "user1"}])
        assert exc.value.code == 2

    def test_invalid_header_string_exits_2(self):
        with pytest.raises(SystemExit) as exc:
            control_servers_from_config([{"url": "https://s1.com", "identifier": "u", "headers": ["no-colon"]}])
        assert exc.value.code == 2

    def test_headers_wrong_type_exits_2(self):
        with pytest.raises(SystemExit) as exc:
            control_servers_from_config([{"url": "https://s1.com", "identifier": "u", "headers": 42}])
        assert exc.value.code == 2

    def test_non_string_identifier_exits_2(self):
        # Pydantic rejects an int identifier; surface it as a clean exit 2.
        with pytest.raises(SystemExit) as exc:
            control_servers_from_config([{"url": "https://s1.com", "identifier": 123}])
        assert exc.value.code == 2


class TestApplyConfigFileNoOp:
    def test_no_config_file_leaves_args_untouched(self):
        parser, args = _parse(["scan", "--server-timeout", "7"])
        before = vars(args).copy()
        apply_config_file(parser, args, ["scan", "--server-timeout", "7"])
        assert vars(args) == before

    def test_config_file_absent_keeps_defaults(self):
        parser, args = _parse(["scan"])
        apply_config_file(parser, args, ["scan"])
        assert args.server_timeout == 10  # code default preserved
        assert args.skills is True


class TestApplyConfigFileScalars:
    def test_yaml_value_fills_unpassed_flag(self, tmp_path):
        path = _write_yaml(tmp_path, "server_timeout: 30\nanalysis_url: https://yaml.example/api\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.server_timeout == 30
        assert args.analysis_url == "https://yaml.example/api"

    def test_explicit_cli_flag_overrides_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, "server_timeout: 30\n")
        argv = ["scan", "--config-file", path, "--server-timeout", "5"]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.server_timeout == 5  # CLI wins over YAML

    def test_store_true_can_be_enabled_from_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, "verbose: true\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.verbose is True

    def test_boolean_optional_no_flag_overrides_yaml(self, tmp_path):
        # YAML enables skills, CLI --no-skills must win.
        path = _write_yaml(tmp_path, "skills: true\n")
        argv = ["scan", "--config-file", path, "--no-skills"]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.skills is False

    def test_hyphenated_yaml_keys_accepted(self, tmp_path):
        path = _write_yaml(tmp_path, "server-timeout: 42\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.server_timeout == 42

    def test_unknown_key_is_ignored(self, tmp_path, capsys):
        path = _write_yaml(tmp_path, "not_a_real_flag: 1\nserver_timeout: 15\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.server_timeout == 15
        assert "not_a_real_flag" in capsys.readouterr().err

    def test_null_yaml_value_keeps_code_default_not_stringified(self, tmp_path):
        # A key with no value (``analysis_url:``) parses as YAML null. It must
        # be treated like the key was omitted (code default kept), not run
        # through str() into the literal string "None".
        path = _write_yaml(tmp_path, "analysis_url:\nserver_timeout: 15\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.analysis_url == "https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10"
        assert args.server_timeout == 15


class TestApplyConfigFileControlServers:
    _YAML = (
        "control_servers:\n"
        "  - url: https://yaml-server.com\n"
        "    identifier: yaml-user\n"
        "    headers:\n"
        "      Auth: yaml-token\n"
    )

    def test_control_servers_loaded_from_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, self._YAML)
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.control_servers == [
            ControlServer(url="https://yaml-server.com", headers={"Auth": "yaml-token"}, identifier="yaml-user")
        ]

    def test_null_control_servers_key_is_ignored(self, tmp_path):
        # ``control_servers:`` with no value parses as YAML null; it must be
        # treated like the key was omitted rather than raising a "must be a
        # list" error.
        path = _write_yaml(tmp_path, "control_servers:\nserver_timeout: 15\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.control_servers == []
        assert args.server_timeout == 15

    def test_cli_control_server_replaces_yaml_completely(self, tmp_path):
        # Passing any control-server block flag wipes the YAML array entirely.
        path = _write_yaml(tmp_path, self._YAML)
        argv = [
            "scan",
            "--config-file",
            path,
            "--control-server",
            "https://cli-server.com",
            "--control-identifier",
            "cli-user",
        ]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.control_servers == [ControlServer(url="https://cli-server.com", headers={}, identifier="cli-user")]
        # The YAML server must be gone — no element-wise merge.
        assert all(cs.url != "https://yaml-server.com" for cs in args.control_servers)


class TestApplyConfigFileRepeatableHeaders:
    """--verification-H is a repeatable (append) array: same complete-replacement
    rule as control_servers — passing it on the CLI discards the YAML list."""

    _YAML = 'verification_H:\n  - "X-From-Yaml: a"\n  - "X-Second: b"\n'

    def test_verification_headers_loaded_from_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, self._YAML)
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.verification_H == ["X-From-Yaml: a", "X-Second: b"]

    def test_cli_header_replaces_yaml_completely(self, tmp_path):
        # A single --verification-H on the CLI wipes the whole YAML array; no merge.
        path = _write_yaml(tmp_path, self._YAML)
        argv = ["scan", "--config-file", path, "--verification-H", "X-From-Cli: only"]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.verification_H == ["X-From-Cli: only"]
        assert all("Yaml" not in h for h in args.verification_H)


def _action(parser: argparse.ArgumentParser, dest: str):
    return {a.dest: a for a in parser._actions}[dest]


class TestConfigValueCoercion:
    """apply_config_file must validate/convert YAML values the way argparse would,
    rather than a raw setattr — type converters, choices, and scalar-vs-list shape."""

    # --- The reported bug: a stringy boolean must not be silently truthy. ---
    def test_boolean_flag_string_false_normalized(self, tmp_path):
        # skip_ssl_verify is store_true; "false" must become the bool False.
        path = _write_yaml(tmp_path, 'skip_ssl_verify: "false"\n')
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.skip_ssl_verify is False

    def test_boolean_flag_native_bool_kept(self, tmp_path):
        path = _write_yaml(tmp_path, "skip_ssl_verify: true\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.skip_ssl_verify is True

    def test_boolean_flag_rejects_non_bool_non_str(self, tmp_path):
        # A list is neither a bool nor a stringy bool → exit 2.
        path = _write_yaml(tmp_path, "skip_ssl_verify:\n  - 1\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        with pytest.raises(SystemExit) as exc:
            apply_config_file(parser, args, argv)
        assert exc.value.code == 2

    # --- Scalar type conversion via action.type (e.g. str2bool, float). ---
    def test_scalar_str2bool_type_applied_to_string(self, tmp_path):
        # suppress_mcpserver_io uses type=str2bool; "false" → False.
        path = _write_yaml(tmp_path, 'suppress_mcpserver_io: "false"\n')
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.suppress_mcpserver_io is False

    def test_scalar_numeric_string_converted(self, tmp_path):
        path = _write_yaml(tmp_path, 'server_timeout: "30"\n')
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.server_timeout == 30.0
        assert isinstance(args.server_timeout, float)

    def test_scalar_invalid_conversion_exits_2(self, tmp_path):
        path = _write_yaml(tmp_path, 'server_timeout: "not-a-number"\n')
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        with pytest.raises(SystemExit) as exc:
            apply_config_file(parser, args, argv)
        assert exc.value.code == 2

    def test_scalar_rejects_collection_shape(self, tmp_path):
        # analysis_url is scalar; a list is a shape mismatch → exit 2.
        path = _write_yaml(tmp_path, "analysis_url:\n  - https://a\n  - https://b\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        with pytest.raises(SystemExit) as exc:
            apply_config_file(parser, args, argv)
        assert exc.value.code == 2

    # --- List-shaped options require a list (a lone scalar is wrapped). ---
    def test_list_scalar_wrapped(self, tmp_path):
        path = _write_yaml(tmp_path, 'verification_H: "X-One: 1"\n')
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.verification_H == ["X-One: 1"]

    def test_list_rejects_mapping(self, tmp_path):
        path = _write_yaml(tmp_path, "verification_H:\n  a: b\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        with pytest.raises(SystemExit) as exc:
            apply_config_file(parser, args, argv)
        assert exc.value.code == 2

    def test_positional_files_rejects_mapping(self, tmp_path):
        path = _write_yaml(tmp_path, "files:\n  a: b\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        with pytest.raises(SystemExit) as exc:
            apply_config_file(parser, args, argv)
        assert exc.value.code == 2

    def test_non_string_yaml_key_exits_2(self, tmp_path):
        # YAML permits non-string keys (e.g. `123:`); reject cleanly, don't crash.
        path = _write_yaml(tmp_path, "123: true\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        with pytest.raises(SystemExit) as exc:
            apply_config_file(parser, args, argv)
        assert exc.value.code == 2

    # --- choices membership is enforced (uses a purpose-built action). ---
    def test_choices_enforced(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--mode", choices=["a", "b"])
        action = _action(parser, "mode")
        assert _coerce_config_value(action, "mode", "a") == "a"
        with pytest.raises(SystemExit) as exc:
            _coerce_config_value(action, "mode", "c")
        assert exc.value.code == 2


class TestApplyConfigFileFiles:
    def test_files_loaded_from_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, "files:\n  - /a/config.json\n  - /b/config.json\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.files == ["/a/config.json", "/b/config.json"]

    def test_cli_positional_files_replace_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, "files:\n  - /a/config.json\n")
        argv = ["scan", "/cli/config.json", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.files == ["/cli/config.json"]


class TestApplyConfigFilePushKeyAndMachineId:
    """--push-key / --machine-id (v0.6+) are ordinary scalar options, so they
    are settable from the config file through the same generic mechanism as
    any other flag (see TestApplyConfigFileScalars)."""

    def test_push_key_and_machine_id_loaded_from_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, "push_key: yaml-push-key\nmachine_id: yaml-machine-id\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.push_key == "yaml-push-key"
        assert args.machine_id == "yaml-machine-id"

    def test_explicit_cli_push_key_overrides_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, "push_key: yaml-push-key\n")
        argv = ["scan", "--config-file", path, "--push-key", "cli-push-key"]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.push_key == "cli-push-key"

    def test_explicit_cli_machine_id_overrides_yaml(self, tmp_path):
        path = _write_yaml(tmp_path, "machine_id: yaml-machine-id\n")
        argv = ["scan", "--config-file", path, "--machine-id", "cli-machine-id"]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.machine_id == "cli-machine-id"

    def test_numeric_push_key_coerced_to_string(self, tmp_path):
        # A bare numeric YAML scalar must be normalized to str, matching what
        # a real CLI invocation would receive (argv tokens are always strings).
        path = _write_yaml(tmp_path, "push_key: 12345\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.push_key == "12345"
        assert isinstance(args.push_key, str)

    def test_numeric_machine_id_coerced_to_string(self, tmp_path):
        path = _write_yaml(tmp_path, "machine_id: 12345\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.machine_id == "12345"
        assert isinstance(args.machine_id, str)

    def test_empty_string_push_key_from_yaml_preserved(self, tmp_path):
        path = _write_yaml(tmp_path, 'push_key: ""\n')
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.push_key == ""

    def test_null_push_key_and_machine_id_kept_as_none_not_stringified(self, tmp_path):
        # A key written with no value (``push_key:``) parses as YAML null
        # (Python None). It must be treated like the key was never in the
        # file -- keeping the code default of None -- rather than being run
        # through the str() type converter, which would otherwise produce
        # the literal string "None".
        path = _write_yaml(tmp_path, "push_key:\nmachine_id:\n")
        argv = ["scan", "--config-file", path]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.push_key is None
        assert args.machine_id is None


class TestConfigFilePushKeyPrecedenceOverLegacyFlags:
    """Unlike most flags, --push-key / --machine-id resolve against the
    *deprecated* --control-server-H / --control-identifier flags, not
    against their own CLI spelling (see cli._effective_push_key /
    _effective_identifier). This means the usual "CLI beats config file"
    rule does not hold across that old/new pair: a config-file push_key /
    machine_id wins even when the legacy flags are passed explicitly on the
    command line, because only an *explicit* --push-key / --machine-id (not
    the legacy flags) counts as an override.
    """

    def test_config_push_key_wins_over_legacy_cli_flags(self, tmp_path):
        path = _write_yaml(tmp_path, "push_key: config-push-key\n")
        argv = [
            "scan",
            "--config-file",
            path,
            "--control-server",
            "https://cli-server.com",
            "--control-server-H",
            "x-client-id: legacy-cli-key",
            "--control-identifier",
            "cli-user",
        ]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.push_key == "config-push-key"
        assert _effective_push_key(args) == "config-push-key"

    def test_config_machine_id_wins_over_legacy_cli_flag(self, tmp_path):
        path = _write_yaml(tmp_path, "machine_id: config-machine-id\n")
        argv = [
            "scan",
            "--config-file",
            path,
            "--control-server",
            "https://cli-server.com",
            "--control-identifier",
            "cli-user",
        ]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.machine_id == "config-machine-id"
        assert _effective_identifier(args) == "config-machine-id"

    def test_explicit_cli_push_key_still_wins_over_legacy_flags_and_config(self, tmp_path):
        # An *explicit* --push-key on the CLI is the one thing that legitimately
        # overrides both the config file and the legacy flags.
        path = _write_yaml(tmp_path, "push_key: config-push-key\n")
        argv = [
            "scan",
            "--config-file",
            path,
            "--control-server",
            "https://cli-server.com",
            "--control-server-H",
            "x-client-id: legacy-cli-key",
            "--control-identifier",
            "cli-user",
            "--push-key",
            "explicit-cli-push-key",
        ]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.push_key == "explicit-cli-push-key"
        assert _effective_push_key(args) == "explicit-cli-push-key"

    def test_no_config_push_key_still_falls_back_to_legacy_cli_header(self, tmp_path):
        # Sanity check: without a config-file push_key, legacy CLI flags
        # still work as before.
        path = _write_yaml(tmp_path, "server_timeout: 30\n")
        argv = [
            "scan",
            "--config-file",
            path,
            "--control-server",
            "https://cli-server.com",
            "--control-server-H",
            "x-client-id: legacy-cli-key",
            "--control-identifier",
            "cli-user",
        ]
        parser, args = _parse(argv)
        apply_config_file(parser, args, argv)
        assert args.push_key is None
        assert _effective_push_key(args) == " legacy-cli-key"
