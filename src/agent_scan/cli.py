# fix ssl certificates if custom certificates (i.e. ZScaler) are used
# as this needs to occur at the beginning of the file, we need to disable the ruff rule
# ruff: noqa: E402
from typing import Literal, NoReturn, cast

import truststore

truststore.inject_into_ssl()

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass

import psutil
import rich
import yaml
from pydantic import ValidationError
from rich.logging import RichHandler

from agent_scan.consent import collect_consent
from agent_scan.models import (
    FAILURE_CATEGORY_TO_CODE,
    ControlServer,
    InspectedPath,
    McpServerRiskIndexes,
    ScanResponse,
    SkillRiskIndexes,
    TokenAndClientInfo,
    TokenAndClientInfoList,
)
from agent_scan.pipelines import (
    AnalyzeArgs,
    InspectArgs,
    PushArgs,
    discover_clients_to_inspect,
    inspect_analyze_push_pipeline,
    inspect_pipeline,
)
from agent_scan.printer import print_inspected_machine, print_scan_response
from agent_scan.utils import ensure_unicode_console, get_hostname, get_push_key, parse_headers, suppress_stdout
from agent_scan.version import version_info

# Configure logging to suppress all output by default
logging.getLogger().setLevel(logging.CRITICAL + 1)  # Higher than any standard level
# Add null handler to prevent "No handler found" warnings
logging.getLogger().addHandler(logging.NullHandler())

CLI_USAGE_ERROR_EXIT_CODE = 2


class MissingIdentifierError(Exception):
    """Raised when a control server is missing an identifier."""

    pass


def setup_logging(verbose=False, log_to_stderr=False):
    """Configure logging based on the verbose flag."""
    if verbose:
        # Configure the root logger
        root_logger = logging.getLogger()
        # Remove any existing handlers (including the NullHandler)
        for hdlr in root_logger.handlers:
            root_logger.removeHandler(hdlr)
        # markup=False on both handlers: log messages carry arbitrary scanned
        # data (payloads, file paths, server output) that can contain "[...]"
        # which Rich would otherwise parse as console markup and raise
        # MarkupError. Intentional styling goes through rich.print, not logging.
        if log_to_stderr:
            # stderr logging
            stderr_console = rich.console.Console(stderr=True)
            logging.basicConfig(
                format="%(message)s",
                datefmt="[%X]",
                force=True,
                level=logging.DEBUG,
                handlers=[RichHandler(markup=False, rich_tracebacks=True, console=stderr_console)],
            )
            root_logger.debug("Verbose mode enabled, logging initialized to stderr")
        else:  # stdout logging
            logging.basicConfig(
                format="%(message)s",
                datefmt="[%X]",
                force=True,
                level=logging.DEBUG,
                handlers=[RichHandler(markup=False, rich_tracebacks=True)],
            )
            root_logger.debug("Logging initialized to stdout")
        root_logger.debug("Logging initialized")


def get_invoking_name():
    try:
        parent = psutil.Process().parent()
        cmd = parent.cmdline()
        argv = sys.argv[1:]
        # remove args that are in argv from cmd
        for i in range(len(argv)):
            if cmd[-1] == argv[-i]:
                cmd = cmd[:-1]
            else:
                break
        cmd = " ".join(cmd)
    except Exception:
        cmd = "agent-scan"
    return cmd


def str2bool(v: str) -> bool:
    return v.lower() in ("true", "1", "t", "y", "yes")


def _expand_equals_tokens(argv: list[str]) -> list[str]:
    """
    Expand ``--flag=value`` into ``--flag``, ``value`` for the control-server
    block flags so both spellings parse identically. The block parser below scans
    for bare flag tokens, so ``--control-server=https://x`` would otherwise be one
    token and silently yield no servers. Only the first ``=`` is split, preserving
    ``=`` inside URLs/headers (e.g. ``?version=2``).
    """
    control_flags = ("--control-server", "--control-server-H", "--control-identifier")
    expanded: list[str] = []
    for token in argv:
        if "=" in token and token.split("=", 1)[0] in control_flags:
            expanded.extend(token.split("=", 1))
        else:
            expanded.append(token)
    return expanded


def parse_control_servers(argv) -> list[ControlServer]:
    """
    Parse control server arguments from sys.argv.
    Returns a list of ControlServer instances.
    Raises MissingIdentifierError if any control server is missing an identifier.
    """
    argv = _expand_equals_tokens(argv)
    server_starts = [i for i, arg in enumerate(argv) if arg == "--control-server"]

    control_servers: list[ControlServer] = []
    for idx, start in enumerate(server_starts):
        end = server_starts[idx + 1] if idx + 1 < len(server_starts) else len(argv)
        block = argv[start:end]

        if len(block) < 2 or block[1].startswith("--"):
            continue

        url = block[1]
        headers: list[str] = []
        identifier: str | None = None

        i = 2
        while i < len(block):
            if block[i] == "--control-server-H" and i + 1 < len(block) and not block[i + 1].startswith("--"):
                headers.append(block[i + 1])
                i += 2
            elif block[i] == "--control-identifier" and i + 1 < len(block) and not block[i + 1].startswith("--"):
                identifier = block[i + 1]
                i += 2
            else:
                i += 1

        if identifier is None:
            rich.print(f"[bold red]Control server {url} is missing a --control-identifier[/bold red]")
            raise MissingIdentifierError(f"Control server {url} is missing a --control-identifier")

        control_servers.append(
            ControlServer(
                url=url,
                headers=parse_headers(headers),
                identifier=identifier,
            )
        )

    return control_servers


def _warn_deprecated_flag(flag_name: str, replacement: str) -> None:
    rich.print(
        f"[yellow]Warning: {flag_name} is deprecated and will be removed in a future release. "
        f"Use {replacement} instead.[/yellow]",
        file=sys.stderr,
    )


def warn_deprecated_control_flags(args) -> None:
    """Warn once per invocation for each deprecated control-server flag used.

    --control-server-H is a generic "additional header" flag, so it only
    warns when it's actually carrying the x-client-id push-key trick, not
    when it's used for an unrelated custom header. --control-identifier
    warns on any use, even though --machine-id can only hold a single value
    and can't represent the distinct identifiers a multi-control-server
    setup requires — the warning still nudges toward the replacement for
    the common single-server case.
    """
    raw_headers = getattr(args, "control_server_H", None)
    if raw_headers:
        try:
            headers = parse_headers(raw_headers)
        except ValueError:
            headers = {}
        if any("x-client-id" in header.lower() for header in headers):
            _warn_deprecated_flag("--control-server-H", "--push-key")

    if getattr(args, "control_identifier", None):
        _warn_deprecated_flag("--control-identifier", "--machine-id")


# Option strings that make up a single control-server block. Passing any of
# them on the CLI triggers complete replacement of the config-file's
# ``control_servers`` list (see apply_config_file).
_CONTROL_SERVER_DESTS = ("control_server", "control_server_H", "control_identifier")


def _iter_all_actions(parser: argparse.ArgumentParser):
    """Yield every argparse action reachable from ``parser``, descending into subparsers."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for subparser in action.choices.values():
                yield from _iter_all_actions(subparser)
        else:
            yield action


def explicitly_provided_dests(parser: argparse.ArgumentParser, argv: list[str]) -> set[str]:
    """
    Return the set of argument ``dest`` names the user passed explicitly on the
    command line.

    We inspect the raw ``argv`` rather than the parsed namespace because argparse
    cannot distinguish "flag omitted" (dest holds its default) from "flag passed
    with a value equal to its default". Both ``--flag value`` and ``--flag=value``
    spellings are recognized, as are the two option strings of a
    BooleanOptionalAction (``--skills`` / ``--no-skills`` both map to ``skills``).
    """
    option_to_dest: dict[str, str] = {}
    for action in _iter_all_actions(parser):
        for option in action.option_strings:
            option_to_dest[option] = action.dest

    provided: set[str] = set()
    for token in argv:
        option = token.split("=", 1)[0]
        dest = option_to_dest.get(option)
        if dest is not None:
            provided.add(dest)
    return provided


def _fail_config(message: str) -> NoReturn:
    """Print a config-file error to stderr and exit with the CLI's usage code."""
    rich.print(f"[bold red]{message}[/bold red]", file=sys.stderr)
    sys.exit(2)


def load_config_file(path: str) -> dict:
    """Read a YAML config file into a mapping. Exits with code 2 on any error."""
    expanded = os.path.expanduser(path)
    try:
        with open(expanded) as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        _fail_config(f"Config file not found: {path}")
    except OSError as e:
        _fail_config(f"Could not read config file {path}: {e}")
    except yaml.YAMLError as e:
        _fail_config(f"Invalid YAML in config file {path}: {e}")

    if data is None:  # empty file
        return {}
    if not isinstance(data, dict):
        _fail_config(f"Config file {path} must contain a YAML mapping at the top level.")
    return data


def control_servers_from_config(raw) -> list[ControlServer]:
    """
    Build ControlServer instances from the config file's ``control_servers`` block.

    Each entry is a mapping with ``url``, ``identifier``, and optional ``headers``.
    Headers may be given as a mapping (``{name: value}``) or as a list of
    ``"Name: value"`` strings (matching the ``--control-server-H`` CLI form).
    """
    if not isinstance(raw, list):
        _fail_config("Invalid config file: 'control_servers' must be a list.")

    control_servers: list[ControlServer] = []
    for entry in raw:
        if not isinstance(entry, dict):
            _fail_config("Invalid config file: each 'control_servers' entry must be a mapping.")
        url = entry.get("url")
        identifier = entry.get("identifier")
        raw_headers = entry.get("headers") or {}

        if not url or not isinstance(url, str):
            _fail_config("Invalid config file: a 'control_servers' entry is missing a string 'url'.")
        if identifier is None:
            _fail_config(f"Invalid config file: control server '{url}' is missing an 'identifier'.")

        # Headers may be a mapping ({name: value}) or a list of "Name: value"
        # strings (matching the --control-server-H CLI form).
        if isinstance(raw_headers, dict):
            headers = raw_headers
        elif isinstance(raw_headers, list):
            try:
                headers = parse_headers(raw_headers)
            except ValueError as exc:
                _fail_config(f"Invalid config file: control server '{url}' has an invalid header ({exc}).")
        else:
            _fail_config(
                f"Invalid config file: control server '{url}' 'headers' must be a mapping "
                "or a list of 'Name: value' strings."
            )

        try:
            control_servers.append(ControlServer(url=url, headers=headers, identifier=identifier))
        except ValidationError as exc:
            detail = exc.errors()[0].get("msg", "invalid value") if exc.errors() else "invalid value"
            _fail_config(f"Invalid config file: control server '{url}' is invalid ({detail}).")

    return control_servers


def _convert_config_scalar(action: argparse.Action, raw_key: str, value: object) -> object:
    """
    Apply the action's ``type`` converter to a single YAML scalar and enforce
    ``choices`` — the same validation argparse would run on a CLI token.

    ``type`` converters (e.g. ``str2bool``, ``int``, ``float``, ``str``) always
    receive a string on the CLI (argv tokens are strings), so we stringify a
    non-string YAML value (e.g. ``push_key: 12345``, ``server_timeout: 30``)
    before converting, rather than only converting when YAML already handed us
    a string. This is a generic, type-agnostic rule that applies to every
    scalar flag: it normalizes a numeric YAML value into the flag's real type
    (``str`` for a string flag, ``float`` for ``server_timeout``, etc.)
    instead of silently keeping the mismatched native YAML type. Exits with
    code 2 on a failed conversion or an out-of-choices value.
    """
    converted = value
    # argparse's ``type`` may be a registered type name (str) rather than a
    # callable; guard with callable() so we only invoke real converters.
    if callable(action.type):
        try:
            converted = action.type(value) if isinstance(value, str) else action.type(str(value))
        except (ValueError, TypeError) as exc:
            _fail_config(f"Invalid config file: '{raw_key}' has an invalid value {value!r} ({exc}).")
    if action.choices is not None and converted not in action.choices:
        allowed = ", ".join(str(c) for c in action.choices)
        _fail_config(f"Invalid config file: '{raw_key}' must be one of: {allowed}.")
    return converted


def _coerce_config_value(action: argparse.Action, raw_key: str, value: object) -> object:
    """
    Validate/convert a YAML value so it behaves like the equivalent CLI flag,
    reusing argparse's expectations rather than a raw ``setattr``.

    - Boolean flags (``store_true``/``store_false``/``BooleanOptionalAction``,
      i.e. ``nargs == 0``): require a ``bool``, or a string normalized via
      ``str2bool``; anything else is rejected. This stops values like
      ``skip_ssl_verify: "false"`` from being silently truthy.
    - List-shaped options (``append`` actions and ``nargs`` ``*``/``+`` such as
      ``verification_H`` and the positional ``files``): require a list; a lone
      scalar is wrapped into a one-element list; each element is type-converted.
    - Plain scalars: reject collections (shape mismatch), then type-convert and
      choice-check.

    Exits with code 2 via ``_fail_config`` on any type/shape violation.
    """
    # store_true / store_false / BooleanOptionalAction consume no argument.
    if action.nargs == 0:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return str2bool(value)
        _fail_config(f"Invalid config file: '{raw_key}' must be a boolean.")

    # append options and nargs '*'/'+' are list-shaped.
    if isinstance(action, argparse._AppendAction) or action.nargs in ("*", "+"):
        if isinstance(value, list):
            items: list = value
        elif isinstance(value, str | int | float | bool):
            items = [value]  # accept a lone scalar as a single-element list
        else:
            _fail_config(f"Invalid config file: '{raw_key}' must be a list.")
        return [_convert_config_scalar(action, raw_key, item) for item in items]

    # Plain scalar option.
    if isinstance(value, list | dict):
        _fail_config(f"Invalid config file: '{raw_key}' must be a single value, not a {type(value).__name__}.")
    return _convert_config_scalar(action, raw_key, value)


def apply_config_file(parser: argparse.ArgumentParser, args: argparse.Namespace, argv: list[str]) -> None:
    """
    Merge values from ``args.config_file`` into ``args``.

    Precedence cascade: code defaults < YAML config file < explicit CLI flags.
    Scalar options are overridden field-by-field. Block/list options
    (``control_servers``, append lists, and the positional ``files``) use
    *complete replacement*: if the user supplied the corresponding flag on the
    command line, the whole YAML value for that key is discarded rather than
    merged element-wise.

    No-op when ``--config-file`` was not supplied, preserving current behavior.
    """
    config_path = getattr(args, "config_file", None)
    if not config_path:
        return

    config = load_config_file(config_path)
    explicit = explicitly_provided_dests(parser, argv)

    # The positional ``files`` list has no option string, so treat any positional
    # value present on the CLI as an explicit override of the YAML ``files``.
    if getattr(args, "files", None):
        explicit.add("files")

    dest_to_action = {a.dest: a for a in _iter_all_actions(parser)}
    valid_dests = {dest for dest in dest_to_action if dest not in (argparse.SUPPRESS, "help")}

    # control_servers is assembled outside argparse (see parse_control_servers),
    # so it is handled here with complete-replacement semantics.
    if config.get("control_servers") is not None and not any(dest in explicit for dest in _CONTROL_SERVER_DESTS):
        args.control_servers = control_servers_from_config(config["control_servers"])

    # For every remaining key the rule is uniform: an explicit CLI flag wins,
    # otherwise the config value is applied. This yields field-level override for
    # scalars and *complete replacement* for repeatable/list args (e.g. the
    # ``append`` flag ``--verification-H``): argparse hands us the whole CLI list
    # as one value, so we take either the entire CLI list or the entire YAML
    # list, never a per-element merge — the same semantics used for
    # ``control_servers`` above.
    for raw_key, value in config.items():
        # YAML allows non-string keys (e.g. ``true:`` or ``1:``); reject them
        # cleanly instead of crashing on ``.replace``.
        if not isinstance(raw_key, str):
            _fail_config(f"Invalid config file: keys must be strings, got {raw_key!r}.")
        key = raw_key.replace("-", "_")
        if key in ("control_servers", "config_file"):
            continue  # handled above / self-reference
        if key in _CONTROL_SERVER_DESTS:
            continue  # control servers come from the 'control_servers' block only
        if key not in valid_dests:
            rich.print(f"[yellow]Ignoring unknown key '{raw_key}' in config file.[/yellow]", file=sys.stderr)
            continue
        if key in explicit:
            continue  # explicit CLI flag wins over the config file (whole value)
        if value is None:
            # A key written with no value (``push_key:``) parses as YAML/Python
            # ``None``. Treat that the same as the key being absent entirely
            # (keep the code default / CLI-derived value) rather than running
            # it through the type converter, which would otherwise stringify
            # it into the literal text "None".
            continue
        # Validate/convert exactly as argparse would for the equivalent CLI flag
        # (type converters, choices, scalar-vs-list shape) before assigning.
        setattr(args, key, _coerce_config_value(dest_to_action[key], raw_key, value))


def add_common_arguments(parser):
    """Add arguments that are common to multiple commands."""
    parser.add_argument(
        "--storage-file",
        type=str,
        default="~/.mcp-scan",
        help="Path to store scan results and scanner state",
        metavar="FILE",
    )
    parser.add_argument(
        "--analysis-url",
        type=str,
        default="https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10",
        help="URL endpoint for the verification server; Agent Scan always uses the 2026-07-10 API version",
        metavar="URL",
    )
    parser.add_argument(
        "--verification-H",
        action="append",
        help="Additional headers for the verification server",
    )
    parser.add_argument(
        "--mcp-oauth-tokens-path",
        type=str,
        help="Path of the file where the MCP OAuth tokens are stored.",
    )
    parser.add_argument(
        "--verbose",
        default=False,
        action="store_true",
        help="Enable detailed logging output",
    )
    parser.add_argument(
        "--print-errors",
        default=False,
        action="store_true",
        help="Show error details and tracebacks",
    )
    parser.add_argument(
        "--print-full-descriptions",
        default=False,
        action="store_true",
        help="Show full entity and skill-file descriptions without truncation",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results in JSON format instead of rich text",
    )
    parser.add_argument(
        "--skip-ssl-verify",
        default=False,
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--skills",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Scan skills beyond mcp servers (default: enabled). Use --no-skills to disable.",
    )
    add_bootstrap_argument(parser)
    parser.add_argument(
        "--scan-all-users",
        default=False,
        action="store_true",
        help="Scan all users on the machine.",
    )
    parser.add_argument(
        "--show-analysis-results",
        action="store_true",
        default=False,
        help="Show the scan results. Overrides the default behavior when using push keys.",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        default=False,
        help="Exit with a non-zero code when there are analysis findings or runtime failures. Requires --dangerously-run-mcp-servers.",
    )
    parser.add_argument(
        "--config-file",
        type=str,
        default=None,
        help=(
            "Load CLI arguments from a YAML config file. Precedence is "
            "code defaults < config file < explicit CLI flags: any flag you also "
            "pass on the command line overrides the file."
        ),
        metavar="FILE",
    )


def add_bootstrap_argument(parser):
    parser.add_argument(
        "--no-bootstrap",
        default=False,
        action="store_true",
        help="No-op retained for backward compatibility; does not change behavior.",
    )


def add_server_arguments(parser):
    """Add arguments related to MCP server connections."""
    server_group = parser.add_argument_group("MCP Server Options")
    server_group.add_argument(
        "--server-timeout",
        type=float,
        default=10,
        help="Seconds to wait before timing out server connections (default: 10)",
        metavar="SECONDS",
    )
    # Only stdio MCP server stderr is relayed; stdout is reserved for the
    # JSON-RPC protocol and is always consumed by the MCP client, never shown.
    # Default is None so we can distinguish three cases:
    #   1. None  -> unset. resolve_server_io_default() picks based on
    #               interactivity of the command.
    #   2. True  -> explicit override to silence MCP server stderr.
    #   3. False -> explicit override to stream MCP server stderr.
    server_group.add_argument(
        "--suppress-mcpserver-io",
        default=None,
        type=str2bool,
        help=(
            "Suppress stderr from stdio MCP servers (stdout carries the "
            "JSON-RPC protocol and is never shown). "
            "Default: False for interactive runs (stderr is streamed with a "
            "[server-name] prefix), True otherwise."
        ),
        metavar="BOOL",
    )
    server_group.add_argument(
        "--dangerously-run-mcp-servers",
        default=False,
        action="store_true",
        help=("Skip the interactive consent prompt and start every stdio MCP server listed in the scanned configs."),
    )


def add_control_server_arguments(parser):
    parser.add_argument(
        "--control-server",
        action="append",
        help=(
            "Upload scan results to this control server URL. "
            "Must be paired with a --control-identifier for that same server block. "
            "Can be specified multiple times."
        ),
    )
    parser.add_argument(
        "--control-server-H",
        action="append",
        help="Additional header for the current --control-server block (repeatable)",
    )
    parser.add_argument(
        "--control-identifier",
        action="append",
        help=(
            "Required per --control-server block. "
            "Non-anonymous identifier for that control server (for example: email, hostname, serial number)."
        ),
    )
    parser.add_argument(
        "--push-key",
        type=str,
        default=None,
        help="Push key used to authenticate with the analysis server.",
        metavar="KEY",
    )
    parser.add_argument(
        "--machine-id",
        type=str,
        default=None,
        help="Non-anonymous identifier for this machine (for example: hostname, serial number). ",
        metavar="ID",
    )


def add_scan_arguments(scan_parser):
    scan_parser.add_argument(
        "--checks-per-server",
        type=int,
        default=1,
        help="No-op retained for backward compatibility; does not change behavior.",
        metavar="NUM",
    )
    add_control_server_arguments(scan_parser)


def add_ignore_failure_codes_argument(parser) -> None:
    parser.add_argument(
        "--ignore-failure-codes",
        type=str,
        default=None,
        help="Comma-separated X-codes to omit from --ci exit evaluation",
    )


def setup_scan_parser(scan_parser, add_files=True, add_ci_ignore_options=True, add_show_full_discovery_option=True):
    if add_files:
        scan_parser.add_argument(
            "files",
            nargs="*",
            default=[],
            help="Path(s) to MCP config file(s). If not provided, well-known paths will be checked",
            metavar="CONFIG_FILE",
        )
    add_common_arguments(scan_parser)
    if add_ci_ignore_options:
        scan_parser.add_argument(
            "--ignore-risks",
            type=str,
            default=None,
            help="Comma-separated risk names to omit from --ci output and exit evaluation",
        )
        add_ignore_failure_codes_argument(scan_parser)
    if add_show_full_discovery_option:
        scan_parser.add_argument(
            "--show-full-discovery",
            action="store_true",
            default=False,
            help="Show every MCP entity and skill file in human-readable scan output",
        )
    add_server_arguments(scan_parser)
    add_scan_arguments(scan_parser)


def _effective_push_key(args) -> str | None:
    """Push key from --push-key, falling back to the deprecated --control-server-H
    x-client-id header.

    On evo, an externally-supplied --push-key is ignored: evo always
    authenticates with the one-time key it mints and injects into
    args.control_servers, so an outside value must never silently replace
    it (both before minting, where it would wrongly suppress the upfront
    tenant/token prompts, and after, where it would wrongly override the
    minted key).
    """
    if getattr(args, "command", None) != "evo":
        push_key = getattr(args, "push_key", None)
        if push_key is not None:
            return push_key
    return get_push_key(getattr(args, "control_servers", []) or [])


def _effective_identifier(args) -> str | None:
    """Machine identifier from --machine-id, falling back to the deprecated
    --control-identifier on the first control-server block."""
    machine_id = getattr(args, "machine_id", None)
    if machine_id is not None:
        return machine_id
    control_servers = getattr(args, "control_servers", None) or []
    return next((s.identifier for s in control_servers), None)


def is_interactive_run(args) -> bool:
    """
    True when the run is a manual, interactive invocation by a human who can
    answer yes or no consent prompts.
    """
    command = getattr(args, "command", None)
    if command == "inspect":
        return True
    # If the scan is run with a push key, skip consent prompts.
    has_push_key = bool(_effective_push_key(args))
    return not has_push_key


@dataclass(frozen=True)
class HandshakeDecision:
    # Whether to start stdio MCP server subprocesses to read their
    # tool / prompt / resource catalogs.
    do_stdio_handshake: bool
    # Whether to run the interactive per-server y/n consent prompt
    # before any subprocess is started.
    collect_consent: bool


def decide_handshake(args) -> HandshakeDecision:
    """
    Command logic for stdio handshake + interactive consent.

        command       push_key  --dangerously  do_stdio_handshake  collect_consent
        ------------  --------  -------------  ------------------  ---------------
        inspect       N/A       no             True                True
        inspect       N/A       yes            True                False
        scan / None   no        no             True                True
        scan / None   no        yes            True                False
        scan / None   yes       no             False               False
        scan / None   yes       yes            True                False
        evo / other   any       no             False               False
        evo / other   any       yes            True                False
    """
    command = getattr(args, "command", None)
    dangerously_run_mcp_servers = bool(getattr(args, "dangerously_run_mcp_servers", False))

    # 1. Explicit user opt-in via --dangerously-run-mcp-servers. Spawn
    # every stdio MCP server and skip consent.
    if dangerously_run_mcp_servers:
        return HandshakeDecision(do_stdio_handshake=True, collect_consent=False)

    # 2. Attended scan - handshake and prompt for per-server consent.
    # inspect always qualifies.
    # scan / no-subcommand qualifies when there is no push key.
    is_attended_scan = command == "inspect" or (
        (command is None or command == "scan") and not bool(_effective_push_key(args))
    )
    if is_attended_scan:
        return HandshakeDecision(do_stdio_handshake=True, collect_consent=True)

    # 3. Default - unattended (push-key scan, evo, or any
    # future subcommand).
    # Safe default — no handshake, no consent.
    return HandshakeDecision(do_stdio_handshake=False, collect_consent=False)


def _print_dangerous_warning(suppress_io: bool) -> None:
    """Print the dangerous-flag banner. Tip is only relevant when stderr
    is actually being streamed (suppress_io=False)."""
    message = (
        "[bold red]--dangerously-run-mcp-servers is set: starting every "
        "stdio MCP server listed in the scanned configs without "
        "prompting.[/bold red]\n"
    )
    if not suppress_io:
        message += "Tip: set --suppress-mcpserver-io=true to hide server stderr output.\n"
    rich.print(message)


def resolve_server_io_default(args) -> None:
    """
    Fill in a value for --suppress-mcpserver-io when the user didn't pass
    it explicitly: False for interactive runs, else True.
    """
    if getattr(args, "suppress_mcpserver_io", None) is None:
        args.suppress_mcpserver_io = not is_interactive_run(args)


def enforce_consent_requirements(args) -> None:
    """
    --ci must opt into starting subprocesses explicitly, because CI runs
    cannot answer the interactive per-server consent prompt.
    """
    dangerously_run_mcp_servers = getattr(args, "dangerously_run_mcp_servers", False)
    ci_mode = getattr(args, "ci", False)

    if ci_mode and not dangerously_run_mcp_servers:
        rich.print(
            "[bold red]Running with --ci requires --dangerously-run-mcp-servers.[/bold red]\n"
            "Agent Scan starts subprocesses for every stdio MCP server it "
            "scans, so CI runs must confirm trust explicitly.",
            file=sys.stderr,
        )
        sys.exit(CLI_USAGE_ERROR_EXIT_CODE)


def main():
    ensure_unicode_console()
    # Create main parser with description
    program_name = get_invoking_name()
    parser = argparse.ArgumentParser(
        prog=program_name,
        # Disable prefix abbreviation (argparse defaults it on). Abbreviations
        # are undocumented, and the config-file merge detects explicitly-passed
        # flags by matching full option strings in argv (see
        # explicitly_provided_dests) — an abbreviation like ``--verb`` would slip
        # past that check. allow_abbrev is per-parser and does not inherit, so it
        # is set again on each subparser below.
        allow_abbrev=False,
        description="Snyk Agent Scan: Security scanner for Model Context Protocol servers, agents, skills and tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            f"  {program_name}                      # Scan all known MCP configs\n"
            f"  {program_name} ~/custom/config.json # Scan a specific config file\n"
            f"  {program_name} inspect              # Just inspect tools without verification\n"
            f"  {program_name} --no-skills          # Scan only mcp servers, skip skills.\n"
            f"  {program_name} --verbose            # Enable detailed logging output\n"
            f"  {program_name} --print-errors       # Show error details and tracebacks\n"
            f"  {program_name} --json               # Output results in JSON format\n"
            f"  {program_name} --ci                 # With --ci, exit with a non-zero code when there are analysis findings or runtime failures\n\n"
            f"  # Multiple control servers with individual options:\n"
            f'  {program_name} --control-server https://server1.com --control-server-H "Auth: token1" \\\n'
            f"    --control-identifier user@example.com \\\n"
            f'    --control-server https://server2.com --control-server-H "Auth: token2" \\\n'
            f"    --control-identifier serial-123\n"
        ),
    )

    # Create subparsers for commands
    subparsers = parser.add_subparsers(
        dest="command",
        title="Commands",
        description="Available commands (default: scan)",
        metavar="COMMAND",
    )
    # SCAN command
    scan_parser = subparsers.add_parser(
        "scan",
        allow_abbrev=False,
        help="Scan one or more MCP config files [default]",
        description=(
            "Scan one or more MCP configuration files for security risks. "
            "If no files are specified, well-known config locations will be checked."
        ),
    )
    setup_scan_parser(scan_parser)

    # INSPECT command
    inspect_parser = subparsers.add_parser(
        "inspect",
        allow_abbrev=False,
        help="Print descriptions of tools, prompts, and resources without verification",
        description="Inspect and display MCP tools, prompts, and resources without security verification.",
    )
    add_common_arguments(inspect_parser)
    add_ignore_failure_codes_argument(inspect_parser)
    add_server_arguments(inspect_parser)
    add_control_server_arguments(inspect_parser)
    inspect_parser.add_argument(
        "files",
        type=str,
        nargs="*",
        default=[],
        help="Configuration files to inspect (default: known MCP config locations)",
        metavar="CONFIG_FILE",
    )

    # HELP command
    help_parser = subparsers.add_parser(  # noqa: F841
        "help",
        help="Show detailed help information",
        description="Display detailed help information and examples.",
    )

    # EVO command
    evo_parser = subparsers.add_parser("evo", allow_abbrev=False, help="Push scan results to Snyk Evo")

    # use the same parser as scan
    setup_scan_parser(evo_parser, add_ci_ignore_options=False, add_show_full_discovery_option=False)

    # MCP-AUTH command: interactively authenticate an OAuth-protected remote server
    mcp_auth_parser = subparsers.add_parser(
        "mcp-auth", help="Authenticate an OAuth-protected remote MCP server so scans can use it"
    )
    setup_scan_parser(mcp_auth_parser, add_files=False)
    mcp_auth_parser.add_argument("server", nargs="?", help="Name of the MCP server (as configured) to authenticate")
    mcp_auth_parser.add_argument("--url", help="Authenticate a remote MCP server by URL directly")
    mcp_auth_parser.add_argument(
        "--all-unauthenticated", action="store_true", help="Authenticate every discovered remote MCP server"
    )

    # GUARD command
    guard_parser = subparsers.add_parser(
        "guard",
        allow_abbrev=False,
        help="Install, uninstall, or check status of Agent Guard hooks",
        description="Manage Agent Guard hooks for Claude Code, Cursor, and Codex.",
    )
    guard_subparsers = guard_parser.add_subparsers(
        dest="guard_command",
        title="Guard commands",
        description="Available guard commands (default: show status)",
        metavar="GUARD_COMMAND",
    )

    guard_install_parser = guard_subparsers.add_parser(
        "install",
        allow_abbrev=False,
        help="Install Agent Guard hooks for a client",
    )
    guard_install_parser.add_argument(
        "client",
        choices=["claude", "cursor", "codex", "all"],
        help="Client to install hooks for",
    )
    guard_install_parser.add_argument(
        "--url",
        type=str,
        default="https://api.snyk.io",
        help="Remote hooks base URL (default: https://api.snyk.io)",
    )
    guard_install_parser.add_argument(
        "--tenant-id",
        type=str,
        default=None,
        dest="tenant_id",
        help="Snyk tenant ID (required when minting a push key; not needed if PUSH_KEY is set)",
    )
    guard_install_parser.add_argument(
        "--test",
        action="store_true",
        default=False,
        help="Deprecated, no-op",
    )
    guard_install_parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Override the config file path (default: client-specific well-known path)",
    )
    guard_install_parser.add_argument(
        "--managed",
        action="store_true",
        default=False,
        help="Install hooks to the managed (admin/MDM) config path instead of the user-level path",
    )

    guard_uninstall_parser = guard_subparsers.add_parser(
        "uninstall",
        allow_abbrev=False,
        help="Remove Agent Guard hooks for a client",
    )
    guard_uninstall_parser.add_argument(
        "client",
        choices=["claude", "cursor", "codex", "all"],
        help="Client to uninstall hooks from",
    )
    guard_uninstall_parser.add_argument(
        "--file",
        type=str,
        default=None,
        help="Override the config file path (default: client-specific well-known path)",
    )
    guard_uninstall_parser.add_argument(
        "--managed",
        action="store_true",
        default=False,
        help="Uninstall hooks from the managed (admin/MDM) config path instead of the user-level path",
    )

    # Parse arguments (default to 'scan' if no command provided)
    if (len(sys.argv) == 1 or sys.argv[1] not in subparsers.choices) and (
        not (len(sys.argv) == 2 and sys.argv[1] == "--help")
    ):
        sys.argv.insert(1, "scan")

    # Parse control servers before argparse to preserve their grouping
    try:
        control_servers = parse_control_servers(sys.argv)
    except MissingIdentifierError:
        sys.exit(1)

    args = parser.parse_args()

    # Attach parsed control servers to args
    args.control_servers = control_servers

    # Merge a --config-file (if any) before resolving defaults, so its values
    # sit between code defaults and explicit CLI flags in the precedence cascade.
    apply_config_file(parser, args, sys.argv[1:])

    warn_deprecated_control_flags(args)

    # Resolve deferred defaults and enforce safety rules before dispatching.
    resolve_server_io_default(args)
    enforce_consent_requirements(args)

    # Display version banner
    if not (hasattr(args, "json") and args.json):
        rich.print(f"[bold blue]Snyk Agent Scan v{version_info}[/bold blue]\n")

    # Set up logging if verbose flag is enabled
    do_log = hasattr(args, "verbose") and args.verbose
    setup_logging(do_log, log_to_stderr=True)

    # Handle commands
    if args.command == "help" or (args.command is None and hasattr(args, "help") and args.help):
        parser.print_help()
        sys.exit(0)
    elif args.command == "inspect":
        asyncio.run(print_scan_inspect(mode="inspect", args=args))
        sys.exit(0)
    elif args.command == "scan" or args.command is None:  # default to scan
        asyncio.run(print_scan_inspect(args=args))
        sys.exit(0)
    elif args.command == "evo":
        asyncio.run(evo(args))
        sys.exit(0)
    elif args.command == "mcp-auth":
        asyncio.run(mcp_auth(args))
        sys.exit(0)
    elif args.command == "guard":
        from agent_scan.guard import run_guard

        sys.exit(run_guard(args))

    else:
        # This shouldn't happen due to argparse's handling
        rich.print(f"[bold red]Unknown command: {args.command}[/bold red]")
        parser.print_help()
        sys.exit(1)


async def evo(args):
    """
    Pushes the scan results to the Evo API.

    1. Creates a client_id (shared secret)
    2. Pushes scan results to the Evo API
    3. Revokes the client_id
    """
    from agent_scan.pushkeys import mint_push_key, revoke_push_key

    if getattr(args, "push_key", None) is not None:
        rich.print(
            "[yellow]Note: evo always authenticates with a key it mints itself; "
            "the --push-key you supplied will be ignored.[/yellow]",
            file=sys.stderr,
        )
        args.push_key = None

    rich.print(
        "Go to https://app.snyk.io and select the tenant on the left nav bar. "
        "Copy the Tenant ID from the URL and paste it here: "
    )
    tenant_id = input().strip()
    rich.print("Paste the Authorization token from https://app.snyk.io/account (API Token -> KEY -> click to show): ")
    token = input().strip()

    base_url = "https://api.snyk.io"
    push_scan_url = f"{base_url}/hidden/mcp-scan/push?version=2025-08-28"

    # Mint a push key
    try:
        client_id = mint_push_key(base_url, tenant_id, token)
        rich.print("Client ID created")
    except RuntimeError as e:
        rich.print(f"[bold red]Error calling Snyk API[/bold red]: {e}")
        return

    # Run scan with the push key
    args.control_servers = [
        ControlServer(
            url=push_scan_url,
            identifier=get_hostname() or None,
            headers=parse_headers([f"x-client-id:{client_id}"]),
        )
    ]
    await run_scan(args, mode="scan")

    # Revoke the push key
    try:
        revoke_push_key(base_url, tenant_id, token, client_id)
        rich.print("Client ID revoked")
    except RuntimeError as e:
        rich.print(f"[bold red]Error revoking client_id[/bold red]: {e}")


def _should_show_analysis_results(args) -> bool:
    """Show analysis results (force synchronous analysis) for evo, CI, or --show-analysis-results."""
    return (
        getattr(args, "command", None) == "evo"
        or getattr(args, "ci", False)
        or getattr(args, "show_analysis_results", False)
    )


async def mcp_auth(args):
    """Interactively authenticate an OAuth-protected remote MCP server.

    Runs the browser OAuth flow and persists the token to the local store, so
    subsequent (unattended) scans use and refresh it. This is the only command
    that performs an interactive authorization; the scan path never does.
    """
    from urllib.parse import urlparse

    from agent_scan.models import RemoteServer
    from agent_scan.oauth_flow import authenticate_server
    from agent_scan.oauth_store import OAuthTokenStore

    store = OAuthTokenStore()
    url_arg = getattr(args, "url", None)
    server_arg = getattr(args, "server", None)
    all_unauth = getattr(args, "all_unauthenticated", False)

    targets: list[tuple[str, str]] = []
    if url_arg:
        name = server_arg or urlparse(url_arg).hostname or url_arg
        targets = [(name, url_arg)]
    else:
        # Discover remote MCP servers from this machine's agent configs.
        inspect_args = InspectArgs(
            timeout=getattr(args, "server_timeout", 10),
            tokens=[],
            paths=[],
            all_users=getattr(args, "scan_all_users", False),
            scan_skills=False,
        )
        clients_to_inspect, _, _ = await discover_clients_to_inspect(inspect_args)
        remote: dict[str, str] = {}
        for client in clients_to_inspect:
            for _config_path, entries in client.mcp_configs.items():
                if isinstance(entries, list):
                    for name, server in entries:
                        if isinstance(server, RemoteServer):
                            remote.setdefault(name, server.url)
        if all_unauth:
            targets = list(remote.items())
        elif server_arg:
            if server_arg not in remote:
                rich.print(f"[bold red]No remote MCP server named '{server_arg}' found.[/bold red]")
                if remote:
                    rich.print(f"Discovered remote servers: {', '.join(sorted(remote))}")
                else:
                    rich.print("No remote MCP servers were discovered on this machine.")
                return
            targets = [(server_arg, remote[server_arg])]
        else:
            rich.print("[bold red]Specify a server name, --url <url>, or --all-unauthenticated.[/bold red]")
            return

    if not targets:
        rich.print("No remote MCP servers to authenticate.")
        return

    for name, url in targets:
        rich.print(f"\n[bold]Authenticating '{name}'[/bold] ({url}) ...")
        result = await authenticate_server(url, name, store)
        if result.ok:
            rich.print(f"[bold green]{name}: authenticated[/bold green]")
        else:
            rich.print(f"[bold red]{name}: authentication failed[/bold red] — {result.message}")


async def run_scan(args, mode: Literal["scan", "inspect"] = "scan") -> ScanResponse | list[InspectedPath]:
    """
    Run the scan or inspect flow through their shared discovery and consent setup.

    ``inspect`` stops after producing the local ``InspectedPath`` results.
    ``scan`` sends those results to the analysis backend and returns the final,
    potentially backend-enriched ``ScanResponse``.

    Flow:
    1. Build InspectArgs from CLI args.
    2. Discover the clients/configs that would be inspected.
    3. If interactive and --dangerously-run-mcp-servers is not set, prompt
       the user per stdio server for consent. Declined servers are recorded as
       user_declined errors and never started.
    4. Run the existing inspect / analyze / push pipeline with the filtered
       plan and optional live stderr streaming.
    """
    verbose: bool = hasattr(args, "verbose") and args.verbose
    scan_all_users: bool = hasattr(args, "scan_all_users") and args.scan_all_users

    server_timeout: int = args.server_timeout if hasattr(args, "server_timeout") else 10
    files: list[str] | None = args.files if hasattr(args, "files") else None
    scan_skills: bool = hasattr(args, "skills") and args.skills
    tokens: list[TokenAndClientInfo] = []
    if hasattr(args, "mcp_oauth_tokens_path") and args.mcp_oauth_tokens_path:
        with open(args.mcp_oauth_tokens_path) as f:
            tokens = TokenAndClientInfoList.model_validate_json(f.read()).root

    inspect_args = InspectArgs(
        timeout=server_timeout,
        tokens=tokens,
        paths=files,
        all_users=scan_all_users,
        scan_skills=scan_skills,
    )

    # Resolve the MCP server IO flag and the consent flag.
    if getattr(args, "suppress_mcpserver_io", None) is None:
        args.suppress_mcpserver_io = not is_interactive_run(args)
    suppress_io: bool = bool(args.suppress_mcpserver_io)
    stream_stderr: bool = not suppress_io

    decision = decide_handshake(args)
    dangerously_run_mcp_servers: bool = bool(getattr(args, "dangerously_run_mcp_servers", False))

    # Step 1: Discover everything we would inspect without starting any server.
    clients_to_inspect, unresolved_paths, scanned_usernames = await discover_clients_to_inspect(inspect_args)

    # Collect consent when applicable; otherwise show the
    # dangerous-flag banner to users at the terminal. Silent
    # otherwise.
    declined_servers: set[tuple[str, str]] = set()
    if decision.collect_consent:
        declined_servers = collect_consent(clients_to_inspect)
    elif dangerously_run_mcp_servers and is_interactive_run(args):
        _print_dangerous_warning(suppress_io)

    if mode == "scan":
        skip_ssl_verify: bool = bool(hasattr(args, "skip_ssl_verify") and args.skip_ssl_verify)

        control_servers: list[ControlServer] = args.control_servers if hasattr(args, "control_servers") else []
        # --machine-id / --push-key take precedence over the deprecated
        # --control-identifier / --control-server-H equivalents. Resolved once
        # here so every downstream consumer (PushArgs, the pipeline) sees the
        # same already-resolved value instead of re-deriving it.
        identifier: str | None = _effective_identifier(args)
        push_key: str | None = _effective_push_key(args)

        analyze_args = AnalyzeArgs(
            analysis_url=args.analysis_url,
            identifier=identifier,
            additional_headers=parse_headers(args.verification_H),
            max_retries=3,
            skip_ssl_verify=skip_ssl_verify,
            show_analysis_results=_should_show_analysis_results(args),
        )
        push_args = PushArgs(
            control_servers=control_servers,
            push_key=push_key,
            skip_ssl_verify=skip_ssl_verify,
            version=version_info,
        )
        return await inspect_analyze_push_pipeline(
            inspect_args,
            analyze_args,
            push_args,
            verbose=verbose,
            clients_to_inspect=clients_to_inspect,
            unresolved_paths=unresolved_paths,
            scanned_usernames=scanned_usernames,
            stream_stderr=stream_stderr,
            declined_servers=declined_servers,
            do_stdio_handshake=decision.do_stdio_handshake,
        )
    elif mode == "inspect":
        inspected_paths, _scanned_usernames = await inspect_pipeline(
            inspect_args,
            clients_to_inspect=clients_to_inspect,
            unresolved_paths=unresolved_paths,
            scanned_usernames=scanned_usernames,
            stream_stderr=stream_stderr,
            declined_servers=declined_servers,
            do_stdio_handshake=decision.do_stdio_handshake,
        )
        return inspected_paths
    else:
        raise ValueError(f"Unknown mode: {mode}, expected 'scan' or 'inspect'")


def _collect_failure_codes(result: list[InspectedPath]) -> set[str]:
    """Collect X00x codes from operational failures in inspected paths."""
    codes: set[str] = set()
    for r in result:
        if r.error and r.error.is_failure:
            codes.add(FAILURE_CATEGORY_TO_CODE.get(r.error.category, FAILURE_CATEGORY_TO_CODE[None]))
        for s in r.servers:
            if s.error and s.error.is_failure:
                codes.add(FAILURE_CATEGORY_TO_CODE.get(s.error.category, FAILURE_CATEGORY_TO_CODE[None]))
        for skill in r.skills:
            if skill.error and skill.error.is_failure:
                codes.add(FAILURE_CATEGORY_TO_CODE.get(skill.error.category, FAILURE_CATEGORY_TO_CODE[None]))
    return codes


_VALID_RISK_NAMES = frozenset(McpServerRiskIndexes.model_fields) | frozenset(SkillRiskIndexes.model_fields)
_VALID_FAILURE_CODES = frozenset(FAILURE_CATEGORY_TO_CODE.values())


def _parse_comma_separated(raw_value: str | None) -> set[str]:
    """Parse a comma-separated CLI option into non-empty, stripped values."""
    return {value.strip() for value in raw_value.split(",") if value.strip()} if raw_value else set()


def _parse_ignore_risks(args, ci_mode: bool) -> set[str]:
    """Parse --ignore-risks, which is valid only for CI scans."""
    requested = _parse_comma_separated(getattr(args, "ignore_risks", None))
    if requested and not ci_mode:
        rich.print(
            "[bold red]Error: --ignore-risks can only be used with --ci.[/bold red]",
            file=sys.stderr,
        )
        sys.exit(CLI_USAGE_ERROR_EXIT_CODE)

    unknown = requested - _VALID_RISK_NAMES
    for name in sorted(unknown):
        rich.print(f"[yellow]Warning: unknown risk name: {name}[/yellow]", file=sys.stderr)
    return requested - unknown


def _parse_ignore_failure_codes(args, ci_mode: bool) -> set[str]:
    """Parse --ignore-failure-codes, which is valid only for CI scans."""
    requested = _parse_comma_separated(getattr(args, "ignore_failure_codes", None))
    if requested and not ci_mode:
        rich.print(
            "[bold red]Error: --ignore-failure-codes can only be used with --ci.[/bold red]",
            file=sys.stderr,
        )
        sys.exit(CLI_USAGE_ERROR_EXIT_CODE)

    unknown = requested - _VALID_FAILURE_CODES
    for code in sorted(unknown):
        rich.print(f"[yellow]Warning: unknown failure code: {code}[/yellow]", file=sys.stderr)
    return requested - unknown


def _apply_ignore_risks(response: ScanResponse, ignored_risks: set[str]) -> None:
    """Remove ignored risks before rendering and CI exit evaluation."""
    for path in response.scan_path_responses:
        risk_indexes = [server.risk_indexes for server in path.server_risks]
        risk_indexes.extend(skill.risk_indexes for skill in path.skill_risks)
        for indexes in risk_indexes:
            for name in ignored_risks & indexes.__class__.model_fields.keys():
                setattr(indexes, name, None)


def _has_risks(response: ScanResponse) -> bool:
    for path in response.scan_path_responses:
        for server in path.server_risks:
            if any(value is not None for value in server.risk_indexes.model_dump().values()):
                return True
        for skill in path.skill_risks:
            if any(value is not None for value in skill.risk_indexes.model_dump().values()):
                return True
    return False


def _collect_response_failure_codes(response: ScanResponse) -> set[str]:
    codes: set[str] = set()
    for path in response.scan_path_responses:
        errors = [path.error]
        errors.extend(server.error for server in path.server_risks)
        errors.extend(skill.error for skill in path.skill_risks)
        for error in errors:
            if error and error.is_failure:
                codes.add(FAILURE_CATEGORY_TO_CODE.get(error.category, FAILURE_CATEGORY_TO_CODE[None]))
    return codes


def _handle_ci_exit(
    result: list[InspectedPath] | ScanResponse,
    json_output: bool,
    ignored_failure_codes: set[str] | None = None,
) -> None:
    """In CI mode, exit with code 1 if any risk or runtime failure remains."""
    if isinstance(result, ScanResponse):
        failure_codes = _collect_response_failure_codes(result)
        has_risks = _has_risks(result)
    else:
        failure_codes = _collect_failure_codes(result)
        has_risks = False
    failure_codes -= ignored_failure_codes or set()
    if not has_risks and not failure_codes:
        return

    if not json_output:
        reasons = []
        if has_risks:
            reasons.append("risks found")
        if failure_codes:
            reasons.append(f"runtime failure codes: {', '.join(sorted(failure_codes))}")
        rich.print(
            f"[bold red]CI (--ci): exiting with code 1 ({'; '.join(reasons)}).[/bold red]",
            file=sys.stderr,
        )
    sys.exit(1)


async def print_scan_inspect(mode="scan", args=None):
    json_output: bool = hasattr(args, "json") and args.json
    print_errors: bool = hasattr(args, "print_errors") and args.print_errors
    full_description: bool = hasattr(args, "print_full_descriptions") and args.print_full_descriptions
    ci_mode: bool = hasattr(args, "ci") and args.ci
    ignored_risks = _parse_ignore_risks(args, ci_mode)
    ignored_failure_codes = _parse_ignore_failure_codes(args, ci_mode)

    if json_output:
        with suppress_stdout():
            result = await run_scan(args, mode=mode)
    else:
        result = await run_scan(args, mode=mode)

    if mode == "inspect":
        inspected_paths = cast("list[InspectedPath]", result)
        if json_output:
            print(json.dumps({p.path: p.model_dump(mode="json") for p in inspected_paths}, indent=2))
        else:
            print_inspected_machine(inspected_paths, print_errors, full_description, args)
        if ci_mode:
            _handle_ci_exit(inspected_paths, json_output, ignored_failure_codes)
        return

    response = cast("ScanResponse", result)
    if ignored_risks:
        _apply_ignore_risks(response, ignored_risks)

    if json_output:
        print(json.dumps(response.model_dump(mode="json", exclude_none=True), indent=2))
    else:
        print_scan_response(
            response,
            print_errors,
            args,
            show_all=bool(getattr(args, "show_full_discovery", False)),
        )

    if ci_mode:
        _handle_ci_exit(response, json_output, ignored_failure_codes)


if __name__ == "__main__":
    main()
