"""Tests for verbose logging setup.

Regression coverage for a crash where scanned content containing bracketed
text (e.g. a discovered instructions path like
``[/c:/Users/user/.copilot/instructions, /workspace/.github/instructions]``)
was logged at DEBUG level in --verbose mode and the Rich logging handler tried
to parse it as console markup, raising ``rich.errors.MarkupError`` from inside
``RichHandler.emit`` and aborting the scan before results were pushed.
"""

import io
import logging

import pytest
from rich.console import Console

from agent_scan.cli import setup_logging
from agent_scan.traffic_capture import _print_server_line
from tests.unit._secret_fixtures import synthetic_secret

# A payload fragment that Rich's markup parser reads as an unmatched closing
# tag ("[/...]") — this is what crashed verbose scans.
BRACKETED_MESSAGE = "Payload: [/c:/Users/user/.copilot/instructions, /workspace/.github/instructions]"


@pytest.fixture
def restore_root_logger():
    """Save and restore the root and third-party loggers' handlers and levels.

    ``setup_logging`` calls ``logging.basicConfig(force=True)``, which mutates
    global logging state; this fixture keeps the change from leaking into other
    tests.
    """
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    third_party_names = ("httpx", "httpcore", "mcp")
    saved_third_party = {name: logging.getLogger(name).level for name in third_party_names}
    try:
        yield
    finally:
        for hdlr in root.handlers[:]:
            root.removeHandler(hdlr)
        for hdlr in saved_handlers:
            root.addHandler(hdlr)
        root.setLevel(saved_level)
        for name, level in saved_third_party.items():
            logging.getLogger(name).setLevel(level)


@pytest.mark.parametrize("log_to_stderr", [False, True])
def test_verbose_debug_log_with_brackets_does_not_raise(restore_root_logger, log_to_stderr):
    """A DEBUG log containing "[/...]" must not crash the Rich handler."""
    setup_logging(verbose=True, log_to_stderr=log_to_stderr)

    logger = logging.getLogger("agent_scan.test_cli_logging")
    # Must not raise rich.errors.MarkupError (or anything else).
    logger.debug("%s", BRACKETED_MESSAGE)
    logger.debug(BRACKETED_MESSAGE)


@pytest.mark.parametrize("log_to_stderr", [False, True])
def test_verbose_debug_log_redacts_url_query_and_auth_headers(restore_root_logger, capsys, log_to_stderr):
    """mcp_client-style debug logs with ?token= URLs and auth headers must be redacted."""
    setup_logging(verbose=True, log_to_stderr=log_to_stderr)

    logger = logging.getLogger("agent_scan.mcp_client")
    url = "https://mcp.example.com/mcp?token=FAKE-SECRET-123"
    headers = {
        "Authorization": "Bearer FAKE-SECRET-456",
        "Proxy-Authorization": "Basic FAKE-SECRET-789",
    }
    logger.debug("Creating Streamable HTTP client with URL: %s with headers %s", url, headers)

    captured = capsys.readouterr()
    output = captured.err if log_to_stderr else captured.out
    assert "Creating Streamable HTTP client" in output
    assert "FAKE-SECRET-123" not in output
    assert "FAKE-SECRET-456" not in output
    assert "FAKE-SECRET-789" not in output
    assert "**REDACTED**" in output


def test_verbose_debug_log_tolerates_malformed_format_args(restore_root_logger):
    """Mismatched %-format arguments in a log call must not raise out of _RedactingLogFilter."""
    setup_logging(verbose=True, log_to_stderr=True)

    logging.getLogger("agent_scan.test_cli_logging").debug("bad format %s %s", "only-one-arg")


def test_verbose_logging_suppresses_httpx_httpcore_and_mcp_debug_logs(restore_root_logger, capsys):
    """Third-party HTTP/MCP DEBUG and INFO logs must be suppressed in verbose mode."""
    setup_logging(verbose=True, log_to_stderr=True)

    logging.getLogger("httpx").debug("httpx debug FAKE-SECRET-HTTPX-DBG")
    logging.getLogger("httpx").info("HTTP Request: POST https://example.com/mcp?token=FAKE-SECRET-HTTPX-INFO")
    logging.getLogger("httpcore.http11").debug("send_request_headers FAKE-SECRET-HTTPCORE")
    logging.getLogger("mcp.client.streamable_http").debug("Connecting to endpoint FAKE-SECRET-MCP")

    err = capsys.readouterr().err
    assert "FAKE-SECRET-HTTPX-DBG" not in err
    assert "FAKE-SECRET-HTTPX-INFO" not in err
    assert "FAKE-SECRET-HTTPCORE" not in err
    assert "FAKE-SECRET-MCP" not in err


def test_print_server_line_redacts_bearer_and_github_token():
    """Live stdio MCP server stderr lines must be sanitized before printing."""
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=300, height=25)
    fake_gh_token = "ghp" + "_" + (synthetic_secret(b"stderr-github-token") * 2)[:36]

    _print_server_line(
        "demo-server",
        f"Auth error: Bearer FAKE-SECRET-123 token={fake_gh_token} url=https://api.example.com/cb?key=FAKE-SECRET-456",
        console,
    )

    rendered = buf.getvalue()
    assert "[demo-server]" in rendered
    assert "FAKE-SECRET-123" not in rendered
    assert "FAKE-SECRET-456" not in rendered
    assert fake_gh_token not in rendered
    assert "**REDACTED**" in rendered
    assert "**REDACTED_SECRET_GITHUBTOKENDETECTOR**" in rendered
