"""Tests for verbose logging setup.

Regression coverage for a crash where scanned content containing bracketed
text (e.g. a discovered instructions path like
``[/c:/Users/user/.copilot/instructions, /workspace/.github/instructions]``)
was logged at DEBUG level in --verbose mode and the Rich logging handler tried
to parse it as console markup, raising ``rich.errors.MarkupError`` from inside
``RichHandler.emit`` and aborting the scan before results were pushed.
"""

import logging

import pytest

from agent_scan.cli import setup_logging

# A payload fragment that Rich's markup parser reads as an unmatched closing
# tag ("[/...]") — this is what crashed verbose scans.
BRACKETED_MESSAGE = "Payload: [/c:/Users/user/.copilot/instructions, /workspace/.github/instructions]"


@pytest.fixture
def restore_root_logger():
    """Save and restore the root logger's handlers and level.

    ``setup_logging`` calls ``logging.basicConfig(force=True)``, which mutates
    global logging state; this fixture keeps the change from leaking into other
    tests.
    """
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        yield
    finally:
        for hdlr in root.handlers[:]:
            root.removeHandler(hdlr)
        for hdlr in saved_handlers:
            root.addHandler(hdlr)
        root.setLevel(saved_level)


@pytest.mark.parametrize("log_to_stderr", [False, True])
def test_verbose_debug_log_with_brackets_does_not_raise(restore_root_logger, log_to_stderr):
    """A DEBUG log containing "[/...]" must not crash the Rich handler."""
    setup_logging(verbose=True, log_to_stderr=log_to_stderr)

    logger = logging.getLogger("agent_scan.test_cli_logging")
    # Must not raise rich.errors.MarkupError (or anything else).
    logger.debug("%s", BRACKETED_MESSAGE)
    logger.debug(BRACKETED_MESSAGE)
