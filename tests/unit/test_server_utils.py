"""Unit tests for the e2e server-readiness helper."""

import socket
import subprocess
import sys
import threading
import time

import pytest

from tests.server_utils import wait_for_port


def _unused_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_wait_for_port_returns_once_a_late_listener_appears():
    """The case a fixed sleep gets wrong: the server only starts listening after a delay."""
    port = _unused_port()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def listen_late():
        time.sleep(0.6)
        listener.bind(("127.0.0.1", port))
        listener.listen()

    thread = threading.Thread(target=listen_late, daemon=True)
    thread.start()
    try:
        started = time.monotonic()
        wait_for_port(port, timeout=10)
        assert time.monotonic() - started >= 0.5  # it really waited for the listener, not just returned
    finally:
        thread.join()
        listener.close()


def test_wait_for_port_times_out_when_nothing_listens():
    with pytest.raises(TimeoutError, match="nothing listening"):
        wait_for_port(_unused_port(), timeout=0.3)


def test_wait_for_port_fails_fast_with_the_exit_code_when_the_server_process_dies():
    process = subprocess.Popen([sys.executable, "-c", "raise SystemExit(3)"])
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="exited with code 3"):
        wait_for_port(_unused_port(), process=process, timeout=30)
    assert time.monotonic() - started < 10  # did not sit out the 30s timeout
