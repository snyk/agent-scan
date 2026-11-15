"""Helpers for tests that start a local MCP server in a subprocess."""

import socket
import subprocess
import time


def wait_for_port(
    port: int,
    *,
    process: subprocess.Popen | None = None,
    timeout: float = 60.0,
    host: str = "127.0.0.1",
) -> None:
    """Block until something accepts TCP connections on ``host:port``.

    Replaces fixed ``time.sleep`` waits, which race against slow runners:
    ``uv run python server.py`` has to resolve the environment, start Python and start
    uvicorn before anything listens, and on a loaded CI machine that can take longer than
    the sleep. Raises ``RuntimeError`` straight away, with the exit code, if ``process``
    dies first, and ``TimeoutError`` if nothing is listening by the deadline.
    """
    deadline = time.monotonic() + timeout
    while True:
        if process is not None and process.poll() is not None:
            raise RuntimeError(
                f"server process exited with code {process.returncode} before listening on {host}:{port}"
            )
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"nothing listening on {host}:{port} after {timeout:.0f}s") from None
            time.sleep(0.1)
