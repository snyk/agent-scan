"""
Traffic capture utilities for MCP protocol debugging.

This module provides classes to capture MCP protocol traffic (sent and received
messages, plus stderr output) for debugging failed server connections.
"""

import asyncio
import contextlib
import hashlib
import os
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import rich

# Palette used to color per-server stderr prefixes.
_STREAM_COLOR_PALETTE: tuple[str, ...] = (
    "cyan",
    "green",
    "yellow",
    "magenta",
    "blue",
    "bright_cyan",
    "bright_green",
    "bright_yellow",
    "bright_magenta",
    "bright_blue",
    "color(33)",  # dodger blue
    "color(39)",  # deep sky blue
    "color(44)",  # dark turquoise
    "color(49)",  # spring green
    "color(75)",  # steel blue
    "color(78)",  # sea green
    "color(81)",  # light sky blue
    "color(108)",  # dark sea green
    "color(111)",  # light cornflower
    "color(114)",  # sea green
    "color(117)",  # sky blue
    "color(141)",  # medium purple
    "color(147)",  # light steel blue
    "color(150)",  # pale sea green
    "color(156)",  # pale green
    "color(159)",  # pale turquoise
    "color(179)",  # light goldenrod
    "color(180)",  # tan
    "color(186)",  # khaki
    "color(214)",  # orange
    "color(220)",  # gold
    "color(228)",  # khaki
)

# Shared lock so concurrent servers don't interleave lines mid-write.
_STREAM_PRINT_LOCK = threading.Lock()


def _color_for_server(name: str, config_path: str | None = None) -> str:
    """
    Pick a stable palette color for a server using the config_path.
    """
    key = f"{config_path or ''}\x00{name}".encode()
    digest = hashlib.sha1(key, usedforsecurity=False).digest()
    # Use the first 4 bytes to reduce bucketing bias now that the palette is
    # larger than 256 entries could tolerate from a single byte.
    idx = int.from_bytes(digest[:4], "big") % len(_STREAM_COLOR_PALETTE)
    return _STREAM_COLOR_PALETTE[idx]


def _print_server_line(
    server_name: str,
    line: str,
    console: "rich.console.Console | None",
    *,
    config_path: str | None = None,
) -> None:
    """Print a single captured stderr line prefixed with the server name."""
    color = _color_for_server(server_name, config_path)
    # rich markup is escaped on the content to prevent a hostile server from
    # emitting our own style tags.
    from rich.markup import escape

    target = console or rich.get_console()
    with _STREAM_PRINT_LOCK:
        target.print(f"[{color}]\\[{escape(server_name)}][/{color}] {escape(line)}")


@dataclass
class TrafficCapture:
    """Captures MCP protocol traffic (messages sent and received) plus stderr."""

    sent: list[Any] = field(default_factory=list)
    received: list[Any] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)

    def get_traffic_log(self, max_chars: int = 10000) -> str | None:
        """Format captured traffic as a string for error reporting."""
        lines = []
        for msg in self.sent:
            lines.append(f">>> SENT: {msg}")
        for msg in self.received:
            lines.append(f"<<< RECV: {msg}")
        for line in self.stderr:
            lines.append(f"STDERR: {line}")

        if not lines:
            return None

        output = "\n".join(lines)
        if len(output) > max_chars:
            return output[:max_chars] + "\n... (truncated)"
        return output


class PipeStderrCapture:
    """
    A file-like object backed by a real OS pipe for capturing stderr.

    This can be passed to subprocess.Popen as stderr because it has a real
    file descriptor via fileno().
    """

    def __init__(
        self,
        capture: TrafficCapture,
        *,
        stream_server_name: str | None = None,
        stream_config_path: str | None = None,
        stream_console: "rich.console.Console | None" = None,
    ):
        self._capture = capture
        self._stream_server_name = stream_server_name
        self._stream_config_path = stream_config_path
        self._stream_console = stream_console
        self._read_fd, self._write_fd = os.pipe()
        self._write_file = os.fdopen(self._write_fd, "w")
        self._reader_task: asyncio.Task | None = None
        self._closed = False

    def fileno(self) -> int:
        """Return the write end file descriptor for subprocess."""
        return self._write_fd

    def write(self, data: str) -> int:
        """Write to the pipe (used if errlog is written to directly)."""
        return self._write_file.write(data)

    def flush(self) -> None:
        """Flush the write buffer."""
        self._write_file.flush()

    async def start_reading(self) -> None:
        """Start a background task to read from the pipe and capture stderr."""
        self._reader_task = asyncio.create_task(self._read_stderr())

    async def _read_stderr(self) -> None:
        """Read stderr from the pipe in a background task."""
        loop = asyncio.get_event_loop()
        read_file = os.fdopen(self._read_fd, "r")
        try:
            while True:
                # Read in executor to avoid blocking the event loop
                line = await loop.run_in_executor(None, read_file.readline)
                if not line:
                    break
                line = line.rstrip("\n\r")
                if line:
                    self._capture.stderr.append(line)
                    if self._stream_server_name is not None:
                        _print_server_line(
                            self._stream_server_name,
                            line,
                            self._stream_console,
                            config_path=self._stream_config_path,
                        )
        except Exception:
            pass  # Pipe closed or error
        finally:
            with contextlib.suppress(Exception):
                read_file.close()

    async def close(self) -> None:
        """Close the pipe and stop reading."""
        if self._closed:
            return
        self._closed = True

        with contextlib.suppress(Exception):
            self._write_file.close()

        # Give reader a moment to finish
        if self._reader_task:
            with contextlib.suppress(Exception):
                # Cancel the reader task since the write end is closed
                self._reader_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                    await asyncio.wait_for(self._reader_task, timeout=0.1)


class CapturingReadStream:
    """Wraps a read stream to capture all received messages."""

    def __init__(self, read_stream, capture: TrafficCapture):
        self._read_stream = read_stream
        self._capture = capture

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            msg = await self._read_stream.__anext__()
            self._capture.received.append(msg)
            return msg
        except StopAsyncIteration:
            raise

    # Delegate async context manager protocol
    async def __aenter__(self):
        if hasattr(self._read_stream, "__aenter__"):
            await self._read_stream.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self._read_stream, "__aexit__"):
            return await self._read_stream.__aexit__(exc_type, exc_val, exc_tb)
        return None

    # Delegate any other attributes to the underlying stream
    def __getattr__(self, name):
        return getattr(self._read_stream, name)


class CapturingWriteStream:
    """Wraps a write stream to capture all sent messages."""

    def __init__(self, write_stream, capture: TrafficCapture):
        self._write_stream = write_stream
        self._capture = capture

    async def send(self, msg):
        """Send a message and capture it."""
        self._capture.sent.append(msg)
        return await self._write_stream.send(msg)

    async def __call__(self, msg):
        """Also support callable interface for compatibility."""
        self._capture.sent.append(msg)
        if hasattr(self._write_stream, "send"):
            return await self._write_stream.send(msg)
        return await self._write_stream(msg)

    # Delegate async context manager protocol
    async def __aenter__(self):
        if hasattr(self._write_stream, "__aenter__"):
            await self._write_stream.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self._write_stream, "__aexit__"):
            return await self._write_stream.__aexit__(exc_type, exc_val, exc_tb)
        return None

    # Delegate any other attributes to the underlying stream
    def __getattr__(self, name):
        return getattr(self._write_stream, name)


@asynccontextmanager
async def capturing_client(client_cm, capture: TrafficCapture) -> AsyncIterator[tuple]:
    """Wrap a client context manager to capture all traffic."""
    async with client_cm as (read, write):
        yield CapturingReadStream(read, capture), CapturingWriteStream(write, capture)
