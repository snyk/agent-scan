"""
Stdio MCP shim that logs all traffic to a per-session, per-server file.

Slot this into a Claude MCP config entry in place of the real server command::

    {
      "mcpServers": {
        "fetch": {
          "command": "snyk-agent-scan-mcp-shim",
          "args": ["--server-name", "fetch", "--", "uvx", "mcp-server-fetch"]
        }
      }
    }

The shim spawns the wrapped command, proxies stdin/stdout transparently, and
tees every line to ``/tmp/mcp_comm_<agent>__<server>.log`` as JSONL. The agent
id is derived from the parent process (PPID) plus the working directory so
each Claude Code session gets its own file per server.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

LOG_DIR = Path("/tmp")
_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _slug(value: str) -> str:
    cleaned = _SLUG_RE.sub("-", value).strip("-")
    return cleaned or "unknown"


def derive_agent_id(cwd: Path | None = None, ppid: int | None = None) -> str:
    cwd = cwd if cwd is not None else Path.cwd()
    ppid = ppid if ppid is not None else os.getppid()
    return f"{_slug(cwd.name)}_pid{ppid}"


def derive_server_id(server_name: str | None, command: list[str]) -> str:
    if server_name:
        return _slug(server_name)
    if not command:
        return "unknown"
    return _slug(Path(command[0]).name)


def log_path_for(agent_id: str, server_id: str) -> Path:
    return LOG_DIR / f"mcp_comm_{agent_id}__{server_id}.log"


class _Logger:
    """Thread-safe JSONL writer. Silently degrades if the file can't be opened."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        try:
            self._fh: BinaryIO | None = path.open("ab", buffering=0)
        except OSError as exc:
            self._fh = None
            print(f"mcp-shim: cannot open log {path}: {exc}", file=sys.stderr)

    def write(self, direction: str, raw: bytes) -> None:
        if self._fh is None:
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "dir": direction,
            "raw": raw.decode("utf-8", errors="replace").rstrip("\r\n"),
        }
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
        with self._lock, contextlib.suppress(OSError):
            self._fh.write(line)

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                finally:
                    self._fh = None


def _pump(src: BinaryIO, dst: BinaryIO | None, logger: _Logger, direction: str) -> None:
    """Copy lines from src to dst (if given) and log each line."""
    try:
        for line in iter(src.readline, b""):
            logger.write(direction, line)
            if dst is not None:
                try:
                    dst.write(line)
                    dst.flush()
                except (BrokenPipeError, OSError):
                    break
    except (OSError, ValueError):
        # ValueError happens when the underlying fd is closed mid-read.
        pass
    finally:
        if dst is not None:
            with contextlib.suppress(BrokenPipeError, OSError):
                dst.flush()


def _parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(
        prog="snyk-agent-scan-mcp-shim",
        description="Wrap an MCP stdio server and log all traffic to /tmp.",
    )
    parser.add_argument(
        "--server-name",
        default=None,
        help="Logical name used in the log filename. Defaults to basename of the wrapped command.",
    )
    if "--" in argv:
        sep = argv.index("--")
        own_args = argv[:sep]
        command = argv[sep + 1 :]
    else:
        # Allow omitting '--' as long as no shim flags come after the command.
        own_args = []
        command = []
        i = 0
        while i < len(argv):
            arg = argv[i]
            if arg == "--server-name":
                own_args.extend(argv[i : i + 2])
                i += 2
            elif arg.startswith("--server-name="):
                own_args.append(arg)
                i += 1
            else:
                command = argv[i:]
                break
    args = parser.parse_args(own_args)
    return args, command


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args, command = _parse_args(argv)

    agent_id = derive_agent_id()
    server_id = derive_server_id(args.server_name, command)
    logger = _Logger(log_path_for(agent_id, server_id))

    if not command:
        logger.write("shim-error", b"no command given to shim")
        logger.close()
        print("mcp-shim: no command given (use: ... -- <cmd> [args...])", file=sys.stderr)
        return 2

    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
    except FileNotFoundError as exc:
        logger.write("shim-error", f"command not found: {exc}".encode())
        logger.close()
        print(f"mcp-shim: {exc}", file=sys.stderr)
        return 127
    except OSError as exc:
        logger.write("shim-error", f"spawn failed: {exc}".encode())
        logger.close()
        print(f"mcp-shim: spawn failed: {exc}", file=sys.stderr)
        return 126

    def _forward_signal(signum: int, _frame: object) -> None:
        with contextlib.suppress(ProcessLookupError):
            proc.send_signal(signum)

    original_handlers: list[tuple[int, Any]] = []
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        with contextlib.suppress(ValueError, OSError):
            original_handlers.append((int(sig), signal.signal(sig, _forward_signal)))

    parent_stdin = sys.stdin.buffer
    parent_stdout = sys.stdout.buffer

    threads = [
        threading.Thread(
            target=_pump,
            args=(parent_stdin, proc.stdin, logger, "client->server"),
            name="mcp-shim-stdin",
            daemon=True,
        ),
        threading.Thread(
            target=_pump,
            args=(proc.stdout, parent_stdout, logger, "server->client"),
            name="mcp-shim-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=_pump,
            args=(proc.stderr, None, logger, "stderr"),
            name="mcp-shim-stderr",
            daemon=True,
        ),
    ]
    for t in threads:
        t.start()

    rc = proc.wait()

    # Let the stdout/stderr pumps drain anything still buffered.
    if proc.stdout is not None:
        with contextlib.suppress(OSError):
            proc.stdout.close()
    if proc.stderr is not None:
        with contextlib.suppress(OSError):
            proc.stderr.close()
    for t in threads[1:]:
        t.join(timeout=1.0)

    # Closing our stdin reader is best-effort; the daemon thread will die on exit.
    if proc.stdin is not None:
        with contextlib.suppress(OSError):
            proc.stdin.close()

    for signo, handler in original_handlers:
        with contextlib.suppress(ValueError, OSError, TypeError):
            signal.signal(signo, handler)

    logger.close()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
