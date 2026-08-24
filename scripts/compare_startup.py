#!/usr/bin/env python3
"""Time ``agent-scan --help`` across packaged builds and print a comparison table.

Invoked by the ``compare-startup`` Makefile target. Each CLI argument is a
pipe-separated triple describing one build variant::

    "LABEL|EXE|ARTIFACT"

  LABEL     human-readable variant name (e.g. "PyInstaller onefile")
  EXE       path to the executable to invoke with ``--help`` (may be missing
            when that build failed — reported as "BUILD FAILED")
  ARTIFACT  path whose on-disk size represents the shipped artifact; a file for
            single-file builds, a directory for --onedir

The point of the comparison is startup latency, so each variant is timed over
several consecutive ``--help`` runs: the first run is "cold" (populates OS
file-cache / per-launch extraction caches) and the rest are "warm".
"""

import contextlib
import os
import subprocess
import sys
import time

RUNS = 3


def artifact_size(path: str) -> int:
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            fp = os.path.join(root, name)
            with contextlib.suppress(OSError):
                total += os.path.getsize(fp)
    return total


def human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"


def bench(exe: str) -> list[float]:
    times: list[float] = []
    for _ in range(RUNS):
        start = time.perf_counter()
        subprocess.run([exe, "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        times.append(time.perf_counter() - start)
    return times


def main() -> None:
    rows: list[tuple[str, list[str], str]] = []
    for arg in sys.argv[1:]:
        parts = arg.split("|")
        label = parts[0]
        exe = parts[1] if len(parts) > 1 else ""
        artifact = parts[2] if len(parts) > 2 and parts[2] else exe
        if exe and os.path.isfile(exe) and os.access(exe, os.X_OK):
            times = bench(exe)
            size = human(artifact_size(artifact)) if artifact and os.path.exists(artifact) else "-"
            rows.append((label, [f"{t:.2f}s" for t in times], size))
        else:
            rows.append((label, [], "BUILD FAILED"))

    headers = ["Variant"] + [f"run {i + 1}" for i in range(RUNS)] + ["artifact"]
    table: list[list[str]] = [headers]
    for label, run_cells, size in rows:
        cells = run_cells if run_cells else ["—"] * RUNS
        table.append([label, *cells, size])

    widths = [max(len(row[col]) for row in table) for col in range(len(headers))]

    def fmt(row: list[str]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))

    print()
    print(fmt(table[0]))
    print("  ".join("-" * w for w in widths))
    for row in table[1:]:
        print(fmt(row))
    print()
    print(f"(first run = cold / populates caches; runs 2-{RUNS} = warm)")


if __name__ == "__main__":
    main()
