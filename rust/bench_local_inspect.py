#!/usr/bin/env python3
"""Fresh-process benchmark for the additive Rust local-inspect vertical slice.

This is intentionally stdlib-only. It makes no network/API request and does not
flush the global filesystem cache. Redirect its JSON stdout to retain raw samples.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "tests" / "skills"
SUBSET = ("algorithmic-art", "canvas-design", "mcp-builder")


def summary(samples: list[float]) -> dict[str, object]:
    ordered = sorted(samples)
    return {
        "n": len(samples),
        "median_s": round(statistics.median(samples), 4),
        "mean_s": round(statistics.mean(samples), 4),
        "min_s": round(min(samples), 4),
        "max_s": round(max(samples), 4),
        "p95_s": round(ordered[math.ceil(len(samples) * 0.95) - 1], 4),
        "stdev_s": round(statistics.stdev(samples), 4) if len(samples) > 1 else 0,
        "samples_s": [round(sample, 4) for sample in samples],
    }


def run(command: list[str], environment: dict[str, str]) -> float:
    start = time.perf_counter()
    completed = subprocess.run(command, cwd=ROOT, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    elapsed = time.perf_counter() - start
    if completed.returncode:
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)}")
    return elapsed


def repeated(command: list[str], environment: dict[str, str], samples: int) -> dict[str, object]:
    return summary([run(command, environment) for _ in range(samples)])


def corpus_shape(root: Path) -> dict[str, int]:
    files = [path for path in root.rglob("*") if path.is_file()]
    skills = [
        path
        for path in root.iterdir()
        if path.is_dir() and any(child.name.lower() == "skill.md" for child in path.iterdir())
    ]
    return {"skills": len(skills), "files": len(files), "bytes": sum(path.stat().st_size for path in files)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-cli", default=str(ROOT / ".venv/bin/snyk-agent-scan"))
    parser.add_argument("--python", default=str(ROOT / ".venv/bin/python"))
    parser.add_argument("--rust", default=str(ROOT / "target/release/snyk-agent-scan-rust"))
    parser.add_argument("--scan-samples", type=int, default=12)
    parser.add_argument("--startup-samples", type=int, default=30)
    parser.add_argument("--alias-samples", type=int, default=10)
    args = parser.parse_args()

    for executable in (args.python_cli, args.python, args.rust):
        if not Path(executable).is_file():
            parser.error(f"missing executable: {executable}")

    with tempfile.TemporaryDirectory(prefix="agent-scan-rust-bench-") as temp:
        temp_path = Path(temp)
        home = temp_path / "home"
        home.mkdir()
        environment = os.environ | {
            "HOME": str(home),
            "SNYK_TOKEN": "",
            "NO_COLOR": "1",
            "AGENT_SCAN_PYTHON": args.python,
        }
        python_full = [args.python_cli, "inspect", "--skills", "--json", str(SKILLS)]
        rust_full = [args.rust, "inspect", "--skills", "--json", str(SKILLS)]

        source = temp_path / "source"
        source.mkdir()
        for name in SUBSET:
            (source / name).symlink_to(SKILLS / name, target_is_directory=True)
        aliases = []
        for number in range(1, 9):
            alias = temp_path / f"project-{number}"
            alias.symlink_to(source, target_is_directory=True)
            aliases.append(str(alias))
        python_alias = [args.python_cli, "inspect", "--skills", "--json", *aliases]
        rust_alias = [args.rust, "inspect", "--skills", "--json", *aliases]

        alias_python: list[float] = []
        alias_rust: list[float] = []
        # Interleave variants to avoid attributing all background/thermal drift
        # to one implementation.
        for _ in range(args.alias_samples):
            alias_python.append(run(python_alias, environment))
            alias_rust.append(run(rust_alias, environment))

        output = {
            "method": {
                "measurement": "time.perf_counter around one newly spawned process; stdout/stderr to DEVNULL",
                "cache": "filesystem cache intentionally warm; no privileged global cache flush",
                "network": "none; explicit inspect paths only",
                "corpus": corpus_shape(SKILLS),
                "alias_corpus": {
                    "source_skills": list(SUBSET),
                    "aliases": 8,
                    "expected_skill_records": len(SUBSET) * 8,
                },
            },
            "machine": {
                "platform": platform.platform(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "commands": {
                "python_help": [args.python_cli, "--help"],
                "rust_help": [args.rust, "--help"],
                "python_full": python_full,
                "rust_full": rust_full,
                "python_alias": python_alias,
                "rust_alias": rust_alias,
            },
            "results": {
                "python_help": repeated([args.python_cli, "--help"], environment, args.startup_samples),
                "rust_help": repeated([args.rust, "--help"], environment, args.startup_samples),
                "python_full": repeated(python_full, environment, args.scan_samples),
                "rust_full": repeated(rust_full, environment, args.scan_samples),
                "python_alias": summary(alias_python),
                "rust_alias": summary(alias_rust),
            },
        }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
