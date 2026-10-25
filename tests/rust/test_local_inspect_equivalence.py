"""Executable compatibility checks for the supported Rust local-inspect slice.

Run with AGENT_SCAN_RUST_BINARY pointing to a release-built binary. The normal
Python test suite skips these checks when Rust is not being validated.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUST_BINARY = os.environ.get("AGENT_SCAN_RUST_BINARY")
pytestmark = pytest.mark.skipif(
    not RUST_BINARY, reason="set AGENT_SCAN_RUST_BINARY to validate the Rust local-inspect slice"
)


def _run(command: list[str], environment: dict[str, str]) -> dict:
    completed = subprocess.run(command, cwd=ROOT, env=environment, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def _environment(tmp_path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(tmp_path / "home"),
            "SNYK_TOKEN": "",
            # The Rust binary invokes this exact installed implementation as a
            # private redaction worker. This is the security compatibility seam.
            "AGENT_SCAN_PYTHON": sys.executable,
        }
    )
    return environment


def _python_inspect(path: Path, environment: dict[str, str]) -> dict:
    return _run([sys.executable, "-m", "agent_scan.run", "inspect", "--skills", "--json", str(path)], environment)


def _rust_inspect(path: Path, environment: dict[str, str]) -> dict:
    assert RUST_BINARY is not None
    return _run([RUST_BINARY, "inspect", "--skills", "--json", str(path)], environment)


def test_matches_python_for_repository_skill_corpus(tmp_path: Path) -> None:
    """All valid test skills retain Python's JSON content and ordering."""
    environment = _environment(tmp_path)
    corpus = ROOT / "tests" / "skills"
    assert _rust_inspect(corpus, environment) == _python_inspect(corpus, environment)


def test_matches_python_and_removes_a_detect_secrets_fixture(tmp_path: Path) -> None:
    """Regression: Rust must never replace Python redaction with an approximation."""
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: example\ndescription: redaction test\n---\n")
    secret = "AKIAIOSFODNN7EXAMPLE"
    (skill / "instructions.md").write_text(f"credential = {secret}\n")
    environment = _environment(tmp_path)

    python_result = _python_inspect(skill, environment)
    rust_result = _rust_inspect(skill, environment)

    assert rust_result == python_result
    assert secret not in json.dumps(rust_result)
    assert "REDACTED_SECRET_AWSKEYDETECTOR" in json.dumps(rust_result)


@pytest.mark.skipif(os.name != "posix", reason="the additive Rust cache uses Unix target identity")
def test_aliases_retain_python_attribution_and_content(tmp_path: Path) -> None:
    source = tmp_path / "source"
    skill = source / "example"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: example\ndescription: alias test\n---\n")
    (skill / "instructions.md").write_text("credential = AKIAIOSFODNN7EXAMPLE\n")
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.symlink_to(source, target_is_directory=True)
    second.symlink_to(source, target_is_directory=True)
    environment = _environment(tmp_path)

    assert _rust_inspect(first, environment) == _python_inspect(first, environment)
    assert _rust_inspect(second, environment) == _python_inspect(second, environment)
    # A single Rust invocation shares the target-identity cache while preserving
    # both lexical explicit paths in the output, just as Python does.
    assert RUST_BINARY is not None
    rust_both = _run([RUST_BINARY, "inspect", "--skills", "--json", str(first), str(second)], environment)
    python_both = _run(
        [sys.executable, "-m", "agent_scan.run", "inspect", "--skills", "--json", str(first), str(second)],
        environment,
    )
    assert rust_both == python_both
    assert list(rust_both) == [str(first), str(second)]


def test_redaction_worker_failure_emits_no_output(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: example\ndescription: failure test\n---\n")
    environment = _environment(tmp_path)
    environment["AGENT_SCAN_PYTHON"] = str(tmp_path / "missing-python")

    assert RUST_BINARY is not None
    completed = subprocess.run(
        [RUST_BINARY, "inspect", "--skills", "--json", str(skill)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "redaction worker" in completed.stderr
