"""Generic canary executor — co-located with the ``agent_scan.canary`` specs, run by an external harness.

This is **test/CI tooling**, not shipped in the ``agent_scan`` wheel: it lives under ``tests/`` and is put
on ``PYTHONPATH`` by the runner (agent-scan's own tests) and by the agent-scan-backoffice canary (which
clones this repo and runs ``PYTHONPATH=<clone>/tests``). It drives the real agent binary to write its
on-disk state using the imported canary spec, runs agent-scan's ``inspect``, and compares the result to
the canary's declared ``expected()`` items.

:func:`run_agent` is **param-driven**: the caller (a thin CLI in the backoffice) parses argv / reads the
environment and passes typed values in. Nothing here reads ``sys.argv`` or ``$<AGENT>_BIN`` — the seed
commands and paths come from the canary spec and the caller's arguments, so the executable/paths that
reach ``subprocess``/``shutil`` are not taint sources within this project.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from .baseline import ComparisonResult, compare, format_report
from .normalize import build_inventory

if TYPE_CHECKING:
    from agent_scan.canary import AgentCanary, ExpectedItem

# The inspect command when no override is given AND no source agent-scan is wired in: the published
# release. When agent-scan IS importable, _resolve_scan_cmd auto-selects the source `snyk-agent-scan`
# console script instead, so inspect tracks the specs.
DEFAULT_SCAN_CMD = ["uvx", "snyk-agent-scan@latest"]

# Every agent the canary supports, mapped from the friendly --agent key to the discoverer name that keys
# agent_scan.canary.CANARIES. The specs are co-located with the discoverers in agent-scan (shipped in the
# wheel and imported by name); this runner is the test-time interpreter of them.
CANARY_AGENT_SCAN_NAME = {
    "claude": "claude code",
    "vscode": "vscode",
    "cursor": "cursor",
    "kiro": "kiro",
    "windsurf": "windsurf",
    "antigravity": "antigravity",
}

SUPPORTED_AGENTS = set(CANARY_AGENT_SCAN_NAME)


def resolve_agent_bin(configured: str, candidates: tuple[str, ...] = ()) -> str:
    """Resolve an agent binary to something exec'able.

    Try the configured name, then each candidate in order; for each, prefer a PATH hit
    (``shutil.which``) and otherwise an existing explicit/expanded path (``os.path.isfile``). If nothing
    is found, return *configured* unchanged so the caller's "could not exec `<name>`" warning still names
    the real binary instead of a silently-rewritten path.
    """
    for name in (configured, *candidates):
        on_path = shutil.which(name)
        if on_path:
            return on_path
        expanded = os.path.expandvars(os.path.expanduser(name))
        if os.path.isfile(expanded):
            return expanded
    return configured


def _install_fallbacks(scan_name: str) -> tuple[str, ...]:
    """Executor-side install-location fallbacks for an agent's CLI when the bare name isn't on the PATH
    this process captured at startup — deployment knowledge keyed by the agent-scan discoverer name."""
    if os.name == "nt":
        return {"windsurf": (r"%LOCALAPPDATA%\devin\cli\bin\devin.exe",)}.get(scan_name, ())
    return {"claude code": ("~/.local/bin/claude",)}.get(scan_name, ())


def _resolve_canary_bin(canary: AgentCanary, *, bin_override: str | None = None) -> str:
    """Resolve *canary*'s agent binary from its declared ``bin_candidates`` (agent-scan owns the CLI
    names) plus an optional explicit *bin_override* (the caller supplies this from ``--bin`` / ``$<AGENT>_BIN``)
    and this executor's :func:`_install_fallbacks`."""
    names = tuple(canary.bin_candidates) or (canary.name,)
    if bin_override:
        names = (bin_override, *names)
    fallbacks = (*names[1:], *_install_fallbacks(canary.name))
    return resolve_agent_bin(names[0], fallbacks)


def _load_canary(agent: str) -> AgentCanary | None:
    """Return agent-scan's ``AgentCanary`` for the friendly *agent* key (from :mod:`agent_scan.canary`),
    or None when the key is unknown or agent-scan isn't importable."""
    scan_name = CANARY_AGENT_SCAN_NAME.get(agent)
    if scan_name is None:
        return None
    try:
        from agent_scan.canary import CANARIES
    except ImportError:
        return None
    return CANARIES.get(scan_name)


def _run(cmd: list[str], *, home: Path, cwd: Path | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # Point the home at our isolated dir on both POSIX (HOME) and Windows (USERPROFILE).
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env.pop("CLAUDE_CONFIG_DIR", None)  # keep the agent + agent-scan agreeing on the home's .claude{,.json}
    print(f"$ {' '.join(cmd)}  (HOME={home}, cwd={cwd or os.getcwd()})", flush=True)
    # stdin=DEVNULL: `inspect` prompts for per-server consent; DEVNULL gives an immediate EOF so consent
    # auto-declines (servers aren't started, but they're still discovered — which is all we assert).
    return subprocess.run(
        cmd,
        env=env,
        cwd=str(cwd) if cwd else None,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


class SeedError(RuntimeError):
    """A required (``non_fatal=False``) seed command failed — the canary leg is invalid, so fail fast."""


def _run_seed_command(cmd, *, home: Path, project: Path) -> None:
    """Run one canary ``SeedCommand`` against the fake home. ``cmd.non_fatal`` is load-bearing: a
    best-effort step that fails warns and continues, while a required seed that fails raises SeedError."""
    cwd = project if cmd.run_in_project else None
    label = " ".join(cmd.argv)
    try:
        result = _run(list(cmd.argv), home=home, cwd=cwd, timeout=cmd.timeout)
    except OSError as exc:
        if cmd.non_fatal:
            print(f"note: best-effort `{cmd.argv[0]}` could not exec ({exc}); continuing.", file=sys.stderr)
            return
        raise SeedError(f"required seed `{label}` could not exec `{cmd.argv[0]}`: {exc}") from exc
    if result.returncode == 0:
        return
    if cmd.non_fatal:
        print(f"note: best-effort `{label}` exited {result.returncode}; continuing.", file=sys.stderr)
        return
    raise SeedError(
        f"required seed `{label}` exited {result.returncode} — enforced scope cannot be seeded.\n"
        f"stdout:\n{result.stdout[-1500:]}\nstderr:\n{result.stderr[-1500:]}"
    )


def _canary_fixture_root() -> Path:
    """The on-disk ``agent_scan.canary`` package dir — the root every ``FixtureFile.src`` resolves under.
    Split out so tests can point it at a temp tree without a real agent-scan checkout."""
    import agent_scan.canary as canary_pkg

    return Path(canary_pkg.__file__).resolve().parent


def _materialize_fixtures(canary: AgentCanary, project: Path) -> None:
    """Copy every scope's committed fixtures (``scope.files()``) into the project — for scopes no CLI
    writes. Run BEFORE any seed command (a fixture ``.mcp.json`` must be on disk when ``claude mcp add -s
    project`` merges into it). ``FixtureFile.src`` resolves under the ``agent_scan.canary`` package dir;
    ``dest`` lands under the project. Both ends are confined to their root (realpath + commonpath) so a
    malformed spec can't read/write outside them via ``..``."""
    fixtures = [f for scope in canary.scopes for f in scope.files()]
    if not fixtures:
        return
    root = os.path.realpath(_canary_fixture_root())
    project_root = os.path.realpath(project)
    for f in fixtures:
        src = os.path.realpath(os.path.join(root, *f.src.split("/")))
        dest = os.path.realpath(os.path.join(project_root, f.dest))
        if os.path.commonpath([root, src]) != root:
            raise ValueError(f"fixture src escapes the canary package dir: {f.src!r}")
        if os.path.commonpath([project_root, dest]) != project_root:
            raise ValueError(f"fixture dest escapes the project dir: {f.dest!r}")
        src_p, dest_p = Path(src), Path(dest)
        dest_p.parent.mkdir(parents=True, exist_ok=True)
        if src_p.is_dir():
            shutil.copytree(src_p, dest_p, dirs_exist_ok=True)
        else:
            shutil.copy2(src_p, dest_p)


def _prepare_via_canary(canary: AgentCanary, home: Path, project: Path, agent_bin: str) -> None:
    """Drive the real agent using its imported canary: materialize committed fixtures, then run each
    scope's seed commands against the fake home with the (already-resolved) *agent_bin*."""
    from agent_scan.canary import CanaryContext

    project.mkdir(parents=True, exist_ok=True)
    _materialize_fixtures(canary, project)
    ctx = CanaryContext(home=home, project=project, bin=agent_bin)
    for scope in canary.scopes:
        for cmd in scope.commands(ctx):
            _run_seed_command(cmd, home=home, project=project)
    for gap in canary.gaps():
        print(f"  gap [{gap.label}] mirrored but not canaried — {gap.why}")


def run_scan(home: Path, *, scan_cmd: list[str] | None = None, server_timeout: int = 5) -> dict:
    """Run ``<scan_cmd> inspect --json`` against *home* and return the parsed output dict.
    ``--no-bootstrap`` keeps it local and backend-free so the signal is purely about what the agent wrote."""
    cmd = [
        *(scan_cmd or DEFAULT_SCAN_CMD),
        "inspect",
        "--json",
        "--no-bootstrap",
        "--server-timeout",
        str(server_timeout),
    ]
    proc = _run(cmd, home=home, timeout=300)
    if not proc.stdout.strip():
        raise RuntimeError(
            f"agent-scan produced no JSON on stdout (exit {proc.returncode}).\nstderr tail:\n{proc.stderr[-2000:]}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise RuntimeError(f"could not parse agent-scan JSON: {exc}\nstdout head:\n{proc.stdout[:2000]}") from exc


def evaluate(
    inspect_output: dict,
    *,
    home: Path,
    project: Path,
    expected: list[ExpectedItem],
) -> ComparisonResult:
    """Compare the inspect output against the canary's declared expectations (``canary.expected()``)."""
    inventory = build_inventory(inspect_output, home=str(home), project=str(project))
    return compare(expected, inventory)


def _agent_scan_importable() -> bool:
    """True if ``agent_scan`` imports in this interpreter — i.e. a source checkout was wired in via
    ``uv run --with <clone>``, which also exposes the ``snyk-agent-scan`` console script on PATH."""
    try:
        return importlib.util.find_spec("agent_scan") is not None
    except (ImportError, ValueError):
        return False


def resolve_scan_cmd(scan_cmd_override: str | None) -> list[str]:
    """The agent-scan command for inspect. An explicit *scan_cmd_override* wins; else the source
    ``snyk-agent-scan`` console script when ``agent_scan`` is importable; else the published release."""
    if scan_cmd_override:
        return scan_cmd_override.split()
    if _agent_scan_importable():
        print(
            "inspect: agent_scan importable from source — using the `snyk-agent-scan` console script "
            "(tracks the canary specs); pass an explicit scan command to override.",
            file=sys.stderr,
        )
        return ["snyk-agent-scan"]
    return list(DEFAULT_SCAN_CMD)


def run_agent(
    agent: str,
    *,
    scan_cmd_override: str | None = None,
    bin_override: str | None = None,
    fixed_home: str | None = None,
    project_override: str | None = None,
    server_timeout: int = 5,
    keep: bool = False,
) -> bool:
    """Canary one *agent* (a friendly key in :data:`CANARY_AGENT_SCAN_NAME`) in an isolated home.

    Param-driven: the caller supplies the inspect command, an optional binary override, and the
    home/project dirs (``fixed_home``/``project_override`` only for a single-agent run). Returns True if
    the agent's declared ``expected()`` items are all detected.
    """
    created_temp = fixed_home is None
    # Normalize the operator-supplied dirs through realpath before anything is built/scanned/cleaned.
    home = Path(os.path.realpath(fixed_home or tempfile.mkdtemp(prefix=f"canary-{agent}-")))
    home.mkdir(parents=True, exist_ok=True)
    project = (
        Path(os.path.realpath(project_override))
        if (project_override and fixed_home)
        else home / "work" / "dummy-project"
    )

    canary = _load_canary(agent)
    if canary is None:
        print(
            f"\n[{agent}] FAIL — could not import agent_scan.canary; run with `uv run --with <agent-scan "
            "checkout>` (or install agent-scan) so the in-dev canary specs are importable.\n",
            file=sys.stderr,
        )
        return False
    expected = canary.expected()
    scan_cmd = resolve_scan_cmd(scan_cmd_override)

    print(f"== agent-scan canary [{agent}] ==\nHOME={home}\nproject={project}\nexpected items={len(expected)}\n")
    try:
        agent_bin = _resolve_canary_bin(canary, bin_override=bin_override)
        _prepare_via_canary(canary, home, project, agent_bin)
        try:
            inspect_output = run_scan(home, scan_cmd=scan_cmd, server_timeout=server_timeout)
        except (RuntimeError, subprocess.SubprocessError) as exc:
            print(f"\n[{agent}] FAIL — agent-scan inspect did not produce a usable result:\n{exc}\n", file=sys.stderr)
            return False
        result = evaluate(inspect_output, home=home, project=project, expected=expected)
        print(f"\n[{agent}] " + format_report(result) + "\n")
        return result.ok
    except SeedError as exc:
        print(f"\n[{agent}] FAIL — required seed failed before the scan:\n{exc}\n", file=sys.stderr)
        return False
    finally:
        if created_temp and not keep:
            shutil.rmtree(home, ignore_errors=True)
