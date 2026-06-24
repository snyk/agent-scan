"""Tests for the co-located canary executor (``canary_runner``).

Covers the generic interpreter against the REAL :data:`agent_scan.canary.CANARIES` (every ``SeedCommand``
dispatched, every ``FixtureFile`` materialized), the param-driven ``run_agent`` orchestration (offline,
with fakes), inventory normalization, and the expected-set comparison. ``canary_runner`` imports as a
top-level package via ``pythonpath = ["tests"]`` (the same name the backoffice imports it under).
"""

from __future__ import annotations

import json
import subprocess
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from canary_runner import (
    SUPPORTED_AGENTS,
    SeedError,
    build_inventory,
    compare,
    evaluate,
    format_report,
    resolve_agent_bin,
    resolve_scan_cmd,
    run_agent,
)
from canary_runner.normalize import HOME_PLACEHOLDER, PROJECT_PLACEHOLDER, InventoryItem, normalize_path
from canary_runner.runner import (
    _install_fallbacks,
    _load_canary,
    _prepare_via_canary,
    _resolve_canary_bin,
    _run,
)

from agent_scan.canary import CANARIES, CanaryContext, SeedCommand

_DATA = Path(__file__).resolve().parents[1] / "canary_runner" / "data"
SAMPLE_HOME = "/tmp/canary-fakehome"
SAMPLE_PROJECT = "/tmp/canary-fakehome/projects/dummy-project"


@dataclass(frozen=True)
class _Exp:
    """Minimal stand-in for an expected item — the field set compare()/evaluate() consume."""

    kind: str
    name: str
    scope: str
    path_contains: tuple[str, ...] = field(default=())


# --- normalize ---------------------------------------------------------------------


def test_normalize_path_folds_home_and_macos_private_realpath():
    assert (
        normalize_path(f"{SAMPLE_HOME}/.claude/skills/x", SAMPLE_HOME, SAMPLE_PROJECT)
        == f"{HOME_PLACEHOLDER}/.claude/skills/x"
    )
    assert (
        normalize_path(f"/private{SAMPLE_HOME}/.claude/skills/x", SAMPLE_HOME, SAMPLE_PROJECT)
        == f"{HOME_PLACEHOLDER}/.claude/skills/x"
    )


def test_normalize_path_prefers_project_over_home_when_nested():
    raw = f"{SAMPLE_PROJECT}/.claude/skills/canary-project-skill"
    assert (
        normalize_path(raw, SAMPLE_HOME, SAMPLE_PROJECT) == f"{PROJECT_PLACEHOLDER}/.claude/skills/canary-project-skill"
    )


def test_normalize_path_leaves_unrelated_paths_unchanged():
    assert normalize_path("/usr/local/bin/foo", SAMPLE_HOME, SAMPLE_PROJECT) == "/usr/local/bin/foo"


def test_build_inventory_dedups_and_flattens():
    out = {
        "/a": {"servers": [{"name": "srv", "server": {"type": "stdio"}}]},
        "/b": {"servers": [{"name": "srv", "server": {"type": "stdio"}}]},  # dup
    }
    inv = build_inventory(out, home=SAMPLE_HOME, project=SAMPLE_PROJECT)
    assert inv == [InventoryItem("mcp", "srv", "stdio", None)]


# --- compare / format --------------------------------------------------------------

EXPECTED = [
    _Exp("mcp", "canary-global-mcp", "mcp/global"),
    _Exp("skill", "canary-plugin-skill", "skill/plugin", ("$HOME/.claude/plugins/", "skills/canary-plugin-skill")),
]


def _matching_inventory() -> list[InventoryItem]:
    return [
        InventoryItem("mcp", "canary-global-mcp", "stdio", None),
        InventoryItem(
            "skill",
            "canary-plugin-skill",
            "skill",
            f"{HOME_PLACEHOLDER}/.claude/plugins/cache/mkt/p/skills/canary-plugin-skill",
        ),
    ]


def test_compare_full_match_is_ok():
    result = compare(EXPECTED, _matching_inventory())
    assert result.ok and result.missing == [] and len(result.matched) == 2


def test_compare_missing_item_fails_and_names_scope():
    inv = [i for i in _matching_inventory() if i.name != "canary-global-mcp"]
    result = compare(EXPECTED, inv)
    assert not result.ok
    assert [m.name for m in result.missing] == ["canary-global-mcp"]
    assert result.missing[0].scope == "mcp/global"


def test_compare_extras_are_informational_not_failure():
    inv = [*_matching_inventory(), InventoryItem("skill", "extra", "skill", f"{HOME_PLACEHOLDER}/x.md")]
    result = compare(EXPECTED, inv)
    assert result.ok and [e.name for e in result.extras] == ["extra"]


def test_compare_wrong_path_counts_as_missing():
    inv = _matching_inventory()
    inv[1] = InventoryItem("skill", "canary-plugin-skill", "skill", f"{HOME_PLACEHOLDER}/.claude/skills/wrong")
    assert "canary-plugin-skill" in [m.name for m in compare(EXPECTED, inv).missing]


def test_format_report_mentions_missing_and_pass():
    rep_fail = format_report(compare(EXPECTED, [i for i in _matching_inventory() if i.name != "canary-global-mcp"]))
    assert "FAIL" in rep_fail and "canary-global-mcp" in rep_fail and "mcp/global" in rep_fail
    assert "PASS" in format_report(compare(EXPECTED, _matching_inventory()))


# --- _run_seed_command -------------------------------------------------------------


def _seed(argv, *, non_fatal, run_in_project=False, timeout=30):
    return SeedCommand(argv=argv, run_in_project=run_in_project, timeout=timeout, non_fatal=non_fatal)


def test_run_seed_command_raises_on_required_failure(monkeypatch, tmp_path):
    from canary_runner.runner import _run_seed_command

    monkeypatch.setattr(
        "canary_runner.runner._run", lambda cmd, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr="boom")
    )
    with pytest.raises(SeedError):
        _run_seed_command(_seed(("claude", "mcp", "add"), non_fatal=False), home=tmp_path, project=tmp_path)


def test_run_seed_command_warns_but_continues_on_best_effort(monkeypatch, tmp_path, capsys):
    from canary_runner.runner import _run_seed_command

    monkeypatch.setattr(
        "canary_runner.runner._run", lambda cmd, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr="boom")
    )
    _run_seed_command(_seed(("claude", "plugin", "install", "x"), non_fatal=True), home=tmp_path, project=tmp_path)
    assert "best-effort" in capsys.readouterr().err


def test_run_seed_command_raises_when_required_binary_missing(monkeypatch, tmp_path):
    from canary_runner.runner import _run_seed_command

    def _missing(cmd, **kw):
        raise FileNotFoundError("no such binary")

    monkeypatch.setattr("canary_runner.runner._run", _missing)
    with pytest.raises(SeedError):
        _run_seed_command(_seed(("claude", "mcp", "add"), non_fatal=False), home=tmp_path, project=tmp_path)


# --- _prepare_via_canary glue (offline, fake canary; real CanaryContext) -----------


def _scope(label, builder, *, files=()):
    return types.SimpleNamespace(label=label, commands=builder, files=lambda: list(files))


def _fake_canary(scopes, *, gaps=()):
    return types.SimpleNamespace(scopes=scopes, gaps=lambda: list(gaps), name="claude code", bin_candidates=("claude",))


def test_prepare_via_canary_dispatches_in_order_with_given_bin_and_prints_gaps(monkeypatch, tmp_path, capsys):
    recorded = []
    monkeypatch.setattr(
        "canary_runner.runner._run",
        lambda cmd, *, home, cwd=None, timeout=None: recorded.append((tuple(cmd), cwd, timeout))
        or types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    home, project = tmp_path / "home", tmp_path / "home" / "proj"
    canary = _fake_canary(
        [
            _scope("mcp/global", lambda ctx: [_seed((ctx.bin, "mcp", "add", "-s", "user", "g"), non_fatal=False)]),
            _scope(
                "mcp/project",
                lambda ctx: [
                    _seed(
                        (ctx.bin, "mcp", "add", "-s", "project", "p"), non_fatal=False, run_in_project=True, timeout=90
                    )
                ],
            ),
        ],
        gaps=[types.SimpleNamespace(label="skill/global", why="no claude CLI creates it")],
    )
    _prepare_via_canary(canary, home, project, "/resolved/claude")
    assert project.is_dir()
    assert recorded == [
        (("/resolved/claude", "mcp", "add", "-s", "user", "g"), None, 30),
        (("/resolved/claude", "mcp", "add", "-s", "project", "p"), project, 90),
    ]
    out = capsys.readouterr().out
    assert "gap [skill/global]" in out and "no claude CLI creates it" in out


def test_prepare_via_canary_materializes_fixtures_before_commands(monkeypatch, tmp_path):
    pkg = tmp_path / "pkg"
    (pkg / "fixtures" / "proj" / ".claude" / "skills" / "s").mkdir(parents=True)
    (pkg / "fixtures" / "proj" / ".claude" / "skills" / "s" / "SKILL.md").write_text("---\nname: s\n---\n")
    (pkg / "fixtures" / "proj" / ".mcp.json").write_text("{}")
    monkeypatch.setattr("canary_runner.runner._canary_fixture_root", lambda: pkg)
    home, project = tmp_path / "home", tmp_path / "home" / "proj"
    present = []
    monkeypatch.setattr(
        "canary_runner.runner._run",
        lambda cmd, *, home, cwd=None, timeout=None: present.append((project / ".mcp.json").is_file())
        or types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    canary = _fake_canary(
        [
            _scope(
                "skill/project",
                lambda ctx: [],
                files=[types.SimpleNamespace(src="fixtures/proj/.claude/skills/s", dest=".claude/skills/s")],
            ),
            _scope(
                "mcp/file-fixture",
                lambda ctx: [],
                files=[types.SimpleNamespace(src="fixtures/proj/.mcp.json", dest=".mcp.json")],
            ),
            _scope("mcp/file", lambda ctx: [_seed((ctx.bin, "mcp", "add"), non_fatal=False, run_in_project=True)]),
        ]
    )
    _prepare_via_canary(canary, home, project, "claude")
    assert (project / ".claude" / "skills" / "s" / "SKILL.md").is_file()
    assert (project / ".mcp.json").is_file()
    assert present == [True]  # fixture on disk before the command ran


def test_prepare_via_canary_rejects_dest_escaping_project(monkeypatch, tmp_path):
    pkg = tmp_path / "pkg"
    (pkg / "fixtures").mkdir(parents=True)
    (pkg / "fixtures" / "f.txt").write_text("x")
    monkeypatch.setattr("canary_runner.runner._canary_fixture_root", lambda: pkg)
    monkeypatch.setattr(
        "canary_runner.runner._run", lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr="")
    )
    evil = _fake_canary(
        [_scope("x", lambda ctx: [], files=[types.SimpleNamespace(src="fixtures/f.txt", dest="../escape.txt")])]
    )
    with pytest.raises(ValueError, match="escapes the project"):
        _prepare_via_canary(evil, tmp_path / "home", tmp_path / "home" / "proj", "claude")
    assert not (tmp_path / "escape.txt").exists()


def test_prepare_via_canary_propagates_seed_error_and_stops(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "canary_runner.runner._run", lambda cmd, **kw: types.SimpleNamespace(returncode=1, stdout="", stderr="boom")
    )
    later = []
    canary = _fake_canary(
        [
            _scope("mcp/global", lambda ctx: [_seed((ctx.bin, "mcp", "add"), non_fatal=False)]),
            _scope("mcp/project", lambda ctx: later.append(True) or []),
        ]
    )
    with pytest.raises(SeedError):
        _prepare_via_canary(canary, tmp_path / "h", tmp_path / "h" / "p", "claude")
    assert later == []


# --- dispatch contract against the REAL specs --------------------------------------


@pytest.mark.parametrize("canary", list(CANARIES.values()), ids=lambda c: c.name)
def test_interpreter_dispatches_every_seed_command(canary, monkeypatch, tmp_path):
    recorded: list[tuple] = []
    monkeypatch.setattr(
        "canary_runner.runner.subprocess.run",
        lambda cmd, *_a, **kw: recorded.append((tuple(cmd), kw.get("cwd"), kw.get("timeout")))
        or subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr=""),
    )
    home, project = tmp_path / "home", tmp_path / "proj"
    _prepare_via_canary(canary, home, project, "fake-bin")
    ctx = CanaryContext(home=home, project=project, bin="fake-bin")
    expected = [
        (tuple(c.argv), str(project) if c.run_in_project else None, c.timeout)
        for s in canary.scopes
        for c in s.commands(ctx)
    ]
    assert recorded == expected, f"{canary.name}: interpreter did not dispatch the spec's commands verbatim"


@pytest.mark.parametrize("canary", list(CANARIES.values()), ids=lambda c: c.name)
def test_interpreter_materializes_every_fixture_file(canary, monkeypatch, tmp_path):
    monkeypatch.setattr(
        "canary_runner.runner.subprocess.run",
        lambda cmd, *_a, **_kw: subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr=""),
    )
    home, project = tmp_path / "home", tmp_path / "proj"
    _prepare_via_canary(canary, home, project, "fake-bin")
    for f in [f for s in canary.scopes for f in s.files()]:
        assert (project / f.dest).exists(), f"{canary.name}: fixture not materialized at {f.dest}"


# --- run_agent orchestration (offline) ---------------------------------------------


def test_run_agent_fails_on_seed_error(monkeypatch):
    monkeypatch.setattr(
        "canary_runner.runner._load_canary",
        lambda a: types.SimpleNamespace(expected=lambda: [], name="claude code", bin_candidates=("claude",)),
    )
    monkeypatch.setattr("canary_runner.runner._resolve_canary_bin", lambda *a, **k: "claude")
    monkeypatch.setattr("canary_runner.runner.resolve_scan_cmd", lambda _o: ["noop"])
    monkeypatch.setattr(
        "canary_runner.runner._prepare_via_canary", lambda *a, **k: (_ for _ in ()).throw(SeedError("x"))
    )
    monkeypatch.setattr(
        "canary_runner.runner.run_scan", lambda *a, **k: pytest.fail("scan must not run after SeedError")
    )
    assert run_agent("claude", fixed_home=None) is False


def test_run_agent_fails_cleanly_on_scan_error(monkeypatch, capsys):
    monkeypatch.setattr(
        "canary_runner.runner._load_canary",
        lambda a: types.SimpleNamespace(expected=lambda: [], name="claude code", bin_candidates=("claude",)),
    )
    monkeypatch.setattr("canary_runner.runner._resolve_canary_bin", lambda *a, **k: "claude")
    monkeypatch.setattr("canary_runner.runner.resolve_scan_cmd", lambda _o: ["noop"])
    monkeypatch.setattr("canary_runner.runner._prepare_via_canary", lambda *a, **k: None)
    monkeypatch.setattr(
        "canary_runner.runner.run_scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no output"))
    )
    assert run_agent("claude", fixed_home=None) is False
    assert "did not produce a usable result" in capsys.readouterr().err


def test_run_agent_returns_none_canary_as_failure(monkeypatch, capsys):
    monkeypatch.setattr("canary_runner.runner._load_canary", lambda a: None)
    assert run_agent("claude", fixed_home=None) is False
    assert "could not import agent_scan.canary" in capsys.readouterr().err


def test_supported_agents_are_all_canary_keys():
    assert {"claude", "vscode", "cursor", "kiro", "windsurf", "antigravity"} == SUPPORTED_AGENTS


def test_load_canary_unknown_agent_is_none():
    assert _load_canary("emacs") is None


# --- bin / scan-cmd resolution -----------------------------------------------------


def test_resolve_agent_bin_prefers_path_then_existing_file(monkeypatch, tmp_path):
    monkeypatch.setattr("canary_runner.runner.shutil.which", lambda c: "/usr/bin/x" if c == "onpath" else None)
    assert resolve_agent_bin("onpath", ()) == "/usr/bin/x"
    exe = tmp_path / "x.exe"
    exe.write_text("b")
    assert resolve_agent_bin("missing", (str(exe),)) == str(exe)
    assert resolve_agent_bin("nope", ("/does/not/exist",)) == "nope"


def test_resolve_canary_bin_drives_off_bin_candidates_and_override(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        "canary_runner.runner.resolve_agent_bin",
        lambda c, cand=(): seen.update(configured=c, candidates=tuple(cand)) or "/x",
    )
    canary = types.SimpleNamespace(name="gemini", bin_candidates=("gemini-cli", "gemini"))
    _resolve_canary_bin(canary)
    assert seen["configured"] == "gemini-cli" and "gemini" in seen["candidates"]
    assert "~/.local/bin/claude" not in seen["candidates"]
    _resolve_canary_bin(
        types.SimpleNamespace(name="claude code", bin_candidates=("claude",)), bin_override="/custom/claude"
    )
    assert seen["configured"] == "/custom/claude"


def test_install_fallbacks_os_specific(monkeypatch):
    monkeypatch.setattr("canary_runner.runner.os.name", "posix")
    assert _install_fallbacks("claude code") == ("~/.local/bin/claude",) and _install_fallbacks("windsurf") == ()
    monkeypatch.setattr("canary_runner.runner.os.name", "nt")
    assert _install_fallbacks("windsurf") and _install_fallbacks("cursor") == ()


def test_resolve_scan_cmd_precedence(monkeypatch):
    assert resolve_scan_cmd("uvx snyk-agent-scan@1.2.3") == ["uvx", "snyk-agent-scan@1.2.3"]
    monkeypatch.setattr("canary_runner.runner._agent_scan_importable", lambda: True)
    assert resolve_scan_cmd(None) == ["snyk-agent-scan"]
    monkeypatch.setattr("canary_runner.runner._agent_scan_importable", lambda: False)
    assert resolve_scan_cmd(None) == ["uvx", "snyk-agent-scan@latest"]


# --- _run + evaluate on a real captured sample -------------------------------------


def test_run_feeds_devnull_stdin(tmp_path):
    proc = _run([sys.executable, "-c", "import sys; sys.stdin.read()"], home=tmp_path, timeout=15)
    assert proc.returncode == 0


def test_evaluate_pipeline_on_real_inspect_sample():
    sample = json.loads((_DATA / "inspect_sample_claude.json").read_text())
    expected = [
        _Exp("mcp", "canary-global-mcp", "mcp/global"),
        _Exp("mcp", "canary-project-inline-mcp", "mcp/project-inline"),
        _Exp("mcp", "canary-project-file-mcp", "mcp/project-file"),
        _Exp("mcp", "discord", "mcp/plugin"),
        _Exp("skill", "access", "skill/plugin", ("$HOME/.claude/plugins/", "skills/access")),
        _Exp("skill", "configure", "skill/plugin", ("$HOME/.claude/plugins/", "skills/configure")),
    ]
    result = evaluate(sample, home=SAMPLE_HOME, project=SAMPLE_PROJECT, expected=expected)
    assert result.ok and result.missing == [] and len(result.matched) == 6
