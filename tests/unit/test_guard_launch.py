"""Tests for agent_scan.guard_launch — the guard run <client> launcher (Option B)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_scan import guard_launch, identity


@pytest.fixture
def logged_in(tmp_path, monkeypatch):
    """Point HOME at a tmp dir and enroll a push key + default profile."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(identity, "IDENTITY_PATH", tmp_path / ".config" / "snyk-agent-guard" / "identity.json")
    monkeypatch.setattr(guard_launch, "_PROFILES_ROOT", tmp_path / ".config" / "snyk-agent-guard" / "profiles")
    identity.save_identity("pk-test-9999", "t-1", "http://localhost:9", "standard", "h", path=identity.IDENTITY_PATH)
    return tmp_path


def _run(client, profile=None):
    args = SimpleNamespace(guard_command="run", run_command=client, profile=profile, agent_args=[])
    captured = {}

    def fake_run(cmd, env=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return SimpleNamespace(returncode=0)

    with patch("agent_scan.guard_launch.subprocess.run", side_effect=fake_run):
        with patch("agent_scan.guard_launch.shutil.which", side_effect=lambda b: f"/usr/bin/{b}"):
            rc = guard_launch.run_launch(args)
    return rc, captured


def test_not_logged_in_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(identity, "IDENTITY_PATH", tmp_path / "absent.json")
    monkeypatch.delenv("PUSH_KEY", raising=False)
    args = SimpleNamespace(guard_command="run", run_command="claude", profile="strict", agent_args=[])
    assert guard_launch.run_launch(args) == 1


def test_claude_launches_with_settings_flag(logged_in):
    rc, cap = _run("claude", "strict")
    assert rc == 0
    # Launches the bare binary; config comes from a guard-owned CLAUDE_CONFIG_DIR (not --settings,
    # which would additively merge the user's allowedDomains).
    assert cap["cmd"] == ["/usr/bin/claude"]
    assert "--settings" not in cap["cmd"]
    config_dir = Path(cap["env"]["CLAUDE_CONFIG_DIR"])
    settings = json.loads((config_dir / "settings.json").read_text())
    assert settings["sandbox"]["enabled"] is True
    # push key from login is embedded in the hook command
    assert "pk-test-9999" in settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]


def _claude_settings(cap):
    return json.loads((Path(cap["env"]["CLAUDE_CONFIG_DIR"]) / "settings.json").read_text())


def test_profiles_are_isolated(logged_in):
    _, cap_strict = _run("claude", "strict")
    _, cap_perm = _run("claude", "permissive")
    base = logged_in / ".config" / "snyk-agent-guard" / "profiles" / "claude"
    assert (base / "strict" / "settings.json").exists()
    assert (base / "permissive" / "settings.json").exists()
    assert _claude_settings(cap_strict)["sandbox"]["network"]["allowedDomains"] == []
    assert _claude_settings(cap_perm)["sandbox"]["network"]["allowedDomains"] == ["*"]


def test_strict_sandbox_replaces_user_allowed_domains(logged_in, monkeypatch):
    """The leaking bug: a user's own ~/.claude/settings.json sandbox must NOT widen strict."""
    user_claude = logged_in / ".claude"
    user_claude.mkdir()
    (user_claude / "settings.json").write_text(
        json.dumps({"model": "opus", "sandbox": {"network": {"allowedDomains": ["github.com", "evil.com"]}}})
    )
    _, cap = _run("claude", "strict")
    settings = _claude_settings(cap)
    assert settings["sandbox"]["network"]["allowedDomains"] == []  # ours wins, user's domains gone
    assert settings["model"] == "opus"  # non-sandbox user settings preserved


def test_profile_defaults_to_login_choice(logged_in):
    _, cap = _run("claude", None)  # no --profile -> login default "standard"
    assert "github.com" in _claude_settings(cap)["sandbox"]["network"]["allowedDomains"]


def test_codex_uses_codex_home_env(logged_in):
    rc, cap = _run("codex", "strict")
    assert rc == 0
    assert cap["cmd"] == ["/usr/bin/codex"]
    codex_home = cap["env"]["CODEX_HOME"]
    assert codex_home.endswith("profiles/codex/strict")


def test_codex_seeds_via_symlinks_and_tolerates_dangling_links(logged_in):
    """Codex seeds CODEX_HOME with symlinks to ~/.codex; dangling links/bulky dirs don't break it."""
    user_codex = logged_in / ".codex"
    user_codex.mkdir()
    (user_codex / "auth.json").write_text("{}")  # real config -> symlinked through
    (user_codex / "config.toml").write_text('model = "o3"')  # guard-owned -> re-rendered, not symlinked
    (user_codex / "skills").mkdir()
    (user_codex / "skills" / "dangling").symlink_to(user_codex / "nonexistent")  # the original crash

    rc, cap = _run("codex", "strict")
    assert rc == 0

    home = Path(cap["env"]["CODEX_HOME"])
    assert (home / "auth.json").is_symlink()  # user config carried over by link
    assert (home / "config.toml").is_file() and not (home / "config.toml").is_symlink()  # guard-owned
    assert (home / "hooks.json").is_file() and not (home / "hooks.json").is_symlink()


def _codex_config(cap):
    import tomllib

    return tomllib.loads((Path(cap["env"]["CODEX_HOME"]) / "config.toml").read_text())


def test_codex_merges_user_config_preserving_model(logged_in):
    """The fix: model/providers carry over from ~/.codex/config.toml; guard owns only sandbox keys."""
    user_codex = logged_in / ".codex"
    user_codex.mkdir()
    (user_codex / "config.toml").write_text(
        'model = "o3"\n'
        'model_provider = "openai"\n'
        "[model_providers.openai]\n"
        'name = "OpenAI"\n'
    )
    _, cap = _run("codex", "strict")
    cfg = _codex_config(cap)
    assert cfg["model"] == "o3"  # preserved (was lost before)
    assert cfg["model_provider"] == "openai"
    assert cfg["model_providers"]["openai"]["name"] == "OpenAI"
    assert cfg["sandbox_mode"] == "workspace-write"  # guard's block wins
    assert cfg["approval_policy"]  # guard owns it


def test_codex_strips_conflicting_user_sandbox_keys(logged_in):
    """A user's own sandbox keys must be replaced by guard's (no TOML duplicate-key crash)."""
    user_codex = logged_in / ".codex"
    user_codex.mkdir()
    (user_codex / "config.toml").write_text(
        'model = "o3"\n'
        'sandbox_mode = "danger-full-access"\n'
        'approval_policy = "never"\n'
        "[features.network_proxy]\n"
        "enabled = false\n"
        "[features.other]\n"
        "keep = true\n"
    )
    _, cap = _run("codex", "strict")  # parses cleanly == no duplicate keys
    cfg = _codex_config(cap)
    assert cfg["model"] == "o3"
    assert cfg["sandbox_mode"] == "workspace-write"  # guard wins, user's danger-full-access dropped
    assert "network_proxy" not in cfg["features"]  # guard owns it; strict has no proxy, user's dropped
    assert cfg["features"]["other"]["keep"] is True  # unrelated nested key preserved


def test_codex_merges_features_without_duplicate_key(logged_in):
    """Regression: a user [features] table must merge with guard's features.network_proxy into one
    key — not emit a second `features`, which made Codex fail to load config.toml (duplicate key)."""
    user_codex = logged_in / ".codex"
    user_codex.mkdir()
    (user_codex / "config.toml").write_text('model = "o3"\n[features]\njs_repl = false\n')
    _, cap = _run("codex", "standard")  # standard => network allowlist => guard emits features.network_proxy
    cfg = _codex_config(cap)  # parses cleanly == no duplicate `features` key
    assert cfg["features"]["js_repl"] is False  # user feature preserved
    assert cfg["features"]["network_proxy"]["enabled"] is True  # guard's proxy merged into the same table
    assert cfg["model"] == "o3"


def test_codex_seeds_session_state_for_resume(logged_in):
    """sessions/, archived_sessions/, history.jsonl are symlinked so `codex resume` finds them."""
    user_codex = logged_in / ".codex"
    (user_codex / "sessions").mkdir(parents=True)
    (user_codex / "sessions" / "s1.jsonl").write_text("{}")
    (user_codex / "archived_sessions").mkdir()
    (user_codex / "history.jsonl").write_text("{}")
    _, cap = _run("codex", "strict")
    home = Path(cap["env"]["CODEX_HOME"])
    assert (home / "sessions").is_symlink()
    assert (home / "sessions" / "s1.jsonl").exists()
    assert (home / "archived_sessions").is_symlink()
    assert (home / "history.jsonl").is_symlink()


# ---------------------------------------------------------------------------
# Passthrough sanitization
# ---------------------------------------------------------------------------

import pytest as _pytest  # noqa: E402

from agent_scan.guard_launch import _sanitize_passthrough  # noqa: E402


@_pytest.mark.parametrize(
    "client,toks,exp_clean,exp_removed",
    [
        ("claude", ["--resume", "--verbose"], ["--resume", "--verbose"], []),
        # --dangerously-skip-permissions only drops Claude's permission prompts; hooks + the OS
        # sandbox still compose, so the guard lets it through rather than stripping it.
        (
            "claude",
            ["--dangerously-skip-permissions", "--resume"],
            ["--dangerously-skip-permissions", "--resume"],
            [],
        ),
        ("claude", ["--settings", "/tmp/x.json", "--resume"], ["--resume"], ["--settings /tmp/x.json"]),
        ("claude", ["--settings=/tmp/x.json"], [], ["--settings=/tmp/x.json"]),
        ("codex", ["--yolo", "-q"], ["-q"], ["--yolo"]),
        ("codex", ["--sandbox", "danger-full-access"], [], ["--sandbox danger-full-access"]),
        ("codex", ["--sandbox=danger-full-access"], [], ["--sandbox=danger-full-access"]),
    ],
)
def test_sanitize_passthrough(client, toks, exp_clean, exp_removed):
    clean, removed = _sanitize_passthrough(client, toks)
    assert clean == exp_clean
    assert removed == exp_removed


def test_extract_launch_passthrough_profile_before_client(monkeypatch):
    from agent_scan import cli

    monkeypatch.setattr(
        cli.sys, "argv", ["snyk-agent-scan", "guard", "run", "--profile", "standard", "claude", "--resume"]
    )
    passthrough = cli._extract_launch_passthrough()
    assert passthrough == ["--resume"]
    assert cli.sys.argv == ["snyk-agent-scan", "guard", "run", "--profile", "standard", "claude"]


def test_extract_launch_passthrough_profile_equals_form(monkeypatch):
    from agent_scan import cli

    monkeypatch.setattr(cli.sys, "argv", ["snyk-agent-scan", "guard", "run", "--profile=strict", "codex", "--resume"])
    passthrough = cli._extract_launch_passthrough()
    assert passthrough == ["--resume"]
    assert cli.sys.argv == ["snyk-agent-scan", "guard", "run", "--profile", "strict", "codex"]


def test_extract_launch_passthrough_no_profile(monkeypatch):
    from agent_scan import cli

    monkeypatch.setattr(cli.sys, "argv", ["snyk-agent-scan", "guard", "run", "claude", "--resume"])
    passthrough = cli._extract_launch_passthrough()
    assert passthrough == ["--resume"]
    assert cli.sys.argv == ["snyk-agent-scan", "guard", "run", "claude"]


def test_extract_launch_passthrough_forwards_everything_after_client(monkeypatch):
    from agent_scan import cli

    # Args after the client are forwarded verbatim — even ones that look like our own flags.
    monkeypatch.setattr(
        cli.sys, "argv", ["x", "guard", "run", "--profile", "strict", "claude", "--", "--profile", "other"]
    )
    passthrough = cli._extract_launch_passthrough()
    assert passthrough == ["--", "--profile", "other"]


def test_extract_launch_passthrough_not_a_launcher(monkeypatch):
    from agent_scan import cli

    monkeypatch.setattr(cli.sys, "argv", ["x", "guard", "install", "claude"])
    assert cli._extract_launch_passthrough() is None


def test_extract_launch_passthrough_bare_run_not_a_launcher(monkeypatch):
    from agent_scan import cli

    monkeypatch.setattr(cli.sys, "argv", ["x", "guard", "run"])
    assert cli._extract_launch_passthrough() is None
