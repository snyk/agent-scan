"""Tests for agent_scan.sandbox — profile schema and the per-harness compile layer."""

from __future__ import annotations

import pytest

from agent_scan.sandbox import (
    DEFAULT_PROFILE,
    MCP_NOTE,
    PROFILES,
    compile_claude,
    compile_codex,
    compile_for,
    get_profile,
    render_codex_toml,
)


def test_three_profiles_exist_and_default_is_strict():
    assert set(PROFILES) == {"strict", "standard", "permissive"}
    assert DEFAULT_PROFILE == "strict"


def test_get_profile_unknown_raises():
    with pytest.raises(ValueError):
        get_profile("nope")


# --- Claude --------------------------------------------------------------


def test_claude_strict_is_locked_down():
    sb = compile_claude(get_profile("strict"))
    cfg = sb.config["sandbox"]
    assert cfg["enabled"] is True
    assert cfg["failIfUnavailable"] is True
    assert cfg["allowUnsandboxedCommands"] is False
    # network off -> empty allowlist
    assert cfg["network"]["allowedDomains"] == []
    # credential dirs blocked
    assert "~/.ssh" in cfg["filesystem"]["denyRead"]
    # no docker exclusion (denied, not run unsandboxed)
    assert "excludedCommands" not in cfg
    # strict keeps full network isolation (no TLS trust escape hatch)
    assert "enableWeakerNetworkIsolation" not in cfg
    assert MCP_NOTE in sb.notes


def test_claude_standard_allows_listed_domains_and_escape_hatch():
    cfg = compile_claude(get_profile("standard")).config["sandbox"]
    assert cfg["allowUnsandboxedCommands"] is True
    assert "github.com" in cfg["network"]["allowedDomains"]
    assert "~/.aws" in cfg["filesystem"]["denyRead"]
    # docker/uv are excluded from the sandbox so they drop into the normal approval prompt
    # (approve = run unsandboxed, deny = blocked) instead of silently failing inside.
    assert cfg["excludedCommands"] == ["docker *", "uv *"]
    # standard opens the TLS trust service for Go-based tools behind the MITM proxy
    assert cfg["enableWeakerNetworkIsolation"] is True


def test_claude_permissive_is_unrestricted():
    """Permissive is full access — identical to Codex danger-full-access, no cred carve-out."""
    sb = compile_claude(get_profile("permissive"))
    cfg = sb.config["sandbox"]
    assert cfg["network"]["allowedDomains"] == ["*"]
    assert cfg["enableWeakerNetworkIsolation"] is True
    assert cfg["excludedCommands"] == ["docker *", "uv *"]
    # writes everywhere; no write/read carve-outs (the cred courtesy is gone for parity)
    assert cfg["filesystem"]["allowWrite"] == ["/"]
    assert "denyWrite" not in cfg["filesystem"]
    assert "denyRead" not in cfg["filesystem"]


# --- Codex ---------------------------------------------------------------


def test_codex_strict_network_off():
    sb = compile_codex(get_profile("strict"))
    cfg = sb.config
    assert cfg["sandbox_mode"] == "workspace-write"
    assert cfg["approval_policy"] == "untrusted"
    assert cfg["sandbox_workspace_write"]["network_access"] is False
    assert "features" not in cfg  # no proxy when network off
    assert any("docker remains sandboxed" in note for note in sb.notes)


def test_codex_standard_uses_network_proxy_domains():
    cfg = compile_codex(get_profile("standard")).config
    assert cfg["sandbox_workspace_write"]["network_access"] is True
    domains = cfg["features"]["network_proxy"]["domains"]
    assert domains["github.com"] == "allow"
    assert cfg["features"]["network_proxy"]["enabled"] is True


def test_codex_permissive_is_full_access():
    cfg = compile_codex(get_profile("permissive")).config
    assert cfg["sandbox_mode"] == "danger-full-access"
    assert cfg["approval_policy"] == "never"
    # full access => no redundant workspace/proxy keys
    assert "sandbox_workspace_write" not in cfg
    assert "features" not in cfg


def test_render_codex_toml_has_no_section_headers():
    """The fragment must be safe to prepend: only top-level inline assignments."""
    toml = render_codex_toml(compile_codex(get_profile("standard")).config)
    assert "[sandbox_workspace_write]" not in toml
    assert "[features" not in toml
    assert toml.startswith("approval_policy = ")
    assert 'features.network_proxy = {' in toml
    assert '"github.com" = "allow"' in toml


# --- dispatch ------------------------------------------------------------


@pytest.mark.parametrize("client", ["claude", "codex"])
def test_compile_for_dispatch(client):
    out = compile_for(client, get_profile("standard"))
    assert out.config
    assert MCP_NOTE in out.notes


@pytest.mark.parametrize("prof", ["strict", "standard"])
def test_writable_paths_are_identical_across_harnesses(prof):
    """A bounded profile grants the exact same (absolute) write scope on Claude and Codex."""
    claude = compile_claude(get_profile(prof)).config["sandbox"]["filesystem"].get("allowWrite", [])
    codex = compile_codex(get_profile(prof)).config["sandbox_workspace_write"].get("writable_roots", [])
    assert claude == codex
    # absolute, with the credential dirs deliberately absent (protected by exclusion)
    assert all(not p.startswith("~") for p in claude)
    assert not any("/.ssh" in p for p in claude)
