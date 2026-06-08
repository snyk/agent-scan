"""Unified sandbox profiles and the per-harness compile layer for Agent Guard.

A single :class:`SandboxProfile` expresses the three things every built-in sandbox
(Claude Code / Codex / Cursor) can model — writable paths, read policy, and network
policy — plus how to treat commands that cannot be sandboxed at all (e.g. docker).

The three hardcoded profiles (``strict`` / ``standard`` / ``permissive``) follow the
"Proposed security profiles" section of the feature spec. ``compile_<harness>``
translates a profile into that harness's native config and returns any intentional
degradations as human-readable ``notes`` so callers can warn honestly.

v0 keeps profiles hardcoded here; identity (``guard login``) is the seam through which
Evo will later serve per-role profiles without a CLI release.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_PROFILE = "strict"

# Credential locations. Strict additionally blocks ~/.config; standard leaves it
# readable (matching the spec's two different credential sets).
_STRICT_READ_DENY = ["~/.ssh", "~/.aws", "~/.config", ".env"]
_STD_READ_DENY = ["~/.ssh", "~/.aws", ".env"]

# Package registries, GitHub, and common vendor APIs for the standard allowlist.
_STD_NETWORK_ALLOW = [
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "*.githubusercontent.com",
    "github.com",
    "*.github.com",
    "crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "api.openai.com",
    "api.anthropic.com",
]

# Commands that cannot run under Claude's OS sandbox because they reach a daemon it blocks:
# docker talks to its daemon over a socket outside the writable roots; uv probes the macOS system
# proxy via SCDynamicStore (the configd daemon) when initializing its HTTP client, which Claude's
# Seatbelt profile denies — crashing uv before any request. The uv crash is Claude-profile-specific,
# NOT a universal Seatbelt fact: Codex's sandbox profile permits uv (verified — `uv sync` runs under
# Codex strict), which is why compile_codex never excludes it. Under the "ask" policy these are
# excluded from the Claude sandbox so they fall through to the normal approval prompt instead of failing.
UNSANDBOXABLE_COMMANDS = ["docker *", "uv *"]

# The standing caveat that holds for every harness in v0.
MCP_NOTE = (
    "MCP servers run outside the OS sandbox in all three harnesses — these "
    "filesystem/network limits cover bash (and Codex's own file edits) only, not MCP tools."
)


@dataclass(frozen=True)
class SandboxProfile:
    name: str
    # Writable roots beyond the project dir (paths may use ~ and are expanded per harness).
    write_paths: list[str] = field(default_factory=list)
    # Paths that must never be written even when otherwise writable (e.g. creds in permissive).
    write_deny: list[str] = field(default_factory=list)
    read_mode: str = "denylist"  # "allowlist" | "denylist"
    read_allow: list[str] = field(default_factory=list)  # used when read_mode == "allowlist"
    read_deny: list[str] = field(default_factory=list)  # credential dirs always blocked
    network: str = "off"  # "off" | "allowlist" | "on"
    network_allow: list[str] = field(default_factory=list)  # domains when network == "allowlist"
    unsandboxed: str = "deny"  # "deny" | "ask" | "allow" — commands that can't be sandboxed (docker)
    # macOS/Claude only: open the system TLS trust service (com.apple.trustd.agent) inside the
    # sandbox so Go-based tools (gh, gcloud, terraform) can verify certs behind Claude's MITM
    # proxy. Reduces isolation (a potential exfil path), so it stays off in strict.
    weaken_network_isolation: bool = False


PROFILES: dict[str, SandboxProfile] = {
    "strict": SandboxProfile(
        name="strict",
        write_paths=["/tmp"],
        read_mode="allowlist",
        read_allow=["."],
        read_deny=_STRICT_READ_DENY,
        network="off",
        unsandboxed="deny",
    ),
    "standard": SandboxProfile(
        name="standard",
        write_paths=["/tmp", "~/.cache", "~/.npm"],
        read_mode="denylist",
        read_deny=_STD_READ_DENY,
        network="allowlist",
        network_allow=_STD_NETWORK_ALLOW,
        unsandboxed="ask",
        weaken_network_isolation=True,
    ),
    "permissive": SandboxProfile(
        name="permissive",
        # Full-access tier: writes everywhere, to behave identically to Codex danger-full-access.
        # No credential carve-out — that courtesy existed only on Claude and broke cross-harness parity.
        write_paths=["/"],
        read_mode="denylist",
        read_deny=[],
        network="on",
        unsandboxed="allow",
        weaken_network_isolation=True,
    ),
}


@dataclass
class CompiledSandbox:
    """A harness-native sandbox config plus any intentional degradation notes."""

    config: dict
    notes: list[str] = field(default_factory=list)


def get_profile(name: str) -> SandboxProfile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(f"Unknown sandbox profile: {name!r}. Choose from {sorted(PROFILES)}.") from None


def _abspath(p: str) -> str:
    """Expand ~ for harnesses that require absolute roots. Leaves relative project paths alone."""
    if p.startswith("~"):
        return os.path.expanduser(p)
    return p


def _writable_roots(profile: SandboxProfile) -> list[str]:
    """Canonical writable roots for a profile, identical across harnesses (absolute paths).

    The project dir is writable by default in every harness, so it is implicit and never listed.
    Both compilers feed this through verbatim so a profile grants the *same* write scope on Claude
    and Codex; credential dirs are protected by their absence here (no harness needs a write-deny).
    """
    return [_abspath(p) for p in profile.write_paths]


# ---------------------------------------------------------------------------
# Claude Code  ->  settings.json "sandbox" object
# ---------------------------------------------------------------------------


def compile_claude(profile: SandboxProfile, managed: bool = False) -> CompiledSandbox:
    """Compile to the ``sandbox`` object for ~/.claude/settings.json (or managed-settings.json).

    Network is a HARD boundary at user scope on macOS: Claude's bash sandbox is a Seatbelt profile
    that denies all outbound by default and permits egress only to its localhost proxy, so a
    proxy-unaware client gets EPERM and non-allowlisted hosts are silently dropped (verified
    empirically — no click-through prompt). MANAGED settings do not make the network hard (it already
    is); ``sandbox.network.allowManagedDomainsOnly`` only stops a user's own settings.json from
    additively widening the allowlist. Reads differ: the credential ``denyRead`` block is hard at
    user scope, but confining reads to ``allowRead`` becomes hard only under
    ``sandbox.filesystem.allowManagedReadPathsOnly`` (managed) — otherwise it falls to the
    tool-permission layer, which covers Read/Edit/Write, not bash. Scope: the OS sandbox wraps the
    bash tool only; MCP runs outside it.
    """
    notes: list[str] = [MCP_NOTE]
    sandbox: dict = {"enabled": True}

    if profile.unsandboxed == "deny":
        sandbox["failIfUnavailable"] = True
        sandbox["allowUnsandboxedCommands"] = False
        # docker/uv are left inside the sandbox where they fail — i.e. denied. We deliberately do
        # NOT add them to excludedCommands, which would run them unsandboxed.
        notes.append("docker and uv are denied (they cannot run under the OS sandbox).")
    else:
        sandbox["allowUnsandboxedCommands"] = True
        # docker/uv can't run under the OS sandbox (docker talks to its daemon over a socket
        # outside the writable roots; uv crashes probing the macOS system proxy). Enabling
        # Seatbelt at all blocks that IPC regardless of how open the network/read rules are, so
        # exclude them whenever the sandbox is on but escalation is permitted (ask + allow).
        sandbox["excludedCommands"] = list(UNSANDBOXABLE_COMMANDS)
        if profile.unsandboxed == "ask":
            # They drop into Claude's normal approval flow: prompt, approve runs them outside
            # the sandbox, deny blocks them.
            notes.append(
                "docker and uv run outside the sandbox via excludedCommands — they prompt for "
                "approval (approve = run unsandboxed, deny = blocked)."
            )
        else:  # "allow" — permissive: full access, matching Codex danger-full-access
            notes.append(
                "Permissive is full access (matches Codex danger-full-access): writes, reads and "
                "network are unrestricted and docker/uv run outside the sandbox — uniform across harnesses."
            )

    filesystem: dict = {}
    if profile.write_paths:
        # Canonical absolute roots — identical to Codex's writable_roots for the same profile.
        filesystem["allowWrite"] = _writable_roots(profile)
    if profile.write_deny:
        filesystem["denyWrite"] = profile.write_deny
    if profile.read_mode == "allowlist":
        filesystem["allowRead"] = profile.read_allow
        # Defense-in-depth: still block creds explicitly.
        if profile.read_deny:
            filesystem["denyRead"] = profile.read_deny
        if managed:
            filesystem["allowManagedReadPathsOnly"] = True
            notes.append("Read-allowlisting is enforced: only managed allowRead paths are honored.")
        else:
            notes.append(
                "Read-allowlisting is only fully enforced via managed settings "
                "(allowManagedReadPathsOnly); at user scope reads outside the allowlist may still "
                "be permitted, so credential dirs are blocked via denyRead as a fallback."
            )
    elif profile.read_deny:
        filesystem["denyRead"] = profile.read_deny
    if filesystem:
        sandbox["filesystem"] = filesystem

    if profile.network == "off":
        network: dict = {"allowedDomains": []}
    elif profile.network == "allowlist":
        network = {"allowedDomains": list(profile.network_allow)}
    else:  # "on"
        network = {"allowedDomains": ["*"]}
    if profile.network == "off":
        notes.append(
            "Network is hard-blocked at the socket layer: outbound is denied except to the local "
            "proxy, so a proxy-unaware client gets EPERM (verified) — no prompt."
        )
    elif profile.network == "allowlist":
        notes.append(
            "Network is locked to the allowlist at the socket layer: direct egress is denied and "
            "non-allowlisted hosts are dropped by the proxy (EPERM for proxy-unaware clients)."
        )
    if managed and profile.network != "on":
        # allowManagedDomainsOnly stops a user's own settings.json from widening the allowlist;
        # it does not change the (already hard) socket-level enforcement.
        network["allowManagedDomainsOnly"] = True
        notes.append("Managed: a user's own settings.json cannot widen the allowlist.")
    sandbox["network"] = network

    if profile.weaken_network_isolation:
        # macOS only: lets sandboxed Go-based tools (gh, gcloud, terraform) reach the system TLS
        # trust service to verify certs behind Claude's MITM proxy. Harmless/ignored elsewhere.
        sandbox["enableWeakerNetworkIsolation"] = True
        notes.append(
            "Weaker network isolation is on (macOS): the system TLS trust service is reachable so "
            "Go-based tools (gh, gcloud, terraform) can verify certs — opens a potential exfil path."
        )
    return CompiledSandbox(config={"sandbox": sandbox}, notes=notes)


# ---------------------------------------------------------------------------
# Codex  ->  config.toml keys
# ---------------------------------------------------------------------------

_CODEX_APPROVAL = {"deny": "untrusted", "ask": "on-request", "allow": "never"}


def compile_codex(profile: SandboxProfile, managed: bool = False) -> CompiledSandbox:
    """Compile to a structured dict mirroring ~/.codex/config.toml.

    Network domain filtering uses [features.network_proxy] (allow/deny per host),
    layered on [sandbox_workspace_write].network_access.
    """
    notes: list[str] = [MCP_NOTE]
    config: dict = {}

    config["approval_policy"] = _CODEX_APPROVAL[profile.unsandboxed]

    if profile.unsandboxed == "allow":
        # danger-full-access removes all restrictions; workspace/network keys are moot.
        config["sandbox_mode"] = "danger-full-access"
        return CompiledSandbox(config=config, notes=notes)

    config["sandbox_mode"] = "workspace-write"
    if profile.unsandboxed == "deny":
        notes.append(
            "Codex has no per-command exclusion; docker remains sandboxed in strict and fails closed "
            "when it needs daemon/socket access — even after approval (approval gates whether a "
            "command runs, not whether the sandbox applies)."
        )
    if profile.read_deny:
        notes.append("Codex always permits reads — credential-dir read blocking is not enforced here.")

    workspace_write: dict = {}
    roots = _writable_roots(profile)  # identical to Claude's allowWrite for the same profile
    if roots:
        workspace_write["writable_roots"] = roots
    workspace_write["network_access"] = profile.network != "off"
    config["sandbox_workspace_write"] = workspace_write

    if profile.network == "allowlist":
        domains = {d: "allow" for d in profile.network_allow}
        config["features"] = {"network_proxy": {"enabled": True, "domains": domains}}
    elif profile.network == "on":
        config["features"] = {"network_proxy": {"enabled": True, "domains": {"*": "allow"}}}

    return CompiledSandbox(config=config, notes=notes)


def render_codex_toml(config: dict) -> str:
    """Render the dict from :func:`compile_codex` to a TOML fragment (no deps).

    Uses only top-level key assignments with inline tables — and NO ``[section]``
    headers — so the fragment can be safely prepended to an existing config.toml
    without capturing the user's following content into one of our tables.
    """

    def _val(v: object) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, str):
            return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
        if isinstance(v, list):
            return "[" + ", ".join(_val(x) for x in v) + "]"
        if isinstance(v, dict):
            return "{ " + ", ".join(f"{_key(k)} = {_val(x)}" for k, x in v.items()) + " }"
        raise TypeError(f"Unsupported TOML value: {v!r}")

    def _key(k: str) -> str:
        # Bare keys allowed for [A-Za-z0-9_-]; otherwise quote.
        return k if all(c.isalnum() or c in "_-" for c in k) and k else _val(k)

    lines: list[str] = []
    for key in ("approval_policy", "sandbox_mode"):
        if key in config:
            lines.append(f"{key} = {_val(config[key])}")
    ww = config.get("sandbox_workspace_write")
    if ww:
        lines.append(f"sandbox_workspace_write = {_val(ww)}")
    proxy = config.get("features", {}).get("network_proxy")
    if proxy:
        lines.append(f"features.network_proxy = {_val(proxy)}")
    return "\n".join(lines).rstrip("\n") + "\n"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

_COMPILERS = {
    "claude": compile_claude,
    "codex": compile_codex,
}


def compile_for(client: str, profile: SandboxProfile, managed: bool = False) -> CompiledSandbox:
    return _COMPILERS[client](profile, managed)
