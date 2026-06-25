"""Shape tests for the canary specs: derived expectations, seed commands, fixtures, gaps."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from canary_test_supported_agents import CANARIES, CanaryContext
from canary_test_supported_agents.base import ExpectedItem, FixtureScope, Gap, McpScope, PluginScope
from canary_test_supported_agents.claude_code import ClaudeCodeCanary

CTX = CanaryContext(home=Path("/home"), project=Path("/home/proj"), bin="claude")

# Item order follows scope order: the .mcp.json fixture (mcp/project-file-fixture) is seeded just before
# the `-s project` CLI write (mcp/project-file) that merges into it, so its item comes first.
EXPECTED_ITEMS = [
    ExpectedItem("mcp", "canary-global-mcp", "mcp/global"),
    ExpectedItem("mcp", "canary-project-inline-mcp", "mcp/project-inline"),
    ExpectedItem("mcp", "canary-project-fixture-mcp", "mcp/project-file-fixture"),
    ExpectedItem("mcp", "canary-project-file-mcp", "mcp/project-file"),
    ExpectedItem("mcp", "discord", "mcp/plugin"),
    ExpectedItem("skill", "access", "skill/plugin", ("$HOME/.claude/plugins/", "skills/access")),
    ExpectedItem("skill", "configure", "skill/plugin", ("$HOME/.claude/plugins/", "skills/configure")),
    ExpectedItem(
        "skill", "canary-project-skill", "skill/project", ("$PROJECT/.claude/skills/", "canary-project-skill")
    ),
]


def test_registry_keys_on_discoverer_name():
    assert "claude code" in CANARIES
    assert isinstance(CANARIES["claude code"], ClaudeCodeCanary)


def test_expected_items_in_order():
    assert ClaudeCodeCanary().expected() == EXPECTED_ITEMS


def test_scope_order_fixture_before_merging_mcp_scope_then_gaps():
    scopes = ClaudeCodeCanary().scopes
    labels = [s.label for s in scopes]
    assert labels == [
        "mcp/global",
        "mcp/project-inline",
        "mcp/project-file-fixture",
        "mcp/project-file",
        "lifecycle/trust",
        "mcp+skill/plugin",
        "skill/project",
        "skill/global",
        "mcp/managed",
        "mcp/plugin-manifest",
        "skill/plugin-manifest",
    ]
    # The committed .mcp.json fixture must precede the `-s project` McpScope that merges into it, so
    # `claude mcp add` adds to (rather than gets clobbered by) the fixture — both servers are detected.
    assert labels.index("mcp/project-file-fixture") < labels.index("mcp/project-file")
    by_label = {s.label: s for s in scopes}
    assert isinstance(by_label["mcp+skill/plugin"], PluginScope)  # the live plugin install
    assert {s.label for s in scopes if isinstance(s, Gap)} == {
        "skill/global",
        "mcp/managed",
        "mcp/plugin-manifest",
        "skill/plugin-manifest",
    }


def test_mcp_scope_emits_claude_mcp_add():
    scope = next(s for s in ClaudeCodeCanary().scopes if isinstance(s, McpScope) and s.label == "mcp/project-file")
    (cmd,) = scope.commands(CTX)
    assert cmd.argv == ("claude", "mcp", "add", "-s", "project", "canary-project-file-mcp", "--", "echo", "file")
    assert cmd.run_in_project is True


def _plugin_scope(label):
    return next(s for s in ClaudeCodeCanary().scopes if isinstance(s, PluginScope) and s.label == label)


def test_plugin_scope_marketplace_pin_then_installs_narrow_to_broad():
    scope = _plugin_scope("mcp+skill/plugin")
    argvs = [" ".join(c.argv) for c in scope.commands(CTX)]
    # Build the clone path the same way the code does, so the assertion holds on Windows too (backslashes).
    clone = str(CTX.home / ".claude" / "plugins" / "marketplaces" / "claude-plugins-official")
    assert argvs == [
        "claude plugin marketplace add anthropics/claude-plugins-official",
        f"git -C {clone} fetch --depth 1 origin {scope.pin_sha}",
        f"git -C {clone} checkout --detach {scope.pin_sha}",
        "claude plugin install discord@claude-plugins-official --scope local",
        "claude plugin install discord@claude-plugins-official --scope project",
        "claude plugin install discord@claude-plugins-official --scope user",
    ]


def test_plugin_pin_steps_are_fatal_but_add_and_installs_degrade():
    # The two git PIN steps (fetch + checkout) must be FATAL: if the pin can't be applied, the executor
    # must fail the leg loudly (SeedError) rather than fall through to `plugin install`, which would
    # install unpinned LATEST — still satisfying the discord/access/configure assertions and passing
    # green against the wrong version (the pin exists precisely to give a deterministic baseline).
    # The marketplace add and the per-scope installs stay non-fatal: a failed install leaves its
    # enforced items MISSING, which the inspect comparison already catches (safe degrade).
    scope = _plugin_scope("mcp+skill/plugin")
    cmds = scope.commands(CTX)

    pin = [c for c in cmds if c.argv[0] == "git"]
    assert len(pin) == 2  # fetch + checkout
    assert all(not c.non_fatal for c in pin), "git fetch/checkout pin steps must be fatal"

    add = next(c for c in cmds if c.argv[:4] == ("claude", "plugin", "marketplace", "add"))
    assert add.non_fatal  # may be idempotent/transient; its failure cascades into the fatal fetch anyway

    installs = [c for c in cmds if c.argv[:2] == ("claude", "plugin") and "install" in c.argv]
    assert installs and all(c.non_fatal for c in installs)  # failed install → MISSING → caught by inspect


def test_gaps_are_inert():
    for gap in ClaudeCodeCanary().gaps():
        assert gap.commands(CTX) == []
        assert gap.files() == []
        assert gap.expected() == []
        assert gap.mirrors  # still references its discoverer method


def test_fixture_scopes_declare_files_and_assert_items_but_run_no_command():
    fixtures = {s.label: s for s in ClaudeCodeCanary().scopes if isinstance(s, FixtureScope)}
    assert set(fixtures) == {"skill/project", "mcp/project-file-fixture"}

    skill = fixtures["skill/project"]
    assert skill.commands(CTX) == []  # no CLI can write a project skill
    (sf,) = skill.files()
    assert (sf.src, sf.dest) == (
        "test_projects/proj/.claude/skills/canary-project-skill",
        ".claude/skills/canary-project-skill",
    )
    assert skill.expected() == [
        ExpectedItem(
            "skill", "canary-project-skill", "skill/project", ("$PROJECT/.claude/skills/", "canary-project-skill")
        )
    ]

    server = fixtures["mcp/project-file-fixture"]
    (mf,) = server.files()
    assert (mf.src, mf.dest) == ("test_projects/proj/.mcp.json", ".mcp.json")
    assert server.expected() == [ExpectedItem("mcp", "canary-project-fixture-mcp", "mcp/project-file-fixture")]


def test_committed_fixtures_are_locatable():
    # Every declared FixtureFile.src must resolve to a real committed path under the package dir — the
    # same lookup the backoffice executor does (it imports canary_test_supported_agents from the cloned
    # source tree and resolves src against the package dir). A miss here means the backoffice would copy
    # nothing and the scope would fail MISSING in CI. These fixtures are test support, not shipped in the
    # agent_scan wheel, so this guards the source tree (not a built artifact).
    root = files("canary_test_supported_agents")
    for canary in CANARIES.values():
        for scope in canary.scopes:
            for f in scope.files():
                # Join segment-by-segment (root.joinpath(*src.split("/"))) the way the backoffice
                # executor resolves it, rather than as one slash-bearing string, so the lookup is
                # identical on Windows.
                src = root.joinpath(*f.src.split("/"))
                assert src.is_dir() or src.is_file(), f"fixture not locatable: {f.src}"
