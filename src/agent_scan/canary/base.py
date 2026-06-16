"""Live-test ("canary") specs, co-located with the discoverers — see :mod:`agent_scan.canary`.

These are **declarative and runner-agnostic**: a :class:`Scope` says how to drive the real agent binary
to write a detection scope (a list of :class:`SeedCommand`) and what ``inspect`` must then detect
(:class:`ExpectedItem`), but it does NOT execute anything. An external executor (the agent-scan-backoffice
canary) imports an :class:`AgentCanary`, runs its commands in an isolated home against the real binary,
runs ``inspect``, and compares. Co-location means the seed recipe + expectation for a scope live in the
same repo (same PR) as the discoverer method they test, so they cannot drift; ``test_canary_covers_scopes``
enforces that every scope-producing ``_discover_*`` method has a canary :class:`Scope`.
"""

from __future__ import annotations

from abc import ABC
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from agent_scan.agents.base import AgentDiscoverer


@dataclass(frozen=True)
class CanaryContext:
    """The per-leg context an executor supplies: the isolated home/project and the resolved agent
    binary. Pure data — no execution. Installing the binary (and providing any secrets) is the
    executor's job, not the spec's."""

    home: Path
    project: Path
    bin: str


@dataclass(frozen=True)
class SeedCommand:
    """One command the executor should run to seed a scope.

    ``run_in_project`` → run with cwd = the dummy project. ``non_fatal`` → a non-zero exit should warn,
    not fail the leg (e.g. the headless trust step, or best-effort plugin installs); a failed *required*
    seed instead surfaces downstream as a MISSING scope. Seed commands run against the fake home."""

    argv: tuple[str, ...]
    run_in_project: bool = False
    timeout: int = 180
    non_fatal: bool = False


@dataclass(frozen=True)
class ExpectedItem:
    """One item ``inspect`` must detect once a scope is seeded. ``path_contains`` (skills) verifies the
    item was found in the right scope; use ``$HOME``/``$PROJECT`` placeholders (the executor normalizes
    detected paths to those)."""

    kind: str  # "mcp" | "skill"
    name: str
    scope: str
    path_contains: tuple[str, ...] = ()


class Scope(ABC):
    """One detection scope mirroring a discoverer ``_discover_*`` method.

    ``mirrors`` holds the discoverer method OBJECT(s) this scope tests (rename-proof — a rename breaks
    the reference at import; the coverage test compares method objects, no regex). ``commands`` returns
    the seed commands; ``expected`` the items to detect. A :class:`Gap` overrides neither (no live writer)."""

    label: str
    mirrors: tuple[Callable, ...]

    def commands(self, ctx: CanaryContext) -> list[SeedCommand]:
        return []

    def expected(self) -> list[ExpectedItem]:
        return []

    @property
    def enforced(self) -> bool:
        return bool(self.expected())


@dataclass(frozen=True)
class McpScope(Scope):
    """A single ``<bin> mcp add -s <cli_scope> <name> -- <cmd...>`` write + its expected ``mcp`` item."""

    label: str
    mirrors: tuple[Callable, ...]
    server_name: str
    cli_scope: str  # the -s value: user | local | project
    command: tuple[str, ...]
    run_in_project: bool = False

    def commands(self, ctx: CanaryContext) -> list[SeedCommand]:
        return [
            SeedCommand(
                argv=(ctx.bin, "mcp", "add", "-s", self.cli_scope, self.server_name, "--", *self.command),
                run_in_project=self.run_in_project,
            )
        ]

    def expected(self) -> list[ExpectedItem]:
        return [ExpectedItem(kind="mcp", name=self.server_name, scope=self.label)]


@dataclass(frozen=True)
class PluginScope(Scope):
    """One pinned marketplace-plugin install (marketplace add → pin clone → install at each scope) that
    yields multiple expected items (the bundled mcp server + skills). Narrow→broad scope order avoids a
    later scope deduping an earlier one's enablement write. All steps non-fatal (enforced items surface
    as MISSING if the install fails)."""

    label: str
    mirrors: tuple[Callable, ...]
    marketplace: str
    marketplace_repo: str
    plugin: str
    pin_sha: str
    expected_items: tuple[ExpectedItem, ...]
    scopes: tuple[str, ...] = ("local", "project", "user")

    def commands(self, ctx: CanaryContext) -> list[SeedCommand]:
        clone = ctx.home / ".claude" / "plugins" / "marketplaces" / self.marketplace
        spec = f"{self.plugin}@{self.marketplace}"
        cmds = [
            SeedCommand((ctx.bin, "plugin", "marketplace", "add", self.marketplace_repo), non_fatal=True),
            SeedCommand(("git", "-C", str(clone), "fetch", "--depth", "1", "origin", self.pin_sha), non_fatal=True),
            SeedCommand(("git", "-C", str(clone), "checkout", "--detach", self.pin_sha), non_fatal=True),
        ]
        cmds += [
            SeedCommand((ctx.bin, "plugin", "install", spec, "--scope", s), run_in_project=True, non_fatal=True)
            for s in self.scopes
        ]
        return cmds

    def expected(self) -> list[ExpectedItem]:
        return list(self.expected_items)


@dataclass(frozen=True)
class LifecycleStep(Scope):
    """A non-asserting prerequisite: run the agent headlessly so it trusts/registers the project. Mirrors
    no discoverer scope (``mirrors=()``); asserts nothing."""

    label: str = "lifecycle/trust"
    mirrors: tuple[Callable, ...] = ()
    prompt: str = "List the files in this directory."

    def commands(self, ctx: CanaryContext) -> list[SeedCommand]:
        return [
            SeedCommand(
                argv=(ctx.bin, "-p", self.prompt, "--permission-mode", "bypassPermissions"),
                run_in_project=True,
                non_fatal=True,
            )
        ]


@dataclass(frozen=True)
class Gap(Scope):
    """A discoverer scope with no live writer: mirrored for fidelity (so the coverage test counts its
    method as covered) but never seeded or asserted. ``why`` documents why it can't be driven live."""

    label: str
    mirrors: tuple[Callable, ...]
    why: str


class AgentCanary(ABC):
    """The live-test counterpart of one ``AgentDiscoverer`` — one ``Scope`` per scope-producing method.

    Subclasses set ``discoverer`` (the discoverer class) and ``scopes`` (ordered). Installing the agent
    binary (and providing any secrets) is the executor's responsibility, not the spec's."""

    discoverer: type[AgentDiscoverer]

    @property
    def name(self) -> str:
        return self.discoverer.name

    @property
    def scopes(self) -> list[Scope]:
        raise NotImplementedError

    def expected(self) -> list[ExpectedItem]:
        return [item for scope in self.scopes for item in scope.expected()]

    def gaps(self) -> list[Gap]:
        return [s for s in self.scopes if isinstance(s, Gap)]
