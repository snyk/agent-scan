"""Turn raw ``snyk-agent-scan inspect --json`` output into a stable, host-independent inventory.

The own-home ``inspect`` output is a dict keyed by the client install path; every discovered
skill / MCP server for that client is flattened into a single ``servers`` list, and the source
config path is dropped from each entry. Two consequences shape this module:

* The same logical item appears **more than once** — once from the well-known-client pass and once
  from the agent-discoverer pass, and on macOS once as ``/tmp/...`` and once as the ``/private/tmp/...``
  realpath. We therefore de-duplicate.
* An MCP server entry carries no source path, so its detection **scope is only recoverable from its
  (uniquely chosen) fixture name**. A skill entry carries ``server.path``, which we normalize so the
  scope can also be verified against the expected set.
"""

from __future__ import annotations

from dataclasses import dataclass

HOME_PLACEHOLDER = "$HOME"
PROJECT_PLACEHOLDER = "$PROJECT"


@dataclass(frozen=True)
class InventoryItem:
    """One detected component, reduced to its stable identity.

    ``path`` is the normalized filesystem location for skills and ``None`` for MCP servers
    (the inspect output does not report an MCP server's source path).
    """

    kind: str  # "mcp" | "skill"
    name: str
    server_type: str | None  # "stdio" | "sse" | "http" | "ws" | "skill" | None
    path: str | None


def _to_slash(path: str) -> str:
    """Normalize separators to ``/`` so Windows (backslash) and POSIX paths compare identically."""
    return path.replace("\\", "/")


def _path_variants(path: str) -> set[str]:
    """All spellings a host might report for *path* (slash-form), folding the macOS ``/private`` realpath."""
    p = path.rstrip("/")
    variants = {p}
    if p.startswith("/private/"):
        variants.add(p[len("/private") :])  # /private/tmp/x -> /tmp/x
    elif p.startswith("/"):
        variants.add("/private" + p)  # /tmp/x -> /private/tmp/x
    return variants


def normalize_path(raw: str, home: str, project: str | None) -> str:
    """Replace the home/project prefixes of *raw* with stable placeholders.

    Separators are normalized to ``/`` first, so a Windows path (``C:\\Users\\me\\.claude\\...``)
    folds the same way a POSIX one does and the result is always slash-form. The project prefix is
    preferred over the home prefix when the project is nested under the home directory (the more
    specific match wins), so project-scoped items are labelled ``$PROJECT/...`` not ``$HOME/...``.
    """
    raw_s = _to_slash(raw).rstrip("/")
    candidates: list[tuple[str, str]] = []
    if project:
        candidates += [(v, PROJECT_PLACEHOLDER) for v in _path_variants(_to_slash(project))]
    candidates += [(v, HOME_PLACEHOLDER) for v in _path_variants(_to_slash(home))]
    # Longest prefix first so the most specific location wins.
    for prefix, placeholder in sorted(candidates, key=lambda c: len(c[0]), reverse=True):
        if raw_s == prefix:
            return placeholder
        if raw_s.startswith(prefix + "/"):
            return placeholder + raw_s[len(prefix) :]
    return raw_s


def build_inventory(inspect_output: dict, *, home: str, project: str | None = None) -> list[InventoryItem]:
    """Flatten + de-duplicate the inspect output into a sorted list of :class:`InventoryItem`."""
    items: set[InventoryItem] = set()
    for path_result in inspect_output.values():
        if not isinstance(path_result, dict):
            continue
        for server_result in path_result.get("servers") or []:
            name = server_result.get("name")
            if not name:
                continue
            server = server_result.get("server") or {}
            server_type = server.get("type")
            if server_type == "skill":
                raw_path = server.get("path")
                items.add(
                    InventoryItem(
                        kind="skill",
                        name=name,
                        server_type="skill",
                        path=normalize_path(raw_path, home, project) if raw_path else None,
                    )
                )
            else:
                items.add(InventoryItem(kind="mcp", name=name, server_type=server_type, path=None))
    return sorted(items, key=lambda i: (i.kind, i.name, i.path or ""))
