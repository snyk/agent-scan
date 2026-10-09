"""The discover-remote loop: start, run ops, step, until the backend sends no ops."""

import base64
import json
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp
from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from agent_scan.remote_discovery.executor import Executor
from agent_scan.remote_discovery.upload import MockFileUploadApi
from agent_scan.version import version_info

CAPABILITIES = ["env", "read", "glob", "find", "upload_tree"]
DISCOVERY_PATH = "/hidden/agent-scan/discovery"
PARTS_SHOWN = 2


@dataclass
class Inventory:
    """What the client keeps across steps. The backend keeps nothing."""

    servers: dict[str, dict] = field(default_factory=dict)
    skill_dirs: dict[str, dict] = field(default_factory=dict)
    projects: dict[str, dict] = field(default_factory=dict)
    errors: list[dict] = field(default_factory=list)

    def add(self, found: dict[str, Any]) -> None:
        for s in found.get("servers", []):
            self.servers.setdefault(s["server_id"], s)
        for d in found.get("skill_dirs", []):
            self.skill_dirs.setdefault(d["path"], d)
        for p in found.get("projects", []):
            self.projects.setdefault(p["path"], p)
        self.errors.extend(found.get("errors", []))


@dataclass
class Stats:
    rounds: int = 0
    backend_calls: int = 0
    request_bytes: int = 0
    ops: int = 0
    started: float = field(default_factory=time.monotonic)


def _decode_ctx(token: str) -> Any:
    try:
        body = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except (IndexError, ValueError):
        return "<undecodable>"


class Printer:
    def __init__(self, console: Console, full: bool, show_ctx: bool) -> None:
        self.console = console
        self.full = full
        self.show_ctx = show_ctx

    def shorten(self, value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            out = {k: self.shorten(v, k) for k, v in value.items()}
            if self.show_ctx:
                for k in ("ctx", "step_ctx"):
                    if isinstance(value.get(k), str):
                        out[f"{k}_decoded"] = _decode_ctx(value[k])
            return out
        if isinstance(value, list):
            if key == "parts" and not self.full and len(value) > PARTS_SHOWN:
                hidden = value[PARTS_SHOWN:]
                more = f"… {len(hidden)} more parts, {sum(p['bytes'] for p in hidden)} bytes; --full to show"
                return [self.shorten(v, key) for v in value[:PARTS_SHOWN]] + [more]
            return [self.shorten(v, key) for v in value]
        if isinstance(value, str) and not self.full:
            if key == "bytes_b64" and len(value) > 60:
                return f"<{len(value)} base64 chars; --full to show>"
            if key in ("ctx", "step_ctx") and len(value) > 40:
                return f"{value[:24]}…<{len(value)} chars signed>"
        return value

    def _body(self, data: Any) -> None:
        # print_json soft-wraps, so long paths are never cropped.
        if data is None:
            self.console.print("(empty body)")
        else:
            self.console.print_json(data=self.shorten(data))

    def exchange(self, source: str, method: str, url: str, body: Any, status: int, resp: Any) -> None:
        self.console.print(f"\n[bold cyan]→ {source}[/] [bold]{method}[/] {url}", soft_wrap=True)
        self._body(body)
        color = "green" if status < 400 else "red"
        self.console.print(f"[bold {color}]← {status}[/]")
        self._body(resp)


async def _post(session: aiohttp.ClientSession, url: str, body: dict, printer: Printer, stats: Stats) -> dict:
    raw = json.dumps(body).encode()
    stats.backend_calls += 1
    stats.request_bytes += len(raw)
    async with session.post(url, data=raw, headers={"Content-Type": "application/json"}) as resp:
        text = await resp.text()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {"raw": text}
        printer.exchange("backend", "POST", url, body, resp.status, data)
        if resp.status >= 400:
            raise RuntimeError(f"backend returned {resp.status}: {data}")
        return data


def _print_summary(console: Console, inv: Inventory, stats: Stats, revision_files: int, partial: bool) -> None:
    console.print(Rule("[bold]Discovery result (client-side inventory)"))
    servers = Table(title=f"MCP servers ({len(inv.servers)})", show_lines=False)
    for col in ("name", "scope", "type", "command / url", "config_path"):
        servers.add_column(col, overflow="fold")
    for s in inv.servers.values():
        cfg = s["server"]
        servers.add_row(
            s["name"], s["scope"], cfg.get("type", ""), str(cfg.get("command") or cfg.get("url")), s["config_path"]
        )
    console.print(servers)

    skill_dirs = Table(title=f"Skill folders uploaded ({len(inv.skill_dirs)}; skills are found at analysis)")
    for col in ("scope", "files", "manifest", "path"):
        skill_dirs.add_column(col, overflow="fold")
    for d in inv.skill_dirs.values():
        skill_dirs.add_row(d["scope"], str(d["file_count"]), d["manifest_sha256"][:12], d["path"])
    console.print(skill_dirs)

    projects = Table(title=f"Projects ({len(inv.projects)})")
    projects.add_column("path", overflow="fold")
    for p in inv.projects.values():
        projects.add_row(p["path"])
    console.print(projects)

    if inv.errors:
        errors = Table(title=f"Errors ({len(inv.errors)})")
        errors.add_column("path", overflow="fold")
        errors.add_column("message", overflow="fold")
        for e in inv.errors:
            errors.add_row(e["path"], e["message"])
        console.print(errors)

    console.print(
        f"rounds={stats.rounds} backend_calls={stats.backend_calls} ops={stats.ops} "
        f"request_bytes={stats.request_bytes} revision_files={revision_files} "
        f"partial={partial} elapsed={time.monotonic() - stats.started:.2f}s"
    )


async def run_remote_discovery(backend_url: str, *, full: bool = False, show_ctx: bool = False) -> int:
    console = Console()
    printer = Printer(console, full, show_ctx)
    stats = Stats()
    inv = Inventory()
    base = backend_url.rstrip("/") + DISCOVERY_PATH

    async with aiohttp.ClientSession() as session:
        console.print(Rule("[bold]start"))
        resp = await _post(
            session,
            f"{base}/start",
            {
                "cli_version": version_info,
                "capabilities": CAPABILITIES,
                "machine_facts": {"os": sys.platform},
            },
            printer,
            stats,
        )
        uploader = MockFileUploadApi(resp["upload"]["org_id"], printer.exchange)
        revision = uploader.create_revision()
        executor = Executor(uploader, revision)
        inv.add(resp.get("found", {}))

        while resp.get("ops"):
            stats.rounds += 1
            console.print(Rule(f"[bold]round {stats.rounds}: running {len(resp['ops'])} ops locally"))
            stats.ops += len(resp["ops"])
            results = [executor.run(op) for op in resp["ops"]]
            resp = await _post(
                session,
                f"{base}/step",
                {"step_ctx": resp["step_ctx"], "results": results},
                printer,
                stats,
            )
            inv.add(resp.get("found", {}))

        console.print(Rule("[bold]discovery done: seal the skill revision"))
        uploader.seal(revision)

    _print_summary(console, inv, stats, len(revision.files), bool(resp.get("partial")))
    console.print("\n[bold yellow]Next (not sent in this POC): handshakes, then POST /analysis with[/]")
    console.print_json(
        data={
            "revision_id": revision.id,
            "servers": list(inv.servers.values()),
            "skill_dirs": list(inv.skill_dirs.values()),
        }
    )
    return 0
