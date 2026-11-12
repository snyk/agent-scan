"""Remote discovery: the CLI-side op executor and the ``found`` -> ``ClientToInspect`` merge."""

import os
from pathlib import Path

from agent_scan.remote_discovery.builder import build_clients
from agent_scan.remote_discovery.executor import run_op


def _find(root: Path, **op: object) -> list[str]:
    result = run_op({"op_id": "1", "kind": "find", "roots": [str(root)], "max_depth": 6, **op})
    assert result["status"] == "ok"
    return sorted(Path(m["path"]).relative_to(root).as_posix() for m in result["matches"])


def test_find_follows_only_child_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "deep").mkdir(parents=True)
    (target / "deep/.mcp.json").write_text("{}")
    (tmp_path / "root/sub").mkdir(parents=True)
    os.symlink(target, tmp_path / "root/a")
    os.symlink(target, tmp_path / "root/sub/b")
    os.symlink(tmp_path / "root", tmp_path / "root/sub/loop")
    root = tmp_path / "root"

    assert _find(root, file_names=[".mcp.json"]) == []
    assert _find(root, file_names=[".mcp.json"], follow_child_links=True) == ["a/deep/.mcp.json"]


def test_find_file_suffixes(tmp_path: Path) -> None:
    (tmp_path / "x.json").mkdir()
    for name in ("a.json", "b.md", "sub/c.json"):
        (tmp_path / name).parent.mkdir(exist_ok=True)
        (tmp_path / name).write_text("{}")
    (tmp_path / "D.JSON").write_text("{}")

    assert _find(tmp_path, file_suffixes=[".json"], max_depth=1) == ["a.json"]
    assert _find(tmp_path, file_suffixes=[".json"], max_depth=1, ignore_case=True) == ["D.JSON", "a.json"]
    assert _find(tmp_path, file_suffixes=[".json"]) == ["a.json", "sub/c.json"]


def test_env_sends_only_absolute_paths(monkeypatch) -> None:
    monkeypatch.setenv("CODEX_HOME", "/opt/codex")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("COPILOT_HOME", "relative/dir")
    monkeypatch.setenv("SEEDS", os.pathsep.join(["/a", "rel", "", "/b"]))
    monkeypatch.setenv("LONG", "/" + "x" * 5000)
    monkeypatch.delenv("UNSET_VAR", raising=False)
    op = {
        "op_id": "1",
        "kind": "env",
        "names": ["CODEX_HOME", "GITHUB_TOKEN", "COPILOT_HOME", "SEEDS", "LONG", "UNSET_VAR", "lower", "A-B"],
        "path_lists": ["SEEDS"],
    }
    result = run_op(op)
    assert result["status"] == "ok"
    assert result["values"] == {
        "CODEX_HOME": "/opt/codex",
        "GITHUB_TOKEN": None,
        "COPILOT_HOME": None,
        "SEEDS": os.pathsep.join(["/a", "/b"]),
        "LONG": None,
        "UNSET_VAR": None,
    }
    assert "ghp_secret" not in repr(result)


def test_env_caps_names() -> None:
    names = [f"V{i}" for i in range(100)]
    assert len(run_op({"op_id": "1", "kind": "env", "names": names})["values"]) == 64


def _mcp(key: str, name: str, **flags: bool) -> dict:
    return {
        "client": "claude code",
        "username": "me",
        "key": key,
        "candidates": [{"maps": [{name: {"command": name}}]}],
        "fallback": {"kind": "parse_error", "message": "x"},
        **flags,
    }


def test_merge_last_write_wins_and_canonical(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text("{}")
    link = tmp_path / "link.json"
    os.symlink(real, link)
    found = {
        "clients": [{"name": "claude code", "client_path": "/x", "username": "me"}],
        "mcp_configs": [
            _mcp("/a.json", "first"),
            _mcp("/a.json", "second"),
            _mcp(str(link), "via-link", canonical=True),
            _mcp(str(real), "direct", canonical=True),
        ],
        "skills_dirs": [],
    }
    (client,) = build_clients(found)
    configs = client.mcp_configs
    assert [name for name, _ in configs["/a.json"]] == ["second"]
    # Two spellings of one file merge under its resolved path.
    assert [name for name, _ in configs[real.resolve().as_posix()]] == ["via-link", "direct"]
    assert str(link) not in configs


def _stdio_found(raw: dict, roots: list[str]) -> dict:
    return {
        "clients": [{"name": "codex", "client_path": "/x", "username": "me"}],
        "mcp_configs": [
            {
                "client": "codex",
                "username": "me",
                "key": "/c.toml",
                "candidates": [{"maps": [{"tool": raw}]}],
                "fallback": {"kind": "parse_error", "message": "x"},
                "stdio_roots": {"tool": roots},
            }
        ],
        "skills_dirs": [],
    }


def test_stdio_roots_resolve_one_executable(tmp_path: Path, monkeypatch) -> None:
    signed: list[str | None] = []

    def fake_sign(server, *, signature_command=None):
        signed.append(signature_command)
        return server

    monkeypatch.setattr("agent_scan.remote_discovery.builder.check_server_signature", fake_sign)
    plugin = tmp_path / "plugin"
    (plugin / "bin").mkdir(parents=True)
    (plugin / "bin/run tool").write_text("#!/bin/sh\n")
    raw = {"command": "./bin/run tool", "args": ["--x"], "cwd": "."}
    found = _stdio_found(raw, [str(tmp_path / "missing"), str(plugin)])
    (client,) = build_clients(found)
    ((_, server),) = client.mcp_configs["/c.toml"]
    executable = str((plugin / "bin/run tool").resolve())
    assert signed == [executable]
    # The uploaded command stays as configured; the resolved one is runtime context.
    assert (server.command, server.args) == ("./bin/run tool", ["--x"])
    assert (server.runtime_command, server.runtime_cwd) == (executable, str(plugin.resolve()))


def test_stdio_roots_ignored_when_ambiguous_or_escaping(tmp_path: Path, monkeypatch) -> None:
    signed: list[str | None] = []

    def fake_sign(server, *, signature_command=None):
        signed.append(signature_command)
        return server

    monkeypatch.setattr("agent_scan.remote_discovery.builder.check_server_signature", fake_sign)
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "tool").write_text("")
    (tmp_path / "outside").write_text("")
    roots = [str(tmp_path / "a"), str(tmp_path / "b")]
    build_clients(_stdio_found({"command": "./tool", "cwd": "."}, roots))
    build_clients(_stdio_found({"command": "../outside", "cwd": "."}, [str(tmp_path / "a")]))
    assert signed == [None, None]
