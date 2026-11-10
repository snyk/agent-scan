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
