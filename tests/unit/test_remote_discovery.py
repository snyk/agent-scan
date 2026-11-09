"""Remote discovery: the CLI-side op executor and the ``found`` -> ``ClientToInspect`` merge."""

import os
from pathlib import Path

from agent_scan.remote_discovery.builder import build_clients
from agent_scan.remote_discovery.executor import run_op


def _find(root: Path, **op: object) -> list[str]:
    result = run_op({"op_id": "1", "kind": "find", "roots": [str(root)], "max_depth": 6, **op})
    assert result["status"] == "ok"
    return sorted(Path(m["path"]).relative_to(root).as_posix() for m in result["matches"])


def test_find_follow_links_and_skip_hidden(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "deep").mkdir(parents=True)
    (target / "deep/.mcp.json").write_text("{}")
    (tmp_path / "root/.hidden").mkdir(parents=True)
    (tmp_path / "root/.hidden/.mcp.json").write_text("{}")
    (tmp_path / "root/.mcp.json").write_text("{}")
    os.symlink(target, tmp_path / "root/a")
    root = tmp_path / "root"

    assert _find(root, file_names=[".mcp.json"]) == [".hidden/.mcp.json", ".mcp.json"]
    assert _find(root, file_names=[".mcp.json"], follow_links=True, skip_hidden=True) == [
        ".mcp.json",
        "a/deep/.mcp.json",
    ]


def test_find_symlink_loop_is_bounded(tmp_path: Path) -> None:
    os.symlink(tmp_path, tmp_path / "loop")
    result = run_op({"op_id": "1", "kind": "find", "roots": [str(tmp_path)], "max_depth": 12, "follow_links": True})
    assert result["status"] == "ok"


def _mcp(key: str, name: str, **flags: bool) -> dict:
    return {
        "client": "claude code",
        "username": "me",
        "key": key,
        "candidates": [{"maps": [{name: {"command": name}}]}],
        "fallback": {"kind": "parse_error", "message": "x"},
        **flags,
    }


def test_merge_well_known_first_and_canonical(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text("{}")
    link = tmp_path / "link.json"
    os.symlink(real, link)
    found = {
        "clients": [{"name": "claude code", "client_path": "/x", "username": "me"}],
        "mcp_configs": [
            # Arrives after the discoverer entry but is applied first.
            _mcp("/wk.json", "discoverer", canonical=True),
            _mcp("/wk.json", "well-known", well_known=True),
            _mcp(str(link), "via-link", canonical=True),
            _mcp(str(real), "direct", canonical=True),
        ],
        "skills_dirs": [],
    }
    (client,) = build_clients(found)
    configs = client.mcp_configs
    assert [name for name, _ in configs["/wk.json"]] == ["discoverer"]
    # Two spellings of one file merge under its resolved path.
    assert [name for name, _ in configs[real.resolve().as_posix()]] == ["via-link", "direct"]
    assert str(link) not in configs
