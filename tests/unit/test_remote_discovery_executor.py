import base64
import hashlib

from rich.console import Console

from agent_scan.remote_discovery.client import Printer
from agent_scan.remote_discovery.executor import Executor
from agent_scan.remote_discovery.upload import MAX_PATH_CHARS, MockFileUploadApi, revision_path


def _executor():
    calls = []
    api = MockFileUploadApi("org", lambda *a: calls.append(a))
    rev = api.create_revision()
    return Executor(api, rev), rev, calls


def _op(kind, **kw):
    return {"op_id": "o1", "ctx": "c", "kind": kind, "handler": kw.pop("handler", "h"), **kw}


def test_env_returns_only_allowed_names(monkeypatch):
    monkeypatch.setenv("HOME", "/Users/me")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/Users/me/.cfg")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    ex, _, _ = _executor()
    result = ex.run(_op("env", names=["HOME", "XDG_CONFIG_HOME", "CLAUDE_CONFIG_DIR", "OPENAI_API_KEY"]))
    assert result["env"] == {"HOME": "/Users/me", "XDG_CONFIG_HOME": "/Users/me/.cfg", "CLAUDE_CONFIG_DIR": None}
    assert result["denied"] == ["OPENAI_API_KEY"]


def test_read_denies_files_outside_policy(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("x")
    ex, _, _ = _executor()
    result = ex.run(_op("read", paths=[str(secret)]))
    assert result["status"] == "DENIED_BY_POLICY"
    assert "files" not in result


def test_read_sends_bytes_then_unchanged(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text('{"mcpServers": {}}')
    ex, _, _ = _executor()
    first = ex.run(_op("read", paths=[str(cfg), str(tmp_path / "nope" / "mcp.json")]))
    assert base64.b64decode(first["files"][0]["bytes_b64"]) == b'{"mcpServers": {}}'
    assert first["missing"] == [str(tmp_path / "nope" / "mcp.json")]
    second = ex.run(_op("read", paths=[str(cfg)]))
    assert second["files"] == [] and second["unchanged"] == [str(cfg)]
    other_handler = ex.run(_op("read", handler="h2", paths=[str(cfg)]))
    assert len(other_handler["files"]) == 1


def test_glob_rejects_recursive_and_wildcard_names(tmp_path):
    ex, _, _ = _executor()
    assert ex.run(_op("glob", patterns=[f"{tmp_path}/**/mcp.json"]))["status"] == "DENIED_BY_POLICY"
    assert ex.run(_op("glob", patterns=[f"{tmp_path}/*/*"]))["status"] == "DENIED_BY_POLICY"


def test_glob_matches(tmp_path):
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "workspace.json").write_text("{}")
    ex, _, _ = _executor()
    result = ex.run(_op("glob", patterns=[f"{tmp_path}/*/workspace.json"]))
    assert [f["path"] for f in result["files"]] == [f"{tmp_path}/a/workspace.json", f"{tmp_path}/b/workspace.json"]


def test_find_respects_depth_and_names(tmp_path):
    (tmp_path / "p" / "skills").mkdir(parents=True)
    (tmp_path / "p" / "mcp.json").write_text("{}")
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "mcp.json").write_text("{}")
    ex, _, _ = _executor()
    result = ex.run(_op("find", roots=[str(tmp_path)], file_names=["mcp.json"], dir_names=["skills"], max_depth=2))
    assert {(m["path"], m["kind"]) for m in result["matches"]} == {
        (f"{tmp_path}/p/mcp.json", "file"),
        (f"{tmp_path}/p/skills", "dir"),
    }
    assert ex.run(_op("find", roots=[str(tmp_path)], file_names=["id_rsa"], max_depth=2))["status"] == (
        "DENIED_BY_POLICY"
    )


def test_upload_tree_uploads_once_and_lists(tmp_path):
    skills = tmp_path / "skills"
    (skills / "s1").mkdir(parents=True)
    (skills / "s1" / "SKILL.md").write_text("# s1")
    (skills / "s1" / ".git").mkdir()
    (skills / "s1" / ".git" / "HEAD").write_text("x")
    ex, rev, calls = _executor()
    result = ex.run(_op("upload_tree", dirs=[str(skills), str(tmp_path / "x" / "skills")]))
    file_sha = hashlib.sha256(b"# s1").hexdigest()
    manifest = hashlib.sha256(f"s1/SKILL.md\0{file_sha}\n".encode()).hexdigest()
    assert result["dirs"][0] == {
        "path": str(skills),
        "status": "OK",
        "file_count": 1,
        "manifest_sha256": manifest,
    }
    assert result["dirs"][1] == {"path": str(tmp_path / "x" / "skills"), "status": "NOT_FOUND"}
    assert len(rev.files) == 1 and rev.parts == 1
    ex.run(_op("upload_tree", dirs=[str(skills)]))
    assert rev.parts == 1
    assert ex.run(_op("upload_tree", dirs=[str(tmp_path)]))["status"] == "DENIED_BY_POLICY"
    assert len(calls) == 2


def test_revision_path_caps_length():
    long_path = "/" + "a" * 300 + "/SKILL.md"
    assert len(revision_path(long_path)) <= MAX_PATH_CHARS
    assert revision_path("/Users/me/x") == "Users/me/x"


def test_printer_truncates_upload_parts():
    parts = [{"name": f"f{i}", "bytes": 10} for i in range(5)]
    short = Printer(Console(), full=False, show_ctx=False).shorten({"parts": parts})
    assert short["parts"] == [parts[0], parts[1], "… 3 more parts, 30 bytes; --full to show"]
    assert Printer(Console(), full=True, show_ctx=False).shorten({"parts": parts})["parts"] == parts
