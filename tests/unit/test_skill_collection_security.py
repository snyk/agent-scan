"""ADS-1331: confined, bounded skill collection without losing readable siblings."""

import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from agent_scan import skill_client
from agent_scan.inspect import _inspect_skill
from agent_scan.models import DiscoveredSkill, InspectedPath
from agent_scan.models.api.v20260710 import SkillRequest
from agent_scan.printer import print_inspected_path
from agent_scan.skill_client import collect_skill_files, inspect_skills_dir, resolve_skill_name
from agent_scan.utils import is_path_within_boundary

SKILL_CONTENT = "---\nname: demo-skill\ndescription: harmless demo skill\n---\n\n# Demo skill\n"
CANARY = "INTERNAL-CANARY-not-a-real-secret\n"


@pytest.fixture
def skill(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    root = tmp_path / "skills" / "demo-skill"
    (root / "data").mkdir(parents=True)
    (root / "SKILL.md").write_text(SKILL_CONTENT)
    return root


@pytest.mark.parametrize("plugin_boundary", [False, True])
def test_escaping_file_symlink_is_reported_without_collecting_content(skill, tmp_path, plugin_boundary, capsys):
    target = tmp_path / "target"
    target.mkdir()
    (target / "secret_notes.md").write_text(CANARY)
    (skill / "data" / "notes.md").symlink_to("../../../target/secret_notes.md")
    discovered = (
        inspect_skills_dir(str(skill.parent), boundary=str(skill.parent))[0]
        if plugin_boundary
        else DiscoveredSkill(name=skill.name, path=str(skill))
    )

    inspected = _inspect_skill(discovered)

    assert [(file.path, file.content) for file in inspected.files] == [
        ("SKILL.md", SKILL_CONTENT),
        ("data/notes.md", "[link outside skill folder: home]"),
    ]
    assert inspected.error is not None
    assert inspected.error.category == "skill_scan_error"
    assert "Skipped data/notes.md: Path resolves outside the skill root" in inspected.error.message
    assert CANARY.strip() not in inspected.model_dump_json()
    request = SkillRequest.from_inspected(inspected)
    assert request.error is not None
    assert "data/notes.md" in request.error.message
    assert CANARY.strip() not in request.model_dump_json()
    assert request.files == inspected.files
    assert SkillRequest.model_validate_json(request.model_dump_json()).files == inspected.files
    assert str(target) not in request.model_dump_json()
    print_inspected_path(InspectedPath(path=str(skill), skills=[inspected]))
    output = capsys.readouterr().out
    assert "data/notes.md" in output
    assert "SKILL.md" in output


@pytest.mark.parametrize("target_name", ["target", "demo-skill-sibling"])
def test_escaping_directory_symlink_is_not_traversed(skill, tmp_path, target_name):
    outside = skill.parent / target_name
    outside.mkdir()
    (outside / "notes.md").write_text(CANARY)
    (skill / "data" / "external").symlink_to(outside, target_is_directory=True)
    errors = []

    files = collect_skill_files(str(skill), errors=errors)

    assert [(file.path, file.content) for file in files] == [
        ("SKILL.md", SKILL_CONTENT),
        ("data/external", "[link outside skill folder: home]"),
    ]
    assert errors == ["Skipped data/external: Path resolves outside the skill root"]


def test_symlinked_root_and_internal_links_remain_supported(skill, tmp_path):
    (skill / "data" / "notes.md").write_text("safe reference")
    (skill / "reference.md").symlink_to("data/notes.md")
    (skill / "references").symlink_to("data", target_is_directory=True)
    root_link = tmp_path / "linked-skill"
    root_link.symlink_to(skill, target_is_directory=True)

    inspected = _inspect_skill(DiscoveredSkill(name="linked", path=str(root_link)))

    assert inspected.name == "demo-skill"
    assert inspected.error is None
    assert {file.path: file.content for file in inspected.files} == {
        "SKILL.md": SKILL_CONTENT,
        "reference.md": "safe reference",
        "data/notes.md": "safe reference",
        "references/notes.md": "safe reference",
    }


def test_internal_skill_md_symlink_is_allowed(skill):
    (skill / "SKILL.md").rename(skill / "data" / "instructions.md")
    (skill / "SKILL.md").symlink_to("data/instructions.md")

    inspected = _inspect_skill(DiscoveredSkill(name="demo", path=str(skill)))

    assert inspected.name == "demo-skill"
    assert inspected.error is None
    assert {file.path for file in inspected.files} == {"SKILL.md", "data/instructions.md"}


def test_broken_symlink_does_not_blank_skill(skill):
    (skill / "data" / "broken.md").symlink_to("missing.md")

    inspected = _inspect_skill(DiscoveredSkill(name="demo", path=str(skill)))

    assert [(file.path, file.content) for file in inspected.files] == [
        ("SKILL.md", SKILL_CONTENT),
        ("data/broken.md", "[broken skill link: missing]"),
    ]
    assert inspected.name == "demo-skill"
    assert inspected.error is not None
    assert "data/broken.md" in inspected.error.message


@pytest.mark.parametrize("failure", [PermissionError("denied"), FileNotFoundError("removed")])
def test_file_open_error_preserves_readable_siblings(skill, failure):
    failing = skill / "data" / "notes.md"
    failing.write_text("not readable")
    original_open = open

    def fail_one_file(path, *args, **kwargs):
        if Path(path) == failing:
            raise failure
        return original_open(path, *args, **kwargs)

    errors = []
    with patch("builtins.open", side_effect=fail_one_file):
        files = collect_skill_files(str(skill), errors=errors)

    assert [file.path for file in files] == ["SKILL.md"]
    assert len(errors) == 1
    assert errors == [f"Skipped data/notes.md: {type(failure).__name__}"]


@pytest.mark.parametrize(
    "filename,content", [("large.md", b"a" * 129), ("large.bin", b"\xff" * 129), ("wide.md", "é" * 65)]
)
def test_oversized_files_are_per_file_errors(skill, monkeypatch, filename, content):
    monkeypatch.setattr(skill_client, "_MAX_SKILL_FILE_BYTES", 128)
    (skill / filename).write_bytes(content.encode() if isinstance(content, str) else content)

    inspected = _inspect_skill(DiscoveredSkill(name="demo", path=str(skill)))

    assert [file.path for file in inspected.files] == ["SKILL.md"]
    assert inspected.error is not None
    assert f"Skipped {filename}: Skill file exceeds 128 byte limit" in inspected.error.message


def test_read_limit_is_enforced_even_if_file_grows_after_stat(skill, monkeypatch):
    monkeypatch.setattr(skill_client, "_MAX_SKILL_FILE_BYTES", 128)
    monkeypatch.setattr(skill_client.os, "fstat", lambda fd: SimpleNamespace(st_size=0))
    (skill / "large.md").write_bytes(b"a" * 129)
    errors = []

    assert [file.path for file in collect_skill_files(str(skill), errors=errors)] == ["SKILL.md"]
    assert errors == ["Skipped large.md: Skill file exceeds 128 byte limit"]


def test_oversized_command_has_visible_file_error(tmp_path, monkeypatch):
    monkeypatch.setattr(skill_client, "_MAX_SKILL_FILE_BYTES", 128)
    command = tmp_path / "command.md"
    command.write_bytes(b"a" * 129)

    inspected = _inspect_skill(DiscoveredSkill(name="command", path=str(command)))

    assert inspected.files == []
    assert inspected.error is not None
    assert inspected.error.message == "Skipped command.md: Skill file exceeds 128 byte limit"


def test_invalid_utf8_file_does_not_blank_skill(skill):
    (skill / "invalid.md").write_bytes(b"\xff")

    inspected = _inspect_skill(DiscoveredSkill(name="demo", path=str(skill)))

    assert [file.path for file in inspected.files] == ["SKILL.md"]
    assert inspected.error is not None
    assert "Skipped invalid.md:" in inspected.error.message


def test_file_at_read_limit_is_collected(skill, monkeypatch):
    monkeypatch.setattr(skill_client, "_MAX_SKILL_FILE_BYTES", 128)
    (skill / "data" / "notes.md").write_bytes(b"a" * 128)
    errors = []

    files = collect_skill_files(str(skill), errors=errors)

    assert len(files) == 2
    assert errors == []


def test_production_size_limit_rejects_sparse_file_before_read(skill):
    with (skill / "large.bin").open("wb") as file:
        file.truncate(20 * 1024 * 1024 + 1)
    errors = []

    assert [file.path for file in collect_skill_files(str(skill), errors=errors)] == ["SKILL.md"]
    assert "byte limit" in errors[0]


def test_skill_name_read_is_also_bounded(skill, monkeypatch):
    monkeypatch.setattr(skill_client, "_MAX_SKILL_FILE_BYTES", 32)
    with pytest.raises(skill_client.SkillInspectionError, match="byte limit"):
        resolve_skill_name(DiscoveredSkill(name="demo", path=str(skill)))


def test_depth_limit_reports_skipped_directory(skill, monkeypatch):
    monkeypatch.setattr(skill_client, "_MAX_SKILL_WALK_DEPTH", 2)
    deep = skill / "data" / "nested"
    deep.mkdir()
    (deep / "notes.md").write_text("too deep")
    errors = []

    assert [file.path for file in collect_skill_files(str(skill), errors=errors)] == ["SKILL.md"]
    assert errors == ["Skipped data/nested: Skill directory exceeds 2 level depth limit"]


def test_boundary_uses_resolved_paths_and_not_string_prefixes(skill, tmp_path):
    assert is_path_within_boundary(skill / "SKILL.md", skill)
    assert not is_path_within_boundary(str(skill) + "-sibling/file.md", skill)
    (skill / "data" / "external").symlink_to(tmp_path, target_is_directory=True)
    assert not is_path_within_boundary(skill / "data" / "external" / "file.md", skill)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not available on this platform")
def test_skill_md_special_file_is_not_read(skill):
    (skill / "SKILL.md").unlink()
    os.mkfifo(skill / "SKILL.md")

    inspected = _inspect_skill(DiscoveredSkill(name="demo", path=str(skill)))

    assert inspected.files == []
    assert inspected.error is not None
    assert "not a regular file" in inspected.error.message
