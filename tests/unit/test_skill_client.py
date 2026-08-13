"""Unit tests for command-file scanning in ``skill_client``.

``inspect_skills_dir`` only handles ``<name>/SKILL.md`` subdirectories; Claude
Code command files are flat ``*.md`` files, so they need their own scanner
(``inspect_commands_dir``).
"""

import hashlib
from pathlib import Path

import pytest
import yaml

from agent_scan.models.skill import DiscoveredSkill
from agent_scan.redact import redact_text
from agent_scan.skill_client import (
    BINARY_FILE_DESCRIPTION_PREFIX,
    SkillInspectionError,
    collect_skill_files,
    inspect_commands_dir,
)
from tests.unit._secret_fixtures import synthetic_secret

_FAKE_SKILL_SECRET = synthetic_secret()


def test_inspect_commands_dir_surfaces_flat_md_files(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "deploy.md").write_text("# Deploy\nrun the deploy")
    (commands / "release.md").write_text("# Release")

    found = {skill.name: skill for skill in inspect_commands_dir(str(commands))}

    assert set(found) == {"deploy", "release"}
    assert isinstance(found["deploy"], DiscoveredSkill)
    # ``inspect_commands_dir`` builds paths with ``os.path.join`` (OS-native
    # separators), so compare via ``Path`` rather than a hardcoded "/" suffix.
    deploy_path = Path(found["deploy"].path)
    assert deploy_path.name == "deploy.md"
    assert deploy_path.parent.name == "commands"


def test_inspect_commands_dir_namespaces_nested_files_with_colon(tmp_path):
    commands = tmp_path / "commands"
    (commands / "git").mkdir(parents=True)
    (commands / "git" / "commit.md").write_text("# Commit")

    names = {skill.name for skill in inspect_commands_dir(str(commands))}

    assert names == {"git:commit"}


def test_inspect_commands_dir_ignores_non_md_files(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "deploy.md").write_text("# Deploy")
    (commands / "README.txt").write_text("not a command")
    (commands / "helper.py").write_text("print('hi')")

    names = {skill.name for skill in inspect_commands_dir(str(commands))}

    assert names == {"deploy"}


def test_inspect_commands_dir_empty_dir_returns_empty(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()

    assert inspect_commands_dir(str(commands)) == []


def test_inspect_commands_dir_respects_max_walk_depth(tmp_path, monkeypatch):
    """A command file nested deeper than the depth cap is pruned — traversal stops
    at the cap rather than walking the whole subtree, mirroring the depth-bounded
    plugin/extension walks (``_walk_under_depth``) so a pathologically deep tree
    can't blow up the scan.
    """
    import agent_scan.skill_client as skill_client

    monkeypatch.setattr(skill_client, "_MAX_COMMANDS_WALK_DEPTH", 3)

    commands = tmp_path / "commands"
    commands.mkdir()
    # Shallow file (relative parts = 1) — within the cap, must be found.
    (commands / "deploy.md").write_text("# Deploy")
    # Deep file (relative parts = 4: a/b/c/deep.md) — beyond cap 3, must be pruned.
    deep = commands / "a" / "b" / "c"
    deep.mkdir(parents=True)
    (deep / "deep.md").write_text("# Deep")

    names = {skill.name for skill in skill_client.inspect_commands_dir(str(commands))}

    assert "deploy" in names
    assert "a:b:c:deep" not in names


# ---------------------------------------------------------------------------
# collect_skill_files: raw file collection for the v2026-07-10 request payload
# The collected files are the input to the v2026-07-10 request payload.
# ---------------------------------------------------------------------------


def test_collect_skill_files_single_file_command(tmp_path):
    cmd = tmp_path / "deploy.md"
    cmd.write_text("# Deploy\nrun the deploy")

    files = collect_skill_files(str(cmd))

    assert len(files) == 1
    assert files[0].path == "deploy.md"
    assert files[0].content == "# Deploy\nrun the deploy"


def test_collect_skill_files_directory_relative_paths(tmp_path):
    skill = tmp_path / "my-skill"
    (skill / "scripts").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: my-skill\n---\ndo things")
    (skill / "scripts" / "run.py").write_text("print('hi')")
    (skill / "reference.md").write_text("# Reference")

    by_path = {f.path: f.content for f in collect_skill_files(str(skill))}

    assert set(by_path) == {"SKILL.md", "reference.md", "scripts/run.py"}
    # nested files keep a forward-slash, skill-relative path
    assert by_path["scripts/run.py"] == "print('hi')"


def test_collect_skill_files_deterministic_order(tmp_path):
    skill = tmp_path / "skill"
    (skill / "a").mkdir(parents=True)
    (skill / "b").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: s\n---\nx")
    (skill / "a" / "one.md").write_text("1")
    (skill / "b" / "two.md").write_text("2")

    assert [f.path for f in collect_skill_files(str(skill))] == ["SKILL.md", "a/one.md", "b/two.md"]


def test_collect_skill_files_redacts_secrets(tmp_path):
    raw = f"api_key = {_FAKE_SKILL_SECRET}\n"
    cmd = tmp_path / "cmd.md"
    cmd.write_text(raw)

    files = collect_skill_files(str(cmd))

    assert _FAKE_SKILL_SECRET not in files[0].content
    # redaction is exactly the shared redact_text applied to the raw content
    assert files[0].content == redact_text(raw)


def test_collect_skill_files_redacts_secrets_from_every_text_file_kind(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        f"---\nname: skill\ndescription: Safe description\n---\napi_key = {_FAKE_SKILL_SECRET}\n"
    )
    (skill / "reference.md").write_text(f"api_key = {_FAKE_SKILL_SECRET}\n")
    (skill / "run.py").write_text(f'API_KEY = "{_FAKE_SKILL_SECRET}"\n')
    (skill / "config.txt").write_text(f"api_key = {_FAKE_SKILL_SECRET}\n")

    files = collect_skill_files(str(skill), validate_skill_md_frontmatter=True)

    assert {file.path for file in files} == {"SKILL.md", "reference.md", "run.py", "config.txt"}
    assert all(_FAKE_SKILL_SECRET not in file.content for file in files)


def test_collect_skill_files_binary_hash_marker(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: s\n---\nx")
    binary_content = b"\xff\xd8\xff\xe0\x00binary\x00data"
    (skill / "logo.png").write_bytes(binary_content)

    by_path = {f.path: f.content for f in collect_skill_files(str(skill))}

    assert by_path["logo.png"] == f"{BINARY_FILE_DESCRIPTION_PREFIX}{hashlib.sha256(binary_content).hexdigest()}"


def test_collect_skill_files_non_existent_path_raises(tmp_path):
    missing = tmp_path / "does-not-exist"
    with pytest.raises(FileNotFoundError):
        collect_skill_files(str(missing))


def test_collect_skill_files_rejects_path_that_is_not_file_or_directory(tmp_path, monkeypatch):
    special_path = tmp_path / "special"
    special_path.touch()
    monkeypatch.setattr("agent_scan.skill_client.os.path.isfile", lambda _path: False)
    monkeypatch.setattr("agent_scan.skill_client.os.path.isdir", lambda _path: False)

    with pytest.raises(ValueError, match="not a file or directory"):
        collect_skill_files(str(special_path))


def test_collect_skill_files_rejects_symlinked_skill_path(tmp_path):
    target = tmp_path / "target.md"
    target.write_text("secret")
    link = tmp_path / "skill.md"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        collect_skill_files(str(link))


def test_collect_skill_files_rejects_symlinked_file_inside_skill(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("instructions")
    (skill / "outside.txt").symlink_to(outside)

    with pytest.raises(ValueError, match="symbolic link"):
        collect_skill_files(str(skill))


def test_collect_skill_files_requires_skill_md_when_frontmatter_validation_is_enabled(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "reference.md").write_text("# Reference")

    with pytest.raises(SkillInspectionError, match=r"neither SKILL\.md nor skill\.md"):
        collect_skill_files(str(skill), validate_skill_md_frontmatter=True)


def test_collect_skill_files_rejects_malformed_skill_md_frontmatter_yaml(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: [unterminated\n---\n# Instructions\n")

    with pytest.raises(SkillInspectionError, match="invalid yaml"):
        collect_skill_files(str(skill), validate_skill_md_frontmatter=True)


@pytest.mark.parametrize("frontmatter", ["[one, two]", "plain text", "42", "null"])
def test_collect_skill_files_rejects_non_mapping_skill_md_frontmatter(tmp_path, frontmatter):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(f"---\n{frontmatter}\n---\n# Instructions\n")

    with pytest.raises(SkillInspectionError, match="frontmatter must be a mapping"):
        collect_skill_files(str(skill), validate_skill_md_frontmatter=True)


@pytest.mark.parametrize("missing_field", ["name", "description"])
def test_collect_skill_files_requires_skill_md_frontmatter_identity_fields(tmp_path, missing_field):
    skill = tmp_path / "skill"
    skill.mkdir()
    frontmatter = {"name": "skill", "description": "Does useful work"}
    del frontmatter[missing_field]
    (skill / "SKILL.md").write_text(f"---\n{yaml.safe_dump(frontmatter)}---\n# Instructions\n")

    with pytest.raises(SkillInspectionError, match=rf"Missing {missing_field}"):
        collect_skill_files(str(skill), validate_skill_md_frontmatter=True)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", 123),
        ("description", ["not", "text"]),
        ("name", ""),
        ("description", "   "),
    ],
)
def test_collect_skill_files_rejects_non_text_skill_md_frontmatter_identity_fields(tmp_path, field, value):
    skill = tmp_path / "skill"
    skill.mkdir()
    frontmatter = {"name": "skill", "description": "Does useful work", field: value}
    (skill / "SKILL.md").write_text(f"---\n{yaml.safe_dump(frontmatter)}---\n# Instructions\n")

    with pytest.raises(SkillInspectionError, match=rf"{field}.*non-empty string"):
        collect_skill_files(str(skill), validate_skill_md_frontmatter=True)
