"""Unit tests for command-file scanning in ``skill_client``.

``inspect_skills_dir`` only handles ``<name>/SKILL.md`` subdirectories; Claude
Code command files are flat ``*.md`` files, so they need their own scanner
(``inspect_commands_dir``).
"""

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from agent_scan.models.skill import DiscoveredSkill, SkillFrontmatter
from agent_scan.redact import redact_text
from agent_scan.skill_client import (
    BINARY_FILE_DESCRIPTION_PREFIX,
    SkillInspectionError,
    collect_skill_files,
    inspect_commands_dir,
    parse_skill_frontmatter,
    resolve_skill_name,
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

    files = collect_skill_files(str(skill))

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


def test_collect_skill_files_follows_symlinked_command_file(tmp_path):
    target = tmp_path / "target.md"
    target.write_text("command instructions")
    link = tmp_path / "skill.md"
    link.symlink_to(target)

    files = collect_skill_files(str(link))

    assert [(file.path, file.content) for file in files] == [("skill.md", "command instructions")]


def test_collect_skill_files_follows_symlinked_skill_directory(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text("skill instructions")
    link = tmp_path / "skill"
    link.symlink_to(target, target_is_directory=True)

    files = collect_skill_files(str(link))

    assert [(file.path, file.content) for file in files] == [("SKILL.md", "skill instructions")]


def test_collect_skill_files_follows_symlinked_file_inside_skill(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("linked reference")
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("instructions")
    (skill / "reference.txt").symlink_to(outside)

    by_path = {file.path: file.content for file in collect_skill_files(str(skill))}

    assert by_path == {
        "SKILL.md": "instructions",
        "reference.txt": "linked reference",
    }


def test_collect_skill_files_follows_symlinked_directory_inside_skill(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "reference.md").write_text("linked reference")
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("instructions")
    (skill / "references").symlink_to(outside, target_is_directory=True)

    by_path = {file.path: file.content for file in collect_skill_files(str(skill))}

    assert by_path == {
        "SKILL.md": "instructions",
        "references/reference.md": "linked reference",
    }


def _collect_skill_files_in_subprocess(skill_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from agent_scan.skill_client import collect_skill_files; import sys; collect_skill_files(sys.argv[1])",
            str(skill_path),
        ],
        capture_output=True,
        text=True,
        # Guards against a real hang (symlink cycle / blocking FIFO open), not a
        # perf budget: the child cold-starts a fresh interpreter and imports
        # detect_secrets, which can take >2s on a loaded CI runner. Kept well
        # above that import cost so a genuine hang still fails fast.
        timeout=10,
        check=False,
    )


def test_collect_skill_files_rejects_symlink_cycle(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("instructions")
    (skill / "loop").symlink_to(skill, target_is_directory=True)

    result = _collect_skill_files_in_subprocess(skill)

    assert result.returncode != 0
    assert "symbolic link cycle" in result.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not available on this platform")
def test_collect_skill_files_rejects_symlink_to_fifo(tmp_path):
    fifo = tmp_path / "input"
    os.mkfifo(fifo)
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("instructions")
    (skill / "input.txt").symlink_to(fifo)

    result = _collect_skill_files_in_subprocess(skill)

    assert result.returncode != 0
    assert "not a regular file" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory permissions required")
def test_collect_skill_files_propagates_directory_traversal_error(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("instructions")
    unreadable = skill / "unreadable"
    unreadable.mkdir()
    unreadable.chmod(0)
    if os.access(unreadable, os.R_OK):
        unreadable.chmod(0o700)
        pytest.skip("Current user can read mode-000 directories")

    try:
        with pytest.raises(PermissionError):
            collect_skill_files(str(skill))
    finally:
        unreadable.chmod(0o700)


def test_resolve_skill_name_requires_skill_md_for_directory_skill(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "reference.md").write_text("# Reference")
    with pytest.raises(SkillInspectionError, match=r"neither SKILL\.md nor skill\.md"):
        resolve_skill_name(DiscoveredSkill(name="skill", path=str(skill)))


def test_parse_skill_frontmatter_rejects_malformed_yaml(tmp_path):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: [unterminated\n---\n# Instructions\n")
    skill_md = collect_skill_files(str(skill))[0]

    with pytest.raises(SkillInspectionError, match="invalid yaml"):
        parse_skill_frontmatter(skill_md.content, str(skill))


@pytest.mark.parametrize("frontmatter", ["[one, two]", "plain text", "42", "null"])
def test_parse_skill_frontmatter_rejects_non_mapping_yaml(tmp_path, frontmatter):
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(f"---\n{frontmatter}\n---\n# Instructions\n")
    skill_md = collect_skill_files(str(skill))[0]

    with pytest.raises(SkillInspectionError, match="frontmatter must be a mapping"):
        parse_skill_frontmatter(skill_md.content, str(skill))


@pytest.mark.parametrize("missing_field", ["name", "description"])
def test_parse_skill_frontmatter_requires_identity_fields(tmp_path, missing_field):
    skill = tmp_path / "skill"
    skill.mkdir()
    frontmatter = {"name": "skill", "description": "Does useful work"}
    del frontmatter[missing_field]
    (skill / "SKILL.md").write_text(f"---\n{yaml.safe_dump(frontmatter)}---\n# Instructions\n")
    skill_md = collect_skill_files(str(skill))[0]

    with pytest.raises(SkillInspectionError, match=rf"Missing {missing_field}"):
        parse_skill_frontmatter(skill_md.content, str(skill))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", 123),
        ("description", ["not", "text"]),
        ("name", ""),
        ("description", "   "),
    ],
)
def test_parse_skill_frontmatter_rejects_non_text_identity_fields(tmp_path, field, value):
    skill = tmp_path / "skill"
    skill.mkdir()
    frontmatter = {"name": "skill", "description": "Does useful work", field: value}
    (skill / "SKILL.md").write_text(f"---\n{yaml.safe_dump(frontmatter)}---\n# Instructions\n")
    skill_md = collect_skill_files(str(skill))[0]

    with pytest.raises(SkillInspectionError, match=rf"{field}.*non-empty string"):
        parse_skill_frontmatter(skill_md.content, str(skill))


def test_parse_skill_frontmatter_returns_validated_metadata():
    assert parse_skill_frontmatter(
        "---\nname: '  my-skill  '\ndescription: '  Does useful work  '\n---\n# Content",
        "/skills/my-skill",
    ) == SkillFrontmatter(
        name="my-skill",
        description="Does useful work",
    )


def test_parse_skill_frontmatter_ignores_delimited_body_content():
    content = "Intro text\n---\nname: not-frontmatter\ndescription: desc\n---\n# Content"

    with pytest.raises(SkillInspectionError, match="Could not find the YAML"):
        parse_skill_frontmatter(content, "/skills/example")


def test_resolve_skill_name_uses_directory_skill_frontmatter(tmp_path):
    skill_path = tmp_path / "directory-name"
    skill_path.mkdir()
    (skill_path / "SKILL.md").write_text("---\nname: authentic-skill\ndescription: desc\n---\n# Content")

    assert resolve_skill_name(DiscoveredSkill(name="directory-name", path=str(skill_path))) == "authentic-skill"


def test_resolve_skill_name_preserves_namespaced_command_name(tmp_path):
    command_path = tmp_path / "commit.md"
    command_path.write_text("---\nname: custom-git-commit\ndescription: desc\n---\n# Prompt")

    assert resolve_skill_name(DiscoveredSkill(name="git:commit", path=str(command_path))) == "git:commit"


def test_resolve_skill_name_reads_frontmatter_before_file_content_redaction(tmp_path):
    skill_path = tmp_path / "directory-name"
    skill_path.mkdir()
    (skill_path / "SKILL.md").write_text(
        f"---\nname: authentic-skill\ndescription: {_FAKE_SKILL_SECRET}\n---\n# Content"
    )

    files = collect_skill_files(str(skill_path))

    assert "**REDACTED_SECRET_" in files[0].content
    assert resolve_skill_name(DiscoveredSkill(name="directory-name", path=str(skill_path))) == "authentic-skill"


@pytest.mark.parametrize(
    "content",
    [
        "# Prompt without frontmatter",
        "---\n[invalid yaml\n---",
        "---\ndescription: no name\n---",
        "---\nname: 123\n---",
    ],
)
def test_resolve_skill_name_preserves_command_name_regardless_of_frontmatter(tmp_path, content):
    command_path = tmp_path / "commit.md"
    command_path.write_text(content)

    assert resolve_skill_name(DiscoveredSkill(name="git:commit", path=str(command_path))) == "git:commit"
