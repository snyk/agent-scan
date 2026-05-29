"""Unit tests for command-file scanning in ``skill_client``.

``inspect_skills_dir`` only handles ``<name>/SKILL.md`` subdirectories; Claude
Code command files are flat ``*.md`` files, so they need their own scanner
(``inspect_commands_dir``) and ``inspect_skill`` must also accept a single-file
``SkillServer`` so the discovered commands can be inspected downstream.
"""

from agent_scan.models import SkillServer
from agent_scan.skill_client import inspect_commands_dir, inspect_skill


def test_inspect_commands_dir_surfaces_flat_md_files(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "deploy.md").write_text("# Deploy\nrun the deploy")
    (commands / "release.md").write_text("# Release")

    found = dict(inspect_commands_dir(str(commands)))

    assert set(found) == {"deploy", "release"}
    assert isinstance(found["deploy"], SkillServer)
    assert found["deploy"].path.endswith("/commands/deploy.md")


def test_inspect_commands_dir_namespaces_nested_files_with_colon(tmp_path):
    commands = tmp_path / "commands"
    (commands / "git").mkdir(parents=True)
    (commands / "git" / "commit.md").write_text("# Commit")

    names = {name for name, _ in inspect_commands_dir(str(commands))}

    assert names == {"git:commit"}


def test_inspect_commands_dir_ignores_non_md_files(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "deploy.md").write_text("# Deploy")
    (commands / "README.txt").write_text("not a command")
    (commands / "helper.py").write_text("print('hi')")

    names = {name for name, _ in inspect_commands_dir(str(commands))}

    assert names == {"deploy"}


def test_inspect_commands_dir_empty_dir_returns_empty(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()

    assert inspect_commands_dir(str(commands)) == []


def test_inspect_skill_handles_single_md_file_without_frontmatter(tmp_path):
    cmd = tmp_path / "deploy.md"
    cmd.write_text("# Deploy\nDo the deploy.")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    # Name falls back to the file stem when there is no YAML frontmatter.
    assert sig.metadata.serverInfo.name == "deploy"
    # The full file content is surfaced as a prompt.
    assert any("Do the deploy." in (p.description or "") for p in sig.prompts)


def test_inspect_skill_uses_frontmatter_description_for_command_file(tmp_path):
    cmd = tmp_path / "release.md"
    cmd.write_text("---\ndescription: Cut a release\n---\nSteps to release.")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    assert sig.metadata.instructions == "Cut a release"
