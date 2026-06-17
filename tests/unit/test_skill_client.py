"""Unit tests for command-file scanning in ``skill_client``.

``inspect_skills_dir`` only handles ``<name>/SKILL.md`` subdirectories; Claude
Code command files are flat ``*.md`` files, so they need their own scanner
(``inspect_commands_dir``) and ``inspect_skill`` must also accept a single-file
``SkillServer`` so the discovered commands can be inspected downstream.
"""

from pathlib import Path

from agent_scan.models import SkillServer
from agent_scan.skill_client import inspect_commands_dir, inspect_skill
from tests.unit._secret_fixtures import synthetic_secret


def test_inspect_commands_dir_surfaces_flat_md_files(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "deploy.md").write_text("# Deploy\nrun the deploy")
    (commands / "release.md").write_text("# Release")

    found = dict(inspect_commands_dir(str(commands)))

    assert set(found) == {"deploy", "release"}
    assert isinstance(found["deploy"], SkillServer)
    # ``inspect_commands_dir`` builds paths with ``os.path.join`` (OS-native
    # separators), so compare via ``Path`` rather than a hardcoded "/" suffix.
    deploy_path = Path(found["deploy"].path)
    assert deploy_path.name == "deploy.md"
    assert deploy_path.parent.name == "commands"


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

    names = {name for name, _ in skill_client.inspect_commands_dir(str(commands))}

    assert "deploy" in names
    assert "a:b:c:deep" not in names


def test_inspect_skill_handles_single_md_file_without_frontmatter(tmp_path):
    cmd = tmp_path / "deploy.md"
    cmd.write_text("# Deploy\nDo the deploy.")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    # Name falls back to the file stem when there is no YAML frontmatter.
    assert sig.metadata.serverInfo.name == "deploy"
    # The full file content is surfaced as a prompt.
    assert any("Do the deploy." in (p.description or "") for p in sig.prompts)


def test_inspect_skill_command_file_prompt_name_matches_server_name(tmp_path):
    """The single prompt emitted for a command file carries the command's resolved
    name (the file stem) — not the raw ``<stem>.md`` filename — so the prompt and
    ``serverInfo`` agree on one name."""
    cmd = tmp_path / "deploy.md"
    cmd.write_text("# Deploy\nDo the deploy.")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    assert sig.metadata.serverInfo.name == "deploy"
    assert [p.name for p in sig.prompts] == ["deploy"]


def test_inspect_skill_command_file_prompt_name_follows_frontmatter_name(tmp_path):
    """A frontmatter ``name`` override applies to both ``serverInfo`` and the prompt,
    keeping the two consistent."""
    cmd = tmp_path / "deploy.md"
    cmd.write_text("---\nname: ship-it\ndescription: d\n---\nbody")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    assert sig.metadata.serverInfo.name == "ship-it"
    assert [p.name for p in sig.prompts] == ["ship-it"]


def test_inspect_skill_uses_frontmatter_description_for_command_file(tmp_path):
    cmd = tmp_path / "release.md"
    cmd.write_text("---\ndescription: Cut a release\n---\nSteps to release.")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    assert sig.metadata.instructions == "Cut a release"


def test_inspect_skill_non_string_frontmatter_does_not_crash(tmp_path):
    """A command file whose frontmatter ``description`` is a YAML list (not a
    string) must not raise — it should fall back to the file stem / empty desc."""
    cmd = tmp_path / "weird.md"
    cmd.write_text("---\ndescription:\n  - a\n  - b\n---\nbody")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    assert sig.metadata.serverInfo.name == "weird"
    assert isinstance(sig.metadata.instructions, str)


def test_inspect_skill_body_horizontal_rules_not_parsed_as_frontmatter(tmp_path):
    """A file that does NOT start with frontmatter but uses ``---`` as markdown
    horizontal rules must keep the file stem as its name, not parse body text."""
    cmd = tmp_path / "deploy.md"
    cmd.write_text("Run build\n\n---\n\nname: hijacked\ndescription: nope\n\n---\n\ndone")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    assert sig.metadata.serverInfo.name == "deploy"


# A high-entropy fake credential used to assert that skill contents are redacted
# at read time. Derived at runtime (see ``synthetic_secret``) rather than a
# hardcoded literal so repo secret scanners don't flag a checked-in secret.
_FAKE_SKILL_SECRET = synthetic_secret()


def test_inspect_skill_redacts_secrets_in_command_file(tmp_path):
    """inspect_skill must redact secrets in a single-file command before returning."""
    cmd = tmp_path / "deploy.md"
    cmd.write_text(f"# Deploy\nexport TOKEN={_FAKE_SKILL_SECRET}\n")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    assert _FAKE_SKILL_SECRET not in sig.model_dump_json()


def test_inspect_skill_redacts_secrets_across_skill_tree(tmp_path):
    """inspect_skill redacts secrets in SKILL.md, the frontmatter description,
    bundled scripts (tools), nested prompts and other resources -- the whole
    signature, across every file type traverse_skill_tree surfaces and into
    nested subdirectories."""
    skill = tmp_path / "myskill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        f"---\nname: myskill\ndescription: uses {_FAKE_SKILL_SECRET}\n---\n# Heading\nkey={_FAKE_SKILL_SECRET}\n"
    )
    # Scripts -> tools (one per supported language extension).
    (skill / "run.sh").write_text(f"export GH={_FAKE_SKILL_SECRET}\n")
    (skill / "deploy.py").write_text(f"API_KEY = '{_FAKE_SKILL_SECRET}'\n")
    (skill / "client.js").write_text(f"const token = '{_FAKE_SKILL_SECRET}';\n")
    (skill / "client.ts").write_text(f"const token: string = '{_FAKE_SKILL_SECRET}';\n")
    # Non-script, non-md files -> resources.
    (skill / "notes.txt").write_text(f"remember the token {_FAKE_SKILL_SECRET}\n")
    (skill / "config.json").write_text(f'{{"apiKey": "{_FAKE_SKILL_SECRET}"}}\n')
    # Nested directory with a markdown prompt -> recursion.
    nested = skill / "references"
    nested.mkdir()
    (nested / "guide.md").write_text(f"# Guide\nUse {_FAKE_SKILL_SECRET} to authenticate.\n")

    sig = inspect_skill(SkillServer(path=str(skill)))

    dump = sig.model_dump_json()
    assert _FAKE_SKILL_SECRET not in dump
    assert sig.metadata.serverInfo.name == "myskill"
    # Non-secret structure (skill name, descriptions, headings, file names,
    # prose) is preserved across every surfaced file and the nested prompt.
    for retained in (
        "myskill",
        "description",
        "uses",
        "# Heading",
        "run.sh",
        "deploy.py",
        "client.js",
        "client.ts",
        "notes.txt",
        "remember the token",
        "config.json",
        "guide.md",
        "# Guide",
        "to authenticate",
    ):
        assert retained in dump


def test_inspect_skill_preserves_clean_content(tmp_path):
    """Redaction at read time must not mangle skills that contain no secrets."""
    cmd = tmp_path / "deploy.md"
    cmd.write_text("# Deploy\nDo the deploy.")

    sig = inspect_skill(SkillServer(path=str(cmd)))

    assert any("Do the deploy." in (p.description or "") for p in sig.prompts)


def test_inspect_skill_preserves_binary_file_hash(tmp_path):
    """A binary resource is surfaced as a synthetic 'Binary file. Hash: <sha256>'
    description. That digest is self-generated and secret-free, so redaction at
    read time must leave it intact -- otherwise the 64-char hash trips the hex
    high-entropy detector and every binary collapses to an identical, useless
    description. Also guards against the binary-marker prefix drifting between
    skill_client (which writes it) and redact (which exempts it)."""
    import hashlib

    skill = tmp_path / "myskill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: myskill\ndescription: a skill\n---\n# Heading\n")
    blob = b"\xff\xfe\x00\x01\x02 not utf-8 \x80\x81"
    (skill / "logo.bin").write_bytes(blob)
    expected = f"Binary file. Hash: {hashlib.sha256(blob).hexdigest()}"

    sig = inspect_skill(SkillServer(path=str(skill)))

    assert any((r.description or "") == expected for r in sig.resources)


def test_binary_marker_prefix_owned_by_skill_client():
    """The binary-marker prefix is defined in ``skill_client`` itself, and
    ``redact``'s matcher accepts a marker built from it -- the two must not drift
    apart."""
    import agent_scan.skill_client as skill_client
    from agent_scan.redact import _is_synthetic_binary_description

    assert "BINARY_FILE_DESCRIPTION_PREFIX" in vars(skill_client)
    digest = "a" * 64
    assert _is_synthetic_binary_description(f"{skill_client.BINARY_FILE_DESCRIPTION_PREFIX}{digest}")


def test_redact_and_skill_client_import_without_cycle():
    """``redact`` imports the binary-marker prefix from ``skill_client`` lazily so
    the two modules don't form an import cycle. Guard against a regression that
    moves that import back to module scope: a fresh interpreter must import each
    module first without error, in either order."""
    import subprocess
    import sys

    for module in ("agent_scan.redact", "agent_scan.skill_client"):
        result = subprocess.run(
            [sys.executable, "-c", f"import {module}"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"importing {module} first failed:\n{result.stderr}"
