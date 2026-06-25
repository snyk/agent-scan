"""Unit tests for ``skill_client``: skill-tree inspection, secret redaction at
read time, and the binary-marker contract shared with ``redact``.
"""

from agent_scan.models import SkillServer
from agent_scan.skill_client import inspect_skill
from tests.unit._secret_fixtures import synthetic_secret

# A high-entropy fake credential used to assert that skill contents are redacted
# at read time. Derived at runtime (see ``synthetic_secret``) rather than a
# hardcoded literal so repo secret scanners don't flag a checked-in secret.
_FAKE_SKILL_SECRET = synthetic_secret()


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
