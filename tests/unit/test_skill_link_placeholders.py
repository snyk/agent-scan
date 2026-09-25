"""Link signals contain only fixed categories, never external content or paths."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_scan import skill_client
from agent_scan.inspect import _inspect_skill
from agent_scan.models import DiscoveredSkill
from agent_scan.models.api.v20260710 import SkillRequest
from agent_scan.skill_client import collect_skill_files
from agent_scan.utils import is_path_within_boundary

SKILL_CONTENT = "---\nname: demo\ndescription: demo skill\n---\nUse data/reference to do the task.\n"
CANARY = "INTERNAL-CANARY-not-a-real-secret"


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "private-user-name"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(skill_client, "_SKILL_LINK_SYSTEM_PATHS", (str(tmp_path / "system"),))
    root = home / "skills" / "demo"
    (root / "data").mkdir(parents=True)
    (root / "SKILL.md").write_text(SKILL_CONTENT)
    return home, root


@pytest.mark.parametrize(
    "target_relative,category",
    [
        (".ssh/id_demo", "ssh-credentials"),
        (".aws/credentials", "cloud-credentials"),
        (".config/gcloud/application_default_credentials.json", "cloud-credentials"),
        (".azure/token", "cloud-credentials"),
        (".kube/config", "cloud-credentials"),
        (".netrc", "netrc-credentials"),
        (".git-credentials", "netrc-credentials"),
        (".npmrc", "netrc-credentials"),
        (".pypirc", "netrc-credentials"),
        ("notes.md", "home"),
        (".ssh-other/notes.md", "home"),
        (".config/gcloud-other/notes.md", "home"),
        (".netrc-backup", "home"),
        ("../system/config", "system"),
        ("../system-other/config", "other"),
        ("../external/notes.md", "other"),
    ],
)
def test_external_link_placeholder_category_and_payload(layout, target_relative, category):
    home, root = layout
    target = home / target_relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(CANARY)
    (root / "data" / "reference").symlink_to(target)
    real_open = open

    def confined_open(path, *args, **kwargs):
        assert is_path_within_boundary(path, root), "External target must never be opened"
        return real_open(path, *args, **kwargs)

    with patch("builtins.open", side_effect=confined_open):
        inspected = _inspect_skill(DiscoveredSkill(name="demo", path=str(root)))

    request = SkillRequest.from_inspected(inspected)
    assert [file.path for file in request.files] == ["SKILL.md", "data/reference"]
    marker = request.files[1]
    assert marker.model_dump() == {"path": "data/reference", "content": f"[link outside skill folder: {category}]"}
    assert CANARY not in request.model_dump_json()
    assert str(target.resolve()) not in marker.model_dump_json()
    assert "private-user-name" not in marker.model_dump_json()
    assert request.error is not None
    assert request.error.message == "Skipped data/reference: Path resolves outside the skill root"
    assert SkillRequest.model_validate_json(request.model_dump_json()).files == request.files


def test_external_directory_gets_one_placeholder_without_scanning_or_reading(layout):
    home, root = layout
    target = home / ".ssh"
    (target / "nested").mkdir(parents=True)
    (target / "id_demo").write_text(CANARY)
    (target / "nested" / "secret").write_text(CANARY)
    (root / "data" / "reference").symlink_to(target, target_is_directory=True)
    real_scandir = os.scandir

    def confined_scandir(path):
        assert is_path_within_boundary(path, root), "External directory must never be traversed"
        return real_scandir(path)

    with patch("agent_scan.skill_client.os.scandir", side_effect=confined_scandir):
        files = collect_skill_files(str(root))

    assert [(file.path, file.content) for file in files] == [
        ("SKILL.md", SKILL_CONTENT),
        ("data/reference", "[link outside skill folder: ssh-credentials]"),
    ]


@pytest.mark.parametrize("outside", [False, True])
@pytest.mark.parametrize("directory", [False, True])
def test_broken_links_have_missing_placeholder_and_warning(layout, outside, directory):
    home, root = layout
    target = home / ".ssh" / "missing" if outside else root / "missing"
    (root / "data" / "reference").symlink_to(target, target_is_directory=directory)
    errors = []

    files = collect_skill_files(str(root), errors=errors)

    kind = "link outside skill folder" if outside else "broken skill link"
    assert [(file.path, file.content) for file in files] == [
        ("SKILL.md", SKILL_CONTENT),
        ("data/reference", f"[{kind}: missing]"),
    ]
    assert len(errors) == 1
    assert errors[0].startswith("Skipped data/reference:")
    assert "private-user-name" not in errors[0]


def test_credential_category_follows_resolved_home_directory(layout):
    home, root = layout
    relocated = home.parent / "relocated-credentials"
    relocated.mkdir()
    (relocated / "id_demo").write_text(CANARY)
    (home / ".ssh").symlink_to(relocated, target_is_directory=True)
    (root / "data" / "reference").symlink_to(home / ".ssh" / "id_demo")

    files = collect_skill_files(str(root))

    assert files[1].content == "[link outside skill folder: ssh-credentials]"


def test_unreadable_target_still_has_coarse_category(layout):
    home, _ = layout
    with patch("agent_scan.skill_client.os.stat", side_effect=PermissionError):
        assert skill_client._skill_link_target_category(str(home / ".ssh" / "id_demo")) == "ssh-credentials"


@pytest.mark.parametrize("system_path", skill_client._SKILL_LINK_SYSTEM_PATHS)
def test_platform_system_paths_have_system_category(system_path):
    target = os.path.realpath(os.path.join(system_path, "synthetic-file"))
    with patch("agent_scan.skill_client.os.stat", return_value=None):
        assert skill_client._skill_link_target_category(target) == "system"


def test_normal_missing_file_is_not_misrepresented_as_link(layout):
    _, root = layout
    target = root / "data" / "reference"
    target.write_text("ordinary file")
    real_stat = os.stat

    def missing_regular_file(path, *args, **kwargs):
        if Path(path) == target:
            raise FileNotFoundError("removed")
        return real_stat(path, *args, **kwargs)

    errors = []
    with patch("agent_scan.skill_client.os.stat", side_effect=missing_regular_file):
        files = collect_skill_files(str(root), errors=errors)

    assert [file.path for file in files] == ["SKILL.md"]
    assert len(errors) == 1
    assert "Skipped data/reference:" in errors[0]
