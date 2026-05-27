import pytest

from agent_scan.inspect import get_mcp_config_per_client
from agent_scan.well_known_clients import (
    LINUX_WELL_KNOWN_CLIENTS,
    MACOS_WELL_KNOWN_CLIENTS,
    WINDOWS_WELL_KNOWN_CLIENTS,
)


def _agents_client(clients):
    return next(client for client in clients if client.name == "agents")


def test_agents_client_discovers_agents_skills_directory_on_all_platforms():
    for clients in (MACOS_WELL_KNOWN_CLIENTS, LINUX_WELL_KNOWN_CLIENTS, WINDOWS_WELL_KNOWN_CLIENTS):
        agents = _agents_client(clients)

        assert "~/.agents" in agents.client_exists_paths
        assert "~/.agents/skills" in agents.skills_dir_paths


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "clients",
    [MACOS_WELL_KNOWN_CLIENTS, LINUX_WELL_KNOWN_CLIENTS, WINDOWS_WELL_KNOWN_CLIENTS],
    ids=["macos", "linux", "windows"],
)
async def test_agents_skills_directory_is_scanned_from_default_home(tmp_path, clients):
    home = tmp_path / "home"
    skill_dir = home / ".agents" / "skills" / "demo-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Demo Skill\n\nA test skill.", encoding="utf-8")

    ctis = await get_mcp_config_per_client(_agents_client(clients), [(home, "test-user")])

    skills_path = (home / ".agents" / "skills").resolve().as_posix()
    assert len(ctis) == 1
    assert ctis[0].username == "test-user"
    assert skills_path in ctis[0].skills_dirs
    skills = ctis[0].skills_dirs[skills_path]
    assert isinstance(skills, list)
    assert [(name, skill.path) for name, skill in skills] == [("demo-skill", skill_dir.as_posix())]
