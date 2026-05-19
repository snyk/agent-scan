from pathlib import Path

import pytest

from agent_scan import bootstrap as bootstrap_module


@pytest.mark.asyncio
async def test_payload_includes_required_fields(monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path("/home/alice"), "alice")],
    )

    payload = await bootstrap_module._build_request("scan", None, "machine-1", ["--ci"])
    data = payload.model_dump()

    assert set(data) == {"client", "host", "paths"}
    assert data["client"]["name"] == "agent-scan"
    assert data["client"]["command"] == "scan"
    assert data["client"]["control_identifier"] == "machine-1"
    assert data["host"]["hostname"]
    assert data["host"]["current_username"]
    assert data["host"]["python_version"]
    assert data["paths"]["cwd"]
    assert data["paths"]["current_home_dir"]
    assert data["paths"]["executable"]


@pytest.mark.asyncio
async def test_home_directories_match_helper_and_are_capped(monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path(f"/home/user-{i}"), f"user-{i}") for i in range(1002)],
    )

    payload = await bootstrap_module._build_request("scan", None, None, [])
    paths = payload.model_dump()["paths"]

    assert len(paths["home_directories"]) == 1000
    assert paths["home_directories"][0] == {"path": "/home/user-0", "username": "user-0"}
    assert paths["home_directories_truncated"] is True


@pytest.mark.asyncio
async def test_windows_payload_reflects_platform_and_wsl(monkeypatch):
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    monkeypatch.setattr(bootstrap_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(bootstrap_module.platform, "release", lambda: "10")
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path("C:/Users/Alice"), "Alice")],
    )

    payload = await bootstrap_module._build_request("scan", None, None, [])
    host = payload.model_dump()["host"]

    assert host["os"] == "Windows"
    assert host["is_wsl"] is True


@pytest.mark.asyncio
async def test_argv_flags_are_redacted(monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path("/home/alice"), "alice")],
    )
    argv = [
        "--ci",
        "--no-skills",
        "--push-key",
        "AKIAIOSFODNN7EXAMPLE",
        "--control-server-H",
        "x-client-id:fake-pat-placeholder-not-a-real-token",
    ]

    payload = await bootstrap_module._build_request("scan", None, None, argv)
    argv_flags = payload.model_dump()["client"]["argv_flags"]

    assert "--ci" in argv_flags
    assert "--no-skills" in argv_flags
    assert "AKIAIOSFODNN7EXAMPLE" not in argv_flags
    assert "x-client-id:fake-pat-placeholder-not-a-real-token" not in argv_flags


@pytest.mark.asyncio
async def test_is_ci_flips_with_environment(monkeypatch):
    monkeypatch.setenv("AGENT_SCAN_ENVIRONMENT", "ci")
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path("/home/alice"), "alice")],
    )

    payload = await bootstrap_module._build_request("scan", None, None, [])

    assert payload.model_dump()["host"]["is_ci"] is True


def test_container_detection_defaults_false_on_permission_error(monkeypatch):
    monkeypatch.setattr(Path, "exists", lambda self: False)

    def raise_permission(self, *args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", raise_permission)

    assert bootstrap_module._detect_container() is False


def test_wsl_detection_defaults_false(monkeypatch):
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(bootstrap_module.platform, "release", lambda: "6.8.0-generic")

    assert bootstrap_module._detect_wsl() is False



@pytest.mark.asyncio
async def test_payload_excludes_schema_version_and_scanned_usernames(monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path("/home/alice"), "alice")],
    )

    payload = await bootstrap_module._build_request("scan", None, None, [])
    data = payload.model_dump()

    assert "schema_version" not in data
    assert "scanned_usernames" not in data
