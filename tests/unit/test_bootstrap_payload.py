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

    payload = await bootstrap_module._build_request("scan", None, None, [], scan_all_users=True)
    paths = payload.model_dump()["paths"]

    assert len(paths["home_directories"]) == 1000
    assert paths["home_directories"][0] == {"path": "/home/user-0", "username": "user-0"}
    assert paths["home_directories_truncated"] is True


@pytest.mark.asyncio
async def test_home_enumeration_defaults_to_current_user_only(monkeypatch):
    """Without --scan-all-users, bootstrap must not enumerate every readable home dir.

    The bootstrap payload's home_directories field is intended to mirror what the
    scan itself touches — so a single-user scan should only report the current
    user's home, never the full /home/* tree (or Windows profiles / WSL homes).
    """
    captured_kwargs: dict = {}

    def fake_home_dirs(all_users=False):
        captured_kwargs["all_users"] = all_users
        return [(Path("/home/me"), "me")] if not all_users else [(Path(f"/home/u{i}"), f"u{i}") for i in range(50)]

    monkeypatch.setattr(bootstrap_module, "get_readable_home_directories", fake_home_dirs)

    payload = await bootstrap_module._build_request("scan", None, None, [])
    paths = payload.model_dump()["paths"]

    assert captured_kwargs["all_users"] is False
    assert paths["home_directories"] == [{"path": "/home/me", "username": "me"}]


@pytest.mark.asyncio
async def test_home_enumeration_opts_in_when_scan_all_users(monkeypatch):
    """Passing scan_all_users=True must forward all_users=True to the helper."""
    captured_kwargs: dict = {}

    def fake_home_dirs(all_users=False):
        captured_kwargs["all_users"] = all_users
        return [(Path(f"/home/u{i}"), f"u{i}") for i in range(3)]

    monkeypatch.setattr(bootstrap_module, "get_readable_home_directories", fake_home_dirs)

    payload = await bootstrap_module._build_request("scan", None, None, [], scan_all_users=True)
    paths = payload.model_dump()["paths"]

    assert captured_kwargs["all_users"] is True
    assert {entry["username"] for entry in paths["home_directories"]} == {"u0", "u1", "u2"}


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
    # Mixed-case alphanumeric placeholders. Pure lowercase-hex literals
    # of this length match upstream secret-scanner heuristics for legacy
    # GitHub PATs and trigger false positives on the PR scan; mixing in
    # uppercase letters breaks that shape while keeping the entropy high
    # enough for detect-secrets' HighEntropyStringsPlugin. Redaction here
    # is actually driven by Pass D (sensitive flag/header name) regardless
    # of value shape, so any non-empty distinct values would work.
    push_key_value = "Hk9mPq2vNwBzRtY7Lc4hJfDsAe6u"
    client_id_value = "Vp3WbZxMrTcLqYn8XfJgAk5Bs7Hu"
    argv = [
        "--ci",
        "--no-skills",
        "--push-key",
        push_key_value,
        "--control-server-H",
        f"x-client-id:{client_id_value}",
    ]

    payload = await bootstrap_module._build_request("scan", None, None, argv)
    argv_flags = payload.model_dump()["client"]["argv_flags"]

    assert "--ci" in argv_flags
    assert "--no-skills" in argv_flags
    assert push_key_value not in argv_flags
    assert client_id_value not in argv_flags
    assert any(flag.startswith("**REDACTED_SECRET_") for flag in argv_flags)


@pytest.mark.asyncio
async def test_control_server_header_value_is_redacted_as_single_token(monkeypatch):
    # The --control-server-H value has the shape "header_name:header_value"
    # and is passed to the CLI as a single argv token (no "=" splitting).
    # This test isolates that behaviour: the entire "x-client-id:<hex>"
    # token must be replaced by exactly one redaction marker, with no
    # partial-leak of either the header name or the header value, and
    # the surrounding flag token must remain intact.
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path("/home/alice"), "alice")],
    )
    # Mixed-case alphanumeric — same reasoning as test_argv_flags_are_redacted
    # above: lowercase-hex literals trigger upstream PAT scanners on PRs.
    client_id_value = "Vp3WbZxMrTcLqYn8XfJgAk5Bs7Hu"
    header_token = f"x-client-id:{client_id_value}"
    argv = ["--control-server-H", header_token]

    payload = await bootstrap_module._build_request("scan", None, None, argv)
    argv_flags = payload.model_dump()["client"]["argv_flags"]

    # Surrounding flag is preserved at its original index.
    assert argv_flags[0] == "--control-server-H"
    # The header-value token is fully replaced by exactly one redaction
    # marker — the entire "header_name:header_value" pair is treated as
    # a single unit, so neither the header name nor the value leaks.
    assert len(argv_flags) == 2
    assert argv_flags[1].startswith("**REDACTED_SECRET_")
    assert argv_flags[1].endswith("**")
    assert client_id_value not in argv_flags[1]
    assert "x-client-id" not in argv_flags[1]
    assert ":" not in argv_flags[1]


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
