import sys
from pathlib import Path

import pytest

from agent_scan import bootstrap as bootstrap_module

# Several tests in this module mock POSIX-only filesystem signals
# (/.dockerenv, /run/.containerenv, /etc/timezone, /etc/localtime) by
# string-matching against str(Path(...)). On Windows that string contains
# backslashes and the monkeypatch matchers never fire. zoneinfo also
# requires the `tzdata` package on Windows, which is not a runtime dep.
# The functions under test still behave correctly on Windows; the
# Linux-shaped scenarios just cannot be simulated there.
_posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="mocks POSIX-only paths / zoneinfo behavior not available on Windows",
)


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
    # `runtimes` is an open dict populated by `_DEFAULT_PROBED_TOOLS`; "python"
    # is one of those probes (`python --version`), so the key is always
    # present in the request even when the binary is missing on PATH (in
    # which case the value is None).
    assert "python" in data["host"]["runtimes"]
    assert data["paths"]["cwd"]
    assert data["paths"]["current_home_dir"]
    assert data["paths"]["executable"]


@pytest.mark.asyncio
async def test_payload_runtimes_passes_through_probed_tools_verbatim(monkeypatch):
    # `runtimes` is whatever `get_tool_versions` returns, no post-processing
    # in `_build_request`. python is just another probed tool now.
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path("/home/alice"), "alice")],
    )

    async def fake_probes():
        return {
            "python": "Python 3.12.5",
            "node": "v20.10.0",
            "npx": "10.2.3",
            "uvx": "0.4.18",
            "docker": None,
        }

    monkeypatch.setattr(bootstrap_module, "get_tool_versions", fake_probes)

    payload = await bootstrap_module._build_request("scan", None, None, [])
    runtimes = payload.model_dump()["host"]["runtimes"]

    assert runtimes["python"] == "Python 3.12.5"
    assert runtimes["node"] == "v20.10.0"
    assert runtimes["npx"] == "10.2.3"
    assert runtimes["uvx"] == "0.4.18"
    # `None` means "we probed and the tool isn't installed" — it must be
    # preserved as an explicit null in the payload, not dropped.
    assert runtimes["docker"] is None


@pytest.mark.asyncio
async def test_home_directories_match_helper_and_are_capped(monkeypatch):
    monkeypatch.setattr(
        bootstrap_module,
        "get_readable_home_directories",
        lambda all_users=False: [(Path(f"/home/user-{i}"), f"user-{i}") for i in range(1002)],
    )

    payload = await bootstrap_module._build_request("scan", None, None, [], scan_all_users=True)
    paths = payload.model_dump()["paths"]

    # str(Path(...)) keeps native separators (backslashes on Windows), and the
    # payload stringifies via the same transform — so we mirror it here rather
    # than hard-coding POSIX literals that fail on Windows runners.
    assert len(paths["home_directories"]) == 1000
    assert paths["home_directories"][0] == {"path": str(Path("/home/user-0")), "username": "user-0"}
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
    # See note above: stringify via Path() to keep the assertion portable
    # between POSIX and Windows runners.
    assert paths["home_directories"] == [{"path": str(Path("/home/me")), "username": "me"}]


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


@_posix_only
def test_container_detection_podman_marker_file(monkeypatch):
    """Podman drops /run/.containerenv (not /.dockerenv); rootless Podman in
    particular has no /.dockerenv, so this marker is the only signal until
    we fall through to cgroup inspection."""
    monkeypatch.setattr(Path, "exists", lambda self: str(self) == "/run/.containerenv")

    assert bootstrap_module._detect_container() is True


def test_container_detection_podman_cgroup_token(monkeypatch):
    """Rootless Podman on a host without /run/.containerenv (e.g. user-namespaced
    runs) is still detectable via the 'libpod' / 'podman' tokens in the cgroup."""
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, **kwargs: "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-abc.scope",
    )

    assert bootstrap_module._detect_container() is True


def test_container_detection_no_signals_returns_false(monkeypatch):
    """A bare-metal host with no marker files and a plain cgroup must report False."""
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, **kwargs: "0::/user.slice/user-1000.slice/session-1.scope",
    )

    assert bootstrap_module._detect_container() is False


def test_wsl_detection_defaults_false(monkeypatch):
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(bootstrap_module.platform, "release", lambda: "6.8.0-generic")

    assert bootstrap_module._detect_wsl() is False


@_posix_only
def test_timezone_prefers_tz_env_iana_name(monkeypatch):
    """An IANA $TZ value (e.g. 'Europe/Berlin') is returned verbatim — it's the
    most explicit signal a user can give us, and it's stable across hosts."""
    monkeypatch.setenv("TZ", "Europe/Berlin")

    assert bootstrap_module._get_timezone() == "Europe/Berlin"


def test_timezone_ignores_non_iana_tz_env(monkeypatch):
    """A legacy/POSIX $TZ value (e.g. 'CET-1CEST,M3.5.0,M10.5.0/3') is not IANA
    and must not be returned; we fall through to the next source."""
    monkeypatch.setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3")
    # Disable /etc/timezone and /etc/localtime so the fallback chain is observable.
    monkeypatch.setattr(bootstrap_module.Path, "read_text", lambda self, **k: (_ for _ in ()).throw(OSError()))
    monkeypatch.setattr(bootstrap_module.Path, "resolve", lambda self, **k: bootstrap_module.Path("/etc/localtime"))

    result = bootstrap_module._get_timezone()

    # Whatever we fall through to, it must not be the raw POSIX TZ string.
    assert result != "CET-1CEST,M3.5.0,M10.5.0/3"


@_posix_only
def test_timezone_reads_etc_timezone_when_tz_env_absent(monkeypatch):
    """Debian/Ubuntu canonical source: /etc/timezone holds the IANA name."""
    monkeypatch.delenv("TZ", raising=False)

    real_read_text = bootstrap_module.Path.read_text

    def fake_read_text(self, *args, **kwargs):
        if str(self) == "/etc/timezone":
            return "America/Los_Angeles\n"
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(bootstrap_module.Path, "read_text", fake_read_text)

    assert bootstrap_module._get_timezone() == "America/Los_Angeles"


@_posix_only
def test_timezone_falls_back_to_localtime_symlink(monkeypatch):
    """macOS and most modern Linux: /etc/localtime is a symlink into the
    zoneinfo tree; the IANA name follows 'zoneinfo/' in the resolved path."""
    monkeypatch.delenv("TZ", raising=False)
    monkeypatch.setattr(
        bootstrap_module.Path,
        "read_text",
        lambda self, **k: (_ for _ in ()).throw(OSError()),
    )

    real_resolve = bootstrap_module.Path.resolve

    def fake_resolve(self, *args, **kwargs):
        if str(self) == "/etc/localtime":
            return bootstrap_module.Path("/var/db/timezone/zoneinfo/Asia/Tokyo")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(bootstrap_module.Path, "resolve", fake_resolve)

    assert bootstrap_module._get_timezone() == "Asia/Tokyo"


def test_timezone_returns_a_value_when_all_iana_sources_fail(monkeypatch):
    """When no IANA source is available, the function must still return *something*
    (offset label, tzname, or None) — never raise. The caller persists this
    verbatim, so a hard failure here would leak into the payload as a 500."""
    monkeypatch.delenv("TZ", raising=False)
    monkeypatch.setattr(
        bootstrap_module.Path,
        "read_text",
        lambda self, **k: (_ for _ in ()).throw(OSError()),
    )
    monkeypatch.setattr(
        bootstrap_module.Path,
        "resolve",
        lambda self, **k: bootstrap_module.Path("/etc/localtime"),
    )

    # The actual returned value depends on the host's tzinfo, but the function
    # must complete without raising and produce a non-empty string (or None on
    # a TZ-less host, which would also be acceptable).
    result = bootstrap_module._get_timezone()
    assert result is None or isinstance(result, str)


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
