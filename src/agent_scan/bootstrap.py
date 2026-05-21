from __future__ import annotations

import asyncio
import locale as locale_module
import logging
import os
import platform
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

import aiohttp
from pydantic import ValidationError

from agent_scan.models import (
    ClientBootstrapRequest,
    ClientBootstrapResponse,
    ClientInfo,
    ControlServer,
    HomeDirectoryEntry,
    HostInfo,
    PathsInfo,
)
from agent_scan.redact import redact_args
from agent_scan.runtime_config import RuntimeConfig
from agent_scan.utils import (
    get_environment,
    get_hostname,
    get_readable_home_directories,
    get_tool_versions,
    get_username,
)
from agent_scan.verify_api import setup_tcp_connector
from agent_scan.version import version_info

logger = logging.getLogger(__name__)

_RETRY_STATUSES = {408, 429}
_HOME_DIRECTORIES_LIMIT = 1000

# Canonical control-server URL contract. The push endpoint is the surface
# users configure via --control-server; the bootstrap endpoint is its
# sibling on the same host. Changing one without the other will silently
# disable startup correlation, so both live here as a single source of
# truth — update together if Snyk renames either path.
CANONICAL_PUSH_PATH_SUFFIX = "/mcp-scan/push"
CLIENT_BOOTSTRAP_PATH_SUFFIX = "/mcp-scan/client-bootstrap"


def _client_bootstrap_url(control_server_url: str) -> str | None:
    parsed = urlsplit(control_server_url)
    path = parsed.path.rstrip("/")
    if not path.endswith(CANONICAL_PUSH_PATH_SUFFIX):
        return None
    path = path[: -len(CANONICAL_PUSH_PATH_SUFFIX)] + CLIENT_BOOTSTRAP_PATH_SUFFIX
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


def _detect_wsl() -> bool:
    try:
        return bool(os.environ.get("WSL_DISTRO_NAME")) or "microsoft" in platform.release().lower()
    except Exception:
        logger.warning("WSL detection failed; reporting is_wsl=False", exc_info=True)
        return False


def _detect_container() -> bool:
    # Marker files: /.dockerenv is Docker; /run/.containerenv is Podman (and
    # other OCI runtimes that follow the systemd-nspawn convention). Checking
    # both covers rootless Podman, which does not create /.dockerenv.
    try:
        if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
            return True
        cgroup = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    # cgroup hints catch container runtimes that don't drop a marker file —
    # "container=" is set by systemd-nspawn/LXC, "docker"/"kubepods" by
    # Docker and Kubernetes, "libpod"/"podman" by Podman (rootful and
    # rootless alike on cgroup v1).
    return any(token in cgroup for token in ("container=", "docker", "kubepods", "libpod", "podman"))


def _get_locale() -> str | None:
    try:
        return locale_module.setlocale(locale_module.LC_CTYPE)
    except locale_module.Error:
        return None


def _is_iana_timezone(name: str) -> bool:
    # An IANA zone is one the stdlib `zoneinfo` database can load. This
    # filters out POSIX TZ strings like "CET-1CEST,M3.5.0,M10.5.0/3" which
    # textually contain "/" but are not IANA names.
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    except ImportError:
        # Pre-3.9 fallback: accept anything that looks like Area/Location
        # without POSIX-rule punctuation.
        return "/" in name and "," not in name and not name.startswith(":")
    try:
        ZoneInfo(name)
        return True
    except (ZoneInfoNotFoundError, ValueError):
        return False


def _get_timezone() -> str | None:
    # Prefer a stable IANA name (e.g. "Europe/Berlin") so the backend can
    # compare values across hosts. Fall back through several sources because
    # no single one is reliable everywhere:
    #   1. $TZ if it loads as an IANA zone (set explicitly by the user/env).
    #   2. /etc/timezone (Debian/Ubuntu) — one line, IANA name.
    #   3. The symlink target of /etc/localtime (most modern Linux, macOS) —
    #      resolves to .../zoneinfo/<Area>/<Location>.
    #   4. time.tzname + UTC offset (e.g. "CET (UTC+01:00)") — a labelled
    #      offset; less stable than IANA but still meaningful to humans.
    #   5. str(tzinfo) as a last resort (often just an offset like "UTC+02:00").
    try:
        tz_env = os.environ.get("TZ", "").strip().lstrip(":")
        if tz_env and _is_iana_timezone(tz_env):
            return tz_env

        try:
            etc_timezone = Path("/etc/timezone").read_text(encoding="utf-8").strip()
            if etc_timezone and _is_iana_timezone(etc_timezone):
                return etc_timezone
        except OSError:
            pass

        try:
            localtime = Path("/etc/localtime").resolve()
            parts = localtime.parts
            if "zoneinfo" in parts:
                zoneinfo_idx = parts.index("zoneinfo")
                iana = "/".join(parts[zoneinfo_idx + 1 :])
                if iana and _is_iana_timezone(iana):
                    return iana
        except OSError:
            pass

        now = datetime.now().astimezone()
        offset = now.strftime("%z")  # e.g. "+0200" or "" if naive
        if offset:
            offset_label = f"UTC{offset[:3]}:{offset[3:]}" if len(offset) == 5 else f"UTC{offset}"
            tz_label = time.tzname[bool(now.dst())] if time.tzname else ""
            if tz_label:
                return f"{tz_label} ({offset_label})"
            return offset_label

        tzinfo = now.tzinfo
        return str(tzinfo) if tzinfo is not None else None
    except Exception:
        logger.warning("Timezone detection failed; payload field will be null", exc_info=True)
        return None


async def _build_request(
    command: Literal["scan", "inspect", "evo", "guard"],
    subcommand: str | None,
    control_identifier: str | None,
    argv: list[str],
    scan_all_users: bool = False,
) -> ClientBootstrapRequest:
    # Security review allowlist: this payload sends client metadata, host OS
    # details, hostname/current username, CI/WSL/container booleans, shell/term,
    # locale/timezone, cwd/home/executable paths, readable home directories capped
    # at 1000 entries, redacted argv tokens, and a runtimes dict containing
    # best-effort versions of python/node/npx/uvx/docker (each value is the
    # verbatim first line of `<tool> --version`, or None when probing fails).
    # It intentionally excludes scanned_usernames and schema_version.
    # Home enumeration mirrors the scan's --scan-all-users opt-in: a single-user
    # scan only reports the current user's home, matching what discovery touches.
    # Run the two slow signals (home enumeration + external tool probes)
    # concurrently. Both are subprocess/IO bound and independent, so total
    # wall time is bounded by whichever is slower rather than their sum.
    home_dirs_raw, runtimes = await asyncio.gather(
        asyncio.to_thread(get_readable_home_directories, all_users=scan_all_users),
        get_tool_versions(),
    )
    home_dirs_sorted = sorted(home_dirs_raw, key=lambda item: str(item[0]))
    home_dirs_truncated = len(home_dirs_sorted) > _HOME_DIRECTORIES_LIMIT
    home_dirs = home_dirs_sorted[:_HOME_DIRECTORIES_LIMIT]

    return ClientBootstrapRequest(
        client=ClientInfo(
            name="agent-scan",
            version=version_info,
            command=command,
            subcommand=subcommand,
            control_identifier=control_identifier,
            argv_flags=redact_args(argv),
        ),
        host=HostInfo(
            os=platform.system(),
            os_release=platform.release(),
            os_version=platform.version(),
            arch=platform.machine(),
            processor=platform.processor(),
            hostname=get_hostname(),
            current_username=get_username(),
            is_ci=(get_environment() or "").lower() == "ci",
            is_wsl=_detect_wsl(),
            is_container=_detect_container(),
            shell=os.environ.get("SHELL"),
            term=os.environ.get("TERM"),
            locale=_get_locale(),
            timezone=_get_timezone(),
            runtimes=runtimes,
        ),
        paths=PathsInfo(
            cwd=os.getcwd(),
            current_home_dir=str(Path.home()),
            home_directories=[HomeDirectoryEntry(path=str(path), username=username) for path, username in home_dirs],
            home_directories_truncated=home_dirs_truncated,
            executable=sys.executable,
        ),
    )


def _should_retry(status: int) -> bool:
    return status in _RETRY_STATUSES or status >= 500


async def bootstrap_first_control_server(
    control_servers: list[ControlServer],
    *,
    command: Literal["scan", "inspect", "evo", "guard"],
    subcommand: str | None,
    control_identifier: str | None,
    argv: list[str],
    no_bootstrap: bool,
    scan_all_users: bool = False,
    skip_ssl_verify: bool = False,
    timeout_seconds: float = 3.0,
    max_attempts: int = 3,
) -> RuntimeConfig:
    # Outer safety net: bootstrap is documented as best-effort and must never
    # abort the command. The inner implementation already handles expected
    # failure modes (network errors, validation errors, payload build errors),
    # but anything outside those families — e.g. an OSError from connector
    # setup, a bug in a third-party lib, an AttributeError — would otherwise
    # propagate. We catch Exception (not BaseException) so KeyboardInterrupt,
    # SystemExit, and asyncio.CancelledError all keep their default propagation
    # semantics: Ctrl-C and explicit exits still kill the command, and a
    # gather()-sibling cancel can unwind this task instead of being turned
    # into a silent default-RuntimeConfig return.
    try:
        return await _bootstrap_first_control_server_impl(
            control_servers,
            command=command,
            subcommand=subcommand,
            control_identifier=control_identifier,
            argv=argv,
            no_bootstrap=no_bootstrap,
            scan_all_users=scan_all_users,
            skip_ssl_verify=skip_ssl_verify,
            timeout_seconds=timeout_seconds,
            max_attempts=max_attempts,
        )
    except Exception as exc:
        logger.warning("Client bootstrap crashed; using defaults: %s", exc)
        return RuntimeConfig()


async def _bootstrap_first_control_server_impl(
    control_servers: list[ControlServer],
    *,
    command: Literal["scan", "inspect", "evo", "guard"],
    subcommand: str | None,
    control_identifier: str | None,
    argv: list[str],
    no_bootstrap: bool,
    scan_all_users: bool,
    skip_ssl_verify: bool,
    timeout_seconds: float,
    max_attempts: int,
) -> RuntimeConfig:
    if not control_servers or no_bootstrap:
        return RuntimeConfig()

    control_server = control_servers[0]
    if len(control_servers) > 1:
        logger.warning(
            "bootstrap sent only to %s; %s additional control servers will receive scan results but not bootstrap",
            control_server.url,
            len(control_servers) - 1,
        )

    try:
        payload = await _build_request(command, subcommand, control_identifier, argv, scan_all_users)
    except Exception as exc:
        logger.warning("Client bootstrap failed; using defaults: %s", exc)
        return RuntimeConfig()

    url = _client_bootstrap_url(control_server.url)
    if url is None:
        logger.warning(
            "control-server URL %r does not end in %s; skipping bootstrap",
            control_server.url,
            CANONICAL_PUSH_PATH_SUFFIX,
        )
        return RuntimeConfig()
    headers = dict(control_server.headers)
    headers.setdefault("Content-Type", "application/json")
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    # Bootstrap is best-effort: a single warning on failure is enough, so we
    # skip aiohttp trace configs to avoid mutating process-wide logger levels.
    last_error = "unknown error"

    for attempt in range(max_attempts):
        if attempt > 0:
            await asyncio.sleep(attempt)

        try:
            async with aiohttp.ClientSession(
                connector=setup_tcp_connector(skip_ssl_verify=skip_ssl_verify),
                trust_env=True,
            ) as session:
                async with session.post(
                    url,
                    data=payload.model_dump_json(),
                    headers=headers,
                    timeout=timeout,
                ) as response:
                    # Accept any 2xx as success. The control server returns
                    # 201 for a freshly created bootstrap event today; widening
                    # to the whole 2xx range avoids brittleness if it ever
                    # switches to 200 (rerun-of-same-payload semantics) or 202.
                    if 200 <= response.status < 300:
                        data = await response.json(content_type=None)
                        response_model = ClientBootstrapResponse.model_validate(data)
                        return RuntimeConfig(
                            bootstrap_event_id=response_model.bootstrap_event_id,
                            config=response_model.runtime_config,
                            source="bootstrap",
                        )

                    # Do NOT read or log response.text(): on a non-2xx the
                    # server body may carry internal error detail (stack
                    # snippets, query fragments, IDs) that we must not leak
                    # into client-side logs. Status code is enough for the
                    # client's purposes — retry decisions are status-based,
                    # and operators investigating a failure should look at
                    # the server-side logs keyed by the request's tenant.
                    last_error = f"HTTP {response.status}"
                    if not _should_retry(response.status) or attempt == max_attempts - 1:
                        break
        except (TimeoutError, asyncio.TimeoutError, aiohttp.ClientError) as exc:
            last_error = str(exc) or exc.__class__.__name__
            if attempt == max_attempts - 1:
                break
        except (ValidationError, ValueError, TypeError) as exc:
            last_error = str(exc) or exc.__class__.__name__
            break

    logger.warning("Client bootstrap failed; using defaults: %s", last_error)
    return RuntimeConfig()
