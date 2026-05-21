import asyncio
import contextlib
import getpass
import glob
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from rapidfuzz.distance import Levenshtein

from agent_scan.models import ControlServer, StdioServer


def get_environment() -> str | None:
    return os.getenv("AGENT_SCAN_ENVIRONMENT", os.getenv("MCP_SCAN_ENVIRONMENT"))


def get_hostname() -> str:
    ci_hostname = os.getenv("AGENT_SCAN_CI_HOSTNAME")
    if get_environment() == "ci" and ci_hostname:
        return ci_hostname
    try:
        return platform.node() or "unknown"
    except Exception:
        return "unknown"


def get_username() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


# Per-tool wall-clock cap. The bootstrap handshake is best-effort and runs
# before any HTTP retry, so a hung `docker --version` (e.g. Docker Desktop
# starting on macOS) must not stall scan startup. Two seconds is enough for
# every probe we care about on a healthy host; anything slower is treated
# as "not installed."
_TOOL_VERSION_PROBE_TIMEOUT = 2.0
# Tools we expect to find on developer machines. Order is preserved in the
# returned dict for stable serialization of the bootstrap payload. `python`
# is probed via `python --version` like every other entry — note that this
# may resolve to a different interpreter than the one running agent-scan
# if multiple Pythons are on PATH; that's accepted in exchange for treating
# every runtime uniformly.
_DEFAULT_PROBED_TOOLS: tuple[str, ...] = ("python", "node", "npx", "uvx", "docker")

# Wall-clock cap for the `Get-CimInstance Win32_UserProfile` query that
# enumerates Windows user profiles under --scan-all-users. WMI/CIM is known
# to hang when the local repository is corrupted, the WinMgmt service is
# unresponsive, or a domain controller round-trip stalls; 10s is generous
# enough for healthy hosts (typical query is <500ms) while still preventing
# scan startup and bootstrap payload build from blocking indefinitely.
_WINDOWS_PROFILE_QUERY_TIMEOUT = 10.0


def _probe_tool_version(command: str) -> str | None:
    """Run `<command> --version` and return the first non-empty output line.

    Returns None when the binary is missing, the call times out, exits
    non-zero, or otherwise fails. Never raises — the caller folds the
    result straight into telemetry, so any exception here would break
    the bootstrap payload build and cascade into a failed handshake.

    Output channel choice is intentionally lenient: `node --version`
    writes to stdout, `docker --version` writes to stdout, but some
    third-party tools (and old npm versions) write to stderr. We prefer
    stdout and fall back to stderr so the most common case is correct
    without specializing per tool.
    """
    try:
        result = subprocess.run(
            [command, "--version"],
            capture_output=True,
            text=True,
            timeout=_TOOL_VERSION_PROBE_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError, OSError):
        return None
    if result.returncode != 0:
        return None
    output = (result.stdout or result.stderr or "").strip()
    if not output:
        return None
    return output.splitlines()[0].strip() or None


async def get_tool_versions(
    tools: Iterable[str] = _DEFAULT_PROBED_TOOLS,
) -> dict[str, str | None]:
    """Probe versions of external tools in parallel.

    Always returns a dict with one entry per requested tool. Missing /
    unprobeable tools map to None — distinct from absent keys, which
    signal "we didn't ask about this tool at all." Probes are offloaded
    to threads via asyncio.to_thread so the slowest one bounds total
    wall-clock time, not the sum.
    """
    tool_list = list(tools)
    results = await asyncio.gather(*(asyncio.to_thread(_probe_tool_version, t) for t in tool_list))
    return dict(zip(tool_list, results, strict=True))


def ensure_unicode_console() -> None:
    """On Windows, reconfigure stdout/stderr to UTF-8 so Unicode (e.g. emoji) prints without UnicodeEncodeError.
    Uses errors='replace' so unsupported chars are replaced instead of raising. Safe to call on all platforms.
    See https://github.com/pallets/click/issues/2121#issuecomment-1691716436"""
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            with contextlib.suppress(AttributeError, OSError):
                stream.reconfigure(encoding="utf-8", errors="replace")


logger = logging.getLogger(__name__)


def get_relative_path(path: str) -> str:
    try:
        expanded_path = os.path.expanduser(path)
        home_dir = os.path.expanduser("~")
        if expanded_path.startswith(home_dir):
            result = "~" + expanded_path[len(home_dir) :]
            # Normalize to forward slashes for consistent display across platforms
            return result.replace("\\", "/")
        return path
    except Exception:
        return path


def calculate_distance(responses: list[str], reference: str):
    return sorted([(w, Levenshtein.distance(w, reference)) for w in responses], key=lambda x: x[1])


class TempFile:
    """A windows compatible version of tempfile.NamedTemporaryFile."""

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.file = None

    def __enter__(self):
        args = self.kwargs.copy()
        args["delete"] = False
        self.file = tempfile.NamedTemporaryFile(**args)
        return self.file

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.file.close()
        os.unlink(self.file.name)


def parse_headers(headers: list[str] | None) -> dict:
    if headers is None:
        return {}
    headers = [header.strip() for header in headers]
    for header in headers:
        if ":" not in header:
            raise ValueError(f"Invalid header: {header}")
    return {header.split(":")[0]: header.split(":")[1] for header in headers}


def check_executable_exists(command: str) -> bool:
    path = Path(command)
    return path.exists() or shutil.which(command) is not None


def resolve_command_and_args(server_config: StdioServer) -> tuple[str, list[str]]:
    """
    Resolve the command and arguments for a StdioServer.
    """
    # check if command points to an executable and whether it exists absolute or on the path
    if check_executable_exists(server_config.command):
        return server_config.command, server_config.args

    command, args = server_config.command, server_config.args
    if os.path.sep in command:
        logger.warning(f"Path does not exist: {command}")
        raise ValueError(f"Path does not exist: {command}")

    # attempt to find the command in well-known directories
    # npx via nvm - look for node versions directory
    nvm_pattern = os.path.expanduser("~/.nvm/versions/node/*/bin")
    nvm_dirs = sorted(glob.glob(nvm_pattern), reverse=True)
    fallback_dirs = [
        # node / npx
        *nvm_dirs,
        os.path.expanduser("~/.npm-global/bin"),
        os.path.expanduser("~/.yarn/bin"),
        os.path.expanduser("~/.local/share/pnpm"),
        os.path.expanduser("~/.config/yarn/global/node_modules/.bin"),
        # python / uvx
        os.path.expanduser("~/.cargo/bin"),
        os.path.expanduser("~/.pyenv/shims"),
        # user local paths
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/.bin"),
        os.path.expanduser("~/bin"),
        # package manager paths
        "/opt/homebrew/bin",
        "/opt/local/bin",
        "/snap/bin",
        # system paths
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        # docker path
        "/Applications/Docker.app/Contents/Resources/bin",
    ]

    for d in fallback_dirs:
        potential_path = os.path.join(d, command)
        if check_executable_exists(potential_path):
            logger.debug(f"Found {command} at fallback location: {potential_path}")
            return potential_path, args

    logger.warning(f"Command {command} not found in any fallback location")
    raise ValueError(f"Command {command} not found")


@contextlib.contextmanager
def suppress_stdout():
    with open(os.devnull, "w") as devnull:
        with contextlib.redirect_stdout(devnull):
            yield


def get_push_key(control_servers: list[ControlServer] | list[dict[str, Any]]) -> str | None:
    parsed_control_servers: list[ControlServer] = []
    for control_server in control_servers:
        if isinstance(control_server, dict):
            parsed_control_servers.append(
                ControlServer(
                    url=control_server["url"],
                    headers=parse_headers(control_server["headers"]),
                    identifier=control_server["identifier"],
                )
            )
        else:
            parsed_control_servers.append(control_server)
    for control_server in parsed_control_servers:
        for header in control_server.headers:
            if "x-client-id" in header.lower():
                return control_server.headers[header]
    return None


def get_readable_home_directories(all_users: bool = False) -> list[tuple[Path, str]]:
    """
    Retrieve a list of all human user home directories on the machine
    that the current process actually has permission to read and traverse.
    Logs the access status for each found directory.

    Returns a list of (home_directory_path, username) tuples.
    """
    if not all_users:
        return [(Path.home(), getpass.getuser())]

    system = platform.system()
    home_dirs: dict[Path, str] = {}

    if system in ("Linux", "Darwin"):
        import pwd

        # macOS usually starts human UIDs at 500, Linux at 1000
        uid_threshold = 500 if system == "Darwin" else 1000

        for user in pwd.getpwall():
            if user.pw_uid >= uid_threshold and user.pw_name != "nobody":
                dir_path = Path(user.pw_dir)

                if dir_path.is_dir():
                    # Check for Read (R_OK) and Traverse/Execute (X_OK) permissions
                    if os.access(dir_path, os.R_OK | os.X_OK):
                        logger.info(f"Found user '{user.pw_name}' at {dir_path} -> Access: GRANTED")
                        home_dirs[dir_path] = user.pw_name
                    else:
                        logger.info(f"Found user '{user.pw_name}' at {dir_path} -> Access: DENIED")

    elif system == "Windows":
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_UserProfile | Where-Object { $_.Special -eq $false } | Select-Object -ExpandProperty LocalPath",
            ]
            # Cap the CIM query at 10s. Win32_UserProfile via WMI/CIM can hang
            # indefinitely when the WMI repository is corrupted, the WinMgmt
            # service is unresponsive, or a domain controller round-trip
            # stalls. Without this cap, both scan discovery and the bootstrap
            # payload build block before any network timeout could fire.
            # On timeout we fall through to WSL enumeration and return an
            # empty Windows profile set rather than aborting the scan.
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=_WINDOWS_PROFILE_QUERY_TIMEOUT,
            )

            for line in result.stdout.splitlines():
                clean_path = line.strip()
                if clean_path:
                    dir_path = Path(clean_path)
                    if dir_path.is_dir():
                        # Windows primarily relies on R_OK for basic directory readability
                        if os.access(dir_path, os.R_OK):
                            username = dir_path.name
                            logger.info(f"Found profile at {dir_path} -> Access: GRANTED")
                            home_dirs[dir_path] = username
                        else:
                            logger.info(f"Found profile at {dir_path} -> Access: DENIED")

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to fetch Windows profiles: {e}")
        except subprocess.TimeoutExpired as e:
            logger.warning(
                "Windows profile query timed out after %ss; reporting no Win32 profiles "
                "(WSL enumeration still proceeds). Likely cause: WMI/CIM is slow or stuck.",
                _WINDOWS_PROFILE_QUERY_TIMEOUT,
            )
            logger.debug("Win32_UserProfile timeout detail: %s", e)

        for wsl_home, wsl_user in get_wsl_home_directories():
            if wsl_home in home_dirs:
                continue
            home_dirs[wsl_home] = wsl_user

    else:
        raise NotImplementedError(f"Unsupported OS: {system}")

    return list(home_dirs.items())


def _list_wsl_distros() -> list[str]:
    """
    Return the list of installed, non-hidden WSL distro names (e.g. "Ubuntu-24.04").
    Returns an empty list if WSL is not installed or the call fails.
    """
    try:
        # `wsl.exe -l -q` emits one distro name per line in UTF-16LE.
        proc = subprocess.run(
            ["wsl.exe", "--list", "--quiet"],
            capture_output=True,
            check=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.info(f"WSL not available or failed to list distros: {e}")
        return []

    raw = proc.stdout
    # wsl.exe output is UTF-16LE on most Windows builds; fall back to utf-8.
    for encoding in ("utf-16-le", "utf-16", "utf-8"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        return []

    distros: list[str] = []
    for line in text.splitlines():
        name = line.strip().replace("\x00", "")
        if name:
            distros.append(name)
    return distros


def get_wsl_home_directories() -> list[tuple[Path, str]]:
    """
    Enumerate human home directories that live inside WSL distros, exposed to
    Windows via the `\\\\wsl.localhost\\<Distro>\\home\\<user>` UNC share.

    Only runs on Windows; returns an empty list otherwise. Silently returns []
    if WSL is not installed, no distros are registered, or the filesystem is
    not reachable (e.g. the distro cannot be started).
    """
    if platform.system() != "Windows":
        return []

    results: dict[Path, str] = {}
    for distro in _list_wsl_distros():
        # Prefer the modern \wsl.localhost alias; fall back to \wsl$ which is
        # what older Windows builds expose.
        for prefix in (r"\\wsl.localhost", r"\\wsl$"):
            distro_home = Path(f"{prefix}\\{distro}\\home")
            try:
                if not distro_home.is_dir():
                    continue
                user_dirs = list(distro_home.iterdir())
            except OSError as e:
                logger.info(f"WSL home unreachable for {distro} via {prefix}: {e}")
                continue

            for user_dir in user_dirs:
                try:
                    if not user_dir.is_dir():
                        continue
                    if not os.access(user_dir, os.R_OK | os.X_OK):
                        logger.info(f"WSL home {user_dir} -> Access: DENIED")
                        continue
                except OSError as e:
                    logger.info(f"WSL home {user_dir} not inspectable: {e}")
                    continue

                logger.info(f"Found WSL user '{user_dir.name}' in distro '{distro}' -> Access: GRANTED")
                results[user_dir] = user_dir.name
            # Found a working prefix for this distro; no need to try the alias.
            break

    return list(results.items())
