import logging
import os
import platform
import subprocess
import sys
from pathlib import Path

from agent_scan.models import CandidateClient

# Set up logger for this module
logger = logging.getLogger(__name__)


MACOS_WELL_KNOWN_CLIENTS: list[CandidateClient] = [
    CandidateClient(
        name="windsurf",
        client_exists_paths=["~/.codeium"],
        mcp_config_paths=["~/.codeium/windsurf/mcp_config.json"],
        skills_dir_paths=["~/.codeium/windsurf/skills"],
    ),
    CandidateClient(
        name="cursor",
        client_exists_paths=["~/.cursor"],
        mcp_config_paths=["~/.cursor/mcp.json"],
        skills_dir_paths=["~/.cursor/skills"],
    ),
    CandidateClient(
        name="vscode",
        client_exists_paths=["~/.vscode"],
        mcp_config_paths=[
            "~/Library/Application Support/Code/User/settings.json",
            "~/Library/Application Support/Code/User/mcp.json",
        ],
        skills_dir_paths=["~/.copilot/skills"],
    ),
    CandidateClient(
        name="claude",
        client_exists_paths=["~/Library/Application Support/Claude"],
        mcp_config_paths=["~/Library/Application Support/Claude/claude_desktop_config.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="claude code",
        client_exists_paths=["~/.claude"],
        mcp_config_paths=["~/.claude.json"],
        skills_dir_paths=["~/.claude/skills"],
    ),
    CandidateClient(
        name="gemini cli",
        client_exists_paths=["~/.gemini"],
        mcp_config_paths=["~/.gemini/settings.json"],
        skills_dir_paths=["~/.gemini/skills"],
    ),
    CandidateClient(
        name="clawdbot",
        client_exists_paths=["~/.clawdbot"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.clawdbot/skills"],
    ),
    CandidateClient(
        name="kiro",
        client_exists_paths=["~/.kiro"],
        mcp_config_paths=["~/.kiro/settings/mcp.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="opencode",
        client_exists_paths=["~/.config/opencode"],
        mcp_config_paths=[],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="antigravity",
        client_exists_paths=["~/.gemini/antigravity"],
        mcp_config_paths=["~/.gemini/antigravity/mcp_config.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="codex",
        client_exists_paths=["~/.codex"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.codex/skills"],
    ),
]

LINUX_WELL_KNOWN_CLIENTS: list[CandidateClient] = [
    CandidateClient(
        name="windsurf",
        client_exists_paths=["~/.codeium"],
        mcp_config_paths=["~/.codeium/windsurf/mcp_config.json"],
        skills_dir_paths=["~/.codeium/windsurf/skills"],
    ),
    CandidateClient(
        name="cursor",
        client_exists_paths=["~/.cursor"],
        mcp_config_paths=["~/.cursor/mcp.json"],
        skills_dir_paths=["~/.cursor/skills"],
    ),
    CandidateClient(
        name="vscode",
        client_exists_paths=["~/.vscode", "~/.config/Code"],
        mcp_config_paths=[
            "~/.config/Code/User/settings.json",
            "~/.vscode/mcp.json",
            "~/.config/Code/User/mcp.json",
        ],
        skills_dir_paths=["~/.copilot/skills"],
    ),
    CandidateClient(
        name="claude code",
        client_exists_paths=["~/.claude"],
        mcp_config_paths=["~/.claude.json"],
        skills_dir_paths=["~/.claude/skills"],
    ),
    CandidateClient(
        name="gemini cli",
        client_exists_paths=["~/.gemini"],
        mcp_config_paths=["~/.gemini/settings.json"],
        skills_dir_paths=["~/.gemini/skills"],
    ),
    CandidateClient(
        name="openclaw",
        client_exists_paths=["~/.clawdbot", "~/.openclaw"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.clawdbot/skills", "~/.openclaw/skills"],
    ),
    CandidateClient(
        name="kiro",
        client_exists_paths=["~/.kiro"],
        mcp_config_paths=["~/.kiro/settings/mcp.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="opencode",
        client_exists_paths=["~/.config/opencode"],
        mcp_config_paths=[],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="antigravity",
        client_exists_paths=["~/.gemini/antigravity"],
        mcp_config_paths=["~/.gemini/antigravity/mcp_config.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="codex",
        client_exists_paths=["~/.codex"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.codex/skills"],
    ),
]


WINDOWS_WELL_KNOWN_CLIENTS: list[CandidateClient] = [
    CandidateClient(
        name="windsurf",
        client_exists_paths=["~/.codeium"],
        mcp_config_paths=["~/.codeium/windsurf/mcp_config.json"],
        skills_dir_paths=["~/.codeium/windsurf/skills"],
    ),
    CandidateClient(
        name="cursor",
        client_exists_paths=["~/.cursor"],
        mcp_config_paths=["~/.cursor/mcp.json"],
        skills_dir_paths=["~/.cursor/skills"],
    ),
    CandidateClient(
        name="vscode",
        client_exists_paths=["~/.vscode", "~/.config/Code"],
        mcp_config_paths=[
            "~/.config/Code/User/settings.json",
            "~/.vscode/mcp.json",
            "~/.config/Code/User/mcp.json",
        ],
        skills_dir_paths=["~/.copilot/skills"],
    ),
    CandidateClient(
        name="claude",
        client_exists_paths=["~/AppData/Roaming/Claude"],
        mcp_config_paths=["~/AppData/Roaming/Claude/claude_desktop_config.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="claude code",
        client_exists_paths=["~/.claude"],
        mcp_config_paths=["~/.claude.json"],
        skills_dir_paths=["~/.claude/skills"],
    ),
    CandidateClient(
        name="gemini cli",
        client_exists_paths=["~/.gemini"],
        mcp_config_paths=["~/.gemini/settings.json"],
        skills_dir_paths=["~/.gemini/skills"],
    ),
    CandidateClient(
        name="openclaw",
        client_exists_paths=["~/.clawdbot", "~/.openclaw"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.clawdbot/skills", "~/.openclaw/skills"],
    ),
    CandidateClient(
        name="kiro",
        client_exists_paths=["~/.kiro"],
        mcp_config_paths=["~/.kiro/settings/mcp.json"],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="opencode",
        client_exists_paths=["~/.config/opencode"],
        mcp_config_paths=[],
        skills_dir_paths=[],
    ),
    CandidateClient(
        name="antigravity",
        client_exists_paths=["~/.gemini/antigravity"],
        mcp_config_paths=["~/.gemini/antigravity/mcp_config.json"],
        skills_dir_paths=[],
    ),
]


def get_well_known_clients() -> list[CandidateClient]:
    if sys.platform == "linux" or sys.platform == "linux2":
        return LINUX_WELL_KNOWN_CLIENTS
    elif sys.platform == "darwin":
        return MACOS_WELL_KNOWN_CLIENTS
    elif sys.platform == "win32":
        return WINDOWS_WELL_KNOWN_CLIENTS
    else:
        return []


# Platform-specific client paths
if sys.platform == "linux" or sys.platform == "linux2":
    # Linux
    CLIENT_PATHS = {
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "vscode": ["~/.vscode/mcp.json", "~/.config/Code/User/settings.json", "~/.config/Code/User/mcp.json"],
    }
elif sys.platform == "darwin":
    # OS X
    CLIENT_PATHS = {
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "claude": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
        "vscode": [
            "~/.vscode/mcp.json",
            "~/Library/Application Support/Code/User/settings.json",
            "~/Library/Application Support/Code/User/mcp.json",
        ],
    }
elif sys.platform == "win32":
    CLIENT_PATHS = {
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "claude": ["~/AppData/Roaming/Claude/claude_desktop_config.json"],
        "vscode": [
            "~/.vscode/mcp.json",
            "~/AppData/Roaming/Code/User/settings.json",
            "~/AppData/Roaming/Code/User/mcp.json",
        ],
    }
else:
    CLIENT_PATHS = {}


def get_client_from_path(path: str) -> str | None:
    """
    Returns the client name from a path.

    Args:
        path (str): The path to get the client from.

    Returns:
        str: The client name or None if it cannot be guessed from the path.
    """
    path = os.path.realpath(os.path.expanduser(path))
    for client, paths in CLIENT_PATHS.items():
        real_paths = [os.path.realpath(os.path.expanduser(path)) for path in paths]
        if path in real_paths:
            return client
    return None


def get_readable_home_directories(all_users: bool = False) -> list[Path]:
    """
    Retrieve a list of all human user home directories on the machine
    that the current process actually has permission to read and traverse.
    Logs the access status for each found directory.
    """
    if not all_users:
        return [Path.home()]

    system = platform.system()
    home_dirs: set[Path] = set()

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
                        home_dirs.add(dir_path)
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
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            for line in result.stdout.splitlines():
                clean_path = line.strip()
                if clean_path:
                    dir_path = Path(clean_path)
                    if dir_path.is_dir():
                        # Windows primarily relies on R_OK for basic directory readability
                        if os.access(dir_path, os.R_OK):
                            logger.info(f"Found profile at {dir_path} -> Access: GRANTED")
                            home_dirs.add(dir_path)
                        else:
                            logger.info(f"Found profile at {dir_path} -> Access: DENIED")

        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to fetch Windows profiles: {e}")

    else:
        raise NotImplementedError(f"Unsupported OS: {system}")

    return list(home_dirs)


def expand_path(path: Path, home_directory: Path | None) -> Path:
    if home_directory is None or not str(path).startswith("~"):
        return path

    suffix = path.parts[1:]
    return home_directory / Path(*suffix)
