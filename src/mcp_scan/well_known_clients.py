import logging
import os
import re
import sys

from mcp.types import Implementation, InitializeResult, ServerCapabilities, Tool, ToolsCapability

from mcp_scan.mcp_client import ServerSignature, StdioServer
from mcp_scan.models import CandidateClient, ScanPathResult, ServerScanResult

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
        name="openclaw",
        client_exists_paths=["~/.clawdbot", "~/.openclaw"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.clawdbot/skills", "~/.openclaw/skills", "~/.openclaw/workspace/skills", ".openclaw/skills"],
    ),
    CandidateClient(
        name="amp",
        client_exists_paths=["~/.config/agents", ".amp"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.config/agents/skills", ".amp/skills"],
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
        skills_dir_paths=["~/.clawdbot/skills", "~/.openclaw/skills", "~/.openclaw/workspace/skills", ".openclaw/skills"],
    ),
    CandidateClient(
        name="amp",
        client_exists_paths=["~/.config/agents", ".amp"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.config/agents/skills", ".amp/skills"],
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
        skills_dir_paths=["~/.clawdbot/skills", "~/.openclaw/skills", "~/.openclaw/workspace/skills", ".openclaw/skills"],
    ),
    CandidateClient(
        name="amp",
        client_exists_paths=["~/.config/agents", ".amp"],
        mcp_config_paths=[],
        skills_dir_paths=["~/.config/agents/skills", ".amp/skills"],
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


# Built-in tools for each client
CLIENT_TOOLS = {
    "windsurf": {
        # Search Tools
        "codebase_search": "Find relevant code snippets across your codebase based on semantic search.",
        "find": "Search for files and directories using glob patterns.",
        "grep_search": "Search for a specified pattern within files.",
        "list_directory": "List the contents of a directory and gather information about file size and number of children directories.",
        "read_file": "Read the contents of a file.",
        # Edit Tools
        "edit_file": "Make changes to an existing file.",
        "write_to_file": "Create new files.",
        # Run Tools
        "run_terminal_command": "Execute terminal commands with internet access and monitor output.",
    },
    "cursor": {
        # Search Tools
        "Read File": "Reads up to 250 lines (750 in max mode) of a file.",
        "List Directory": "Read the structure of a directory without reading file contents.",
        "Codebase": "Perform semantic searches within your indexed codebase.",
        "Grep": "Search for exact keywords or patterns within files.",
        "Search Files": "Find files by name using fuzzy matching.",
        "Web": "Generate search queries and perform web searches.",
        "Fetch Rules": "Retrieve specific rules based on type and description.",
        # Edit Tools
        "Edit & Reapply": "Suggest edits to files and apply them automatically.",
        "Delete File": "Delete files autonomously (can be disabled in settings).",
        # Run Tools
        "Terminal": "Execute terminal commands with internet access and monitor output.",
    },
    "vscode": {
        # VSCode tools can be added here when needed
        "extensions": "Search for extensions in the Visual Studio Code Extensions Marketplace",
        "fetch": "Fetch the main content from a web page. You should include the URL of the page ...",
        "findTestFiles": "For a source code file, find the file that contains the tests. For a test file, fi...",
        "githubRepo": "Searches a GitHub repository for relevant source code snippets. You can s...",
        "new": "Scaffold a new workspace in VS Code",
        "openSimpleBrowser": "Preview a locally hosted website in the Simple Browser",
        "problems": "Check errors for a particular file",
        "runCommands": "Run commands in terminal with internet access",
        "runNotebooks": "Run notebook cells",
        "runTasks": "Runs tasks and gets their output for your workspace",
        "search": "Search and read files in your workspace",
        "searchResults": "The results from the search view",
        "terminalLastCommand": "The active terminal's last run command",
        "terminalSelection": "The active terminal's selection",
        "testFailure": "Includes information about the last unit test failure",
        "usages": "Find references, definitions, and other usages of a symbol",
        "vscodeAPI": "Use VS Code API references to answer questions about VS Code extension ...",
        "changes": "Get diffs of changed files",
        "codebase": "Find relevant file chunks, symbols, and other information in your codebase",
        "editFiles": "Edit files in your workspace",
    },
}

# Platform-specific client paths
if sys.platform == "linux" or sys.platform == "linux2":
    # Linux
    CLIENT_PATHS = {
        "windsurf": ["~/.codeium/windsurf/mcp_config.json"],
        "cursor": ["~/.cursor/mcp.json"],
        "vscode": ["~/.vscode/mcp.json", "~/.config/Code/User/settings.json", "~/.config/Code/User/mcp.json"],
    }
    WELL_KNOWN_MCP_PATHS = [path for client, paths in CLIENT_PATHS.items() for path in paths]
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
    WELL_KNOWN_MCP_PATHS = [path for client, paths in CLIENT_PATHS.items() for path in paths]
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

    WELL_KNOWN_MCP_PATHS = [path for client, paths in CLIENT_PATHS.items() for path in paths]
else:
    WELL_KNOWN_MCP_PATHS = []


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


def client_shorthands_to_paths(shorthands: list[str]):
    """
    Converts a list of client shorthands to a list of paths.

    Does nothing if the shorthands are already paths.
    """
    paths = []
    if any(not re.match(r"^[A-z0-9_-]+$", shorthand) for shorthand in shorthands):
        return shorthands

    for shorthand in shorthands:
        if shorthand in CLIENT_PATHS:
            paths.extend(CLIENT_PATHS[shorthand])
        else:
            raise ValueError(f"{shorthand} is not a valid client shorthand")
    return paths


def get_builtin_tools(path_result: ScanPathResult) -> ScanPathResult:
    """
    Add built-in tools for well-known clients to the scan result.

    Args:
        path_result: The scan path result to add built-in tools to

    Returns:
        ScanPathResult with built-in tools added for the detected client
    """
    output = path_result.clone()
    client = get_client_from_path(path_result.path)

    if client and client in CLIENT_TOOLS:
        tools_dict = CLIENT_TOOLS[client]

        # Skip if no tools defined for this client
        if not tools_dict:
            logger.info("No tools defined for %s; not adding built-in tools", client)
            return output

        # Create server and metadata
        server = StdioServer(command=client)
        client_display_name = client.title()
        instructions = f"Built-in tools for {client_display_name}."

        metadata = InitializeResult(
            protocolVersion="built-in",
            capabilities=ServerCapabilities(tools=ToolsCapability(listChanged=False)),
            serverInfo=Implementation(name=client_display_name, version="built-in"),
            instructions=instructions,
        )

        signature = ServerSignature(metadata=metadata, tools=[], prompts=[], resources=[], resource_templates=[])

        # Create Tool entities programmatically
        for tool_name, tool_description in tools_dict.items():
            signature.tools.append(
                Tool(
                    name=tool_name,
                    description=tool_description,
                    inputSchema={},
                    outputSchema={},
                    annotations=None,
                    meta={},
                )
            )
        if output.servers is None:
            output.servers = []
        output.servers.append(
            ServerScanResult(name=f"{client_display_name} (built-in)", server=server, signature=signature)
        )
    elif client:
        logger.warning("Unknown client; not adding built-in tools for %s", client)

    return output
