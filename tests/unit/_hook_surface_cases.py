"""Evidence-only wire cases shared by installed forwarders and discovery."""

HOOK_SURFACE_CASES = [
    (
        "github-copilot",
        {"AI_AGENT": "github_copilot_vscode_agent", "COPILOT_CLI": "1"},
        {"AI_AGENT": "github_copilot_vscode_agent", "COPILOT_CLI": "1"},
    ),
    ("github-copilot", {"AI_AGENT": "", "COPILOT_CLI": "1"}, {"AI_AGENT": "", "COPILOT_CLI": "1"}),
    ("github-copilot", {"CLAUDE_CODE_ENTRYPOINT": "cli"}, {}),
    ("claude-code", {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli", "AI_AGENT": "other"}, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}),
    ("claude-code", {"CLAUDE_CODE_ENTRYPOINT": ""}, {"CLAUDE_CODE_ENTRYPOINT": ""}),
    (
        "codex",
        {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": "Codex Desktop"},
        {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": "Codex Desktop"},
    ),
    (
        "codex",
        {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": 'Größe 😀 "\\literal\\u00e9"\r\n\t\x01\x7f'},
        {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": 'Größe 😀 "\\literal\\u00e9"\r\n\t\x01\x7f'},
    ),
    (
        "cursor",
        {"CURSOR_INVOKED_AS": "😀" * 128, "CURSOR_CLI_MODE": "🌍" * 128},
        {"CURSOR_INVOKED_AS": "😀" * 128, "CURSOR_CLI_MODE": "🌍" * 128},
    ),
    ("codex", {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": "😀" * 129}, {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": None}),
    ("codex", {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": "a" * 129}, {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": None}),
    ("codex", {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": "a" * 128}, {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE": "a" * 128}),
    ("codex", {}, {}),
    (
        "cursor",
        {"CURSOR_CLI": r'"C:\Program Files\Cursor\Cursor.exe"', "CURSOR_CLI_MODE": "local"},
        {"CURSOR_CLI": None, "CURSOR_CLI_MODE": "local"},
    ),
    ("cursor", {"CURSOR_INVOKED_AS": "", "CURSOR_CLI": ""}, {"CURSOR_INVOKED_AS": "", "CURSOR_CLI": None}),
    ("cursor", {"CURSOR_AGENT_SOCKET": "/run/cursor/api.sock"}, {"CURSOR_AGENT_SOCKET": None}),
    ("codex", {"CURSOR_AGENT_SOCKET": "/run/cursor/api.sock"}, {}),
]
