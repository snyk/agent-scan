# Agent discovery reference

This page lists every place Agent Scan looks for MCP servers and skills, for each agent. The README tables under [Supported agents and capabilities](../README.md#supported-agents-and-capabilities) link here.

- [How to read this page](#how-to-read-this-page)
- [What happens during a scan](#what-happens-during-a-scan)
- [Windows and WSL](#windows-and-wsl)
- [Discovery methods](#discovery-methods)
- Agents: [Claude Code](#claude-code) · [Claude Desktop](#claude-desktop) · [Codex](#codex) · [GitHub Copilot](#github-copilot) · [OpenCode](#opencode) · [VS Code](#vs-code) · [Cursor](#cursor) · [Windsurf](#windsurf) · [Kiro](#kiro) · [Antigravity](#antigravity) · [Gemini CLI](#gemini-cli) · [OpenClaw](#openclaw) · [Amp](#amp) · [Amazon Q](#amazon-q)

## How to read this page

Each agent has a table. Each row is one place Agent Scan looks. The **Scope** column matches the scopes in the README:

| Scope | Meaning |
| --- | --- |
| Detect | How we tell the agent is installed. If this fails, we skip the agent. |
| System | Machine-wide files: set by an admin, or shipped inside the app. |
| User | Files in the user's home directory. |
| Env | Environment variables that change or add paths. |
| Projects | Where we find out which projects the user opened in that agent. |
| Project / WS | Paths we check in each project folder and in each of its parent folders. |
| Ext / plugin | Installed extensions or plugins. We walk these folders. |

We check every row in every home we scan (see [What happens during a scan](#what-happens-during-a-scan)). JSON files can have comments and trailing commas. We skip files over 20 MiB.

Path notation:

- `~` is the home directory we're scanning.
- `<project>` is a project folder, or any folder above it up to `/`. For `~/work/app`, `<project>/.mcp.json` means `~/work/app/.mcp.json`, `~/work/.mcp.json`, `~/.mcp.json` and `/.mcp.json`. Project folders come from that agent's **Projects** rows.
- `<userdata>` is the settings folder of a VS Code-style editor. See [User data directory](#user-data-directory).
- `a | b` or `a or b` means we check both names. For example, `opencode.json | .jsonc` means `opencode.json` and `opencode.jsonc`. If both exist, we read both.
- `{a,b}` means each name in turn. For example, `plugins/{cache,local}` is `plugins/cache` and `plugins/local`.
- `*` matches one folder or file name. `**` matches any number of folders (we stop at 10 levels).
- `→` means "open this file and read this field". See [Reading arrows](#reading-arrows).

### Reading arrows

The part after `→` is a field in the file. It usually holds more paths, like project folders or plugin folders. `.` goes into an object, and `[]` means "each item in the list".

For example, `~/.gemini/config/projects/*.json` → `projectResources.resources[].folderUri` means: open each `.json` file in `~/.gemini/config/projects/`, go into `projectResources`, then `resources`, and take `folderUri` from each item. With this file:

```json
{
  "projectResources": {
    "resources": [
      { "folderUri": "file:///Users/me/repo-a" },
      { "folderUri": "file:///Users/me/repo-b" }
    ]
  }
}
```

we get two project folders, `/Users/me/repo-a` and `/Users/me/repo-b`, and check the **Project / WS** rows in both. We turn `file://` URIs into normal paths. We skip other kinds, like `vscode-remote://`.

### User data directory

VS Code and its forks (Cursor, Windsurf, Kiro, Antigravity) keep files in two places:

- A dot folder in the home directory, like `~/.vscode` or `~/.cursor`. This has extensions and some agent files.
- A settings folder, written `<userdata>` on this page. This has settings, profiles and the list of opened projects. Where it lives depends on the OS.

| OS | `<userdata>` |
| --- | --- |
| macOS | `~/Library/Application Support/<Name>` |
| Linux | `~/.config/<Name>` |
| Windows | `~/AppData/Roaming/<Name>` |

`<Name>` depends on the editor:

| Agent | `<Name>` |
| --- | --- |
| VS Code | `Code`, `Code - Insiders` |
| Cursor | `Cursor` |
| Windsurf | `Windsurf` |
| Kiro | `Kiro` |
| Antigravity | `Antigravity`, `Antigravity IDE` |

So `<userdata>/User/mcp.json` is `~/Library/Application Support/Cursor/User/mcp.json` for Cursor on macOS, and `C:\Users\<you>\AppData\Roaming\Code\User\mcp.json` for VS Code on Windows.

What we read inside `<userdata>`:

| Path | What for |
| --- | --- |
| `User/mcp.json` | User MCP servers |
| `User/settings.json` | MCP servers (`mcp.servers` or `mcpServers`), and `chat.agentSkillsLocations` where the editor has it |
| `User/profiles/*/` | The same files, for each profile |
| `User/workspaceStorage/*/workspace.json` | Opened projects |

Each editor's table says which of these it uses. For portable VS Code we also check `$VSCODE_PORTABLE/user-data`.

## What happens during a scan

This is what `agent-scan scan` does before it starts any MCP server. Discovery only reads files. It never runs anything.

1. **Pick the homes.** By default just your home. With `--scan-all-users`:
   - macOS / Linux: every account with uid ≥ 500 (macOS) or ≥ 1000 (Linux), skipping `nobody`, whose home we can read and enter.
   - Windows: every user profile from `Get-CimInstance Win32_UserProfile` (we give up after 10 seconds), plus WSL homes. See [Windows and WSL](#windows-and-wsl).
   - Homes we can't read are skipped and logged.
2. **First pass: fixed list.** A fixed list of agents and paths for the current OS (`well_known_clients.py`). For each agent and each home: check the install path, then read its MCP config files and skills folders. Paths that start with `~` are checked once per home. Paths that don't (machine-wide) are checked once. This is the only pass for Gemini CLI, OpenClaw, Amp and Amazon Q.
3. **Second pass: per-agent discovery.** For each home, every agent with its own discovery code (`agents/`) checks if it's installed and then runs all the rows in its table: projects, parent folders, plugins, extensions and so on.
4. **Merge.** Results from both passes are combined per agent and user. If both passes found the same file, the second pass wins. Paths are resolved first, so a file reached through a symlink isn't counted twice.
5. **Report users.** We only report the usernames where we found an agent. If we found nothing, we report all users we scanned (with `--scan-all-users`) or just you.

Other things that affect what we find:

| Topic | What happens |
| --- | --- |
| `--paths` | Skips both passes. Each value can be a server spec, a `SKILL.md`, a skill folder, a folder of skills, or an MCP config file. Missing paths are reported as "file not found". |
| `--no-skills` | Both passes skip skills. The install check still runs, so agents still show up. |
| Broken files | A broken file we expected (like `~/.cursor/mcp.json`) is reported as "could not parse". A file we only picked up because of its name (like an `mcp.json` inside an extension, or a `settings.json`) is skipped quietly if it doesn't look like MCP config. |
| No access | A file or folder we're not allowed to read counts as missing, not as an error. |
| One bad agent | If one agent's discovery crashes, we log it and carry on with the others. Servers and skills are collected separately, so a crash in one doesn't lose the other. |
| Current folder | The folder you run `scan` from isn't treated as a project. The only exceptions are OpenClaw and Amp, whose fixed paths are relative to it. |

## Windows and WSL

On Windows, Agent Scan runs as a Windows program, but it can also see the Linux homes inside WSL. With `--scan-all-users`. To find Linux-style configs in those homes, the fixed list on Windows is the Windows list **plus** the Linux list.

## Discovery methods

Every row on this page uses one of a few methods. They fall into three steps:

1. **Locate**: find where to look. Only runs if the agent is installed.
2. **Expand**: find more places to look, based on something Locate found. For example, a config file that lists projects, or a plugin folder.
3. **Read**: get MCP servers and skills out of the files and folders found by Locate or Expand.

Some steps run more than once. When we find a new project folder (Expand), we check it for config files (Locate) and read them (Read). When a plugin file points to another folder (Expand), we search that folder too (Expand) and read what's there (Read). We only follow links we know each agent uses. We don't search the whole disk.

| Method | What it does | What a rule needs | Example |
| --- | --- | --- | --- |
| Install check (Locate) | Checks the agent's home exists. If not, we skip the agent. | A list of paths. Any one is enough. | `~/.codex` or `$CODEX_HOME` |
| Known locations (Locate) | Reads files and skills folders at fixed paths: in the home, machine-wide, or inside the app. | A path for each OS. Can use `~`, `<userdata>`, `$VAR` or `%VAR%`. | `~/.cursor/mcp.json`, `/etc/codex/config.toml`, `<userdata>/User/mcp.json` |
| Project-relative paths (Locate) | Checks the same paths in each project folder and its parent folders. | Paths relative to `<project>` | `<project>/.mcp.json`, `<project>/.claude/skills` |
| Recorded projects (Expand) | Gets project folders from the agent's own list of opened projects. | A file and a field, or a fixed SQLite query | `~/.claude.json` → `projects` keys; OpenCode `SELECT worktree FROM project` |
| Pointers (Expand) | Reads a file that lists more paths: plugin folders, MCP files or skills folders. | A file, a field, and what the path is relative to | `installed_plugins.json` → `installPath`, `plugin.json` → `skills[]`, `extensions.json` → `relativeLocation` |
| Directory search (Expand) | Walks a folder (up to 10 levels) looking for known file and folder names. | A folder and the names to look for | `~/.claude/plugins/cache/**` → `.mcp.json`, `skills/` |
| MCP config file (Read) | Reads a file that only holds MCP config. | The format (JSON, JSONC) and the layouts we accept | `.mcp.json`, `mcp_config.json` |
| Embedded MCP block (Read) | Reads MCP servers from one key in a bigger config file. | The format and the key | `settings.json` → `mcp.servers`, `config.toml` → `[mcp_servers]`, `devcontainer.json` → `customizations.vscode.mcp.servers` |
| Skills directory (Read) | Lists the `<name>/SKILL.md` folders inside a folder. | A folder | `~/.claude/skills` |
| Custom extraction (Read) | Gets servers out of files that aren't config, with code written for that agent. | Agent-specific code | Extension JavaScript |

Methods each agent uses:

| Agent | Install check | Known locations | Project-relative | Recorded projects | Pointers | Directory search | MCP config file | Embedded MCP block | Skills directory | Custom extraction |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| [Claude Code](#claude-code) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| [Claude Desktop](#claude-desktop) | ✓ | ✓ | | | ✓ | ✓ | ✓ | ✓ | ✓ | |
| [Codex](#codex) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| [GitHub Copilot](#github-copilot) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| [OpenCode](#opencode) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | ✓ | ✓ | |
| [VS Code](#vs-code) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| [Cursor](#cursor) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| [Windsurf](#windsurf) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| [Kiro](#kiro) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | |
| [Antigravity](#antigravity) | ✓ | ✓ | ✓ | ✓ | | ✓ | ✓ | ✓ | ✓ | |
| [Gemini CLI](#gemini-cli) | ✓ | ✓ | | | | | | ✓ | ✓ | |
| [OpenClaw](#openclaw) | ✓ | ✓ | | | | | | | ✓ | |
| [Amp](#amp) | ✓ | ✓ | | | | | | | ✓ | |
| [Amazon Q](#amazon-q) | ✓ | ✓ | | | | | ✓ | ✓ | | |

Notes:

- **Embedded MCP block** includes config files that have an MCP key among other settings, like `~/.claude.json` → `mcpServers`, `opencode.json` → `mcp`, `plugin.json` → `mcpServers`, and Kiro or Amazon Q agent files.
- Environment variables are part of **Known locations** paths (for example `$CODEX_HOME/config.toml`). We only use them when scanning your own home, because they come from your shell, not from other users. Machine-wide variables (`ProgramFiles`, `ProgramData`) are always used.

## Claude Code

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.claude` or `$CLAUDE_CONFIG_DIR` | | |
| System | macOS `/Library/Application Support/ClaudeCode/managed-mcp.json` | MCP | Set by admins |
| System | Linux `/etc/claude-code/managed-mcp.json` | MCP | Set by admins |
| System | Windows `%ProgramW6432%` or `%ProgramFiles%\ClaudeCode\managed-mcp.json` | MCP | Set by admins |
| User | `~/.claude.json` → `mcpServers` | MCP | Uses `$CLAUDE_CONFIG_DIR/.claude.json` if set, else `~/.claude.json` |
| User | `~/.claude/skills` | Skills | A folder in here with `.claude-plugin/plugin.json` is treated as a plugin |
| Env | `CLAUDE_CONFIG_DIR` | | Changes the base folder |
| Env | `CLAUDE_CODE_PLUGIN_CACHE_DIR` | | Another plugin folder, or the plugin cache itself |
| Env | `CLAUDE_CODE_PLUGIN_SEED_DIR` | | A list of more plugin folders (split by the OS path separator) |
| Projects | `~/.claude.json` → `projects` keys | | Each key is a project path |
| Project / WS | `~/.claude.json` → `projects.<project>.mcpServers` | MCP | Path must match exactly |
| Project / WS | `<project>/.mcp.json` | MCP | |
| Project / WS | `<project>/.claude/skills` | Skills | |
| Project / WS | `<project>/.agents/skills` | Skills | |
| Ext / plugin | `<base>/plugins/{cache,repos,synced}/**` | MCP, Skills | Looks for `.mcp.json`, `skills/`, and `{.claude,.codex,.cursor}-plugin/plugin.json`. Skips `marketplaces/`, which lists plugins you could install, not ones you have. |
| Ext / plugin | `<base>/plugins/installed_plugins.json` → `plugins.*[].installPath` | MCP, Skills | Adds plugins installed outside the folders above. Up to 256. |
| Ext / plugin | `plugin.json` → `mcpServers` (inline) and `skills[]` (relative paths) | MCP, Skills | Paths can't point outside the plugin folder |

We ignore env var paths that are relative, `/`, `/home`, `/Users`, or a folder above your home. Plugin `.mcp.json` can be wrapped (`{"mcpServers": {...}}`) or flat. We drop remote connectors that have no URL.

## Claude Desktop

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | macOS `~/Library/Application Support/Claude` | | |
| Detect | Linux `~/.config/Claude` | | |
| Detect | Windows `~/AppData/Roaming/Claude` | | |
| User | `<install>/claude_desktop_config.json` → `mcpServers` | MCP | |
| Ext / plugin | `<install>/local-agent-mode-sessions/*/*/rpm/manifest.json` → `plugins[].id` | | Lists installed plugins (`<rpm>/<id>`). macOS and Linux only. |
| Ext / plugin | Each plugin folder from the list, up to 10 levels | MCP, Skills | Looks for `.mcp.json`, `skills/`, `.claude-plugin/plugin.json`. No symlinks. Paths can't leave the plugin folder. |
## Codex

`<codex_home>` is `$CODEX_HOME` if set, else `~/.codex`.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.codex` or `$CODEX_HOME` | | |
| System | macOS/Linux `/etc/codex/config.toml` → `[mcp_servers]` | MCP | |
| System | Windows `%PROGRAMDATA%\OpenAI\Codex\config.toml` → `[mcp_servers]` | MCP | |
| System | `/etc/codex/skills` | Skills | Set by admins |
| User | `<codex_home>/config.toml` → `[mcp_servers]` | MCP | |
| User | `<codex_home>/*.config.toml` | MCP | Profile configs |
| User | `<codex_home>/skills`, `<codex_home>/skills/.system` | Skills | |
| User | `~/.agents/skills` | Skills | |
| Env | `CODEX_HOME` | | Changes `<codex_home>` |
| Projects | `<codex_home>/config.toml` → `[projects]` keys | | We ignore `trust_level` |
| Project / WS | `<project>/.codex/config.toml` → `[mcp_servers]` | MCP | |
| Project / WS | `<project>/.agents/skills` | Skills | |
| Ext / plugin | `<codex_home>/plugins/**`, up to 10 levels | MCP, Skills | Looks for `.mcp.json`, `skills/`, `.codex-plugin/plugin.json` or `.claude-plugin/plugin.json` |
| Ext / plugin | `plugin.json` → `mcpServers` (a file starting with `./`), `skills` (a folder starting with `./`) | MCP, Skills | If a plugin has both, `.codex-plugin` wins over `.claude-plugin` |

Plugin `.mcp.json` can use `mcp_servers`, `mcpServers`, or a flat map.

## GitHub Copilot

Covers Copilot CLI and the desktop app. `<copilot_home>` is `$COPILOT_HOME` if set, else `~/.copilot`. Copilot in VS Code reads the same user files, see [VS Code](#vs-code).

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.copilot` or `$COPILOT_HOME` | | |
| User | `<copilot_home>/mcp-config.json` | MCP | |
| User | `<copilot_home>/skills` | Skills | |
| User | `~/.agents/skills` | Skills | |
| Env | `COPILOT_HOME` | | Changes `<copilot_home>` |
| Projects | `<copilot_home>/permissions-config.json` → `locations` keys | | We only read the paths, not the permissions |
| Project / WS | `<project>/.mcp.json`, `<project>/.github/mcp.json` | MCP | |
| Project / WS | `<project>/.github/skills`, `<project>/.claude/skills`, `<project>/.agents/skills` | Skills | |
| Ext / plugin | `<copilot_home>/installed-plugins/<marketplace>/<plugin>/**`, up to 10 levels | MCP, Skills | Looks for `.mcp.json`, `mcp.json`, `skills/` |
| Ext / plugin | Plugin manifest → `mcpServers` (inline or a path), `skills` (a path or a list) | MCP, Skills | We use the first one we find: `.plugin/plugin.json`, `plugin.json`, `.github/plugin/plugin.json`, `.claude-plugin/plugin.json` |

## OpenCode

`<global>` is any of `$XDG_CONFIG_HOME/opencode`, `$OPENCODE_CONFIG_DIR`, `~/.config/opencode`, `~/.opencode`.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | Any `<global>` folder, or the file in `$OPENCODE_CONFIG` | | |
| System | macOS `/Library/Application Support/opencode` | MCP, Skills | `opencode.json` / `.jsonc`, `skills` / `skill` |
| System | Linux `/etc/opencode` | MCP, Skills | Same files |
| System | Windows `%PROGRAMDATA%\opencode` | MCP, Skills | Same files |
| User | `<global>/opencode.json` or `.jsonc` → `mcp` | MCP | |
| User | `<global>/skills` or `<global>/skill` | Skills | |
| User | `~/.claude/skills`, `~/.agents/skills` | Skills | |
| User | `skills.paths[]` in any OpenCode config | Skills | `~` is home, absolute paths are used as is, relative paths are checked in each project |
| User | `~/.cache/opencode/skills/<hash>/` | Skills | Skills downloaded from URLs. Also under `$XDG_CACHE_HOME`. One level only. |
| Env | `OPENCODE_CONFIG`, `OPENCODE_CONFIG_DIR` | | Another config file or folder |
| Env | `OPENCODE_DB` | | Another project database. We skip `:memory:`. |
| Env | `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME` | | More config, data and cache folders |
| Projects | `~/.local/share/opencode/opencode*.db` → `project.worktree` | | SQLite, opened read-only. Also under `$XDG_DATA_HOME` and `$OPENCODE_DB`. |
| Project / WS | `<project>/opencode.json` or `.jsonc`, `<project>/.opencode/opencode.json` or `.jsonc` | MCP | |
| Project / WS | `<project>/.opencode/skills` or `skill`, `<project>/.claude/skills`, `<project>/.agents/skills` | Skills | |

## VS Code

Covers VS Code and VS Code Insiders. `<userdata>` names: `Code`, `Code - Insiders`.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.vscode`, `~/.vscode-insiders`, or `<userdata>` | | |
| System | Extensions that ship with the app | MCP, Skills | macOS `/Applications/Visual Studio Code.app/Contents/Resources/app/extensions` (also `~/Applications` and Insiders); Windows `~/AppData/Local/Programs/Microsoft VS Code/resources/app/extensions`, `C:/Program Files/Microsoft VS Code/...`; Linux `/usr/share/code/resources/app/extensions`, `/usr/share/code-insiders/...` |
| User | `<userdata>/User/mcp.json` | MCP | |
| User | `<userdata>/User/settings.json` → `mcp.servers`, `"mcp.servers"`, or `mcpServers` | MCP | Skipped if there's no MCP block |
| User | `<userdata>/User/profiles/*/mcp.json` and `settings.json` | MCP | One per profile |
| User | `~/.vscode/mcp.json`, `~/.copilot/mcp-config.json` | MCP | |
| User | `~/.copilot/skills`, `~/.claude/skills`, `~/.agents/skills` | Skills | |
| User | `chat.agentSkillsLocations` in user or profile `settings.json` | Skills | `~` is home, relative paths are from the workspace folder |
| Env | `VSCODE_PORTABLE` | | Adds `<p>/user-data` and `<p>/extensions` |
| Projects | `<userdata>/User/workspaceStorage/*/workspace.json` → `folder` | | Local folders only. We skip remote workspaces. |
| Projects | `workspace.json` → `.code-workspace` → `folders[]` | | Workspaces with more than one folder |
| Project / WS | `<project>/.vscode/mcp.json`, `<project>/.mcp.json` | MCP | |
| Project / WS | `<project>/.devcontainer/devcontainer.json`, `<project>/.devcontainer.json` → `customizations.vscode.mcp.servers` | MCP | |
| Project / WS | `.code-workspace` → `settings.mcp.servers` | MCP | |
| Project / WS | `<project>/.github/skills`, `<project>/.claude/skills`, `<project>/.agents/skills` | Skills | |
| Project / WS | `chat.agentSkillsLocations` in `<project>/.vscode/settings.json` or `.code-workspace` | Skills | |
| Ext / plugin | `~/.vscode/extensions`, `~/.vscode-insiders/extensions`, up to 10 levels | MCP, Skills | Only extensions listed in `extensions.json`, so leftovers from uninstalled ones are skipped. Looks for `mcp.json`, `skills/`. |
| Ext / plugin | Extension JavaScript (`package.json` → `main`, then `**/*.{js,cjs,mjs}`) | MCP | Only extensions with `contributes.mcpServerDefinitionProviders`. We find `McpStdioServerDefinition` / `McpHttpServerDefinition` calls with fixed values. We miss servers built at runtime. |

## Cursor

`<userdata>` name: `Cursor`. Uses the same VS Code rules for `<userdata>`, profiles, `settings.json`, opened projects and `extensions.json`.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.cursor` or `<userdata>` | | |
| System | Extensions that ship with the app | MCP, Skills | macOS `/Applications/Cursor.app/Contents/Resources/app/extensions` (also `~/Applications`); Windows `~/AppData/Local/Programs/Cursor/resources/app/extensions`; Linux `/usr/share/cursor/resources/app/extensions` |
| User | `~/.cursor/mcp.json`, `<userdata>/User/mcp.json`, `<userdata>/User/settings.json` | MCP | |
| User | `<userdata>/User/profiles/*/mcp.json` and `settings.json` | MCP | |
| User | `~/.cursor/skills`, `~/.cursor/skills-cursor`, `~/.agents/skills`, `~/.claude/skills`, `~/.codex/skills` | Skills | `skills-cursor` has Cursor's built-in skills |
| Projects | `<userdata>/User/workspaceStorage/*/workspace.json` → `folder` | | |
| Project / WS | `<project>/.cursor/mcp.json`, `<project>/.mcp.json` | MCP | |
| Project / WS | `<project>/.cursor/skills`, `<project>/.agents/skills`, `<project>/.claude/skills`, `<project>/.codex/skills` | Skills | |
| Ext / plugin | `~/.cursor/extensions`, up to 10 levels | MCP, Skills | Only extensions listed in `extensions.json` |
| Ext / plugin | `~/.cursor/plugins/{cache,local}/**`, up to 10 levels | MCP, Skills | Looks for `mcp.json`, `.mcp.json`, `skills/`. We don't walk the rest of `plugins/`, which lists plugins you could install. |

## Windsurf

`<userdata>` name: `Windsurf`.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.codeium/windsurf`, `~/.codeium`, or `<userdata>` | | |
| System | macOS `/Library/Application Support/Windsurf/skills` | Skills | |
| System | Linux `/etc/windsurf/skills` | Skills | |
| System | Windows `C:\ProgramData\Windsurf\skills` | Skills | |
| System | Extensions that ship with the app | MCP, Skills | macOS `/Applications/Windsurf.app/Contents/Resources/app/extensions` (also `~/Applications`); Windows `~/AppData/Local/Programs/Windsurf/resources/app/extensions` |
| User | `~/.codeium/windsurf/mcp_config.json` | MCP | |
| User | `<userdata>/User/settings.json` | MCP | Skipped if there's no MCP block |
| User | `<userdata>/User/profiles/*/settings.json` | MCP | |
| User | `~/.codeium/windsurf/skills`, `~/.agents/skills`, `~/.claude/skills` | Skills | |
| Projects | `<userdata>/User/workspaceStorage/*/workspace.json` → `folder` | | |
| Project / WS | `<project>/.mcp.json`, `<project>/.windsurf/mcp.json` | MCP | |
| Project / WS | `<project>/.windsurf/skills`, `<project>/.agents/skills`, `<project>/.claude/skills` | Skills | |
| Ext / plugin | `~/.windsurf/extensions`, up to 10 levels | MCP, Skills | Only extensions listed in `extensions.json` |

## Kiro

`<userdata>` name: `Kiro`.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.kiro` or `<userdata>` | | |
| System | Extensions that ship with the app | MCP, Skills | macOS `/Applications/Kiro.app/Contents/Resources/app/extensions` (also `~/Applications`); Windows `~/AppData/Local/Programs/Kiro/resources/app/extensions`. Our best guess, not checked on a real install yet. |
| User | `~/.kiro/settings/mcp.json` | MCP | Also reads `powers.mcpServers` |
| User | `~/.kiro/agents/*.json` → `mcpServers` | MCP | Custom agents |
| User | `~/.kiro/skills` | Skills | |
| Projects | `<userdata>/User/workspaceStorage/*/workspace.json` → `folder` | | |
| Project / WS | `<project>/.kiro/settings/mcp.json`, `<project>/.mcp.json` | MCP | |
| Project / WS | `<project>/.kiro/agents/*.json` → `mcpServers` | MCP | |
| Project / WS | `<project>/.kiro/skills`, `<project>/.agents/skills` | Skills | |
| Ext / plugin | `~/.kiro/extensions`, up to 10 levels | MCP, Skills | Only extensions listed in `extensions.json` |
| Ext / plugin | `~/.kiro/powers/installed`, up to 10 levels | MCP, Skills | No list to check against, so we scan every folder |

## Antigravity

`<userdata>` names: `Antigravity`, `Antigravity IDE`.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.gemini/antigravity` or `<userdata>` | | |
| User | `~/.gemini/antigravity/mcp_config.json`, `~/.gemini/config/mcp_config.json` | MCP | |
| User | `<userdata>/User/settings.json`, `~/.gemini/settings.json` | MCP | Skipped if there's no MCP block |
| User | `<userdata>/User/profiles/*/settings.json` | MCP | |
| User | `~/.gemini/skills`, `~/.gemini/antigravity/skills`, `~/.agents/skills`, `~/.agent/skills` | Skills | |
| Projects | `~/.gemini/config/projects/*.json` → `projectResources.resources[].folderUri` | | The main source. `workspaceStorage` is usually empty for Antigravity. |
| Projects | `<userdata>/User/workspaceStorage/*/workspace.json` → `folder` | | |
| Project / WS | `<project>/.mcp.json`, `<project>/.agents/mcp_config.json`, `<project>/.gemini/mcp_config.json` | MCP | |
| Project / WS | `<project>/.agent/skills`, `<project>/.agents/skills` | Skills | |
| Ext / plugin | `~/.gemini/config/plugins`, `~/.gemini/extensions`, up to 10 levels | MCP, Skills | No list to check against, so we scan every folder |

## Gemini CLI

Fixed paths only. We don't look at projects or plugins.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.gemini` | | |
| User | `~/.gemini/settings.json` | MCP | |
| User | `~/.gemini/skills` | Skills | |

## OpenClaw

Fixed paths only.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.clawdbot` or `~/.openclaw` | | |
| User | `~/.clawdbot/skills`, `~/.openclaw/skills` | Skills | |
| Project / WS | `~/.openclaw/workspace/skills` | Skills | A fixed path. We don't look up opened projects. |
| Project / WS | `.openclaw/skills` | Skills | Relative to the folder you run Agent Scan from |

## Amp

Fixed paths only.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.config/agents`, or `.amp` in the current folder | | |
| User | `~/.config/agents/skills` | Skills | |
| Project / WS | `.amp/skills` | Skills | Relative to the folder you run Agent Scan from |

## Amazon Q

Fixed paths only. On Windows these are checked in every home, including WSL homes.

| Scope | Location | Finds | Notes |
| --- | --- | --- | --- |
| Detect | `~/.aws/amazonq` | | |
| User | `~/.aws/amazonq/mcp.json` | MCP | |
| User | `~/.aws/amazonq/agents/default.json`, `~/.aws/amazonq/agents/mcp.json` | MCP | |
