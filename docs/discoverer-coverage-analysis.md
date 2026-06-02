# Agent Discoverer Coverage Analysis — MCP Servers & Skills

**Scope:** How completely the `agent_scan.agents` discoverer classes find the MCP
servers and Skills that **Claude Code, VS Code (+ GitHub Copilot), Cursor,
Windsurf, Kiro, and Antigravity** document.

**Method:** Each agent's official documentation was inventoried for every
documented MCP-config and skills location (user/global, project/workspace,
profile, plugin/extension, enterprise/managed). That inventory was cross-checked
against the concrete discoverers:

- `src/agent_scan/agents/claude_code.py` — `ClaudeCodeDiscoverer`
- `src/agent_scan/agents/vscode/{vscode,cursor,windsurf,kiro,antigravity}.py` —
  all extend `VSCodeFamilyDiscoverer` (`src/agent_scan/agents/vscode/base.py`)
- format models in `src/agent_scan/models.py`

Legend: ✅ covered · ⚠️ conditional / partial · ❌ documented-but-not-covered (gap)
· ➕ over-covered (scanned beyond docs; harmless belt-and-suspenders).

---

## 1. Executive summary

Coverage of **documented** configuration surfaces is **high across all six
agents** — for every agent, every officially documented MCP-config file and
skills directory that lives at a *static, predictable path* is scanned.

| Agent | MCP coverage | Skills coverage | Most material gap |
|---|---|---|---|
| Claude Code | ✅ High | ✅ High | Documented `ws` / `streamable-http` now parse; an *unknown* future `type` can still sink a file pending per-server validation (§7.1) |
| VS Code + Copilot | ✅ High | ✅ High | Extension-API-registered (programmatic) MCP servers have no file to scan (§2) |
| Cursor | ✅ High | ✅ High | Nested `.cursor/mcp.json` / `.cursor/skills` *below* an opened root (§7.2) |
| Windsurf | ✅ Complete* | ✅ Complete* | None material — scans every documented surface (*small documented surface) |
| Kiro | ✅ High | ✅ Complete* | Powers' MCP servers ("Powers section" key) + installed-Power path are undocumented (§6) |
| Antigravity | ✅ High | ✅ High | Official docs are an unreadable SPA; coverage rests on codelabs/CLI docs + version drift (§6) |

The dominant residual gaps are **structural and cross-cutting**, not per-agent
path omissions (§7):

1. A single unsupported remote `type` value rejects an entire MCP file.
2. Discovery walks workspace **ancestors up**, never **descends** into nested
   subdirectories that documentation says are picked up.
3. Servers registered **programmatically** (VS Code extension API) leave no file
   on disk to discover.
4. Per-workspace/project discovery only fires for projects the IDE has actually
   **opened** (recorded in `workspaceStorage` / `~/.claude.json`).

---

## 2. Claude Code — `ClaudeCodeDiscoverer`

Docs: [mcp](https://code.claude.com/docs/en/mcp),
[managed-mcp](https://code.claude.com/docs/en/managed-mcp),
[skills](https://code.claude.com/docs/en/skills),
[plugins-reference](https://code.claude.com/docs/en/plugins-reference).

### MCP

| Documented surface | Shape | Discoverer | Status |
|---|---|---|---|
| `~/.claude.json` top-level `mcpServers` (user scope) | wrapped | `_discover_global_mcp_servers` | ✅ |
| `~/.claude.json` → `projects.<path>.mcpServers` (local scope) | wrapped | `_discover_project_mcp_servers` | ✅ |
| `<project>/.mcp.json` (project scope) | wrapped/flat | `_discover_project_mcp_servers` (+ ancestor walk) | ✅ |
| Plugin `<root>/.mcp.json` | flat or wrapped | `_discover_plugin_mcp_servers` | ✅ |
| Inline `mcpServers` in `.claude-plugin/plugin.json` | wrapped | `_discover_plugin_manifest_mcp_servers` | ✅ |
| `managed-mcp.json` — macOS `/Library/Application Support/ClaudeCode/`, Linux `/etc/claude-code/`, Windows `…\ClaudeCode\` | wrapped | `_discover_managed_mcp_servers` | ✅ (all 3 OS, matches docs exactly) |
| Env relocation `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_PLUGIN_CACHE_DIR`, `CLAUDE_CODE_PLUGIN_SEED_DIR` | — | `_claude_base_dir` / `_plugin_root_dirs` (own-home only) | ✅ |

Plugin walks scan three subtrees: `cache`, `marketplaces`, `repos`
(`_plugin_subdirs`). Official docs only confirm `cache/` and `marketplaces/`
(plus `data/`); **`repos/` is a legacy/back-compat name, not in current docs** —
➕ harmless over-coverage (a non-existent dir is simply skipped).

**Gap (model-level) — RESOLVED for documented transports:** remote
`type: "ws"` (WebSocket) and `type: "streamable-http"` are documented Claude
Code transports. `RemoteServer.type` now accepts `Literal["sse", "http", "ws"]`
and a `field_validator` folds `streamable-http`/`streamable-https` onto `http`
(case-insensitively), so these servers parse and are discovered instead of
sinking their file. **Residual:** an entry with a still-*unknown* `type` (or
otherwise malformed) continues to fail the whole-file validation — per-server
validation (option (b)) remains a follow-up. See §7.1.

**Gap (undocumented, n/a):** docs reference an "Enterprise" skills row but
publish no managed-skills path analogous to `managed-mcp.json`. Nothing to scan;
flagged for completeness.

### Skills & commands

| Documented surface | Layout | Discoverer | Status |
|---|---|---|---|
| `~/.claude/skills/<name>/SKILL.md` | dir-per-skill | `_discover_global_skill` | ✅ |
| `<project>/.claude/skills` (+ every ancestor to root) | dir-per-skill | `_discover_project_skills` | ✅ |
| `<project>/.agents/skills` (+ every ancestor to root) | dir-per-skill | `_discover_project_skills` | ✅ (cross-agent convention; verified empirically that Claude Code loads it) |
| Plugin `<root>/skills/` + `plugin.json` `skills[]` array | dir-per-skill | `_discover_plugin_skills` / `_discover_plugin_manifest_skills` | ✅ |
| `~/.claude/commands/*.md`, `<project>/.claude/commands/*.md`, plugin `commands/` | flat `*.md` + namespacing | `_discover_global/project/plugin_commands` | ✅ |

**Gap (inherent):** docs describe *on-demand* nested discovery of
`<subdir>/.claude/skills` when editing files deeper than the opened root. The
discoverer walks ancestors **up**, not descendants **down**, so a skills dir in
an un-opened subdirectory is not found (§7.2).

---

## 3. VS Code + GitHub Copilot — `VSCodeDiscoverer`

Docs: [mcp-servers](https://code.visualstudio.com/docs/copilot/customization/mcp-servers),
[mcp-configuration](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration),
[agent-skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills).

### MCP

| Documented surface | Key | Discoverer | Status |
|---|---|---|---|
| Workspace `.vscode/mcp.json` | `servers` (+`inputs`) | `_discover_workspace_mcp` | ✅ (`VSCodeMCPConfig`) |
| Workspace-root `.mcp.json` | `servers` | `_discover_workspace_mcp` | ✅ (undocumented; verified empirically that VS Code loads it) |
| User `<userdata>/User/mcp.json` | `servers` | `_discover_user_mcp_files` | ✅ |
| `~/.vscode/mcp.json` | `servers` | `_discover_user_mcp_files` | ✅ |
| `settings.json` `mcp.servers` (nested **and** dotted `"mcp.servers"`) | nested/dotted | `_discover_user_settings_mcp` → `_parse_settings_mcp_gated` | ✅ |
| Per-profile `<userdata>/User/profiles/<id>/{mcp.json,settings.json}` | mixed | `_discover_profile_mcp_files` | ✅ |
| `.code-workspace` → `settings.mcp.servers` | nested/dotted | `_discover_code_workspace_mcp` | ✅ |
| `.devcontainer/devcontainer.json` → `customizations.vscode.mcp.servers` | nested | `_discover_devcontainer_mcp` | ✅ |
| Claude Desktop import via `chat.mcp.discovery.enabled` | object map / legacy bool | `_discover_claude_desktop_import` | ✅ (handles object + legacy bool; default off) |
| Extension-bundled `mcp.json` (`~/.vscode[-insiders]/extensions`) | any family format | `_discover_extension_mcp_servers` | ✅ |
| Insiders userdata `Code - Insiders` | — | `_user_data_dir_names` | ✅ |
| Portable mode `VSCODE_PORTABLE` | — | `_portable_user_data_dir` | ✅ (env var name unconfirmed in docs; mechanism documented) |

**Gap (inherent):** the `chat.mcp.discovery.enabled` object also has
`windsurf` / `cursor-global` / `cursor-workspace` sources. The discoverer imports
**only** the Claude Desktop source. Servers from the other three are *not*
imported here — but they are discovered independently by the Windsurf/Cursor
discoverers, so no server is actually lost (only the "VS Code re-uses them"
attribution).

**Gap (inherent, unavoidable):** extensions may register MCP servers
**programmatically** via `McpServerDefinitionProvider` (no on-disk file). These
cannot be found by any filesystem scan.

### Skills

`.github/skills`, `.claude/skills`, `.agents/skills` (workspace) and
`~/.copilot/skills`, `~/.claude/skills`, `~/.agents/skills` (user) — all ✅ via
`_workspace_skills_relative` / `_skills_dir_paths`. The
`chat.agentSkillsLocations` object map (and the relative-to-workspace resolution)
is honored by `_discover_settings_skill_locations`. ✅

> Note: current `microsoft/vscode` source constants list only `.github/skills`
> and `.claude/skills`; `.agents/skills` appears in the docs but not (yet) in
> source. The discoverer follows the **docs** — ➕ minor over-coverage, not a gap.

---

## 4. Cursor — `CursorDiscoverer`

Docs: [cursor.com/docs/mcp](https://cursor.com/docs/mcp),
[cursor.com/docs/skills](https://cursor.com/docs/skills).

### MCP

| Documented surface | Key | Discoverer | Status |
|---|---|---|---|
| `~/.cursor/mcp.json` (global) | `mcpServers` | `_discover_user_mcp_files` | ✅ |
| `<project>/.cursor/mcp.json` (workspace) | `mcpServers` | `_discover_workspace_mcp` | ✅ |
| `<project>/.mcp.json` (workspace root) | `mcpServers` | `_discover_workspace_mcp` | ✅ (undocumented; verified empirically that Cursor loads it) |

Remote servers use `url` (not `serverUrl`); `RemoteServer` accepts it. Cursor
omits `type` on remotes — fine, the URL key drives detection. The inherited
`User/mcp.json` + `User/settings.json` fallbacks are ➕ not Cursor-documented but
presence-gated, so harmless.

**Gap:** docs state a `.cursor/mcp.json` "anywhere inside your repository" is
picked up (`project → global → nested`). The discoverer covers the opened root
and its **ancestors**, not nested **descendants** — a nested-subdir config below
an opened root is missed (§7.2).

### Skills

All four workspace dirs (`.cursor/skills`, `.agents/skills`, `.claude/skills`,
`.codex/skills`) and all four user dirs (`~/.cursor/skills`, `~/.agents/skills`,
`~/.claude/skills`, `~/.codex/skills`) **match the docs exactly**. ✅ Same nested-
descendant caveat applies.

> `~/.cursor/extensions` and the per-OS Cursor userdata path are **not** in
> official docs (community/convention only). They are used as inferred
> belt-and-suspenders (`_extension_paths`) and skipped if absent — flagged per
> the "don't advertise undocumented coverage" principle.

---

## 5. Windsurf — `WindsurfDiscoverer`

Docs: [Cascade MCP](https://docs.windsurf.com/windsurf/cascade/mcp),
[Cascade Skills](https://docs.windsurf.com/windsurf/cascade/skills).

### MCP

| Documented surface | Key | Discoverer | Status |
|---|---|---|---|
| `~/.codeium/windsurf/mcp_config.json` (the **only** documented MCP file) | `mcpServers`, remote `serverUrl`/`url` | `_discover_user_mcp_files` | ✅ |

Research confirms Windsurf documents **no** per-project MCP file. The discoverer's
`.windsurf/mcp.json` workspace entry is ➕ speculative over-coverage (already
annotated as such in code) — harmless. Remote `serverUrl` is accepted via
`RemoteServer`'s alias. **MCP coverage of documented surfaces is complete.**

### Skills

Workspace (`.windsurf/skills`, `.agents/skills`, `.claude/skills`), user
(`~/.codeium/windsurf/skills`, `~/.agents/skills`, `~/.claude/skills`), and the
**enterprise system paths** — macOS `/Library/Application Support/Windsurf/skills`,
Linux `/etc/windsurf/skills`, Windows `C:\ProgramData\Windsurf\skills`
(`_platform_system_skills_dirs`) — **all match the docs exactly**. ✅

> Windsurf gates `.claude/skills` reading behind a "Claude Code config reading"
> toggle; the discoverer scans those dirs unconditionally — ➕ it may surface
> skills present on disk that Windsurf itself wouldn't load. Acceptable for a
> security scan (the files exist regardless). Windsurf "Workflows"/"Rules" are a
> distinct artifact class, not Skills, and are correctly out of scope.

---

## 6. Kiro & Antigravity — `KiroDiscoverer`, `AntigravityDiscoverer`

### Kiro — docs: [mcp/configuration](https://kiro.dev/docs/mcp/configuration/), [skills](https://kiro.dev/docs/skills/), [powers](https://kiro.dev/docs/powers/)

| Documented surface | Discoverer | Status |
|---|---|---|
| `~/.kiro/settings/mcp.json` (user, `mcpServers`) | `_discover_user_mcp_files` | ✅ |
| `<root>/.kiro/settings/mcp.json` (workspace) | `_discover_workspace_mcp` | ✅ |
| `~/.kiro/skills`, `<root>/.kiro/skills` | `_skills_dir_paths` / `_workspace_skills_relative` | ✅ |

Remote servers use only `url` (no `type`) — accepted. Skills match docs exactly.
Steering/Specs/Hooks are correctly **not** treated as skills.

**Gap — Powers (undocumented internals):**
- Installing a Power registers its MCP server into `~/.kiro/settings/mcp.json`
  *"under the Powers section."* The **literal JSON key is undocumented.** If it is
  a nested wrapper (e.g. `powers.mcpServers`) rather than top-level `mcpServers`,
  none of the family format models match it and those servers are **missed**.
  (A prior commit deliberately dropped an unverified `powers.mcp.json` path —
  consistent with not guessing.)
- The discoverer walks `~/.kiro/powers/installed` as an extension root, but the
  **installed-Power on-disk path is not in `kiro.dev` docs** — it is inferred
  from the `kirodotdev/powers` *authoring* layout (`power-{name}/` with `mcp.json`
  + `steering/`). ⚠️ Low-confidence coverage: correct if the install path matches
  the authoring layout, otherwise a no-op. Flag for confirmation against an
  official source.

### Antigravity — docs: SPA (unreadable); coverage rests on Google codelabs + Gemini CLI docs

| Documented surface | Discoverer | Status |
|---|---|---|
| `~/.gemini/antigravity/mcp_config.json` (1.0 IDE) | `_discover_user_mcp_files` | ✅ |
| `~/.gemini/config/mcp_config.json` (2.0 shared IDE+CLI) | `_discover_user_mcp_files` | ✅ |
| `~/.gemini/settings.json` top-level `mcpServers` (remote `httpUrl`) | `_discover_gated_home_settings_mcp` | ✅ (`httpUrl` accepted via alias) |
| `<userdata>/User/settings.json` nested `mcp.servers` | `_discover_user_settings_mcp` | ✅ (gated; Antigravity-reading unconfirmed but harmless) |
| userdata `Antigravity` + `Antigravity IDE` | `_user_data_dir_names` | ✅ (both version folders) |
| Extensions `~/.gemini/extensions` | `_discover_extension_mcp_servers` | ✅ |

**No per-workspace MCP path** is officially documented; `_workspace_mcp_relative`
is correctly left empty (the code documents this decision and refuses to guess
`.agents/mcp_config.json`-style community paths). Remote `serverUrl`/`httpUrl`
are both accepted.

Skills: `~/.gemini/skills` (2.0 actual), `~/.agents/skills` (installer target),
`~/.gemini/antigravity/skills` (codelab path), `~/.agent/skills` (legacy), plus
workspace `.agent/skills` / `.agents/skills` — all ✅. This spans both the
codelab-documented and the version-drifted-actual locations.

**Caveats:** (a) the official `antigravity.google/docs` MCP/Skills pages are a
client-rendered SPA the research could not read — "official" rests on Google
codelabs and Gemini CLI docs; (b) there is **live version drift** (1.0
`~/.gemini/antigravity/…` vs 2.0 `~/.gemini/config/…` and `~/.gemini/skills`) —
the discoverer hedges by scanning both, which is the right call. The
generated-cache dirs (`antigravity-ide/mcp/`, `antigravity-cli/mcp/`) are
correctly **not** scanned.

---

## 7. Cross-cutting structural gaps

These affect multiple agents and are where coverage is most improvable.

### 7.1 One unsupported remote `type` sinks the whole file *(option (a) fixed; (b) pending)*

`RemoteServer.type` was `Literal["sse", "http"] | None`. Claude Code documents
`type: "ws"` and `type: "streamable-http"`. Because a config's `mcpServers` map
validates as a single Pydantic unit, **one** server with such a `type` raised a
`ValidationError` that converted the entire file into a `CouldNotParseMCPConfig`
— every (including valid) server in the file was lost. Was verified:

```
RemoteServer type='ws':             REJECTED
RemoteServer type='streamable-http': REJECTED
{good stdio + one ws server} -> ENTIRE FILE REJECTED (all servers lost)
```

**Option (a) — done.** `RemoteServer.type` is now `Literal["sse", "http", "ws"]
| None` with a `field_validator` that folds `streamable-http`/`streamable-https`
onto `http` (case-insensitively, since it's the same Streamable HTTP transport
the client implements and `ws` isn't connectable but must still be discovered).
A config carrying these documented transports now parses and yields all servers.

**Option (b) — follow-up.** Validate servers individually so one bad entry
doesn't drop its siblings. This generalises the fix to *unknown* future `type`
values and to genuinely malformed single entries, but it is a cross-cutting
change to the shared parse path (`_load_and_parse_mcp` / `_parse_mcp_file`) and
must decide how a dropped server is surfaced rather than silently lost — tracked
separately.

### 7.2 Ancestor-only traversal misses nested configs

Both `ClaudeCodeDiscoverer` and the VS Code family resolve opened roots and walk
**ancestors up to filesystem root** (`_project_paths_with_ancestors`). They never
**descend** into subdirectories. But Claude Code ("nested discovery"), Cursor
("anywhere inside your repository"), and VS Code monorepos all document configs
that live in subdirectories *below* an opened root. Such configs are found only
if that subdir was itself opened as a workspace. (Plugin/extension trees *are*
walked with a depth-bounded descend, so this gap is specific to **project/workspace
scope**.)

### 7.3 Programmatic MCP registration is invisible to a file scan

VS Code extensions can register servers via the MCP extension API with no
on-disk config. No filesystem-based discoverer can surface these — an inherent
boundary, worth stating explicitly so coverage isn't over-claimed.

### 7.4 Discovery requires the project/IDE to have been opened

Per-workspace scanning depends on the workspace appearing in
`<userdata>/User/workspaceStorage` (VS Code family) or the `projects` map in
`~/.claude.json` (Claude Code). A repo cloned but never opened in the IDE — or
whose `workspaceStorage` entry was pruned — won't have its `.vscode/mcp.json`,
`.cursor/skills`, etc. scanned. By design, but a real coverage boundary.

---

## 8. Bottom line

For **statically-located, officially-documented** MCP configs and skills
directories, the discoverers are **comprehensive** across all six agents:
user/global, project/workspace, profiles, plugins/extensions, devcontainers,
multi-root workspaces, enterprise/managed and system paths, and per-OS variants
are all covered, and the code deliberately refuses to invent undocumented paths
(Antigravity workspace MCP, Kiro `powers.mcp.json`) rather than advertise
coverage it can't back.

The remaining gaps are **structural**, in rough priority order:

1. **`type: "ws"` / `"streamable-http"` rejection sinking a whole file** (§7.1) —
   ✅ fixed for these documented transports; per-server validation (option (b),
   covering *unknown* types) remains a follow-up.
2. **Nested-descendant project configs** (§7.2) — affects Claude Code / Cursor /
   VS Code monorepos.
3. **Kiro Powers** MCP key + installed path (§6) — blocked on undocumented
   internals; revisit when Kiro publishes them.
4. **Programmatic VS Code MCP servers** (§7.3) and **never-opened projects**
   (§7.4) — inherent limits of filesystem discovery, documented here so coverage
   is not over-stated.
