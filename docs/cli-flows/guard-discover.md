# `guard discover`

`snyk-agent-scan guard discover --client {claude-code|cursor|codex|github-copilot} [--scope servers|skills|all] [--url URL]`

Not intended for humans: it is the command that the **session-start hook** installed by `guard install` runs (asynchronously) when an agent session begins. It discovers the MCP servers visible from the session's working folders and sends one `sessionStartServerDiscovery` event directly to Agent Monitor.

Required environment (set by the generated hook command): `PUSH_KEY`, `MACHINE_ID`, optionally `REMOTE_HOOKS_BASE_URL`. Required stdin: the agent's hook JSON payload (read with a 5 s timeout, 1 MiB cap).

Entry points: `snyk-agent-guard-discover.{sh,ps1}` -> `cli.py:main` -> `guard.run_guard` -> `guard._run_discover` -> `guard._send_servers_discovered_event`.

## Sequence diagram

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User and agent
    participant AG as Coding agent (Claude Code, Cursor, Codex, Copilot)
    end
    box rgba(80,140,220,0.18) Flow logic
    participant TR as snyk-agent-guard-discover.sh (trampoline)
    participant CLI as cli.main
    participant G as guard.py (_run_discover)
    participant PIPE as pipelines.py (discovery)
    participant HEV as hook_events.py
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant OS as OS / env / stdin
    participant FS as Filesystem
    participant SQL as SQLite (opencode DB)
    participant SUB as Subprocess (codesign)
    end
    box rgba(220,100,100,0.18) Backends
    participant MON as Agent Monitor
    end

    AG->>TR: SessionStart hook (async) - env PUSH_KEY, MACHINE_ID, AGENT_SCAN_COMMAND, stdin = hook JSON
    alt MACHINE_ID or AGENT_SCAN_COMMAND missing
        TR-->>AG: exit 0 silently
    end
    TR->>CLI: exec AGENT_SCAN_COMMAND guard discover --client X --scope servers (stdout and stderr to /dev/null, errors ignored)

    CLI->>CLI: full bootstrap (shared flow A) - argparse, banner, logging - banner goes to /dev/null
    CLI->>G: run_guard -> _run_discover(args)
    G->>OS: env PUSH_KEY, MACHINE_ID, REMOTE_HOOKS_BASE_URL
    alt PUSH_KEY, MACHINE_ID or --client missing
        G-->>CLI: exit 1
    end

    rect rgba(150,150,150,0.15)
    Note over G,OS: Read the session context from stdin
    G->>OS: read stdin (daemon thread, 5 s, 1 MiB)
    G->>G: json.loads, pick target folder field by client (cwd, or workspace_roots for Cursor) and session id field (session_id, or conversation_id for Cursor)
    Note over G: any parse problem is swallowed, discovery continues with no target folders
    end

    rect rgba(220,170,60,0.15)
    Note over G,SUB: Discovery (shared flow B, no MCP server is contacted)
    G->>PIPE: discover_clients_to_inspect(paths empty, scope, target_folders) in a daemon thread, 60 s limit
    PIPE->>FS: resolve + exists for target folders
    PIPE->>FS: well-known client dirs, config files, plugin / extension dirs, skills dirs (per --scope)
    PIPE->>FS: project roots (~/.claude.json projects, workspaceStorage) + ancestor walk
    PIPE->>SQL: opencode project table
    PIPE->>SUB: codesign for stdio binaries (macOS)
    PIPE-->>G: clients_to_inspect
    G->>G: _servers_discovered_entries - wrap as InspectedPath without signatures, build_scan_request, dump JSON
    end

    opt client is claude-code and scope includes servers
        rect rgba(150,150,150,0.15)
        Note over G,FS: Claude Desktop logged connectors (remaining time of the 60 s budget)
        G->>OS: readable home directories (current user)
        G->>FS: glob claude-code-sessions and local-agent-mode-sessions JSON, skip symlinked paths, read
        G->>G: newest connector per org and uuid, URL query redacted
        end
    end

    rect rgba(220,100,100,0.15)
    Note over G,MON: Deliver
    G->>G: payload = sessionStartServerDiscovery + servers + claudeLoggedMcpServers + duration + session id, scrub push keys
    G->>HEV: send_hook_event(url, client, push key, payload, machine id, max_retries=1)
    HEV->>OS: hostname, username, AI_AGENT / COPILOT_CLI env (Copilot surface header)
    HEV->>MON: POST /hidden/agent-monitor/hooks/CLIENT?version=... (aiohttp, 15 s) headers X-User, X-Client-Id, body "base64:..."
    alt HTTP below 400
        MON-->>HEV: ok
        G-->>CLI: 0
    else error or transport failure
        G-->>CLI: 1 (exit code ignored by the trampoline)
    end
    end
    CLI-->>TR: exit code
    TR-->>AG: exit 0 always
```

## Notes

- A full CLI start-up (argparse tree, optional config file, banner, logging setup, psutil lookup of the parent process) runs for every agent session start, only to dispatch to one function. `guard` is imported lazily, but the generic bootstrap is not skipped.
- Discovery here reuses `pipelines.discover_clients_to_inspect`, then re-implements the "inspect without contacting servers" step by importing private helpers from `inspect.py` (`_config_error_to_scan_error`, `_inspection_component_name`, `_join_scan_errors`) and `verify_api.build_scan_request`.
- Same hand-off style as install: the push key travels via environment variables defined inside the hook command text; the CLI never reads the agent config.
- The wire contract (base64 body, `X-User`, `X-Client-Id`) is implemented twice: in `hook_events.py` (Python) and in `snyk-agent-guard.sh` / `.ps1` (see [guard hook runtime](guard-hook-runtime.md)).
