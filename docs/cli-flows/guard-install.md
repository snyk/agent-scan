# `guard install`

`snyk-agent-scan guard install {claude|cursor|codex|github-copilot|all} [--url URL] [--tenant-id ID] [--machine-id ID] [--file PATH] [--managed]`

Installs Agent Guard hooks into the selected coding agent(s): copies the forwarder shell / PowerShell scripts next to the agent's config, rewrites the agent's hook config so every hook event is piped through the forwarder, verifies the setup with a test event, and reports the MCP servers found on the machine.

Entry points: `cli.py:main` -> `guard.run_guard` -> `guard._run_install` -> `guard._install_hooks` (per client) -> `guard._send_servers_discovered_event`.

Two credential modes:

- **Interactive** (no `PUSH_KEY` env): needs `SNYK_TOKEN` (env or typed) and a tenant id; the command mints a push key and revokes it again if the install fails before anything was written.
- **Headless / MDM** (`PUSH_KEY` env set): no Snyk token, no tenant lookup, no minting.

## Sequence diagram

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User
    participant T as Terminal (stdin / stdout)
    end
    box rgba(80,140,220,0.18) Flow logic
    participant G as guard.py (_run_install, _install_hooks)
    participant KEYS as pushkeys.py
    participant PIPE as pipelines.py (discovery)
    participant HEV as hook_events.py
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant OS as OS / env
    participant FS as Filesystem
    participant SUB as Subprocess (bash or powershell forwarder, curl)
    end
    box rgba(220,100,100,0.18) Backends
    participant PLAT as Snyk Platform API
    participant MON as Agent Monitor (hook endpoints)
    end

    rect rgba(150,150,150,0.15)
    Note over T,G: Phase 0 - bootstrap and input resolution
    T->>G: guard install CLIENT [flags] (via shared flow A, run_guard)
    G->>OS: env PUSH_KEY (headless if set), TENANT_ID, MACHINE_ID
    alt no machine id
        G->>OS: hostname via uname
        G->>T: warning - hostname used temporarily
    end
    alt client is all and --file given
        G->>T: error, exit 1
    end
    opt no --file and not --managed
        loop each client
            G->>FS: is_dir(~/.claude | ~/.cursor | ~/.codex | ~/.copilot)
        end
        G->>T: warn and skip clients whose agent is not installed (nothing left = return)
    end
    end

    rect rgba(220,100,100,0.15)
    Note over T,PLAT: Phase 1 - credentials (interactive mode only)
    opt PUSH_KEY not set
        G->>OS: env SNYK_TOKEN
        opt missing
            G->>T: prompt for API token
            T-->>G: stdin
        end
        opt tenant id missing
            G->>T: prompt for tenant id
            T-->>G: stdin
        end
        G->>KEYS: fetch_guard_enabled(url, tenant, token)
        KEYS->>PLAT: GET /hidden/tenants/TENANT/agent-monitor/guard-enabled (urllib, 15 s)
        PLAT-->>KEYS: enabled true or false, 403 = access denied
        alt not enabled or error
            G->>T: explanation, exit 1
        end
        loop each client
            G->>FS: os.access(config parent dir, W_OK) preflight
        end
        G->>KEYS: mint_push_key(url, tenant, token, description "agent-guard (host) Label")
        KEYS->>PLAT: POST /hidden/tenants/TENANT/mcp-scan/push-key
        PLAT-->>KEYS: client_id
        G->>T: "Push key minted abcd...wxyz"
    end
    end

    rect rgba(80,140,220,0.15)
    Note over G,MON: Phase 2 - per client install (_install_hooks)
    loop each client (claude, cursor, codex, github-copilot)
        G->>FS: read existing config (JSON, or requirements.toml for managed Codex)
        G->>G: detect existing guard command (regex), extract old push key, compute push_key_changed
        G->>OS: env AGENT_SCAN_COMMAND, else sys.frozen executable, else console script next to python
        G->>FS: importlib.resources read bundled snyk-agent-guard.sh / .ps1 (+ discover script)
        G->>G: substitute __AGENT_SCAN_VERSION__ in the install-time variables section, sha256
        G->>FS: read current script (if any), compare checksum
        G->>FS: mkdir -p hooks dir, write script when changed, chmod +x
        G->>G: render hook command (PUSH_KEY=... REMOTE_HOOKS_BASE_URL=... TENANT_ID=... MACHINE_ID=... bash script --client X)
        G->>G: prepare config in memory - drop old guard entries, append one entry per event, add async SessionStart discovery entry, compute added / modified / removed diff
        G->>SUB: run forwarder script, stdin = hooksConfigured test payload (first_install, diff, checksums), 15 s
        SUB->>MON: curl POST /hidden/agent-monitor/hooks/CLIENT?version=... body base64, headers X-User, X-Client-Id
        MON-->>SUB: JSON, success true expected
        SUB-->>G: stdout and exit code
        alt exit code not 0 or response lacks success=true
            G->>FS: delete newly created scripts
            G->>T: "Aborting install - test event failed"
            G-->>G: SystemExit(1) - goes to Phase 3 cleanup
        end
        G->>FS: backup existing config to FILE.backup, write JSON if content changed
        opt Copilot managed (policy.d)
            G->>FS: chmod - clear group / world write bits on config and scripts
        end
        opt discovery hook not installable
            G->>FS: delete stale discover script
        end
        G->>T: "hooks installed" summary - config, script, URL, masked push key
    end
    end

    rect rgba(120,90,200,0.15)
    Note over G,MON: Phase 3 - failure handling
    alt exception during Phase 2 and key was minted here
        alt no client finished
            G->>KEYS: revoke_push_key
            KEYS->>PLAT: DELETE /hidden/tenants/TENANT/mcp-scan/push-key (header x-client-id)
        else some clients finished
            G->>T: warning - key stays active, run uninstall
        end
        G-->>T: re-raise, exit code 1
    end
    end

    rect rgba(220,170,60,0.15)
    Note over G,MON: Phase 4 - report discovered MCP servers (first installed client only)
    G->>T: "Discovering MCP servers..."
    G->>PIPE: discover_clients_to_inspect(scope SERVERS) in a daemon thread, 60 s limit
    PIPE->>FS: config files, project roots, plugin dirs (shared flow B, servers only, no handshake)
    PIPE-->>G: clients_to_inspect
    G->>G: convert to ScanPathRequest JSON (same model as scan, redacted)
    opt hook client is claude-code
        G->>FS: glob Claude Desktop claude-code-sessions / local-agent-mode-sessions JSON, read connectors
    end
    G->>G: payload hooksConfiguredServerDiscovery + duration, push keys scrubbed
    G->>HEV: send_hook_event(url, client, push key, payload, machine id, max_retries=2)
    HEV->>MON: POST /hidden/agent-monitor/hooks/CLIENT (aiohttp, 15 s) body "base64:..."
    alt HTTP below 400
        G->>T: "Discovered N MCP servers -> OK"
    else error
        G->>T: yellow warning only (install still exits 0)
    end
    G-->>T: exit code 0
    end
```

## Files touched on the client machine

| Resource | Path (user scope) | Managed scope (`--managed`) | Access |
|----------|-------------------|-----------------------------|--------|
| Claude Code settings | `~/.claude/settings.json` | OS-specific `managed-settings.json` | read, backup, write |
| Cursor hooks | `~/.cursor/hooks.json` | OS-specific `hooks.json` | read, backup, write |
| Codex hooks | `~/.codex/hooks.json` | `/etc/codex/requirements.toml` (re-rendered from scratch) | read, backup, write |
| Copilot hooks | `~/.copilot/hooks/snyk-agent-guard.json` | `/etc/github-copilot/policy.d/snyk-agent-guard.json` | read, backup, write, chmod |
| Forwarder scripts | `<config dir>/hooks/snyk-agent-guard.{sh,ps1}`, `snyk-agent-guard-discover.{sh,ps1}` | same | write, chmod +x |
| Backups | `<config file>.backup` | same | copy |

## Observations

- `guard.py` (2100+ lines) holds argument handling, credential prompts, four different config file formats, script deployment, diffing and event delivery in one module; each client has its own `_prepare_*_config` / `_filter_*_hooks` / `_detect_*_install` triple.
- The install state is stored **in the hook command text** (push key, URL, tenant id as `KEY='value'` prefixes) and recovered by regex.
- Two transports to the same backend: the test event goes through the shell forwarder (`bash` + `curl`) in a subprocess, the discovery event through in-process `aiohttp`.
- The discovery event is sent for the **first installed client only**, even for `install all`, although the payload describes every agent on the machine.
- `--test` is accepted and ignored. `all` with `--managed` skips the "is the agent installed" check.
- Secrets handling: the push key appears in the hook command line (visible in the agent's config and in process environment of every hook run), and is masked in all console output.
