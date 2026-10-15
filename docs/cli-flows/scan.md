# `scan` (default command)

`snyk-agent-scan [scan] [CONFIG_FILE ...]`. Running the binary without a sub-command is rewritten to `scan` (see [A. CLI bootstrap](shared-subflows.md#a-cli-bootstrap)).

Entry points: `cli.py:main` -> `print_scan_inspect(mode="scan")` -> `run_scan` -> `pipelines.inspect_analyze_push_pipeline`.

What it does: discover MCP configs and skills on the machine, optionally start / contact each MCP server to read its tool catalog, redact secrets, send everything to the Snyk analysis API and render the returned risk scores.

## Sequence diagram

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User
    participant T as Terminal (stdin / stdout / stderr)
    end
    box rgba(80,140,220,0.18) Flow logic
    participant CLI as cli.py (print_scan_inspect, run_scan)
    participant PIPE as pipelines.py
    participant CONS as consent.py
    participant INSP as inspect.py + mcp_client + skill_client
    participant RED as redact.py
    participant API as verify_api.py
    participant PRN as printer.py
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant FS as Filesystem
    participant SQL as SQLite (opencode DB)
    participant SUB as Subprocesses (stdio MCP servers, codesign)
    participant OS as OS / env
    end
    box rgba(220,100,100,0.18) Backends
    participant MCP as Remote MCP servers
    participant SNYK as Snyk analysis API
    end

    rect rgba(150,150,150,0.15)
    Note over T,CLI: Phase 0 - bootstrap (shared flow A)
    T->>CLI: snyk-agent-scan [flags] [files]
    CLI->>FS: optional --config-file YAML
    CLI->>OS: psutil parent cmdline, env
    CLI->>CLI: argparse, default "scan", resolve flags, enforce --ci rules
    CLI->>T: banner (unless --json)
    end

    rect rgba(150,150,150,0.15)
    Note over CLI,FS: Phase 1 - input preparation
    CLI->>CLI: _parse_ignore_risks / _parse_ignore_failure_codes (only valid with --ci, else exit 2)
    opt --json
        CLI->>CLI: redirect stdout to /dev/null while scanning
    end
    opt --mcp-oauth-tokens-path
        CLI->>FS: read token file
        CLI->>CLI: validate as TokenAndClientInfoList (pydantic)
    end
    CLI->>CLI: build InspectArgs (timeout, tokens, paths, all_users, scan_skills, scope)
    CLI->>CLI: decide_handshake(args) -> (do_stdio_handshake, collect_consent)
    end

    rect rgba(220,170,60,0.15)
    Note over CLI,SUB: Phase 2 - discovery, no server is started (shared flow B)
    CLI->>PIPE: discover_clients_to_inspect(inspect_args)
    PIPE->>OS: home directories (current user, or pwd / powershell / wsl.exe for --scan-all-users)
    PIPE->>FS: stat client dirs, glob configs, read + parse MCP config files, list skills dirs
    PIPE->>FS: project roots from ~/.claude.json, workspaceStorage/*/workspace.json
    PIPE->>SQL: opencode project table (SELECT worktree FROM project)
    PIPE->>SUB: codesign verify for stdio binaries (macOS)
    PIPE-->>CLI: clients_to_inspect, unresolved_paths, scanned_usernames
    end

    rect rgba(120,90,200,0.15)
    Note over CLI,T: Phase 3 - consent (decision)
    alt decision.collect_consent (attended scan, no push key, no dangerous flag)
        CLI->>CONS: collect_consent(clients_to_inspect)
        CONS->>T: stderr - list stdio commands (env masked) and remote URLs (query masked)
        loop each server
            CONS->>T: "Allow Agent Scan to start / connect to X? [y/N]"
            T-->>CONS: stdin line (anything but y / yes = decline, EOF = decline)
        end
        CONS-->>CLI: declined set of (config_path, server_name)
    else --dangerously-run-mcp-servers and interactive
        CLI->>T: red warning banner
    else unattended (push key) or CI
        Note over CLI: silent, no prompts
    end
    end

    rect rgba(60,170,110,0.15)
    Note over CLI,MCP: Phase 4 - inspection (shared flow C)
    CLI->>PIPE: inspect_analyze_push_pipeline(inspect_args, analyze_args, push_args, clients, declined, do_stdio_handshake)
    loop each client, each server (sequential)
        alt declined
            PIPE->>INSP: result = UserDeclinedError, server not contacted
        else stdio and handshake disabled (push-key scan, evo)
            PIPE->>INSP: config recorded only
        else stdio
            INSP->>SUB: spawn, initialize, list prompts / resources / tools, terminate
            SUB-->>T: server stderr (prefixed) unless suppressed
        else remote
            INSP->>OS: DNS check against blocked ranges
            INSP->>MCP: initialize + list calls (up to 6 transport/URL candidates)
        end
    end
    opt skills enabled (default)
        INSP->>FS: walk every skill directory, read files
        INSP->>RED: redact_text for each file (detect-secrets)
    end
    PIPE->>RED: redact_inspected_path (env, headers, URL query, args, tracebacks)
    end

    rect rgba(220,100,100,0.15)
    Note over API,SNYK: Phase 5 - analysis (shared flow D)
    PIPE->>API: analyze_machine(inspected_paths, url, identifier, push_key ...)
    API->>API: build ScanRequest (second redaction, home-relative paths, hostname, usernames)
    alt push key and async analysis enabled for tenant and no --show-analysis-results
        API->>SNYK: GET config, then POST gzip payload to async endpoint
        SNYK-->>API: 202
        API->>T: warning - results not shown locally
        API-->>CLI: ScanResponse without risks
    else SNYK_TOKEN or SNYK_CLI_USE
        API->>SNYK: POST payload (180 s, 3 attempts for timeouts)
        SNYK-->>API: ScanResponse with risk indexes per server / skill
        API-->>CLI: ScanResponse
    else no credentials
        API->>T: hint to set SNYK_TOKEN
        API-->>CLI: SnykTokenError -> run.py exit code 1
    end
    end

    rect rgba(150,150,150,0.15)
    Note over CLI,T: Phase 6 - presentation and exit code (decisions)
    opt --ignore-risks
        CLI->>CLI: null out the ignored risk fields in the response
    end
    alt --json
        CLI->>T: stdout - ScanResponse JSON (exclude_none)
    else
        CLI->>PRN: print_scan_response(response, print_errors, show_full_discovery)
        PRN->>T: rich tree per path, servers, skills, risk scores
    end
    opt --ci
        CLI->>CLI: has_risks or failure codes (minus ignored)?
        CLI-->>T: stderr reason, exit code 1
    end
    CLI-->>T: exit code 0
    end
```

## Decision table: `decide_handshake`

| Situation | Start stdio servers | Ask consent |
|-----------|--------------------|-------------|
| `--dangerously-run-mcp-servers` | yes | no |
| no push key (attended) | yes | yes |
| push key (MDM / unattended) | no (remote servers are still contacted, without a prompt) | no |
| `--ci` | requires `--dangerously-run-mcp-servers` | no |

## Where the work happens

| Concern | Layer | Code |
|---------|-------|------|
| Flag merge, default command, CI rules, exit codes | Flow logic | `cli.py` |
| Home dirs, config files, skills, project roots, SQLite, `codesign` | Client machine | `pipelines.py`, `inspect.py`, `agents/*`, `skill_client.py`, `signed_binary.py`, `utils.py` |
| Consent, server start-or-skip decision, error normalization | Flow logic | `cli.decide_handshake`, `consent.py`, `inspect._inspect_server` |
| Talking to MCP servers (stdio / HTTP / SSE) | Client machine + remote MCP | `mcp_client.py`, `traffic_capture.py` |
| Secret redaction | Flow logic | `redact.py` (applied at skill read, after inspection, and again at request build) |
| Risk scoring | Backend | Snyk analysis API (no scoring logic on the client) |
| Rendering and CI verdict | Flow logic | `printer.py`, `cli._handle_ci_exit` |

## Exit codes

- `0` normal completion (even if risks are found, unless `--ci`).
- `1` `--ci` with risks or failure codes, missing `SNYK_TOKEN`, missing control identifier.
- `2` usage errors (`--ci` without `--dangerously-run-mcp-servers`, `--ignore-*` without `--ci`, bad config file).

## Notes specific to `scan`

- `--storage-file`, `--checks-per-server` and `--no-bootstrap` are parsed but unused in code.
- The `--control-server` block is parsed, but the client never contacts that URL: its `x-client-id` header becomes the push key, and the presence of any control server sets `X-Push: skip` on the analysis call.
- `suppress_mcpserver_io` is resolved twice (`main()` and `run_scan()`).
