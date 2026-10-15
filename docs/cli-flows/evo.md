# `evo`

`snyk-agent-scan evo [CONFIG_FILE ...]`. "Push scan results to Snyk Evo": mint a short-lived push key for a tenant, run a scan authenticated by that key, then revoke the key.

Entry points: `cli.py:main` -> `cli.evo` -> `run_scan(mode="scan")` -> `pipelines.inspect_analyze_push_pipeline`.

It reuses the `scan` argument parser (without `--ignore-risks`, `--ignore-failure-codes`, `--show-full-discovery`) and the whole scan pipeline; the only evo-specific logic is the push-key lifecycle around it.

## Sequence diagram

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User
    participant T as Terminal (stdin / stdout / stderr)
    end
    box rgba(80,140,220,0.18) Flow logic
    participant CLI as cli.py (evo, run_scan)
    participant KEYS as pushkeys.py
    participant PIPE as pipelines.py
    participant INSP as inspect + mcp_client + skill_client
    participant API as verify_api.py
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant FS as Filesystem / SQLite
    participant SUB as Subprocesses (codesign)
    participant OS as OS / env
    end
    box rgba(220,100,100,0.18) Backends
    participant PLAT as Snyk Platform API (push-key)
    participant MCP as Remote MCP servers
    participant SNYK as Snyk analysis API
    end

    rect rgba(150,150,150,0.15)
    Note over T,CLI: Phase 0 - bootstrap (shared flow A), command = evo
    T->>CLI: snyk-agent-scan evo [flags]
    CLI->>CLI: argparse, config file, banner, logging
    CLI->>CLI: evo() - drop any user supplied --push-key (stderr note)
    end

    rect rgba(120,90,200,0.15)
    Note over CLI,T: Phase 1 - credentials from the human
    CLI->>T: "Go to app.snyk.io, copy Tenant ID"
    T-->>CLI: stdin - tenant id
    CLI->>T: "Paste the Authorization token"
    T-->>CLI: stdin - API token (read with input(), echoed)
    end

    rect rgba(220,100,100,0.15)
    Note over CLI,PLAT: Phase 2 - mint push key
    CLI->>KEYS: mint_push_key(https://api.snyk.io, tenant, token)
    KEYS->>PLAT: POST /hidden/tenants/TENANT/mcp-scan/push-key?version=2025-08-28 (urllib, 15 s)
    alt success
        PLAT-->>KEYS: JSON with client_id
        KEYS-->>CLI: client_id
        CLI->>T: "Client ID created"
    else RuntimeError
        KEYS-->>CLI: HTTP / network error text
        CLI->>T: red error
        CLI-->>T: return -> exit code 0
    end
    end

    rect rgba(80,140,220,0.15)
    Note over CLI,PIPE: Phase 3 - scan authenticated by the key
    CLI->>CLI: args.control_servers = [ControlServer(push url, hostname, x-client-id header)]
    CLI->>PIPE: run_scan(args, "scan")
    Note over CLI: command is evo, so decide_handshake gives do_stdio_handshake=false, collect_consent=false (unless --dangerously-run-mcp-servers)
    PIPE->>OS: home directories
    PIPE->>FS: discovery - config files, skills dirs, project roots, opencode SQLite (shared flow B)
    PIPE->>SUB: codesign for stdio binaries (macOS)
    loop each server
        alt stdio server
            PIPE->>INSP: recorded from config only, process is NOT started
        else remote server
            INSP->>MCP: initialize + list tools / prompts / resources (no consent prompt)
        end
    end
    INSP->>FS: read + redact skill files
    PIPE->>API: analyze_machine(push_key, show_analysis_results=true because command is evo)
    API->>SNYK: POST ScanRequest with X-Push-Key and X-Push: skip (synchronous endpoint)
    SNYK-->>API: ScanResponse
    API-->>CLI: ScanResponse
    Note over CLI: return value of run_scan is discarded - nothing is printed or written
    end

    rect rgba(220,100,100,0.15)
    Note over CLI,PLAT: Phase 4 - revoke push key
    CLI->>KEYS: revoke_push_key(base, tenant, token, client_id)
    KEYS->>PLAT: DELETE /hidden/tenants/TENANT/mcp-scan/push-key (header x-client-id)
    alt 200 / 204
        CLI->>T: "Client ID revoked"
    else RuntimeError
        CLI->>T: red "Error revoking client_id"
    end
    CLI-->>T: exit code 0
    end
```

## Observations

- **No results are rendered.** `evo()` awaits `run_scan` and ignores the response; `print_scan_response` is never called. `_should_show_analysis_results` forces synchronous analysis for evo, yet the response is thrown away, so the only visible output is "Client ID created / revoked". The visible effect is the server-side push triggered by the key.
- **No `try/finally` around the scan.** If discovery, inspection or analysis raises, the minted key is not revoked.
- **Exit code is always 0**, including when minting fails.
- Base URL (`https://api.snyk.io`) and the push URL are hard-coded in `cli.evo`; `--analysis-url` is still honoured for the analysis call, so the two can point at different environments.
- `push_scan_url` is stored as a control server URL but never requested by the client (only its `x-client-id` header is used) - same caveat as in [`scan`](scan.md).
- Tenant id and API token are read with plain `input()`, so the token is echoed. `guard install` has the same pattern.
- Compared to `scan`: stdio servers are not started (any non-scan/inspect command defaults to no handshake), no consent prompts, and `--ignore-*` options are not registered. `--ci` is still accepted (it comes from the common arguments and forces `--dangerously-run-mcp-servers`), but no CI evaluation happens because `print_scan_inspect` is bypassed.
