# `inspect`

`snyk-agent-scan inspect [CONFIG_FILE ...]`. Prints the tools, prompts, resources and skill files found on the machine **without** calling the Snyk analysis backend.

Entry points: `cli.py:main` -> `print_scan_inspect(mode="inspect")` -> `run_scan(mode="inspect")` -> `pipelines.inspect_pipeline`.

Difference to [`scan`](scan.md): same bootstrap, discovery, consent and inspection; the analysis step (shared flow D) is skipped, nothing leaves the machine except the traffic to the MCP servers themselves, and the output is the raw `InspectedPath` list.

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
    end

    rect rgba(150,150,150,0.15)
    Note over T,CLI: Phase 0 - bootstrap (shared flow A)
    T->>CLI: snyk-agent-scan inspect [flags] [files]
    CLI->>FS: optional --config-file YAML
    CLI->>CLI: argparse, resolve flags, banner (unless --json), logging
    end

    rect rgba(150,150,150,0.15)
    Note over CLI,FS: Phase 1 - input preparation
    CLI->>CLI: --ignore-failure-codes accepted only with --ci
    opt --json
        CLI->>CLI: stdout redirected while the pipeline runs
    end
    opt --mcp-oauth-tokens-path
        CLI->>FS: read + validate OAuth token file
    end
    CLI->>CLI: decide_handshake -> always do_stdio_handshake=true, collect_consent = not --dangerously-run-mcp-servers
    Note over CLI: inspect is always treated as interactive, even when a push key is configured
    end

    rect rgba(220,170,60,0.15)
    Note over CLI,SUB: Phase 2 - discovery (shared flow B)
    CLI->>PIPE: discover_clients_to_inspect
    PIPE->>OS: home directories
    PIPE->>FS: client dirs, MCP configs, skills dirs, project roots
    PIPE->>SQL: opencode project table
    PIPE->>SUB: codesign for stdio binaries (macOS)
    PIPE-->>CLI: clients_to_inspect, unresolved_paths, usernames
    end

    rect rgba(120,90,200,0.15)
    Note over CLI,T: Phase 3 - consent
    alt not --dangerously-run-mcp-servers
        CLI->>CONS: collect_consent(clients_to_inspect)
        CONS->>T: stderr - plan, then one [y/N] prompt per server
        T-->>CONS: answers on stdin
        CONS-->>CLI: declined set
    else
        CLI->>T: red warning banner
    end
    end

    rect rgba(60,170,110,0.15)
    Note over CLI,MCP: Phase 4 - inspection (shared flow C)
    CLI->>PIPE: inspect_pipeline(inspect_args, clients, declined, do_stdio_handshake=true)
    loop each client, each server
        alt declined
            PIPE->>INSP: UserDeclinedError result
        else stdio
            INSP->>SUB: spawn, initialize, list prompts / resources / tools, terminate
            SUB-->>T: stderr stream with [server] prefix (default for interactive)
        else remote
            INSP->>OS: DNS guard
            INSP->>MCP: initialize + list calls
        end
    end
    opt skills (default on)
        INSP->>FS: walk skill dirs, read files
        INSP->>RED: redact_text
    end
    PIPE->>RED: redact_inspected_path
    PIPE-->>CLI: list of InspectedPath
    end

    rect rgba(150,150,150,0.15)
    Note over CLI,T: Phase 5 - presentation
    alt --json
        CLI->>T: stdout - JSON keyed by client path
    else
        CLI->>PRN: print_inspected_machine(paths, print_errors, full_description)
        PRN->>T: rich tree of servers, entities, skills
    end
    opt --ci
        CLI->>CLI: failure codes minus --ignore-failure-codes
        CLI-->>T: exit code 1 if any runtime failure remains
    end
    CLI-->>T: exit code 0
    end
```

## What is *not* in this flow

- No call to `verify_api.analyze_machine`: no `SNYK_TOKEN`, push key, hostname / username collection, or request payload is built.
- No second redaction pass (only `redact_inspected_path` plus skill-file redaction), so what is printed is exactly what `scan` would have sent for the same servers, after local redaction.
- Risk scoring and the `--ignore-risks` option do not exist here (`--ci` can only fail on runtime failures).

## Notes

- `inspect` registers `add_control_server_arguments` (`--control-server`, `--push-key`, `--machine-id`), but none of them has an effect in this mode.
- The consent and handshake logic is the same shared code as `scan`, so any change to server contact rules affects both.
