# Shared sub-flows

Building blocks reused by several commands. The per-command files link here instead of repeating them.

| ID | Sub-flow | Used by |
|----|----------|---------|
| A | [CLI bootstrap](#a-cli-bootstrap) | every command |
| B | [Discovery](#b-discovery-discover_clients_to_inspect) | `scan`, `inspect`, `evo`, `guard install`, `guard discover` |
| C | [Inspection](#c-inspection-inspect_client) | `scan`, `inspect`, `evo` |
| D | [Analysis request](#d-analysis-request-analyze_machine) | `scan`, `evo` |

Layer legend (same in every diagram):

- **User** – the terminal (stdin / stdout / stderr).
- **Flow logic** – Python modules inside `agent_scan`.
- **Client machine resources** – filesystem, OS/env, SQLite, local subprocesses.
- **Backends** – remote MCP servers and Snyk services.

---

## A. CLI bootstrap

Source: `run.py`, `cli.py:main` (lines 830-1087).

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User
    participant T as Terminal
    end
    box rgba(80,140,220,0.18) Flow logic
    participant RUN as run.py
    participant CLI as cli.main
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant OS as OS / env / process table
    participant FS as Filesystem
    end

    T->>RUN: snyk-agent-scan [args]
    RUN->>CLI: main() evaluated before asyncio.run starts
    CLI->>OS: Windows only - reconfigure stdout/stderr to UTF-8
    CLI->>OS: psutil parent process cmdline (used as argparse prog name)
    CLI->>CLI: build argparse tree (scan, inspect, help, evo, guard + sub-commands)
    alt argv[1] is not a known sub-command
        CLI->>CLI: sys.argv.insert(1, "scan")  (default command)
    end
    CLI->>CLI: parse_control_servers(sys.argv) - hand-rolled block parser
    alt control server without --control-identifier
        CLI->>T: error on stdout
        CLI-->>RUN: sys.exit(1)
    end
    CLI->>CLI: parser.parse_args()
    opt --config-file given
        CLI->>FS: open + yaml.safe_load(config file)
        CLI->>CLI: merge  defaults < YAML < explicit CLI flags
        Note over CLI: bad YAML, unknown type, bad choice -> sys.exit(2)
    end
    CLI->>T: deprecation warnings on stderr (--control-server-H x-client-id, --control-identifier)
    CLI->>CLI: resolve_server_io_default  (suppress MCP stderr = not interactive)
    CLI->>CLI: enforce_consent_requirements  (--ci needs --dangerously-run-mcp-servers, else exit 2)
    opt not --json
        CLI->>T: banner "Snyk Agent Scan vX"
    end
    CLI->>CLI: setup_logging (--verbose -> RichHandler on stderr)
    CLI->>CLI: dispatch on args.command
    Note over CLI: help -> print_help, scan/None -> print_scan_inspect, inspect -> print_scan_inspect(mode=inspect), evo -> evo(), guard -> run_guard()
    CLI-->>RUN: sys.exit(code)
```

Observations
- `run.py` calls `asyncio.run(main())` but `main()` is a plain function that always ends in `sys.exit(...)`. It works only because `SystemExit` escapes before `asyncio.run` receives the return value.
- `except (SnykTokenError, MissingIdentifierError)` in `run.py` partly duplicates the handling inside `main()`.

---

## B. Discovery (`discover_clients_to_inspect`)

Source: `pipelines.py:61-162`, `inspect.py:78-221`, `agents/*`, `well_known_clients.py`, `utils.py:277`.
No MCP server is started here, the output is a list of `ClientToInspect` (config files parsed, skills directories listed).

```mermaid
sequenceDiagram
    autonumber
    box rgba(80,140,220,0.18) Flow logic
    participant PIPE as pipelines.py
    participant LEG as Phase A - legacy tables<br/>(well_known_clients + inspect.py)
    participant ABC as Phase B - AgentDiscoverer<br/>(agents/*)
    participant SIG as signed_binary.py
    participant SKL as skill_client.py
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant OS as OS (pwd, env, powershell, wsl)
    participant FS as Filesystem
    participant SQL as SQLite (opencode DB)
    participant SUB as Subprocess (codesign)
    end

    rect rgba(150,150,150,0.15)
    Note over PIPE,OS: 1. Which home directories to look at
    alt default (current user)
        PIPE->>OS: Path.home(), getpass.getuser()
    else --scan-all-users on Linux/macOS
        PIPE->>OS: pwd.getpwall(), keep uid >= 500/1000
        PIPE->>FS: os.access(home, R_OK|X_OK)
    else --scan-all-users on Windows
        PIPE->>SUB: powershell Get-CimInstance Win32_UserProfile (10 s cap)
        PIPE->>SUB: wsl.exe --list --quiet
        PIPE->>FS: list \\wsl.localhost\distro\home\* and access check
    end
    end

    alt explicit CONFIG_FILE arguments
        rect rgba(150,150,150,0.15)
        Note over PIPE,FS: 2a. Explicit paths
        loop each path
            alt direct-scan spec (npm:, pypi:, oci:, sse:, streamable-http(s):)
                PIPE->>PIPE: synthesize StdioServer (npx / uvx / docker run) or RemoteServer, no FS access
            else skills enabled and path is a directory
                PIPE->>FS: exists(SKILL.md)?
                PIPE->>LEG: directory with SKILL.md = single skill, else treat as skills dir
            else skills enabled and basename is SKILL.md
                PIPE->>PIPE: parent folder = skill, grandparent = client path
            else treat as MCP config file
                PIPE->>LEG: get_mcp_config_per_client(CandidateClient(path))
            end
            alt nothing resolved
                PIPE->>PIPE: InspectedPath(error=file_not_found, is_failure=false)
            end
        end
        end
    else automatic discovery
        rect rgba(150,150,150,0.15)
        Note over PIPE,FS: 2b-0. Optional target folders (only set by guard discover)
        PIPE->>FS: Path.resolve(), exists() - dedupe, skip missing or unreadable
        end

        rect rgba(220,170,60,0.15)
        Note over PIPE,SUB: 2b-1. Phase A - legacy static tables, every well-known client
        loop each CandidateClient for the current OS, each home directory
            LEG->>FS: stat client_exists_paths (for example ~/.cursor)
            alt client not present
                LEG-->>PIPE: nothing (logged at info level)
            else client present
                LEG->>FS: expand mcp_config_globs, depth-limited glob (for example ~/.claude/plugins/cache/**/.mcp.json)
                loop each mcp config path
                    LEG->>FS: exists(), open(), read utf-8
                    LEG->>LEG: pyjson5.loads, then try pydantic models in order<br/>ClaudeCode, Claude, VSCode, VSCodeMCP, Plugin, OpenCode(opt), Unknown, WithoutMCP
                    opt macOS and server is stdio
                        LEG->>SIG: check_server_signature(server)
                        SIG->>OS: shutil.which, realpath
                        SIG->>SUB: codesign --verify --strict, then codesign -dvvv
                        Note over SIG: skipped for code launchers (python, node, npx, uv, docker ...)
                    end
                end
                LEG->>FS: glob skills_dir_globs, isdir, listdir each skills dir
                LEG->>SKL: inspect_skills_dir(path) - keep sub-dirs holding SKILL.md
            end
        end
        end

        rect rgba(120,90,200,0.15)
        Note over PIPE,SQL: 2b-2. Phase B - per-agent discoverers (10 classes), sequential after phase A
        loop each home directory
            PIPE->>ABC: find_discoverers(home, target_folders)
            ABC->>FS: client_exists() per discoverer (stat install dirs)
            loop each installed discoverer
                PIPE->>ABC: discover(scope SERVERS / SKILLS / ALL)
                Note over ABC: each half isolated by try/except
                ABC->>FS: read global config (for example ~/.claude.json, settings.json, mcp.json) with size cap
                alt Claude Code
                    ABC->>FS: projects map inside ~/.claude.json = opened project roots
                else VS Code family (Cursor, Windsurf, Kiro, Antigravity)
                    ABC->>FS: walk User/workspaceStorage/*/workspace.json and .code-workspace files
                else OpenCode
                    ABC->>FS: glob opencode*.db in data dirs, is_file()
                    ABC->>SQL: SELECT worktree FROM project (mode=ro, fallback immutable=1)
                end
                ABC->>FS: for every project root AND each ancestor - stat/read .mcp.json, .vscode/mcp.json, skills dirs
                ABC->>FS: walk plugin / extension directories (depth-limited), read manifests and MCP files
                ABC->>SIG: check_server_signature for stdio servers (codesign on macOS)
                ABC->>SKL: inspect_skills_dir / inspect_commands_dir (os.listdir, os.walk)
                ABC-->>PIPE: ClientToInspect(name, client_path, mcp_configs, skills_dirs)
                PIPE->>PIPE: merge with phase A result by (client name, username)<br/>dict union, phase B wins on identical keys
            end
        end
        end
    end

    PIPE->>PIPE: scanned_usernames = users with a detected agent,<br/>else all readable (if --scan-all-users) else current user
    PIPE-->>PIPE: return (clients_to_inspect, unresolved_paths, scanned_usernames)
```

Observations
- Two parallel discovery mechanisms (static tables in `well_known_clients.py` plus the `AgentDiscoverer` classes) run for the same agents and are merged afterwards. Claude Code, VS Code, Cursor, etc. are therefore discovered twice and `check_server_signature` (a `codesign` subprocess) can run twice for the same server.
- Discovery is where almost all client-machine I/O happens. SQLite is used in exactly one place (OpenCode project list).
- `get_hostname()` / `get_username()` exist in both `utils.py` and `verify_api.py`.

---

## C. Inspection (`inspect_client`)

Source: `pipelines.py:165-203`, `inspect.py:234-486`, `mcp_client.py`, `skill_client.py`, `redact.py`.
Runs strictly sequentially: client by client, server by server.

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User
    participant T as Terminal (stderr)
    end
    box rgba(80,140,220,0.18) Flow logic
    participant PIPE as pipelines.inspect_pipeline
    participant INSP as inspect.py
    participant MCPC as mcp_client.py
    participant SKL as skill_client.py
    participant RED as redact.py
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant OS as OS (PATH, DNS)
    participant FS as Filesystem
    participant SUB as Stdio MCP server process
    end
    box rgba(220,100,100,0.18) Backends
    participant MCP as Remote MCP server
    end

    loop each ClientToInspect
        PIPE->>INSP: inspect_client(client, timeout, tokens, scan_skills, stream_stderr, declined, do_stdio_handshake)
        loop each mcp config entry
            alt entry is FileNotFound / UnknownFormat / CouldNotParse
                INSP->>INSP: collect as path-level ScanError
            else list of servers
                loop each (name, server) - sequential
                    alt (config_path, name) in declined set
                        INSP->>INSP: InspectedServer(error=UserDeclinedError) - server never contacted
                    else stdio server and do_stdio_handshake is false
                        INSP->>INSP: InspectedServer(config only, no signature)
                    else stdio server
                        INSP->>MCPC: check_server(config, timeout)
                        MCPC->>OS: resolve_command_and_args (exists, shutil.which, nvm / brew / ~/.local/bin fallbacks)
                        MCPC->>SUB: spawn process with args, env, cwd and stderr pipe
                        MCPC->>SUB: JSON-RPC initialize
                        MCPC->>SUB: prompts/list, resources/list, resources/templates/list, tools/list
                        SUB-->>MCPC: responses (whole exchange wrapped in wait_for(timeout))
                        opt stream_stderr
                            SUB-->>T: stderr lines prefixed with [server-name]
                        end
                        MCPC->>SUB: close streams, terminate process
                        MCPC-->>INSP: ServerSignature (metadata, prompts, resources, templates, tools)
                    else remote server
                        loop up to 6 (transport, url) candidates - http or sse x /mcp, as is, /sse
                            MCPC->>OS: getaddrinfo(host), reject link-local and cloud-metadata IPs
                            MCPC->>MCP: HTTPS initialize (no redirects, headers from config, optional OAuth token from file)
                            MCP-->>MCPC: capabilities
                            MCPC->>MCP: prompts/list, resources/list, tools/list (only if capability announced)
                            MCP-->>MCPC: lists
                        end
                        Note over MCPC: first candidate that works wins, original url/type restored on total failure
                    end
                    alt any exception
                        INSP->>INSP: InspectedServer(error=ServerStartupError / ServerHTTPError + captured traffic log)
                    end
                end
            end
        end
        opt scan_skills
            loop each skills dir / DiscoveredSkill
                INSP->>SKL: collect_skill_files(skill path)
                SKL->>FS: os.scandir walk (sorted, follows links, detects symlink cycles, rejects non-regular files)
                SKL->>FS: open + read each file
                SKL->>RED: redact_text(content) via detect-secrets
                Note over SKL: non-UTF-8 asset -> sha256 marker "Binary file. Hash: ..."
                INSP->>SKL: resolve_skill_name (read SKILL.md, parse YAML frontmatter name/description)
            end
        end
        INSP-->>PIPE: InspectedPath(client, path, servers, skills, joined error)
    end
    PIPE->>RED: redact_inspected_path for every result
    Note over RED: env values, header values, URL query values, secrets in args, traceback and server_output
    PIPE-->>PIPE: (inspected_paths, scanned_usernames)
```

Observations
- No concurrency: a machine with N slow servers costs up to N x `--server-timeout` (and up to 6 x timeout per remote server).
- Redaction happens twice: locally in `inspect_pipeline`, then again on a deep copy when the API request is built (`models/api/v20260710.py`).
- Skill file content is redacted at read time (`skill_client`), config redaction happens later (`redact_inspected_path`) - two different places for the same concern.

---

## D. Analysis request (`analyze_machine`)

Source: `verify_api.py:434-607`.

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User
    participant T as Terminal (stderr)
    end
    box rgba(80,140,220,0.18) Flow logic
    participant PIPE as pipelines.py
    participant API as verify_api.py
    participant MOD as models/api/v20260710
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant OS as OS / env
    participant FS as Filesystem (CA bundles)
    end
    box rgba(220,100,100,0.18) Backends
    participant CFG as Snyk Agent Scan config endpoint
    participant ASYNC as Snyk async analysis endpoint
    participant SYNC as Snyk analysis-machine endpoint
    end

    PIPE->>API: analyze_machine(inspected_paths, analysis_url, identifier, push_key, skip_pushing, show_analysis_results ...)
    API->>API: force ?version=2026-07-10 on analysis_url
    API->>OS: hostname (uname), username (getpass) or scanned_usernames
    API->>MOD: ScanRequest.from_inspected_paths (second redaction pass on deep copies)
    API->>API: path = home-relative (~/...), client name from well-known table
    API->>OS: read env SNYK_TOKEN, SNYK_CLI_USE, AGENT_SCAN_ENVIRONMENT

    alt push key present (MDM / evo)
        API->>API: header X-Push-Key
        opt not --show-analysis-results
            API->>FS: build TLS context - certifi + SSL_CERT_FILE / REQUESTS_CA_BUNDLE / NODE_EXTRA_CA_CERTS
            API->>CFG: GET /hidden/agent-scan/config  (5 s, up to 2 tries)
            CFG-->>API: async_analysis_enabled true or false
            opt async enabled
                API->>ASYNC: POST gzip(ScanRequest) (75 s, up to 3 tries, 5xx/transport retried)
                ASYNC-->>API: 202 Accepted
                API->>T: yellow warning "results processed on Snyk side"
                API-->>PIPE: ScanResponse built locally from the request (no risks)
            end
        end
    else SNYK_TOKEN set
        API->>API: url path -> /hidden/mcp-scan/cli/analysis-machine, Authorization token
    else SNYK_CLI_USE=true
        API->>API: url path -> /hidden/mcp-scan/cli/analysis-machine, auth done by Snyk CLI proxy
    else nothing set
        API->>T: red hint "set SNYK_TOKEN"
        API-->>PIPE: raise SnykTokenError (run.py exits 1)
    end

    opt control servers or push key present
        API->>API: header X-Push: skip
    end
    loop attempt 1..3 (backoff 1 s, 2 s)
        API->>FS: build TLS context (see above)
        API->>SYNC: POST ScanRequest JSON (180 s)
        alt 200
            SYNC-->>API: ScanResponse (risk scores per server and skill)
            API-->>PIPE: ScanResponse
        else TimeoutError
            API->>API: retry
        else HTTP error (401, 413, 429, other 4xx, 5xx)
            API-->>PIPE: analysis_error response for every path, no retry
        else other exception
            API-->>PIPE: re-raise
        end
    end
    API-->>PIPE: after 3 timeouts, analysis_error response for every path
```

Observations
- Auth mode is decided by string-rewriting the URL path (`/hidden/mcp-scan/analysis-machine` to `/cli/analysis-machine`, `.../config`, `.../async/analysis`) - routing logic lives inside the HTTP client function.
- Retry policy is inconsistent: the synchronous call retries only `TimeoutError`; 5xx and plain connection errors are not retried, while the async submit and config check retry 5xx and connection errors.
- The deprecated `--control-server` URL is never called by the client. `bool(control_servers)` only sets `X-Push: skip`, and the `x-client-id` header is read as the push key.
