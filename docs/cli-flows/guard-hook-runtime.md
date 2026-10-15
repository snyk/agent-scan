# Guard hook runtime (supporting flow, not a CLI sub-command)

After `guard install`, every hook event of the agent runs `src/agent_scan/hooks/snyk-agent-guard.sh` (or `.ps1` on Windows). The Python CLI is **not** involved at this point; the script is a thin forwarder to Agent Monitor and the verdict logic lives entirely in the backend. It is documented here because it shares the wire contract with `guard install` (test event) and `guard discover`.

## Sequence diagram

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User and agent
    participant AG as Coding agent (Claude Code, Cursor, Codex, Copilot)
    end
    box rgba(80,140,220,0.18) Flow logic
    participant SH as snyk-agent-guard.sh
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant OS as OS / env / coreutils (cat, base64, uname, id)
    participant CURL as curl subprocess
    end
    box rgba(220,100,100,0.18) Backends
    participant MON as Agent Monitor
    end

    AG->>SH: hook event (PreToolUse, UserPromptSubmit, SessionStart, ...) - env PUSH_KEY, REMOTE_HOOKS_BASE_URL, MACHINE_ID, stdin = event JSON
    SH->>SH: parse --client, validate required env (usage error = exit 1)
    SH->>OS: cat stdin payload, base64 encode, "base64:" prefix
    SH->>OS: hostname, username (uname, id), env AI_AGENT / COPILOT_CLI (Copilot only)
    SH->>SH: build X-User JSON (hostname, username, identifier = MACHINE_ID, cli_version)
    SH->>CURL: POST $REMOTE_HOOKS_BASE_URL/hidden/agent-monitor/hooks/CLIENT?version=2025-11-11 (max 60 s)
    CURL->>MON: headers User-Agent, X-User, X-Client-Id (push key), X-Agent-Surface
    Note over MON: Evaluates policy, may hold PreToolUse up to ~25 s waiting for session discovery
    alt response received, HTTP below 400
        MON-->>CURL: verdict JSON
        CURL-->>SH: body + status
        SH-->>AG: stdout = verdict body, exit 0 (agent allows or blocks per verdict)
    else timeout, curl error, HTTP 400 or above
        SH-->>AG: fail open - exit 0, stderr message, systemMessage JSON on stdout for Claude Code and Codex only
    end
```

## Notes

- Fail-open is implemented in the shell script, per client output schema (Cursor and Copilot get an empty stdout).
- `guard install` verifies the same script by running it once with a `hooksConfigured` payload and requiring `"success": true` in the response body (the server answers HTTP 200 even for an invalid push key).
- `snyk-agent-guard.ps1` mirrors the bash logic for Windows; both carry an "install-time variables" section that `guard install` fills with the CLI version.
