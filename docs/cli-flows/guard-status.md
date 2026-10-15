# `guard` (no sub-command) - status

`snyk-agent-scan guard`. Shows whether Agent Guard hooks are installed for Claude Code, Cursor, Codex and GitHub Copilot, at user level and at managed (admin / MDM) level. Purely local and read-only.

Entry points: `cli.py:main` -> `guard.run_guard` -> `guard._run_status`.

## Sequence diagram

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User
    participant T as Terminal
    end
    box rgba(80,140,220,0.18) Flow logic
    participant CLI as cli.main
    participant G as guard.py (_run_status, _detect_*)
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant FS as Filesystem
    end

    T->>CLI: snyk-agent-scan guard
    CLI->>CLI: bootstrap (shared flow A), command = guard, guard_command = None
    CLI->>T: banner
    CLI->>G: run_guard(args)
    G->>G: guard_command is None -> _run_status()

    Note over G,FS: Module-level constants fix the paths at import time
    G->>T: "User-level hooks:"
    loop Claude Code, Cursor, Codex, GitHub Copilot
        G->>FS: exists(user-level hooks file of the agent)
        alt file exists
            G->>FS: read + json.load
            G->>G: for every known event, look for a command matching PUSH_KEY=...snyk-agent-guard (regex)
            G->>G: parse command text - REMOTE_HOOKS_BASE_URL, PUSH_KEY, TENANT_ID
            G->>T: INSTALLED  [host]  [Push Key: abcd...wxyz]  (events)
        else missing or no guard hooks
            G->>T: NOT INSTALLED
        end
    end

    G->>T: "Managed hooks:"
    loop same four clients, managed paths
        G->>FS: exists(OS-specific managed path)
        Note over G,FS: macOS /Library/Application Support/ClaudeCode/managed-settings.json, /etc/codex/requirements.toml, /etc/github-copilot/policy.d/snyk-agent-guard.json ... (Linux and Windows have their own)
        alt Codex requirements.toml
            G->>FS: read text, line-parse [[hooks.*]] tables with regex
        else JSON clients
            G->>FS: read + json.load
        end
        alt PermissionError
            G->>T: UNREADABLE (permission denied)
        else
            G->>T: INSTALLED or NOT INSTALLED
        end
    end

    G->>T: usage hints (interactive, managed, headless MDM flows)
    G-->>CLI: 0
    CLI-->>T: exit code 0
```

## Notes

- No backend is contacted. The push key is shown masked (first 4 / last 4 characters).
- Detection is text matching on the stored hook command (`_DETECTION_RE`), not a registry of installs. The installed command line therefore doubles as the persistence format for push key, URL and tenant id (also used later by [`guard uninstall`](guard-uninstall.md) to revoke the key).
- A malformed JSON file or a `PermissionError` on a **user-level** path is not handled in `_run_status`; it is caught by `run_guard`, which prints an error and returns exit code 1 for the whole command. Only managed paths get per-file `PermissionError` handling.
