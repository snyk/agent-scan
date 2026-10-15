# `guard uninstall`

`snyk-agent-scan guard uninstall {claude|cursor|codex|github-copilot|all} [--file PATH] [--managed]`

Removes Agent Guard hooks from the selected agent config(s), deletes the forwarder scripts and, when it can, revokes the push key that was stored in the hook command.

Entry points: `cli.py:main` -> `guard.run_guard` -> `guard._run_uninstall` -> `guard._uninstall_single_client` (per client).

## Sequence diagram

```mermaid
sequenceDiagram
    autonumber
    box rgba(150,150,150,0.2) User
    participant T as Terminal
    end
    box rgba(80,140,220,0.18) Flow logic
    participant G as guard.py (_run_uninstall, _uninstall_*)
    participant KEYS as pushkeys.py
    end
    box rgba(60,170,110,0.18) Client machine resources
    participant OS as OS / env
    participant FS as Filesystem
    end
    box rgba(220,100,100,0.18) Backends
    participant PLAT as Snyk Platform API
    end

    T->>G: guard uninstall CLIENT [--file] [--managed] (via shared flow A, run_guard)
    alt client is all and --file given
        G->>T: error, exit 1
    end

    loop each selected client
        G->>T: "Removing Agent Guard user|managed hooks from X"
        G->>G: resolve config path (override, managed table, or user default)

        rect rgba(150,150,150,0.15)
        Note over G,FS: Read current state
        G->>FS: exists(config), read + parse (JSON, or requirements.toml)
        G->>G: detect guard command by regex, extract push key, URL, tenant id from the command text
        end

        rect rgba(220,170,60,0.15)
        Note over G,FS: Remove hooks
        alt Codex managed requirements.toml
            alt file missing
                G->>T: "Nothing to uninstall"
            else guard hooks found
                G->>FS: copy to FILE.backup
                G->>FS: delete requirements.toml (whole file, not only guard entries)
            end
        else JSON config
            alt file missing
                G->>T: "No file found. Nothing to uninstall."
            else
                G->>G: filter out guard entries per client shape (grouped / flat / Copilot keys bash, powershell, command)
                alt nothing removed
                    G->>T: "No Agent Guard hooks found"
                else
                    G->>FS: copy to FILE.backup
                    G->>FS: write JSON back (drop empty hooks key except Cursor)
                    G->>T: "Removed N hook(s) (M other preserved)"
                end
            end
        end
        G->>FS: delete snyk-agent-guard.* and snyk-agent-guard-discover.* script if present
        end

        rect rgba(220,100,100,0.15)
        Note over G,PLAT: Revoke key
        opt a push key was found in the old hook command
            G->>OS: env SNYK_TOKEN
            alt tenant id recovered and SNYK_TOKEN set
                G->>KEYS: revoke_push_key(url, tenant, token, push key)
                KEYS->>PLAT: DELETE /hidden/tenants/TENANT/mcp-scan/push-key (header x-client-id)
                alt 200 / 204
                    G->>T: "Push key revoked"
                else error
                    G->>T: warning, uninstall continues
                end
            else
                G->>T: "Push key was not revoked (set SNYK_TOKEN to revoke on uninstall)"
            end
        end
        end
    end
    G-->>T: exit code 0 (1 on invalid JSON or permission error)
```

## Notes

- Uninstall is the inverse of the install, but it is **not** symmetrical in what it needs: it recovers the push key / tenant id by parsing the previously written hook command, so a config edited by hand can lose the ability to revoke.
- The Codex managed variant deletes the whole `requirements.toml` (backup first), while install re-renders the whole file; any non-Agent-Guard content in that file is not preserved in either direction.
- With `--managed` the revoke step still depends on the *current user's* `SNYK_TOKEN`; headless MDM uninstalls without a token leave the key active.
- `PermissionError` while reading a managed path aborts the run with exit code 1 (no per-client recovery, unlike `guard` status).
