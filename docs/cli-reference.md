# Agent Scan CLI reference

This reference covers both the `2025-09-02` API used by Agent Scan v0.5.x and the risk-based `2026-07-10` API used by Agent Scan v0.6 and later. Commands and flags are documented once when their behavior is shared; version-specific behavior is called out where it differs.

## Version selection

<a id="agent-scan-v05x"></a>

### Agent Scan v0.5.x

> [!IMPORTANT]
> Agent Scan v0.5.x is planned for deprecation but remains supported for now. Pin a concrete v0.5.x release so an existing workflow does not silently switch APIs or output formats.

```bash
uvx snyk-agent-scan@0.5.17
```

v0.5.x uses issue codes and severity labels. Its JSON schema and CI ignore flag differ from v0.6 and later.

<a id="agent-scan-v06-and-later"></a>

### Agent Scan v0.6 and later

```bash
uvx snyk-agent-scan@latest
```

v0.6 and later uses named, scored risk indicators and separates risk ignores from operational failure-code ignores.

Agent Scan ships in two forms:

| Entrypoint | Command | Notes |
| --- | --- | --- |
| **Standalone CLI** | `snyk-agent-scan` or `uvx snyk-agent-scan@VERSION` | Python package; primary surface documented below |
| **Snyk CLI extension** | `snyk agent-scan --experimental` | Go wrapper that downloads a pinned binary and forwards flags; see [Snyk CLI extension flags](#snyk-cli-extension-flags) |

Unless noted, flags apply to the standalone CLI. When no subcommand is given, `scan` is assumed.

> **Experimental output.** Issue/risk names, JSON field names, and human-readable output may change between releases. See the [project README](../README.md) for the stability notice.

## Commands

| Command | Description |
| --- | --- |
| `scan` | Discover and inspect MCP configs, agents, and skills, then request security analysis (default) |
| `inspect` | List tools, prompts, resources, and skills without requesting security analysis |
| `help` | Print top-level help |
| `evo` | Interactive flow: mint a push key, scan, upload to Snyk Evo, and revoke the key |
| `guard` | Install, uninstall, or show the status of Agent Guard hooks |

### Positional arguments

The scan-like commands accept optional paths:

```bash
snyk-agent-scan [scan] [CONFIG_FILE ...]
snyk-agent-scan inspect [CONFIG_FILE ...]
snyk-agent-scan evo [CONFIG_FILE ...]
```

| Argument | Applies to | Description |
| --- | --- | --- |
| `CONFIG_FILE ...` | `scan`, `inspect`, `evo` | One or more MCP configuration files, `SKILL.md` files, or directories. If omitted, well-known agent configuration locations are discovered automatically. |

## Shared options (`scan`, `inspect`, and `evo`)

### Output and logging

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--json` | boolean | `false` | Emit JSON on stdout instead of rich text. Non-JSON status lines are suppressed. The schema depends on the command and CLI version; see [JSON output](json-output.md). |
| `--verbose` | boolean | `false` | Enable debug logging to stderr. |
| `--print-errors` | boolean | `false` | Show error details and tracebacks in the human-readable report. |
| `--print-full-descriptions` | boolean | `false` | Show full tool and skill descriptions rather than truncating them. |
| `--show-analysis-results` | boolean | `false` | Force synchronous analysis so scan results are returned and displayed. Overrides the default push-key behavior, which submits the scan asynchronously and returns no local results. Implied by `--ci` and the `evo` command. See [Push keys and results](#push-keys-and-results). |

### Discovery and scope

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--no-skills` | boolean | off | Skip agent skill discovery and analysis. Skills are included by default. |
| `--skills` | boolean | on (implicit) | **Deprecated/no-op.** Accepted for backward compatibility but redundant because skills are enabled by default. Prefer omitting it; use `--no-skills` to opt out. |
| `--scan-all-users` | boolean | `false` | Scan all readable user home directories (and WSL profiles on Windows), rather than only the current user. |

With `--no-skills`, explicit skill paths, skill directories, and automatically discovered skills are all skipped.

### Analysis and upload

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--storage-file FILE` | string | `~/.mcp-scan` | Path for local scan state and cached results. |
| `--analysis-url URL` | string | version-specific | Analysis API endpoint; see the defaults below. With `SNYK_TOKEN`, the CLI rewrites it to the `/cli/analysis-machine` variant automatically. In v0.6+, any supplied `version` query parameter is replaced with `2026-07-10` so the URL cannot select an incompatible wire contract. |
| `--verification-H HEADER` | repeatable | — | Extra HTTP header for the analysis request, in `Name: value` format. Repeat for multiple headers. |
| `--skip-ssl-verify` | boolean | `false` | Disable TLS certificate verification for analysis and upload calls. |
| `--mcp-oauth-tokens-path PATH` | string | — | JSON file containing MCP OAuth tokens (`TokenAndClientInfoList` schema) for OAuth-protected remote MCP servers. |

The default analysis URL is the main version-dependent value:

| CLI version | Default analysis URL |
| --- | --- |
| v0.5.x | `https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2025-09-02` |
| v0.6 and later | `https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10` |

The URL version must match the request and response models used by the installed Agent Scan version.

### Push key and machine identifier (v0.6 and later)

| v0.6 flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--push-key KEY` | string | — | Push key used to authenticate with the analysis server. Replaces the soon-to-be-deprecated `--control-server-H "x-client-id: <push-key>"` pattern below and does not require a `--control-server` block. |
| `--machine-id ID` | string | — | Non-anonymous identifier for this machine (for example, email, hostname, or serial number). Replaces the soon-to-be-deprecated `--control-identifier` below. |

If both a new flag and its soon-to-be-deprecated equivalent are given, the new flag wins. Using `--control-server-H` for the `x-client-id` trick, or `--control-identifier` on a single `--control-server` block, emits a one-time deprecation warning pointing at `--push-key` / `--machine-id`.

### Machine identity (`scan` only)

The ADS installer passes these in the scheduled scan's config file (`token_command` and `tenant_id`) for user-mode installs of an enrolled machine, instead of a push key.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--token-command PATH` | string | - | Absolute path of a command that prints a machine access token on stdout when run as `<PATH> token --base-url <API>`. `<API>` is the scheme and host of `--analysis-url`. |
| `--tenant-id ID` | string | - | Snyk tenant ID the token is for. |

Machine mode needs both values:

- **Both set (machine mode):** the scan runs the token command at the start, and again right before the asynchronous analysis submit so a long scan does not send an expired token. It calls the tenant routes on the `--analysis-url` API with `Authorization: Bearer <token>` and no push key: the Agent Scan config (`/hidden/tenants/{tenant_id}/agent-scan/config`), asynchronous analysis (`.../agent-scan/async/analysis`) and backend-driven discovery (`.../coding-agent-discovery/sessions`), at version `2024-10-15`. Without `--machine-id`, the scan identifies the machine by its hostname. The scan fails with an error and exit code 1 when the token command is not an absolute path or fails (non-zero exit, timeout, no single token on stdout), when the tenant config cannot be read, or when the analysis submit fails. The error never includes the token command's output. It never falls back to the push key.
- **One or neither set (push-key mode):** the scan behaves exactly as without these flags. With only one set, it prints a warning first.

Synchronous analysis (the tenant config turns asynchronous analysis off, or `--show-analysis-results` / `--ci` asks for results) has no tenant route. In machine mode the scan fails with an error and exit code 1 right after reading the tenant config, before scanning, and never uses the push key. A machine-mode scan is unattended, like a push-key scan, so it never prompts for consent. The token is never logged or put on a command line. `evo` ignores these flags. A `base_url` key or `--base-url` flag, written by earlier installers, is accepted and ignored.

### Control server (enterprise upload, on deprecation path)

Upload analyzed results to one or more control servers, typically Snyk Evo. This upload mechanism is on a deprecation path and will be replaced.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--control-server URL` | repeatable | — | Upload destination. Each block must include a matching `--control-identifier`. Repeat for multiple destinations. |
| `--control-server-H HEADER` | repeatable | — | Header for the current `--control-server` block, such as `x-client-id: <push-key>`. Repeat within a block for multiple headers. |
| `--control-identifier ID` | repeatable | — | Non-anonymous identifier for the current block, such as an email, hostname, or serial number. Required for every `--control-server`. |
| `--no-bootstrap` | boolean | `false` | See [historical bootstrap behavior](#historical-bootstrap-behavior). In v0.5.14 and later it is an accepted compatibility no-op. |

Options following a `--control-server` apply to that server until the next `--control-server`:

```bash
snyk-agent-scan scan \
  --control-server "https://api.snyk.io/hidden/mcp-scan/push?version=2025-08-28" \
  --control-server-H "x-client-id: <push-key>" \
  --control-identifier user@example.com \
  --control-server https://other.example/push \
  --control-server-H "Authorization: Bearer token2" \
  --control-identifier serial-123
```

#### Historical bootstrap behavior

Agent Scan v0.5.4 through v0.5.13 sent a startup bootstrap request to the first eligible control server before doing other work. This applied to every command that accepted `--control-server`: `scan`, `inspect`, and `evo`. Therefore, in those releases, `inspect --control-server ...` sent a bootstrap request even though `inspect` did not call the analysis API. `--no-bootstrap` disabled that request.

Only the first configured control server received bootstrap. The request was restricted to the Snyk-managed `/mcp-scan/push` endpoint, bootstrap failures did not abort the command, and the eventual scan result could still be uploaded to every configured control server.

The bootstrap implementation was removed in v0.5.14. In v0.5.14 and later—including v0.6—the `--no-bootstrap` flag remains accepted for command-line compatibility but does not change behavior.

#### Push keys and MCP servers (`scan` only)

Enterprise uploads include a push key, either via `--push-key` (v0.6 and later) or the soon-to-be-deprecated `x-client-id` header in `--control-server-H`. Agent Scan treats this as an unattended run, so there is no terminal consent prompt.

| `--dangerously-run-mcp-servers` | Consent prompts | Discovered MCP servers |
| --- | --- | --- |
| not set (default) | skipped | Stdio servers are not started; remote servers and skills are still inspected |
| set | skipped | Every stdio server is started and every remote server is contacted |

Use `--dangerously-run-mcp-servers` only when a trusted fleet or CI job must contact configured MCP servers.

<a id="push-keys-and-results"></a>

#### Push keys and results

When a scan authenticates with a push key and the tenant has asynchronous analysis enabled, Agent Scan submits the scan to the async endpoint and returns immediately without local results—results are processed and reported on the Snyk side. This keeps unattended and fleet scans fast and fire-and-forget.

Pass `--show-analysis-results` to force synchronous analysis instead, so the scan waits for the response and displays results locally (and in `--json` output). The synchronous path is also selected automatically for `--ci` runs and the `evo` command, so `--show-analysis-results` is only needed for a plain push-key `scan`.

## CI mode

`--ci` makes scan-like commands return a non-zero status when relevant security findings or operational failures remain. It must be paired with `--dangerously-run-mcp-servers` in non-interactive use.

### Agent Scan v0.5.x

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--ci` | boolean | `false` | Exit with code `1` if analysis issues or runtime failures remain. |
| `--ignore-issues-codes CODES` | string | — | Comma-separated issue and failure codes to ignore for CI, such as `E001,W015,X001`. Only valid with `--ci`; ignored codes are also removed from JSON output in CI mode. |

| Code | Meaning |
| --- | --- |
| `0` | No remaining issues or failures after ignores |
| `1` | Issues or unignored runtime failures remain |
| `2` | Invalid command-line usage or flag combination |

<a id="v06-ci-mode"></a>

### Agent Scan v0.6 and later

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--ci` | boolean | `false` | Exit with code `1` if security risks or operational failures remain. |
| `--ignore-risks NAMES` | string | — | Comma-separated [risk names](risks.md) to omit from output and CI evaluation, such as `private_data,suspicious_download_url`. Only valid with `--ci`. |
| `--ignore-failure-codes CODES` | string | — | Comma-separated [failure codes](failure-codes.md) to omit from CI evaluation, such as `X001,X007`. Errors remain visible in output. Only valid with `--ci`. |

Risk names and failure codes are case-sensitive. Unknown values produce a warning and are not applied. `inspect` supports `--ignore-failure-codes` because it can encounter operational failures but has no risks to ignore. `evo` supports neither ignore flag.

| Code | Meaning |
| --- | --- |
| `0` | No remaining risks or operational failures after ignores |
| `1` | Risks or unignored operational failures remain |
| `2` | Invalid command-line usage or flag combination |

## MCP server options

These options apply to `scan`, `inspect`, and `evo` in both CLI versions.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--server-timeout SECONDS` | float | `10` | Timeout for MCP server connections, including stdio handshakes and remote servers. |
| `--suppress-mcpserver-io BOOL` | boolean | see below | Suppress stderr from stdio MCP servers. Stdout carries JSON-RPC and is never shown. Accepted values: `true`, `false`, `1`, `0`, `yes`, `no`, `y`, `n`, `t`, `f`. |
| `--dangerously-run-mcp-servers` | boolean | `false` | Skip foreground per-server consent and contact every configured MCP server. This starts stdio subprocesses; background remote inspection occurs with or without this flag. Required with `--ci` in CI/CD. Use only in trusted environments. |

| Run type | Default for `--suppress-mcpserver-io` |
| --- | --- |
| Interactive (`inspect`, or `scan` without a push key) | `false`; stderr is streamed with a `[server-name]` prefix |
| Unattended (push-key scan, `evo`, and similar flows) | `true`; stderr is hidden |

Remote MCP requests refuse destinations resolving to link-local addresses or known cloud-metadata endpoints (`169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, and `100.100.100.200`), including unattended runs and runs using `--dangerously-run-mcp-servers`. Loopback and private addresses remain allowed. HTTP redirects are not followed. Validation runs before each request, but the subsequent connection resolves DNS again, leaving a DNS-rebinding window.

**Handshake and consent matrix for discovered MCP servers:**

| Command | Push key | `--dangerously-run-mcp-servers` | Start stdio | Connect remote | Consent prompt |
| --- | --- | --- | --- | --- | --- |
| `inspect` | — | no | yes | yes | each server |
| `inspect` | — | yes | yes | yes | no |
| `scan` | no | no | yes | yes | each server |
| `scan` | no | yes | yes | yes | no |
| `scan` | yes | no | no | yes | no |
| `scan` | yes | yes | yes | yes | no |
| `evo` | yes (automatic) | no | no | yes | no |

Remote targets passed directly as `streamable-http:`, `streamable-https:`, or `sse:` arguments are contacted because the command-line target is an explicit connection request.

> Scanning MCP configurations can execute stdio commands or make outbound requests to remote URLs. Review consent prompts carefully or run inside a sandbox. See the README [Security Warning](../README.md#security-warning).

## `scan`

`scan` runs the full pipeline: discover → inspect → redact → analyze → optional upload.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--checks-per-server NUM` | integer | `1` | **No-op.** Accepted for backward compatibility; does not change behavior. |

The analysis result is the main version difference:

### Agent Scan v0.5.x

- Uses the `2025-09-02` analysis API.
- Reports issue codes and severity labels.
- `scan --json` prints the path-keyed `ScanPathResult` schema.
- Uses `--ignore-issues-codes` for both security issues and operational failures in CI.

### Agent Scan v0.6 and later

- Uses the `2026-07-10` analysis API.
- Reports named risk indicators with scores from 0 to 1000.
- Human-readable output is compact by default: clean servers and skills show counts by entity or file type, while risky components list only the entities or files connected to a risk and summarize the remainder.
- `--show-full-discovery` expands the human-readable report to list every MCP tool, prompt, resource, resource template, and skill file. It does not affect JSON output, which is always complete, or `inspect`, which always lists all locally inspected details.
- `scan --json` prints a `ScanResponse` containing `scan_path_responses`.
- Uses `--ignore-risks` and `--ignore-failure-codes` independently in CI.

| v0.6 flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--show-full-discovery` | boolean | `false` | Expand human-readable `scan` output to list every MCP entity and skill file instead of the compact summary. |

## Configuration file

Load argument values from a YAML file instead of passing them all on the command line. Applies to `scan`, `inspect`, and `evo` (not `guard`). **Any** flag from the sections above — Shared options, MCP server options, and `scan` options — is settable.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--config-file FILE` | string | — | Path to a YAML file supplying argument values. Errors (missing file, invalid YAML, non-mapping top level) exit with code **2**. |

**Precedence.** Values resolve as `code defaults < config file < explicit CLI flags`. A flag you also pass on the command line always wins over the file; a flag you omit takes the file's value, or the built-in default if the file doesn't set it.

**Keys.** Use the flag's long name with dashes or underscores — `server-timeout` and `server_timeout` are equivalent. Values are native YAML types (`true`/`false`, numbers, strings, lists), so `--suppress-mcpserver-io` becomes `suppress_mcpserver_io: true` and `--dangerously-run-mcp-servers` becomes `dangerously_run_mcp_servers: true`. Unknown keys are ignored with a warning on stderr.

**Validation.** Values are checked the same way argparse checks CLI input: the flag's type converter is applied, `choices` are enforced, and boolean/scalar/list shapes must match (a boolean flag rejects non-boolean values, a list option rejects a mapping, etc.). String forms of booleans are normalized (`skip_ssl_verify: "false"` → `false`). An invalid type, value, or shape exits with code **2**.

**Scalars vs. blocks/lists.** Scalar options (`server_timeout`, `analysis_url`, booleans, …) override field-by-field. Block/list options — the positional `files`, repeatable headers like `verification_H`, and the `control_servers` block — use **complete replacement**: if you pass *any* CLI flag for that structure, the file's entire array for it is discarded (no element-wise merge) and rebuilt from the CLI alone.

**Control servers.** The `--control-server` / `--control-server-H` / `--control-identifier` block is expressed as a `control_servers` list; `headers` may be a mapping or a list of `Name: value` strings. Passing any one of those three flags on the CLI replaces the whole `control_servers` list from the file.

```yaml
# agent-scan.yaml
json: true
skills: true              # set false to skip skills (equivalent to --no-skills)
scan_all_users: true

# MCP server options are settable too
server_timeout: 30
suppress_mcpserver_io: true
dangerously_run_mcp_servers: true

verification_H:
  - "X-Trace: abc123"
files:
  - ~/.cursor/mcp.json
  - ~/.claude/skills

# Push key and machine identifier (v0.6 and later)
push_key: <push-key>
machine_id: user@example.com

# Machine identity, as the ADS installer writes it (see "Machine identity" above)
token_command: /path/to/ads-installer
tenant_id: <tenant-id>

# Legacy control-server block (superseded by push_key/machine_id above)
control_servers:
  - url: https://api.snyk.io/hidden/mcp-scan/push?version=2025-08-28
    identifier: user@example.com
    headers:
      x-client-id: <push-key>
```

```bash
# Use the file as-is
snyk-agent-scan scan --config-file agent-scan.yaml

# ...but override one scalar for this run (CLI wins)
snyk-agent-scan scan --config-file agent-scan.yaml --server-timeout 5

# Passing --control-server discards the file's control_servers list entirely
snyk-agent-scan scan --config-file agent-scan.yaml \
  --control-server https://other.example/push --control-identifier host-1
```

> Notes:
> - `push_key` / `machine_id` are ordinary scalars in the precedence cascade (`code defaults < config file < explicit CLI flags`), but they resolve *against the soon-to-be-deprecated `--control-server-H` / `--control-identifier` flags* rather than against each other's own CLI flag. Concretely: if you pass the legacy `--control-server-H "x-client-id: ..."` / `--control-identifier` on the command line but the config file sets `push_key` / `machine_id`, the **file's value wins**, because only an *explicit* `--push-key` / `--machine-id` on the command line — not the legacy flags — is checked as an override. Passing `--push-key` / `--machine-id` explicitly on the command line still overrides the file as usual.
> - `skills` is on by default. In YAML, set `skills: false` to disable skill scanning (equivalent to `--no-skills`); there is no separate `no_skills` toggle — the `skills` key is the single source of truth.
> - `dangerously_run_mcp_servers: true` in the file has the same effect as the flag, including satisfying the `--ci` requirement that it be set — a config file can therefore enable stdio MCP server execution. This is intended, but review config files with that in mind.
> - **On/off flags set to `true` in a file cannot be turned off on the command line.** Flags such as `json`, `scan_all_users`, and `dangerously_run_mcp_servers` are `store_true` and have no `--no-…` counterpart, so once a config file sets them to `true` there is no CLI flag to override them back to `false` for a single run — edit or omit the file instead. (`skills` is the exception: it has `--no-skills`.)

---

## `inspect`

`inspect` uses the shared discovery and MCP options but does not request security analysis. It prints the locally discovered servers, skills, tools, prompts, resources, and resource templates. Its behavior is shared across the documented versions except for the [historical bootstrap behavior](#historical-bootstrap-behavior) in v0.5.4–v0.5.13.

## `evo`

`evo` uses the scan discovery, inspection, analysis, and upload flow:

1. Prompt for a Snyk tenant ID and API token.
2. Mint a short-lived push key (`x-client-id`).
3. Run `scan` with the Snyk push endpoint configured automatically.
4. Revoke the push key when finished.

`evo` always authenticates with the push key it mints for that run. In v0.6 and later, an explicit `--push-key` on the command line is ignored — it never substitutes for the minted key.

`--ci` is accepted for compatibility but does not change `evo` output or exit status. Shared argument validation still requires it to be paired with `--dangerously-run-mcp-servers`. Use `scan` when CI risk/failure evaluation is required.

## `guard`

Manage [Agent Guard](https://evo.ai.snyk.io) hooks for Claude Code, Cursor, Codex, and Github Copilot:

```bash
snyk-agent-scan guard [install|uninstall|discover] [OPTIONS]
snyk-agent-scan guard
```

### `guard install`

```bash
snyk-agent-scan guard install {claude,cursor,codex,github-copilot,all} [OPTIONS]
```

After configuring the hooks, installation sends a `hooksConfiguredServerDiscovery` event. It also configures a
fire-and-forget session-start hook that reports discovered MCP servers with a `sessionStartServerDiscovery` event.

The installed hook scripts wait at most 60 seconds for the Agent Guard response. On a timeout, and on any transport
or HTTP failure, they fail open: exit 0 with one line on stderr. On Claude Code and Codex they also return a
`systemMessage` that the agent shows as a warning ("Unable to reach Snyk Evo to validate agent behavior. Please check
your network and configuration and try again."); Cursor and GitHub Copilot, whose hook output has no such field,
receive nothing on stdout.

Install and uninstall replace a client configuration file by writing a new file and moving it over the old one, so an
agent never reads a half-written file. The new file keeps the old file's permission bits and, when the command runs as
root, its owner and group; a symlinked configuration stays a symlink and its target is updated. Nothing else carries
over: ACLs, extended attributes (such as a SELinux label set by hand) and file flags are lost, the new file gets its
directory's inherited ACL, and other hard links to the old file keep the old content. If you set any of these on a
configuration file, set them again after installing or uninstalling.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--url URL` | string | `https://api.snyk.io` | Remote hook base URL for the Snyk API environment. |
| `--tenant-id ID` | string | — | Snyk tenant UUID. Required when minting a push key; unnecessary when `PUSH_KEY` is set. |
| `--machine-id ID` | string | — | Required non-anonymous machine identifier sent in the `X-User` header's `identifier` field. May instead be set with `MACHINE_ID`. |
| `--file PATH` | string | — | Override the client configuration path. |
| `--managed` | boolean | `false` | Install in the admin/MDM-managed configuration rather than the user configuration. |
| `--check-installed` | boolean | `false` | With `--managed`, skip agents that are not installed for any user on the machine. Without it, managed installs do not check. Non-managed installs always check. |
| `--test` | boolean | `false` | **Deprecated/no-op.** |
| `--no-config-file` | boolean | `false` | Write no guard configuration file; the hooks read their values from the environment (see below). Needs `PUSH_KEY` set and `--env-placeholder PUSH_KEY=<VAR>`. |
| `--env-placeholder NAME=VAR` | string, repeatable | — | With `--no-config-file`, write `NAME="$VAR"` into the hook commands, expanded when the hook runs. `NAME` is one of `PUSH_KEY`, `REMOTE_HOOKS_BASE_URL`, `MACHINE_ID`, `MACHINE_SERIAL`, `AGENT_SCAN_COMMAND`. Values without a placeholder are written as literals; the push key never is. |

#### Where the hooks get their values

By default, `guard install` writes the hook values (`PUSH_KEY`, or with [machine identity](#guard-machine-identity)
`ADS_TOKEN_COMMAND` instead; `REMOTE_HOOKS_BASE_URL`, `TENANT_ID`, `MACHINE_ID`, `MACHINE_SERIAL`,
`AGENT_SCAN_COMMAND`) to `snyk-agent-guard.conf`, next to the hook scripts: mode 0600 for a user install, 0644 for a
managed one. The hook commands carry no values. The scripts parse the file line by line, never
source or evaluate it, and ignore these variables in their environment.

With `--no-config-file`, no such file is written, and an existing one is removed. It is for push-key installs only;
with `ADS_TOKEN_COMMAND` set, install fails. The hook commands pass
`--from-env` (`-FromEnv` on Windows), and the scripts read the values from their environment:

| Configuration file next to the script | `--from-env` on the hook command | Values come from |
| --- | --- | --- |
| present | either | the file only; the environment is ignored |
| absent | yes | the environment (`PUSH_KEY`, or `PUSHKEY`; or `ADS_TOKEN_COMMAND` and `TENANT_ID` for machine identity; `REMOTE_HOOKS_BASE_URL`; `MACHINE_ID`; `MACHINE_SERIAL`; for discovery also `AGENT_SCAN_COMMAND`) |
| absent | no | nowhere: the hook stops with a usage error |

This lets the hook scripts run without `guard install`, for example from a plugin that ships them. Such a hook
command just adds `--from-env`. On POSIX, the command can set the values from differently named variables, for
example secrets:

```bash
PUSH_KEY=... sudo -E snyk-agent-scan guard install cursor --managed --url https://api.snyk.io \
  --no-config-file --env-placeholder PUSH_KEY=SNYK_ADS_PUSH_KEY --env-placeholder MACHINE_ID=SNYK_ADS_MACHINE_ID
# writes: PUSH_KEY="$SNYK_ADS_PUSH_KEY" REMOTE_HOOKS_BASE_URL='https://api.snyk.io' MACHINE_ID="$SNYK_ADS_MACHINE_ID" \
#         bash '/etc/cursor/hooks/snyk-agent-guard.sh' --client cursor --from-env
```

On Windows, `powershell -File` cannot set environment variables, so every value must already be in the agent's
environment under its own name. `--env-placeholder` then only accepts `NAME=NAME`.

**Security.** In environment mode, whatever sets the agent's environment controls the hooks. That includes the push
key, and so the tenant whose policy decides and which receives the events. Use it only where an administrator
controls that environment, such as agent secrets or MDM. Don't use it where a repository or user can set it, for
example through `env` in a project's agent settings. The scripts limit the damage:

- `REMOTE_HOOKS_BASE_URL` from the environment must be `https://` to `snyk.io`, `snykgov.io` or a subdomain of either,
  or `localhost`. Any other URL is refused, so events and the push key can't be sent anywhere else.
- The discovery hook runs `AGENT_SCAN_COMMAND` from the environment only if it's an existing executable file. It never
  evaluates it as a shell command.
- A hook command without `--from-env` never falls back to the environment, so deleting the configuration file stops
  the hooks instead of handing them to the environment.

There is no configuration file, so there is no configuration checksum: agent-monitor can't detect a change to the
values between installs.

### `guard discover`

```bash
snyk-agent-scan guard discover [OPTIONS]
```

This internal command is invoked by the SessionStart hook configured by `guard install`. It reads the current target
folder(s) from the selected client's hook payload, discovers MCP servers locally, and sends the resulting
`sessionStartServerDiscovery` event directly to Agent Monitor; it is not normally run by hand.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--url URL` | string | `https://api.snyk.io` | Remote hook base URL for the Snyk API environment. |
| `--client {claude-code,cursor,codex,github-copilot}` | string | required | Hook client whose target-folder payload and endpoint conventions should be used. |
| `--scope {servers,skills,all}` | string | `all` | Discovery data to collect. The session-start hook installed by `guard install` passes `servers`, because the event it sends carries MCP servers only. |

### `guard uninstall`

```bash
snyk-agent-scan guard uninstall {claude,cursor,codex,github-copilot,all} [OPTIONS]
```

Uninstall replaces configuration files the same way install does; see `guard install` for which file properties are
kept.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--file PATH` | string | — | Override the client configuration path. |
| `--managed` | boolean | `false` | Uninstall from the admin/MDM-managed configuration. |

### Guard environment variables

| Variable | Purpose |
| --- | --- |
| `PUSH_KEY` | Pre-provisioned push key; skips minting when set |
| `TENANT_ID` | Tenant UUID alternative to `--tenant-id` |
| `SNYK_TOKEN` | Required to mint/revoke push keys and verify that Guard is enabled for the tenant |
| `MACHINE_ID` | Required non-anonymous machine identifier sent with hook events; alternative to `guard install --machine-id` |
| `MACHINE_SERIAL` | Optional hardware serial captured by `guard install` for hook and discovery events. Sent as `machine_serial` alongside the hostname; absent or empty values become JSON `null`. The captured value, including an empty value, overrides any later inherited `MACHINE_SERIAL`. Does not change `MACHINE_ID`. |
| `AGENT_SCAN_COMMAND` | Optional Agent Scan command invoked by the session-start discovery hook, with the hook arguments appended. The hook is installed only when this is set. A value that is not an existing executable file is run as a shell command. |
| `ADS_TOKEN_COMMAND` | Machine identity: a command that prints a machine access token on stdout when run as `<command> token --base-url <url>`, where `<url>` is `guard install --url`. Set together with `TENANT_ID`; see [Guard machine identity](#guard-machine-identity). |

Pass `MACHINE_SERIAL` again whenever you reinstall or update Guard hooks. Reinstalling without it, or with a blank value, replaces any previously captured serial with JSON `null`; the old value is not preserved.

#### Guard machine identity

The ADS installer decides how the hooks authenticate and passes `guard install` either a push key or a machine identity: `ADS_TOKEN_COMMAND` and `TENANT_ID` (or `--tenant-id`), for user-mode installs on an enrolled machine. Machine identity needs both, as in `scan`. `TENANT_ID` alone is the push-key flow's tenant, and `ADS_TOKEN_COMMAND` without `TENANT_ID` prints a warning and uses the push key. The API is `--url`, as for a push key; the token command refuses any API other than the one the machine enrolled with. `ADS_BASE_URL` is not used.

- **Install:** `guard install` runs `"$ADS_TOKEN_COMMAND" token --base-url <--url>` once as a check. If it fails (non-zero exit, timeout, no single token on stdout), the install fails with an error and exit code 1 and changes nothing. A `TENANT_ID` that is not a plain id (letters, digits, `.`, `_`, `~`, `-`), or a `--url` with quotes, backslashes or whitespace fails the same way. No push key is minted or used, even when `PUSH_KEY` is also set. The [configuration file](#where-the-hooks-get-their-values) holds `ADS_TOKEN_COMMAND`, `REMOTE_HOOKS_BASE_URL`, `TENANT_ID`, `MACHINE_ID` and `MACHINE_SERIAL`, and no push key or other secret. The test event goes through the tenant route like every later hook event; if it is rejected, the install fails as it does with a push key. `--managed` installs use a push key only and fail when `ADS_TOKEN_COMMAND` is set.
- **Hook runtime:** on every invocation the hooks, and the events that `guard install` and `guard discover` send themselves, run the token command and send the event to `POST {REMOTE_HOOKS_BASE_URL}/hidden/tenants/{TENANT_ID}/agent-monitor/hooks/{client}?version=2025-11-11` (the same version as the push-key route) with `Authorization: Bearer <token>` and no `X-Client-Id`. The token command's time counts toward the 60-second request budget. If it fails, the hook fails open like an unreachable API (exit 0, one stderr line, the `systemMessage` where supported); it never falls back to the push key. The payload and the other headers are the same as with a push key. The token is never logged and never put on a command line. A push key wins over machine identity in the hooks and in `guard discover`. With a configuration file the hooks read neither from the agent's environment, so an `ADS_TOKEN_COMMAND` or `PUSH_KEY` there cannot change the mode; in environment mode (`--from-env`, no file) a `PUSH_KEY` in the environment wins.
- **Switching:** re-running `guard install` in the other mode rewrites the configuration file; the hook commands stay the same. Switching from a push key to machine identity does not revoke the old push key, because a machine identity install has no Snyk API token to revoke it with; install warns, and the key stays active until you revoke it in Snyk. `guard status` shows `[Machine identity]` for such hooks, and `guard uninstall` removes them without a push key to revoke.

## Environment variables

| Variable | Used by | Description |
| --- | --- | --- |
| `SNYK_TOKEN` | Standalone CLI | Snyk API token for analysis (`Authorization: token …`). Required for `scan` unless a push key is configured through `--push-key` (v0.6 and later) or the soon-to-be-deprecated `--control-server-H`. Never required for `evo`, which always mints and uses its own push key. Obtain it from https://app.snyk.io/account. |
| `SNYK_CLI_USE` | Binary invoked through Snyk CLI | Set to `true` by the extension so analysis uses the proxy-authenticated `/cli/analysis-machine` endpoint. |
| `SNYK_API` | Standalone CLI | Override the Snyk API base URL for local development or custom regions. |
| `SNYK_TENANT_ID` | Snyk CLI extension | Alternative to `--tenant-id` for the Go wrapper. |
| `AGENT_SCAN_ENVIRONMENT` | Analysis and upload | Environment label sent as `X-Environment` (default: `production`). Also accepts the older `MCP_SCAN_ENVIRONMENT` name. |
| `AGENT_SCAN_CI_HOSTNAME` | Upload | When `AGENT_SCAN_ENVIRONMENT=ci`, use this hostname instead of the machine node name. |
| `PUSH_KEY` | `guard install` | Pre-provisioned push key for hook installation. |
| `MACHINE_SERIAL` | `scan`, Agent Guard | Optional machine serial sent alongside hostname. Leading/trailing whitespace is removed; absent or blank values become JSON `null`. Does not change the machine identifier. |
| `TENANT_ID` | `guard install`, Agent Guard hooks | Tenant UUID for hook installation, and the tenant of the machine identity routes. |
| `ADS_TOKEN_COMMAND` | `guard install`, Agent Guard hooks | Machine identity for the hooks; see [Guard machine identity](#guard-machine-identity). |
| `HOOK_VERSION` | Agent Guard hooks | Override the hook/API line version built into Guard artifacts. |

## Snyk CLI extension flags

The Snyk CLI command `snyk agent-scan` is implemented by [cli-extension-agent-scan](https://github.com/snyk/cli-extension-agent-scan). It requires `--experimental` and delegates to the embedded Agent Scan binary.

Run `snyk auth` first. Analysis passes through a local credential proxy, so a valid Snyk CLI session is required even with `--no-upload`.

```bash
snyk agent-scan --experimental [EXTENSION_FLAGS] [AGENT_SCAN_ARGS...]
```

### Extension-only flags

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--experimental` | boolean | `false` | Required to enable the Agent Scan workflow. |
| `--tenant-id UUID` | string | — | Snyk tenant ID. Required with `--json` when no client ID is supplied; otherwise resolved interactively or from `SNYK_TENANT_ID`. |
| `--client-id UUID` | string | — | Push-key client ID passed to the control server as `x-client-id`. If omitted and upload is enabled, the extension mints one. |
| `--no-upload` | boolean | `false` | Do not upload results to Evo. Analysis still runs. |
| `--json` | boolean | `false` | Forward JSON output to the embedded binary. |
| `--skills [PATH]` | string/boolean | skills on | Using `--skills` alone is deprecated because skills are enabled by default. A supplied path remains supported and is forwarded as a scan target. |

### Snyk CLI flags consumed by the extension

| Snyk CLI flag | Effect on Agent Scan |
| --- | --- |
| `--insecure` | Adds `--skip-ssl-verify` to the embedded binary |
| `--debug` / `-d` | Adds `--verbose` to the embedded binary |

### What the extension adds automatically

For a default scan without `--no-upload`, the extension:

- Prepends `scan` if no path is supplied.
- Sets `--analysis-url` from the configured Snyk API URL.
- Mints or reuses a push key and appends the corresponding `--control-server`, `--control-server-H`, and `--control-identifier` arguments.
- Starts a local proxy for Snyk CLI credential injection.

With `--no-upload`, it does not mint a client ID or add control-server arguments, but analysis still runs through the authenticated proxy. Explicit subcommands such as `inspect`, `help`, and `guard` do not configure upload.

The older `snyk mcp-scan` alias is deprecated and is treated as `snyk agent-scan`.

## Examples

### Standalone

```bash
# Full scan with v0.6 or later
uvx snyk-agent-scan@latest

# Full scan pinned to v0.5.x
uvx snyk-agent-scan@0.5.17

# Scan MCP components but skip skills
snyk-agent-scan --no-skills

# Scan a specific configuration or skill directory
snyk-agent-scan ~/.cursor/mcp.json
snyk-agent-scan ~/.claude/skills

# Inspect without analysis
snyk-agent-scan inspect

# v0.5.x CI with selected issue/failure codes ignored
snyk-agent-scan --ci --dangerously-run-mcp-servers \
  --ignore-issues-codes W015,X001

# v0.6+ CI with selected risks and failures ignored
snyk-agent-scan --ci --dangerously-run-mcp-servers \
  --ignore-risks private_data,suspicious_download_url \
  --ignore-failure-codes X001

# Load flags from a YAML config file (CLI flags still override it)
snyk-agent-scan --config-file agent-scan.yaml
snyk-agent-scan --config-file agent-scan.yaml --server-timeout 5

# Enterprise upload with a push key
snyk-agent-scan scan \
  --control-server "https://api.snyk.io/hidden/mcp-scan/push?version=2025-08-28" \
  --control-server-H "x-client-id: <push-key>" \
  --control-identifier "$(hostname)"
```

### Snyk CLI extension

```bash
# Authenticated scan with upload to Evo
snyk auth
snyk agent-scan --experimental

# Local analysis without Evo upload
snyk agent-scan --experimental --no-upload

# JSON output
snyk agent-scan --experimental --json --tenant-id "<tenant-uuid>"

# Scan a specific path
snyk agent-scan --experimental ~/.claude/skills
```

### Agent Guard

```bash
# Check hook status
snyk-agent-scan guard

# Install for all supported clients
SNYK_TOKEN=... snyk-agent-scan guard install all --tenant-id "<tenant-uuid>" --machine-id "<machine-id>"

# Install through an MDM-managed configuration
PUSH_KEY=... snyk-agent-scan guard install cursor --managed --machine-id "<machine-id>"

# Uninstall
snyk-agent-scan guard uninstall all
```

## Related documentation

- [Scanning overview](scanning.md) — shared discovery and analysis workflow
- [Issue codes](issue-codes.md) — v0.5.x security findings
- [Risk reference](risks.md) — v0.6+ security risk indicators and scores
- [Failure codes](failure-codes.md) — operational discovery, inspection, and analysis failures
- [JSON output](json-output.md) — versioned programmatic output schemas
- [Developer guide — entrypoints](https://github.com/snyk/agent-scan-dev-guide/blob/main/agent-scan-entrypoints-and-release.md) — standalone, Snyk CLI, and MDM paths
