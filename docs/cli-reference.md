# Agent Scan CLI reference

Complete reference for **Agent Scan** command-line flags and options. Agent Scan ships in two forms:

| Entrypoint | Command | Notes |
| --- | --- | --- |
| **Standalone CLI** | `snyk-agent-scan` (or `uvx snyk-agent-scan@latest`) | Python package; primary surface documented below |
| **Snyk CLI extension** | `snyk agent-scan --experimental` | Go wrapper that downloads a pinned binary and forwards flags — see [Snyk CLI extension flags](#snyk-cli-extension-flags) |

Unless noted, flags apply to the standalone CLI. When no subcommand is given, **`scan` is assumed**.

> **Experimental output.** Issue codes, JSON field names, and human-readable output may change between releases. See the [project README](../README.md) for the stability notice.

---

## Commands

| Command | Description |
| --- | --- |
| `scan` | Scan MCP configs, agents, and skills for security issues (default) |
| `inspect` | List tools, prompts, and resources without running security analysis |
| `help` | Print top-level help |
| `evo` | Interactive flow: mint a push key, scan, upload to Snyk Evo, revoke the key |
| `guard` | Install, uninstall, or show status of Agent Guard hooks |

### Positional arguments

Most scan-like commands accept optional config paths:

```bash
snyk-agent-scan [scan] [CONFIG_FILE ...]
snyk-agent-scan inspect [CONFIG_FILE ...]
snyk-agent-scan evo [CONFIG_FILE ...]
```

| Argument | Applies to | Description |
| --- | --- | --- |
| `CONFIG_FILE ...` | `scan`, `inspect`, `evo` | One or more MCP config files, `SKILL.md` files, or directories to scan. If omitted, well-known agent config locations on the machine are discovered automatically. |

---

## Global options (scan, inspect, evo)

These flags are shared by `scan`, `inspect`, and `evo`.

### Output and logging

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--json` | boolean | `false` | Emit results as JSON on stdout instead of rich text. Non-JSON status lines are suppressed during the scan. See [JSON output](json-output.md). |
| `--verbose` | boolean | `false` | Enable debug logging to stderr. |
| `--print-errors` | boolean | `false` | Show error details and tracebacks in the human-readable report. |
| `--print-full-descriptions` | boolean | `false` | Show full tool/skill descriptions in output (not truncated). |

### Discovery and scope

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--skills` / `--no-skills` | boolean | `--skills` (enabled) | Include agent skills in the scan. Use `--no-skills` to scan MCP servers only. |
| `--scan-all-users` | boolean | `false` | Scan all readable user home directories on the machine (and WSL profiles on Windows), not just the current user. Also expands the control-server bootstrap payload to list those homes. |

### Analysis and upload

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--storage-file FILE` | string | `~/.mcp-scan` | Path for local scan state and cached results. |
| `--analysis-url URL` | string | `https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2025-09-02` | Analysis API endpoint. With `SNYK_TOKEN`, the CLI rewrites this to the `/cli/analysis-machine` variant automatically. |
| `--verification-H HEADER` | repeatable | — | Extra HTTP header for the analysis request. Format: `Name: value` (repeat for multiple headers). |
| `--skip-ssl-verify` | boolean | `false` | Disable TLS certificate verification for analysis and upload HTTP calls. |
| `--mcp-oauth-tokens-path PATH` | string | — | JSON file containing MCP OAuth tokens (`TokenAndClientInfoList` schema) used when connecting to OAuth-protected remote MCP servers. |

### Control server (enterprise upload)

Upload analyzed results to one or more control servers (typically Snyk Evo).

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--control-server URL` | repeatable | — | Upload destination URL. Each block **must** include a matching `--control-identifier`. Can be specified multiple times for multi-tenant upload. |
| `--control-server-H HEADER` | repeatable | — | HTTP header for the **current** `--control-server` block (e.g. `x-client-id: <push-key>`). Repeat within a block for multiple headers. |
| `--control-identifier ID` | repeatable | — | Non-anonymous machine identifier for the **current** `--control-server` block (email, hostname, serial number, etc.). **Required** for every `--control-server`. |
| `--no-bootstrap` | boolean | `false` | Skip the one-shot startup bootstrap request to the first control server. |

**Control-server block syntax** — options after a `--control-server` apply only to that server until the next `--control-server`:

```bash
snyk-agent-scan scan \
  --control-server https://api.snyk.io/hidden/mcp-scan/push?version=2025-08-28 \
  --control-server-H "x-client-id: <push-key>" \
  --control-identifier user@example.com \
  --control-server https://other.example/push \
  --control-server-H "Authorization: Bearer token2" \
  --control-identifier serial-123
```

**Push key and stdio MCP servers (`scan` only).** Enterprise uploads include an `x-client-id` push key in `--control-server-H`. Agent Scan treats that as an **unattended** run — there is no one at the terminal to answer y/n consent prompts.

On `scan`, that changes stdio MCP behavior as follows:

| `--dangerously-run-mcp-servers` | Consent prompts | Stdio MCP subprocesses |
| --- | --- | --- |
| not set (default) | skipped | **not started** — servers stay in the report as configured but not live-inspected; remote MCP servers and skills are still scanned |
| set | skipped | **started** for every stdio server in the scanned configs |

Add `--dangerously-run-mcp-servers` when a fleet or CI job must actually execute stdio MCP commands (typical for trusted MDM policies). This is the same flag required by `--ci` in non-interactive environments.

`inspect` is unaffected: it always runs interactively (consent prompts when applicable), even if a push key is configured. See [MCP server options](#mcp-server-options) for the full handshake matrix.

Bootstrap behavior is described in the [README — Control Server Bootstrap](../README.md#control-server-bootstrap).

### CI mode

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--ci` | boolean | `false` | Exit with code **1** if any analysis issues or runtime failure codes remain after the scan. Requires `--dangerously-run-mcp-servers` in non-interactive environments. |
| `--ignore-issues-codes CODES` | string | — | Comma-separated issue/failure codes to ignore for `--ci` exit status (e.g. `W001,W015,X001`). **Only valid with `--ci`.** Ignored codes are also removed from JSON output in CI mode. |

**Exit codes (scan / inspect with `--ci`):**

| Code | Meaning |
| --- | --- |
| `0` | Success; no remaining issues or failures (after ignores) |
| `1` | `--ci`: findings or unignored runtime failures present |
| `2` | Invalid flag combination (e.g. `--ignore-issues-codes` without `--ci`, or `--ci` without `--dangerously-run-mcp-servers`) |

---

## MCP server options

Applies to: `scan`, `inspect`, `evo`.

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--server-timeout SECONDS` | float | `10` | Timeout for MCP server connections (stdio handshake and remote servers). |
| `--suppress-mcpserver-io BOOL` | boolean | see below | Suppress **stderr** from stdio MCP servers. Stdout is always consumed as JSON-RPC and never shown. Accepted values: `true`, `false`, `1`, `0`, `yes`, `no`, `y`, `n`, `t`, `f`. |
| `--dangerously-run-mcp-servers` | boolean | `false` | Skip interactive per-server consent and start every stdio MCP server listed in scanned configs. **Required with `--ci` in CI/CD.** Use only in trusted environments. |

**Default for `--suppress-mcpserver-io`:**

| Run type | Default |
| --- | --- |
| Interactive (`inspect`, or `scan` without push key) | `false` — stderr streamed with a `[server-name]` prefix |
| Unattended (push-key scan, `evo`, etc.) | `true` — stderr hidden |

**Handshake and consent matrix** (stdio MCP servers):

| Command | Push key | `--dangerously-run-mcp-servers` | Start servers | Consent prompt |
| --- | --- | --- | --- | --- |
| `inspect` | — | no | yes | yes |
| `inspect` | — | yes | yes | no |
| `scan` | no | no | yes | yes |
| `scan` | no | yes | yes | no |
| `scan` | yes | no | no | no |
| `scan` | yes | yes | yes | no |
| `evo` | yes (auto) | no | no | no |

> Scanning MCP configs **executes** the commands defined in them. Review consent prompts carefully or run inside a sandbox. See [Security Warning](../README.md#security-warning) in the README.

---

## `scan`-only options

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--checks-per-server NUM` | integer | `1` | Number of analysis passes per MCP server. |

`scan` runs the full pipeline: discover → inspect → redact → analyze → (optional) upload.

---

## `inspect`

Same global and MCP options as `scan`, but **no security analysis** — only discovery and MCP handshake to print tool/prompt/resource metadata.

When `--control-server` is set, `inspect` still sends the startup bootstrap request (unless `--no-bootstrap`). It does not call the analysis API unless you use `scan`.

---

## `evo`

Uses the same flags as `scan`. Additionally:

1. Prompts interactively for **tenant ID** (from the Snyk app URL) and **API token** (from https://app.snyk.io/account).
2. Mints a short-lived push key (`x-client-id` header).
3. Runs `scan` with the Snyk push endpoint configured automatically.
4. Revokes the push key when finished.

No extra flags beyond the shared scan options.

---

## `guard`

Manage [Agent Guard](https://evo.ai.snyk.io) hooks for Claude Code, Cursor, and Codex.

```bash
snyk-agent-scan guard [install|uninstall] [OPTIONS]
snyk-agent-scan guard              # show installation status (default)
```

### `guard install`

```bash
snyk-agent-scan guard install {claude,cursor,codex,all} [OPTIONS]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--url URL` | string | `https://api.snyk.io` | Remote hooks base URL for the Snyk API environment. |
| `--tenant-id ID` | string | — | Snyk tenant UUID. Required when minting a push key; not needed if `PUSH_KEY` is already set. |
| `--file PATH` | string | — | Override the client config file path (default: client-specific well-known path). |
| `--managed` | boolean | `false` | Install to the admin/MDM managed config path instead of the user-level path. |
| `--test` | boolean | `false` | **Deprecated.** No-op. |

### `guard uninstall`

```bash
snyk-agent-scan guard uninstall {claude,cursor,codex,all} [OPTIONS]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--file PATH` | string | — | Override the config file path. |
| `--managed` | boolean | `false` | Uninstall from the managed (admin/MDM) path. |

### Guard environment variables

| Variable | Purpose |
| --- | --- |
| `PUSH_KEY` | Pre-provisioned push key; skips minting when set |
| `TENANT_ID` | Tenant UUID (alternative to `--tenant-id`) |
| `SNYK_TOKEN` | Required to mint/revoke push keys and to verify Guard is enabled for the tenant |

---

## Environment variables

| Variable | Used by | Description |
| --- | --- | --- |
| `SNYK_TOKEN` | Standalone CLI | Snyk API token for analysis (`Authorization: token …`). Required for `scan`/`evo` unless a push key is configured via `--control-server-H`. Get a token at https://app.snyk.io/account. |
| `SNYK_CLI_USE` | Standalone binary via Snyk CLI | Set to `true` by the Snyk CLI extension so analysis uses the proxy-authenticated `/cli/analysis-machine` endpoint without embedding the token in env. |
| `SNYK_API` | Standalone CLI | Override Snyk API base URL (local dev / custom regions). |
| `SNYK_TENANT_ID` | Snyk CLI extension | Alternative to `--tenant-id` for the Go wrapper. |
| `AGENT_SCAN_ENVIRONMENT` | Bootstrap, analysis | Environment label sent as `X-Environment` (default: `production`). Also accepts legacy `MCP_SCAN_ENVIRONMENT`. |
| `AGENT_SCAN_CI_HOSTNAME` | Bootstrap, upload | When `AGENT_SCAN_ENVIRONMENT=ci`, use this hostname instead of the machine node name. |
| `PUSH_KEY` | `guard install` | Pre-provisioned push key for hook installation |
| `TENANT_ID` | `guard install` | Tenant UUID for hook installation |
| `HOOK_VERSION` | Agent Guard hooks | Override the hook/API line version baked into Guard artifacts |

---

## Snyk CLI extension flags

The Snyk CLI command `snyk agent-scan` is implemented by **cli-extension-agent-scan**. It requires `--experimental` and delegates to the embedded Agent Scan binary.

```bash
snyk agent-scan --experimental [EXTENSION_FLAGS] [AGENT_SCAN_ARGS...]
```

### Extension-only flags

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--experimental` | boolean | `false` | **Required.** Enables the agent-scan workflow. |
| `--tenant-id UUID` | string | — | Snyk tenant ID. Required when using `--json` without a client ID; otherwise resolved interactively or from `SNYK_TENANT_ID`. Must be a valid UUID. |
| `--client-id UUID` | string | — | Push-key client ID passed as `x-client-id` to the control server. If omitted (and not using `--no-upload`), the extension mints one via the authenticated Snyk CLI session. Must be a valid UUID when provided. |
| `--no-upload` | boolean | `false` | Scan and analyze locally without uploading to Evo. Requires Snyk CLI authentication (`snyk auth`). |
| `--json` | boolean | `false` | Forwarded to the Agent Scan binary. |
| `--skills [PATH]` | string / boolean | — | Forwarded to the binary. `--skills` alone enables skills; `--skills /path` enables skills and passes `/path` as a scan target. |

### Snyk CLI flags consumed by the extension

| Snyk CLI flag | Effect on Agent Scan |
| --- | --- |
| `--insecure` | Adds `--skip-ssl-verify` to the binary |
| `--debug` / `-d` | Adds `--verbose` to the binary |

### What the extension adds automatically

When uploading (default, without `--no-upload`):

- Prepends `scan` if no subcommand or config path is given
- Sets `--analysis-url` from `SNYK_API` / configured API URL
- Appends `--control-server`, `--control-server-H "x-client-id: …"`, and `--control-identifier <hostname>`
- Starts a local MITM proxy for Snyk CLI credential injection

When `--no-upload` is set:

- Requires `snyk auth`; no control-server arguments are added
- Analysis still runs through the authenticated proxy

### Deprecated alias

`snyk mcp-scan` is deprecated. The extension prints a warning and treats it like `agent-scan`.

---

## Examples

### Standalone

```bash
# Full machine scan (default command is scan)
uvx snyk-agent-scan@latest

# MCP only, no skills
uvx snyk-agent-scan@latest --no-skills

# Specific config or skill directory
uvx snyk-agent-scan@latest ~/.cursor/mcp.json
uvx snyk-agent-scan@latest ~/.claude/skills

# Inspect without analysis
uvx snyk-agent-scan@latest inspect

# JSON for CI parsing
uvx snyk-agent-scan@latest --json --no-skills ./my-skill

# CI pipeline (non-interactive)
uvx snyk-agent-scan@latest --ci --dangerously-run-mcp-servers --json

# CI with ignored warnings
uvx snyk-agent-scan@latest --ci --dangerously-run-mcp-servers \
  --ignore-issues-codes W001,W015

# All users on a shared machine
uvx snyk-agent-scan@latest --scan-all-users

# Enterprise upload with push key
export SNYK_TOKEN=...   # not required when push key is in control-server headers
uvx snyk-agent-scan@latest scan \
  --control-server "https://api.snyk.io/hidden/mcp-scan/push?version=2025-08-28" \
  --control-server-H "x-client-id: <push-key>" \
  --control-identifier "$(hostname)"
```

### Snyk CLI extension

```bash
# Authenticated scan with upload to Evo
snyk auth
snyk agent-scan --experimental

# Explicit tenant and client IDs
snyk agent-scan --experimental \
  --tenant-id "<tenant-uuid>" \
  --client-id "<client-uuid>"

# Local scan only, no upload
snyk agent-scan --experimental --no-upload

# JSON output
snyk agent-scan --experimental --json --tenant-id "<tenant-uuid>"

# Scan a specific path
snyk agent-scan --experimental --skills ~/.claude/skills
```

### Agent Guard

```bash
# Check hook status
snyk-agent-scan guard

# Install for all supported clients (user-level)
SNYK_TOKEN=... snyk-agent-scan guard install all --tenant-id "<tenant-uuid>"

# MDM managed install
PUSH_KEY=... snyk-agent-scan guard install cursor --managed

# Uninstall
snyk-agent-scan guard uninstall all
```

---

## Related documentation

- [Scanning overview](scanning.md) — how discovery and analysis work
- [Issue codes](issue-codes.md) — security finding reference
- [JSON output](json-output.md) — programmatic output schema
- [Developer guide — entrypoints](https://github.com/snyk/agent-scan-dev-guide/blob/main/agent-scan-entrypoints-and-release.md) — standalone vs Snyk CLI vs MDM paths
