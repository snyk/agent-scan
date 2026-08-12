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
| `--analysis-url URL` | string | version-specific | Analysis API endpoint; see the defaults below. With `SNYK_TOKEN`, the CLI rewrites it to the `/cli/analysis-machine` variant automatically. |
| `--verification-H HEADER` | repeatable | — | Extra HTTP header for the analysis request, in `Name: value` format. Repeat for multiple headers. |
| `--skip-ssl-verify` | boolean | `false` | Disable TLS certificate verification for analysis and upload calls. |
| `--mcp-oauth-tokens-path PATH` | string | — | JSON file containing MCP OAuth tokens (`TokenAndClientInfoList` schema) for OAuth-protected remote MCP servers. |

The default analysis URL is the main version-dependent value:

| CLI version | Default analysis URL |
| --- | --- |
| v0.5.x | `https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2025-09-02` |
| v0.6 and later | `https://api.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10` |

The URL version must match the request and response models used by the installed Agent Scan version.

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

#### Push keys and stdio MCP servers (`scan` only)

Enterprise uploads include an `x-client-id` push key in `--control-server-H`. Agent Scan treats this as an unattended run, so there is no terminal consent prompt.

| `--dangerously-run-mcp-servers` | Consent prompts | Stdio MCP subprocesses |
| --- | --- | --- |
| not set (default) | skipped | Not started; servers remain in the result as configured, while remote servers and skills are still inspected |
| set | skipped | Started for every stdio server in the scanned configurations |

Use `--dangerously-run-mcp-servers` only when a trusted fleet or CI job must execute configured stdio MCP commands.

## CI mode

`--ci` makes scan-like commands return a non-zero status when relevant security findings or operational failures remain. It must be paired with `--dangerously-run-mcp-servers` in non-interactive use.

### Agent Scan v0.5.x

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--ci` | boolean | `false` | Exit with code `1` if analysis issues or runtime failures remain. |
| `--ignore-issues-codes CODES` | string | — | Comma-separated issue and failure codes to ignore for CI, such as `W001,W015,X001`. Only valid with `--ci`; ignored codes are also removed from JSON output in CI mode. |

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
| `--ignore-risks NAMES` | string | — | Comma-separated [risk names](risks.md) to omit from output and CI evaluation, such as `dangerous_words,suspicious_download_url`. Only valid with `--ci`. |
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
| `--dangerously-run-mcp-servers` | boolean | `false` | Skip per-server consent and start every configured stdio MCP server. Required with `--ci` in CI/CD. Use only in trusted environments. |

| Run type | Default for `--suppress-mcpserver-io` |
| --- | --- |
| Interactive (`inspect`, or `scan` without a push key) | `false`; stderr is streamed with a `[server-name]` prefix |
| Unattended (push-key scan, `evo`, and similar flows) | `true`; stderr is hidden |

**Handshake and consent matrix for stdio MCP servers:**

| Command | Push key | `--dangerously-run-mcp-servers` | Start servers | Consent prompt |
| --- | --- | --- | --- | --- |
| `inspect` | — | no | yes | yes |
| `inspect` | — | yes | yes | no |
| `scan` | no | no | yes | yes |
| `scan` | no | yes | yes | no |
| `scan` | yes | no | no | no |
| `scan` | yes | yes | yes | no |
| `evo` | yes (automatic) | no | no | no |

> Scanning MCP configurations executes the commands defined in them. Review consent prompts carefully or run inside a sandbox. See the README [Security Warning](../README.md#security-warning).

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
- `scan --json` prints a `ScanResponse` containing `scan_path_responses`.
- Uses `--ignore-risks` and `--ignore-failure-codes` independently in CI.

## `inspect`

`inspect` uses the shared discovery and MCP options but does not request security analysis. It prints the locally discovered servers, skills, tools, prompts, resources, and resource templates. Its behavior is shared across the documented versions except for the [historical bootstrap behavior](#historical-bootstrap-behavior) in v0.5.4–v0.5.13.

## `evo`

`evo` uses the scan discovery, inspection, analysis, and upload flow:

1. Prompt for a Snyk tenant ID and API token.
2. Mint a short-lived push key (`x-client-id`).
3. Run `scan` with the Snyk push endpoint configured automatically.
4. Revoke the push key when finished.

`--ci` is accepted for compatibility but does not change `evo` output or exit status. Shared argument validation still requires it to be paired with `--dangerously-run-mcp-servers`. Use `scan` when CI risk/failure evaluation is required.

## `guard`

Manage [Agent Guard](https://evo.ai.snyk.io) hooks for Claude Code, Cursor, and Codex:

```bash
snyk-agent-scan guard [install|uninstall] [OPTIONS]
snyk-agent-scan guard
```

### `guard install`

```bash
snyk-agent-scan guard install {claude,cursor,codex,all} [OPTIONS]
```

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| `--url URL` | string | `https://api.snyk.io` | Remote hook base URL for the Snyk API environment. |
| `--tenant-id ID` | string | — | Snyk tenant UUID. Required when minting a push key; unnecessary when `PUSH_KEY` is set. |
| `--file PATH` | string | — | Override the client configuration path. |
| `--managed` | boolean | `false` | Install in the admin/MDM-managed configuration rather than the user configuration. |
| `--test` | boolean | `false` | **Deprecated/no-op.** |

### `guard uninstall`

```bash
snyk-agent-scan guard uninstall {claude,cursor,codex,all} [OPTIONS]
```

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

## Environment variables

| Variable | Used by | Description |
| --- | --- | --- |
| `SNYK_TOKEN` | Standalone CLI | Snyk API token for analysis (`Authorization: token …`). Required for `scan`/`evo` unless a push key is configured through `--control-server-H`. Obtain it from https://app.snyk.io/account. |
| `SNYK_CLI_USE` | Binary invoked through Snyk CLI | Set to `true` by the extension so analysis uses the proxy-authenticated `/cli/analysis-machine` endpoint. |
| `SNYK_API` | Standalone CLI | Override the Snyk API base URL for local development or custom regions. |
| `SNYK_TENANT_ID` | Snyk CLI extension | Alternative to `--tenant-id` for the Go wrapper. |
| `AGENT_SCAN_ENVIRONMENT` | Analysis and upload | Environment label sent as `X-Environment` (default: `production`). Also accepts the older `MCP_SCAN_ENVIRONMENT` name. |
| `AGENT_SCAN_CI_HOSTNAME` | Upload | When `AGENT_SCAN_ENVIRONMENT=ci`, use this hostname instead of the machine node name. |
| `PUSH_KEY` | `guard install` | Pre-provisioned push key for hook installation. |
| `TENANT_ID` | `guard install` | Tenant UUID for hook installation. |
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
  --ignore-issues-codes W001,X001

# v0.6+ CI with selected risks and failures ignored
snyk-agent-scan --ci --dangerously-run-mcp-servers \
  --ignore-risks dangerous_words,suspicious_download_url \
  --ignore-failure-codes X001

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
SNYK_TOKEN=... snyk-agent-scan guard install all --tenant-id "<tenant-uuid>"

# Install through an MDM-managed configuration
PUSH_KEY=... snyk-agent-scan guard install cursor --managed

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
