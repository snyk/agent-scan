# Scanning with `snyk-agent-scan`

Agent Scan discovers agents, MCP servers, and skills on your machine and checks them for security concerns. It supports interactive local scans and scheduled background scans that report results to [Snyk Evo](https://evo.ai.snyk.io).

This guide covers both Agent Scan v0.5.x and v0.6 and later. v0.5.x remains supported for now but is planned for deprecation. Where behavior differs, the relevant version is called out explicitly.

## Quick Start

Run the command for the version you want to use:

### Agent Scan v0.6 and later

```bash
uvx snyk-agent-scan@latest
```

### Agent Scan v0.5.x

Pin a v0.5.x release so that a future `latest` release does not change the API or output format underneath an existing workflow. The examples use v0.5.17 as a concrete release:

```bash
uvx snyk-agent-scan@0.5.17
```

Both versions automatically discover supported agent configurations, including Claude Code/Desktop, Cursor, Gemini CLI, and Windsurf. Both also accept explicit MCP configuration or skill paths:

```bash
# Scan an MCP configuration
snyk-agent-scan ~/.vscode/mcp.json

# Scan a single agent skill
snyk-agent-scan ~/path/to/my/SKILL.md

# Scan all Claude skills
snyk-agent-scan ~/.claude/skills

# Scan MCP components but skip skills
snyk-agent-scan --no-skills
```

When running these examples through `uvx`, replace `snyk-agent-scan` with `uvx snyk-agent-scan@latest` for v0.6 and later or `uvx snyk-agent-scan@0.5.17` for v0.5.x.

## Scan and Background Modes

Agent Scan has two main modes of operation:

1. **Scan mode:** discovers and analyzes agents, MCP servers, and skills, then prints a report for review.
2. **Background mode (MDM):** scans machines at regular intervals and reports the results to Snyk Evo so security teams can monitor their agent supply chain centrally. To set this up, [contact us](https://evo.ai.snyk.io/#contact-us).

## How It Works

![Scanning overview](assets/scan.svg)

Agent Scan searches local agent configuration files for agents, skills, and MCP servers. It connects to MCP servers to retrieve their declared tools, prompts, resources, and resource templates. Skills are included by default; use `--no-skills` to skip them.

It then performs local checks and sends the data required for analysis to the Agent Scan API. Agent Scan does not store or log MCP tool-call usage data, including the contents or results of tool calls. By using Agent Scan, you agree to the Snyk [terms of use for Agent Scan](../TERMS.md).

The data sent for analysis differs by version:

### Agent Scan v0.5.x

Agent applications, skills, tool names, and descriptions are shared with Snyk. Results use issue codes and severity labels; see the [issue code reference](issue-codes.md). Operational errors use the separate [failure code reference](failure-codes.md).

### Agent Scan v0.6 and later

Discovered client information, MCP server configurations and signatures, and skill files are shared with Snyk. Secrets in configuration values and text are redacted before transmission. Results use scored risk indicators; see the [risk reference](risks.md). Operational errors remain separate in the [failure code reference](failure-codes.md).

### Env var placeholders in stdio server configs

A stdio MCP server's `env` block in a client config (`.claude.json`, `.mcp.json`,
etc.) can reference `${NAME}` to pull a value from whichever environment is
running the scan, instead of hardcoding a secret in the config file:

```json
{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "mcp-remote@0.3.0", "https://example.com/mcp", "--header", "Authorization:${AUTH_HEADER}"],
      "env": { "AUTH_HEADER": "${AUTH_HEADER}" }
    }
  }
}
```

`${AUTH_HEADER}` in the `env` value is substituted from the scanning
process's own environment variable of the same name at the moment the
server is spawned. Note the child process's env-var *key* (the left side,
`"AUTH_HEADER"` here) doesn't have to match the placeholder name on the
right — `"env": {"FOO_TOKEN": "${MY_SECRET}"}` is equally valid. If the
referenced variable isn't set when the scan runs, the placeholder is left
unexpanded and a warning is logged (visible with `--verbose`) rather than
silently connecting with a blank credential.

This only applies to `env` values. A value inside `args` (as in the
`mcp-remote` example above) is *not* expanded by Agent Scan itself --
`mcp-remote` and similar wrapper commands already resolve `${VAR}`
references in their own arguments from their own process environment, so
once the variable is present in the spawned process's environment (via the
`env` block), that resolution happens downstream, in the wrapper.

## CLI Usage

The command structure and most options are shared by both versions:

- **Default command:** `scan`; omit the subcommand to scan well-known agent configurations.
- **`inspect`:** discover components and inspect MCP capabilities without requesting security analysis.
- **Skills:** included by default; use `--no-skills` for MCP-only scanning.
- **`--ci`:** return a non-zero exit code when relevant findings or operational failures remain; use `--dangerously-run-mcp-servers` when consent cannot be provided interactively.
- **`--json`:** print machine-readable output; see [JSON output](json-output.md) for the versioned schemas.
- **`--show-analysis-results`:** force synchronous analysis so results are displayed for push-key scans, which otherwise submit asynchronously and return no local results. See [Push keys and results](cli-reference.md#push-keys-and-results).

Common examples:

```bash
# Scan all known MCP configurations and agent skills
snyk-agent-scan

# Scan a specific configuration file
snyk-agent-scan ~/custom/config.json

# Scan MCP components but skip skills
snyk-agent-scan --no-skills

# Inspect without requesting security analysis
snyk-agent-scan inspect

# Run in CI
snyk-agent-scan --ci --dangerously-run-mcp-servers
```

### Agent Scan v0.5.x differences

- Security findings use issue codes and severity labels.
- `--ignore-issues-codes` controls which security issue and operational failure codes affect the CI exit status.
- `--json` prints the path-keyed `ScanPathResult` format.

See the [v0.5.x CLI reference](cli-reference.md#agent-scan-v05x) for the complete list of commands, flags, defaults, and exit behavior.

### Agent Scan v0.6 and later differences

- Security findings use risk names and scores.
- `--ignore-risks` and `--ignore-failure-codes` independently control which risks and operational failures affect the CI exit status.
- Human-readable `scan` output is compact by default. Clean servers and skills show counts by entity or file type; risky components list only risk-connected entities or files and summarize the remainder. Pass `--show-full-discovery` to list every MCP entity and skill file. This flag does not affect JSON output or `inspect`, which already returns complete details.
- `--json` prints the `ScanResponse` format for `scan`; `inspect --json` remains a local inspection result.

See the [v0.6 and later CLI reference](cli-reference.md#agent-scan-v06-and-later) for the complete list of commands, flags, defaults, and exit behavior.
