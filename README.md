<p align="center">
  <h1 align="center">
  Snyk Agent Scan
  </h1>
</p>

<p align="center">
  Discover and scan agent components on your machine for prompt injections<br/>
  and vulnerabilities (including agents, MCP servers, skills).
</p>

> **NEW** Read our [technical report on the emerging threats of the agent skill eco-system](.github/reports/skills-report.pdf) published together with Agent Scan 0.4, which adds support for scanning agent skills.

<p align="center">
  <a href="https://pypi.python.org/pypi/snyk-agent-scan"><img src="https://img.shields.io/pypi/v/snyk-agent-scan.svg" alt="snyk-agent-scan"/></a>
  <a href="https://pypi.python.org/pypi/snyk-agent-scan"><img src="https://img.shields.io/pypi/l/snyk-agent-scan.svg" alt="snyk-agent-scan license"/></a>
  <a href="https://pypi.python.org/pypi/snyk-agent-scan"><img src="https://img.shields.io/pypi/pyversions/snyk-agent-scan.svg" alt="snyk-agent-scan python version requirements"/></a>
</p>

<div align="center">
  <img width="1304" height="976" alt="agent-scan-pretty" src="https://github.com/user-attachments/assets/49c32115-703c-465f-bb09-1b6bae852253" />
</div>

<br>

Agent Scan helps you keep an inventory of all your installed agent components (harnesses, MCP servers, and skills) and scans them for common threats like prompt injections, sensitive data handling, or malware payloads hidden in natural language. **By default** it focuses on MCP servers; add `--skills` to autodiscover and scan agent skills.

## Security Warning

> **⚠️ IMPORTANT: Scanning MCP configurations will execute the commands defined in them.**
>
> When Agent Scan scans an MCP configuration file, it starts the stdio MCP servers by executing the commands and arguments specified in the config. This is necessary to retrieve tool descriptions and perform security analysis.
>
> **Recommendations:**
> - **Run scans inside a sandbox** (Docker container, VM, or disposable environment) when evaluating untrusted or third-party MCP configs
> - **Review the consent prompt carefully** during interactive scans, it shows the exact command and arguments that will be executed for each server
> - **Use `--dangerously-run-mcp-servers`** only in trusted environments where you've verified all MCP server commands
>
> By default, Agent Scan requires explicit user consent (y/n) before starting each stdio MCP server during interactive runs. This gives you control over what gets executed on your system.

## Highlights

- Auto-discover MCP configurations, agent tools, skills
- Scanning of Claude, Cursor, Windsurf, Gemini CLI, Amp, Amazon Q, and other agents.
- Detects [15+ distinct security risks](docs/issue-codes.md) across MCP servers and agent skills:
  - MCP: [Prompt Injection](docs/issue-codes.md#E001), [Tool Poisoning](docs/issue-codes.md#E001), [Tool Shadowing](docs/issue-codes.md#E002), [Toxic Flows](docs/issue-codes.md#ToxicFlows)
  - Skills: [Prompt Injection](docs/issue-codes.md#E004), [Malware Payloads](docs/issue-codes.md#E006), [Untrusted Content](docs/issue-codes.md#W011), [Credential Handling](docs/issue-codes.md#W007), [Hardcoded Secrets](docs/issue-codes.md#W008)

## Supported agents and capabilities

Agent Scan auto-discovers agents and their capabilities (MCP servers or skills) when their install paths exist. The table reflects [well-known agent definitions](src/agent_scan/well_known_clients.py).

- **✓**: at least one path is defined for that capability.
- **✗**: the agent is listed for that OS but has no paths for that capability.
- **—**: that agent is not included for that OS.
- **Skills** columns apply when using `--skills`.

| Agent | macOS MCP | macOS Skills | Linux MCP | Linux Skills | Windows MCP | Windows Skills |
| --- | :---: | :---: | :---: | :---: | :---: | :---: |
| Windsurf | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Cursor | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| VS Code | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Claude Desktop | ✓ | ✗ | — | — | ✓ | ✗ |
| Claude Code | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Gemini CLI | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| OpenClaw | ✗ | ✓ | ✗ | ✓ | ✗ | ✓ |
| Amp | ✗ | ✓ | ✗ | ✓ | ✗ | ✓ |
| Kiro | ✓ | ✗ | ✓ | ✗ | ✓ | ✗ |
| OpenCode | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Antigravity | ✓ | ✗ | ✓ | ✗ | ✓ | ✗ |
| Codex | ✗ | ✓ | ✗ | ✓ | — | — |
| Amazon Q | ✓ | ✗ | ✓ | ✗ | — | — |

## Quick Start

To get started:

1. **Sign up at [Snyk](https://snyk.io)** and get an API token from [https://app.snyk.io/account](https://app.snyk.io/account) (API Token → KEY → click to show).
2. **Set the token as an environment variable** before running any scan:
   ```bash
   export SNYK_TOKEN=your-api-token-here
   ```
3. Have [uv](https://docs.astral.sh/uv/getting-started/installation/) installed on your system.

### Scanning

To run a full scan of your machine (auto-discovers agents, MCP servers, skills), run:

```bash
uvx snyk-agent-scan@latest
```


This will scan for security vulnerabilities in MCP servers, tools, prompts, and resources. It will automatically discover a variety of agent configurations, including Claude Code/Desktop, Cursor, Gemini CLI, and Windsurf.

To also auto-discover and scan agent skills, pass the `--skills` flag:

```bash
uvx snyk-agent-scan@latest --skills
```

You can also scan particular MCP configuration files or skills:

```bash
# scan a specific mcp configuration
uvx snyk-agent-scan@latest ~/.vscode/mcp.json
# scan a single agent skill
uvx snyk-agent-scan@latest --skills ~/path/to/my/SKILL.md
# scan all claude skills
uvx snyk-agent-scan@latest --skills ~/.claude/skills
```

#### Example Run

[![Agent Scan security vulnerabilities demo](demo.svg)](https://asciinema.org/a/716858)

## Scanner Capabilities

Agent Scan is a security scanning tool to both scan and inspect the supply chain of agent components on your machine. It scans for common security vulnerabilities like prompt injections, tool poisoning, toxic flows, or vulnerabilities in agent skills.

Agent Scan operates in two main modes which can be used jointly or separately:

1. **Scan Mode**: The CLI command `snyk-agent-scan` scans the current machine for agents and agent components such as skills and MCP servers. Upon completion, it will output a comprehensive report for the user to review.

2. **Background Mode** (MDM, Crowdstrike). Agent Scan scans the machine in regular intervals in the background, and reports the results to a [Snyk Evo](https://evo.ai.snyk.io) instance. This can be used by security teams to monitor the company-wide agent supply chain in a central location. To set this up, please [contact us](https://evo.ai.snyk.io/#contact-us).

## How It Works

### Scanning

Agent Scan searches through your local agent's configuration files to find agents, skills, and MCP servers. For MCP, it connects to servers and retrieves tool descriptions.

#### Interactive Consent for MCP Servers

> **⚠️ Security Note**: Scanning an MCP config executes the commands defined in it. Always review what will be executed before approving.

By default, Agent Scan prompts for user consent before starting each stdio MCP server during interactive runs. This consent flow:

- Shows the server name, command, and environment variables (redacted) that will be executed
- Allows you to approve or decline each server individually
- Prevents potentially untrusted servers from running without your explicit permission
- Records declined servers with a `user_declined` error (they are never started)

**Best Practices:**
- Review the command and arguments carefully before approving
- When scanning untrusted or third-party MCP configs, run Agent Scan inside a sandbox (Docker, VM, or disposable environment)
- Decline any servers with unfamiliar or suspicious commands

For non-interactive environments (e.g., CI/CD pipelines), you must use the `--dangerously-run-mcp-servers` flag to bypass the consent prompt and start all servers automatically. **Only use this flag in trusted environments where all MCP server commands have been verified.**

#### Analysis and Validation

Agent Scan validates the components, both with local checks and by invoking the Agent Scan API. For this, skills, agent applications, tool names, and descriptions are shared with Snyk. By using Agent Scan, you agree to the Snyk [terms of use for Agent Scan](./TERMS.md).

A unique, persistent, and anonymous ID is assigned to your scans for analysis. You can opt out of sending this information using the `--opt-out` flag.

Agent Scan does not store or log any usage data, i.e. the contents and results of your MCP tool calls.

## CLI Parameters

Agent Scan provides the following commands:

```
snyk-agent-scan - Security scanner for agents, MCP servers, and skills
```

### Common Options

These options are available for all commands:

```
--storage-file FILE    Path to store scan results and scanner state (default: ~/.mcp-scan)
--base-url URL         Base URL for the verification server
--verbose              Enable detailed logging output
--print-errors         Show error details and tracebacks
--json                 Output results in JSON format instead of rich text
```

### Commands

#### scan (default)

Scan MCP configurations for security vulnerabilities in tools, prompts, and resources.

```
snyk-agent-scan scan [CONFIG_FILE...]
```

Options:

```
--skills                          Also scan agent skills (default: off)
--checks-per-server NUM           Number of checks to perform on each server (default: 1)
--server-timeout SECONDS          Seconds to wait before timing out server connections (default: 10)
--suppress-mcpserver-io BOOL      Suppress stderr from stdio MCP servers (stdout carries the JSON-RPC protocol
                                  and is never shown). Default: False for interactive runs (stderr is streamed
                                  with a [server-name] prefix), True otherwise.
--dangerously-run-mcp-servers     ⚠️ DANGER: Skip the interactive consent prompt and automatically start every
                                  stdio MCP server listed in the scanned configs. Only use in trusted
                                  environments where you've verified all MCP server commands.
```

#### inspect

Print descriptions of tools, prompts, and resources without verification.

```
snyk-agent-scan inspect [CONFIG_FILE...]
```

Options:

```
--server-timeout SECONDS          Seconds to wait before timing out server connections (default: 10)
--suppress-mcpserver-io BOOL      Suppress stderr from stdio MCP servers (stdout carries the JSON-RPC protocol
                                  and is never shown). Default: False for interactive runs (stderr is streamed
                                  with a [server-name] prefix), True otherwise.
--dangerously-run-mcp-servers     ⚠️ DANGER: Skip the interactive consent prompt and automatically start every
                                  stdio MCP server listed in the scanned configs. Only use in trusted
                                  environments where you've verified all MCP server commands.
```

#### help

Display detailed help information and examples.

```bash
snyk-agent-scan help
```

### Examples

```bash
# Scan all known MCP configs
snyk-agent-scan

# Scan all known MCP configs and agent skills
snyk-agent-scan --skills

# Scan a specific config file
snyk-agent-scan ~/custom/config.json

# Scan a specific skill file
snyk-agent-scan --skills ~/path/to/my/SKILL.md

# Scan a directory for skills
snyk-agent-scan --skills ~/.claude/skills

# Just inspect tools without verification
snyk-agent-scan inspect

# Skip consent prompts and run all servers (ONLY for CI/CD or fully trusted environments)
snyk-agent-scan --dangerously-run-mcp-servers

# Suppress MCP server stderr output during scanning
snyk-agent-scan --suppress-mcpserver-io=true

# CI mode (requires --dangerously-run-mcp-servers in non-interactive environments)
snyk-agent-scan --ci --dangerously-run-mcp-servers
```

## Demo

This repository includes a vulnerable MCP server that can demonstrate Model Context Protocol security issues that Agent Scan finds.

How to demo MCP security issues?

1. Clone this repository
2. Create an `mcp.json` config file in the cloned git repository root directory with the following contents:

```jsonc
{
  "mcpServers": {
    "Demo MCP Server": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "mcp", "run", "demoserver/server.py"],
    },
  },
}
```

3. Run Agent Scan: `uvx --python 3.13 snyk-agent-scan@latest scan --full-toxic-flows mcp.json`

Note: if you place the `mcp.json` configuration filepath elsewhere then adjust the `args` path inside the MCP server configuration to reflect the path to the MCP Server (`demoserver/server.py`) as well as the `uvx` command that runs Agent Scan with the correct filepath to `mcp.json`.

## Agent Scan is closed to contributions

Agent Scan does not accept external contributions at this time.

We welcome suggestions, bug reports, or feature requests as GitHub issues.

## Development Setup

To run Agent Scan from source, follow these steps:

```bash
uv run pip install -e .
uv run -m src.agent_scan.cli
```

## Including Agent Scan results in your own project / registry

If you want to include Agent Scan results in your own project or registry, please [reach out](https://evo.ai.snyk.io/#contact-us). There are designated APIs for this purpose. Using the standard Agent Scan API for large scale scanning is considered abuse and will result in your account being blocked.

## Documentation

- [Scanning](docs/scanning.md) — How scanning works, CLI parameters, and usage examples.
- [Issue Codes](docs/issue-codes.md) — Reference for all security issues detected by Agent Scan.

## Further Reading

- [Introducing MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan)
- [MCP Security Notification Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)
- [MCP Prompt Injection](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)
- [Toxic Flow Analysis](https://invariantlabs.ai/blog/toxic-flow-analysis)
- [Skills Report](.github/reports/skills-report.pdf)

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
