<p align="center">
  <h1 align="center">
  mcp-scan
  </h1>
</p>

<p align="center">
  Discover and scan agent components on your machine for prompt injections<br/>
  and vulnerabilities (including agents, MCP servers, skills).
</p>

> **NEW** Read our [technical report on the emerging threats of the agent skill eco-system](.github/reports/skills-report.pdf) published together with mcp-scan 0.4, which adds support for scanning agent skills.

<p align="center">
  <a href="https://pypi.python.org/pypi/mcp-scan"><img src="https://img.shields.io/pypi/v/mcp-scan.svg" alt="mcp-scan"/></a>
  <a href="https://pypi.python.org/pypi/mcp-scan"><img src="https://img.shields.io/pypi/l/mcp-scan.svg" alt="mcp-scan license"/></a>
  <a href="https://pypi.python.org/pypi/mcp-scan"><img src="https://img.shields.io/pypi/pyversions/mcp-scan.svg" alt="mcp-scan python version requirements"/></a>
  <a href="https://agentaudit.dev/packages/mcp-scan"><img src="https://agentaudit.dev/api/badge/mcp-scan" alt="AgentAudit Security"/></a>
</p>

<div align="center">
  <img src=".github/mcp-scan-cmd-banner.png?raw=true" alt="MCP-Scan logo"/>
</div>

<br>

MCP-scan helps you keep an inventory of all your installed agent components (harnesses, MCP servers, skills) and scans them for common threats like prompt injections, sensitive data handling or malware payloads hidden natural language.

## Highlights

- Auto-discover MCP configurations, agent tools, skills
- Detects MCP Security Vulnerabilities:
  - Prompt Injection Attacks
  - Tool Poisoning Attacks
  - Toxic Flows
- Scan local STDIO MCP servers and remote HTTP/SSE MCP servers
- Detects Agent Skill Vulnerabilities:
  - Prompt Injection Attacks, Malware Payloads
  - Exposure to untrusted third parties (e.g. moltbook)
  - Sensitive Data Handling
  - Hard-coded secrets

## Quick Start

To get started, make sure you have uv [installed](https://docs.astral.sh/uv/getting-started/installation/) on your system.

### Scanning

To run a full scan of your machine (auto-discovers agents, MCP servers, skills), run:

```bash
uvx mcp-scan@latest --skills
```

This will scan for security vulnerabilities in servers, skills, tools, prompts, and resources. It will automatically discover a variety of agent configurations, including Claude Code/Desktop, Cursor, Gemini CLI and Windsurf. Omit `--skills` to skip skill analysis.

You can also scan particular configuration files:

```bash
 # scan mcp configurations
uvx mcp-scan@latest ~/.vscode/mcp.json
 # scan a single agent skill
uvx mcp-scan@latest --skills ~/path/to/my/SKILL.md
# scan all claude skills
uvx mcp-scan@latest --skills ~/.claude/skills
```

#### Example Run

[![MCP Scan for security vulnerabilities demo](demo.svg)](https://asciinema.org/a/716858)

## MCP Security Scanner Capabilities

MCP-Scan is a security scanning tool to both statically and dynamically scan and monitor your MCP connections. It checks them for common security vulnerabilities like [prompt injections](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), [tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) and [toxic flows](https://invariantlabs.ai/blog/mcp-github-vulnerability). Consult our detailed [Documentation](https://invariantlabs-ai.github.io/docs/mcp-scan) for more information.

MCp-Scan operates in two main modes which can be used jointly or separately:

1. `mcp-scan scan` statically scans all your installed servers for malicious tool descriptions and tools (e.g. [tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), cross-origin escalation, rug pull attacks, toxic flows).

   [Quickstart →](#server-scanning).

2. `mcp-scan proxy` continuously monitors your MCP connections in real-time, and can restrict what agent systems can do over MCP (tool call checking, data flow constraints, PII detection, indirect prompt injection etc.).

   [Quickstart →](#server-proxying).

<br/>
<br/>

<div align="center">
<img src="https://invariantlabs-ai.github.io/docs/mcp-scan/assets/proxy.svg" width="420pt" align="center"/>
<br/>
<br/>

_mcp-scan in proxy mode._

</div>

## Features

- Scanning of Claude, Cursor, Windsurf, and other file-based MCP client configurations
- Scanning for prompt injection attacks in tools and [tool poisoning attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) using [Guardrails](https://github.com/invariantlabs-ai/invariant?tab=readme-ov-file#analyzer)
- [Enforce guardrailing policies](https://invariantlabs-ai.github.io/docs/mcp-scan/guardrails-reference/) on MCP tool calls and responses, including PII detection, secrets detection, tool restrictions and entirely custom guardrailing policies.
- Audit and log MCP traffic in real-time via [`mcp-scan proxy`](#proxy)
- Detect cross-origin escalation attacks (e.g. [tool shadowing](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)), and detect and prevent [MCP rug pull attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), i.e. mcp-scan detects changes to MCP tools via hashing

### Server Proxying

Using `mcp-scan proxy`, you can monitor, log, and safeguard all MCP traffic on your machine. This allows you to inspect the runtime behavior of agents and tools, and prevent attacks from e.g., untrusted sources (like websites or emails) that may try to exploit your agents. mcp-scan proxy is a dynamic security layer that runs in the background, and continuously monitors your MCP traffic.

#### Example Run

<img width="903" alt="image" src="https://github.com/user-attachments/assets/63ac9632-8663-40c3-a765-0bfdfbdf9a16" />

#### Enforcing Guardrails

You can also add guardrailing rules, to restrict and validate the sequence of tool uses passing through proxy.

For this, create a `~/.mcp-scan/guardrails_config.yml` with the following contents:

```yml
<client-name>: # your client's shorthand (e.g., cursor, claude, windsurf)
  <server-name>: # your server's name according to the mcp config (e.g., whatsapp-mcp)
    guardrails:
      secrets: block # block calls/results with secrets

      custom_guardrails:
        - name: "Filter tool results with 'error'"
          id: "error_filter_guardrail"
          action: block # or just 'log'
          content: |
            raise "An error was found." if:
              (msg: ToolOutput)
              "error" in msg.content
```

From then on, all calls proxied via `mcp-scan proxy` will be checked against your configured guardrailing rules for the current client/server.

Custom guardrails are implemented using Invariant Guardrails. To learn more about these rules, see the [official documentation](https://invariantlabs-ai.github.io/docs/mcp-scan/guardrails-reference/).

## How It Works

### Scanning

MCP-Scan `scan` searches through your configuration files to find MCP server configurations. It connects to these servers and retrieves tool descriptions.

It then scans tool descriptions, both with local checks and by invoking Invariant Guardrailing via an API. For this, tool names and descriptions are shared with invariantlabs.ai. By using MCP-Scan, you agree to the invariantlabs.ai [terms of use](./TERMS.md) and [privacy policy](https://invariantlabs.ai/privacy-policy).

Invariant Labs is collecting data for security research purposes (only about tool descriptions and how they change over time, not your user data). Don't use MCP-scan if you don't want to share your tools. Additionally, a unique, persistent, and anonymous ID is assigned to your scans for analysis. You can opt out of sending this information using the `--opt-out` flag.

MCP-scan does not store or log any usage data, i.e. the contents and results of your MCP tool calls.

### Proxying

For runtime monitoring using `mcp-scan proxy`, MCP-Scan can be used as a proxy server. This allows you to monitor and guardrail system-wide MCP traffic in real-time. To do this, mcp-scan temporarily injects a local [Invariant Gateway](https://github.com/invariantlabs-ai/invariant-gateway) into MCP server configurations, which intercepts and analyzes traffic. After the `proxy` command exits, Gateway is removed from the configurations.

You can also configure guardrailing rules for the proxy to enforce security policies on the fly. This includes PII detection, secrets detection, tool restrictions, and custom guardrailing policies. Guardrails and proxying operate entirely locally using [Guardrails](https://github.com/invariantlabs-ai/invariant) and do not require any external API calls.

## CLI parameters

MCP-scan provides the following commands:

```
mcp-scan - Security scanner for Model Context Protocol servers and tools
```

### Common Options

These options are available for all commands:

```
--storage-file FILE    Path to store scan results and whitelist information (default: ~/.mcp-scan)
--base-url URL         Base URL for the verification server
--verbose              Enable detailed logging output
--print-errors         Show error details and tracebacks
--full-toxic-flows     Show all tools that could take part in toxic flow. By default only the top 3 are shown.
--json                 Output results in JSON format instead of rich text
```

### Commands

#### scan (default)

Scan MCP configurations for security vulnerabilities in tools, prompts, and resources.

```
mcp-scan [CONFIG_FILE...]
```

Options:

```
--checks-per-server NUM           Number of checks to perform on each server (default: 1)
--server-timeout SECONDS          Seconds to wait before timing out server connections (default: 10)
--suppress-mcpserver-io BOOL      Suppress stdout/stderr from MCP servers (default: True)
--skills                          Autodetects and analyzes skills
--skills PATH_TO_SKILL_MD_FILE    Analyzes the specific skill
--skills PATHS_TO_DIRECTORY       Recursively detects and analyzes all skills in the directory
```

#### proxy

Run a proxy server to monitor and guardrail system-wide MCP traffic in real-time. Temporarily injects [Gateway](https://github.com/invariantlabs-ai/invariant-gateway) into MCP server configurations, to intercept and analyze traffic. Removes Gateway again after the `proxy` command exits.

This command requires the `proxy` optional dependency (extra).

- Run via uvx:
  ```bash
  uvx --with "mcp-scan[proxy]" mcp-scan@latest proxy
  ```
  This installs the `proxy` extra into an uvx-managed virtual environment, not your current shell venv.

Options:

```
CONFIG_FILE...                  Path to MCP configuration files to setup for proxying.
--pretty oneline|compact|full   Pretty print the output in different formats (default: compact)
```

#### inspect

Print descriptions of tools, prompts, and resources without verification.

```
mcp-scan inspect [CONFIG_FILE...]
```

Options:

```
--server-timeout SECONDS      Seconds to wait before timing out server connections (default: 10)
--suppress-mcpserver-io BOOL  Suppress stdout/stderr from MCP servers (default: True)
```

#### whitelist

Manage the whitelist of approved entities. When no arguments are provided, this command displays the current whitelist.

```
# View the whitelist
mcp-scan whitelist

# Add to whitelist
mcp-scan whitelist TYPE NAME HASH

# Reset the whitelist
mcp-scan whitelist --reset
```

Options:

```
--reset                       Reset the entire whitelist
--local-only                  Only update local whitelist, don't contribute to global whitelist
```

Arguments:

```
TYPE                          Type of entity to whitelist: "tool", "prompt", or "resource"
NAME                          Name of the entity to whitelist
HASH                          Hash of the entity to whitelist
```

#### help

Display detailed help information and examples.

```bash
mcp-scan help
```

### Examples

```bash
# Scan all known MCP configs
mcp-scan

# Scan a specific config file
mcp-scan ~/custom/config.json

# Just inspect tools without verification
mcp-scan inspect

# View whitelisted tools
mcp-scan whitelist

# Whitelist a tool
mcp-scan whitelist tool "add" "a1b2c3..."
```

## Demo

This repository includes a vulnerable MCP server that can demonstrate Model Context Protocol security issues that MCP-Scan finds.

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

3. Run MCP-Scan: `uvx --python 3.13 mcp-scan@latest scan --full-toxic-flows mcp.json`

Note: if you place the `mcp.json` configuration filepath elsewhere then adjust the `args` path inside the MCP server configuration to reflect the path to the MCP Server (`demoserver/server.py`) as well as the `uvx` command that runs MCP-Scan CLI with the correct filepath to `mcp.json`.

## MCP-Scan is closed to contributions

MCP-Scan can currently no longer accept external contributions. We are focused on stabilizing releases.
We welcome suggestions, bug reports, or feature requests as GitHub issues.

## Development Setup

To run this package from source, follow these steps:

```bash
uv run pip install -e .
uv run -m src.mcp_scan.cli
```

For proxy functionality (e.g., `mcp-scan proxy`, `mcp-scan server`), install with the proxy extra:

```bash
uv run pip install -e .[proxy]
```

## Including MCP-scan results in your own project / registry

If you want to include MCP-scan results in your own project or registry, please reach out to the team via `mcpscan@invariantlabs.ai`, and we can help you with that.
For automated scanning we recommend using the `--json` flag and parsing the output.

## Further Reading

- [Introducing MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan)
- [MCP Security Notification Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)
- [MCP Prompt Injection](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)
- [Toxic Flow Analysis](https://invariantlabs.ai/blog/toxic-flow-analysis)

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
