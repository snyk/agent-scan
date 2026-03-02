# Issue Code Reference

This is the reference for all issues that can be detected via `snyk-agent-scan`.

## Issues

Issues are identified security threats that result in compromised MCP servers or skills, and should be addressed as soon as possible.

<a id="E001"></a>

### E001: Prompt injection in tool description

![E001 | issue](https://img.shields.io/badge/E001-issue-red) ![MCP](https://img.shields.io/badge/MCP-blue)

Detected a prompt injection in the tool description. The tool should be deactivated immediately.

This is a form of [tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) where a malicious MCP server embeds hidden adversarial instructions inside its tool descriptions to hijack the agent. Unlike [E003](#E003), which detects overt behavioral directives, E001 targets deceptive injections that are designed to be invisible to the user.

<a id="E002"></a>

### E002: Cross-server tool reference (tool shadowing)

![E002 | issue](https://img.shields.io/badge/E002-issue-red) ![MCP](https://img.shields.io/badge/MCP-blue)

A tool from one MCP server references a tool belonging to a different server. MCP servers should be self-contained, when a server's tool description mentions tools from another server, it can poison the behavior of those trusted tools.

This is a [tool shadowing attack](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), where a malicious server overrides or interferes with the behavior of a legitimate tool from another server.

<a id="E003"></a>

### E003: Tool description hijacks agent behavior

![E003 | issue](https://img.shields.io/badge/E003-issue-red) ![MCP](https://img.shields.io/badge/MCP-blue)

The tool description contains overt instructions that attempt to hijack the agent into performing a set of potentially dangerous actions. Tools should be at the disposal of the agent and should not provide it with directives.

Unlike [E001](#E001), which targets hidden adversarial injections, E003 detects tool descriptions that go beyond describing the tool's functionality and instead try to force the agent into specific behaviors — for example, instructing it to always call certain tools, avoid safety checks, or perform actions unrelated to the tool's stated purpose. These directives may not be hidden, but are still dangerous because they override the agent's autonomy.

<a id="E004"></a>

### E004: Prompt injection in skill

![E004 | issue](https://img.shields.io/badge/E004-issue-red) ![Skills](https://img.shields.io/badge/Skills-purple)

Detected a prompt injection in the skill instructions. The skill contains hidden or deceptive instructions that fall outside its stated purpose and attempt to override the agent's safety guidelines or intended behavior.

<a id="E005"></a>

### E005: Suspicious download URL in skill

![E005 | issue](https://img.shields.io/badge/E005-issue-red) ![Skills](https://img.shields.io/badge/Skills-purple)

Detected a suspicious URL in the skill instructions that could lead the agent to download and execute malicious scripts or binaries. This includes links to executables from untrusted sources, typosquatting of official packages, URL shorteners that obscure the destination, and personal file hosting services.

Such links pose a significant risk as they indicate that Agent Scan cannot verify the full behavior of a skill (analysis is limited to the skill's own content, not externally referenced dependencies).

<a id="E006"></a>

### E006: Malicious code patterns in skill

![E006 | issue](https://img.shields.io/badge/E006-issue-red) ![Skills](https://img.shields.io/badge/Skills-purple)

Detected high-risk code patterns in the skill content — including its prompts, tool definitions, and resources — such as data exfiltration, backdoors, remote code execution, credential theft, system compromise, supply chain attacks, and obfuscation techniques.

## Warnings

Warnings are potential security threats. They do not necessarily indicate a security issue, but should be investigated.

<a id="W001"></a>

### W001: Suspicious words in tool description

![W001 | warning](https://img.shields.io/badge/W001-warning-yellow) ![MCP](https://img.shields.io/badge/MCP-blue)

The tool description contains words commonly associated with prompt injection attempts, such as "important" or "crucial". These words are often used in tool poisoning attacks to draw the agent's attention and override its normal decision-making process.

While the presence of these words alone does not confirm malicious intent, it is a signal worth investigating, especially when combined with unusual tool descriptions.

<a id="W002"></a>

### W002: Too many entities

![W002 | warning](https://img.shields.io/badge/W002-warning-yellow) ![MCP](https://img.shields.io/badge/MCP-blue)

The server exposes more than 100 entities (tools, resources, and prompts combined). Agent performance is expected to degrade when too many tools are available, as the agent's context becomes cluttered and tool selection becomes unreliable. A large number of entities also increases the attack surface.

<a id="W007"></a>

### W007: Insecure credential handling in skill

![W007 | warning](https://img.shields.io/badge/W007-warning-yellow) ![Skills](https://img.shields.io/badge/Skills-purple)

The skill handles credentials insecurely by requiring the agent to include secret values verbatim in its generated output. This exposes credentials in the agent's context and conversation history, creating a risk of data exfiltration.

<a id="W008"></a>

### W008: Hardcoded secrets in skill

![W008 | warning](https://img.shields.io/badge/W008-warning-yellow) ![Skills](https://img.shields.io/badge/Skills-purple)

Detected sensitive credentials directly embedded within the skill content, such as API keys, access tokens, private keys, or service-specific secrets. Secrets should never be hardcoded in plain text within skill instructions.

<a id="W009"></a>

### W009: Direct financial execution capability

![W009 | warning](https://img.shields.io/badge/W009-warning-yellow) ![Skills](https://img.shields.io/badge/Skills-purple)

The skill is specifically designed for direct financial operations, giving the agent the ability to move money or execute financial transactions — such as payment processing, cryptocurrency operations, banking integrations, or market order execution.

<a id="W011"></a>

### W011: Exposure to untrusted third-party content

![W011 | warning](https://img.shields.io/badge/W011-warning-yellow) ![Skills](https://img.shields.io/badge/Skills-purple)

The skill exposes the agent to untrusted, user-generated content from public third-party sources, creating a risk of indirect prompt injection. This includes browsing arbitrary URLs, reading social media posts or forum comments, and analyzing content from unknown websites.

<a id="W012"></a>

### W012: Unverifiable external dependency

![W012 | warning](https://img.shields.io/badge/W012-warning-yellow) ![Skills](https://img.shields.io/badge/Skills-purple)

The skill fetches instructions or code from an external URL at runtime, and the fetched content directly controls the agent's prompts or executes code. This dynamic dependency allows the external source to modify the agent's behavior without any changes to the skill itself.

Some skills implement this behavior to enable auto-update mechanisms, however, it allows skills authors to change skill instructions at any point in time, disabling any form of version pinning and allowing for potential remote instruction changes (RCE risk).

<a id="W013"></a>

### W013: System service modification

![W013 | warning](https://img.shields.io/badge/W013-warning-yellow) ![Skills](https://img.shields.io/badge/Skills-purple)

The skill prompts the agent to compromise the security or integrity of the user's machine by modifying system-level services or configurations, such as obtaining elevated privileges, altering startup scripts, or changing system-wide settings. This may be legitimate in rare cases, but should be investigated.

## Toxic Flows

A toxic flow is a threat that arises when multiple tools (that are benign individually) can be used in combination by an attacker in a malicious way.

For each tool, Agent Scan classifies whether it can act as an **untrusted content** source (returns data from external or user-controlled sources), a **private data** accessor (exposes sensitive user data), a **public sink** (sends data to external or public destinations), or a **destructive** action (performs irreversible operations). Toxic flows are then detected when dangerous combinations of these classifications exist within the same agent.

<a id="TF001"></a>

### TF001: Data Leak Toxic Flow

![TF001 | issue](https://img.shields.io/badge/TF001-issue-red) ![MCP](https://img.shields.io/badge/MCP-blue)

A Data Leak Toxic Flow allows an attacker to exfiltrate private data from the user through the agent. This flow requires three components to be present across the agent's available tools:

- An **untrusted content** tool: A tool whose output could be malicious, such as fetching information from a webpage set up by an attacker.
- A **private data** tool: A tool that exposes private data to the agent, such as reading files from the user's machine or querying a database.
- A **public sink** tool: A tool that the agent can use to send information to external parties, such as sending a message on WhatsApp, posting to a public repository, or making an HTTP request.

The attack works as follows: the agent uses the **untrusted content** tool for an unrelated user task. The tool's output contains a prompt injection that compromises the agent. The compromised agent then uses the **private data** tool to access sensitive information, and finally leaks it through the **public sink** tool.

> **Note:** A single tool may act as **untrusted content**, **private data**, and **public sink** simultaneously.

<a id="TF002"></a>

### TF002: Destructive Toxic Flow

![TF002 | issue](https://img.shields.io/badge/TF002-issue-red) ![MCP](https://img.shields.io/badge/MCP-blue)

A Destructive Toxic Flow allows an attacker to cause irreversible damage through the agent. This flow requires two components:

- An **untrusted content** tool: A tool whose output could be malicious, such as fetching information from a webpage set up by an attacker.
- A **destructive** tool: An irreversible tool that can cause permanent damage, such as deleting files, sending money, or modifying critical system state.

The attack works as follows: the agent uses the **untrusted content** tool for an unrelated user task. The tool's output contains a prompt injection that compromises the agent. The compromised agent then uses the **destructive** tool to cause irreversible damage to the environment.

> **Note:** A single tool may act as **untrusted content** and **destructive** simultaneously.

## System

System codes indicate scanner status information, configuration issues, or analysis limitations. These are not security threats but may affect the quality of the scan.

<a id="W003"></a>

### W003: Could not identify MCP server

![W003 | system](https://img.shields.io/badge/W003-system-white) ![MCP](https://img.shields.io/badge/MCP-blue)

Agent Scan could not determine the identity of this MCP server in terms of matching to a package manager or registry. This typically indicates custom, homebrew or non-standard server implementations that are not published via Docker/PyPI/NPM/etc which can be a risk.

<a id="W004"></a>

### W004: MCP server not in Agent Scan registry

![W004 | system](https://img.shields.io/badge/W004-system-white) ![MCP](https://img.shields.io/badge/MCP-blue)

The MCP server was identified but is not present in Agent Scan's registry of known servers. Security analysis is applied to the server as best as possible, but it is not as thorough as for servers that are in the registry.

<a id="W005"></a>

### W005: Tool not in registry

![W005 | system](https://img.shields.io/badge/W005-system-white) ![MCP](https://img.shields.io/badge/MCP-blue)

The tool was not found in Agent Scan's registry, even though the server it belongs to is registered. This may indicate that the tool was recently added, renamed, or is not part of the server's expected toolset. It could also indicate a rug pull attack where a server has been modified after initial registration.

<a id="W006"></a>

### W006: Could not run MCP server

![W006 | system](https://img.shields.io/badge/W006-system-white) ![MCP](https://img.shields.io/badge/MCP-blue)

Agent Scan was unable to start the MCP server to retrieve its tools and descriptions. This may happen when the server binary is missing, dependencies like docker or NPM are not installed, or the server configuration is incorrect. Security analysis may still be available if the server identity can be determined and looked up in the registry.

<a id="X001"></a>

### X001: Could not reach analysis server

![X001 | system](https://img.shields.io/badge/X001-system-white)

The backend of `snyk-agent-scan` could not be reached. This might happen when:

- The `snyk-agent-scan` backend is down.
- You manually selected the backend using the `--base-url` flag, and the backend you selected cannot be reached.
- There is no connection to the internet.

<a id="X002"></a>

### X002: Whitelisted

![X002 | system](https://img.shields.io/badge/X002-system-white)

(deprecated) The tool has been whitelisted. It will now show in green even if issues are detected.
