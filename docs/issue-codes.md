# Issue Code Reference

This is the reference for all issues that can be detected via `snyk-agent-scan`.

---

## Compromised MCP Servers

These issues hilight that the installed MCP server is acting maliciously. This yields a very important security threat, as it effectivly exposes a successful supply chain attack

<a id="E001"></a>

### ![E001 | critical](https://img.shields.io/badge/E001-critical-red) ![MCP](https://img.shields.io/badge/MCP-blue) Prompt injection in tool description

Detected a prompt injection in the tool description. The tool should be deactivated immediately.

This is a form of [tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) where a malicious MCP server embeds hidden adversarial instructions inside its tool descriptions to hijack the agent. These injections are designed to be invisible to the user while manipulating the agent's behavior.

<a id="E002"></a>

### ![E002 | high](https://img.shields.io/badge/E002-high-orange) ![MCP](https://img.shields.io/badge/MCP-blue) Cross-server tool reference (tool shadowing)

A tool from one MCP server references a tool belonging to a different server. MCP servers should be self-contained, when a server's tool description mentions tools from another server, it can poison the behavior of those trusted tools.

This is a [tool shadowing attack](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks), where a malicious server overrides or interferes with the behavior of a legitimate tool from another server.

<a id="W001"></a>

### ![W001 | low](https://img.shields.io/badge/W001-low-lightgray) ![MCP](https://img.shields.io/badge/MCP-blue) Suspicious words in tool description

The tool description contains words commonly associated with prompt injection attempts, such as "important", "crucial", "critical", "vital", "urgent", "ignore", "disregard", "override", or "bypass". These words are often used in tool poisoning attacks to draw the agent's attention and override its normal decision-making process.

While the presence of these words alone does not confirm malicious intent, it is a signal worth investigating, especially when combined with unusual tool descriptions.

---

<a id="ToxicFlows">

## Toxic Flows

Research from [Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability) and [Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) demonstrates how a critical vulnerability arises when an agent simultaneously has: exposure to untrusted content, access to private data, and the ability to communicate with the internet. This combination is referred to as a toxic flow.

In practice, most agents possess all three of these characteristics and are therefore inherently vulnerable. For this reason, our analysis focuses on each component individually. We flag servers that expose the agent to untrusted data ([W015](#W015), [W016](#W016)); servers that expose particularly sensitive private data that should be excluded from the agent's context ([W017](#W017), [W018](#W018)); and servers with potentially destructive capabilities ([W019](#W019), [W020](#W020)). We currently do not separately flag internet communication capabilities, as most agents include network access tools (such as curl) by default.

<a id="W015"></a>

### ![W015 | medium](https://img.shields.io/badge/W015-medium-yellow) ![MCP](https://img.shields.io/badge/MCP-blue) Untrusted content detected

The MCP server exposes the agent to potentially untrusted content from unverified third-party data sources. This creates a risk of indirect prompt injection, where malicious content from external sources could manipulate the agent's behavior.

High-confidence detection indicates tools that clearly fetch or process data from user-controllable or public sources without adequate sanitization.

<a id="W016"></a>

### ![W016 | low](https://img.shields.io/badge/W016-low-lightgray) ![MCP](https://img.shields.io/badge/MCP-blue) Potential untrusted content detected

Lower-confidence detection of potential untrusted content exposure. The MCP server may expose the agent to content from third-party sources, but the risk is less certain than [W015](#W015).

This warning suggests investigating whether the tool properly validates and sanitizes external data before presenting it to the agent.

<a id="W017"></a>

### ![W017 | medium](https://img.shields.io/badge/W017-medium-yellow) ![MCP](https://img.shields.io/badge/MCP-blue) Sensitive data exposure

The MCP server's explicit, named purpose is to integrate with and retrieve highly sensitive or non-public information, such as personal communications (emails, direct messages, private chat histories), financial records (bank details, account balances), or credential vaults (passwords, API keys, secure tokens). This exposes critically private user data directly into the agent's context.

Loading sensitive data into an AI agent's context dramatically increases the risk of unauthorized disclosure through prompt injection attacks, logging leaks, or model provider access. Once private emails, credentials, or financial information enters the agent's session, a single exploit or misconfiguration can exfiltrate confidential data to attackers or expose it in unintended system outputs.

<a id="W018"></a>

### ![W018 | low](https://img.shields.io/badge/W018-low-lightgray) ![MCP](https://img.shields.io/badge/MCP-blue) Workspace data exposure

The MCP server grants access to tools that retrieve local workspace files, project code, or user-managed data stores. While less sensitive than personal communications or financial records ([W017](#W017)), these tools still expose non-public information such as proprietary code, local notes, or development artifacts into the agent's context.

Loading workspace data into an AI agent's context introduces risk of intellectual property leakage or inadvertent disclosure of internal project details. If the agent is compromised through prompt injection or logging vulnerabilities, attackers can access proprietary source code, architectural decisions, or internal documentation that should remain confidential.

<a id="W019"></a>

### ![W019 | medium](https://img.shields.io/badge/W019-medium-yellow) ![MCP](https://img.shields.io/badge/MCP-blue) Destructive capabilities

The MCP server grants access to tools that can modify shared infrastructure, execute arbitrary system commands, or affect other users and team resources. This includes capabilities such as executing arbitrary system shell commands, interacting with a user's live/authenticated web browser, modifying state in shared team SaaS applications (e.g., shared project boards, team repositories), or triggering irreversible financial transactions.

Granting an AI agent access to shared infrastructure or system-level execution creates risk of widespread service disruption, data corruption, or financial loss. If the agent hallucinates or gets exploited, it can instantly corrupt team databases, execute malicious commands across your infrastructure, or trigger irreversible financial transactions that affect your entire organization.

<a id="W020"></a>

### ![W020 | low](https://img.shields.io/badge/W020-low-lightgray) ![MCP](https://img.shields.io/badge/MCP-blue) Local destructive capabilities

The MCP server grants access to tools that can modify or delete local files, alter personal settings, or change state within a single user's environment. While the blast radius is contained to one user's machine (unlike [W019](#W019)), these capabilities still enable irreversible changes to local data and project files.

Even local-only modifications carry risk of permanent data loss or project corruption within a user's workspace. If the agent misinterprets instructions or hallucinates, it can delete uncommitted work, overwrite configuration files, or corrupt local repositories, requiring manual recovery or resulting in lost productivity.

---

## Compromised Skills

These issues indicate that the installed skill is acting maliciously. This represents a critical security threat, as it effectively exposes a successful supply chain attack.

<a id="E004"></a>

### ![E004 | critical](https://img.shields.io/badge/E004-critical-red) ![Skills](https://img.shields.io/badge/Skills-purple) Prompt injection in skill

Detected a prompt injection in the skill instructions. The skill contains hidden or deceptive instructions that fall outside its stated purpose and attempt to override the agent's safety guidelines or intended behavior.

<a id="E005"></a>

### ![E005 | critical](https://img.shields.io/badge/E005-critical-red) ![Skills](https://img.shields.io/badge/Skills-purple) Suspicious download URL in skill

Detected a suspicious URL in the skill instructions that could lead the agent to download and execute malicious scripts or binaries. This includes links to executables from untrusted sources, typosquatting of official packages, URL shorteners that obscure the destination, and personal file hosting services.

Such links pose a significant risk as they indicate that Agent Scan cannot verify the full behavior of a skill (analysis is limited to the skill's own content, not externally referenced dependencies).

<a id="E006"></a>

### ![E006 | critical](https://img.shields.io/badge/E006-critical-red) ![Skills](https://img.shields.io/badge/Skills-purple) Malicious code patterns in skill

Detected high-risk code patterns in the skill content — including its prompts, tool definitions, and resources — such as data exfiltration, backdoors, remote code execution, credential theft, system compromise, supply chain attacks, and obfuscation techniques.

---

## Vulnerable Skills

These issues highlight how benign skills can play a role during an attack. The attack itself has not occurred yet, rather we found a risky pattern or capability.

<a id="W007"></a>

### ![W007 | high](https://img.shields.io/badge/W007-high-orange) ![Skills](https://img.shields.io/badge/Skills-purple) Insecure credential handling in skill

The skill handles credentials insecurely by requiring the agent to include secret values verbatim in its generated output. This exposes credentials in the agent's context and conversation history, creating a risk of data exfiltration.

<a id="W008"></a>

### ![W008 | high](https://img.shields.io/badge/W008-high-orange) ![Skills](https://img.shields.io/badge/Skills-purple) Hardcoded secrets in skill

Detected sensitive credentials directly embedded within the skill content, such as API keys, access tokens, private keys, or service-specific secrets. Secrets should never be hardcoded in plain text within skill instructions.

<a id="W009"></a>

### ![W009 | medium](https://img.shields.io/badge/W009-medium-yellow) ![Skills](https://img.shields.io/badge/Skills-purple) Direct financial execution capability

The skill is specifically designed for direct financial operations, giving the agent the ability to move money or execute financial transactions — such as payment processing, cryptocurrency operations, banking integrations, or market order execution.

<a id="W011"></a>

### ![W011 | medium](https://img.shields.io/badge/W011-medium-yellow) ![Skills](https://img.shields.io/badge/Skills-purple) Exposure to untrusted third-party content

The skill exposes the agent to untrusted, user-generated content from public third-party sources, creating a risk of indirect prompt injection. This includes browsing arbitrary URLs, reading social media posts or forum comments, and analyzing content from unknown websites.

<a id="W012"></a>

### ![W012 | high](https://img.shields.io/badge/W012-high-orange) ![Skills](https://img.shields.io/badge/Skills-purple) Unverifiable external dependency

The skill fetches instructions or code from an external URL at runtime, and the fetched content directly controls the agent's prompts or executes code. This dynamic dependency allows the external source to modify the agent's behavior without any changes to the skill itself.

Some skills implement this behavior to enable auto-update mechanisms, however, it allows skills authors to change skill instructions at any point in time, disabling any form of version pinning and allowing for potential remote instruction changes (RCE risk).

<a id="W013"></a>

### ![W013 | medium](https://img.shields.io/badge/W013-medium-yellow) ![Skills](https://img.shields.io/badge/Skills-purple) System service modification

The skill prompts the agent to compromise the security or integrity of the user's machine by modifying system-level services or configurations, such as obtaining elevated privileges, altering startup scripts, or changing system-wide settings. This may be legitimate in rare cases, but should be investigated.

<a id="W014"></a>

### ![W014 | low](https://img.shields.io/badge/W014-low-lightgray) ![Skills](https://img.shields.io/badge/Skills-purple) Missing SKILL.md file

The skill is missing the required SKILL.md file. This file provides essential metadata and documentation about the skill's purpose, capabilities, and security considerations. Without it, the security analysis may be incomplete and users cannot properly evaluate the skill before use.
