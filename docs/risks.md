# Risk reference

> [!NOTE]
> This reference applies to Agent Scan v0.6 and later, using the `2026-07-10` analysis API. Agent Scan v0.5.x uses the [issue-code reference](issue-codes.md).

Agent Scan reports security findings as risk indicators on each discovered MCP server or agent skill. A risk indicator is present only when the analysis finds evidence for that risk. Every indicator contains a score and human-readable evidence. MCP server indicators can identify affected tools. Skill indicators can identify relevant file locations, and the URL-related skill indicators can also include the detected URLs.

Use the indicator names in this document with [`--ignore-risks`](cli-reference.md#v06-ci-mode). Risk names are case-sensitive.

Operational problems such as an MCP server failing to start are not security risks. They use separate `X` codes documented in the [failure code reference](failure-codes.md).

## Risk scores

Scores range from 0 to 1000, where a higher score represents greater risk. Agent Scan currently emits four score levels and renders them with the same purple scale used by Snyk Evo:

| Score | Level | CLI color |
| --- | --- | --- |
| 100 | Low | Neutral gray (`#55555d`) |
| 300 | Medium | Light purple (`#cbabee`) |
| 600 | High | Purple (`#9456d2`) |
| 1000 | Critical | Deep purple (`#7535b6`) |

The JSON schema accepts any integer from 0 through 1000 so that the scoring model can evolve. Use the risk indicator name, score, and evidence together when evaluating a result rather than treating the score as a category by itself.

## MCP server risks

MCP server indicators appear under `server_risks[].risk_indexes` in scan JSON. Their `affected_tools` field contains indexes into that server's `entities` array; the human-readable report resolves those indexes to tool names.

<a id="dangerous_words"></a>

### `dangerous_words` — Dangerous words

Tool descriptions contain manipulative language intended to influence an agent's decisions, inflate a tool's priority, or encourage the agent to disregard its normal instructions. Review the affected descriptions and remove or sanitize the server if the language is not necessary and trustworthy.

<a id="prompt_injection_tool_desc"></a>

### `prompt_injection_tool_desc` — Prompt injection in tool

A tool description contains instructions that blur the boundary between descriptive metadata and commands to the agent. Such content can override the user's intent, disclose data, or cause harmful actions. Disable the affected server until its tool descriptions are trusted and sanitized.

<a id="untrusted_content"></a>

### `untrusted_content` — Untrusted content

The server exposes content from channels where attackers can submit data, such as email, issue trackers, or support tickets. Processing attacker-controlled content can expose the agent to indirect prompt injection. Avoid combining this server with destructive or sensitive capabilities without appropriate isolation and approval controls.

<a id="private_data"></a>

### `private_data` — Private data

The server can retrieve sensitive, non-public data such as personal communications, financial records, or credentials. Bringing this data into an agent's context increases the consequences of prompt injection, logging mistakes, and unintended disclosure. Restrict access and avoid pairing it with untrusted-content or outbound-network capabilities.

<a id="destructive_capabilities"></a>

### `destructive_capabilities` — Destructive capabilities

The server exposes tools that can modify shared infrastructure, execute system commands, or affect other users and services. A compromised or mistaken agent could cause service disruption, data loss, or financial harm. Require human approval for state-changing operations and grant only the minimum necessary access.

## Skill risks

Skill indicators appear under `skill_risks[].risk_indexes` in scan JSON. Most can include `locations` identifying relevant files and line ranges. The URL-related indicators also include the URLs found during analysis.

<a id="prompt_injection_skill_instructions"></a>

### `prompt_injection_skill_instructions` — Potential prompt injection

The skill instructions contain manipulative or hidden directives that may override the user's intent or the agent's normal safeguards. Do not use the skill until its instructions have been reviewed and the deceptive content removed.

<a id="suspicious_download_url"></a>

### `suspicious_download_url` — Suspicious download URL

The skill directs the agent to download or execute content from an untrusted, obscured, or suspicious location rather than a verified source. The result can include `malicious_urls` with the URLs that triggered the indicator. Avoid running the skill and verify every referenced artifact independently.

<a id="malicious_code"></a>

### `malicious_code` — Malicious code

The skill contains code patterns associated with behavior such as data exfiltration, credential theft, backdoors, or obfuscated payloads. Treat the skill as compromised and do not execute it.

<a id="insecure_credential_handling"></a>

### `insecure_credential_handling` — Insecure credential handling

The skill instructs the agent to handle API keys, tokens, cookies, passwords, or other credentials directly. Passing secrets through the model or command output can expose them through logs, prompts, or unintended disclosure. Use secure credential stores and keep secret values outside model-visible content.

<a id="secret_detection"></a>

### `secret_detection` — Secret detection

The skill appears to contain a live credential, such as an API key or private key, instead of a placeholder or secure reference. Remove the secret, rotate it immediately, and use an environment variable or secret manager.

<a id="direct_money_access"></a>

### `direct_money_access` — Direct money access

The skill gives an agent direct authority over payment systems, banking APIs, cryptocurrency wallets, trading systems, or other financial operations. Require explicit human approval for every transaction and limit the skill's permissions.

<a id="third_party_content_exposure"></a>

### `third_party_content_exposure` — Third party content exposure

The skill tells the agent to fetch and act on content from public or user-controlled sources such as arbitrary web pages, forums, or social media. That content can contain indirect prompt injection. Use the skill only with strong isolation and without sensitive or destructive capabilities.

<a id="unverifiable_dependencies"></a>

### `unverifiable_dependencies` — Unverifiable dependencies

The skill fetches executable code or instructions from remote URLs at runtime, so its behavior can change independently of the installed skill. The result can include `unverifiable_urls` identifying these dependencies. Bundle and verify dependencies locally before using the skill.

<a id="modifying_system_services"></a>

### `modifying_system_services` — Attempt to modify system services

The skill instructs the agent to change system files, services, users, permissions, or other host-level configuration. Run it only in a disposable sandbox unless those system changes are explicitly required and reviewed.

<a id="missing_skill_md"></a>

### `missing_skill_md` — Missing SKILL.md

The skill does not include the required `SKILL.md` manifest describing its purpose and capabilities. Add and review the manifest before using the skill.

## Related documentation

- [Failure codes](failure-codes.md) — operational discovery, inspection, and analysis failures
- [JSON output](json-output.md) — risk fields and programmatic examples
- [CLI reference](cli-reference.md#v06-ci-mode) — CI behavior and ignore flags
