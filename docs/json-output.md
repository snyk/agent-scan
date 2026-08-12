# JSON output reference for `snyk-agent-scan`

This reference covers both the `2025-09-02` API used by Agent Scan v0.5.x and the risk-based `2026-07-10` API used by Agent Scan v0.6 and later.

## Agent Scan v0.5.x

> [!IMPORTANT]
> Agent Scan v0.5.x is planned for deprecation. This remains the correct JSON reference for v0.5.x users. The commands pin v0.5.17 as a concrete v0.5.x release.

The `snyk-agent-scan` CLI can emit structured JSON for programmatic consumption — useful in CI/CD pipelines, catalog validation, and custom auditing tools.

Enable JSON mode with `--json`:

```bash
uvx snyk-agent-scan@0.5.17 --json
uvx snyk-agent-scan@0.5.17 --json ~/.claude/skills
uvx snyk-agent-scan@0.5.17 inspect --json ~/.vscode/mcp.json
```

**Output behavior**

- With `--json`, stdout contains **only** the JSON document (the version banner and rich-text report are suppressed).
- Debug logging still goes to stderr when `--verbose` is set.
- Skills are included by default; pass `--no-skills` for MCP-only scans.
- For native pass/fail exit codes in CI, prefer [`--ci`](cli-reference.md#ci-mode) over custom `jq` parsing.

> **Experimental output.** Field names, issue codes, and schema details may change between releases. See the [project README](../README.md) stability notice.

---

### JSON structure overview

The root object is a map from **scan path** (absolute path string) to a `ScanPathResult`:

```json
{
  "/Users/me/.claude/skills/my-skill": {
    "client": "claude-code",
    "path": "/Users/me/.claude/skills/my-skill",
    "error": null,
    "servers": [
      {
        "name": "my-skill",
        "config_path": "/Users/me/.claude/skills",
        "server": {
          "path": "/Users/me/.claude/skills/my-skill/SKILL.md",
          "type": "skill"
        },
        "signature": {
          "metadata": { "...": "..." },
          "tools": [],
          "prompts": [],
          "resources": [],
          "resource_templates": []
        },
        "error": null
      }
    ],
    "issues": [
      {
        "code": "E004",
        "message": "Description of the finding",
        "reference": [0, null],
        "extra_data": null
      }
    ],
    "labels": []
  }
}
```

#### Top-level fields (`ScanPathResult`)

| Field | Type | Description |
| --- | --- | --- |
| `client` | string \| null | Agent client that owns this path (e.g. `cursor`, `claude-code`). |
| `path` | string | Absolute path for this scan result (config file, skill directory, etc.). |
| `error` | object \| null | Path-level error when discovery/parsing failed for this path. See [Execution failures](#1-checking-for-execution-failures). |
| `servers` | array \| null | Inspected MCP servers and skills. `null` when the config could not be read at all. |
| `issues` | array | Security findings from analysis (`E*`, `W*`). Empty in `inspect` mode. |
| `labels` | array | **Deprecated — do not rely on this field.** Kept for schema compatibility. Real findings live in `issues`. |

#### Server entries (`ServerScanResult`)

| Field | Type | Description |
| --- | --- | --- |
| `name` | string \| null | Server or skill name from the config. |
| `config_path` | string \| null | Absolute path of the config file this entry came from. |
| `server` | object | Underlying config: stdio MCP (`command`, `args`, `type: "stdio"`), remote MCP (`url`, `type: "sse"` \| `"http"`), or skill (`path`, `type: "skill"`). |
| `signature` | object \| null | Live tool/prompt/resource catalog when inspection succeeded. |
| `error` | object \| null | Server-level error when startup or inspection failed. |

#### Issue entries (`Issue`)

| Field | Type | Description |
| --- | --- | --- |
| `code` | string | Finding code (e.g. `E001`, `W015`). See [Issue codes](issue-codes.md). |
| `message` | string | Human-readable description. |
| `reference` | array \| null | Index pair into the result: `[server_index, entity_index]`. **`server_index`** selects an entry in `servers[]` (an MCP server *or* a skill). **`entity_index`** selects an item within that entry's catalog — an MCP **tool** (or prompt/resource) for servers, or a **file** within a skill bundle; `null` as the second element means the issue applies to the whole server/skill, not one entity. |
| `extra_data` | object \| null | Optional structured context from analysis. |

#### Error objects (`ScanError`)

| Field | Type | Description |
| --- | --- | --- |
| `message` | string \| null | Short error description. |
| `exception` | string \| null | Serialized exception message. |
| `traceback` | string \| null | Stack trace when captured. |
| `is_failure` | boolean | Whether this error should count as a runtime failure (see CI below). |
| `category` | string \| null | Structured category (e.g. `server_startup`, `file_not_found`). |
| `server_output` | string \| null | Captured MCP traffic / stderr for startup failures. |

---

### 1. Checking for execution failures

Check failures **before** policy violations.

#### Path-level errors

Inspect `error` on each `ScanPathResult`.

- **`error` is not `null`:** Discovery or parsing failed for that path.
- Read `error.message` (and `error.category`) for details.
- **`error.is_failure`:** When `false`, the path was skipped benignly (e.g. `file_not_found`, `unknown_config`). When `true`, treat as a hard failure (e.g. `parse_error`).

#### Server-level errors

Iterate `servers[]`:

- **`servers[i].error` is not `null`:** That MCP server or skill failed to inspect (startup error, HTTP error, skill scan error, user declined consent, etc.).
- Check `servers[i].error.is_failure` the same way as path-level errors.
- A server with `signature: null` and `error: null` was **configured but not live-inspected** (common for stdio MCP on unattended push-key scans without `--dangerously-run-mcp-servers`).

#### Runtime failure codes (`X*`)

Operational failures map to `X*` codes (via `error.category`, or occasionally in `issues`):

| Code | Category | Typical `is_failure` |
| --- | --- | --- |
| `X001` | `server_startup` | true |
| `X002` | `skill_scan_error` | true |
| `X003` | `file_not_found` | false |
| `X004` | `unknown_config` | false |
| `X005` | `parse_error` | true |
| `X006` | `server_http_error` | true |
| `X007` | `analysis_error` | true |
| `X008` | (uncategorized) | true |
| `X009` | `user_declined` | true |

These nine codes match `FAILURE_CATEGORY_TO_CODE` in the CLI source; there is no `X010`.

---

### 2. Checking for policy violations

When inspection and analysis succeeded, read the `issues` array.

| Prefix | Meaning | Example |
| --- | --- | --- |
| **`E`** | Error — high-severity security finding | `E001` prompt injection in MCP tool |
| **`W`** | Warning — lower-severity or informational finding | `W001` suspicious words in tool description |

Full reference: [Issue codes](issue-codes.md).

#### Internal warnings (`W003`–`W006`)

The human-readable CLI hides `W003`, `W004`, `W005`, and `W006` unless `--verbose` is set. **JSON output includes all issues unchanged.**

These codes are v0.5.x internal hints. If you want JSON parsing to mirror the default text report, filter them out in post-processing (examples below).

---

### CI/CD integration

#### Built-in exit codes (recommended)

Use `--ci` for a native non-zero exit when findings or runtime failures remain:

```bash
uvx snyk-agent-scan@0.5.17 \
  --ci \
  --dangerously-run-mcp-servers \
  --json \
  ~/.claude/skills
```

| Exit code | Meaning |
| --- | --- |
| `0` | Clean (no remaining issues or failures) |
| `1` | Issues or unignored runtime failures present |
| `2` | Invalid flags (e.g. `--ci` without `--dangerously-run-mcp-servers`) |

Ignore specific codes in CI with `--ignore-issues-codes W001,W015` (requires `--ci`). Ignored codes are removed from the JSON payload before the exit check.

See [CLI reference — CI mode](cli-reference.md#ci-mode).

---

### Practical examples with `jq`

#### Any critical findings or failures?

```bash
uvx snyk-agent-scan@0.5.17 --json ./my-skill | jq '
  [ .[] ] | map(
    select(
      (.error != null and .error.is_failure) or
      (.servers[]? | .error != null and .error.is_failure) or
      (
        (.issues // []) | map(select(.code | startswith("E"))) | length > 0
      )
    )
  ) | length > 0
'
```

Returns `true` when hard failures or `E*` findings exist.

#### Filter internal warnings

Match the default text output by excluding `W003`–`W006`:

```bash
uvx snyk-agent-scan@0.5.17 --json ./my-skill | jq '
  .[] | (.issues // [])[] |
  select(
    .code as $c | ["W003", "W004", "W005", "W006"] | index($c) | not
  )
'
```

#### Strict compliance check

Fail on any remaining issue (excluding internal warnings) or any `is_failure` error:

```bash
uvx snyk-agent-scan@0.5.17 --json ./my-skill | jq '
  [ .[] ] | map(
    select(
      (.error != null and .error.is_failure) or
      (.servers[]? | .error != null and .error.is_failure) or
      (
        (.issues // []) | map(select(
          .code as $c | ["W003", "W004", "W005", "W006"] | index($c) | not
        )) | length > 0
      )
    )
  ) | length > 0
'
```

If the result is `true`, the target **failed** the check.

#### One-liner exit code via `jq`

When you cannot use `--ci`, derive an exit code from issue codes:

```bash
uvx snyk-agent-scan@0.5.17 --json . | jq -e '
  [
    .[] | (.issues // [])[].code
  ] | map(select(. as $c | ["W003","W004","W005","W006"] | index($c) | not)) | length == 0
' > /dev/null
```

- `jq -e` maps `true` → exit `0`, `false` → exit `1`.
- This checks **issues only**; combine with failure checks above for full coverage.

---

### Node.js integration

```javascript
const { execSync } = require("child_process");

const IGNORE_CODES = new Set(["W003", "W004", "W005", "W006"]);

function checkAgentScan(targetPath) {
  const scanOutput = execSync(
    `uvx snyk-agent-scan@0.5.17 --json ${JSON.stringify(targetPath)}`,
    { encoding: "utf8" }
  );
  const scanResult = JSON.parse(scanOutput);

  for (const [path, result] of Object.entries(scanResult)) {
    if (result.error?.is_failure) {
      throw new Error(`Scan failed for ${path}: ${result.error.message}`);
    }

    for (const server of result.servers ?? []) {
      if (server.error?.is_failure) {
        throw new Error(
          `Inspection failed for ${server.name ?? path}: ${server.error.message}`
        );
      }
    }

    const violations = (result.issues ?? []).filter(
      (issue) => !IGNORE_CODES.has(issue.code)
    );

    if (violations.length > 0) {
      const messages = violations.map((v) => `[${v.code}] ${v.message}`).join(", ");
      throw new Error(`Security findings: ${messages}`);
    }
  }

  return true;
}
```

**Integration notes**

- The root JSON object is keyed by absolute paths — iterate with `Object.entries`.
- Check `error.is_failure` and `servers[].error.is_failure`, not just presence of `error`.
- Filter `W003`–`W006` when mirroring the default text report.
- For CI pipelines, prefer `--ci --dangerously-run-mcp-servers --json` over reimplementing exit logic.

---

### Related documentation

- [CLI reference](cli-reference.md) — all flags, including `--json`, `--ci`, and `--ignore-issues-codes`
- [Issue codes](issue-codes.md) — security finding reference

## Agent Scan v0.6 and later

Agent Scan can emit structured JSON for CI/CD pipelines, catalog validation, and custom auditing tools:

```bash
uvx snyk-agent-scan@latest --json
uvx snyk-agent-scan@latest --json ~/.claude/skills
uvx snyk-agent-scan@latest inspect --json ~/.vscode/mcp.json
```

With `--json`, stdout contains only the JSON document. Debug logging still goes to stderr when `--verbose` is set. Skills are included by default; use `--no-skills` for MCP-only scans.

For native pass/fail behavior, prefer [`--ci`](cli-reference.md#v06-ci-mode) instead of reimplementing Agent Scan's exit logic.

> **Experimental output.** Risk names and JSON fields may change between releases. See the [project README](../README.md) for the stability notice.

### `scan --json`

`scan` performs local discovery and inspection, sends the discovered components to the analysis API, and prints a `ScanResponse`. The root is an object with one `scan_path_responses` array; it is not keyed by path.

```json
{
  "scan_path_responses": [
    {
      "client": "cursor",
      "path": "~/.cursor/mcp.json",
      "server_risks": [
        {
          "name": "github",
          "entities": [
            {
              "name": "create_pull_request",
              "type": "tool"
            },
            {
              "name": "search_code",
              "type": "tool"
            }
          ],
          "risk_indexes": {
            "prompt_injection_tool_desc": {
              "score": 1000,
              "evidence": "The tool description contains instructions directed at the agent.",
              "affected_tools": [0]
            }
          }
        }
      ],
      "skill_risks": [
        {
          "name": "release-helper",
          "files": [
            {
              "name": "SKILL.md",
              "type": "instruction"
            },
            {
              "name": "scripts/install.sh",
              "type": "script"
            }
          ],
          "risk_indexes": {
            "suspicious_download_url": {
              "score": 600,
              "evidence": "The script downloads an executable from an untrusted host.",
              "locations": [
                {
                  "start": {
                    "path": "scripts/install.sh",
                    "line": 12
                  }
                }
              ],
              "malicious_urls": [
                "https://downloads.example.invalid/install.sh"
              ]
            }
          }
        }
      ]
    }
  ]
}
```

Fields whose value is `null` are omitted from scan JSON. Consequently, a clean `risk_indexes` object is empty and an absent `error` field means that component has no reported operational error.

#### Scan response fields

| Field | Type | Description |
| --- | --- | --- |
| `scan_path_responses` | array | One analyzed result for each discovered client or explicitly supplied path. |
| `scan_path_responses[].client` | string, optional | Agent client associated with the path. |
| `scan_path_responses[].path` | string | Display-safe path returned for the analyzed components. |
| `scan_path_responses[].server_risks` | array | Discovered MCP servers and their analysis results. Clean servers remain in this array. |
| `scan_path_responses[].skill_risks` | array | Discovered skills and their analysis results. Clean skills remain in this array. |
| `scan_path_responses[].error` | object, optional | Path-level operational error. |

#### MCP server results

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | MCP server name. |
| `entities` | array | All discovered tools, prompts, resources, and resource templates, including those without risks. |
| `entities[].name` | string | Entity name. |
| `entities[].type` | string | `tool`, `prompt`, `resource`, or `resource_template`. |
| `risk_indexes` | object | Present MCP [risk indicators](risks.md#mcp-server-risks), keyed by their field names. |
| `error` | object, optional | Server-level operational error. |

An MCP risk value contains:

| Field | Type | Description |
| --- | --- | --- |
| `score` | integer | Risk score from 0 through 1000. |
| `evidence` | string | Human-readable reason the indicator was reported. |
| `affected_tools` | integer array, optional | Zero-based indexes into the same server's `entities` array. |

#### Skill results

| Field | Type | Description |
| --- | --- | --- |
| `name` | string | Skill name. |
| `files` | array | Files discovered in the skill, including files without risks. |
| `files[].name` | string | Path of the file within the skill. |
| `files[].type` | string | `instruction`, `script`, or `asset`. |
| `risk_indexes` | object | Present skill [risk indicators](risks.md#skill-risks), keyed by their field names. |
| `error` | object, optional | Skill-level operational error. |

A skill risk value contains `score`, `evidence`, and optionally `locations`. Each location has a `start` occurrence and optional `end` occurrence; occurrences contain `path` and optional `line` and `offset` values.

Two skill risks expose additional URL evidence:

| Risk | Additional field |
| --- | --- |
| `suspicious_download_url` | `malicious_urls` |
| `unverifiable_dependencies` | `unverifiable_urls` |

See the [risk reference](risks.md) for every supported MCP and skill risk name.

### `inspect --json`

`inspect` never contacts the analysis API, so it cannot report risk indexes. It prints local `InspectedPath` results instead. The root is a map keyed by the absolute inspected path:

```json
{
  "/Users/me/.cursor/mcp.json": {
    "client": "cursor",
    "path": "/Users/me/.cursor/mcp.json",
    "servers": [
      {
        "name": "github",
        "config_path": "/Users/me/.cursor/mcp.json",
        "server": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-github"],
          "type": "stdio",
          "env": null,
          "binary_identifier": null
        },
        "signature": null,
        "error": null
      }
    ],
    "skills": [
      {
        "name": "release-helper",
        "installation_path": "/Users/me/.cursor/skills/release-helper",
        "files": [
          {
            "path": "SKILL.md",
            "content": "---\nname: release-helper\ndescription: Prepare releases\n---\n"
          }
        ],
        "error": null
      }
    ],
    "error": null
  }
}
```

The example uses `signature: null` for brevity. After a successful MCP handshake, `signature` contains server metadata plus the full tool, prompt, resource, and resource-template descriptions.

Unlike scan JSON, inspect JSON contains local inspection results and includes `null` fields. It can also contain local configuration values, skill contents, absolute paths, signatures, and detailed errors. Treat it as potentially sensitive and do not publish it without review.

### Error objects and failure codes

Errors can occur on a scan path, MCP server, or skill:

| Field | Type | Description |
| --- | --- | --- |
| `message` | string or null | Short operational error description. |
| `exception` | string or null | Serialized exception detail when available. |
| `traceback` | string or null | Local traceback when retained. |
| `is_failure` | boolean | Whether the error counts as a runtime failure for CI. |
| `category` | string or null | Structured category such as `server_startup` or `parse_error`. |
| `server_output` | string or null | Captured MCP server output when available. |

The CLI maps error categories to `X001`–`X009`. Check `is_failure`, not merely the presence of an error: `file_not_found` and `unknown_config` are normally informational and do not fail CI. See the [failure code reference](failure-codes.md) for the complete mapping.

### CI/CD integration

Use `--ci` to exit with code 1 when any risk or unignored operational failure remains:

```bash
uvx snyk-agent-scan@latest \
  --ci \
  --dangerously-run-mcp-servers \
  --json \
  ~/.claude/skills
```

| Exit code | Meaning |
| --- | --- |
| `0` | No remaining risks or operational failures. |
| `1` | At least one risk or unignored operational failure remains. |
| `2` | Invalid command-line usage or flag combination. |

The two ignore mechanisms are intentionally separate:

- `--ignore-risks dangerous_words,suspicious_download_url` removes those risk fields before both rendering and CI evaluation.
- `--ignore-failure-codes X001,X007` excludes those operational codes from CI evaluation but preserves their errors in the output.

Both flags require `--ci`, are case-sensitive, and warn about unknown values. See [CLI reference — CI mode](cli-reference.md#v06-ci-mode).

### Practical `jq` examples

#### List every risk

```bash
uvx snyk-agent-scan@latest --json | jq -r '
  .scan_path_responses[] |
  .path as $path |
  (
    .server_risks[]? |
    .name as $component |
    .risk_indexes | to_entries[] |
    [$path, "mcp", $component, .key, (.value.score | tostring)] | @tsv
  ),
  (
    .skill_risks[]? |
    .name as $component |
    .risk_indexes | to_entries[] |
    [$path, "skill", $component, .key, (.value.score | tostring)] | @tsv
  )
'
```

#### List operational failures

```bash
uvx snyk-agent-scan@latest --json | jq '
  .scan_path_responses[] |
  .path as $path |
  (
    select(.error?.is_failure == true) |
    {path: $path, component: null, error}
  ),
  (
    .server_risks[]?, .skill_risks[]? |
    select(.error?.is_failure == true) |
    {path: $path, component: .name, error}
  )
'
```

#### Require a clean result with `jq`

When `--ci` cannot be used, `jq -e` can derive a success code from the response:

```bash
uvx snyk-agent-scan@latest --json . | jq -e '
  all(.scan_path_responses[];
    (.error?.is_failure != true) and
    all(.server_risks[]?;
      (.error?.is_failure != true) and (.risk_indexes | length == 0)
    ) and
    all(.skill_risks[]?;
      (.error?.is_failure != true) and (.risk_indexes | length == 0)
    )
  )
' > /dev/null
```

`jq -e` maps `true` to exit code 0 and `false` to exit code 1.

### Node.js integration

```javascript
const { execFileSync } = require("child_process");

function checkAgentScan(targetPath) {
  const output = execFileSync(
    "uvx",
    ["snyk-agent-scan@latest", "--json", targetPath],
    { encoding: "utf8" }
  );
  const response = JSON.parse(output);

  for (const path of response.scan_path_responses) {
    if (path.error?.is_failure) {
      throw new Error(`Scan failed for ${path.path}: ${path.error.message}`);
    }

    for (const component of [...path.server_risks, ...path.skill_risks]) {
      if (component.error?.is_failure) {
        throw new Error(
          `Inspection failed for ${component.name}: ${component.error.message}`
        );
      }

      for (const [name, risk] of Object.entries(component.risk_indexes)) {
        throw new Error(
          `Security risk in ${component.name}: ${name} (${risk.score}/1000)`
        );
      }
    }
  }

  return true;
}
```

For CI pipelines, `--ci --dangerously-run-mcp-servers --json` remains preferable because it automatically follows Agent Scan's risk and failure semantics.

### Related documentation

- [Risk reference](risks.md) — security indicators and scores
- [Failure codes](failure-codes.md) — operational error mapping
- [CLI reference](cli-reference.md) — commands, flags, and exit behavior
