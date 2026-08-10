# JSON output reference for `snyk-agent-scan`

Agent Scan can emit structured JSON for CI/CD pipelines, catalog validation, and custom auditing tools:

```bash
uvx snyk-agent-scan@latest --json
uvx snyk-agent-scan@latest --json ~/.claude/skills
uvx snyk-agent-scan@latest inspect --json ~/.vscode/mcp.json
```

With `--json`, stdout contains only the JSON document. Debug logging still goes to stderr when `--verbose` is set. Skills are included by default; use `--no-skills` for MCP-only scans.

For native pass/fail behavior, prefer [`--ci`](cli-reference.md#ci-mode) instead of reimplementing Agent Scan's exit logic.

> **Experimental output.** Risk names and JSON fields may change between releases. See the [project README](../README.md) for the stability notice.

## `scan --json`

`scan` performs local discovery and inspection, sends the inventory to the analysis API, and prints a `ScanResponse`. The root is an object with one `scan_path_responses` array; it is not keyed by path.

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

### Scan response fields

| Field | Type | Description |
| --- | --- | --- |
| `scan_path_responses` | array | One analyzed result for each discovered client or explicitly supplied path. |
| `scan_path_responses[].client` | string, optional | Agent client associated with the path. |
| `scan_path_responses[].path` | string | Display-safe path returned for the analyzed inventory. |
| `scan_path_responses[].server_risks` | array | MCP server inventory and analysis results. Clean servers remain in this array. |
| `scan_path_responses[].skill_risks` | array | Skill inventory and analysis results. Clean skills remain in this array. |
| `scan_path_responses[].error` | object, optional | Path-level operational error. |

### MCP server results

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

### Skill results

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

## `inspect --json`

`inspect` never contacts the analysis API, so it cannot report risk indexes. It prints local `InspectedPath` inventory instead. The root is a map keyed by the absolute inspected path:

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

Unlike scan JSON, inspect JSON is local inventory and includes `null` fields. It can also contain local configuration values, skill contents, absolute paths, signatures, and detailed errors. Treat it as potentially sensitive and do not publish it without review.

## Error objects and failure codes

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

## CI/CD integration

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

Both flags require `--ci`, are case-sensitive, and warn about unknown values. See [CLI reference — CI mode](cli-reference.md#ci-mode).

## Practical `jq` examples

### List every risk

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

### List operational failures

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

### Require a clean result with `jq`

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

## Node.js integration

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

## Related documentation

- [Risk reference](risks.md) — security indicators and scores
- [Failure codes](failure-codes.md) — operational error mapping
- [CLI reference](cli-reference.md) — commands, flags, and exit behavior
