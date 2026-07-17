# JSON output reference for `snyk-agent-scan`

The `snyk-agent-scan` CLI can emit structured JSON for programmatic consumption — useful in CI/CD pipelines, catalog validation, and custom auditing tools.

Enable JSON mode with `--json`:

```bash
uvx snyk-agent-scan@latest --json
uvx snyk-agent-scan@latest --json ~/.claude/skills
uvx snyk-agent-scan@latest inspect --json ~/.vscode/mcp.json
```

**Output behavior**

- With `--json`, stdout contains **only** the JSON document (the version banner and rich-text report are suppressed).
- Debug logging still goes to stderr when `--verbose` is set.
- Skills are included by default; pass `--no-skills` for MCP-only scans.
- For native pass/fail exit codes in CI, prefer [`--ci`](cli-reference.md#ci-mode) over custom `jq` parsing.

> **Experimental output.** Field names, issue codes, and schema details may change between releases. See the [project README](../README.md) stability notice.

---

## JSON structure overview

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

### Top-level fields (`ScanPathResult`)

| Field | Type | Description |
| --- | --- | --- |
| `client` | string \| null | Agent client that owns this path (e.g. `cursor`, `claude-code`). |
| `path` | string | Absolute path for this scan result (config file, skill directory, etc.). |
| `error` | object \| null | Path-level error when discovery/parsing failed for this path. See [Execution failures](#1-checking-for-execution-failures). |
| `servers` | array \| null | Inspected MCP servers and skills. `null` when the config could not be read at all. |
| `issues` | array | Security findings from analysis (`E*`, `W*`). Empty in `inspect` mode. |
| `labels` | array | Per-tool risk label scores from analysis (MCP scans). Often empty for skills-only paths. |

### Server entries (`ServerScanResult`)

| Field | Type | Description |
| --- | --- | --- |
| `name` | string \| null | Server or skill name from the config. |
| `config_path` | string \| null | Absolute path of the config file this entry came from. |
| `server` | object | Underlying config: stdio MCP (`command`, `args`, `type: "stdio"`), remote MCP (`url`, `type: "sse"` \| `"http"`), or skill (`path`, `type: "skill"`). |
| `signature` | object \| null | Live tool/prompt/resource catalog when inspection succeeded. |
| `error` | object \| null | Server-level error when startup or inspection failed. |

### Issue entries (`Issue`)

| Field | Type | Description |
| --- | --- | --- |
| `code` | string | Finding code (e.g. `E001`, `W015`). See [Issue codes](issue-codes.md). |
| `message` | string | Human-readable description. |
| `reference` | array \| null | `(server_index, entity_index)` into `servers` / entity lists, or `[server_index, null]` for server-scoped issues. |
| `extra_data` | object \| null | Optional structured context from analysis. |

### Error objects (`ScanError`)

| Field | Type | Description |
| --- | --- | --- |
| `message` | string \| null | Short error description. |
| `exception` | string \| null | Serialized exception message. |
| `traceback` | string \| null | Stack trace when captured. |
| `is_failure` | boolean | Whether this error should count as a runtime failure (see CI below). |
| `category` | string \| null | Structured category (e.g. `server_startup`, `file_not_found`). |
| `server_output` | string \| null | Captured MCP traffic / stderr for startup failures. |

---

## 1. Checking for execution failures

Check failures **before** policy violations.

### Path-level errors

Inspect `error` on each `ScanPathResult`.

- **`error` is not `null`:** Discovery or parsing failed for that path.
- Read `error.message` (and `error.category`) for details.
- **`error.is_failure`:** When `false`, the path was skipped benignly (e.g. `file_not_found`, `unknown_config`). When `true`, treat as a hard failure (e.g. `parse_error`).

### Server-level errors

Iterate `servers[]`:

- **`servers[i].error` is not `null`:** That MCP server or skill failed to inspect (startup error, HTTP error, skill scan error, user declined consent, etc.).
- Check `servers[i].error.is_failure` the same way as path-level errors.
- A server with `signature: null` and `error: null` was **configured but not live-inspected** (common for stdio MCP on unattended push-key scans without `--dangerously-run-mcp-servers`).

### Runtime failure codes (`X*`)

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
| `X010` | `skipped_by_runtime_config` | true |

---

## 2. Checking for policy violations

When inspection and analysis succeeded, read the `issues` array.

| Prefix | Meaning | Example |
| --- | --- | --- |
| **`E`** | Error — high-severity security finding | `E001` prompt injection in MCP tool |
| **`W`** | Warning — lower-severity or informational finding | `W001` suspicious words in tool description |

Full reference: [Issue codes](issue-codes.md).

### Internal warnings (`W003`–`W006`)

The human-readable CLI hides `W003`, `W004`, `W005`, and `W006` unless `--verbose` is set. **JSON output includes all issues unchanged.**

These codes are legacy internal hints. If you want JSON parsing to mirror the default text report, filter them out in post-processing (examples below).

---

## CI/CD integration

### Built-in exit codes (recommended)

Use `--ci` for a native non-zero exit when findings or runtime failures remain:

```bash
uvx snyk-agent-scan@latest \
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

## Practical examples with `jq`

### Any critical findings or failures?

```bash
uvx snyk-agent-scan@latest --json ./my-skill | jq '
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

### Filter internal warnings

Match the default text output by excluding `W003`–`W006`:

```bash
uvx snyk-agent-scan@latest --json ./my-skill | jq '
  .[] | (.issues // [])[] |
  select(
    .code as $c | ["W003", "W004", "W005", "W006"] | index($c) | not
  )
'
```

### Strict compliance check

Fail on any remaining issue (excluding internal warnings) or any `is_failure` error:

```bash
uvx snyk-agent-scan@latest --json ./my-skill | jq '
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

### One-liner exit code via `jq`

When you cannot use `--ci`, derive an exit code from issue codes:

```bash
uvx snyk-agent-scan@latest --json . | jq -e '
  [
    .[] | (.issues // [])[].code
  ] | map(select(. as $c | ["W003","W004","W005","W006"] | index($c) | not)) | length == 0
' > /dev/null
```

- `jq -e` maps `true` → exit `0`, `false` → exit `1`.
- This checks **issues only**; combine with failure checks above for full coverage.

---

## Node.js integration

```javascript
const { execSync } = require("child_process");

const IGNORE_CODES = new Set(["W003", "W004", "W005", "W006"]);

function checkAgentScan(targetPath) {
  const scanOutput = execSync(
    `uvx snyk-agent-scan@latest --json ${JSON.stringify(targetPath)}`,
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

## Related documentation

- [CLI reference](cli-reference.md) — all flags, including `--json`, `--ci`, and `--ignore-issues-codes`
- [Issue codes](issue-codes.md) — security finding reference
