# JSON Output Reference for `mcp-scan`

The `mcp-scan` CLI provides a structured JSON output that allows for programmatic verification of skill scans. This is particularly useful for CI/CD pipelines or automated auditing tools.

To generate this output, run the scan with the `--json` flag:

```bash
uvx mcp-scan --skills <path-to-skill-directory> --json
```

## JSON Structure Overview

The output is a dictionary where keys are file paths and values are `ScanPathResult` objects.

```json
{
  "/absolute/path/to/skill": {
    "path": "/absolute/path/to/skill",
    "error": null, 
    "servers": [
      {
        "name": "skill-name",
        "type": "skill",
        "error": null,
        "signature": { ... }
      }
    ],
    "issues": [
      {
        "code": "E001",
        "message": "Description of the error",
        "reference": [0, 1] 
      }
    ]
  }
}
```

## 1. Checking for Execution Failures

Before looking for policy violations, ensure the scanner successfully ran on the target.

### Path-level Failure
Check the top-level `error` field in the result object.
*   **If `error` is not `null`**: The scan failed completely (e.g., file not found, permission denied).
*   **Action**: Read `error.message` for details.

### Server-level Failure
A skill directory might contain multiple "servers" (or parts). Check the `servers` array.
*   Iterate through each item in `servers`.
*   **If `servers[i].error` is not `null`**: That specific part of the skill failed to start or run.
*   **Action**: Read `servers[i].error.message`.

## 2. Checking for Policy Violations

If the scan executed successfully, look at the `issues` array to find policy violations.

| Code Prefix | Meaning | Severity | Example |
| :--- | :--- | :--- | :--- |
| **`E`** | **Error** | **High** | `E001`: Critical security flaw |
| **`W`** | **Warning** | **Medium** | `W001`: Best practice violation |
| **`X`** | **Analysis Error** | **Variable** | `X001`: API analysis failed |
| **`X002`** | **Whitelisted** | **Safe** | Explicitly allowed by user |

### Internal Warnings
The JSON output is verbose and may include internal warnings (codes `W003`, `W004`, `W005`, `W006`) that are typically hidden in the text output. These usually relate to internal scanner states or non-critical hints and can often be ignored for compliance checks.

## Practical Example: Filtering with `jq`

You can use `jq` to parse the output and determine if a skill passes or fails your criteria.

### Basic Check: Any Errors?
To check if there are any critical errors (`E` codes) or execution failures:

```bash
uvx mcp-scan --skills ./my-skill --json | jq '
  [ .[] ] | map(
    select(
      .error != null or 
      (.servers[]? | .error != null) or 
      (
        (.issues // []) | map(select(.code | startswith("E"))) | length > 0
      )
    )
  ) | length > 0
'
```
*   Returns `true` if there are failures or critical errors.
*   Returns `false` if the scan is clean of errors.

### Advanced Check: Filter Internal Warnings
To get a list of "real" issues (ignoring internal warnings `W003`-`W006` and whitelisted items `X002`):

```bash
uvx mcp-scan --skills ./my-skill --json | jq '
  .[] | (.issues // [])[] | 
  select(
    .code as $c | ["W003", "W004", "W005", "W006", "X002"] | index($c) | not
  )
'
```

### Complete Compliance Check
A strict check that fails if there are **any** errors or warnings (excluding internal ones), or if the scan itself failed:

```bash
uvx mcp-scan --skills ./my-skill --json | jq '
  [ .[] ] | map(
    select(
      # Check for execution errors (path or server level)
      (.error != null) or (.servers[]? | .error != null) or
      
      # Check for policy issues, excluding internal warnings and whitelisted items
      (
        (.issues // []) | map(select(
          .code as $c | ["W003", "W004", "W005", "W006", "X002"] | index($c) | not
        )) | length > 0
      )
    )
  ) | length > 0
'
```

If the output is `true`, the skill **failed** the check.

## One-Liner for CI/CD

If you need a concise command for scripts or CI/CD pipelines that simply passes (exit 0) or fails (exit 1) based on policy violations:

```bash
uvx mcp-scan --skills . --json | jq -e '[.[].issues[].code] - ["W003","W004","W005","W006","X002"] == []' > /dev/null
```

### Why this works:
1. `[.[].issues[].code]` collects all found issue codes into a single array.
2. `- ["W003", ...]` removes the internal/whitelisted codes from that array.
3. `== []` checks if any "real" issues remain.
4. `jq -e` sets the shell exit code based on the truthiness of the result (`true` -> 0, `false` -> 1).
5. `> /dev/null` suppresses the output so you only get the exit code.

## Node.js Integration

If you are integrating `mcp-scan` into a Node.js tool, you can use the following pattern to detect failures and policy violations programmatically.

```javascript
const { execSync } = require('child_process');

function checkSkillSecurity(targetPath) {
  try {
    const scanOutput = execSync(`uvx mcp-scan@latest --skills ${targetPath} --json`).toString();
    const scanResult = JSON.parse(scanOutput);

    // Internal codes to ignore
    const IGNORE_CODES = ["W003", "W004", "W005", "W006", "X002"];

    // 1. Check for top-level execution failures
    for (const [path, result] of Object.entries(scanResult)) {
      if (result.error) {
        throw new Error(`Scan failed for ${path}: ${result.error.message}`);
      }

      // 2. Check for server-level startup failures
      const startupError = result.servers?.find(s => s.error)?.error;
      if (startupError) {
        throw new Error(`Server failed to start: ${startupError.message}`);
      }

      // 3. Filter for real policy violations (Errors or Warnings)
      const violations = result.issues.filter(issue => !IGNORE_CODES.includes(issue.code));

      if (violations.length > 0) {
        const messages = violations.map(v => `[${v.code}] ${v.message}`).join(', ');
        throw new Error(`Security policy violations found: ${messages}`);
      }
    }

    return true; // Scan passed and is clean
  } catch (error) {
    // Handle or rethrow for your UI/Spinner
    throw error;
  }
}
```

### Key Integration Points:
*   **Object.entries**: Remember that the root of the JSON is an object keyed by file paths.
*   **Issue Filtering**: Always filter out `W003`-`W006` and `X002` if you want to match the standard "clean" output of the CLI.
*   **Server Errors**: Don't forget to check `result.servers[].error`. A skill might be "invalid" because it failed to execute, even if it has no security `issues` reported yet.
