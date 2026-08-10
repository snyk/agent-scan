# Failure code reference

Agent Scan uses `X001` through `X009` for operational conditions encountered during discovery, inspection, and analysis. These codes describe whether the scan itself completed successfully; they are not security findings and have no risk score.

Failure codes can appear beside an MCP server, skill, or scan path in the human-readable report. In JSON, the corresponding `error` object contains the structured `category`, message, and `is_failure` value.

Use these codes with [`--ignore-failure-codes`](cli-reference.md#ci-mode). Codes are case-sensitive. Ignoring a failure code prevents that code from causing a `--ci` exit, but does not remove the error from human-readable or JSON output.

| Code | Error category | Meaning | Normally fails `--ci` |
| --- | --- | --- | :---: |
| `X001` | `server_startup` | A stdio MCP server could not be started or did not complete its startup handshake. | Yes |
| `X002` | `skill_scan_error` | A skill could not be collected, validated, or inspected. | Yes |
| `X003` | `file_not_found` | A configured or well-known path does not exist. This is normally an informational discovery result. | No |
| `X004` | `unknown_config` | A file does not match a supported MCP configuration format. This is normally informational. | No |
| `X005` | `parse_error` | A configuration file exists but could not be parsed or validated. | Yes |
| `X006` | `server_http_error` | A remote MCP server returned an HTTP or transport error during inspection. | Yes |
| `X007` | `analysis_error` | Agent Scan could not reach or successfully use the analysis API. | Yes |
| `X008` | Unclassified | An operational error did not have a recognized category. | Yes |
| `X009` | `user_declined` | The user declined permission to start a stdio MCP server. | Yes |

The `is_failure` field is the source of truth for CI behavior. `X003` and `X004` normally carry `is_failure: false`, so they do not fail CI even though they are displayed for context. Agent Scan exits with code 1 when at least one security risk or unignored operational error with `is_failure: true` remains.

There is no `X010` code.

## Ignoring operational failures in CI

`--ignore-failure-codes` accepts a comma-separated list and is valid only with `--ci`:

```bash
uvx snyk-agent-scan@latest \
  --ci \
  --dangerously-run-mcp-servers \
  --ignore-failure-codes X001,X007
```

Unknown codes produce a warning and are not applied. Security risks are unaffected; use [`--ignore-risks`](risks.md) separately when necessary.

## Related documentation

- [Risk reference](risks.md) — security risk indicators and scores
- [JSON output](json-output.md) — structured error objects and CI examples
- [CLI reference](cli-reference.md#ci-mode) — exit behavior and ignore flags
