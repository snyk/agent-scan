# GitHub Advanced Security code scanning

Agent Scan can emit SARIF 2.1.0 so findings appear in GitHub Advanced Security code scanning alerts.

## Command line

Write SARIF to a file:

```bash
uvx snyk-agent-scan@latest scan --sarif-output agent-scan.sarif
```

Write SARIF to stdout:

```bash
uvx snyk-agent-scan@latest scan --sarif
```

For CI, combine SARIF with `--ci` so the job fails when Agent Scan finds unignored issues or runtime failures. Because CI cannot answer MCP consent prompts, CI scans that start stdio MCP servers must also opt in with `--dangerously-run-mcp-servers`.

```bash
uvx snyk-agent-scan@latest scan \
  --ci \
  --dangerously-run-mcp-servers \
  --sarif-output agent-scan.sarif
```

## GitHub Actions workflow

```yaml
name: Agent Scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  agent-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v6

      - name: Run Agent Scan
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        run: |
          uvx snyk-agent-scan@latest scan \
            --ci \
            --dangerously-run-mcp-servers \
            --sarif-output agent-scan.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: agent-scan.sarif
```

Use `--ignore-issues-codes W003,W004` with `--ci` if your organization intentionally suppresses specific Agent Scan issue codes. Ignored issues are removed before the SARIF file is written.
