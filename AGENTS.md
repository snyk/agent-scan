# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Build and test commands: `Makefile`; lint/format scope and versions: `.pre-commit-config.yaml`.
- Remote MCP connection policy: `src/agent_scan/mcp_client.py`; wire-compatible scan error codes: `src/agent_scan/models/errors.py`. Preserve the documented loopback/private-network support.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
