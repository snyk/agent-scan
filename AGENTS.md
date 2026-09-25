# Project agent memory

- Local unit suite: `SNYK_TOKEN=unit-test-placeholder uv run --extra test pytest tests/unit`. Some mocked API tests require a token in the environment, as configured in `.github/workflows/tests.yml`; no real credential is needed.
- CLI entry point: `uv run snyk-agent-scan` (see `pyproject.toml`). `inspect` is local-only; `scan` sends content for analysis (see `src/agent_scan/cli.py`).
- Quality checks: `uv run --with pre-commit pre-commit run --all-files`; hook definitions, including mypy, are in `.pre-commit-config.yaml`.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
