#!/usr/bin/env bash
set -euo pipefail
# The path baked in at install time can go stale: a uvx install resolves to an
# absolute path under ~/.cache/uv that uv later garbage-collects. Fall back to
# PATH rather than exec'ing a binary that is no longer there.
bin="${AGENT_SCAN_BIN:-snyk-agent-scan}"
if ! command -v "$bin" >/dev/null 2>&1; then
  bin="snyk-agent-scan"
fi
exec "$bin" guard discover "$@" >/dev/null 2>&1
