#!/usr/bin/env bash
set -euo pipefail
[[ -n "${MACHINE_ID:-}" ]] || exit 1
bin="${AGENT_SCAN_BIN:-snyk-agent-scan}"
if ! command -v "$bin" >/dev/null 2>&1; then
  bin="snyk-agent-scan"
fi
exec "$bin" guard discover "$@" >/dev/null 2>&1
