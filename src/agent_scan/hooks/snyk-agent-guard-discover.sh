#!/usr/bin/env bash
set -euo pipefail
[[ -n "${MACHINE_ID:-}" ]] || exit 0
[[ -n "${AGENT_SCAN_BIN:-}" ]] || exit 0
"$AGENT_SCAN_BIN" guard discover "$@" >/dev/null 2>&1 || true
exit 0
