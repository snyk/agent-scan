#!/usr/bin/env bash
set -euo pipefail
[[ -n "${MACHINE_ID:-}" ]] || exit 0
[[ -n "${AGENT_SCAN_COMMAND:-}" ]] || exit 0
if [[ -x "$AGENT_SCAN_COMMAND" ]]; then
  "$AGENT_SCAN_COMMAND" guard discover "$@" >/dev/null 2>&1 || true
else
  # TODO: ProdSec needs to review this shell-evaluation path before release.
  eval "$AGENT_SCAN_COMMAND guard discover \"\$@\"" >/dev/null 2>&1 || true
fi
exit 0
