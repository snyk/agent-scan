#!/usr/bin/env bash
set -euo pipefail

# --- BEGIN install-time variables ---
INSTALL_PUSH_KEY="__AGENT_GUARD_PUSH_KEY__"
INSTALL_REMOTE_HOOKS_BASE_URL="__AGENT_GUARD_REMOTE_HOOKS_BASE_URL__"
INSTALL_MACHINE_ID="__AGENT_GUARD_MACHINE_ID__"
# --- END install-time variables ---

export PUSH_KEY="${PUSH_KEY:-$INSTALL_PUSH_KEY}"
[[ "$PUSH_KEY" != "__AGENT_GUARD_PUSH_KEY__" ]] || unset PUSH_KEY
export REMOTE_HOOKS_BASE_URL="${REMOTE_HOOKS_BASE_URL:-$INSTALL_REMOTE_HOOKS_BASE_URL}"
[[ "$REMOTE_HOOKS_BASE_URL" != "__AGENT_GUARD_REMOTE_HOOKS_BASE_URL__" ]] || unset REMOTE_HOOKS_BASE_URL
export MACHINE_ID="${MACHINE_ID:-$INSTALL_MACHINE_ID}"
[[ "$MACHINE_ID" != "__AGENT_GUARD_MACHINE_ID__" ]] || unset MACHINE_ID
[[ -n "${MACHINE_ID:-}" ]] || exit 0
[[ -n "${AGENT_SCAN_COMMAND:-}" ]] || exit 0
if [[ -x "$AGENT_SCAN_COMMAND" ]]; then
  "$AGENT_SCAN_COMMAND" guard discover "$@" >/dev/null 2>&1 || true
else
  eval "$AGENT_SCAN_COMMAND guard discover \"\$@\"" >/dev/null 2>&1 || true
fi
exit 0
