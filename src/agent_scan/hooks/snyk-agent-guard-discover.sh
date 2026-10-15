#!/usr/bin/env bash
set -euo pipefail

# --- BEGIN install-time variables ---
INSTALL_PUSH_KEY="__AGENT_GUARD_PUSH_KEY__"
INSTALL_REMOTE_HOOKS_BASE_URL="__AGENT_GUARD_REMOTE_HOOKS_BASE_URL__"
INSTALL_MACHINE_ID="__AGENT_GUARD_MACHINE_ID__"
# --- END install-time variables ---

# Installed values win over the environment; the environment is only a fallback for a
# script never filled in.
[[ "$INSTALL_PUSH_KEY" == "__AGENT_GUARD_PUSH_KEY__" ]] || export PUSH_KEY="$INSTALL_PUSH_KEY"
[[ "$INSTALL_REMOTE_HOOKS_BASE_URL" == "__AGENT_GUARD_REMOTE_HOOKS_BASE_URL__" ]] || export REMOTE_HOOKS_BASE_URL="$INSTALL_REMOTE_HOOKS_BASE_URL"
[[ "$INSTALL_MACHINE_ID" == "__AGENT_GUARD_MACHINE_ID__" ]] || export MACHINE_ID="$INSTALL_MACHINE_ID"
[[ -n "${MACHINE_ID:-}" ]] || exit 0
[[ -n "${AGENT_SCAN_COMMAND:-}" ]] || exit 0
if [[ -x "$AGENT_SCAN_COMMAND" ]]; then
  "$AGENT_SCAN_COMMAND" guard discover "$@" >/dev/null 2>&1 || true
else
  eval "$AGENT_SCAN_COMMAND guard discover \"\$@\"" >/dev/null 2>&1 || true
fi
exit 0
