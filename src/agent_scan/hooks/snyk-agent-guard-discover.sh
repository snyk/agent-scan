#!/usr/bin/env bash
set -euo pipefail

# Session-start discovery trampoline for Snyk Agent Guard.
#
# Usage:
#   bash snyk-agent-guard-discover.sh --client claude-code --scope servers
#
# Configuration is read from snyk-agent-guard.conf next to this script, written by
# `snyk-agent-scan guard install`.

# The hook arguments are passed on to `guard discover`, so only --client and --scope are
# accepted: anything else, such as --url, would apply to the push key read below.
only_client_and_scope() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --client | --scope)
        [[ $# -ge 2 && "$2" != -* ]] || return 1
        shift 2
        ;;
      *) return 1 ;;
    esac
  done
}
only_client_and_scope "$@" || exit 0

CONFIG_FILE="$(dirname "${BASH_SOURCE[0]}")/snyk-agent-guard.conf"
[[ -f "$CONFIG_FILE" && -r "$CONFIG_FILE" ]] || exit 0

PUSH_KEY=""
REMOTE_HOOKS_BASE_URL=""
MACHINE_ID=""
AGENT_SCAN_COMMAND=""
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ "$line" == *=* ]] || continue
  key="${line%%=*}"
  value="${line#*=}"
  case "$key" in
    PUSH_KEY) PUSH_KEY="$value" ;;
    REMOTE_HOOKS_BASE_URL) REMOTE_HOOKS_BASE_URL="$value" ;;
    MACHINE_ID) MACHINE_ID="$value" ;;
    AGENT_SCAN_COMMAND) AGENT_SCAN_COMMAND="$value" ;;
  esac
done < "$CONFIG_FILE"
export PUSH_KEY REMOTE_HOOKS_BASE_URL MACHINE_ID

[[ -n "$MACHINE_ID" ]] || exit 0
[[ -n "$AGENT_SCAN_COMMAND" ]] || exit 0
if [[ -x "$AGENT_SCAN_COMMAND" ]]; then
  "$AGENT_SCAN_COMMAND" guard discover "$@" >/dev/null 2>&1 || true
else
  eval "$AGENT_SCAN_COMMAND guard discover \"\$@\"" >/dev/null 2>&1 || true
fi
exit 0
