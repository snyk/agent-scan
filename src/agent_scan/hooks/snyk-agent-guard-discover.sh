#!/usr/bin/env bash
set -euo pipefail

# Session-start discovery trampoline for Snyk Agent Guard.
#
# Usage:
#   bash snyk-agent-guard-discover.sh --client claude-code --scope servers
#   PUSH_KEY=... MACHINE_ID=... AGENT_SCAN_COMMAND=/path/to/snyk-agent-scan \
#     bash snyk-agent-guard-discover.sh --client claude-code --scope servers --from-env
#
# Configuration is read from snyk-agent-guard.conf next to this script, written by
# `snyk-agent-scan guard install`. Only when there is no such file and the command passes
# --from-env are the values taken from the environment instead: a push key is then required
# (machine identity is never taken from there), REMOTE_HOOKS_BASE_URL must be an https Snyk
# host.
#
# In both modes AGENT_SCAN_COMMAND must be the absolute path of an executable file. It is run
# as that file and never evaluated; a relative path would resolve against the agent's working
# directory, which is the repository. Any other value skips discovery with one line on stderr.

# The hook arguments are passed on to `guard discover`, so only --client and --scope are
# accepted: anything else, such as --url, would apply to the push key read below.
# --from-env selects where the values come from and is not passed on.
FROM_ENV=0
FORWARD_ARGS=()
only_client_and_scope() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --client | --scope)
        [[ $# -ge 2 && "$2" != -* ]] || return 1
        FORWARD_ARGS+=("$1" "$2")
        shift 2
        ;;
      --from-env) FROM_ENV=1; shift ;;
      *) return 1 ;;
    esac
  done
}
only_client_and_scope "$@" || exit 0
set -- ${FORWARD_ARGS[@]+"${FORWARD_ARGS[@]}"}

CONFIG_FILE="$(dirname "${BASH_SOURCE[0]}")/snyk-agent-guard.conf"
# Same rule as snyk-agent-guard.sh.
ENV_URL_RE='^https://([A-Za-z0-9-]+\.)*snyk\.io(:[0-9]+)?(/.*)?$'

if [[ ! -e "$CONFIG_FILE" && "$FROM_ENV" == "1" ]]; then
  # Push key only, as in snyk-agent-guard.sh: machine identity is never taken from the
  # environment, so both are cleared before `guard discover`.
  PUSH_KEY="${PUSH_KEY-${PUSHKEY:-}}"
  ADS_TOKEN_COMMAND=""
  TENANT_ID=""
  [[ -n "$PUSH_KEY" ]] || exit 0
  REMOTE_HOOKS_BASE_URL="${REMOTE_HOOKS_BASE_URL:-}"
  MACHINE_ID="${MACHINE_ID:-}"
  MACHINE_SERIAL="${MACHINE_SERIAL:-}"
  AGENT_SCAN_COMMAND="${AGENT_SCAN_COMMAND:-}"
  # A missing URL would make `guard discover` fall back to its default API, so it ends here
  # like the forwarder's usage error.
  [[ -n "$REMOTE_HOOKS_BASE_URL" && "$REMOTE_HOOKS_BASE_URL" =~ $ENV_URL_RE ]] || exit 0
else
  [[ -f "$CONFIG_FILE" && -r "$CONFIG_FILE" ]] || exit 0

  PUSH_KEY=""
  ADS_TOKEN_COMMAND=""
  TENANT_ID=""
  REMOTE_HOOKS_BASE_URL=""
  MACHINE_ID=""
  MACHINE_SERIAL=""
  AGENT_SCAN_COMMAND=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      PUSH_KEY) PUSH_KEY="$value" ;;
      ADS_TOKEN_COMMAND) ADS_TOKEN_COMMAND="$value" ;;
      TENANT_ID) TENANT_ID="$value" ;;
      REMOTE_HOOKS_BASE_URL) REMOTE_HOOKS_BASE_URL="$value" ;;
      MACHINE_ID) MACHINE_ID="$value" ;;
      MACHINE_SERIAL) MACHINE_SERIAL="$value" ;;
      AGENT_SCAN_COMMAND) AGENT_SCAN_COMMAND="$value" ;;
    esac
  done < "$CONFIG_FILE"
fi
# Every value is exported, even when empty: an inherited one must not stand in for the one
# captured at install. `guard discover` uses the push key when PUSH_KEY is set, and machine
# identity (ADS_TOKEN_COMMAND, TENANT_ID) otherwise, as snyk-agent-guard.sh does.
export PUSH_KEY ADS_TOKEN_COMMAND TENANT_ID REMOTE_HOOKS_BASE_URL MACHINE_ID MACHINE_SERIAL

[[ -n "$MACHINE_ID" ]] || exit 0
[[ -n "$AGENT_SCAN_COMMAND" ]] || exit 0
if [[ "$AGENT_SCAN_COMMAND" != /* || ! -f "$AGENT_SCAN_COMMAND" || ! -x "$AGENT_SCAN_COMMAND" ]]; then
  echo "snyk-agent-guard: AGENT_SCAN_COMMAND must be the absolute path of an executable file; session-start discovery skipped" 1>&2
  exit 0
fi
"$AGENT_SCAN_COMMAND" guard discover "$@" >/dev/null 2>&1 || true
exit 0
