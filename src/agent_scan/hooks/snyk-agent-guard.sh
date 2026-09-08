#!/usr/bin/env bash
#
# Thin-client hook handler for forwarding agent hook events to Evo Agent Guard.
# Supports Claude Code, Cursor, and Codex via the --client argument.
#
# Usage:
#   PUSH_KEY='...' REMOTE_HOOKS_BASE_URL='...' bash snyk-agent-guard.sh --client claude-code
#   PUSH_KEY='...' REMOTE_HOOKS_BASE_URL='...' bash snyk-agent-guard.sh --client cursor
#   PUSH_KEY='...' REMOTE_HOOKS_BASE_URL='...' bash snyk-agent-guard.sh --client codex
#
# Reads a JSON payload from stdin and POSTs it (base64-encoded) to the Agent Guard endpoint.
#
# Requirements: bash, curl, base64, tr
#
set -euo pipefail

# Hook API version.
VERSION="2025-11-11"

# Install-time variables.
#
# `agent-scan guard install` substitutes each __PLACEHOLDER__ between the markers below as
# it copies this script into place (_hook_script_variables in guard.py). Always read them
# through script_var: this script also runs straight from the source tree, and a copy
# written by an older CLI will not know about variables added later, so a placeholder can
# survive. Keep the markers around declarations only -- the tests treat anything
# placeholder-shaped left between them as a substitution that install forgot.
#
# Keep these per-release, never per-machine. agent-monitor's tamper detection compares the
# installed script's checksum between installs, and a per-machine value would give every
# machine a different checksum for the same release.
# --- BEGIN install-time variables ---
AGENT_SCAN_VERSION="__AGENT_SCAN_VERSION__"
# --- END install-time variables ---

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() {
  echo "Error: $*" 1>&2
  exit 1
}

json_escape() {
  local s="${1-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

json_quote() {
  printf '"%s"' "$(json_escape "${1:-}")"
}

# Value of an install-time variable, or "unknown" when its placeholder was not substituted.
# The literal placeholder is worse than nothing on the wire: agent-monitor rejects it as a
# version anyway, and it would read as a real value everywhere else.
script_var() {
  case "${1-}" in
    ""|__*__) printf '%s' "unknown" ;;
    *) printf '%s' "$1" ;;
  esac
}

get_hostname() {
  if [[ -n "${HOSTNAME:-}" ]]; then
    printf '%s' "$HOSTNAME"
    return
  fi
  if command -v uname >/dev/null 2>&1; then
    uname -n 2>/dev/null && return
  fi
  if command -v hostname >/dev/null 2>&1; then
    hostname 2>/dev/null && return
  fi
  printf '%s' "unknown"
}

get_username() {
  if command -v id >/dev/null 2>&1; then
    id -un 2>/dev/null && return
  fi
  if command -v whoami >/dev/null 2>&1; then
    whoami 2>/dev/null && return
  fi
  printf '%s' "unknown"
}

# ---------------------------------------------------------------------------
# Main hook logic
# ---------------------------------------------------------------------------

hook_main() {
  local client=""

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --client) client="${2:-}"; shift 2 ;;
      *) shift ;;
    esac
  done

  [[ -n "$client" ]] || die "Missing required argument: --client <claude-code|cursor>"
  [[ -n "${REMOTE_HOOKS_BASE_URL:-}" ]] || die "REMOTE_HOOKS_BASE_URL environment variable is not set"

  local pushkey
  pushkey="${PUSH_KEY:-${PUSHKEY:-}}"
  [[ -n "$pushkey" ]] || die "PUSH_KEY environment variable is not set"
  [[ -n "${MACHINE_ID:-}" ]] || die "MACHINE_ID environment variable is not set"

  local cli_version user_agent
  cli_version="$(script_var "$AGENT_SCAN_VERSION")"
  user_agent="snyk/snyk-agent-guard.sh Agent Scan v${cli_version}"

  # Determine endpoint based on client
  local endpoint
  case "$client" in
    claude-code) endpoint="/hidden/agent-monitor/hooks/claude-code" ;;
    cursor) endpoint="/hidden/agent-monitor/hooks/cursor" ;;
    codex) endpoint="/hidden/agent-monitor/hooks/codex" ;;
    *) die "Unknown client: ${client}. Expected claude-code, cursor, or codex." ;;
  esac

  local url="${REMOTE_HOOKS_BASE_URL}${endpoint}?version=${VERSION}"

  # Read payload from stdin
  local payload
  payload="$(cat)"
  [[ -n "$payload" ]] || die "Expected JSON payload on stdin"

  command -v base64 >/dev/null 2>&1 || die "Missing required dependency: base64"
  command -v curl >/dev/null 2>&1 || die "Missing required dependency: curl"

  # Base64 encode
  local encoded_body
  encoded_body="base64:$(printf '%s' "$payload" | base64 | tr -d '\n')"

  # Build X-User header
  local hostname username x_user
  hostname="$(get_hostname)"
  username="$(get_username)"

  x_user="$(printf '{%s:%s,%s:%s,%s:%s,%s:%s}' \
    "\"hostname\"" "$(json_quote "$hostname")" \
    "\"username\"" "$(json_quote "$username")" \
    "\"identifier\"" "$(json_quote "$MACHINE_ID")" \
    "\"cli_version\"" "$(json_quote "$cli_version")")"

  # Execute request
  local resp body http_code marker
  marker="__SNYK_AGENT_SCAN_HOOK_HTTP_CODE__="

  local -a curl_args
  curl_args=(
    -sS
    -X POST
    "$url"
    -H "User-Agent: ${user_agent}"
    -H "X-User: ${x_user}"
    -H "Content-Type: text/plain"
    -H "X-Client-Id: ${pushkey}"
    --data-binary @-
  )

  resp="$(printf '%s' "$encoded_body" | curl "${curl_args[@]}" -w $'\n'"${marker}%{http_code}")" || die "Request failed"
  http_code="${resp##*$'\n'"${marker}"}"
  body="${resp%$'\n'"${marker}"*}"

  if [[ "$http_code" =~ ^[0-9]{3}$ ]] && (( http_code >= 400 )); then
    echo "Error: ${http_code}" 1>&2
    exit 1
  fi

  printf '%s' "$body"
}

hook_main "$@"
