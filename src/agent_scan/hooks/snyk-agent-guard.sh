#!/usr/bin/env bash
#
# Thin-client hook handler for forwarding agent hook events to Evo Agent Guard.
# Supports Claude Code, Cursor, Codex, and GitHub Copilot via the --client argument.
#
# Usage:
#   PUSH_KEY='...' REMOTE_HOOKS_BASE_URL='...' bash snyk-agent-guard.sh --client claude-code
#   PUSH_KEY='...' REMOTE_HOOKS_BASE_URL='...' bash snyk-agent-guard.sh --client cursor
#   PUSH_KEY='...' REMOTE_HOOKS_BASE_URL='...' bash snyk-agent-guard.sh --client codex
#   PUSH_KEY='...' REMOTE_HOOKS_BASE_URL='...' bash snyk-agent-guard.sh --client github-copilot
#
# Reads a JSON payload from stdin and POSTs it (base64-encoded) to the Agent Guard endpoint.
#
# Every wait is bounded by one constant, TIMEOUT_SECONDS below: the stdin read, the
# connection and the whole request. Transport and HTTP failures, and a stdin read that times
# out, fail open: nothing on stdout, one line on stderr, exit 0. Usage errors exit 1.
#
# Requirements: bash, curl, base64, tr
#
set -euo pipefail

# --- BEGIN install-time variables ---
# Agent-scan CLI version (replaced at install time).
AGENT_SCAN_VERSION="__AGENT_SCAN_VERSION__"
# --- END install-time variables ---

# Hook API version.
VERSION="2025-11-11"

# Timeout, in seconds, for each wait in this script: the stdin read, the connection and the
# whole request. Every synchronous hook the CLI installs is capped by the agent at 30 s, and
# agent-monitor may legitimately take ~24 s to answer (its 25 s policy budget minus
# headroom), so 27 s is late enough for a slow verdict and early enough that the agent sees
# a clean fail-open exit instead of killing the hook.
TIMEOUT_SECONDS=27

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() {
  echo "Error: $*" 1>&2
  exit 1
}

# Transport and HTTP failures must not block the agent: Copilot denies the tool call on any
# non-zero exit, Cursor blocks on non-JSON stdout but allows on no output, and Claude Code
# and Codex ignore exit 0 with empty stdout. So: one diagnostic line on stderr, nothing on
# stdout, exit 0. Usage errors still go through die().
fail_open() {
  echo "snyk-agent-guard: $*; failing open" 1>&2
  exit 0
}

# Read all of stdin into the caller's ``payload`` within TIMEOUT_SECONDS. bash's read is
# the only builtin with a deadline: an agent that never writes, or never closes the pipe,
# would otherwise hold the hook forever (cat has no timeout and macOS ships no timeout(1)).
# The NUL delimiter keeps newlines; chunking keeps a large payload reasonable; the deadline
# covers the whole read, not each chunk. bash 3.2 compatible: -N does not exist there.
read_payload() {
  local deadline=$(( SECONDS + TIMEOUT_SECONDS )) remaining chunk status
  payload=""
  while :; do
    remaining=$(( deadline - SECONDS ))
    if (( remaining <= 0 )); then
      fail_open "timed out reading hook payload from stdin after ${TIMEOUT_SECONDS}s"
    fi
    chunk=""
    status=0
    IFS= read -r -d '' -n 65536 -t "$remaining" chunk || status=$?
    payload+="$chunk"
    if (( status == 0 )); then
      continue
    fi
    # bash 4+ reports a timeout as a status above 128. bash 3.2 (macOS) reports 1, the
    # same as EOF, so there the deadline decides: a read that returns once SECONDS has
    # reached it waited the full remaining time.
    if (( status > 128 )) || { (( BASH_VERSINFO[0] < 4 )) && (( SECONDS >= deadline )); }; then
      fail_open "timed out reading hook payload from stdin after ${TIMEOUT_SECONDS}s"
    fi
    break
  done
  # The command substitution this replaces stripped trailing newlines; keep that shape.
  while [[ "$payload" == *$'\n' ]]; do
    payload="${payload%$'\n'}"
  done
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

# Identify the agent surface that invoked this hook, for the X-Agent-Surface header.
#
# The --client argument can't answer this: GitHub Copilot's user-level hook config
# (~/.copilot/hooks) is read by every Copilot surface, so one installed config fires
# from the CLI, from Copilot inside VS Code, and from the Copilot desktop app alike —
# and by any other chat participant hosted in VS Code. All Copilot surfaces run the
# same engine and send byte-identical payloads, so the environment the hook process
# inherits is the only thing that tells them apart:
#
#   AI_AGENT=github_copilot_vscode_agent  -> Copilot inside VS Code ("copilot-vscode")
#   AI_AGENT=github_copilot_app_agent     -> Copilot desktop app    ("copilot")
#   COPILOT_CLI set, no AI_AGENT          -> Copilot CLI            ("copilot")
#
# Only reported for the Copilot client: these variables describe the environment rather
# than the caller and are inherited, so another agent running inside a Copilot session
# would otherwise claim a Copilot surface.
get_agent_surface() {
  local client=${1:-}
  [[ "$client" == "github-copilot" ]] || return 0
  if [[ "${AI_AGENT:-}" == "github_copilot_vscode_agent" ]]; then
    printf '%s' "copilot-vscode"
  elif [[ "${AI_AGENT:-}" == github_copilot_* || -n "${COPILOT_CLI:-}" ]]; then
    printf '%s' "copilot"
  fi
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

  [[ -n "$client" ]] || die "Missing required argument: --client <claude-code|cursor|codex|github-copilot>"
  [[ -n "${REMOTE_HOOKS_BASE_URL:-}" ]] || die "REMOTE_HOOKS_BASE_URL environment variable is not set"

  local pushkey
  pushkey="${PUSH_KEY:-${PUSHKEY:-}}"
  [[ -n "$pushkey" ]] || die "PUSH_KEY environment variable is not set"
  [[ -n "${MACHINE_ID:-}" ]] || die "MACHINE_ID environment variable is not set"

  local cli_version user_agent
  cli_version="$AGENT_SCAN_VERSION"
  # Only a copy install never filled in still holds the placeholder, and the literal must
  # not reach the wire. This sits outside the variables section on purpose: substituting
  # over it would rewrite the very literal it tests for.
  if [[ "$cli_version" == "__AGENT_SCAN_VERSION__" ]]; then
    cli_version="unknown"
  fi
  user_agent="snyk/snyk-agent-guard.sh Agent Scan v${cli_version}"

  # Determine endpoint based on client
  local endpoint
  case "$client" in
    claude-code) endpoint="/hidden/agent-monitor/hooks/claude-code" ;;
    cursor) endpoint="/hidden/agent-monitor/hooks/cursor" ;;
    codex) endpoint="/hidden/agent-monitor/hooks/codex" ;;
    github-copilot) endpoint="/hidden/agent-monitor/hooks/github-copilot" ;;
    *) die "Unknown client: ${client}. Expected claude-code, cursor, codex, or github-copilot." ;;
  esac

  local url="${REMOTE_HOOKS_BASE_URL}${endpoint}?version=${VERSION}"

  # Read payload from stdin, bounded by the timeout.
  local payload
  read_payload
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

  local agent_surface
  agent_surface="$(get_agent_surface "$client")"

  local -a curl_args
  curl_args=(
    -sS
    -X POST
    "$url"
    --connect-timeout "$TIMEOUT_SECONDS"
    --max-time "$TIMEOUT_SECONDS"
    -H "User-Agent: ${user_agent}"
    -H "X-User: ${x_user}"
    -H "Content-Type: text/plain"
    -H "X-Client-Id: ${pushkey}"
    --data-binary @-
  )
  if [[ -n "$agent_surface" ]]; then
    curl_args+=(-H "X-Agent-Surface: ${agent_surface}")
  fi

  local curl_status=0
  resp="$(printf '%s' "$encoded_body" | curl "${curl_args[@]}" -w $'\n'"${marker}%{http_code}")" || curl_status=$?
  # curl writes the -w marker even for a failed transfer (http code 000) and may have
  # streamed part of a body before the timeout fired, so resp is only read on success.
  if (( curl_status == 28 )); then
    fail_open "request timed out after ${TIMEOUT_SECONDS}s"
  elif (( curl_status != 0 )); then
    fail_open "request failed (curl exit ${curl_status})"
  fi
  http_code="${resp##*$'\n'"${marker}"}"
  body="${resp%$'\n'"${marker}"*}"

  if [[ "$http_code" =~ ^[0-9]{3}$ ]] && (( http_code >= 400 )); then
    fail_open "HTTP ${http_code}"
  fi

  printf '%s' "$body"
}

hook_main "$@"
