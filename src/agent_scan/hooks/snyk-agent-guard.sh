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
# The request is bounded by TIMEOUT_SECONDS below. Transport and HTTP failures, that timeout
# included, fail open: exit 0, one line on stderr, and on stdout a systemMessage JSON object
# for the clients whose hook output defines one (Claude Code, Codex) so the user is told
# that Agent Guard did not validate the action; nothing on stdout for the others. Usage
# errors exit 1.
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

# Timeout, in seconds, for the whole request. agent-monitor may legitimately take ~50 s to
# answer: it holds a PreToolUse for up to 25 s until the session's discovery arrives, then
# evaluates within its 25 s policy budget. Every synchronous hook the CLI installs is capped
# by the agent at 65 s, so 60 s is late enough for a slow verdict and early enough that the
# agent sees a clean fail-open exit instead of killing the hook.
TIMEOUT_SECONDS=60

# What the user is told when the hook fails open. Embedded in JSON verbatim, so it must stay
# free of double quotes, backslashes and control characters (pinned by a test).
FAIL_OPEN_MESSAGE="Unable to reach Snyk Evo to validate agent behavior. Please check your network and configuration and try again."

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() {
  echo "Error: $*" 1>&2
  exit 1
}

# Clients whose hook output schema defines systemMessage, a warning the agent shows the
# user. Cursor has no such field and its permission hooks block on stdout that does not
# match their schema; Copilot documents no such field and its preToolUse fails closed on
# hook errors. Both therefore get nothing on stdout.
supports_system_message() {
  case "${1:-}" in
    claude-code|codex) return 0 ;;
    *) return 1 ;;
  esac
}

# Usage: fail_open <client> <reason>
#
# Transport and HTTP failures must not block the agent: Copilot denies the tool call on any
# non-zero exit, Cursor blocks on non-JSON stdout but allows on no output, and Claude Code
# and Codex ignore exit 0 with empty stdout. So: exit 0, the user-facing sentence plus the
# technical reason on stderr, and the sentence as a systemMessage on stdout only where the
# client renders it. Usage errors still go through die().
fail_open() {
  local client=$1 reason=$2
  echo "snyk-agent-guard: ${FAIL_OPEN_MESSAGE} (${reason}; failing open)" 1>&2
  if supports_system_message "$client"; then
    printf '{"systemMessage":"%s"}\n' "$FAIL_OPEN_MESSAGE"
  fi
  exit 0
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

  local agent_surface
  agent_surface="$(get_agent_surface "$client")"

  local -a curl_args
  curl_args=(
    -sS
    -X POST
    "$url"
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
    fail_open "$client" "request timed out after ${TIMEOUT_SECONDS}s"
  elif (( curl_status != 0 )); then
    fail_open "$client" "request failed (curl exit ${curl_status})"
  fi
  http_code="${resp##*$'\n'"${marker}"}"
  body="${resp%$'\n'"${marker}"*}"

  if [[ "$http_code" =~ ^[0-9]{3}$ ]] && (( http_code >= 400 )); then
    fail_open "$client" "HTTP ${http_code}"
  fi

  printf '%s' "$body"
}

hook_main "$@"
