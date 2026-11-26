#!/usr/bin/env bash
#
# Thin-client hook handler for forwarding agent hook events to Evo Agent Guard.
# Supports Claude Code, Cursor, Codex, and GitHub Copilot via the --client argument.
#
# Usage:
#   bash snyk-agent-guard.sh --client claude-code
#   bash snyk-agent-guard.sh --client cursor
#   bash snyk-agent-guard.sh --client codex
#   bash snyk-agent-guard.sh --client github-copilot
#   PUSH_KEY=... REMOTE_HOOKS_BASE_URL=... MACHINE_ID=... bash snyk-agent-guard.sh --client cursor --from-env
#
# Configuration is read from snyk-agent-guard.conf next to this script, written by
# `snyk-agent-scan guard install`. Only when there is no such file and the command passes
# --from-env are the values taken from the environment instead (PUSH_KEY, or PUSHKEY when
# PUSH_KEY is unset; REMOTE_HOOKS_BASE_URL, MACHINE_ID, MACHINE_SERIAL). That mode needs a
# push key, never uses machine identity, and accepts only an https Snyk host as
# REMOTE_HOOKS_BASE_URL. Without either, the script stops with a usage error.
#
# Reads a JSON payload from stdin and POSTs it (base64-encoded) to the Agent Guard endpoint.
#
# Two auth modes, chosen by guard install and never mixed:
#   push key          PUSH_KEY and REMOTE_HOOKS_BASE_URL: the push-key route with X-Client-Id.
#   machine identity  ADS_TOKEN_COMMAND, REMOTE_HOOKS_BASE_URL and TENANT_ID (written by guard
#                     install for an ADS installer user-mode install on an enrolled machine):
#                     every run calls `<ADS_TOKEN_COMMAND> token --base-url <REMOTE_HOOKS_BASE_URL>`
#                     and POSTs to the tenant route on REMOTE_HOOKS_BASE_URL with the token as a
#                     bearer token. The token command refuses any API other than the enrolled one.
#                     The token is never logged and never put on a command line.
# A push key wins: when PUSH_KEY is set, the hook uses it and ignores ADS_TOKEN_COMMAND. Machine
# identity applies when no push key is set and ADS_TOKEN_COMMAND is; a missing value is then a
# usage error. guard install writes only one of the two into the configuration file, and the
# environment is not read while the file exists. A token command that fails, times out or prints
# anything other than one token fails open like an unreachable API; there is no fallback to the
# push key.
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

# Agent-scan CLI version (replaced by the release pipeline).
AGENT_SCAN_VERSION="__AGENT_SCAN_VERSION__"

# Hook API version. agent-monitor publishes both hook routes (push key and tenant) under it.
VERSION="2025-11-11"

# Timeout, in seconds, for the whole request; with machine identity the token command's time
# comes out of it too. agent-monitor may legitimately take ~50 s to
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

# Installation configuration, written by `snyk-agent-scan guard install` next to this
# script.
CONFIG_FILE="$(dirname "${BASH_SOURCE[0]}")/snyk-agent-guard.conf"
CFG_PUSH_KEY=""
CFG_ADS_TOKEN_COMMAND=""
CFG_TENANT_ID=""
CFG_REMOTE_HOOKS_BASE_URL=""
CFG_MACHINE_ID=""
CFG_MACHINE_SERIAL=""
CONFIG_SOURCE="$CONFIG_FILE"

# The endpoint an environment may name: https to snyk.io or a subdomain. The
# configuration file is trusted and not checked, so a local endpoint goes there.
ENV_URL_RE='^https://([A-Za-z0-9-]+\.)*snyk\.io(:[0-9]+)?(/.*)?$'

# Sets CONFIG_SOURCE to the file, or to "the environment" with --from-env and no file.
load_config() {
  local from_env="$1"
  if [[ ! -e "$CONFIG_FILE" && "$from_env" == "1" ]]; then
    CONFIG_SOURCE="the environment"
    # Push key only: machine identity is never taken from the environment. PUSHKEY stands in
    # only for an unset PUSH_KEY, not for a placeholder that expanded to nothing.
    CFG_PUSH_KEY="${PUSH_KEY-${PUSHKEY:-}}"
    CFG_REMOTE_HOOKS_BASE_URL="${REMOTE_HOOKS_BASE_URL:-}"
    CFG_MACHINE_ID="${MACHINE_ID:-}"
    CFG_MACHINE_SERIAL="${MACHINE_SERIAL:-}"
    if [[ -n "$CFG_REMOTE_HOOKS_BASE_URL" && ! "$CFG_REMOTE_HOOKS_BASE_URL" =~ $ENV_URL_RE ]]; then
      die "REMOTE_HOOKS_BASE_URL from the environment is not a Snyk endpoint: ${CFG_REMOTE_HOOKS_BASE_URL}"
    fi
    return 0
  fi
  CONFIG_SOURCE="$CONFIG_FILE"
  [[ -f "$CONFIG_FILE" && -r "$CONFIG_FILE" ]] \
    || die "Configuration file not found: ${CONFIG_FILE} (run 'snyk-agent-scan guard install')"
  local line key value
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" == *=* ]] || continue
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      PUSH_KEY) CFG_PUSH_KEY="$value" ;;
      ADS_TOKEN_COMMAND) CFG_ADS_TOKEN_COMMAND="$value" ;;
      TENANT_ID) CFG_TENANT_ID="$value" ;;
      REMOTE_HOOKS_BASE_URL) CFG_REMOTE_HOOKS_BASE_URL="$value" ;;
      MACHINE_ID) CFG_MACHINE_ID="$value" ;;
      MACHINE_SERIAL) CFG_MACHINE_SERIAL="$value" ;;
    esac
  done < "$CONFIG_FILE"
}

json_escape() {
  local s="${1-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\n'/\\n}"
  # JSON strings cannot contain any literal C0 control character. NUL cannot occur in a shell variable.
  local code char escaped
  for (( code=1; code<32; code++ )); do
    printf -v char '\\%03o' "$code"
    printf -v char '%b' "$char"
    printf -v escaped '\\u%04x' "$code"
    s="${s//$char/$escaped}"
  done
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

# Usage: fetch_access_token <deadline>
#
# Runs `"$CFG_ADS_TOKEN_COMMAND" token --base-url "$CFG_REMOTE_HOOKS_BASE_URL"` and sets ACCESS_TOKEN to the token
# it prints. On failure ACCESS_TOKEN is empty, TOKEN_ERROR holds a fixed reason and the function
# returns 1. Called directly, not in $(...), so both variables reach the caller.
#
# Neither macOS nor every Linux has timeout(1), so the command runs behind a pipe that is read
# with `read -t` until <deadline> (a value of $SECONDS): a hung command, or a descendant still
# holding its stdout, cannot hold the hook past it. The command's stderr is discarded, so nothing
# it prints reaches the agent, and its stdout (the token) is never echoed.
fetch_access_token() {
  local deadline=$1
  local pid_marker="__SNYK_AGENT_GUARD_TOKEN_PID__=" exit_marker="__SNYK_AGENT_GUARD_TOKEN_EXIT__="
  local remaining line pid="" status="" token="" lines=0
  ACCESS_TOKEN=""
  TOKEN_ERROR=""
  exec 3< <(
    exec </dev/null 2>/dev/null
    # The child prints its own PID before it execs the token command, so the marker cannot land
    # inside the token (bash 3.2 has no BASHPID; exec keeps the PID).
    "$BASH" -c 'printf "\n%s%d\n" "$1" "$$"; shift; exec "$@"' bash "$pid_marker" \
      "$CFG_ADS_TOKEN_COMMAND" token --base-url "$CFG_REMOTE_HOOKS_BASE_URL" &
    child=$!
    child_status=0
    wait "$child" || child_status=$?
    printf '\n%s%d\n' "$exit_marker" "$child_status"
  )
  while :; do
    remaining=$(( deadline - SECONDS ))
    (( remaining > 0 )) || break
    IFS= read -r -t "$remaining" -u 3 line || break
    line="${line%$'\r'}"
    case "$line" in
      "$pid_marker"*) pid="${line#"$pid_marker"}" ;;
      "$exit_marker"*) status="${line#"$exit_marker"}"; break ;;
      "") ;;
      *) token="$line"; lines=$(( lines + 1 )) ;;
    esac
  done
  exec 3<&-
  if [[ -z "$status" ]]; then
    [[ -z "$pid" ]] || kill -TERM "$pid" 2>/dev/null || true
    TOKEN_ERROR="token command did not finish in time"
    return 1
  fi
  if [[ "$status" != "0" ]]; then
    TOKEN_ERROR="token command failed (exit ${status})"
    return 1
  fi
  # The token goes into a curl config line in double quotes, so anything that would need
  # escaping there is refused rather than escaped.
  if (( lines != 1 )) || [[ "$token" == *[[:space:][:cntrl:]\"\\]* ]]; then
    TOKEN_ERROR="token command printed no single access token"
    return 1
  fi
  ACCESS_TOKEN="$token"
}

# ---------------------------------------------------------------------------
# Main hook logic
# ---------------------------------------------------------------------------

hook_main() {
  local client="" from_env=0

  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --client) client="${2:-}"; shift 2 ;;
      --from-env) from_env=1; shift ;;
      *) shift ;;
    esac
  done

  [[ -n "$client" ]] || die "Missing required argument: --client <claude-code|cursor|codex|github-copilot>"

  load_config "$from_env"
  local machine_identity=0 pushkey="$CFG_PUSH_KEY"
  # A push key wins over ADS_TOKEN_COMMAND (see the header).
  if [[ -z "$pushkey" && -n "$CFG_ADS_TOKEN_COMMAND" ]]; then
    machine_identity=1
    local required="machine identity needs ADS_TOKEN_COMMAND, REMOTE_HOOKS_BASE_URL and TENANT_ID"
    [[ -n "$CFG_REMOTE_HOOKS_BASE_URL" ]] || die "REMOTE_HOOKS_BASE_URL is not set in ${CONFIG_SOURCE} (${required})"
    [[ -n "$CFG_TENANT_ID" ]] || die "TENANT_ID is not set in ${CONFIG_SOURCE} (${required})"
    # A bare name would be looked up in the agent's PATH.
    [[ "$CFG_ADS_TOKEN_COMMAND" == /* ]] || die "ADS_TOKEN_COMMAND must be an absolute path"
    # Tenant ids are UUIDs; one that would need escaping in the URL path is refused.
    [[ "$CFG_TENANT_ID" =~ ^[A-Za-z0-9._~-]+$ ]] || die "TENANT_ID is not a valid tenant id"
  else
    [[ -n "$CFG_REMOTE_HOOKS_BASE_URL" ]] || die "REMOTE_HOOKS_BASE_URL is not set in ${CONFIG_SOURCE}"
    [[ -n "$pushkey" ]] || die "PUSH_KEY is not set in ${CONFIG_SOURCE}"
  fi
  [[ -n "$CFG_MACHINE_ID" ]] || die "MACHINE_ID is not set in ${CONFIG_SOURCE}"

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

  local url
  if (( machine_identity )); then
    url="${CFG_REMOTE_HOOKS_BASE_URL%/}/hidden/tenants/${CFG_TENANT_ID}${endpoint#/hidden}?version=${VERSION}"
  else
    url="${CFG_REMOTE_HOOKS_BASE_URL}${endpoint}?version=${VERSION}"
  fi

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
  local hostname username x_user machine_serial
  hostname="$(get_hostname)"
  username="$(get_username)"
  machine_serial=null
  if [[ -n "$CFG_MACHINE_SERIAL" ]]; then
    machine_serial="$(json_quote "$CFG_MACHINE_SERIAL")"
  fi

  x_user="$(printf '{%s:%s,%s:%s,%s:%s,%s:%s,%s:%s}' \
    "\"hostname\"" "$(json_quote "$hostname")" \
    "\"machine_serial\"" "$machine_serial" \
    "\"username\"" "$(json_quote "$username")" \
    "\"identifier\"" "$(json_quote "$CFG_MACHINE_ID")" \
    "\"cli_version\"" "$(json_quote "$cli_version")")"

  # Execute request
  local resp body http_code marker
  marker="__SNYK_AGENT_SCAN_HOOK_HTTP_CODE__="

  local agent_surface
  agent_surface="$(get_agent_surface "$client")"

  # With machine identity the token command runs first, on every invocation, and its time
  # comes out of TIMEOUT_SECONDS, so the hook as a whole stays within the budget.
  local max_time=$TIMEOUT_SECONDS
  if (( machine_identity )); then
    local started=$SECONDS
    fetch_access_token $(( started + TIMEOUT_SECONDS )) || fail_open "$client" "$TOKEN_ERROR"
    max_time=$(( TIMEOUT_SECONDS - (SECONDS - started) ))
    (( max_time >= 1 )) || max_time=1
  fi

  local -a curl_args
  curl_args=(
    -sS
    -X POST
    "$url"
    --max-time "$max_time"
    -H "User-Agent: ${user_agent}"
    -H "X-User: ${x_user}"
    -H "Content-Type: text/plain"
  )
  if (( ! machine_identity )); then
    curl_args+=(-H "X-Client-Id: ${pushkey}")
  fi
  curl_args+=(--data-binary @-)
  if [[ -n "$agent_surface" ]]; then
    curl_args+=(-H "X-Agent-Surface: ${agent_surface}")
  fi

  local curl_status=0
  if (( machine_identity )); then
    # The Authorization header comes from a curl config read through a pipe (printf is a
    # builtin), so the token never appears in curl's argv.
    resp="$(printf '%s' "$encoded_body" | curl "${curl_args[@]}" \
      -K <(printf 'header = "Authorization: Bearer %s"\n' "$ACCESS_TOKEN") \
      -w $'\n'"${marker}%{http_code}")" || curl_status=$?
  else
    resp="$(printf '%s' "$encoded_body" | curl "${curl_args[@]}" -w $'\n'"${marker}%{http_code}")" || curl_status=$?
  fi
  # curl writes the -w marker even for a failed transfer (http code 000) and may have
  # streamed part of a body before the timeout fired, so resp is only read on success.
  if (( curl_status == 28 )); then
    fail_open "$client" "request timed out after ${max_time}s"
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
