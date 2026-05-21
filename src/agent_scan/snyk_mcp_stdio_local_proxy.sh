#!/usr/bin/env bash
set -eu

hash=$(printf '%s\0' "$@" | shasum -a 256 | cut -c1-12)
log=$(mktemp "/tmp/snyk_mcp_stdio_local_proxy.${hash}.XXXXXX")
printf 'snyk_mcp_stdio_local_proxy log: %s\n' "$log" >&2
"$@" | tee >(grep --line-buffered -E '"(tools|prompts|resources|resourceTemplates)"[[:space:]]*:[[:space:]]*\[|"serverInfo"[[:space:]]*:' >> "$log")
