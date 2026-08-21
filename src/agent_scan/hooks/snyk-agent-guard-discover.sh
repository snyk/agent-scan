#!/usr/bin/env bash
set -euo pipefail
exec "${AGENT_SCAN_BIN:-snyk-agent-scan}" guard discover "$@" >/dev/null 2>&1
