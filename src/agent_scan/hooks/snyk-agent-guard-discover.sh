#!/usr/bin/env bash
set -euo pipefail
exec "${AGENT_SCAN_BIN:-snyk-agent-scan}" guard discover --hook-project-folder-payload-key cwd
