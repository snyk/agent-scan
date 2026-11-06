#
# Session-start discovery trampoline for Snyk Agent Guard (Windows).
# Sets the environment expected by `guard discover` and hands it this process's
# stdin, from which it reads the hook payload.
#
# Usage:
#   powershell -File snyk-agent-guard-discover.ps1 -Client claude-code -Scope servers
#
# Configuration is read from snyk-agent-guard.conf next to this script, written by
# `snyk-agent-scan guard install`.
#
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("claude-code","cursor","codex","github-copilot")]
    [string]$Client,

    [Parameter(Mandatory=$false)]
    [ValidateSet("servers","skills","all")]
    [string]$Scope = "servers"
)

$ErrorActionPreference = "Stop"

$ConfigFile = Join-Path $PSScriptRoot "snyk-agent-guard.conf"
if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) { exit 0 }
$Config = @{}
foreach ($line in Get-Content -LiteralPath $ConfigFile -Encoding UTF8) {
    $parts = $line.Split([char[]]@('='), 2)
    if ($parts.Count -eq 2) { $Config[$parts[0]] = $parts[1] }
}

$env:PUSH_KEY = $Config["PUSH_KEY"]
$env:REMOTE_HOOKS_BASE_URL = $Config["REMOTE_HOOKS_BASE_URL"]
$env:MACHINE_ID = $Config["MACHINE_ID"]
if (-not $env:MACHINE_ID) { exit 0 }

$cmd = $Config["AGENT_SCAN_COMMAND"]
if (-not $cmd) { exit 0 }

$arguments = @("guard", "discover", "--client", $Client, "--scope", $Scope)

# Do not read stdin here. Invoking the binary outside a pipeline lets it inherit this
# process's stdin, so `guard discover` reads the hook payload itself under its own 5s
# cap -- matching snyk-agent-guard-discover.sh, which never touches fd 0. Reading it
# here instead would block forever on an agent that keeps the pipe open.
try {
    if (Test-Path -LiteralPath $cmd -PathType Leaf) {
        & $cmd @arguments *> $null
    } else {
        Invoke-Expression "$cmd $($arguments -join ' ')" *> $null
    }
} catch {
    # Session-start discovery is best-effort telemetry.
}
exit 0
