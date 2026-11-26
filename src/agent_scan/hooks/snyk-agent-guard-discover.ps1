#
# Session-start discovery trampoline for Snyk Agent Guard (Windows).
# Sets the environment expected by `guard discover` and hands it this process's
# stdin, from which it reads the hook payload.
#
# Usage:
#   powershell -File snyk-agent-guard-discover.ps1 -Client claude-code -Scope servers
#   powershell -File snyk-agent-guard-discover.ps1 -Client claude-code -Scope servers -FromEnv
#
# Configuration is read from snyk-agent-guard.conf next to this script, written by
# `snyk-agent-scan guard install`. Only when there is no such file and the command passes
# -FromEnv are the values taken from the environment instead; REMOTE_HOOKS_BASE_URL must
# then be a Snyk host, and AGENT_SCAN_COMMAND an existing file (it is never evaluated).
#
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("claude-code","cursor","codex","github-copilot")]
    [string]$Client,

    [Parameter(Mandatory=$false)]
    [ValidateSet("servers","skills","all")]
    [string]$Scope = "servers",

    # Accepted but never used: hook commands written by earlier versions still pass these,
    # and must keep working until `guard install` rewrites them. All values come from the
    # configuration file.
    [string]$PushKey,
    [string]$TokenCommand,
    [string]$RemoteUrl,
    [string]$TenantId,
    [string]$MachineId,
    [string]$MachineSerial,
    [string]$AgentScanCommand,

    [switch]$FromEnv
)

$ErrorActionPreference = "Stop"

$ConfigFile = Join-Path $PSScriptRoot "snyk-agent-guard.conf"
# Same rule as snyk-agent-guard.ps1.
$EnvUrlPattern = '^(https://([A-Za-z0-9-]+\.)*(snyk|snykgov)\.io|https?://(localhost|127\.0\.0\.1))(:[0-9]+)?(/.*)?$'
$Config = @{}
$valuesFromEnv = (-not (Test-Path -LiteralPath $ConfigFile)) -and $FromEnv
if ($valuesFromEnv) {
    $Config["PUSH_KEY"] = if ($env:PUSH_KEY) { $env:PUSH_KEY } else { $env:PUSHKEY }
    $Config["ADS_TOKEN_COMMAND"] = $env:ADS_TOKEN_COMMAND
    $Config["TENANT_ID"] = $env:TENANT_ID
    $Config["REMOTE_HOOKS_BASE_URL"] = $env:REMOTE_HOOKS_BASE_URL
    $Config["MACHINE_ID"] = $env:MACHINE_ID
    $Config["MACHINE_SERIAL"] = $env:MACHINE_SERIAL
    $Config["AGENT_SCAN_COMMAND"] = $env:AGENT_SCAN_COMMAND
    $envUrl = $Config["REMOTE_HOOKS_BASE_URL"]
    if ($envUrl -and $envUrl -cnotmatch $EnvUrlPattern) { exit 0 }
} else {
    if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) { exit 0 }
    # Session-start discovery is best-effort: an unreadable file ends it quietly, as in
    # snyk-agent-guard-discover.sh.
    try {
        $lines = Get-Content -LiteralPath $ConfigFile -Encoding UTF8
    } catch {
        exit 0
    }
    foreach ($line in $lines) {
        $parts = $line.Split([char[]]@('='), 2)
        if ($parts.Count -eq 2) { $Config[$parts[0]] = $parts[1] }
    }
}

# Every value is set, even when empty (which removes it): an inherited one must not stand in
# for the one captured at install. `guard discover` uses the push key when PUSH_KEY is set,
# and machine identity (ADS_TOKEN_COMMAND, TENANT_ID) otherwise, as snyk-agent-guard.ps1 does.
$env:PUSH_KEY = $Config["PUSH_KEY"]
$env:ADS_TOKEN_COMMAND = $Config["ADS_TOKEN_COMMAND"]
$env:TENANT_ID = $Config["TENANT_ID"]
$env:REMOTE_HOOKS_BASE_URL = $Config["REMOTE_HOOKS_BASE_URL"]
$env:MACHINE_ID = $Config["MACHINE_ID"]
$env:MACHINE_SERIAL = $Config["MACHINE_SERIAL"]
if (-not $env:MACHINE_ID) { exit 0 }

$cmd = $Config["AGENT_SCAN_COMMAND"]
if (-not $cmd) { exit 0 }
# A command from the environment runs only as an existing file, never through Invoke-Expression.
if ($valuesFromEnv -and -not (Test-Path -LiteralPath $cmd -PathType Leaf)) { exit 0 }

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
