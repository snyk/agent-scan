#
# Session-start discovery trampoline for Snyk Agent Guard (Windows).
# Sets the environment expected by `guard discover` and hands it this process's
# stdin, from which it reads the hook payload. Parameters mirror snyk-agent-guard.ps1.
#
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("claude-code","cursor","codex","github-copilot")]
    [string]$Client,

    [Parameter(Mandatory=$false)]
    [string]$PushKey,

    [Parameter(Mandatory=$false)]
    [string]$RemoteUrl,

    [Parameter(Mandatory=$false)]
    [string]$MachineId,

    [Parameter(Mandatory=$false)]
    [string]$MachineSerial,

    [Parameter(Mandatory=$false)]
    [string]$AgentScanCommand,

    [Parameter(Mandatory=$false)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [string]$TokenCommand,

    [Parameter(Mandatory=$false)]
    [string]$AdsBaseUrl,

    [Parameter(Mandatory=$false)]
    [ValidateSet("servers","skills","all")]
    [string]$Scope = "servers"
)

$ErrorActionPreference = "Stop"

if ($PushKey)   { $env:PUSH_KEY = $PushKey }
if ($RemoteUrl) { $env:REMOTE_HOOKS_BASE_URL = $RemoteUrl }
if (-not $MachineId) { $MachineId = $env:MACHINE_ID }
if (-not $MachineId) { exit 0 }
$env:MACHINE_ID = $MachineId
$env:MACHINE_SERIAL = $MachineSerial
# Machine identity for `guard discover` (see snyk-agent-guard.ps1).
if ($TenantId)     { $env:TENANT_ID = $TenantId }
if ($TokenCommand) { $env:ADS_TOKEN_COMMAND = $TokenCommand }
if ($AdsBaseUrl)   { $env:ADS_BASE_URL = $AdsBaseUrl }
# `guard discover` lets a push key win over machine identity, so a PUSH_KEY in the agent's
# environment must not reach it from a machine identity hook.
if (($TokenCommand -or $AdsBaseUrl) -and -not $PushKey) {
    Remove-Item Env:PUSH_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:PUSHKEY -ErrorAction SilentlyContinue
}

$cmd = if ($AgentScanCommand) { $AgentScanCommand } elseif ($env:AGENT_SCAN_COMMAND) { $env:AGENT_SCAN_COMMAND } else { $null }
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
