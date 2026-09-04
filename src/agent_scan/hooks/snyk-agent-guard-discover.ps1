#
# Session-start discovery trampoline for Snyk Agent Guard (Windows).
# Sets the environment expected by `guard discover` and hands it this process's
# stdin, from which it reads the hook payload. Parameters mirror snyk-agent-guard.ps1.
#
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("claude-code","cursor","codex")]
    [string]$Client,

    [Parameter(Mandatory=$false)]
    [string]$PushKey,

    [Parameter(Mandatory=$false)]
    [string]$RemoteUrl,

    [Parameter(Mandatory=$false)]
    [string]$MachineId,

    [Parameter(Mandatory=$false)]
    [string]$AgentScanCommand,

    [Parameter(Mandatory=$false)]
    [ValidateSet("servers","skills","all")]
    [string]$Scope = "servers",

    [Parameter(Mandatory=$false)]
    [string]$SkipDiscoveryScopes
)

$ErrorActionPreference = "Stop"

if ($PushKey)   { $env:PUSH_KEY = $PushKey }
if ($RemoteUrl) { $env:REMOTE_HOOKS_BASE_URL = $RemoteUrl }
if (-not $MachineId) { $MachineId = $env:MACHINE_ID }
if (-not $MachineId) { exit 0 }
$env:MACHINE_ID = $MachineId

$cmd = if ($AgentScanCommand) { $AgentScanCommand } elseif ($env:AGENT_SCAN_COMMAND) { $env:AGENT_SCAN_COMMAND } else { $null }
if (-not $cmd) { exit 0 }

$arguments = @("guard", "discover", "--client", $Client, "--scope", $Scope)
if ($SkipDiscoveryScopes) { $arguments += @("--skip-discovery-scopes", $SkipDiscoveryScopes) }

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
