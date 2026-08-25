#
# Session-start discovery trampoline for Snyk Agent Guard (Windows).
# Sets the environment expected by `guard discover` and forwards the hook
# payload from stdin. Parameters mirror snyk-agent-guard.ps1.
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
    [string]$AgentScanBin,

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

$bin = if ($AgentScanBin) { $AgentScanBin } elseif ($env:AGENT_SCAN_BIN) { $env:AGENT_SCAN_BIN } else { "snyk-agent-scan" }
if (-not (Get-Command $bin -ErrorAction SilentlyContinue)) { $bin = "snyk-agent-scan" }

$arguments = @("guard", "discover", "--client", $Client, "--scope", $Scope)

$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), [System.Text.Encoding]::UTF8, $true)
$payload = $reader.ReadToEnd()
try {
    $payload | & $bin @arguments *> $null
} catch {
    # Session-start discovery is best-effort telemetry.
}
exit 0
