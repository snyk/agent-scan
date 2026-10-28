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
    [string]$ClientId,

    [Parameter(Mandatory=$false)]
    [string]$RemoteUrl,

    [Parameter(Mandatory=$false)]
    [string]$MachineId,

    [Parameter(Mandatory=$false)]
    [string]$AgentScanCommand,

    [Parameter(Mandatory=$false)]
    [ValidateSet("servers","skills","all")]
    [string]$Scope = "servers"
)

$ErrorActionPreference = "Stop"

# --- BEGIN install-time variables ---
$INSTALL_CLIENT_ID = "__AGENT_GUARD_CLIENT_ID__"
$INSTALL_REMOTE_HOOKS_BASE_URL = "__AGENT_GUARD_REMOTE_HOOKS_BASE_URL__"
$INSTALL_MACHINE_ID = '__AGENT_GUARD_MACHINE_ID__'
$INSTALL_AGENT_SCAN_COMMAND = '__AGENT_GUARD_AGENT_SCAN_COMMAND__'
# --- END install-time variables ---

# Installed values take precedence over parameters, which take precedence over env vars,
# so a hook command edited in the agent config cannot redirect a filled-in script.
# Parameters and env vars are only a fallback for a script never filled in.
if ($INSTALL_CLIENT_ID -ne "__AGENT_GUARD_CLIENT_ID__") { $env:CLIENT_ID = $INSTALL_CLIENT_ID } elseif ($ClientId) { $env:CLIENT_ID = $ClientId }
if ($INSTALL_REMOTE_HOOKS_BASE_URL -ne "__AGENT_GUARD_REMOTE_HOOKS_BASE_URL__") { $env:REMOTE_HOOKS_BASE_URL = $INSTALL_REMOTE_HOOKS_BASE_URL } elseif ($RemoteUrl) { $env:REMOTE_HOOKS_BASE_URL = $RemoteUrl }
if ($INSTALL_MACHINE_ID -ne "__AGENT_GUARD_MACHINE_ID__") { $MachineId = $INSTALL_MACHINE_ID } elseif (-not $MachineId) { $MachineId = $env:MACHINE_ID }
if (-not $MachineId) { exit 0 }
$env:MACHINE_ID = $MachineId

$cmd = if ($INSTALL_AGENT_SCAN_COMMAND -ne "__AGENT_GUARD_AGENT_SCAN_COMMAND__") { $INSTALL_AGENT_SCAN_COMMAND } elseif ($AgentScanCommand) { $AgentScanCommand } elseif ($env:AGENT_SCAN_COMMAND) { $env:AGENT_SCAN_COMMAND } else { $null }
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
