#
# Thin-client hook handler for forwarding agent hook events to Evo Agent Guard.
# Supports Claude Code, Cursor, Codex, and Github Copilot via the -Client argument.
#
# Usage:
#   powershell -File snyk-agent-guard.ps1 -Client claude-code -PushKey '...' -RemoteUrl 'https://...'
#
# Reads a JSON payload from stdin and POSTs it (base64-encoded) to the Agent Guard endpoint.
#
# Requirements: PowerShell 5.1+ (built-in on Windows 10+)
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
    [string]$MachineId
)

$ErrorActionPreference = "Stop"

# --- BEGIN install-time variables ---
# Agent-scan CLI version (replaced at install time).
$AGENT_SCAN_VERSION = "__AGENT_SCAN_VERSION__"
# --- END install-time variables ---

# Hook API version.
$VERSION = "2025-11-11"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Parameters take precedence over env vars.
if (-not $PushKey) { $PushKey = if ($env:PUSH_KEY) { $env:PUSH_KEY } elseif ($env:PUSHKEY) { $env:PUSHKEY } else { $null } }
if (-not $PushKey) {
    Write-Error "PUSH_KEY is required (pass -PushKey or set env var)"
    exit 1
}

if (-not $RemoteUrl) { $RemoteUrl = $env:REMOTE_HOOKS_BASE_URL }
if (-not $RemoteUrl) {
    Write-Error "REMOTE_HOOKS_BASE_URL is required (pass -RemoteUrl or set env var)"
    exit 1
}

if (-not $MachineId) { $MachineId = $env:MACHINE_ID }
if (-not $MachineId) {
    Write-Error "MACHINE_ID is required (pass -MachineId or set env var)"
    exit 1
}

switch ($Client) {
    "claude-code" {
        $endpoint = "/hidden/agent-monitor/hooks/claude-code"
    }
    "cursor" {
        $endpoint = "/hidden/agent-monitor/hooks/cursor"
    }
    "codex" {
        $endpoint = "/hidden/agent-monitor/hooks/codex"
    }
    "github-copilot" {
        $endpoint = "/hidden/agent-monitor/hooks/github-copilot"
    }
}

$cliVersion = $AGENT_SCAN_VERSION
# Only a copy install never filled in still holds the placeholder, and the literal must
# not reach the wire. This sits outside the variables section on purpose: substituting
# over it would rewrite the very literal it tests for.
if ($cliVersion -eq '__AGENT_SCAN_VERSION__') {
    $cliVersion = "unknown"
}
$userAgent = "snyk/snyk-agent-guard.ps1 Agent Scan v$cliVersion"
$url = "${RemoteUrl}${endpoint}?version=$VERSION"

# Read payload from stdin as UTF-8 (strips BOM automatically)
$reader = New-Object System.IO.StreamReader([Console]::OpenStandardInput(), [System.Text.Encoding]::UTF8, $true)
$payload = $reader.ReadToEnd().Trim()
if (-not $payload) {
    Write-Error "Expected JSON payload on stdin"
    exit 1
}

# Base64 encode
$bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
$encoded = [System.Convert]::ToBase64String($bytes)
$body = "base64:$encoded"

# Build X-User header
$hostname = try { [System.Net.Dns]::GetHostName() } catch { "unknown" }
$username = try { [System.Environment]::UserName } catch { "unknown" }

# Minimal JSON escaping
function JsonEscape($s) {
    $s = $s -replace '\\', '\\\\'
    $s = $s -replace '"', '\"'
    $s = $s -replace "`t", '\t'
    $s = $s -replace "`r", '\r'
    $s = $s -replace "`n", '\n'
    return $s
}

$xUser = '{{"hostname":"{0}","username":"{1}","identifier":"{2}","cli_version":"{3}"}}' -f `
    (JsonEscape $hostname), (JsonEscape $username), (JsonEscape $MachineId), (JsonEscape $cliVersion)

# Identify whether GitHub Copilot invoked this hook (see get_agent_surface in
# snyk-agent-guard.sh for why the -Client argument cannot answer this: one Copilot hook
# config is shared by the CLI, Copilot in VS Code, and the Copilot desktop app, so only
# the inherited environment identifies them). Empty when the sender isn't Copilot, in
# which case the header is omitted and agent-monitor falls back to its non-Copilot
# agent name.
# Only reported for the Copilot client: these variables describe the environment rather
# than the caller and are inherited, so another agent running inside a Copilot session
# would otherwise claim a Copilot surface.
$agentSurface = if ($Client -ne "github-copilot") {
    ""
} elseif ($env:AI_AGENT -eq "github_copilot_vscode_agent") {
    "copilot-vscode"
} elseif ($env:AI_AGENT -like "github_copilot_*" -or $env:COPILOT_CLI) {
    "copilot"
} else {
    ""
}

# Execute request
try {
    $headers = @{
        "User-Agent"   = $userAgent
        "X-User"       = $xUser
        "Content-Type" = "text/plain"
        "X-Client-Id"  = $PushKey
    }
    if ($agentSurface) {
        $headers["X-Agent-Surface"] = $agentSurface
    }
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $response = Invoke-WebRequest -Uri $url -Method POST -Body $bodyBytes -Headers $headers -UseBasicParsing
    Write-Output $response.Content
} catch {
    $statusCode = $null
    if ($_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
    }
    if ($statusCode) {
        Write-Error "Error: $statusCode"
    } else {
        Write-Error "Request failed: $_"
    }
    exit 1
}
