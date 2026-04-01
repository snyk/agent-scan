#
# Thin-client hook handler for forwarding agent hook events to Evo Agent Guard.
# Supports both Claude Code and Cursor via the -Client argument.
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
    [ValidateSet("claude-code","cursor")]
    [string]$Client,

    [Parameter(Mandatory=$false)]
    [string]$PushKey,

    [Parameter(Mandatory=$false)]
    [string]$RemoteUrl
)

$ErrorActionPreference = "Stop"

# Hook API version.
$VERSION = "2025-11-11"

# Agent-scan CLI version (replaced at install time).
$AGENT_SCAN_VERSION = "__AGENT_SCAN_VERSION__"

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

switch ($Client) {
    "claude-code" {
        $endpoint = "/hidden/agent-monitor/hooks/claude-code"
    }
    "cursor" {
        $endpoint = "/hidden/agent-monitor/hooks/cursor"
    }
}

$userAgent = "snyk/snyk-agent-guard.ps1 Agent Scan v$AGENT_SCAN_VERSION"
$url = "${RemoteUrl}${endpoint}?version=$VERSION"

# Read payload from stdin
$payload = [Console]::In.ReadToEnd()
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

$xUser = '{{"hostname":"{0}","username":"{1}","identifier":"{2}"}}' -f `
    (JsonEscape $hostname), (JsonEscape $username), (JsonEscape $hostname)

# Execute request
try {
    $headers = @{
        "User-Agent"   = $userAgent
        "X-User"       = $xUser
        "Content-Type" = "text/plain"
        "X-Client-Id"  = $PushKey
    }
    $response = Invoke-WebRequest -Uri $url -Method POST -Body $body -Headers $headers -UseBasicParsing
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
