#
# Thin-client hook handler for forwarding agent hook events to Evo Agent Guard.
# Supports Claude Code, Cursor, and Codex via the -Client argument.
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
    [ValidateSet("claude-code","cursor","codex")]
    [string]$Client,

    [Parameter(Mandatory=$false)]
    [string]$PushKey,

    [Parameter(Mandatory=$false)]
    [string]$RemoteUrl,

    [Parameter(Mandatory=$false)]
    [string]$MachineId
)

$ErrorActionPreference = "Stop"

# Hook API version.
$VERSION = "2025-11-11"

# Install-time variables.
#
# `agent-scan guard install` substitutes each __PLACEHOLDER__ between the markers below as
# it copies this script into place (_hook_script_variables in guard.py). Always read them
# through Get-ScriptVar: this script also runs straight from the source tree, and a copy
# written by an older CLI will not know about variables added later, so a placeholder can
# survive. Keep the markers around declarations only -- the tests treat anything
# placeholder-shaped left between them as a substitution that install forgot.
#
# Keep these per-release, never per-machine. agent-monitor's tamper detection compares the
# installed script's checksum between installs, and a per-machine value would give every
# machine a different checksum for the same release.
# --- BEGIN install-time variables ---
$AGENT_SCAN_VERSION = "__AGENT_SCAN_VERSION__"
# --- END install-time variables ---

# Value of an install-time variable, or "unknown" when its placeholder was not substituted.
# The literal placeholder is worse than nothing on the wire: agent-monitor rejects it as a
# version anyway, and it would read as a real value everywhere else.
function Get-ScriptVar($value) {
    if (-not $value -or $value -match '^__[A-Za-z0-9_]+__$') { return "unknown" }
    return $value
}

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
}

$cliVersion = Get-ScriptVar $AGENT_SCAN_VERSION
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

# Execute request
try {
    $headers = @{
        "User-Agent"   = $userAgent
        "X-User"       = $xUser
        "Content-Type" = "text/plain"
        "X-Client-Id"  = $PushKey
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
