#
# Thin-client hook handler for forwarding agent hook events to Evo Agent Guard.
# Supports Claude Code, Cursor, Codex, and Github Copilot via the -Client argument.
#
# Usage:
#   powershell -File snyk-agent-guard.ps1 -Client claude-code
#   powershell -File snyk-agent-guard.ps1 -Client claude-code -FromEnv
#
# Configuration is read from snyk-agent-guard.conf next to this script, written by
# `snyk-agent-scan guard install` (see the Configuration section below). Only when there is
# no such file and the command passes -FromEnv are the values taken from the environment
# instead (PUSH_KEY or PUSHKEY, ADS_TOKEN_COMMAND, REMOTE_HOOKS_BASE_URL, TENANT_ID,
# MACHINE_ID, MACHINE_SERIAL); REMOTE_HOOKS_BASE_URL must then be a Snyk host. Without
# either, the script stops with a usage error.
#
# Reads a JSON payload from stdin and POSTs it (base64-encoded) to the Agent Guard endpoint.
#
# Two auth modes, chosen by guard install and never mixed (see snyk-agent-guard.sh): the push key
# (PUSH_KEY, REMOTE_HOOKS_BASE_URL), or machine identity (ADS_TOKEN_COMMAND, REMOTE_HOOKS_BASE_URL
# and TENANT_ID). With machine identity every run calls
# `<token command> token --base-url <remote url>` and POSTs to the tenant route with the token as
# a bearer token. A push key wins: when PUSH_KEY is set, ADS_TOKEN_COMMAND is ignored. Machine
# identity applies when no push key is set and ADS_TOKEN_COMMAND is; a missing value is then a
# usage error. A token command that fails, times out or prints anything other than one token
# fails open like an unreachable API; there is no fallback to the push key. The token is never
# logged and never put on a command line.
#
# The request is bounded by $TIMEOUT_SECONDS below. Transport and HTTP failures, that timeout
# included, fail open: exit 0, one line on stderr, and on stdout a systemMessage JSON object
# for the clients whose hook output defines one (Claude Code, Codex) so the user is told
# that Agent Guard did not validate the action; nothing on stdout for the others. Usage
# errors exit 1.
#
# Requirements: PowerShell 5.1+ (built-in on Windows 10+)
#
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("claude-code","cursor","codex","github-copilot")]
    [string]$Client,

    # Accepted but never used: hook commands written by earlier versions still pass these,
    # and must keep working until `guard install` rewrites them. All values come from the
    # configuration file; the variables are overwritten from it below.
    [string]$PushKey,
    [string]$TokenCommand,
    [string]$RemoteUrl,
    [string]$TenantId,
    [string]$MachineId,
    [string]$MachineSerial,

    [switch]$FromEnv
)

$ErrorActionPreference = "Stop"

# Agent-scan CLI version (replaced by the release pipeline).
$AGENT_SCAN_VERSION = "__AGENT_SCAN_VERSION__"

# Hook API version. agent-monitor publishes both hook routes (push key and tenant) under it.
$VERSION = "2025-11-11"

# Timeout, in seconds, for the whole request (same reasoning as snyk-agent-guard.sh: the
# agent caps the hook at 65 s and agent-monitor may legitimately take ~50 s to answer). With
# machine identity the token command's time comes out of it too.
$TIMEOUT_SECONDS = 60

# What the user is told when the hook fails open. Embedded in JSON verbatim, so it must stay
# free of double quotes, backslashes and control characters (pinned by a test).
$FAIL_OPEN_MESSAGE = "Unable to reach Snyk Evo to validate agent behavior. Please check your network and configuration and try again."

# Clients whose hook output schema defines systemMessage, a warning the agent shows the
# user (see supports_system_message in snyk-agent-guard.sh for why Cursor and Copilot must
# get nothing on stdout).
$SYSTEM_MESSAGE_CLIENTS = @("claude-code", "codex")

# Transport and HTTP failures must not block the agent (see snyk-agent-guard.sh): exit 0,
# the user-facing sentence plus the technical reason on stderr, and the sentence as a
# systemMessage on stdout only where the client renders it. [Console]::Error is used
# instead of Write-Error, which $ErrorActionPreference = "Stop" would turn into a
# terminating error, a multi-line ErrorRecord and exit code 1. Usage errors below keep
# Write-Error and exit 1.
function FailOpen([string]$reason) {
    [Console]::Error.WriteLine("snyk-agent-guard: $FAIL_OPEN_MESSAGE ($reason; failing open)")
    if ($SYSTEM_MESSAGE_CLIENTS -contains $Client) {
        [Console]::Out.WriteLine('{"systemMessage":"' + $FAIL_OPEN_MESSAGE + '"}')
    }
    exit 0
}

# Runs `<command> token --base-url <base url>` for at most $timeoutSeconds and returns the
# access token it prints. Throws with a fixed reason when the command cannot start, fails, does
# not finish in time or prints anything other than one token. The token only ever travels
# through the child's stdout; its stderr is read and dropped so nothing it prints reaches the
# agent.
function Get-AccessToken([string]$command, [string]$baseUrl, [int]$timeoutSeconds) {
    $process = $null
    # The base URL goes into a hand-quoted argument string; guard install refuses one that would
    # need escaping there, and so does this.
    if ($baseUrl -match '["\\\s]') {
        throw "REMOTE_HOOKS_BASE_URL is not a plain URL"
    }
    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $command
        $startInfo.Arguments = 'token --base-url "' + $baseUrl + '"'
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        try {
            $process = [System.Diagnostics.Process]::Start($startInfo)
        } catch {
            throw "token command could not run"
        }
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $null = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($timeoutSeconds * 1000)) {
            try { $process.Kill() } catch { }
            throw "token command did not finish in time"
        }
        if ($process.ExitCode -ne 0) {
            throw "token command failed (exit $($process.ExitCode))"
        }
        if (-not $stdout.Wait(1000)) {
            throw "token command output did not finish"
        }
        $token = $stdout.Result.Trim()
        if (-not $token -or $token -match '\s') {
            throw "token command printed no single access token"
        }
        return $token
    } finally {
        if ($process) { $process.Dispose() }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Installation configuration, written by `snyk-agent-scan guard install` next to this
# script.
$ConfigFile = Join-Path $PSScriptRoot "snyk-agent-guard.conf"
# The endpoint an environment may name: https to snyk.io, snykgov.io or a subdomain, or
# localhost. The configuration file is trusted and not checked.
$EnvUrlPattern = '^(https://([A-Za-z0-9-]+\.)*(snyk|snykgov)\.io|https?://(localhost|127\.0\.0\.1))(:[0-9]+)?(/.*)?$'
$Config = @{}
if (-not (Test-Path -LiteralPath $ConfigFile) -and $FromEnv) {
    $ConfigSource = "the environment"
    $Config["PUSH_KEY"] = if ($env:PUSH_KEY) { $env:PUSH_KEY } else { $env:PUSHKEY }
    $Config["ADS_TOKEN_COMMAND"] = $env:ADS_TOKEN_COMMAND
    $Config["TENANT_ID"] = $env:TENANT_ID
    $Config["REMOTE_HOOKS_BASE_URL"] = $env:REMOTE_HOOKS_BASE_URL
    $Config["MACHINE_ID"] = $env:MACHINE_ID
    $Config["MACHINE_SERIAL"] = $env:MACHINE_SERIAL
    $envUrl = $Config["REMOTE_HOOKS_BASE_URL"]
    if ($envUrl -and $envUrl -cnotmatch $EnvUrlPattern) {
        Write-Error "REMOTE_HOOKS_BASE_URL from the environment is not a Snyk endpoint: $envUrl"
        exit 1
    }
} else {
    $ConfigSource = $ConfigFile
    if (-not (Test-Path -LiteralPath $ConfigFile -PathType Leaf)) {
        Write-Error "Configuration file not found: $ConfigFile (run 'snyk-agent-scan guard install')"
        exit 1
    }
    foreach ($line in Get-Content -LiteralPath $ConfigFile -Encoding UTF8) {
        $parts = $line.Split([char[]]@('='), 2)
        if ($parts.Count -eq 2) { $Config[$parts[0]] = $parts[1] }
    }
}
# Always overwritten, even with nothing: a value passed on the command line is never used.
$PushKey = $Config["PUSH_KEY"]
$TokenCommand = $Config["ADS_TOKEN_COMMAND"]
$TenantId = $Config["TENANT_ID"]
$RemoteUrl = $Config["REMOTE_HOOKS_BASE_URL"]
$MachineId = $Config["MACHINE_ID"]
$MachineSerial = $Config["MACHINE_SERIAL"]

# A push key wins over machine identity (see the header).
$machineIdentity = (-not $PushKey) -and [bool]$TokenCommand
if (-not $RemoteUrl) {
    $required = if ($machineIdentity) { " (machine identity needs ADS_TOKEN_COMMAND, REMOTE_HOOKS_BASE_URL and TENANT_ID)" } else { "" }
    Write-Error "REMOTE_HOOKS_BASE_URL is not set in $ConfigSource$required"
    exit 1
}
if ($machineIdentity) {
    if (-not $TenantId) {
        Write-Error "TENANT_ID is not set in $ConfigSource (machine identity needs ADS_TOKEN_COMMAND, REMOTE_HOOKS_BASE_URL and TENANT_ID)"
        exit 1
    }
    # A bare name would be looked up in PATH and the current directory.
    if (-not [System.IO.Path]::IsPathRooted($TokenCommand)) {
        Write-Error "ADS_TOKEN_COMMAND must be an absolute path"
        exit 1
    }
    # Tenant ids are UUIDs; one that would need escaping in the URL path is refused.
    if ($TenantId -notmatch '^[A-Za-z0-9._~-]+$') {
        Write-Error "TENANT_ID is not a valid tenant id"
        exit 1
    }
} elseif (-not $PushKey) {
    Write-Error "PUSH_KEY is not set in $ConfigSource"
    exit 1
}
if (-not $MachineId) {
    Write-Error "MACHINE_ID is not set in $ConfigSource"
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
if ($machineIdentity) {
    $url = "$($RemoteUrl.TrimEnd('/'))/hidden/tenants/${TenantId}$($endpoint.Substring('/hidden'.Length))?version=$VERSION"
} else {
    $url = "${RemoteUrl}${endpoint}?version=$VERSION"
}

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

$serial = if ($MachineSerial) { $MachineSerial } else { $null }
$xUser = @{
    hostname = $hostname
    username = $username
    identifier = $MachineId
    cli_version = $cliVersion
    machine_serial = $serial
} | ConvertTo-Json -Compress

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

# With machine identity the token command runs first, on every invocation, and its time comes
# out of $TIMEOUT_SECONDS, so the hook as a whole stays within the budget.
$requestTimeout = $TIMEOUT_SECONDS
$accessToken = $null
if ($machineIdentity) {
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $accessToken = Get-AccessToken $TokenCommand $RemoteUrl $TIMEOUT_SECONDS
    } catch {
        FailOpen "$($_.Exception.Message)"
    }
    $requestTimeout = [Math]::Max(1, $TIMEOUT_SECONDS - [int][Math]::Ceiling($stopwatch.Elapsed.TotalSeconds))
}

# Execute request. Any failure past this point fails open; see FailOpen.
try {
    $headers = @{
        "User-Agent"   = $userAgent
        "X-User"       = $xUser
        "Content-Type" = "text/plain"
    }
    if ($machineIdentity) {
        $headers["Authorization"] = "Bearer $accessToken"
    } else {
        $headers["X-Client-Id"] = $PushKey
    }
    if ($agentSurface) {
        $headers["X-Agent-Surface"] = $agentSurface
    }
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $response = Invoke-WebRequest -Uri $url -Method POST -Body $bodyBytes -Headers $headers `
        -UseBasicParsing -TimeoutSec $requestTimeout
} catch {
    $ex = $_.Exception
    $statusCode = 0
    if ($ex.Response) {
        try { $statusCode = [int]$ex.Response.StatusCode } catch { $statusCode = 0 }
    }
    if ($statusCode -ge 400) {
        FailOpen "HTTP $statusCode"
    }
    # Windows PowerShell 5.1 surfaces -TimeoutSec as a WebException with Status Timeout;
    # PowerShell 7 raises an OperationCanceledException instead. -TimeoutSec bounds the
    # connection and the wait for response headers; a body that stalls afterwards is left
    # to the agent's own hook timeout.
    $timedOut = (
        ($ex -is [System.Net.WebException] -and $ex.Status -eq [System.Net.WebExceptionStatus]::Timeout) -or
        ($ex -is [System.OperationCanceledException])
    )
    if ($timedOut) {
        FailOpen "request timed out after ${requestTimeout}s"
    }
    FailOpen "request failed: $($ex.Message)"
}
Write-Output $response.Content
