@echo off
where /q pwsh && set "PS=pwsh" || set "PS=powershell"
%PS% -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s=Get-Content -Raw -LiteralPath '%~f0'; & ([ScriptBlock]::Create($s.Substring($s.IndexOf('#---PS---')))) %*"
exit /b %ERRORLEVEL%

#---PS---
param(
  [Parameter(ValueFromRemainingArguments=$true)][string[]]$Cmd
)

if (-not $Cmd) { [Console]::Error.WriteLine("snyk_mcp_stdio_local_proxy: no command"); exit 2 }

$joined = ($Cmd -join "`0")
$bytes  = [System.Text.Encoding]::UTF8.GetBytes($joined)
$sha    = [System.Security.Cryptography.SHA256]::Create()
$hash   = (-join ($sha.ComputeHash($bytes) | ForEach-Object { '{0:x2}' -f $_ })).Substring(0, 12)

$dir    = if ($env:TEMP) { $env:TEMP } else { "C:\Windows\Temp" }
$rand   = -join ((1..6) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
$log    = Join-Path $dir "snyk_mcp_stdio_local_proxy.$hash.$rand.log"
[Console]::Error.WriteLine("snyk_mcp_stdio_local_proxy log: $log")

$exe  = $Cmd[0]
$rest = if ($Cmd.Count -gt 1) { $Cmd[1..($Cmd.Count-1)] } else { @() }
& $exe @rest | ForEach-Object {
  $_
  if ($_ -match '"(tools|prompts|resources|resourceTemplates)"\s*:\s*\[|"serverInfo"\s*:') { Add-Content -LiteralPath $log -Value $_ }
}
exit $LASTEXITCODE
