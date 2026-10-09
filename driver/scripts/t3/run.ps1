# Runs one T3 workload body (dot-sourced, so it shares $r) as the scheduled task's SYSTEM user and writes C:\T3\result.json.
param([Parameter(Mandatory)][string]$Body)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path C:\T3 | Out-Null
$r = [ordered]@{ ok = $false }
try { . $Body } catch { $r.ok = $false; $r.error = $_.Exception.Message }
$r | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath C:\T3\result.json -Encoding UTF8
