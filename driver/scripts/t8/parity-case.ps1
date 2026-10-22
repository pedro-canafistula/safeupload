#requires -Version 5.1
# Runs ONE T8 parity case on both sides (unprotected control folder first, then the protected folder) and writes <Out>\<case>.json.
# Started by parity-run.ps1 in its own process so a hung application cannot stop the sweep; steps are appended to
# <Out>\<case>.<side>.steps.ndjson as they finish, so a timeout still shows how far each side got.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Case,
    [Parameter(Mandatory)][string]$ProtectedRoot,
    [Parameter(Mandatory)][string]$ControlRoot,
    [Parameter(Mandatory)][string]$SourceRoot,
    [Parameter(Mandatory)][string]$Out,
    [int]$SettleSeconds = 60
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'parity-lib.ps1')
. (Join-Path $PSScriptRoot 'parity-cases.ps1')
$def = @($Cases | Where-Object { $_.Name -ceq $Case })
if ($def.Count -ne 1) { throw ('Unknown case ' + $Case) }
$def = $def[0]
$script:Roots = @($ProtectedRoot, $ControlRoot, $SourceRoot)
foreach ($dir in $ProtectedRoot, $ControlRoot, $SourceRoot, $Out) { if (-not (Test-Path -LiteralPath $dir)) { throw ('Missing folder ' + $dir) } }
Stop-OfficeProcesses
$control = Invoke-Side 'control' $ControlRoot $def.Fn (Join-Path $Out ($Case + '.control.steps.ndjson')) $SourceRoot $SettleSeconds
Stop-OfficeProcesses
$protected = Invoke-Side 'protected' $ProtectedRoot $def.Fn (Join-Path $Out ($Case + '.protected.steps.ndjson')) $SourceRoot $SettleSeconds
$options = @{ Deterministic = [bool]$def.Deterministic; CompareTimes = [bool]($def.ContainsKey('CompareTimes') -and $def.CompareTimes) }
$deltas = @(Compare-Sides $control $protected $options)
$result = [ordered]@{
    case = $Case; user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    verdict = $(if ($deltas.Count -eq 0) { 'PASS' } else { 'FAIL' })
    deltas = $deltas; control = $control; protected = $protected
}
[IO.File]::WriteAllText((Join-Path $Out ($Case + '.json')), (ConvertTo-Json -InputObject $result -Depth 8), [Text.UTF8Encoding]::new($false))
'CASE ' + $Case + ' ' + $result.verdict + ' deltas=' + $deltas.Count
