#requires -Version 5.1
# T8 native-parity sweep: runs every case (or the named ones) as its own process with a timeout, then writes a summary.
# Must run as the interactive standard user (session 1), because the Microsoft 365 Apps need a desktop.
[CmdletBinding()]
param(
    [string]$ProtectedRoot = 'C:\Protected',
    [string]$ControlRoot = 'C:\T8Control',
    [string]$SourceRoot = 'C:\T8Src',
    [string]$Out = 'C:\T8\parity',
    [string[]]$Case = @(),
    [int]$CaseTimeoutSeconds = 300
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'parity-cases.ps1')
[void](New-Item -ItemType Directory -Force -Path $Out)
$names = if ($Case.Count -gt 0) { $Case } else { @($Cases | ForEach-Object { $_.Name }) }
$summary = @()
foreach ($name in $names) {
    $args2 = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'parity-case.ps1'), '-Case', $name,
        '-ProtectedRoot', $ProtectedRoot, '-ControlRoot', $ControlRoot, '-SourceRoot', $SourceRoot, '-Out', $Out)
    foreach ($f in (Get-ChildItem -LiteralPath $Out -Filter ($name + '.*') -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $f.FullName -Force }
    $started = [DateTime]::UtcNow
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $args2 -WindowStyle Hidden -PassThru
    $done = $proc.WaitForExit($CaseTimeoutSeconds * 1000)
    $timedOut = -not $done
    if ($timedOut) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue; foreach ($n in 'WINWORD', 'EXCEL', 'POWERPNT') { Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue } }
    $json = Join-Path $Out ($name + '.json')
    $verdict = 'ERROR'; $deltas = @()
    if (Test-Path -LiteralPath $json) { $r = Get-Content -LiteralPath $json -Raw | ConvertFrom-Json; $verdict = $r.verdict; $deltas = @($r.deltas) }
    elseif ($timedOut) { $verdict = 'TIMEOUT' }
    $row = [ordered]@{ case = $name; verdict = $verdict; seconds = [int]([DateTime]::UtcNow - $started).TotalSeconds; startUtc = $started.ToString('o'); endUtc = [DateTime]::UtcNow.ToString('o'); deltas = $deltas }
    $summary += [pscustomobject]$row
    'CASE {0,-20} {1,-8} {2,4}s deltas={3}' -f $name, $verdict, $row.seconds, $deltas.Count
    foreach ($x in ($deltas | Select-Object -First 6)) { '    ' + $x }
}
[IO.File]::WriteAllText((Join-Path $Out 'summary.json'), (ConvertTo-Json -InputObject @($summary) -Depth 6), [Text.UTF8Encoding]::new($false))
'PARITY_DONE pass=' + @($summary | Where-Object { $_.verdict -eq 'PASS' }).Count + ' fail=' + @($summary | Where-Object { $_.verdict -ne 'PASS' }).Count
