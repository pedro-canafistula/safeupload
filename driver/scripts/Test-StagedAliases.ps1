<# Synthetic preexisting-link probe. Only on the recorded isolated debuggee. #>
param([switch] $ReproduceKnownGap)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-alias.sys'
$id = [guid]::NewGuid().ToString('N')
$target = 'C:\SafeUpload\Escopo Monitorado\alias-' + $id + '.txt'
$alias = 'C:\Users\vika\Documents\alias-' + $id + '.txt'
$serviceDir = 'C:\Users\vika\Documents\stage-service-publish'
$agent = $null; $loaded = $false; $replaced = $false; $observer = $null
if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters) -match '^SafeUpload\s') { throw 'Original baseline requires unloaded filter.' }
try {
    [IO.File]::WriteAllText($target, 'approved fixture')
    New-Item -ItemType HardLink -Path $alias -Target $target | Out-Null
    & fsutil.exe file queryfileid $target
    & fsutil.exe file queryfileid $alias
    & fsutil.exe hardlink list $target
    # Held physical reader predates the filter; source classification cannot
    # hide a destination-byte leak by denying a new sensitive source open.
    $observer = [IO.FileStream]::new($target, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    Copy-Item $installed $backup -Force
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Load failed.' }
    $loaded = $true
    $agent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-alias-service'
    Start-Sleep -Seconds 2
    # A fresh process has no source-read taint and no private view.
    $write = & powershell.exe -NoProfile -Command "try { [IO.File]::WriteAllText('$alias','CPF: 529.982.247-25'); 'written' } catch { 'denied' }"
    if ($LASTEXITCODE -ne 0) { throw 'Writer probe failed.' }
    $bytes = New-Object byte[] 128
    $count = $observer.Read($bytes,0,$bytes.Length)
    $observed = [Text.Encoding]::UTF8.GetString($bytes,0,$count)
    $isolated = $observed -eq 'approved fixture'
    Write-Output "OutsideAliasWrite=$write; IndependentDestinationIsolated=$isolated"
    if ($ReproduceKnownGap) {
        if ($write -ne 'written' -or $observed -ne 'CPF: 529.982.247-25') { throw 'Expected alias gap was not reproduced.' }
        Write-Output 'KnownPathIdentityGapReproduced=True'
    } elseif (-not $isolated) { throw 'Preexisting hard-link alias changed protected physical bytes.' }
}
finally {
    if ($null -ne $observer) { $observer.Dispose() }
    Stop-StagedTestAgent $agent
    if ($replaced) { Restore-StagedTestDriver $backup $loaded }
    Remove-StagedTestFiles @($alias, $target)
    Write-Output 'DisposableAliasFixturesRemoved=True'
}
