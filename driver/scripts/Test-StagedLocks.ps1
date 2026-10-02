<# Compare owned byte locks with unfiltered NTFS, including pending cancellation. #>
param([switch] $Verifier, [ValidateRange(1,256)][int] $Iterations=1)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
. (Join-Path $PSScriptRoot 'StagedLockProcess.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedLockProbe.cs')
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup='C:\Users\vika\Documents\SafeUpload-original-before-locks.sys'
$id=[guid]::NewGuid().ToString('N')
$reference=Join-Path $env:TEMP ('lock-reference-'+$id+'.txt')
$target='C:\SafeUpload\Escopo Monitorado\locks-'+$id+'.txt'
$loaded=$false; $replaced=$false; $verified=$false; $agent=$null; $cleanup=@(); $observer=$null
if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters) -match '^SafeUpload\s') { throw 'Expected unloaded baseline.' }
try {
    $initial='A'*4096
    [IO.File]::WriteAllText($reference,$initial)
    $timer=[Diagnostics.Stopwatch]::StartNew()
    for($iteration=0;$iteration -lt $Iterations;$iteration++){[StagedLockProbe]::Run($reference)}
    $timer.Stop()
    Write-Output "UnfilteredNTFSLockReference=True Iterations=$Iterations Milliseconds=$($timer.ElapsedMilliseconds)"
    $referenceProcess=Test-StagedLockProcess $reference
    Write-Output "UnfilteredCrossProcessLockBeforeExitAfterExitAfterClose=$referenceProcess"
    $expectedBytes=[IO.File]::ReadAllBytes($reference)
    [IO.File]::WriteAllText($target,$initial)
    $observer=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    Backup-StagedTestDriver $backup
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force
    $replaced=$true
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Verifier setup failed.' }
        $verified=$true
    }
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Load failed.' }
    $loaded=$true
    $agent=Start-StagedTestAgent 'C:\Users\vika\Documents\stage-service-publish' 'C:\Users\vika\Documents\stage-lock-service'
    $ready=$false
    for ($i=0; $i -lt 40 -and -not $ready; $i++) {
        Start-Sleep -Milliseconds 250
        try { $pin=[StagedLockProbe]::Open($target,$false); $ready=$true } catch { }
    }
    if (-not $ready) { throw 'Private writer did not open.' }
    try {
        $timer=[Diagnostics.Stopwatch]::StartNew()
        for($iteration=0;$iteration -lt $Iterations;$iteration++){[StagedLockProbe]::Run($target)}
        $timer.Stop()
        Write-Output "OwnedExclusiveSharedPendingCancelDuplicateCleanupAndMappedLocks=True Iterations=$Iterations Milliseconds=$($timer.ElapsedMilliseconds)"
        $ownedProcess=Test-StagedLockProcess $target
        Write-Output "OwnedCrossProcessLockBeforeExitAfterExitAfterClose=$ownedProcess"
        if($ownedProcess -ne $referenceProcess){throw 'Duplicated lock ownership differs from NTFS.'}
        $physical=New-Object byte[] 4096
        if ($observer.Read($physical,0,$physical.Length) -ne 4096 -or
            [Text.Encoding]::UTF8.GetString($physical) -ne $initial) { throw 'Unapproved lock/mapped writes changed the physical destination.' }
        Write-Output 'HeldIndependentPhysicalReaderIsolated=True'
    } finally { $pin.Dispose() }
    # Fresh independent opens must eventually see the exact approved result.
    $released=$false
    for ($i=0; $i -lt 80 -and -not $released; $i++) {
        Start-Sleep -Milliseconds 250
        $observe=@'
$file=[IO.FileStream]::new('__TARGET__',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {$bytes=New-Object byte[] 4096; $count=$file.Read($bytes,0,4096); [Convert]::ToBase64String($bytes,0,$count)} finally {$file.Dispose()}
'@
        $actual=& powershell.exe -NoProfile -Command ($observe.Replace('__TARGET__',$target))
        $released=$actual -eq [Convert]::ToBase64String($expectedBytes)
    }
    if (-not $released) {
        foreach($path in (Get-ChildItem 'C:\ProgramData\SafeUpload\staging-journal' -Filter '*.json')) {
            $entry=Get-Content -LiteralPath $path.FullName -Raw | ConvertFrom-Json
            if($entry.Transfer.DestinationPath -eq $target){Write-Output ($entry | ConvertTo-Json -Depth 20 -Compress)}
        }
        Write-Output ('ExpectedBase64='+[Convert]::ToBase64String($expectedBytes))
        Write-Output "ObservedBase64=$actual"
        throw 'Exact lock/mapping result was not published.'
    }
    Write-Output 'LockResultApprovedAndPublishedExactly=True'
}
finally {
    if ($null -ne $observer) { $observer.Dispose() }
    Stop-StagedTestAgent $agent
    Save-StagedVerifierEvidence
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verified }
    foreach ($path in (Get-ChildItem 'C:\ProgramData\SafeUpload\staging-journal' -Filter '*.json')) {
        $entry=Get-Content -LiteralPath $path.FullName -Raw | ConvertFrom-Json
        if ($entry.Transfer.DestinationPath -eq $target) { $cleanup+=@($entry.Transfer.StagePath,$path.FullName) }
    }
    Remove-StagedTestFiles ($cleanup+@($reference,$target))
    Write-Output 'LockFixturesRemoved=True'
}
