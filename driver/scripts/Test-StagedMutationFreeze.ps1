<# Pending rename abort holds fresh mutations; reconnect resumes the same view. #>
param([switch] $Verifier,[switch] $ReproduceKnownMappingGap)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedIdentityProbe.cs')
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup='C:\Users\vika\Documents\SafeUpload-original-before-freeze.sys'
$id=[guid]::NewGuid().ToString('N')
$target='C:\SafeUpload\Escopo Monitorado\freeze-'+$id+'.txt'
$renamed='C:\SafeUpload\Escopo Monitorado\freeze-'+$id+'-renamed.txt'
$loaded=$false; $replaced=$false; $verified=$false; $file=$null; $agent=$null; $observer=$null; $cleanup=@()
if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash $installed).Hash -ne $expected){throw 'Original hash mismatch.'}
if((& fltmc.exe filters) -match '^SafeUpload\s'){throw 'Expected unloaded baseline.'}
try {
    [IO.File]::WriteAllText($target,'PUBLIC ORIGINAL')
    $observer=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    Copy-Item $installed $backup -Force
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force; $replaced=$true
    if($Verifier){
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Verifier setup failed.'}; $verified=$true
    }
    & fltmc.exe load SafeUpload | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Load failed.'}; $loaded=$true
    $agent=Start-StagedTestAgent 'C:\Users\vika\Documents\stage-service-publish' 'C:\Users\vika\Documents\stage-freeze-service'
    for($attempt=0;$attempt -lt 40 -and $null -eq $file;$attempt++){
        Start-Sleep -Milliseconds 250
        try{$file=[StagedIdentityProbe]::Open($target,$true,$false)}catch{}
    }
    if($null -eq $file){throw 'Writer did not open.'}
    [StagedIdentityProbe]::Write($file,'frozen-content')
    Stop-StagedTestAgent $agent; $agent=$null
    $refused=$false
    try{[StagedIdentityProbe]::Rename($file,$renamed,$false)}
    catch{if($_.Exception.GetBaseException().NativeErrorCode -eq 32){$refused=$true}else{throw}}
    if(-not $refused){throw 'Offline rename succeeded.'}
    $write=[StagedIdentityProbe]::TryWrite($file)
    $end=[StagedIdentityProbe]::TrySize($file,$false)
    $allocation=[StagedIdentityProbe]::TrySize($file,$true)
    $mapping=[StagedIdentityProbe]::TryWritableMapping($file)
    "PendingAbortWriteEndAllocationMapping=$write,$end,$allocation,$mapping"
    $expectedMapping=if($ReproduceKnownMappingGap){0}else{5}
    if($write -ne 5 -or $end -ne 5 -or $allocation -ne 5 -or $mapping -ne $expectedMapping){throw 'Pending transaction mutation fence differs.'}
    if([StagedIdentityProbe]::Read($file) -ne 'frozen-content'){throw 'Refused mutation changed private bytes.'}
    $bytes=New-Object byte[] 100; $count=$observer.Read($bytes,0,$bytes.Length)
    if([Text.Encoding]::UTF8.GetString($bytes,0,$count) -ne 'PUBLIC ORIGINAL'){throw 'Offline private bytes reached the destination.'}
    Write-Output 'PendingAbortPreservesPrivateAndPhysicalBytes=True'
    $agent=Start-StagedTestAgent 'C:\Users\vika\Documents\stage-service-publish' 'C:\Users\vika\Documents\stage-freeze-reconnected-service'
    $resumed=$false
    for($attempt=0;$attempt -lt 40 -and -not $resumed;$attempt++){
        Start-Sleep -Milliseconds 250
        $resumed=[StagedIdentityProbe]::TryWrite($file) -eq 0
    }
    if(-not $resumed){throw 'Abort acknowledgement did not resume mutations.'}
    [StagedIdentityProbe]::Write($file,'approved after abort')
    Write-Output 'AcknowledgedAbortResumesSamePrivateVersion=True'
    $file.Dispose(); $file=$null
    $released=$false
    for($attempt=0;$attempt -lt 80 -and -not $released;$attempt++){
        Start-Sleep -Milliseconds 250
        $public=& powershell.exe -NoProfile -Command "`$file=[IO.FileStream]::new('$target',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete); `$reader=[IO.StreamReader]::new(`$file); try { `$reader.ReadToEnd() } finally { `$reader.Dispose() }"
        $released=$public -eq 'approved after abort'
    }
    if(-not $released){throw 'Resumed version was not published exactly.'}
    Write-Output 'ReconnectedVersionApprovedAndPublishedExactly=True'
}
finally {
    foreach($item in @($file,$observer)){if($null -ne $item){$item.Dispose()}}
    Stop-StagedTestAgent $agent
    Save-StagedVerifierEvidence
    if($replaced){Restore-StagedTestDriver $backup $loaded $verified}
    foreach($path in (Get-ChildItem 'C:\ProgramData\SafeUpload\staging-journal' -Filter '*.json')){
        $entry=Get-Content $path.FullName -Raw | ConvertFrom-Json
        if($entry.Transfer.DestinationPath.Contains($id)){$cleanup+=@($entry.Transfer.StagePath,$path.FullName)}
    }
    Remove-StagedTestFiles ($cleanup+@($target,$renamed))
    Write-Output 'FreezeFixturesRemoved=True'
}
