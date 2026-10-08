<# Existing kernel publication protocol, including malformed/expired/spoofed
   attempts. The disposable LocalSystem controller writes only benign bytes. #>
param([switch] $ReproduceKnownGap,[switch] $Verifier,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-F]{64}$')][string] $ProbeZipHash)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup='C:\Users\vika\Documents\SafeUpload-original-before-permits.sys'
$documents='C:\Users\vika\Documents'
$id=[guid]::NewGuid().ToString('N')
$prefix='permit-'+$id
$root='C:\SafeUpload\Escopo Monitorado'
$target=Join-Path $root ($prefix+'.txt')
$log=Join-Path $documents ($prefix+'-controller')
$done=Join-Path $documents ($prefix+'.result')
$agent=$null; $observer=$null; $replaced=$false; $loaded=$false; $verified=$false; $passed=$false
if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash $installed).Hash -ne $expected){throw 'Original driver mismatch.'}
if((& fltmc.exe filters) -match '^SafeUpload\s'){throw 'Expected unloaded baseline.'}
if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'Existing agent must not be disturbed.'}
$settings=& verifier.exe /querysettings
if(($settings -join "`n") -notmatch 'Verifier Flags: 0x00000000'){throw 'Unexpected boot Verifier configuration.'}
$zip=Join-Path $documents 'staged-publication-probe.zip'
if((Get-FileHash $zip).Hash -ne $ProbeZipHash){throw 'Publication probe package mismatch.'}
Expand-Archive -LiteralPath $zip -DestinationPath (Join-Path $documents 'staged-publication-probe') -Force
try {
    [IO.File]::WriteAllText($target,'PUBLIC ORIGINAL')
    $observer=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    Backup-StagedTestDriver $backup
    $feature=(Get-FileHash (Join-Path $documents 'SafeUpload-stage-prototype.sys')).Hash
    "FeatureSHA256=$feature; ProbeZipSHA256=$ProbeZipHash"
    Copy-Item (Join-Path $documents 'SafeUpload-stage-prototype.sys') $installed -Force; $replaced=$true
    if($Verifier){
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Verifier setup failed.'}; $verified=$true
    }
    & fltmc.exe load SafeUpload | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Load failed.'}; $loaded=$true
    & (Join-Path $documents 'staged-publication-probe\StagedPublicationProbe.exe') user-connect | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Non-SYSTEM connection fixture failed.'}
    $mode=if($ReproduceKnownGap){'before'}else{'matrix'}
    $agent=Start-StagedTestAgent (Join-Path $documents 'staged-publication-probe') $log 'StagedPublicationProbe.exe' ($id+' '+$mode)
    for($attempt=0;$attempt -lt 480 -and -not (Test-Path $done);$attempt++){Start-Sleep -Milliseconds 250}
    Get-Content ($log+'-out.log') | Out-Host
    Get-Content ($log+'-err.log') | Out-Host
    if(-not (Test-Path $done) -or (Get-Content $done -Raw) -ne '0'){throw 'Publication controller did not pass.'}
    $observer.Position=0
    $bytes=New-Object byte[] 100; $count=$observer.Read($bytes,0,$bytes.Length)
    if([Text.Encoding]::UTF8.GetString($bytes,0,$count) -ne 'PUBLIC ORIGINAL'){throw 'Held destination bytes changed.'}
    foreach($suffix in @('-invalid.pending','-invalid.txt','-wrong.pending','-wrong.txt','-revoked.txt','-expired-create.pending','-expired-create.txt','-expired-rename.txt','-overflow.pending','-disconnect.pending')){
        if(Test-Path (Join-Path $root ($prefix+$suffix))){throw "Negative output exists: $suffix"}
    }
    'HeldOriginalAndNegativeDestinationByteIsolation=True'
    $passed=$true
}
finally {
    if($null -ne $observer){$observer.Dispose()}
    Stop-StagedTestAgent $agent
    Save-StagedVerifierEvidence
    if($replaced){Restore-StagedTestDriver $backup $loaded $verified}
    if($passed){
        if([IO.File]::ReadAllText($target) -ne 'BENIGN APPROVED CONTROL'){throw 'Unfiltered control destination differs.'}
        'IndependentUnfilteredPositiveControlExact=True'
    }
    Remove-StagedTestFiles (@(Get-ChildItem $root -Filter ($prefix+'*') -File | ForEach-Object FullName)+@($done))
}
