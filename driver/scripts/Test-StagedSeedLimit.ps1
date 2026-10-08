<# Service rejects an oversized seed before allocation; exact bound still opens. #>
param([switch] $Verifier)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedIdentityProbe.cs')
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup='C:\Users\vika\Documents\SafeUpload-original-before-seed.sys'
$id=[guid]::NewGuid().ToString('N')
$prefix='C:\SafeUpload\Escopo Monitorado\seed-'+$id
$large=$prefix+'-large.txt'; $exact=$prefix+'-exact.txt'; $ready=$prefix+'-ready.txt'
$journal='C:\ProgramData\SafeUpload\staging-journal'
$maximum=16*1024*1024
$file=$null; $pin=$null; $observer=$null; $agent=$null; $cleanup=@(); $loaded=$false; $replaced=$false; $verified=$false
if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash $installed).Hash -ne $expected){throw 'Original hash mismatch.'}
if((& fltmc.exe filters) -match '^SafeUpload\s'){throw 'Expected unloaded baseline.'}
try {
    foreach($path in @($large,$exact)){
        $length=if($path -eq $large){$maximum+1}else{$maximum}
        $seed=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$seed.SetLength($length); $seed.Position=$length-1; $seed.WriteByte(0x5a); $seed.Flush($true)}finally{$seed.Dispose()}
    }
    $observer=[IO.FileStream]::new($large,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    Copy-Item $installed $backup -Force
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force; $replaced=$true
    if($Verifier){
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Verifier setup failed.'}; $verified=$true
    }
    & fltmc.exe load SafeUpload | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Load failed.'}; $loaded=$true
    $agent=Start-StagedTestAgent 'C:\Users\vika\Documents\stage-service-publish' 'C:\Users\vika\Documents\stage-seed-service'
    for($attempt=0;$attempt -lt 40 -and $null -eq $pin;$attempt++){
        Start-Sleep -Milliseconds 250
        try{$pin=[StagedIdentityProbe]::Open($ready,$true,$true)}catch{}
    }
    if($null -eq $pin){throw 'Service did not admit readiness writer.'}
    $watch=[Diagnostics.Stopwatch]::StartNew(); $errorCode=0
    try{$file=[StagedIdentityProbe]::Open($large,$true,$false)}
    catch{$errorCode=$_.Exception.GetBaseException().NativeErrorCode}
    $watch.Stop()
    if($null -ne $file -or $errorCode -ne 5){throw "Oversized seed was not denied: $errorCode"}
    $entries=@(Get-ChildItem $journal -Filter '*.json' | ForEach-Object {Get-Content $_.FullName -Raw | ConvertFrom-Json} |
        Where-Object {$_.Transfer.DestinationPath -eq $large})
    if($entries.Count -ne 0){throw 'Oversized source was durably allocated.'}
    if($observer.Length -ne $maximum+1){throw 'Oversized rejection changed destination length.'}
    $observer.Position=$maximum
    if($observer.ReadByte() -ne 0x5a){throw 'Oversized rejection changed physical destination bytes.'}
    Write-Output "OversizedSeedDeniedWithoutManifestAndDestinationUnchanged=True Milliseconds=$($watch.ElapsedMilliseconds)"
    $file=[StagedIdentityProbe]::Open($exact,$true,$false)
    if([StagedIdentityProbe]::Length($file) -ne $maximum -or [StagedIdentityProbe]::LastByte($file) -ne 0x5a){throw 'Exact-bound seed differs.'}
    Write-Output 'Exact16MiBSeedAdmittedWithOriginalLastByte=True'
    # Do not qualify parser/publication of the binary-filled boundary fixture.
    # Keep both handles live while disconnecting; unload drains without approval.
    Stop-StagedTestAgent $agent; $agent=$null
}
finally {
    foreach($item in @($file,$pin,$observer)){if($null -ne $item){$item.Dispose()}}
    Stop-StagedTestAgent $agent
    Save-StagedVerifierEvidence
    if($replaced){Restore-StagedTestDriver $backup $loaded $verified}
    foreach($path in (Get-ChildItem $journal -Filter '*.json')){
        $entry=Get-Content $path.FullName -Raw | ConvertFrom-Json
        if($entry.Transfer.DestinationPath.Contains($id)){$cleanup+=@($entry.Transfer.StagePath,$path.FullName)}
    }
    Remove-StagedTestFiles ($cleanup+@($large,$exact,$ready))
    Write-Output 'SeedFixturesRemoved=True'
}
