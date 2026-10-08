<# Logical source-slot recreation while its old public object remains present. #>
param([switch] $ReproduceKnownGap,[switch] $Verifier,[switch] $BootVerifier)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedIdentityProbe.cs')
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup='C:\Users\vika\Documents\SafeUpload-original-before-tombstone.sys'
$id=[guid]::NewGuid().ToString('N')
$root='C:\SafeUpload\Escopo Monitorado'
$journal='C:\ProgramData\SafeUpload\staging-journal'
$fixtures=@(); $observers=@(); $cleanup=@(); $old=$null; $fresh=$null; $agent=$null
$loaded=$false; $replaced=$false; $verified=$false; $passed=$false

function Get-SlotEntries([string] $Path) {
    @(Get-ChildItem $journal -Filter '*.json' | ForEach-Object {
        $entry=Get-Content $_.FullName -Raw | ConvertFrom-Json
        if($entry.Transfer.DestinationPath -eq $Path){$entry}
    } | Sort-Object DestinationGeneration -Descending)
}
function Wait-Slot([string] $Path,[int] $State) {
    for($attempt=0;$attempt -lt 100;$attempt++){
        $entries=@(Get-SlotEntries $Path)
        if($entries.Count -and $entries[0].State -eq $State){return $entries[0]}
        Start-Sleep -Milliseconds 200
    }
    throw "Slot did not reach state $State."
}
function Assert-PhysicalOriginal($Reader) {
    $Reader.Position=0; $bytes=New-Object byte[] 100
    $count=$Reader.Read($bytes,0,$bytes.Length)
    if([Text.Encoding]::UTF8.GetString($bytes,0,$count) -ne 'PUBLIC ORIGINAL'){throw 'Unapproved physical source change.'}
}
if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash $installed).Hash -ne $expected -or (&fltmc.exe filters) -match '^SafeUpload\s'){throw 'Original unloaded baseline required.'}
if($Verifier -and $BootVerifier){throw 'Choose one Verifier mode.'}
if($BootVerifier){
    $q=(&verifier.exe /query)-join "`n"
    if($q -notmatch 'Verifier Flags: 0x([0-9a-fA-F]+)' -or
        ([Convert]::ToUInt32($Matches[1],16) -band 0x209bb) -ne 0x209bb -or $q -notmatch 'SafeUpload.sys'){throw 'Boot standard Verifier not active.'}
    $verified=$true
}
try {
    $dispositions=if($ReproduceKnownGap){@(2)}else{@(2,0,3,5)}
    foreach($disposition in $dispositions){
        $control=Join-Path $env:TEMP "tombstone-native-$id-$disposition.txt"
        $moved=$control+'.renamed.txt'
        $controlHandle=$null;$newControl=$null
        try{
            [IO.File]::WriteAllText($control,'native initial')
            $controlHandle=[StagedIdentityProbe]::Open($control,$true,$false)
            [StagedIdentityProbe]::Rename($controlHandle,$moved,$false)
            $controlInformation=0L
            $newControl=[StagedIdentityProbe]::NativeDisposition($control,$disposition,[ref]$controlInformation)
            if($controlInformation -ne 2 -or [StagedIdentityProbe]::Length($newControl) -ne 0){throw 'Unfiltered native slot control failed.'}
        }finally{
            if($null -ne $newControl){$newControl.Dispose()}
            if($null -ne $controlHandle){$controlHandle.Dispose()}
            Remove-Item $control,$moved -Force -ErrorAction SilentlyContinue
        }
    }
    'UnfilteredNativeRecreatedSlotsReturnFileCreatedAndEmpty=True'
    foreach($disposition in $dispositions){
        $source=Join-Path $root "tombstone-$id-$disposition.txt"
        $target=Join-Path $root "tombstone-$id-$disposition-renamed.txt"
        $secondTarget=Join-Path $root "tombstone-$id-$disposition-renamed-again.txt"
        [IO.File]::WriteAllText($source,'PUBLIC ORIGINAL')
        $reader=[IO.FileStream]::new($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        $observers+=,$reader
        $fixtures+=,[pscustomobject]@{Source=$source;Target=$target;SecondTarget=$secondTarget;Reader=$reader;Disposition=$disposition}
    }
    &tar.exe -xf C:\Users\vika\Documents\stage-service-publish.zip -C C:\Users\vika\Documents\stage-service-publish
    if($LASTEXITCODE -ne 0){throw 'Service extraction failed.'}
    Backup-StagedTestDriver $backup
    Copy-Item C:\Users\vika\Documents\SafeUpload-stage-prototype.sys $installed -Force; $replaced=$true
    if($Verifier){
        &verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Verifier configuration failed.'}; $verified=$true
    }
    &fltmc.exe load SafeUpload | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Load failed.'}; $loaded=$true
    "FeatureSHA256=$((Get-FileHash C:\Users\vika\Documents\SafeUpload-stage-prototype.sys).Hash)"
    "ServiceZipSHA256=$((Get-FileHash C:\Users\vika\Documents\stage-service-publish.zip).Hash)"
    $agent=Start-StagedTestAgent C:\Users\vika\Documents\stage-service-publish C:\Users\vika\Documents\stage-tombstone-service
    foreach($fixture in $fixtures){
        for($attempt=0;$attempt -lt 40 -and $null -eq $old;$attempt++){
            Start-Sleep -Milliseconds 250
            try{$old=[StagedIdentityProbe]::Open($fixture.Source,$true,$false)}catch{}
        }
        if($null -eq $old){throw 'Original private view unavailable.'}
        $oldId=[Convert]::ToBase64String([StagedIdentityProbe]::Identity($old))
        [StagedIdentityProbe]::Write($old,'prior private clean bytes')
        [StagedIdentityProbe]::Rename($old,$fixture.Target,$false)
        $nativeInformation=0L
        if($ReproduceKnownGap){
            $errorCode=0
            try{$fresh=[StagedIdentityProbe]::NativeDisposition($fixture.Source,2,[ref]$nativeInformation)}
            catch{$error=$_.Exception;while($null -ne $error.InnerException){$error=$error.InnerException};$errorCode=$error.NativeErrorCode}
            if($errorCode -ne 183){throw "Expected native STATUS_OBJECT_NAME_COLLISION / error 183, got $errorCode."}
            Assert-PhysicalOriginal $fixture.Reader
            'OccupiedPublicSlotPrivateCreateGapReproduced=True; NativeError=183'
            return
        }
        if([StagedIdentityProbe]::AnonymousNativeCreate($fixture.Source) -ne 5){throw 'Anonymous private slot creation accepted.'}
        foreach($openOnly in @(1,4)){
            $errorCode=0;$probe=$null
            try{$probe=[StagedIdentityProbe]::NativeDisposition($fixture.Source,$openOnly,[ref]$nativeInformation)}
            catch{$error=$_.Exception;while($null -ne $error.InnerException){$error=$error.InnerException};$errorCode=$error.NativeErrorCode}
            finally{if($null -ne $probe){$probe.Dispose()}}
            if($errorCode -ne 2){throw 'OPEN/OVERWRITE exposed the hidden public slot.'}
        }
        $fresh=[StagedIdentityProbe]::NativeDisposition($fixture.Source,$fixture.Disposition,[ref]$nativeInformation)
        if($nativeInformation -ne 2 -or [StagedIdentityProbe]::Length($fresh) -ne 0){throw 'Logical fresh create did not start empty with FILE_CREATED.'}
        $freshId=[Convert]::ToBase64String([StagedIdentityProbe]::Identity($fresh))
        if($freshId -eq $oldId -or [StagedIdentityProbe]::Read($old) -ne 'prior private clean bytes'){throw 'New slot changed prior private identity/content.'}
        [StagedIdentityProbe]::Write($fresh,'CPF: 529.982.247-25 new private slot')
        Assert-PhysicalOriginal $fixture.Reader
        $fresh.Dispose();$fresh=$null
        $blocked=Wait-Slot $fixture.Source 6
        if(-not $blocked.SealedOnce -or $blocked.DestinationGeneration -lt 3){throw 'New slot lacks durable generation and seal.'}
        $public=&powershell.exe -NoProfile -Command "[IO.File]::ReadAllText('$($fixture.Source)')"
        if($LASTEXITCODE -ne 0 -or $public -ne 'PUBLIC ORIGINAL'){throw 'Fresh external process observed private source bytes.'}
        $old.Dispose();$old=$null
        $null=Wait-Slot $fixture.Target 5
        Assert-PhysicalOriginal $fixture.Reader
        # OPEN must seed the blocked private version, never the occupied public slot.
        $fresh=[StagedIdentityProbe]::Open($fixture.Source,$true,$false)
        if([StagedIdentityProbe]::Read($fresh) -ne 'CPF: 529.982.247-25 new private slot' -or
            [Convert]::ToBase64String([StagedIdentityProbe]::Identity($fresh)) -ne $freshId){throw 'Later edit lost prior private bytes or view identity.'}
        [StagedIdentityProbe]::Write($fresh,'new clean approved slot')
        $fresh.Dispose();$fresh=$null
        $released=Wait-Slot $fixture.Source 5
        if($released.Transfer.TransferId -eq $blocked.Transfer.TransferId){throw 'Later edit reused sealed version.'}
        Assert-PhysicalOriginal $fixture.Reader
        # A second view can leave a NEW tombstone at the same slot. It must
        # select the latest owner rather than the first historical OldNames hit.
        $old=[StagedIdentityProbe]::Open($fixture.Source,$true,$false)
        [StagedIdentityProbe]::Rename($old,$fixture.SecondTarget,$false)
        $old.Dispose();$old=$null
        $null=Wait-Slot $fixture.SecondTarget 5
        # Rotate the renamed view's CURRENT version before using its source
        # tombstone. The owner GUID must remain the version that did the rename.
        $old=[StagedIdentityProbe]::Open($fixture.SecondTarget,$true,$false)
        $fresh=[StagedIdentityProbe]::NativeDisposition($fixture.Source,2,[ref]$nativeInformation)
        if($nativeInformation -ne 2 -or [StagedIdentityProbe]::Length($fresh) -ne 0 -or
            [Convert]::ToBase64String([StagedIdentityProbe]::Identity($fresh)) -eq $freshId){throw 'Repeated slot reuse selected stale identity/content.'}
        [StagedIdentityProbe]::Write($fresh,'new clean approved slot')
        $fresh.Dispose();$fresh=$null;$old.Dispose();$old=$null
        $released=Wait-Slot $fixture.Source 5
        $null=Wait-Slot $fixture.SecondTarget 5
        Assert-PhysicalOriginal $fixture.Reader
        "OccupiedSlotRecreatedEmptyAndApproved=True; NativeDisposition=$($fixture.Disposition); Generation=$($released.DestinationGeneration); AnonymousDenied=True; RepeatedReuse=True"
    }
    $passed=$true
}
finally {
    if($null -ne $fresh){$fresh.Dispose()}
    if($null -ne $old){$old.Dispose()}
    foreach($reader in $observers){$reader.Dispose()}
    Stop-StagedTestAgent $agent
    Save-StagedVerifierEvidence
    if($replaced){Restore-StagedTestDriver $backup $loaded $verified}
    if($passed){
        foreach($fixture in $fixtures){
            if([IO.File]::ReadAllText($fixture.Source) -ne 'new clean approved slot' -or
                [IO.File]::ReadAllText($fixture.Target) -ne 'prior private clean bytes' -or
                [IO.File]::ReadAllText($fixture.SecondTarget) -ne 'new clean approved slot'){throw 'Independent unfiltered publication mismatch.'}
        }
        'IndependentUnfilteredSourceAndRenamedBytesExact=True'
    }
    foreach($path in (Get-ChildItem $journal -Filter '*.json')){
        $entry=Get-Content $path.FullName -Raw|ConvertFrom-Json
        if($entry.Transfer.DestinationPath.Contains($id)){$cleanup+=@($entry.Transfer.StagePath,$path.FullName)}
    }
    Remove-StagedTestFiles ($cleanup+@($fixtures|ForEach-Object{$_.Source;$_.Target;$_.SecondTarget}))
    'TombstoneFixturesRemoved=True'
}
