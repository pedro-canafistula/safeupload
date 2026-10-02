<# Native parent/root rename fence. Only disposable configured scope trees move.
   The pre-fix mode preserves the smallest physical-byte isolation failure. #>
param([switch] $ReproduceKnownGap,[switch] $Verifier,[switch] $BootVerifier)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedIdentityProbe.cs')
$documents='C:\Users\vika\Documents'
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup=Join-Path $documents 'SafeUpload-original-before-parent.sys'
$policy='C:\ProgramData\SafeUpload\policy.json'
$id=[guid]::NewGuid().ToString('N')
$parent=Join-Path $documents ('SafeUpload-parent-'+$id)
$scope=Join-Path $parent 'Watched'
$target=Join-Path $scope 'report.txt'
$moved=$parent+'-moved'
$future=$parent+'-future'
$outside=$parent+'-outside'
$journal='C:\ProgramData\SafeUpload\staging-journal'
$policyBackup=Join-Path $documents ('parent-'+$id+'-original-policy.bin')
$agent=$null; $writer=$null; $observer=$null; $policyBytes=$null
$loaded=$false; $replaced=$false; $verified=$false; $cleanup=@()
function Read-Physical {
    if($null -eq $observer){
        $result=&powershell.exe -NoProfile -NonInteractive -Command "[IO.File]::ReadAllText('$target')"
        if($LASTEXITCODE -ne 0){throw 'Independent public reader failed.'}
        return $result
    }
    $observer.Position=0; $bytes=New-Object byte[] 256
    $count=$observer.Read($bytes,0,$bytes.Length)
    [Text.Encoding]::UTF8.GetString($bytes,0,$count)
}
function Get-Entries {
    @(Get-ChildItem $journal -Filter '*.json' | ForEach-Object {
        $entry=Get-Content $_.FullName -Raw | ConvertFrom-Json
        if($entry.Transfer.DestinationPath -eq $target){$entry}
    } | Sort-Object DestinationGeneration -Descending)
}
if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash $installed).Hash -ne $expected -or (&fltmc.exe filters) -match '^SafeUpload\s'){throw 'Original unloaded baseline required.'}
if(@(Get-Process SafeUpload.Agent.Service -ErrorAction SilentlyContinue).Count){throw 'Existing service must not be disturbed.'}
if($Verifier -and $BootVerifier){throw 'Choose one Verifier mode.'}
if($BootVerifier){
    $q=(&verifier.exe /query)-join "`n"
    if($q -notmatch 'Verifier Flags: 0x([0-9a-fA-F]+)' -or
        ([Convert]::ToUInt32($Matches[1],16) -band 0x209bb) -ne 0x209bb -or $q -notmatch 'SafeUpload.sys'){throw 'Boot Verifier not active.'}
    $verified=$true
}else{
    if(((&verifier.exe /querysettings)-join "`n") -notmatch 'Verifier Flags: 0x00000000'){throw 'Unexpected boot Verifier configuration.'}
}
try {
    New-Item -ItemType Directory -Path $scope | Out-Null
    [IO.File]::WriteAllText($target,'PUBLIC ORIGINAL')
    foreach($extended in @($false,$true)){
        if([StagedIdentityProbe]::TryDirectoryRename($parent,$moved,$extended) -ne 0 -or
            [StagedIdentityProbe]::TryDirectoryRename($moved,$parent,$extended) -ne 0){throw 'Unfiltered parent rename control failed.'}
    }
    'UnfilteredNativeParentRename=True; InformationClasses=10,65'
    $observer=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    foreach($extended in @($false,$true)){
        if([StagedIdentityProbe]::TryDirectoryRename($parent,$moved,$extended) -ne 5){throw 'Pinned-child native control differs.'}
    }
    'UnfilteredPinnedPhysicalChildPreventsParentRename=True; NativeError=5'
    $policyBytes=[IO.File]::ReadAllBytes($policy)
    [IO.File]::WriteAllBytes($policyBackup,$policyBytes)
    $testPolicy=[Text.Encoding]::UTF8.GetString($policyBytes)|ConvertFrom-Json
    $testPolicy.monitoredScopes.destinationPaths=@($testPolicy.monitoredScopes.destinationPaths)+@($scope,(Join-Path $future 'Watched'))
    [IO.File]::WriteAllText($policy,($testPolicy|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    Backup-StagedTestDriver $backup
    "FeatureSHA256=$((Get-FileHash (Join-Path $documents 'SafeUpload-stage-prototype.sys')).Hash)"
    "ServiceZipSHA256=$((Get-FileHash (Join-Path $documents 'stage-service-publish.zip')).Hash)"
    Copy-Item (Join-Path $documents 'SafeUpload-stage-prototype.sys') $installed -Force; $replaced=$true
    if($Verifier){
        &verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Verifier setup failed.'}; $verified=$true
    }
    &fltmc.exe load SafeUpload | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Load failed.'}; $loaded=$true
    $log=Join-Path $documents 'stage-parent-service'
    $agent=Start-StagedTestAgent (Join-Path $documents 'stage-service-publish') $log
    for($attempt=0;$attempt -lt 80 -and $null -eq $writer;$attempt++){
        Start-Sleep -Milliseconds 250
        if((Get-Content ($log+'-out.log') -Raw) -match 'Minifiltro conectado\.'){
            try{$writer=[StagedIdentityProbe]::Open($target,$true,$false)}catch{}
        }
    }
    if($null -eq $writer){throw 'Private writer unavailable.'}
    $entries=@(Get-Entries)
    if($entries.Count -ne 1 -or $entries[0].State -ne 0){throw 'Writer lacks durable Allocated entry; do not write.'}
    [StagedIdentityProbe]::Write($writer,'CPF: 529.982.247-25 private parent fixture')
    if((Read-Physical) -ne 'PUBLIC ORIGINAL'){throw 'Initial private write reached public object.'}
    'DurablePrivateWriterAndInitialPhysicalIsolation=True'
    # A physical child object would itself make NTFS deny the parent move.
    # Close it before testing the filter, then use an independent process.
    $observer.Dispose(); $observer=$null
    if($ReproduceKnownGap){
        $renameError=[StagedIdentityProbe]::TryDirectoryRename($parent,$moved,$true)
        if($renameError -ne 0){throw "Expected ancestor rename success, got $renameError."}
        $child=Join-Path $documents ('parent-'+$id+'-observer.ps1')
        $childOut=$child+'.out'; $childErr=$child+'.err'
        $movedTarget=Join-Path $moved 'Watched\report.txt'
        [IO.File]::WriteAllText($child,"[IO.File]::WriteAllText('$movedTarget','UNAPPROVED OUTSIDE WRITE'); [IO.File]::ReadAllText('$movedTarget')")
        $process=Start-Process powershell.exe -ArgumentList ('-NoProfile -NonInteractive -File "'+$child+'"') -Wait -PassThru `
            -RedirectStandardOutput $childOut -RedirectStandardError $childErr
        $cleanup+=@($child,$childOut,$childErr)
        if($process.ExitCode -ne 0){throw 'Fresh outside-path writer failed.'}
        if((Get-Content $childOut -Raw).Trim() -ne 'UNAPPROVED OUTSIDE WRITE' -or
            [StagedIdentityProbe]::Read($writer) -ne 'CPF: 529.982.247-25 private parent fixture'){throw 'Expected public change with unchanged private version not observed.'}
        'AncestorRenameInvalidatesProtectedPath=True; NativeRenameError=0; FreshProcessChangesPublicBytes=True; PrivateVersionUnchanged=True'
        return
    }
    foreach($extended in @($false,$true)){
        foreach($pair in @(@($parent,$moved),@($scope,$scope+'-renamed'))){
            $errorCode=[StagedIdentityProbe]::TryDirectoryRename($pair[0],$pair[1],$extended)
            if($errorCode -ne 5){throw "Source namespace rename expected access denied, got $errorCode."}
        }
        New-Item -ItemType Directory -Path $outside | Out-Null
        if([StagedIdentityProbe]::TryDirectoryRename($outside,$future,$extended) -ne 5){throw 'Destination ancestor rename accepted.'}
        Remove-Item $outside
        # Component boundaries: a sibling whose textual prefix matches is outside.
        $sibling=$scope+'Sibling'; $siblingMoved=$sibling+'-moved'
        New-Item -ItemType Directory -Path $sibling | Out-Null
        if([StagedIdentityProbe]::TryDirectoryRename($sibling,$siblingMoved,$extended) -ne 0){throw 'Outside sibling rename denied.'}
        Remove-Item $siblingMoved
    }
    if((Read-Physical) -ne 'PUBLIC ORIGINAL' -or
        [StagedIdentityProbe]::Read($writer) -ne 'CPF: 529.982.247-25 private parent fixture'){throw 'Rename fence lost public/private bytes.'}
    'NativeSourceRootAndAncestorDenied=True; DestinationAncestorDenied=True; BoundarySiblingAllowed=True; InformationClasses=10,65'
    $writer.Dispose(); $writer=$null
    for($attempt=0;$attempt -lt 100;$attempt++){
        $entries=@(Get-Entries)
        if($entries.Count -and $entries[0].State -eq 6){break}
        Start-Sleep -Milliseconds 200
    }
    if($entries[0].State -ne 6 -or -not $entries[0].SealedOnce -or (Read-Physical) -ne 'PUBLIC ORIGINAL'){throw 'Private version was not safely blocked.'}
    'SealedBlockedVersionAndPhysicalIsolation=True'
}
finally {
    if($null -ne $writer){$writer.Dispose()}
    if($null -ne $observer){$observer.Dispose()}
    Stop-StagedTestAgent $agent
    if($null -ne $policyBytes){[IO.File]::WriteAllBytes($policy,$policyBytes); 'OriginalPolicyBytesRestored=True'}
    Save-StagedVerifierEvidence
    if($replaced){Restore-StagedTestDriver $backup $loaded $verified}
    foreach($manifest in (Get-ChildItem $journal -Filter '*.json')){
        $entry=Get-Content $manifest.FullName -Raw|ConvertFrom-Json
        if($entry.Transfer.DestinationPath.Contains($id)){$cleanup+=@($entry.Transfer.StagePath,$manifest.FullName)}
    }
    Remove-StagedTestFiles ($cleanup+@($policyBackup))
    foreach($tree in @($parent,$moved,$outside,$future)){
        if(Test-Path -LiteralPath $tree){Remove-Item -LiteralPath $tree -Recurse -Force}
    }
    'ParentNamespaceFixturesRemoved=True'
}
