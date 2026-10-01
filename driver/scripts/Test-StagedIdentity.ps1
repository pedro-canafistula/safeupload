<# Native private IDs and namespace views. Always restore the original driver. #>
param([switch] $Verifier)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
Add-Type -Path (Join-Path $PSScriptRoot 'StagedIdentityProbe.cs')
$installed='C:\Windows\System32\drivers\SafeUpload.sys'
$expected='ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$backup='C:\Users\vika\Documents\SafeUpload-original-before-identity.sys'
$id=[guid]::NewGuid().ToString('N')
$source='C:\SafeUpload\Escopo Monitorado\identity-'+$id+'.txt'
$renamed='C:\SafeUpload\Escopo Monitorado\identity-'+$id+'-renamed.txt'
$replacement='C:\SafeUpload\Escopo Monitorado\identity-'+$id+'-replacement.txt'
$cycle='C:\SafeUpload\Escopo Monitorado\identity-'+$id+'-cycle.txt'
$outside='C:\SafeUpload\identity-'+$id+'-outside.txt'
$reference=Join-Path $env:TEMP ('identity-reference-'+$id+'.txt')
$journal='C:\ProgramData\SafeUpload\staging-journal'
$loaded=$false; $replaced=$false; $verified=$false; $agent=$null; $cleanup=@()
$file=$null; $byId=$null; $old=$null; $observer=$null; $displaced=$null
function Read-IdentityManifest([string] $Path) {
    $input=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $reader=[IO.StreamReader]::new($input)
    try { $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
}
function Identity-Entries([string] $Path) {
    @(Get-ChildItem $journal -Filter '*.json' | ForEach-Object { Read-IdentityManifest $_.FullName } |
        Where-Object { $_.Transfer.DestinationPath -eq $Path })
}
function Wait-IdentityState($Entry, [int] $State) {
    $path=Join-Path $journal (([guid]$Entry.Transfer.TransferId).ToString('N')+'.json')
    for($attempt=0;$attempt -lt 120;$attempt++) {
        $entry=Read-IdentityManifest $path
        if($entry.State -eq $State){return $entry}
        if($agent.Process.HasExited){throw 'Agent exited.'}
        Start-Sleep -Milliseconds 250
    }
    throw "Identity version stayed in state $($entry.State), expected $State."
}
function Assert-SameIdentity($First,$Second) {
    if([Convert]::ToBase64String($First) -ne [Convert]::ToBase64String($Second)){throw 'Logical identity changed.'}
}
function Assert-DirectoryIdentity([string] $Path,$Identity) {
    $entry=[StagedIdentityProbe]::DirectoryId([IO.Path]::GetDirectoryName($Path),[IO.Path]::GetFileName($Path))
    if([Convert]::ToBase64String($entry) -ne [Convert]::ToBase64String($Identity,8,16)){throw 'Directory identity differs from handle identity.'}
}
function Independent-Read([string] $Path) {
    & powershell.exe -NoProfile -Command "try { `$file=[IO.FileStream]::new('$Path',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete); `$reader=[IO.StreamReader]::new(`$file); try { `$reader.ReadToEnd() } finally { `$reader.Dispose() } } catch [IO.FileNotFoundException] { 'ABSENT' }"
}
if($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'){throw 'Wrong debuggee.'}
if((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected){throw 'Original hash mismatch.'}
if((& fltmc.exe filters) -match '^SafeUpload\s'){throw 'Expected unloaded baseline.'}
try {
    [IO.File]::WriteAllText($reference,'REFERENCE ORIGINAL')
    $file=[StagedIdentityProbe]::Open($reference,$true,$false)
    $physicalId=[StagedIdentityProbe]::Identity($file)
    Assert-DirectoryIdentity $reference $physicalId
    $relative=[StagedIdentityProbe]::Relative([IO.Path]::GetDirectoryName($reference),[IO.Path]::GetFileName($reference))
    try{Assert-SameIdentity $physicalId ([StagedIdentityProbe]::Identity($relative))}
    finally{$relative.Dispose()}
    $byId=[StagedIdentityProbe]::ById('C:\',$physicalId,$true)
    [StagedIdentityProbe]::Write($byId,'REFERENCE ID WRITE')
    if([StagedIdentityProbe]::Read($file) -ne 'REFERENCE ID WRITE'){throw 'Unfiltered file-ID control failed.'}
    $byId.Dispose(); $byId=$null; $file.Dispose(); $file=$null
    Write-Output ('UnfilteredExtendedFileIdOpenAndDirectoryIdentity=True VolumeSerial64='+[BitConverter]::ToUInt64($physicalId,0).ToString('X16'))
    [IO.File]::WriteAllText($source,'PUBLIC ORIGINAL')
    [IO.File]::WriteAllText($outside,'OUTSIDE PUBLIC ORIGINAL')
    $observer=[IO.FileStream]::new($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    Copy-Item $installed $backup -Force
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force
    $replaced=$true
    if($Verifier){
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Host
        if($LASTEXITCODE -ne 0){throw 'Verifier setup failed.'}; $verified=$true
    }
    & fltmc.exe load SafeUpload | Out-Host
    if($LASTEXITCODE -ne 0){throw 'Load failed.'}; $loaded=$true
    $agent=Start-StagedTestAgent 'C:\Users\vika\Documents\stage-service-publish' 'C:\Users\vika\Documents\stage-identity-service'
    for($attempt=0;$attempt -lt 40 -and $null -eq $file;$attempt++){
        Start-Sleep -Milliseconds 250
        try{$file=[StagedIdentityProbe]::Open($source,$true,$false)}catch{}
    }
    if($null -eq $file){throw 'Private writer did not open.'}
    $logical=[StagedIdentityProbe]::Identity($file)
    if([BitConverter]::ToUInt64($logical,0) -ne [BitConverter]::ToUInt64($physicalId,0)){throw 'Original-volume 64-bit serial differs.'}
    Assert-DirectoryIdentity $source $logical
    [StagedIdentityProbe]::Write($file,'CPF: 529.982.247-25 first')
    $byId=[StagedIdentityProbe]::ById('C:\',$logical,$true)
    Assert-SameIdentity $logical ([StagedIdentityProbe]::Identity($byId))
    if([StagedIdentityProbe]::Read($byId) -ne 'CPF: 529.982.247-25 first'){throw 'File-ID open did not share the private stream.'}
    $file.Dispose(); $file=$null
    [StagedIdentityProbe]::Write($byId,'CPF: 529.982.247-25 prior private')
    Write-Output 'ConcurrentFileIdHandleSurvivesOriginalClose=True'
    $unknown=[byte[]]$logical.Clone(); $unknown[9]=$unknown[9] -bxor 1
    if([StagedIdentityProbe]::TryById('C:\',$unknown,$false) -ne 5){throw 'Unknown private ID fell through.'}
    $probe=Join-Path $PSScriptRoot 'StagedIdentityProbe.cs'
    $encoded=[Convert]::ToBase64String($logical)
    $other=& powershell.exe -NoProfile -Command "Add-Type -Path '$probe'; `$id=[Convert]::FromBase64String('$encoded'); [StagedIdentityProbe]::TryById('C:\',`$id,`$false); [StagedIdentityProbe]::TryById('C:\',`$id,`$true)"
    if(($other -join ',') -ne '5,5'){throw "Another process inherited the private ID: $other"}
    Write-Output 'UnknownAndUnrelatedProcessPrivateIdsDenied=True'
    $controlRead=[StagedIdentityProbe]::ById('C:\',$physicalId,$false)
    try{if([StagedIdentityProbe]::Read($controlRead) -ne 'REFERENCE ID WRITE'){throw 'Physical read-only ID regression.'}}
    finally{$controlRead.Dispose()}
    if([StagedIdentityProbe]::TryById('C:\',$physicalId,$true) -ne 5){throw 'Unknown writable physical ID bypassed admission.'}
    Write-Output 'PhysicalReadOnlyIdPreservedUnknownWritablePhysicalIdDenied=True'
    # The existing service protocol intentionally refuses out-of-scope retargets.
    # Prove refusal retains both views, rather than expanding publication scope.
    $denied=$false
    try{[StagedIdentityProbe]::Rename($byId,$outside,$true)}
    catch{if($_.Exception.GetBaseException().NativeErrorCode -eq 32){$denied=$true}else{throw}}
    if(-not $denied){throw 'Unsupported out-of-scope rename unexpectedly succeeded.'}
    Assert-SameIdentity $logical ([StagedIdentityProbe]::Identity($byId))
    Assert-DirectoryIdentity $source $logical
    if([StagedIdentityProbe]::Read($byId) -ne 'CPF: 529.982.247-25 prior private'){throw 'Refused rename lost private bytes.'}
    if((Independent-Read $outside) -ne 'OUTSIDE PUBLIC ORIGINAL'){throw 'Refused rename changed outside physical bytes.'}
    Write-Output 'NativeRenameOutsidePrefixDeniedAndPrivatePublicViewsUnchanged=True'
    Start-Sleep -Milliseconds 1000 # Wait for the durable abort acknowledgement.
    [StagedIdentityProbe]::Rename($byId,$renamed,$false)
    Assert-DirectoryIdentity $renamed $logical
    $relative=[StagedIdentityProbe]::Relative([IO.Path]::GetDirectoryName($renamed),[IO.Path]::GetFileName($renamed))
    try{
        Assert-SameIdentity $logical ([StagedIdentityProbe]::Identity($relative))
        if([StagedIdentityProbe]::Read($relative) -ne 'CPF: 529.982.247-25 prior private'){throw 'Relative open lost private content.'}
    }finally{$relative.Dispose()}
    Write-Output 'NativeRelativePrivateReopenAfterRename=True'
    Write-Output ('ConcurrentFileIdOpenNativeRenameRace='+[StagedIdentityProbe]::RenameRace($byId,$renamed,$cycle,$logical))
    $first=(Identity-Entries $renamed)[0]
    $byId.Dispose(); $byId=$null
    $null=Wait-IdentityState $first 6
    $old=[StagedIdentityProbe]::ById('C:\',$logical,$false)
    $byId=[StagedIdentityProbe]::ById('C:\',$logical,$true)
    Assert-SameIdentity $logical ([StagedIdentityProbe]::Identity($old))
    Assert-SameIdentity $logical ([StagedIdentityProbe]::Identity($byId))
    if([StagedIdentityProbe]::Read($byId) -ne 'CPF: 529.982.247-25 prior private'){throw 'New version lost prior private content.'}
    $second=@(Identity-Entries $renamed | Where-Object { $_.Transfer.TransferId -ne $first.Transfer.TransferId })
    if($second.Count -ne 1){throw 'File-ID write did not allocate exactly one new version.'}
    [StagedIdentityProbe]::Write($byId,'approved identity result')
    $observer.Position=0; $data=New-Object byte[] 100; $count=$observer.Read($data,0,$data.Length)
    if([Text.Encoding]::UTF8.GetString($data,0,$count) -ne 'PUBLIC ORIGINAL'){throw 'Unapproved bytes reached destination.'}
    Write-Output 'StableLogicalIdDistinctVersionAndHeldPhysicalIsolation=True'
    $byId.Dispose(); $byId=$null
    $null=Wait-IdentityState $second[0] 5
    if((Independent-Read $renamed) -ne 'approved identity result'){throw 'Exact approved result was not published.'}
    if([StagedIdentityProbe]::Read($old) -ne 'CPF: 529.982.247-25 prior private'){throw 'Publication changed the old immutable version.'}
    Write-Output 'OldImmutableVersionSurvivesLaterFileIdEditAndApprovedPublication=True'
    $displaced=[StagedIdentityProbe]::Open($replacement,$true,$true)
    $displacedId=[StagedIdentityProbe]::Identity($displaced)
    [StagedIdentityProbe]::Write($displaced,'CPF: 529.982.247-25 displaced')
    $byId=[StagedIdentityProbe]::ById('C:\',$logical,$true)
    [StagedIdentityProbe]::Write($byId,'replacement identity result')
    [StagedIdentityProbe]::Rename($byId,$replacement,$true)
    Assert-DirectoryIdentity $replacement $logical
    Assert-SameIdentity $displacedId ([StagedIdentityProbe]::Identity($displaced))
    if([StagedIdentityProbe]::TryById('C:\',$displacedId,$false) -ne 5){throw 'Detached replacement identity reopened by ID.'}
    $file=[StagedIdentityProbe]::Open($replacement,$false,$false)
    try{Assert-SameIdentity $logical ([StagedIdentityProbe]::Identity($file))}
    finally{$file.Dispose(); $file=$null}
    if([StagedIdentityProbe]::Read($displaced) -ne 'CPF: 529.982.247-25 displaced'){throw 'Replacement changed displaced held bytes.'}
    $head=@(Identity-Entries $replacement | Sort-Object DestinationGeneration -Descending)[0]
    $byId.Dispose(); $byId=$null
    $null=Wait-IdentityState $head 5
    if((Independent-Read $replacement) -ne 'replacement identity result'){throw 'Replacement was not published exactly.'}
    Write-Output 'PosixReplacementRetainsDisplacedIdentityAndPublishesSourceIdentity=True'
}
finally {
    foreach($item in @($file,$byId,$old,$observer,$displaced)){if($null -ne $item){$item.Dispose()}}
    Stop-StagedTestAgent $agent
    Save-StagedVerifierEvidence
    if($replaced){Restore-StagedTestDriver $backup $loaded $verified}
    foreach($path in (Get-ChildItem $journal -Filter '*.json')){
        $entry=Read-IdentityManifest $path.FullName
        if($entry.Transfer.DestinationPath.Contains($id)){$cleanup+=@($entry.Transfer.StagePath,$path.FullName)}
    }
    Remove-StagedTestFiles ($cleanup+@($reference,$source,$outside,$renamed,$replacement,$cycle))
    Write-Output 'IdentityFixturesRemoved=True'
}
