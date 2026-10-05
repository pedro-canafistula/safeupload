<#
Phase 4 WP2 driver-off observer corpus stimulus. This is not a qualification
adapter and never emits Phase4Suite=PASS. Run inside a checkpointed
WIN10-DEBUGGED session with an independent clean baseline and restoration.
All raw decoding uses StagedInvariantObserver.psm1. The small native helper
below changes test files; it does not decode NTFS or read the raw volume.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$FixtureRoot,
    [Parameter(Mandatory=$true)][string]$EvidenceRoot,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string]$ExpectedObserverSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunGuid
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$script:Results=New-Object 'System.Collections.Generic.List[object]'
$script:FixtureDir=$null
$script:EvidenceDir=$null

function Fail([string]$Reason) { throw ('FAIL:'+$Reason) }
function Inconclusive([string]$Reason) { throw ('INCONCLUSIVE:'+$Reason) }
function Require([bool]$Condition,[string]$Reason) { if(-not $Condition){Fail $Reason} }
function Sha([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','') }
    finally { $sha.Dispose() }
}
function Write-NewBytes([string]$Path,[byte[]]$Bytes) {
    $f=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try { $f.Write($Bytes,0,$Bytes.Length);$f.Flush($true) } finally { $f.Dispose() }
}
function Patch-Bytes([string]$Path,[long]$Offset,[byte[]]$Bytes) {
    $share=[IO.FileShare]([int][IO.FileShare]::ReadWrite -bor [int][IO.FileShare]::Delete)
    $f=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,$share,4096,[IO.FileOptions]::WriteThrough)
    try { $f.Position=$Offset;$f.Write($Bytes,0,$Bytes.Length);$f.Flush($true) } finally { $f.Dispose() }
}
function Set-Length([string]$Path,[long]$Length) {
    $share=[IO.FileShare]([int][IO.FileShare]::ReadWrite -bor [int][IO.FileShare]::Delete)
    $f=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,$share,4096,[IO.FileOptions]::WriteThrough)
    try { $f.SetLength($Length);$f.Flush($true) } finally { $f.Dispose() }
}
function Expected-Bytes([int]$Length,[int]$Seed) {
    $b=[byte[]]::new($Length)
    for($i=0;$i -lt $Length;$i++) { $b[$i]=[byte](($Seed+31*$i+7*[int][Math]::Floor($i/4096))%256) }
    return ,$b
}
function Save-Json([string]$Path,$Value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 32 -Compress)+"`n")
    Write-NewBytes $Path $bytes
}
function Record([string]$Case,[string]$Status,[string]$Reason,$Facts) {
    $entry=[pscustomobject]@{Schema='InvariantObserverCorpus/1';CaseId=$Case;Status=$Status;Reason=$Reason;Facts=$Facts;Utc=[DateTime]::UtcNow.ToString('o')}
    $script:Results.Add($entry)
    $line=[Text.Encoding]::UTF8.GetBytes(($entry | ConvertTo-Json -Depth 20 -Compress)+"`n")
    $f=[IO.FileStream]::new((Join-Path $script:EvidenceDir 'status.ndjson'),[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try { $f.Write($line,0,$line.Length);$f.Flush($true) } finally { $f.Dispose() }
    Write-Output ('Corpus_'+$Case+'='+$Status+';'+$Reason.Replace("`r",' ').Replace("`n",' '))
}
function Invoke-Case([string]$Case,[scriptblock]$Body) {
    $scope=Join-Path $script:FixtureDir $Case
    $evidence=Join-Path $script:EvidenceDir $Case
    $script:LastDisposalError=$null;$script:DisposalRecorded=$false;$script:CurrentCaseEvidence=$evidence
    $facts=$null;$status='PASS';$reason='Driver-off corpus stimulus and observer checks completed; not Phase4 qualification.'
    try {
        [void][IO.Directory]::CreateDirectory($scope)
        [void][IO.Directory]::CreateDirectory($evidence)
        $facts=& $Body $scope $evidence
    }
    catch {
        $reason=$_.Exception.ToString();$status=if($reason.Contains('FAIL:')){'FAIL'}else{'INCONCLUSIVE'}
    }
    if(-not $script:DisposalRecorded){Close-Case $null}
    if($null -ne $script:LastDisposalError) {
        if($status -eq 'PASS'){$status='INCONCLUSIVE'}
        $reason+='; observer disposal: '+$script:LastDisposalError
    }
    Record $Case $status $reason $facts
}
function Open-Case([string]$Scope,[string]$Evidence,[string]$Name) {
    $guid=[StagedInvariant.Native]::ResolveGuid($Scope)
    $ctx=Open-InvariantObserver $guid $Scope (Join-Path $Evidence 'raw') ('ObserverCorpus-'+$Name+'-'+$RunGuid)
    if($ctx.Status -ne 'OK'){ Inconclusive ('Observer open: '+($ctx.Error | ConvertTo-Json -Depth 12 -Compress)) }
    return $ctx
}
function Close-Case($Context) {
    $closed=$null
    if($null -ne $Context -and $Context.Status -eq 'OK') {
        try {
            $closed=Close-InvariantObserver $Context
        } catch {$closed=[pscustomobject]@{Status='ERROR';Errors=@($_.Exception.ToString())}}
    } else {$closed=[pscustomobject]@{Status='NOT_OPENED';Errors=@('Observer was not opened; no disposal success claim.')}}
    if($closed.Status -ne 'OK'){$script:LastDisposalError=($closed | ConvertTo-Json -Depth 12 -Compress)}
    try {
        Save-Json (Join-Path $script:CurrentCaseEvidence 'disposal.json') $closed
        $script:DisposalRecorded=$true
    } catch {
        $script:LastDisposalError+='; disposal record unavailable: '+$_.Exception.ToString()
    }
}
function Assert-Readers($Capture) {
    foreach($image in @($Capture.Images | Where-Object {$_.Role -eq 'Current' -and -not $_.Absent})) {
        $matched=@($Capture.Readers | Where-Object {$_.Path -ceq $image.Path})
        if($matched.Count -ne 2 -or @($matched | Where-Object {$_.Unbuffered -eq $true}).Count -ne 1 -or
            @($matched | Where-Object {$_.Unbuffered -eq $false}).Count -ne 1){Inconclusive ('Current buffered/unbuffered reader pair missing: '+$image.Path)}
        foreach($reader in $matched){Assert-ReaderResult $reader $image}
    }
    foreach($image in @($Capture.Images | Where-Object {$_.Role -like 'Retained:*'})) {
        $matched=@($Capture.Readers | Where-Object {$null -ne $_.PSObject.Properties['Role'] -and $_.Role -eq 'Retained' -and $_.FileId -ceq $image.Identity.FileId -and $_.Unbuffered -eq $false})
        if($matched.Count -ne 1){Inconclusive ('Held retained reader missing/duplicate: '+$image.Identity.FileId)}
        Assert-ReaderResult $matched[0] $image
    }
}
function Assert-ReaderResult($Reader,$Image) {
    if($Reader.Status -ne 'OK' -or $null -eq $Reader.Result -or $Reader.Result.Status -ne 'OK' -or
        $null -eq $Reader.Result.Before -or $null -eq $Reader.Result.After){
        Inconclusive ('Reader error/missing native result: '+($Reader | ConvertTo-Json -Depth 12 -Compress))
    }
    $before=$Reader.Result.Before;$after=$Reader.Result.After;$raw=$Image.Identity
    if(-not [StagedInvariant.Native]::SameIdentity($before,$after) -or
        $before.FileId -cne $raw.FileId -or $after.FileId -cne $raw.FileId -or
        $before.Reference -ne $raw.Reference -or $after.Reference -ne $raw.Reference -or
        $before.VolumeSerial -ne $raw.VolumeSerial -or $after.VolumeSerial -ne $raw.VolumeSerial){
        Inconclusive ('Reader/raw identity unstable: '+($Reader | ConvertTo-Json -Depth 12 -Compress))
    }
    if($Reader.Result.Length -ne $Image.Length -or $Reader.Result.Digest -cne $Image.Sha256){
        Fail ('Reader/raw byte length or digest mismatch: '+($Reader | ConvertTo-Json -Depth 12 -Compress))
    }
}
function Baseline($Context,[string[]]$Names,[hashtable]$Expected,[string]$Evidence) {
    $b=Capture-InvariantBaseline $Context $Names $Expected
    Save-Json (Join-Path $Evidence 'baseline.json') $b
    if($b.Status -ne 'OK'){
        $errorText=$b.Error | ConvertTo-Json -Depth 12 -Compress
        if($errorText -match 'Raw baseline does not match independent fixture bytes'){Fail ('Canonical raw baseline mismatch: '+$errorText)}
        Inconclusive ('Baseline: '+$errorText)
    }
    Assert-Readers $b
    return $b
}
function Sample($Context,$Base,[string]$Phase,[int]$Sequence,[string]$Evidence) {
    $s=Capture-InvariantSample $Context $Base $Phase $Sequence
    Save-Json (Join-Path $Evidence ('sample-{0:D3}-{1}.json' -f $Sequence,$Phase)) $s
    if($s.Status -ne 'OK'){ Inconclusive ('Sample '+$Phase+': '+($s.Error | ConvertTo-Json -Depth 12 -Compress)) }
    Assert-Readers $s
    return $s
}
function Image($Capture,[string]$Path,[string]$Role='Current') {
    $images=@($Capture.Images | Where-Object { $_.Role -eq $Role -and $_.Path -ceq $Path })
    if($images.Count -ne 1){ Inconclusive ('Missing/duplicate '+$Role+' image: '+$Path) }
    return $images[0]
}
function Check-Image($Image,[byte[]]$Expected) {
    if($null -ne $Image.PSObject.Properties['Absent']){Require (-not $Image.Absent) 'Expected image is absent'}
    Require ($Image.Length -eq $Expected.Length -and $Image.Sha256 -ceq (Sha $Expected)) 'Canonical raw logical image differs from independently generated expected bytes'
    $artifact=[IO.File]::ReadAllBytes($Image.LogicalArtifact.Path)
    Require ($artifact.Length -eq $Expected.Length -and (Sha $artifact) -ceq $Image.LogicalArtifact.Sha256) 'Observer logical artifact missing/corrupt'
    for($i=0;$i -lt $artifact.Length;$i++){if($artifact[$i] -ne $Expected[$i]){Fail ('Observer logical artifact differs at '+$i)}}
    if(@($Image.CrossCheckErrors).Count -ne 0){ Inconclusive ('Raw/API cross-check: '+($Image.CrossCheckErrors -join ';')) }
}
function Changed-Raw($Before,$After) {
    $old=@($Before.Containers | ForEach-Object { $_.Artifact.Sha256 }) -join ';'
    $new=@($After.Containers | ForEach-Object { $_.Artifact.Sha256 }) -join ';'
    return $old -cne $new
}
function Decoder-Rejection([string]$Name,[scriptblock]$Body) {
    try {$null=& $Body;return [pscustomobject]@{Name=$Name;Rejected=$false;Recognized=$false;Chain=@()}}
    catch {
        $e=$_.Exception;$recognized=$false;$chain=@()
        while($null -ne $e) {
            if($e -is [StagedInvariant.ObservationException] -or $e -is [OverflowException]){$recognized=$true}
            $nativeCode=$null;$nativePhase=$null
            if($null -ne $e.PSObject.Properties['NativeCode']){$nativeCode=$e.NativeCode}
            if($null -ne $e.PSObject.Properties['Phase']){$nativePhase=$e.Phase}
            $chain+=,[pscustomobject]@{Type=$e.GetType().FullName;Message=$e.Message;HResult=$e.HResult;NativeCode=$nativeCode;NativePhase=$nativePhase}
            $e=$e.InnerException
        }
        return [pscustomobject]@{Name=$Name;Rejected=$true;Recognized=$recognized;Chain=$chain}
    }
}
function Save-Bin([string]$Path,[byte[]]$Bytes) {
    Write-NewBytes $Path $Bytes
    return [pscustomobject]@{Path=$Path;Length=$Bytes.Length;Sha256=(Sha $Bytes)}
}
function Assert-NoReparseTree([string]$Root) {
    for($p=$Root; -not [string]::IsNullOrWhiteSpace($p); $p=[IO.Path]::GetDirectoryName($p)) {
        $attrs=[IO.File]::GetAttributes($p)
        if(($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse ancestor at cleanup: '+$p)}
    }
    $pending=New-Object 'System.Collections.Generic.Stack[string]';$pending.Push($Root)
    while($pending.Count -gt 0) {
        $p=$pending.Pop();$attrs=[IO.File]::GetAttributes($p)
        if(($attrs -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse child at cleanup: '+$p)}
        if(($attrs -band [IO.FileAttributes]::Directory) -ne 0){
            foreach($child in [IO.Directory]::GetFileSystemEntries($p)){$pending.Push($child)}
        }
    }
}
function Check-ZeroSlack($Image) {
    $data=@($Image.Containers | Where-Object {$_.Kind -eq 'DATA'})
    $allocation=[long]$Image.Identity.Allocation;$eof=[long]$Image.Length
    if($allocation -le $eof -or $data.Count -eq 0){Inconclusive 'Physical allocated slack unavailable'}
    $stream=[IO.MemoryStream]::new()
    try {
        foreach($part in $data){$bytes=[IO.File]::ReadAllBytes($part.Artifact.Path);$stream.Write($bytes,0,$bytes.Length)}
        $physical=$stream.ToArray()
        if($physical.Length -lt $allocation){Inconclusive 'Physical allocation/slack capture truncated'}
        for($i=$eof;$i -lt $allocation;$i++){if($physical[$i] -ne 0){Inconclusive ('Nonzero raw allocated slack at '+$i)}}
    } finally {$stream.Dispose()}
}
function Assert-Platform {
    if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Windows PowerShell 5.1 required'}
    $w=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if($env:COMPUTERNAME -cne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D' -or
        [string]$w.CurrentBuildNumber -cne '19045' -or [int]$w.UBR -ne 2965){throw 'Wrong debuggee UUID/Windows build'}
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated observer required'}
    $flt=& fltmc.exe filters 2>&1 | Out-String
    if($LASTEXITCODE -ne 0 -or $flt -match '(?m)^SafeUpload\s'){throw 'DriverUnloaded precondition failed: filter inventory'}
    $d=@(Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'" -ErrorAction Stop)
    if($d.Count -ne 1 -or $d[0].State -ne 'Stopped'){throw 'DriverUnloaded precondition failed: service state'}
    foreach($root in @($FixtureRoot,$EvidenceRoot)) {
        $full=[IO.Path]::GetFullPath($root)
        if(-not(Test-Path -LiteralPath $full -PathType Container)){throw ('Missing root '+$full)}
        for($p=$full; -not [string]::IsNullOrWhiteSpace($p); $p=[IO.Path]::GetDirectoryName($p)) {
            if(((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse root/ancestor '+$p)}
        }
        $drive=[IO.Path]::GetPathRoot($full).TrimEnd('\')
        $ld=@(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -ceq $drive })
        if($ld.Count -ne 1 -or $ld[0].DriveType -ne 3 -or $ld[0].FileSystem -cne 'NTFS'){throw ('Fixed local NTFS required: '+$full)}
    }
    $fx=[IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')
    $ev=[IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')
    if($fx -ceq $ev -or $fx.StartsWith($ev+'\',[StringComparison]::OrdinalIgnoreCase) -or $ev.StartsWith($fx+'\',[StringComparison]::OrdinalIgnoreCase)){
        throw 'FixtureRoot and EvidenceRoot must be separate trees'
    }
}

# Mutating fixture-only native calls. No raw-volume writes or alternate decoder.
$stimulus=@'
using System;using System.Runtime.InteropServices;
public static class ObserverCorpusStimulus {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
 public static extern bool MoveFileEx(string source,string target,uint flags);
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]
 public static extern bool SetFileInformationByHandle(IntPtr file,int informationClass,ref long information,uint size);
}
'@

$ownedFixtureCreated=$false
try {
    Assert-Platform
    $observer=Join-Path $PSScriptRoot 'StagedInvariantObserver.psm1'
    $actual=(Get-FileHash -LiteralPath $observer -Algorithm SHA256).Hash
    if($actual -cne $ExpectedObserverSha256.ToUpperInvariant()){throw 'Observer module hash mismatch'}
    Import-Module $observer -Force -DisableNameChecking
    if(-not ('ObserverCorpusStimulus' -as [type])){Add-Type -TypeDefinition $stimulus -ErrorAction Stop}
    $script:FixtureDir=Join-Path ([IO.Path]::GetFullPath($FixtureRoot)) ('observer-corpus-'+$RunGuid.ToLowerInvariant())
    $script:EvidenceDir=Join-Path ([IO.Path]::GetFullPath($EvidenceRoot)) ('observer-corpus-'+$RunGuid.ToLowerInvariant())
    if((Test-Path -LiteralPath $script:FixtureDir) -or (Test-Path -LiteralPath $script:EvidenceDir)){throw 'RunGuid collision'}
    [void][IO.Directory]::CreateDirectory($script:EvidenceDir)
    [void][IO.Directory]::CreateDirectory($script:FixtureDir)
    $ownedFixtureCreated=$true
    Save-Json (Join-Path $script:EvidenceDir 'provenance.json') ([pscustomobject]@{
        Schema='InvariantObserverCorpus/1';RunGuid=$RunGuid;Host=$env:COMPUTERNAME;Uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID;
        Build='19045.2965';Boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');
        DriverUnloaded=$true;FixtureRoot=$FixtureRoot;EvidenceRoot=$EvidenceRoot;ObserverSha256=$actual;
        ScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;
        Warning='Corpus stimulus only; no Phase4Suite qualification or lower ledger.'})
} catch {
    if($ownedFixtureCreated -and $null -ne $script:FixtureDir -and (Test-Path -LiteralPath $script:FixtureDir)){
        try {Assert-NoReparseTree $script:FixtureDir;[IO.Directory]::Delete($script:FixtureDir,$true)}catch {[Console]::Error.WriteLine('Owned fixture preflight cleanup failed: '+$_.Exception.ToString())}
    }
    [Console]::Error.WriteLine('Observer corpus preflight failed: '+$_.Exception.ToString())
    exit 2
}

Invoke-Case 'ResidentConversion' {
    param($scope,$evidence)
    $path=Join-Path $scope 'convert.bin';$old=Expected-Bytes 80 11;Write-NewBytes $path $old
    $ctx=$null
    try {
        $ctx=Open-Case $scope $evidence 'ResidentConversion'
        $b=Baseline $ctx @('convert.bin') @{'convert.bin'=$old} $evidence
        $before=Image $b $path;Check-Image $before $old;Require $before.Resident 'Initial 80-byte data not resident'
        $new=Expected-Bytes 8192 19;Set-Length $path $new.Length;Patch-Bytes $path 0 $new
        $s=Sample $ctx $b 'Converted' 1 $evidence;$after=Image $s $path;Check-Image $after $new
        Require (-not $after.Resident -and @($after.Runs | Where-Object {$_.Lcn -ge 0}).Count -gt 0) 'Resident to nonresident conversion not observed'
        Require ((Changed-Raw $before $after) -and $before.Identity.FileId -ceq $after.Identity.FileId) 'Raw conversion or stable identity missing'
        return @{BeforeResident=$before.Resident;AfterResident=$after.Resident;FileId=$after.Identity.FileId;Runs=@($after.Runs).Count}
    } finally {Close-Case $ctx}
}

Invoke-Case 'OneByteAndFourKiB' {
    param($scope,$evidence)
    $one=Expected-Bytes 1 13;$four=Expected-Bytes 4096 17
    $onePath=Join-Path $scope 'one.bin';$fourPath=Join-Path $scope 'four-k.bin'
    Write-NewBytes $onePath $one;Write-NewBytes $fourPath $four
    $ctx=$null
    try {
        $ctx=Open-Case $scope $evidence 'OneByteAndFourKiB'
        $b=Baseline $ctx @('one.bin','four-k.bin') @{'one.bin'=$one;'four-k.bin'=$four} $evidence
        $small=Image $b $onePath;$large=Image $b $fourPath
        Check-Image $small $one;Check-Image $large $four
        $facts=@{OneByte=@{Resident=$small.Resident;Runs=@($small.Runs).Count;FileId=$small.Identity.FileId};
            FourKiB=@{Resident=$large.Resident;Runs=@($large.Runs).Count;FileId=$large.Identity.FileId}}
        Save-Json (Join-Path $evidence 'classification.json') $facts
        if(-not $small.Resident -or @($small.Runs).Count -ne 0){Inconclusive 'Actual one-byte resident representation not produced'}
        if($large.Resident -or @($large.Runs | Where-Object {$_.Lcn -ge 0}).Count -eq 0){Inconclusive 'Actual 4096-byte nonresident allocation not produced'}
        return $facts
    } finally {Close-Case $ctx}
}

Invoke-Case 'SparseMapping' {
    param($scope,$evidence)
    $path=Join-Path $scope 'sparse.bin';Write-NewBytes $path ([byte[]]::new(0))
    $output=& fsutil.exe sparse setflag $path 2>&1 | Out-String
    if($LASTEXITCODE -ne 0){Inconclusive ('Sparse FSCTL unavailable: '+$output)}
    Set-Length $path 1048576
    $old=[byte[]]::new(1048576)
    foreach($offset in @(0,524288,1044480)) {$part=Expected-Bytes 4096 (17+$offset/4096);Patch-Bytes $path $offset $part;[Array]::Copy($part,0,$old,$offset,4096)}
    $ctx=$null
    try {
        $ctx=Open-Case $scope $evidence 'SparseMapping';$b=Baseline $ctx @('sparse.bin') @{'sparse.bin'=$old} $evidence
        $before=Image $b $path;Check-Image $before $old
        if(@($before.Runs | Where-Object {$_.Lcn -lt 0}).Count -eq 0){Inconclusive 'Actual sparse hole map not produced'}
        $sequence=0;$detected=@()
        foreach($where in @('First','Middle','Last')) {
            $runs=@($before.Runs | Where-Object {$_.Lcn -ge 0})
            if($runs.Count -lt 3){Inconclusive 'Three allocated sparse extents not produced'}
            $index=if($where -eq 'First'){0}elseif($where -eq 'Middle'){[int][Math]::Floor($runs.Count/2)}else{$runs.Count-1}
            $offset=[int]($runs[$index].Vcn*$ctx.Geometry.Cluster);$new=[byte[]]$old.Clone();$new[$offset]=[byte](($new[$offset]+1)%256)
            Patch-Bytes $path $offset ([byte[]]@($new[$offset]));$sequence++
            $s=Sample $ctx $b ('Changed'+$where) $sequence $evidence;$after=Image $s $path;Check-Image $after $new
            Require (Changed-Raw $before $after) ('Sparse raw '+$where+' extent change missed')
            $detected+=@{Extent=$where;Offset=$offset;Run=$index};Patch-Bytes $path $offset ([byte[]]@($old[$offset]))
        }
        return @{Holes=@($before.Runs | Where-Object {$_.Lcn -lt 0}).Count;AllocatedRuns=$runs.Count;Detected=$detected}
    } finally {Close-Case $ctx}
}

Invoke-Case 'CompressedMapping' {
    param($scope,$evidence)
    $path=Join-Path $scope 'compressed.bin';Write-NewBytes $path ([byte[]]::new(0))
    $output=& compact.exe /C /A /I /Q $path 2>&1 | Out-String
    if($LASTEXITCODE -ne 0){Inconclusive ('NTFS compression unavailable: '+$output)}
    $old=[byte[]]::new(1048576)
    for($i=0;$i -lt $old.Length;$i++) {$old[$i]=[byte](65+[int][Math]::Floor($i/65536)%4)}
    Patch-Bytes $path 0 $old
    $ctx=$null
    try {
        $ctx=Open-Case $scope $evidence 'CompressedMapping';$b=Baseline $ctx @('compressed.bin') @{'compressed.bin'=$old} $evidence
        $before=Image $b $path;Check-Image $before $old
        $data=@($before.Attributes | Where-Object {$_.Type -eq 128 -and $_.Name -ceq ''})
        if($data.Count -ne 1 -or ($data[0].Flags -band 1) -eq 0 -or $data[0].CompressionUnit -eq 0 -or
            @($before.Runs | Where-Object {$_.Lcn -lt 0}).Count -eq 0){Inconclusive 'Actual NTFS compressed allocation/tail map not produced'}
        $allocated=@($before.Runs | Where-Object {$_.Lcn -ge 0 -and $_.Vcn*$ctx.Geometry.Cluster -lt $before.Length})
        if($allocated.Count -lt 3){Inconclusive ('Three allocated compressed extents NotReady: '+$allocated.Count)}
        $detected=@();$sequence=0
        foreach($where in @('First','Middle','Last')) {
            $index=if($where -eq 'First'){0}elseif($where -eq 'Middle'){[int][Math]::Floor($allocated.Count/2)}else{$allocated.Count-1}
            $offset=[int]($allocated[$index].Vcn*$ctx.Geometry.Cluster)
            $new=[byte[]]$old.Clone();$new[$offset]=[byte](($new[$offset]+1)%256)
            Patch-Bytes $path $offset ([byte[]]@($new[$offset]));$sequence++
            $s=Sample $ctx $b ('Changed'+$where) $sequence $evidence;$after=Image $s $path;Check-Image $after $new
            Require (Changed-Raw $before $after) ('Compressed physical unit '+$where+' change missed')
            $detected+=@{Unit=$where;Offset=$offset};Patch-Bytes $path $offset ([byte[]]@($old[$offset]))
        }
        return @{CompressionUnit=$data[0].CompressionUnit;Runs=@($before.Runs).Count;Detected=$detected}
    } finally {Close-Case $ctx}
}

Invoke-Case 'FragmentedExtents' {
    param($scope,$evidence)
    $stream=[IO.MemoryStream]::new()
    try {
        for($round=0;$round -lt 128;$round++) {
            for($file=0;$file -lt 12;$file++) {
                $path=Join-Path $scope ('fragment-{0:D2}.bin' -f $file)
                if($round -eq 0){Write-NewBytes $path ([byte[]]::new(0))}
                $part=Expected-Bytes 16384 ($round+31*$file)
                $f=[IO.FileStream]::new($path,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
                try {$f.Write($part,0,$part.Length);$f.Flush($true)}finally{$f.Dispose()}
                if($file -eq 0){$stream.Write($part,0,$part.Length)}
            }
        }
        $old=$stream.ToArray()
    } finally {$stream.Dispose()}
    $target=Join-Path $scope 'fragment-00.bin';$ctx=$null
    try {
        $ctx=Open-Case $scope $evidence 'FragmentedExtents';$b=Baseline $ctx @('fragment-00.bin') @{'fragment-00.bin'=$old} $evidence
        $before=Image $b $target;Check-Image $before $old
        $runs=@($before.Runs | Where-Object {$_.Lcn -ge 0 -and $_.Vcn*$ctx.Geometry.Cluster -lt $before.Length})
        if($runs.Count -lt 3){Inconclusive ('Actual fragmentation NotReady: '+$runs.Count+' extents')}
        $detected=@();$sequence=0
        foreach($where in @('First','Middle','Last')) {
            $index=if($where -eq 'First'){0}elseif($where -eq 'Middle'){[int][Math]::Floor($runs.Count/2)}else{$runs.Count-1}
            $offset=[int]($runs[$index].Vcn*$ctx.Geometry.Cluster);$new=[byte[]]$old.Clone();$new[$offset]=[byte](($new[$offset]+1)%256)
            Patch-Bytes $target $offset ([byte[]]@($new[$offset]));$sequence++
            $s=Sample $ctx $b ('Changed'+$where) $sequence $evidence;$after=Image $s $target;Check-Image $after $new
            Require (Changed-Raw $before $after) ('Raw '+$where+' extent change missed')
            $detected+=@{Extent=$where;Offset=$offset;Run=$index};Patch-Bytes $target $offset ([byte[]]@($old[$offset]))
        }
        return @{AllocatedRuns=$runs.Count;Detected=$detected}
    } finally {Close-Case $ctx}
}

Invoke-Case 'ReplacementEofSlack' {
    param($scope,$evidence)
    $target=Join-Path $scope 'target.bin';$source=Join-Path $scope 'source.bin';$old=Expected-Bytes 8192 37;$new=Expected-Bytes 6144 41
    Write-NewBytes $target $old;Write-NewBytes $source $new
    $share=[IO.FileShare]([int][IO.FileShare]::ReadWrite -bor [int][IO.FileShare]::Delete)
    $f=[IO.FileStream]::new($target,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,$share)
    try {$allocation=[long]16384;if(-not [ObserverCorpusStimulus]::SetFileInformationByHandle($f.SafeFileHandle.DangerousGetHandle(),5,[ref]$allocation,8)){
        Inconclusive ('FileAllocationInfo unsupported: '+[Runtime.InteropServices.Marshal]::GetLastWin32Error())};$f.Flush($true)}finally{$f.Dispose()}
    $ctx=$null
    try {
        $ctx=Open-Case $scope $evidence 'ReplacementEofSlack';$b=Baseline $ctx @('target.bin','source.bin') @{'target.bin'=$old;'source.bin'=$new} $evidence
        $before=Image $b $target;Check-Image $before $old
        if($before.Identity.Allocation -le $before.Length){Inconclusive 'Preallocated target slack NotReady: allocation did not exceed EOF'}
        Check-ZeroSlack $before
        if(-not [ObserverCorpusStimulus]::MoveFileEx($source,$target,0x9)){Inconclusive ('Replacement failed: '+[Runtime.InteropServices.Marshal]::GetLastWin32Error())}
        $s=Sample $ctx $b 'Replaced' 1 $evidence;$after=Image $s $target;Check-Image $after $new
        Require ($after.Identity.FileId -cne $before.Identity.FileId) 'Replacement reused old file identity'
        $retained=@($s.Images | Where-Object {$_.Role -like 'Retained:*' -and $_.Identity.FileId -ceq $before.Identity.FileId})
        if($retained.Count -ne 1){Inconclusive 'Old held reader/identity not retained'}
        Check-Image $retained[0] $old
        $grown=[byte[]]::new(12288);[Array]::Copy($new,0,$grown,0,$new.Length)
        Set-Length $target $grown.Length
        $s2=Sample $ctx $b 'EofGrown' 2 $evidence;$after2=Image $s2 $target;Check-Image $after2 $grown
        Require ($after2.Identity.Eof -eq $grown.Length -and (Changed-Raw $after $after2)) 'EOF growth/raw allocation detection missing'
        return @{OldFileId=$before.Identity.FileId;NewFileId=$after.Identity.FileId;OldAllocation=$before.Identity.Allocation;OldEof=$before.Length;NewEof=$after2.Length;RetainedOld=$true}
    } finally {Close-Case $ctx}
}

Invoke-Case 'DirectoryIndexGrowth' {
    param($scope,$evidence)
    $anchor=Join-Path $scope 'anchor.bin';$old=Expected-Bytes 32 51;Write-NewBytes $anchor $old
    for($i=0;$i -lt 850;$i++) {Write-NewBytes (Join-Path $scope ('index-{0:D4}.bin' -f $i)) ([byte[]]::new(0))}
    $ctx=$null
    try {
        $ctx=Open-Case $scope $evidence 'DirectoryIndexGrowth';$b=Baseline $ctx @('anchor.bin','new-name.bin') @{'anchor.bin'=$old;'new-name.bin'=$null} $evidence
        $parent=@($b.Images | Where-Object {$_.Role -eq 'Parent'})[0]
        $index=@($parent.Attributes | Where-Object {$_.Type -eq 160 -and $_.Name -ceq '$I30'})
        if($index.Count -ne 1){Inconclusive 'Nonresident directory index allocation NotReady'}
        $indexRuns=@($index[0].Runs | Where-Object {$_.Lcn -ge 0})
        $new=Expected-Bytes 64 53;$name=Join-Path $scope 'new-name.bin';Write-NewBytes $name $new
        [IO.File]::SetAttributes($name,[IO.FileAttributes]::Hidden)
        $s=Sample $ctx $b 'NameAndMetadataChanged' 1 $evidence
        $newImage=Image $s $name;Check-Image $newImage $new
        $parent2=@($s.Images | Where-Object {$_.Role -eq 'Parent'})[0]
        Require (@($parent.DirectoryEntries | Where-Object {$_.Name -ceq 'new-name.bin'}).Count -eq 0) 'Baseline directory unexpectedly contains new name'
        Require (@($parent2.DirectoryEntries | Where-Object {$_.Name -ceq 'new-name.bin' -and ($_.Attributes -band 2) -ne 0}).Count -gt 0) 'Raw index missed new name/hidden metadata'
        Require (Changed-Raw $parent $parent2) 'Raw directory index/MFT metadata change missed'
        if($indexRuns.Count -lt 2){Inconclusive ('Index fragmentation NotReady: '+$indexRuns.Count+' allocated runs; growth/name detection recorded')}
        $touched=New-Object 'System.Collections.Generic.HashSet[int]'
        foreach($part in @($parent2.Containers | Where-Object {$_.Kind -eq 'INDEX_ALLOCATION'})) {
            for($i=0;$i -lt $indexRuns.Count;$i++) {
                $lo=[long]$indexRuns[$i].Lcn*$ctx.Geometry.Cluster;$hi=$lo+[long]$indexRuns[$i].Clusters*$ctx.Geometry.Cluster
                if($part.Offset -ge $lo -and $part.Offset -lt $hi){[void]$touched.Add($i)}
            }
        }
        if($touched.Count -lt 2){Inconclusive ('Index fragmentation NotReady: decoded containers touched '+$touched.Count+' runs')}
        return @{IndexAllocatedRuns=$indexRuns.Count;IndexRunsActuallyRead=$touched.Count;EntryCount=@($parent2.DirectoryEntries).Count;NewNameDetected=$true;HiddenMetadataDetected=$true}
    } finally {Close-Case $ctx}
}

Invoke-Case 'MftFragmentation' {
    param($scope,$evidence)
    $bytes=Expected-Bytes 64 61;Write-NewBytes (Join-Path $scope 'mft-probe.bin') $bytes
    for($i=0;$i -lt 1000;$i++){Write-NewBytes (Join-Path $scope ('mft-growth-{0:D4}.bin' -f $i)) ([byte[]]::new(0))}
    $ctx=$null
    try {
        $ctx=Open-Case $scope $evidence 'MftFragmentation'
        $names=@('mft-probe.bin');$expected=@{'mft-probe.bin'=$bytes}
        for($i=745;$i -lt 1000;$i++){$name='mft-growth-{0:D4}.bin' -f $i;$names+=,$name;$expected[$name]=[byte[]]::new(0)}
        $b=Baseline $ctx ([string[]]$names) $expected $evidence
        Check-Image (Image $b (Join-Path $scope 'mft-probe.bin')) $bytes
        $runs=@($ctx.Volume.MftRuns | Where-Object {$_.Lcn -ge 0})
        Save-Json (Join-Path $evidence 'mft-runs.json') $runs
        if($runs.Count -lt 2){Inconclusive ('MFT fragmentation NotReady on this volume: '+$runs.Count+' run(s); no manufactured PASS')}
        $containers=@($ctx.InitialScope.Containers)+@($b.Images | ForEach-Object {$_.Containers})
        $touched=New-Object 'System.Collections.Generic.HashSet[int]'
        foreach($part in @($containers | Where-Object {$_.Kind -eq 'MFT'})) {
            for($i=0;$i -lt $runs.Count;$i++) {
                $lo=[long]$runs[$i].Lcn*$ctx.Geometry.Cluster;$hi=$lo+[long]$runs[$i].Clusters*$ctx.Geometry.Cluster
                if($part.Offset -ge $lo -and $part.Offset -lt $hi){[void]$touched.Add($i)}
            }
        }
        if($touched.Count -lt 2){Inconclusive ('MFT fragmentation NotReady: decoded records touched '+$touched.Count+' runs')}
        return @{MftRuns=$runs.Count;RunsActuallyRead=$touched.Count;RawBootstrapArtifacts=@($ctx.BootstrapArtifacts).Count}
    } finally {Close-Case $ctx}
}

Invoke-Case 'FailClosedDecoderCopies' {
    param($scope,$evidence)
    $path=Join-Path $scope 'record.bin';$bytes=Expected-Bytes 80 67;Write-NewBytes $path $bytes
    $ctx=$null
    try {
        $ctx=Open-Case $scope $evidence 'FailClosedDecoderCopies';$b=Baseline $ctx @('record.bin') @{'record.bin'=$bytes} $evidence
        $image=Image $b $path;Check-Image $image $bytes
        $mft=@($image.Containers | Where-Object {$_.Kind -eq 'MFT'})
        if($mft.Count -eq 0){Inconclusive 'Raw MFT record artifact unavailable'}
        $stream=[IO.MemoryStream]::new()
        try {foreach($part in $mft){$chunk=[IO.File]::ReadAllBytes($part.Artifact.Path);$stream.Write($chunk,0,$chunk.Length)};$record=$stream.ToArray()}
        finally {$stream.Dispose()}
        $number=[uint32]$image.Records[0].Number
        if($record.Length -ne $ctx.Geometry.RecordSize){Inconclusive 'MFT container does not hold one record'}
        $bad=[byte[]]$record.Clone();$bad[$ctx.Geometry.Sector-2]=[byte]($bad[$ctx.Geometry.Sector-2] -bxor 1)
        $truncated=[StagedInvariant.Native]::Slice($record,0,$record.Length-1)
        $badRun=[byte[]]@(0x11,0x02)
        $inputs=@{
            RawUsaCorruption=(Save-Bin (Join-Path $evidence 'raw-usa-corruption.bin') $bad)
            TruncatedRawRecord=(Save-Bin (Join-Path $evidence 'truncated-raw-record.bin') $truncated)
            TruncatedRunMapping=(Save-Bin (Join-Path $evidence 'truncated-run-mapping.bin') $badRun)
            ShortRawRead=@{Start=0;End=4096;Rounded=4096;Transfer=4096;Count=2048;EofAllowed=$false;Eof=0}
        }
        $rejections=@()
        $rejections+=,(Decoder-Rejection 'RawUsaCorruption' {$null=[StagedInvariant.Native]::DecodeRecord($bad,$ctx.Geometry.Sector,$number)})
        $rejections+=,(Decoder-Rejection 'TruncatedRawRecord' {$null=[StagedInvariant.Native]::DecodeRecord($truncated,$ctx.Geometry.Sector,$number)})
        $rejections+=,(Decoder-Rejection 'TruncatedRunMapping' {$null=[StagedInvariant.Native]::DecodeRuns($badRun,0,$badRun.Length,0,2)})
        $rejections+=,(Decoder-Rejection 'ShortRawRead' {[StagedInvariant.Native]::ValidateReadResult(0,4096,4096,4096,[uint32]2048,$false,0)})
        $proof=@{RawRecordArtifacts=@($mft | ForEach-Object {$_.Artifact});ExpectedRecord=$number;Inputs=$inputs;Rejections=$rejections;RawDiskWritten=$false}
        Save-Json (Join-Path $evidence 'negative-inputs.json') $proof
        if(@($rejections | Where-Object {-not $_.Rejected}).Count -ne 0){Fail 'Canonical decoder accepted malformed raw input or short read'}
        if(@($rejections | Where-Object {-not $_.Recognized}).Count -ne 0){Inconclusive 'Malformed input got unrelated error type; see negative-inputs.json'}
        return @{Rejected=@($rejections | ForEach-Object {$_.Name});SourceRawRecordSha256=(Sha $record);RawDiskWritten=$false}
    } finally {Close-Case $ctx}
}

# Delete only the unique GUID-owned fixture tree after all observer handles close.
try {
    $ownedName='observer-corpus-'+$RunGuid.ToLowerInvariant()
    if([IO.Path]::GetFileName($script:FixtureDir) -cne $ownedName -or
        -not $script:FixtureDir.StartsWith([IO.Path]::GetFullPath($FixtureRoot).TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){
        throw 'Owned fixture cleanup guard failed'
    }
    Assert-NoReparseTree $script:FixtureDir
    [IO.Directory]::Delete($script:FixtureDir,$true)
    if(Test-Path -LiteralPath $script:FixtureDir){throw 'Owned fixture residue'}
    Record 'OwnedFixtureCleanup' 'PASS' 'Only GUID-owned fixture tree removed; evidence retained.' @{Fixture=$script:FixtureDir}
} catch {Record 'OwnedFixtureCleanup' 'FAIL' $_.Exception.ToString() @{Fixture=$script:FixtureDir}}

$counts=@{PASS=@($script:Results | Where-Object {$_.Status -eq 'PASS'}).Count;FAIL=@($script:Results | Where-Object {$_.Status -eq 'FAIL'}).Count;INCONCLUSIVE=@($script:Results | Where-Object {$_.Status -eq 'INCONCLUSIVE'}).Count}
Save-Json (Join-Path $script:EvidenceDir 'summary.json') ([pscustomobject]@{Schema='InvariantObserverCorpus/1';RunGuid=$RunGuid;Counts=$counts;Results=$script:Results.ToArray();
    AuthoritativeCaseExport=$false;Phase4Suite='NOT_QUALIFIED';EvidenceDir=$script:EvidenceDir;FixturesRemoved=(-not(Test-Path -LiteralPath $script:FixtureDir))})
Write-Output ('Corpus_Summary=pass:'+ $counts.PASS +';fail:'+ $counts.FAIL +';inconclusive:'+ $counts.INCONCLUSIVE +';Phase4Suite:NOT_QUALIFIED')
if($counts.FAIL -gt 0){exit 1}
if($counts.INCONCLUSIVE -gt 0){exit 2}
exit 0
