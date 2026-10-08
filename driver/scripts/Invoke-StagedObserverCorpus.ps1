<# Checkpointed driver-off observer corpus coordinator. The host adapter owns invocation. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunGuid,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$CoordinatorSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$CorpusSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ObserverSha256,
    [Parameter(Mandatory=$true)][string]$CorpusLeaf,
    [Parameter(Mandatory=$true)][string]$ObserverLeaf
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$RunGuid=$RunGuid.ToLowerInvariant()
$docs=[IO.Path]::GetFullPath((Join-Path $env:USERPROFILE 'Documents'))
$fixtureRoot=Join-Path $docs ('SafeUpload-corpus-fixtures-'+$RunGuid)
$evidenceRoot=Join-Path $docs ('SafeUpload-corpus-evidence-'+$RunGuid)
$archive=Join-Path $docs ('SafeUpload-corpus-'+$RunGuid+'.zip')
$corpusInput=Join-Path $docs $CorpusLeaf
$observerInput=Join-Path $docs $ObserverLeaf
$childExit=$null
$timedOut=$false
$archiveHash=$null
$cleanup='False'
$coordinatorStatus='INCONCLUSIVE'
$process=$null
$fixtureCreated=$false
$evidenceCreated=$false
$childForcedKill=$false

function Assert-Platform {
    if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Windows PowerShell 5.1 required'}
    $w=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    if($env:COMPUTERNAME -cne 'WIN10-DEBUGGED' -or
       (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D' -or
       [string]$w.CurrentBuildNumber -cne '19045' -or [int]$w.UBR -ne 2965){
        throw 'Wrong debuggee UUID/Windows build'
    }
    $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Elevated observer required'}
    $flt=& fltmc.exe filters 2>&1 | Out-String
    if($LASTEXITCODE -ne 0 -or $flt -match '(?m)^SafeUpload\s'){throw 'DriverUnloaded precondition failed: filter inventory'}
    $d=@(Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'" -ErrorAction Stop)
    if($d.Count -ne 1 -or $d[0].State -ne 'Stopped'){throw 'DriverUnloaded precondition failed: service state'}
}

function Assert-FileHash([string]$Path,[string]$Expected) {
    if(-not [IO.File]::Exists($Path)){throw ('Missing pinned input: '+$Path)}
    $actual=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    if($actual -cne $Expected.ToUpperInvariant()){throw ('Pinned input hash mismatch: '+$Path)}
}
function Write-NewJson([string]$Path,$Value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 32 -Compress)+"`n")
    $f=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()}
}
function Assert-NoReparseTree([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    $walk=$full
    while($walk){
        if([IO.File]::Exists($walk) -or [IO.Directory]::Exists($walk)){
            $item=Get-Item -LiteralPath $walk -Force -ErrorAction Stop
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse ancestor: '+$walk)}
        }
        $parent=[IO.Directory]::GetParent($walk)
        if($null -eq $parent){break}
        $walk=$parent.FullName
    }
    if([IO.Directory]::Exists($full)){
        foreach($item in @(Get-ChildItem -LiteralPath $full -Force -Recurse -ErrorAction Stop)){
            if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Reparse child: '+$item.FullName)}
        }
    }
}
function Assert-Owned([string]$Path,[string]$ExpectedLeaf) {
    $full=[IO.Path]::GetFullPath($Path)
    if([IO.Path]::GetDirectoryName($full).TrimEnd('\') -ine $docs.TrimEnd('\') -or
       [IO.Path]::GetFileName($full) -cne $ExpectedLeaf){throw ('Unsafe owned path: '+$full)}
    Assert-NoReparseTree $full
}
function Hash-Stream([IO.Stream]$Stream) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-','')}
    finally{$sha.Dispose()}
}
function New-VerifiedArchive([string]$Source,[string]$Target) {
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    $files=@(Get-ChildItem -LiteralPath $Source -File -Recurse -Force -ErrorAction Stop | Sort-Object FullName)
    $entries=New-Object 'System.Collections.Generic.List[object]'
    foreach($file in $files){
        if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw ('Archive reparse input: '+$file.FullName)}
        $relative=$file.FullName.Substring($Source.TrimEnd('\').Length+1).Replace('\','/')
        if($relative -eq 'archive-manifest.json' -or $relative.StartsWith('/') -or $relative.Contains('../')){throw ('Unsafe archive entry: '+$relative)}
        $entries.Add([pscustomobject]@{Path=$relative;Length=[long]$file.Length;Sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToUpperInvariant()})
    }
    Write-NewJson (Join-Path $Source 'archive-manifest.json') ([pscustomobject]@{Schema='ObserverCorpusArchive/1';RunGuid=$RunGuid;Entries=$entries.ToArray()})
    $manifestHash=(Get-FileHash -LiteralPath (Join-Path $Source 'archive-manifest.json') -Algorithm SHA256).Hash.ToUpperInvariant()
    $stream=[IO.FileStream]::new($Target,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None,65536,[IO.FileOptions]::WriteThrough)
    try {
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            foreach($file in @(Get-ChildItem -LiteralPath $Source -File -Recurse -Force | Sort-Object FullName)){
                $relative=$file.FullName.Substring($Source.TrimEnd('\').Length+1).Replace('\','/')
                $entry=$zip.CreateEntry($relative,[IO.Compression.CompressionLevel]::Optimal)
                $input=[IO.File]::OpenRead($file.FullName)
                $output=$entry.Open()
                try{$input.CopyTo($output)}finally{$output.Dispose();$input.Dispose()}
            }
        } finally {$zip.Dispose()}
        $stream.Flush($true)
    } finally {$stream.Dispose()}
    $stream=[IO.File]::OpenRead($Target)
    try {
        $zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$true)
        try {
            $expected=@{}
            foreach($row in $entries){$expected[$row.Path]=$row}
            $seen=@{}
            foreach($entry in $zip.Entries){
                if($seen.ContainsKey($entry.FullName)){throw ('Duplicate archive entry: '+$entry.FullName)}
                $seen[$entry.FullName]=$true
                if($entry.FullName -ne 'archive-manifest.json' -and -not $expected.ContainsKey($entry.FullName)){
                    throw ('Unexpected archive entry: '+$entry.FullName)
                }
                $input=$entry.Open()
                try{$actual=Hash-Stream $input}finally{$input.Dispose()}
                if($entry.FullName -eq 'archive-manifest.json'){
                    if($actual -cne $manifestHash){throw 'Archive manifest hash mismatch'}
                    continue
                }
                if($entry.Length -ne $expected[$entry.FullName].Length -or $actual -cne $expected[$entry.FullName].Sha256){throw ('Archive mismatch: '+$entry.FullName)}
            }
            if($seen.Count -ne $expected.Count+1){throw 'Archive omits evidence entry'}
        } finally {$zip.Dispose()}
    } finally {$stream.Dispose()}
    return (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToUpperInvariant()
}

try {
    Assert-Platform
    if($CorpusLeaf -cnotmatch '^Test-StagedInvariantObserverCorpus-[0-9A-Fa-f]{16}\.ps1$' -or
       $ObserverLeaf -cnotmatch '^StagedInvariantObserver-[0-9A-Fa-f]{16}\.psm1$'){
        throw 'Unexpected staged input leaf'
    }
    Assert-FileHash $PSCommandPath $CoordinatorSha256
    Assert-FileHash $corpusInput $CorpusSha256
    Assert-FileHash $observerInput $ObserverSha256
    if([IO.Directory]::Exists($fixtureRoot) -or [IO.Directory]::Exists($evidenceRoot) -or [IO.File]::Exists($archive)){
        throw 'RunGuid already owns guest artifacts'
    }
    Assert-Owned $fixtureRoot ('SafeUpload-corpus-fixtures-'+$RunGuid)
    Assert-Owned $evidenceRoot ('SafeUpload-corpus-evidence-'+$RunGuid)
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SafeUploadExclusiveDirectory {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="CreateDirectoryW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool Create(string path, IntPtr securityAttributes);
}
'@ -ErrorAction Stop
    if(-not [SafeUploadExclusiveDirectory]::Create($fixtureRoot,[IntPtr]::Zero)){
        throw ('Exclusive fixture creation failed; Win32='+[Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    $fixtureCreated=$true
    if(-not [SafeUploadExclusiveDirectory]::Create($evidenceRoot,[IntPtr]::Zero)){
        throw ('Exclusive evidence creation failed; Win32='+[Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    $evidenceCreated=$true
    Assert-Owned $fixtureRoot ('SafeUpload-corpus-fixtures-'+$RunGuid)
    Assert-Owned $evidenceRoot ('SafeUpload-corpus-evidence-'+$RunGuid)
    $childCorpus=Join-Path $fixtureRoot 'Test-StagedInvariantObserverCorpus.ps1'
    $childObserver=Join-Path $fixtureRoot 'StagedInvariantObserver.psm1'
    [IO.File]::Copy($corpusInput,$childCorpus)
    [IO.File]::Copy($observerInput,$childObserver)
    Assert-FileHash $childCorpus $CorpusSha256
    Assert-FileHash $childObserver $ObserverSha256
    $stdout=Join-Path $evidenceRoot 'child-stdout.txt'
    $stderr=Join-Path $evidenceRoot 'child-stderr.txt'
    $args='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$childCorpus+'" -FixtureRoot "'+$fixtureRoot+'" -EvidenceRoot "'+$evidenceRoot+'" -ExpectedObserverSha256 '+$ObserverSha256+' -RunGuid '+$RunGuid
    $process=Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $args -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    try {
        $handle=$process.Handle # PowerShell 5.1 requires caching before inspecting ExitCode.
        if($handle -eq [IntPtr]::Zero){throw 'Corpus child handle unavailable'}
        if(-not $process.WaitForExit(3600000)){
            $timedOut=$true
            $childForcedKill=$true
            try{$process.Kill()}catch{}
            [void]$process.WaitForExit(30000)
        }
        if(-not $process.HasExited){throw 'Corpus child did not exit after finite kill wait'}
        $exitValue=$process.ExitCode
        if($null -eq $exitValue){throw 'Corpus child ExitCode is null'}
        $childExit=[int]$exitValue
    } finally {
        if($null -ne $process){
            $stopped=$false
            try {
                if(-not $process.HasExited){$childForcedKill=$true;$process.Kill();[void]$process.WaitForExit(30000)}
                $stopped=$process.HasExited
            } catch {$stopped=$false}
            if($stopped){$process.Dispose();$process=$null}
            else{throw 'Corpus child remains live after kill; refuse cleanup'}
        }
    }
    if($timedOut -or $childForcedKill){throw 'Corpus child timed out or required forced termination; recovery required'}
    $summaryPath=Join-Path (Join-Path $evidenceRoot ('observer-corpus-'+$RunGuid)) 'summary.json'
    if([IO.File]::Exists($summaryPath)){
        $summary=Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        if($summary.RunGuid -cne $RunGuid){throw 'Corpus summary RunGuid mismatch'}
        if($childExit -eq 0 -and -not $timedOut){$coordinatorStatus='PASS'}
        elseif($childExit -eq 1){$coordinatorStatus='FAIL'}
    }
    Assert-Owned $evidenceRoot ('SafeUpload-corpus-evidence-'+$RunGuid)
    Write-NewJson (Join-Path $evidenceRoot 'completion.json') ([pscustomobject]@{
        Schema='ObserverCorpusCompletion/1';RunGuid=$RunGuid;ChildExit=$childExit;TimedOut=$timedOut;
        Status=$coordinatorStatus;SummaryPresent=[IO.File]::Exists($summaryPath);
        CoordinatorSha256=$CoordinatorSha256.ToUpperInvariant();CorpusSha256=$CorpusSha256.ToUpperInvariant();
        ObserverSha256=$ObserverSha256.ToUpperInvariant();Utc=[DateTime]::UtcNow.ToString('o')})
    Assert-Owned $evidenceRoot ('SafeUpload-corpus-evidence-'+$RunGuid)
    Assert-Owned $archive ('SafeUpload-corpus-'+$RunGuid+'.zip')
    $archiveHash=New-VerifiedArchive $evidenceRoot $archive
    if(-not $fixtureCreated -or -not $evidenceCreated){throw 'Run-owned roots not created by coordinator'}
    foreach($root in @($fixtureRoot,$evidenceRoot)){
        $expectedLeaf=if($root -eq $fixtureRoot){'SafeUpload-corpus-fixtures-'+$RunGuid}else{'SafeUpload-corpus-evidence-'+$RunGuid}
        Assert-Owned $root $expectedLeaf
        [IO.Directory]::Delete($root,$true)
        if([IO.Directory]::Exists($root)){throw ('Owned root residue: '+$root)}
    }
    foreach($path in @($corpusInput,$observerInput,$PSCommandPath)){
        if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($path)).TrimEnd('\') -ine $docs.TrimEnd('\')){throw ('Staged input outside Documents: '+$path)}
        Assert-NoReparseTree $path
        [IO.File]::Delete($path)
    }
    $cleanup='True'
    Write-Output ('OBSERVER_CORPUS_COMPLETE='+$RunGuid+';ChildExit='+$childExit+';ArchiveSha256='+$archiveHash+';ArchiveName='+[IO.Path]::GetFileName($archive)+';Cleanup='+$cleanup+';Status='+$coordinatorStatus)
} catch {
    $originalError=$_.Exception
    $childStopped=$true
    if($null -ne $process){
        try {
            if(-not $process.HasExited){$childForcedKill=$true;$process.Kill();[void]$process.WaitForExit(30000)}
            $childStopped=$process.HasExited
        } catch {$childStopped=$false}
        if($childStopped){$process.Dispose();$process=$null}
    }
    $recoveryRequired=$timedOut -or $childForcedKill -or -not $childStopped
    if($childStopped -and -not $recoveryRequired -and $evidenceCreated -and -not $archiveHash -and
       [IO.Directory]::Exists($evidenceRoot) -and -not [IO.File]::Exists($archive)){
        try {
            Assert-Owned $evidenceRoot ('SafeUpload-corpus-evidence-'+$RunGuid)
            Assert-Owned $archive ('SafeUpload-corpus-'+$RunGuid+'.zip')
            Write-NewJson (Join-Path $evidenceRoot 'coordinator-error.json') ([pscustomobject]@{
                Schema='ObserverCorpusCoordinatorError/1';RunGuid=$RunGuid;
                Type=$originalError.GetType().FullName;Message=$originalError.ToString();
                ChildExit=$childExit;TimedOut=$timedOut;Utc=[DateTime]::UtcNow.ToString('o')})
            $archiveHash=New-VerifiedArchive $evidenceRoot $archive
        } catch {
            Write-Output ('OBSERVER_CORPUS_ARCHIVE_ERROR='+($_.Exception.Message -replace '[\r\n;]',' '))
        }
    }
    if($recoveryRequired){Write-Output 'OBSERVER_CORPUS_RECOVERY_REQUIRED=True;FixtureRetained=True;EvidenceRetained=True'}
    if(-not $childStopped){Write-Output 'OBSERVER_CORPUS_CHILD_LIVE=True;RecoveryRequired=True'}
    Write-Output ('OBSERVER_CORPUS_ERROR='+$RunGuid+';Type='+$originalError.GetType().FullName+';Message='+($originalError.Message -replace '[\r\n;]',' '))
    if($archiveHash){Write-Output ('OBSERVER_CORPUS_ARCHIVE='+[IO.Path]::GetFileName($archive)+';Sha256='+$archiveHash+';Cleanup='+$cleanup)}
    throw $originalError
}
