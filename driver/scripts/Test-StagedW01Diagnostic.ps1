<#
Source-only RV4-W01 diagnostic child of a checkpointed SYSTEM controller.
The parent provisions the two GUID-owned roots and old target before expanding
policy, starts this child before activation, retains/restores driver and policy,
and independently verifies final baseline. This child always reports INCONCLUSIVE;
its receipts must be judged with the host upper-ledger parser and raw observer.
Never run directly as a Phase 4 qualification or against an uncheckpointed VM.
#>
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunGuid,
    [Parameter(Mandatory=$true)][string]$FixtureRoot,
    [Parameter(Mandatory=$true)][string]$ControlParent,
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$ExpectedBytesFile,
    [Parameter(Mandatory=$true)][string]$ExpectedBytesSha256,
    [Parameter(Mandatory=$true)][string]$VolumeGuid,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{16}$')][string]$VolumeSerialHex,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$FileIdHex,
    [Parameter(Mandatory=$true)][ValidateRange(0,9223372036854771711)][long]$Offset,
    [Parameter(Mandatory=$true)][string]$StimulusExe,
    [Parameter(Mandatory=$true)][string]$ClientSource,
    [Parameter(Mandatory=$true)][string]$InspectorExe,
    [Parameter(Mandatory=$true)][string]$ObserverModule,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [Parameter(Mandatory=$true)][string]$ExpectedStimulusSha256,
    [Parameter(Mandatory=$true)][string]$ExpectedClientSha256,
    [Parameter(Mandatory=$true)][string]$ExpectedInspectorSha256,
    [Parameter(Mandatory=$true)][string]$ExpectedObserverSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{32}$')][string]$ProtectedControlFileIdHex
)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$runGuid=$RunGuid.ToLowerInvariant();$fileId=$FileIdHex.ToUpperInvariant();$serial=$VolumeSerialHex.ToUpperInvariant()
$serialBytes=New-Object byte[] 8
for($i=0;$i -lt 8;$i++){$serialBytes[$i]=[Convert]::ToByte($serial.Substring($i*2,2),16)}
$serialStatus='0x'+([BitConverter]::ToUInt64($serialBytes,0)).ToString('X16')
$runDirectory=Join-Path $ControlParent ('SafeUpload-rv4-w01-'+$runGuid)
$observed=[ordered]@{Schema='Rv4W01Diagnostic/1';RunGuid=$runGuid;Verdict='INCONCLUSIVE';NotVmQualification=$true;Events=@();Errors=@();RecoveryRequired=$false}
$client=$null;$context=$null;$process=$null;$armGeneration=$null;$held=$false;$issued=$false;$released=$false;$postComplete=$false
function Save-Bytes([string]$Path,[byte[]]$Bytes){
    $s=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
    try{$s.Write($Bytes,0,$Bytes.Length);$s.Flush($true)}finally{$s.Dispose()}
}
function Save-Text([string]$Path,[string]$Value){Save-Bytes $Path ([Text.UTF8Encoding]::new($false).GetBytes($Value))}
function Request([string]$Name){
    $temporary=Join-Path $runDirectory ('.'+$Name+'-'+[guid]::NewGuid().ToString('N')+'.tmp')
    Save-Text $temporary ($runGuid+"`n")
    [IO.File]::Move($temporary,(Join-Path $runDirectory ($Name+'.request')))
}
function Wait-Receipt([string]$Name,[int]$Seconds){
    $path=Join-Path $runDirectory ($Name+'.receipt');$deadline=[DateTime]::UtcNow.AddSeconds($Seconds)
    $reason='Not published'
    do {if(Test-Path -LiteralPath $path){
        try{
            $s=$null;$reader=$null
            $s=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
            try{$reader=[IO.StreamReader]::new($s,[Text.UTF8Encoding]::new($false),$true);$text=$reader.ReadToEnd()}
            finally{if($null -ne $reader){$reader.Dispose()}elseif($null -ne $s){$s.Dispose()}}
            $pairs=@{};foreach($line in ($text -split "`n")){
                if(-not $line.Trim()){continue};$clean=$line.TrimEnd("`r");$separator=$clean.IndexOf('=')
                if($separator -lt 1){throw 'Malformed receipt key'}
                $key=$clean.Substring(0,$separator)
                if($pairs.ContainsKey($key)){throw 'Duplicate receipt key'}
                $pairs[$key]=$clean.Substring($separator+1)
            }
            if($pairs.Schema -cne 'Rv4W01StimulusDraft/1' -or $pairs.RunGuid -cne $runGuid){throw 'Foreign/incomplete receipt'}
            return $pairs
        }catch{$reason=$_.Exception.Message} # CreateNew exposes a name before Flush/close.
    };Start-Sleep -Milliseconds 50}while([DateTime]::UtcNow -lt $deadline)
    throw ('Receipt unavailable/incomplete: '+$Name+'; '+$reason)
}
function Inspect([string]$Command,[string]$Artifact=''){
    $raw=[SafeUploadSectionFaultClient]::Inspector($InspectorExe,$Command)
    if($Artifact){Save-Text (Join-Path $EvidenceDirectory $Artifact) $raw}
    return $raw
}
function EntryById([string]$Id,[switch]$AllowMissing,[string]$Artifact=''){
    $snapshot=(Inspect '--activating-status' $Artifact)|ConvertFrom-Json
    if($snapshot.activatingStatus -ne $true){throw 'No activating-status snapshot'}
    $entries=@($snapshot.entries|Where-Object {$_.fileId -ceq $Id})
    if($AllowMissing -and $entries.Count -eq 0){return $null}
    if($entries.Count -ne 1){throw 'Missing/ambiguous exact file ID entry'}
    return $entries[0]
}
function Assert-Pins {
    $pins=@(
        @{Path=$StimulusExe;Hash=$ExpectedStimulusSha256},
        @{Path=$ClientSource;Hash=$ExpectedClientSha256},
        @{Path=$InspectorExe;Hash=$ExpectedInspectorSha256},
        @{Path=$ObserverModule;Hash=$ExpectedObserverSha256}
    )
    foreach($pin in $pins){
        if((Get-FileHash -LiteralPath $pin.Path -Algorithm SHA256).Hash -cne $pin.Hash.ToUpperInvariant()){throw 'Input hash mismatch'}
    }
    if($Offset % 4096 -ne 0){throw 'Unaligned requested offset'}
    if($fileId -ceq $ProtectedControlFileIdHex.ToUpperInvariant()){throw 'Protected control aliases target'}
    if(-not(Test-Path -LiteralPath $EvidenceDirectory -PathType Container) -or
        -not(Test-Path -LiteralPath $FixtureRoot -PathType Container) -or
        -not(Test-Path -LiteralPath $ControlParent -PathType Container) -or
        -not(Test-Path -LiteralPath $Target -PathType Leaf)){throw 'Trusted controller must preprovision distinct evidence/fixture roots and target'}
    if([IO.Path]::GetFileName($FixtureRoot.TrimEnd('\')) -cne ('SafeUpload-rv4-w01-files-'+$runGuid) -or
        [IO.Path]::GetFileName($ControlParent.TrimEnd('\')) -cne ('SafeUpload-rv4-w01-control-'+$runGuid) -or
        [IO.Path]::GetFileName($Target) -cne ('rv4-w01-target-'+$runGuid+'.bin')){throw 'GUID-owned path contract mismatch'}
    if([IO.Path]::GetFullPath($Target) -ine
        [IO.Path]::GetFullPath((Join-Path $FixtureRoot ('rv4-w01-target-'+$runGuid+'.bin')))){
        throw 'Target is not the exact GUID-owned fixture child'
    }
    foreach($path in @($FixtureRoot,$ControlParent,$EvidenceDirectory,$Target,$ExpectedBytesFile)){
        if(((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse input'}
    }
    if((Get-FileHash -LiteralPath $ExpectedBytesFile -Algorithm SHA256).Hash -cne $ExpectedBytesSha256.ToUpperInvariant()){throw 'Independent expected image hash mismatch'}
    if(Test-Path -LiteralPath $runDirectory){throw 'Run directory collision'}
    if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18'){throw 'SYSTEM controller required'}
}
try{
    Assert-Pins
    Add-Type -Path $ClientSource
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class Rv4W01Duplicate {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(IntPtr source,IntPtr handle,IntPtr target,out SafeFileHandle copy,uint access,bool inherit,uint options);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 public static SafeFileHandle Copy(uint pid,long handle) {
   IntPtr process=OpenProcess(0x40,false,pid);
   if(process==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
   try { SafeFileHandle copy; if(!DuplicateHandle(process,new IntPtr(handle),GetCurrentProcess(),out copy,0,false,2))
       throw new Win32Exception(Marshal.GetLastWin32Error()); return copy; }
   finally {CloseHandle(process);}
 }
}
'@
    Import-Module $ObserverModule -Force
    $pin=[SafeUploadSectionFaultClient]::OpenAttributes($Target)
    try{
        $identity=[SafeUploadSectionFaultClient]::Identity($pin)
        if($identity -cne ($serial+$fileId)){throw 'Independent target FILE_ID_INFO mismatch'}
        $volume=[SafeUploadSectionFaultClient]::VolumeForHandle($pin)
        $inventory=@([SafeUploadSectionFaultClient]::Inventory($volume))
        $upper=@($inventory|Where-Object Filter -ceq 'SafeUpload');$lower=@($inventory|Where-Object Filter -ceq 'SafeUploadSectionFault')
        if($upper.Count -ne 1 -or $lower.Count -ne 1 -or $upper[0].Altitude -cne '321410' -or
            $lower[0].Altitude -cne '321409' -or $upper[0].Volume -cne $volume -or $lower[0].Volume -cne $volume){throw 'Actual same-volume upper/lower attachment not proven'}
        $observed.Inventory=$inventory
    }finally{$pin.Dispose()}
    $expected=[IO.File]::ReadAllBytes($ExpectedBytesFile)
    if($expected.Length -lt 4096 -or $Offset -gt ($expected.Length-4096)){throw 'Expected image/range invalid'}
    $context=Open-InvariantObserver $VolumeGuid $FixtureRoot (Join-Path $EvidenceDirectory 'raw') 'RV4-W01-diagnostic'
    if($context.Status -cne 'OK'){throw 'Raw observer open failed'}
    $name=[IO.Path]::GetFileName($Target);$images=@{};$images[$name]=$expected
    $baseline=Capture-InvariantBaseline $context @($name) $images
    Save-Text (Join-Path $EvidenceDirectory 'raw-baseline-decoded.json') ($baseline|ConvertTo-Json -Depth 32)
    if($baseline.Status -cne 'OK'){throw 'Independent raw baseline failed'}
    $baseImage=@($baseline.Images|Where-Object { $_.Path -ceq $Target -and $_.Role -ceq 'Current' })
    if($baseImage.Count -ne 1 -or $baseImage[0].Identity.FileId -cne $fileId -or
        [uint64]$baseImage[0].Identity.VolumeSerial -ne [BitConverter]::ToUInt64($serialBytes,0)){
        throw 'Raw baseline volume/file identity mismatch'
    }
    $observed.Events+=@{Name='baseline';Sha256=$baseImage[0].Sha256}
    $controlBefore=EntryById $ProtectedControlFileIdHex.ToUpperInvariant() -Artifact 'control-before-activating-status.json'
    if($controlBefore.state -cne 'Protected' -or $controlBefore.volumeSerial -cne $serialStatus -or
        $controlBefore.unknownReasons -cne '0x00000000' -or $controlBefore.H -ne 0 -or
        $controlBefore.W -ne 0){throw 'Protected control prestate/identity/H/W mismatch'}
    $controlBeforeJson=$controlBefore|ConvertTo-Json -Depth 16 -Compress
    Save-Text (Join-Path $EvidenceDirectory 'control-before-entry.json') $controlBeforeJson
    $stdout=Join-Path $EvidenceDirectory 'stimulus-stdout.txt';$stderr=Join-Path $EvidenceDirectory 'stimulus-stderr.txt'
    $args=@($FixtureRoot,$ControlParent,$runGuid,[string]$Offset,'120000',$serial,$fileId)
    if(@($args|Where-Object {$_ -match '["\r\n]'}).Count){throw 'Invalid stimulus argument'}
    $quoted=(@($args|ForEach-Object {'"'+$_+'"'}) -join ' ')
    $process=Start-Process -FilePath $StimulusExe -ArgumentList $quoted -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null=$process.Handle # Windows PowerShell 5.1 needs the handle cached before reliable ExitCode readback.
    $opened=Wait-Receipt 'opened' 10
    if($opened.ProcessId -ne [string]$process.Id -or $opened.FileId128Hex -cne $fileId -or
        $opened.VolumeSerialHex -cne $serial -or [long]$opened.Offset -ne $Offset -or
        [int]$opened.Length -ne 4096 -or [int]$opened.Alignment -gt 4096){throw 'Opened receipt identity/geometry mismatch'}
    $duplicate=[Rv4W01Duplicate]::Copy([uint32]$process.Id,[Convert]::ToInt64($opened.WriterHandleHex,16))
    try{
        if([SafeUploadSectionFaultClient]::Identity($duplicate) -cne ($serial+$fileId)){throw 'Duplicated handle identity mismatch'}
        $client=[SafeUploadSectionFaultClient]::new()
        $arm=$client.ArmNoncachedWrite($duplicate)
        $armGeneration=$arm.ArmGeneration
        if($arm.ArmedFileObject -eq 0 -or $armGeneration -eq 0 -or $arm.CurrentHeld -ne 0){throw 'Lower exact-FO arm failed'}
        $observed.Events+=@{Name='armed';Generation=[string]$armGeneration;FileObject=[string]$arm.ArmedFileObject}
    }finally{$duplicate.Dispose()} # Last controller writer duplicate closes BEFORE write.request and cleanup.
    $deadline=[DateTime]::UtcNow.AddSeconds(75)
    do{
        $entry=EntryById $fileId -AllowMissing
        if($null -ne $entry -and ($entry.volumeSerial -cne $serialStatus -or $entry.unknownReasons -cne '0x00000000')){throw 'Target volume/unknown mismatch'}
        if([DateTime]::UtcNow -gt $deadline){throw 'Activation barrier unavailable'}
        if($null -ne $entry -and $entry.state -ceq 'Activating'){break}
        if($null -ne $entry -and $entry.state -notin @('Unscoped','Activating')){throw 'Target entered wrong registry state'}
        Start-Sleep -Milliseconds 50
    }while($true)
    $control=EntryById $ProtectedControlFileIdHex.ToUpperInvariant() -Artifact 'control-at-activating-status.json'
    if(($control|ConvertTo-Json -Depth 16 -Compress) -cne $controlBeforeJson){throw 'Protected control changed at activation'}
    $observed.Events+=@{Name='activating';H=$entry.H;W=$entry.W;Generation=$entry.generation}
    [void](Inspect '--admission-volume-status' 'prewrite-volume-status.json')
    [void](Inspect ('--admission-probe "'+$Target+'"') 'prewrite-target-probe.json')
    $before=Capture-InvariantSample $context $baseline 'BeforeWrite' 1
    Save-Text (Join-Path $EvidenceDirectory 'raw-before-decoded.json') ($before|ConvertTo-Json -Depth 32)
    if($before.Status -cne 'OK'){throw 'Pre-write raw capture failed'}
    # The exact writer is still blocked on write.request here. No target W is
    # allowed across enable/CLEAR; the host rejects any foreign W in the dump.
    [void](Inspect '--admission-trace-enable-lifetime')
    [void](Inspect '--admission-trace-clear' 'trace-clear.txt')
    Request 'write';$issuedReceipt=Wait-Receipt 'issued' 5;$issued=$true
    if($issuedReceipt.WriteCall -cne 'PENDING' -or [int]$issuedReceipt.WriteCallError -ne 997 -or
        [long]$issuedReceipt.Offset -ne $Offset -or [int]$issuedReceipt.Length -ne 4096){throw 'No native pending noncached write'}
    $observed.Events+=@{Name='issued';PayloadSha256=$issuedReceipt.PayloadSha256}
    $holdDeadline=[DateTime]::UtcNow.AddSeconds(5)
    do{
        $status=$client.ReadWriteStatus()
        if($status.TimedOut -ne 0 -or $status.Canceled -ne 0 -or $status.SyntheticFailures -ne 0){throw 'Lower watchdog/cancel/synthetic path'}
        if($status.CurrentHeld -eq 1 -and $status.Held -eq 1 -and $status.ArmGeneration -eq $armGeneration){$held=$true;break}
        if([DateTime]::UtcNow -gt $holdDeadline){throw 'Matching lower hold unavailable'}
        Start-Sleep -Milliseconds 25
    }while($true)
    if($status.ArmedFileObject -ne $arm.ArmedFileObject -or
        $status.WriteOffset -ne [uint64]$Offset -or $status.WriteLength -ne 4096 -or
        ($status.IrpFlags -band 1) -eq 0 -or ($status.IrpFlags -band 2) -ne 0){throw 'Lower noncached/nonpaging exact range unavailable'}
    $holdStarted=[DateTime]::UtcNow
    # Fault.c publishes LowerCallbackData only in the actual post callback.
    # The held proof is arm generation, exact FO, range, and native IRP flags.
    $observed.Events+=@{Name='held';Generation=[string]$status.ArmGeneration;FileObject=[string]$status.ArmedFileObject;Offset=[string]$status.WriteOffset;Length=$status.WriteLength;IrpFlags=$status.IrpFlags}
    Request 'close';[void](Wait-Receipt 'close-entered' 5)
    $cleanupDeadline=[DateTime]::UtcNow.AddSeconds(5)
    do{
        $entry=EntryById $fileId;$status=$client.ReadWriteStatus()
        if($status.TimedOut -ne 0 -or $status.CurrentHeld -ne 1){throw 'Lower hold lost before cleanup proof'}
        if($entry.state -ceq 'Activating' -and $entry.H -eq 0 -and $entry.W -gt 0){break}
        if([DateTime]::UtcNow -gt $cleanupDeadline){throw 'H=0/W>0 cleanup overlap unavailable'}
        Start-Sleep -Milliseconds 25
    }while($true)
    $observed.Events+=@{Name='cleanup-overlap';H=$entry.H;W=$entry.W;Generation=$entry.generation}
    $heldSample=Capture-InvariantSample $context $baseline 'HeldBeforeLowerRelease' 2
    Save-Text (Join-Path $EvidenceDirectory 'raw-held-decoded.json') ($heldSample|ConvertTo-Json -Depth 32)
    if($heldSample.Status -cne 'OK'){throw 'Held raw capture failed'}
    $heldImage=@($heldSample.Images|Where-Object { $_.Path -ceq $Target -and $_.Role -ceq 'Current' })
    if($heldImage.Count -ne 1 -or $heldImage[0].Sha256 -cne $baseImage[0].Sha256){throw 'Held raw target changed before lower release'}
    $entry=EntryById $fileId;$status=$client.ReadWriteStatus()
    if($entry.state -cne 'Activating' -or $entry.H -ne 0 -or $entry.W -le 0 -or $status.CurrentHeld -ne 1 -or $status.TimedOut -ne 0){throw 'Cleanup/hold not retained through raw capture'}
    [void](Inspect '--admission-trace' 'held-upper-trace.jsonl') # Host must match file_cleanup and W_BEGIN exactly.
    if([DateTime]::UtcNow -ge $holdStarted.AddSeconds(20)){throw 'Held diagnostic exceeded 20s release budget'}
    $release=$client.ReleaseHeldWrite();$released=$true
    if($release.TimedOut -ne 0){throw 'Lower watchdog won release race'}
    $observed.Events+=@{Name='release';Generation=[string]$release.ArmGeneration}
    $postDeadline=[DateTime]::UtcNow.AddSeconds(8)
    do{
        $post=$client.ReadWriteStatus()
        if($post.TimedOut -ne 0 -or $post.Canceled -ne 0 -or $post.SyntheticFailures -ne 0){throw 'Not a genuine lower completion'}
        if($post.LowerPosts -eq 1 -and $post.CurrentHeld -eq 0){break}
        if([DateTime]::UtcNow -gt $postDeadline){throw 'Genuine lower post unavailable'}
        Start-Sleep -Milliseconds 25
    }while($true)
    # fltKernel.h defines FLTFL_POST_OPERATION_DRAINING as 0x00000001.
    if($post.LowerStatus -ne 0 -or $post.LowerInformation -ne 4096 -or
        $post.LowerCallbackData -eq 0 -or $post.ArmGeneration -ne $armGeneration -or
        ($post.PostFlags -band 1) -ne 0){throw 'Lower post status/bytes/identity/draining mismatch'}
    $postComplete=$true
    $observed.Events+=@{Name='lower-post';Status=$post.LowerStatus;Information=[string]$post.LowerInformation;PostFlags=$post.PostFlags;CallbackData=[string]$post.LowerCallbackData}
    $completed=Wait-Receipt 'completed' 8;[void](Wait-Receipt 'closed' 8)
    if($completed.CompletionSource -cne 'IOCP' -or $completed.Success -cne 'True' -or
        [int]$completed.NativeError -ne 0 -or [int]$completed.Bytes -ne 4096 -or
        $completed.DeadlineExceeded -cne 'False'){throw 'Matching IOCP outcome not full success'}
    if(-not $process.WaitForExit(8000) -or $process.ExitCode -ne 0 -or
        (Test-Path -LiteralPath (Join-Path $runDirectory 'recovery-required.receipt'))){throw 'Stimulus outcome not safely complete'}
    $after=Capture-InvariantSample $context $baseline 'AfterLowerCompletion' 3
    Save-Text (Join-Path $EvidenceDirectory 'raw-after-decoded.json') ($after|ConvertTo-Json -Depth 32)
    if($after.Status -cne 'OK'){throw 'Post-lower raw capture failed'}
    $afterImage=@($after.Images|Where-Object { $_.Path -ceq $Target -and $_.Role -ceq 'Current' })
    if($afterImage.Count -ne 1 -or -not $afterImage[0].LogicalArtifact){throw 'Post-lower exact raw target unavailable'}
    $rawPath=Join-Path (Join-Path $EvidenceDirectory 'raw') ([IO.Path]::GetFileName($afterImage[0].LogicalArtifact.Path))
    $rawBytes=[IO.File]::ReadAllBytes($rawPath)
    if($rawBytes.Length -lt $Offset+4096){throw 'Post-lower raw range truncated'}
    $range=New-Object byte[] 4096;[Array]::Copy($rawBytes,[int]$Offset,$range,0,4096)
    $rangeSha=[BitConverter]::ToString(([Security.Cryptography.SHA256]::Create().ComputeHash($range))).Replace('-','')
    if($rangeSha -cne $issuedReceipt.PayloadSha256){throw 'Post-lower raw range does not match issued payload'}
    $observed.Events+=@{Name='after-raw';Status=$after.Status;Completion=$completed}
    [void](Inspect '--admission-trace' 'upper-trace.jsonl')
    $controlAfter=EntryById $ProtectedControlFileIdHex.ToUpperInvariant() -Artifact 'control-after-activating-status.json'
    $controlAfterJson=$controlAfter|ConvertTo-Json -Depth 16 -Compress
    Save-Text (Join-Path $EvidenceDirectory 'control-after-entry.json') $controlAfterJson
    if($controlAfterJson -cne $controlBeforeJson){throw 'Protected control changed after lower completion'}
    $observed.Events+=@{Name='capture-complete';Note='Host must run exact W parser and cross-check lower, IOCP, raw, control and restoration; no local PASS'}
}catch{
    $observed.Errors+=@{Type=$_.Exception.GetType().FullName;Message=$_.Exception.Message}
    if($issued -and $process -and -not $process.HasExited){$observed.RecoveryRequired=$true}
}finally{
    if($held -and -not $released -and $null -ne $client){
        try{$release=$client.ReleaseHeldWrite();$observed.Events+=@{Name='emergency-lower-release';TimedOut=[string]$release.TimedOut}}
        catch{$observed.Errors+=@{Type='EmergencyRelease';Message=$_.Exception.Message};$observed.RecoveryRequired=$true}
    }
    if($null -ne $client){
        # Closing this port runs FaultDisconnect -> FaultWriteDisarmLocked,
        # whose callback rundown wait is unbounded. Keep this controller, port,
        # writer, and native writer storage alive in repeated finite waits until
        # completion/cancel has actually quiesced. Never kill the writer.
        $needsRecovery=($null -ne $process -and -not $process.HasExited) -or ($issued -and -not $postComplete)
        if($needsRecovery){
            $observed.RecoveryRequired=$true
            try{Save-Text (Join-Path $EvidenceDirectory 'recovery-required.json')
                ($observed|ConvertTo-Json -Depth 16)}catch{}
            do {
                $settled=$false
                try {
                    $state=$client.ReadWriteStatus()
                    $lowerDone=$state.CurrentHeld -eq 0 -and
                        ($state.LowerPosts -gt 0 -or $state.Canceled -gt 0 -or
                         $state.SyntheticFailures -gt 0 -or -not $issued)
                    $writerDone=$null -eq $process -or $process.HasExited
                    $settled=$lowerDone -and $writerDone
                }catch{}
                if(-not $settled){Start-Sleep -Seconds 1}
            }while(-not $settled)
        }
        $disarmed=$false
        try{$client.DisarmWrite()|Out-Null;$disarmed=$true}
        catch{$observed.Errors+=@{Type='Disarm';Message=$_.Exception.Message};$observed.RecoveryRequired=$true}
        if($disarmed){$client.Dispose()}
        else {
            try{Save-Text (Join-Path $EvidenceDirectory 'disarm-recovery-required.json')
                ($observed|ConvertTo-Json -Depth 16)}catch{}
            while($true){Start-Sleep -Seconds 1} # Do not implicitly disconnect on process exit.
        }
    }
    if($null -ne $context){$observed.ObserverDisposal=Close-InvariantObserver $context}
    if($process){
        $observed.WriterPid=$process.Id;$observed.WriterExited=$process.HasExited
        if(-not $process.HasExited){$observed.RecoveryRequired=$true}
        $process.Dispose() # Disposal is not termination. Retain pending writer and all receipts for external recovery.
    }
    $observed.Qualification='W01/W02/Phase4 NOT_QUALIFIED; independent host and restoration required'
    Save-Text (Join-Path $EvidenceDirectory 'rv4-w01-diagnostic.json') ($observed|ConvertTo-Json -Depth 16)
}
