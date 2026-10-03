<# SYSTEM-side qualification exercise; launched by the checkpointed admission harness. #>
param([Parameter(Mandatory)][string]$Fixture,
    [Parameter(Mandatory)][string]$Inspector,
    [Parameter(Mandatory)][string]$ClientSource,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][string]$TracePrefix,
    [Parameter(Mandatory)][string]$ExpectedInspectorSha256,
    [Parameter(Mandatory)][string]$ExpectedClientSha256,
    [switch]$Capacity,
    [switch]$SectionTeardown,
    [switch]$EmergencyRelease,
    [switch]$Verifier,
    [string]$VhdxPath,
    [string]$DiskpartPath)
$ErrorActionPreference='Stop'
$result=[ordered]@{ Passed=$false; Mode=$(if ($SectionTeardown) { 'nested same-FO pairing plus mandatory dismount with acquire held' } else { 'live lower-stack resource-failure injection and bounded hold' }); Errors=@(); Checks=@(); Probes=@(); PassedChecks=0; FailedChecks=0 }
$client=$null; $file=$null; $mapping=$null; $traces=@{}; $exerciseError=$null; $capacityMappings=@()
function Assert-LowerAttachment([Microsoft.Win32.SafeHandles.SafeFileHandle]$FileHandle=$file.SafeFileHandle) {
    $volume=[SafeUploadSectionFaultClient]::VolumeForHandle($FileHandle)
    $inventory=@([SafeUploadSectionFaultClient]::Inventory($volume))
    $upper=@($inventory|Where-Object Filter -eq 'SafeUpload')
    $lower=@($inventory|Where-Object Filter -eq 'SafeUploadSectionFault')
    if ($upper.Count -ne 1 -or $lower.Count -ne 1 -or $upper[0].Altitude -ne '321410' -or
        $lower[0].Altitude -ne '321409' -or $upper[0].Volume -ne $volume -or $lower[0].Volume -ne $volume) {
        throw 'Actual same-volume lower-stack ordering is not qualified.'
    }
    $result['Attachments_'+$result.Count]=$inventory
    $result.TargetVolume=$volume
}
function Read-UpperStats {
    $raw=[SafeUploadSectionFaultClient]::Inspector($Inspector,'--writer-state-status')
    $state=$raw|ConvertFrom-Json
    foreach($field in @('writerState','sectionInFlightNow','sectionInFlightInserted','sectionInFlightReleased',
        'sectionInFlightRemovedOnFailure','sectionInFlightOverflow','sectionInFlightStuck',
        'writersDroppedAtTeardown','writersDroppedWhileMounted')) {
        if ($state.PSObject.Properties.Name -notcontains $field) { throw ('Missing upper status: '+$field) }
    }
    return $state
}
function Get-UpperStats([switch]$AllowIntentionalHold) {
    $state=Read-UpperStats
    # Only the exact held callback may age beyond the production two-second threshold.
    # The caller brackets this snapshot with same-FO/generation CurrentHeld=1 proof.
    $heldSnapshot = $AllowIntentionalHold -and $state.sectionInFlightNow -eq 1 -and
        $state.sectionInFlightStuck -ge 0 -and $state.sectionInFlightStuck -le 1
    if ($state.writerState -ne $true -or $state.sectionInFlightOverflow -ne 0 -or
        ($state.sectionInFlightStuck -ne 0 -and -not $heldSnapshot)) {
        throw 'Upper section tracking is unknown or stuck.'
    }
    return $state
}
function Get-UpperTrace([string]$Name,[UInt64]$FileObject) {
    $raw=[SafeUploadSectionFaultClient]::Inspector($Inspector,'--admission-trace')
    $traces[$Name]=$raw
    $rows=@($raw -split '[\r\n]+' | Where-Object { $_.Trim().Length -gt 0 } | ForEach-Object { $_|ConvertFrom-Json })
    $summary=@($rows|Where-Object { $_.summary -eq $true })
    if ($summary.Count -ne 1) { throw 'Missing or ambiguous upper trace summary.' }
    foreach($field in @('summary','lostEntries','cursor','snapshotSequence','sectionAcquires','sectionReleases')) {
        if ($summary[0].PSObject.Properties.Name -notcontains $field) { throw ('Missing trace summary field: '+$field) }
    }
    if ($summary[0].lostEntries -ne 0 -or $summary[0].cursor -ne ([UInt64]$summary[0].snapshotSequence + 1)) {
        throw 'Incomplete upper trace.'
    }
    $identity='0x'+$FileObject.ToString('X16')
    return @($rows|Where-Object { $_.targetFileObject -eq $identity })
}
function Reset-UpperTrace {
    [void][SafeUploadSectionFaultClient]::Inspector($Inspector,'--admission-trace-enable-sections')
    [void][SafeUploadSectionFaultClient]::Inspector($Inspector,'--admission-trace-clear')
}

function Add-STOutcome([string]$Name,[bool]$Ok,[string]$Facts) {
    $verdict=if($Ok){'PASS'}else{'FAIL'}
    $line='ST_'+$Name+'='+$Facts+';'+$verdict
    $result.Checks=@($result.Checks)+@($line)
    if($Ok){$result.PassedChecks=[int]$result.PassedChecks+1}else{$result.FailedChecks=[int]$result.FailedChecks+1}
    return $Ok
}

function Invoke-STInspector([string]$Command) {
    return [SafeUploadSectionFaultClient]::Inspector($Inspector,$Command)
}

function Get-STTraceRows([string]$Name) {
    $raw=Invoke-STInspector '--admission-trace'
    $traces[$Name]=$raw
    $rows=@($raw -split '[\r\n]+'|Where-Object { $_.Trim().Length -gt 0 }|ForEach-Object { $_|ConvertFrom-Json })
    $summary=@($rows|Where-Object { $_.summary -eq $true })
    if($summary.Count -ne 1 -or $summary[0].lostEntries -ne 0 -or
        $summary[0].cursor -ne ([UInt64]$summary[0].snapshotSequence+1)){throw ('Upper trace incomplete: '+$Name)}
    return $rows
}

function Get-STWriterStats {
    $state=Invoke-STInspector '--writer-state-status'|ConvertFrom-Json
    foreach($field in @('sectionInFlightNow','sectionInFlightInserted','sectionInFlightReleased',
        'sectionInFlightOverflow','sectionInFlightStuck','sectionInFlightRemovedOnFailure',
        'writersDroppedAtTeardown','writersDroppedWhileMounted')) {
        if($null -eq $state.$field){throw ('Writer status missing '+$field)}
    }
    return $state
}

function Get-STGlobalStatus {
    $status=Invoke-STInspector '--admission-volume-status'|ConvertFrom-Json
    if($null -eq $status.writerGlobalUnknown -or $null -eq $status.admissionVolumes){throw 'Admission volume status schema mismatch.'}
    return $status
}

function Invoke-STProbe([string]$Path,[string]$Label,[UInt64]$ExpectedC,[bool]$ExpectedUntracked=$false) {
    Reset-UpperTrace
    $ack=Invoke-STInspector ('--admission-probe "'+$Path+'"')|ConvertFrom-Json
    $rows=Get-STTraceRows ('probe-'+$Label)
    $probes=@($rows|Where-Object event -eq 'explicit_probe')
    $p=if($probes.Count -eq 1){$probes[0]}else{$null}
    $ok=$null -ne $p -and $ack.status -eq '0x00000000' -and $p.pid -eq 4 -and
        $p.irql -eq 0 -and $p.probeStatus -eq '0x00000000' -and $p.probeStage -eq 8 -and
        [UInt64]$p.inFlightSections -eq $ExpectedC -and [bool]$p.writersUntracked -eq $ExpectedUntracked
    $facts='pid:'+$(if($p){$p.pid}else{'n/a'})+';C:'+$(if($p){$p.inFlightSections}else{'n/a'})+
        ';writersUntracked:'+$(if($p){$p.writersUntracked}else{'n/a'})+';expectedC:'+$ExpectedC+
        ';expectedUntracked:'+$ExpectedUntracked+';probeStatus:'+$(if($p){$p.probeStatus}else{'missing'})+
        ';probeStage:'+$(if($p){$p.probeStage}else{'missing'})
    $result.Probes=@($result.Probes)+@([pscustomobject]@{Label=$Label;Entry=$p;Ack=$ack})
    [void](Add-STOutcome $Label $ok $facts)
    return $p
}

function Invoke-STNative([string]$Executable,[string]$Arguments,[int]$TimeoutSeconds) {
    $start=[Diagnostics.ProcessStartInfo]::new($Executable,$Arguments)
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $process=[Diagnostics.Process]::Start($start)
    $clock=[Diagnostics.Stopwatch]::StartNew()
    try {
        [void]$process.Handle
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if( -not $process.WaitForExit($TimeoutSeconds*1000)) {
            try{$process.Kill()}catch{}
            $killed=$process.WaitForExit(10000)
            $outText='';$errText=''
            if($stdout.Wait(5000)){$outText=$stdout.Result}
            if($stderr.Wait(5000)){$errText=$stderr.Result}
            $forcedExit=if($killed){$process.get_ExitCode()}else{$null}
            return [pscustomobject]@{ExitCode=$forcedExit;TimedOut=$true;Killed=$killed;ElapsedMs=$clock.ElapsedMilliseconds;Output=($outText+$errText)}
        }
        if( -not $stdout.Wait(5000) -or -not $stderr.Wait(5000)){throw 'Native command output drain timed out.'}
        return [pscustomobject]@{ExitCode=$process.get_ExitCode();TimedOut=$false;Killed=$true;ElapsedMs=$clock.ElapsedMilliseconds;Output=($stdout.Result+$stderr.Result)}
    } finally {
        if( -not $process.HasExited){try{$process.Kill();[void]$process.WaitForExit(10000)}catch{}}
        $process.Dispose();$clock.Stop()
    }
}

function ConvertTo-STArgument([string]$Value) {
    return '"'+$Value.Replace('"','\"')+'"'
}

function Read-STTargetInstance($Status,[string]$Guid) {
    $matches=@($Status.admissionVolumes|Where-Object {
        $null -ne $_.volumeGuidStatus -and $_.volumeGuidStatus -eq 0 -and
            -not [string]::IsNullOrWhiteSpace([string]$_.volumeGuid) -and
            ([string]$_.volumeGuid).ToLowerInvariant().Contains($Guid.ToLowerInvariant()) })
    if($matches.Count -gt 1){throw 'VHDX Filter Manager inventory is ambiguous.'}
    if($matches.Count -eq 0){return $null}
    foreach($field in @('contextStatus','fileSystemStatus','volumeInfoStatus','volumeGuidStatus','volumeFlags')){
        if($null -eq $matches[0].$field){throw ('VHDX Filter Manager inventory missing '+$field)}
    }
    if($matches[0].contextStatus -ne 0 -or $matches[0].fileSystemStatus -ne 0 -or $matches[0].volumeInfoStatus -ne 0 -or $matches[0].volumeGuidStatus -ne 0){
        throw 'VHDX Filter Manager inventory did not resolve completely.'
    }
    return $matches[0]
}

function Read-STTargetTrace([string]$Label,[UInt64]$FileObject) {
    $rows=Get-STTraceRows $Label
    $identity='0x'+$FileObject.ToString('X16')
    return @($rows|Where-Object { $_.targetFileObject -eq $identity })
}

function Format-STHandleWrite($Attempt) {
    return 'succeeded:'+$Attempt.Succeeded+';win32Error:'+$Attempt.Win32Error+
        ';win32ErrorHex:0x'+([int]$Attempt.Win32Error).ToString('X8')+';bytesWritten:'+$Attempt.BytesWritten
}

function Invoke-STOldViewWrite([long]$Offset,[byte]$Value) {
    $writeReturned=$false;$flushReturned=$false;$writeException='';$flushException=''
    # Raw, guarded access: a dismounted backing faults with an exception managed code cannot catch (run 4).
    $address=[IntPtr]::Add($script:STVhdxView.SafeMemoryMappedViewHandle.DangerousGetHandle(),
        [int]($script:STVhdxView.PointerOffset+$Offset))
    $writeOutcome=[SafeUploadGuardedView]::Write($address,[byte]$Value)
    if($writeOutcome -eq 'returned'){$writeReturned=$true}else{$writeException=$writeOutcome}
    $flushOutcome=[SafeUploadGuardedView]::Flush($address)
    if($flushOutcome -eq 'returned'){$flushReturned=$true}else{$flushException=$flushOutcome}
    return [pscustomobject]@{Offset=$Offset;Value=$Value;WriteReturned=$writeReturned;FlushReturned=$flushReturned;
        WriteException=$writeException;FlushException=$flushException}
}

function Invoke-SectionTeardownScenario {
    $script:STDiskOwned=$false
    $script:STVhdxFile=$null
    $script:STVhdxMapping=$null
    $script:STVhdxView=$null
    $script:STSecondWriter=$null
    $script:STVhdxInitialHash=''
    # Get-FileHash opens with read-only sharing and fails while this exercise's own writers hold the file (run 3).
    function Get-STShareAllHash([string]$Path) {
        $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        try { $sha=[Security.Cryptography.SHA256]::Create()
            try { return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-','') } finally { $sha.Dispose() } }
        finally { $stream.Dispose() }
    }
    $script:STNestedFile=$null
    $script:STClient=$null
    $script:STNestedThreads=@()
    $script:STTeardownThread=$null
    $script:STCompanionReleaseSent=$false
    $script:STVhdxGuid=''
    $script:STTargetPath=''
    $script:STVoluntaryDetach=@{ExitCode=$null;Output='';Attached=$false;AcquireHeld=$false}
    try {
        if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'SYSTEM required.'}
        if([string]::IsNullOrWhiteSpace($VhdxPath) -or [string]::IsNullOrWhiteSpace($DiskpartPath)){throw 'VHDX and DiskPart paths are required.'}
        if((Test-Path -LiteralPath $VhdxPath) -or (Test-Path -LiteralPath 'S:\')){throw 'Owned VHDX or S: already exists.'}
        if((Get-FileHash $Inspector -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256 -or
            (Get-FileHash $ClientSource -Algorithm SHA256).Hash -ne $ExpectedClientSha256){throw 'Exercise source/artifact hash mismatch.'}
        Add-Type -Path $ClientSource
        $script:STClient=[SafeUploadSectionFaultClient]::new()
        $script:STNestedFile=[IO.FileStream]::new($Fixture,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,
            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        if($script:STNestedFile.Length -ne 4096){throw 'Shared C: fixture length mismatch.'}
        Assert-LowerAttachment $script:STNestedFile.SafeFileHandle
        [void](Add-STOutcome 'CompanionOrderC' $true 'sameVolume:true;SafeUpload:321410;SectionFault:321409')
        [void](Add-STOutcome 'VerifierMode' ($Verifier -eq $true) 'runtimeVerifier:0x13B')

        Reset-UpperTrace
        $globalBefore=Get-STGlobalStatus
        $nestedBefore=Get-STWriterStats
        if($globalBefore.writerGlobalUnknown -ne 0 -or $nestedBefore.sectionInFlightNow -ne 0){throw 'Baseline C state is not known and idle.'}
        $cBefore=Invoke-STProbe $Fixture 'NestedBaselineProbe' 0 $false
        if($null -eq $cBefore -or $cBefore.writeObjects -ne 1){[void](Add-STOutcome 'NestedBaselineWriter' $false ('writeObjects:'+$(if($cBefore){$cBefore.writeObjects}else{'missing'})))}
        else{[void](Add-STOutcome 'NestedBaselineWriter' $true 'writeObjects:1;sharedHandleCount:1')}

        $script:STNestedThreads=@(
            [SafeUploadSectionFaultThreadMapping]::new($script:STNestedFile.SafeFileHandle),
            [SafeUploadSectionFaultThreadMapping]::new($script:STNestedFile.SafeFileHandle))
        $t1=$script:STNestedThreads[0];$t2=$script:STNestedThreads[1]
        Reset-UpperTrace
        $nestedArm=$script:STClient.Send(2,$script:STNestedFile.SafeFileHandle.DangerousGetHandle())
        $t1.Start(4) # PAGE_READWRITE
        $holdDeadline=[DateTime]::UtcNow.AddSeconds(5)
        do {
            $held=$script:STClient.Send(0,[IntPtr]::Zero)
            $t1Held=$held.CurrentHeld -eq 1 -and $held.Held -gt $nestedArm.Held -and
                $held.ArmedFileObject -eq $nestedArm.ArmedFileObject -and $held.ArmGeneration -eq $nestedArm.ArmGeneration -and $t1.Pending
            if( -not $t1Held){Start-Sleep -Milliseconds 10}
        } while( -not $t1Held -and [DateTime]::UtcNow -lt $holdDeadline)
        $fo=[UInt64]$nestedArm.ArmedFileObject
        $t1Trace=Read-STTargetTrace 'nested-t1-held' $fo
        $t1Acquires=@($t1Trace|Where-Object { $_.event -eq 'section_acquire' -and $_.syncType -eq 1 -and $_.pageProtection -eq '0x00000004' })
        $statsHeld=Get-STWriterStats
        [void](Add-STOutcome 'NestedT1Held' ($t1Held -and $t1Acquires.Count -eq 1 -and $statsHeld.sectionInFlightNow -eq [int64]$nestedBefore.sectionInFlightNow+1) `
            ('sameFileObject:0x'+$fo.ToString('X16')+';t1Thread:'+ $t1.NativeThreadId +';currentHeld:'+$held.CurrentHeld+
                ';sectionInFlightNow:'+$statsHeld.sectionInFlightNow+';acquires:'+$t1Acquires.Count))
        [void](Invoke-STProbe $Fixture 'NestedT1HeldProbe' 1 $false)

        for($index=1;$index -le 4;$index++) {
            $matchedBefore=$held.Matched
            $t2.Start(2) # PAGE_READONLY; exact-FO companion passes it.
            $readCompleted=$t2.Wait(10000)
            $readCreated=$readCompleted -and $t2.WorkerError -eq $null -and $t2.Created
            $held=$script:STClient.Send(0,[IntPtr]::Zero)
            $stepTrace=Read-STTargetTrace ('nested-readonly-'+$index) $fo
            $reads=@($stepTrace|Where-Object { $_.event -eq 'section_acquire' -and $_.syncType -eq 1 -and $_.pageProtection -eq '0x00000002' })
            $readReleases=@($stepTrace|Where-Object event -eq 'section_release')
            $stats=Get-STWriterStats
            $stepOk=$readCreated -and $held.CurrentHeld -eq 1 -and $held.Matched -eq $matchedBefore -and
                $reads.Count -eq 1 -and $readReleases.Count -eq 1 -and $stats.sectionInFlightNow -eq [int64]$nestedBefore.sectionInFlightNow+1 -and
                $stats.sectionInFlightStuck -le 1
            [void](Add-STOutcome ('NestedT2ReadOnly_'+$index) $stepOk `
                ('t2Thread:'+$t2.NativeThreadId+';pageProtection:0x00000002;acquires:'+$reads.Count+
                    ';releases:'+$readReleases.Count+';companionMatchedDelta:'+([int64]$held.Matched-[int64]$matchedBefore)+
                    ';currentHeld:'+$held.CurrentHeld+';sectionInFlightNow:'+$stats.sectionInFlightNow+';stuckAtMostOne:'+$stats.sectionInFlightStuck))
            [void](Invoke-STProbe $Fixture ('NestedT2ReadOnlyProbe_'+$index) 1 $false)
        }
        [void](Add-STOutcome 'CompanionWritableScope' $true 'exactFileObject:all-writable-acquires;T2-write-held-if-concurrent:yes;T2-write-deferred-until-T1-release:yes')

        [void]$script:STClient.Send(3,[IntPtr]::Zero)
        $script:STCompanionReleaseSent=$true
        $t1Completed=$t1.Wait(10000) -and $t1.WorkerError -eq $null -and $t1.Created
        $settleDeadline=[DateTime]::UtcNow.AddSeconds(5)
        do {
            $afterT1=Get-STWriterStats
            if($afterT1.sectionInFlightNow -eq [int64]$nestedBefore.sectionInFlightNow){break}
            Start-Sleep -Milliseconds 25
        } while([DateTime]::UtcNow -lt $settleDeadline)
        [void](Add-STOutcome 'NestedT1Release' ($t1Completed -and $afterT1.sectionInFlightNow -eq [int64]$nestedBefore.sectionInFlightNow) `
            ('workerCompleted:'+$t1Completed+';created:'+$t1.Created+';sectionInFlightNow:'+$afterT1.sectionInFlightNow+
                ';insertedDelta:'+([int64]$afterT1.sectionInFlightInserted-[int64]$nestedBefore.sectionInFlightInserted)+
                ';releasedDelta:'+([int64]$afterT1.sectionInFlightReleased-[int64]$nestedBefore.sectionInFlightReleased)))
        [void](Invoke-STProbe $Fixture 'NestedAfterT1Probe' 0 $false)

        $nestedArm2=$script:STClient.Send(2,$script:STNestedFile.SafeFileHandle.DangerousGetHandle())
        $t2.Start(4)
        $holdDeadline=[DateTime]::UtcNow.AddSeconds(5)
        do {
            $held2=$script:STClient.Send(0,[IntPtr]::Zero)
            $t2Held=$held2.CurrentHeld -eq 1 -and $held2.Held -gt $nestedArm2.Held -and
                $held2.ArmedFileObject -eq $nestedArm2.ArmedFileObject -and $held2.ArmGeneration -eq $nestedArm2.ArmGeneration -and $t2.Pending
            if( -not $t2Held){Start-Sleep -Milliseconds 10}
        } while( -not $t2Held -and [DateTime]::UtcNow -lt $holdDeadline)
        $heldStats=Get-STWriterStats
        [void](Add-STOutcome 'NestedT2WritableHeld' ($t2Held -and $heldStats.sectionInFlightNow -eq [int64]$nestedBefore.sectionInFlightNow+1 -and $heldStats.sectionInFlightStuck -le 1) `
            ('sameFileObject:0x'+$fo.ToString('X16')+';t2Thread:'+ $t2.NativeThreadId +';currentHeld:'+$held2.CurrentHeld+
                ';sectionInFlightNow:'+$heldStats.sectionInFlightNow+';stuckAtMostOne:'+$heldStats.sectionInFlightStuck))
        [void](Invoke-STProbe $Fixture 'NestedT2WritableHeldProbe' 1 $false)
        [void]$script:STClient.Send(3,[IntPtr]::Zero)
        $t2Completed=$t2.Wait(10000) -and $t2.WorkerError -eq $null -and $t2.Created
        Start-Sleep -Milliseconds 2250 # expose unreleased readonly slots through the two-second stuck counter
        $nestedAtRest=Get-STWriterStats
        $nestedGlobal=Get-STGlobalStatus
        [void](Invoke-STProbe $Fixture 'NestedFinalProbe' 0 $false)
        $threadPairingOk=$t1.NativeThreadId -ne 0 -and $t2.NativeThreadId -ne 0 -and $t1.NativeThreadId -ne $t2.NativeThreadId
        $nestedCountersOk=([int64]$nestedAtRest.sectionInFlightInserted-[int64]$nestedBefore.sectionInFlightInserted) -eq 2 -and
            ([int64]$nestedAtRest.sectionInFlightReleased-[int64]$nestedBefore.sectionInFlightReleased) -eq 2 -and
            $nestedAtRest.sectionInFlightNow -eq [int64]$nestedBefore.sectionInFlightNow -and
            $nestedAtRest.sectionInFlightOverflow -eq 0 -and $nestedAtRest.sectionInFlightStuck -eq 0 -and
            $nestedGlobal.writerGlobalUnknown -eq 0 -and $t2Completed -and $threadPairingOk
        [void](Add-STOutcome 'NestedConservation' $nestedCountersOk `
            ('t1Thread:'+ $t1.NativeThreadId +';t2Thread:'+ $t2.NativeThreadId +';distinctThreads:'+ $threadPairingOk+
                ';insertedDelta:'+([int64]$nestedAtRest.sectionInFlightInserted-[int64]$nestedBefore.sectionInFlightInserted)+
                ';releasedDelta:'+([int64]$nestedAtRest.sectionInFlightReleased-[int64]$nestedBefore.sectionInFlightReleased)+
                ';now:'+$nestedAtRest.sectionInFlightNow+';overflow:'+$nestedAtRest.sectionInFlightOverflow+
                ';stuck:'+$nestedAtRest.sectionInFlightStuck+';writerGlobalUnknown:'+$nestedGlobal.writerGlobalUnknown))
        foreach($threadWorker in $script:STNestedThreads){try{$threadWorker.Dispose()}catch{$result.Errors+=('Nested thread dispose: '+$_.Exception.Message)}}
        $script:STNestedThreads=@()

        # A newly formatted fixed NTFS VHDX is attached only after SafeUpload is live.
        $script:STDiskOwned=$true
        $diskCommands=@("create vdisk file=`"$VhdxPath`" maximum=128 type=fixed",
            "select vdisk file=`"$VhdxPath`"",'attach vdisk','create partition primary',
            'format fs=ntfs quick label=SafeUploadTeardown','assign letter=S')
        Set-Content -LiteralPath $DiskpartPath -Value $diskCommands -Encoding Ascii
        $createDisk=Invoke-STNative 'diskpart.exe' ('/s '+(ConvertTo-STArgument $DiskpartPath)) 60
        $result.VhdxCreate=$createDisk
        if($createDisk.TimedOut -or $createDisk.ExitCode -ne 0 -or $createDisk.Output -match 'DiskPart has encountered an error'){throw 'Fresh teardown VHDX creation failed.'}
        $volumeDeadline=[DateTime]::UtcNow.AddSeconds(20)
        $volume=$null
        do {
            $volumes=@(Get-CimInstance Win32_Volume -Filter "DriveLetter='S:'" -ErrorAction Stop)
            if($volumes.Count -gt 1){throw 'S: volume identity ambiguous.'}
            if($volumes.Count -eq 1 -and $volumes[0].DriveType -eq 3 -and $volumes[0].FileSystem -eq 'NTFS' -and $volumes[0].DeviceID -match '(?i)\{([0-9a-f-]{36})\}'){
                $volume=$volumes[0];$script:STVhdxGuid=$matches[1].ToLowerInvariant();break
            }
            Start-Sleep -Milliseconds 100
        } while([DateTime]::UtcNow -lt $volumeDeadline)
        if($null -eq $volume){throw 'Fresh fixed NTFS S: did not become ready.'}
        $script:STTargetPath='S:\section-teardown.maptest'
        [IO.File]::WriteAllBytes($script:STTargetPath,[byte[]]::new(4096))

        # Trigger automatic upper attachment and wait for the newly mounted canary before the lower test filter.
        $canaryDeadline=[DateTime]::UtcNow.AddSeconds(35)
        $canary=$null
        do {
            Reset-UpperTrace
            [void](Invoke-STInspector ('--admission-probe "'+$script:STTargetPath+'"'))
            $canaryRows=Get-STTraceRows 'new-volume-canary-poll'
            $canaryEntries=@($canaryRows|Where-Object event -eq 'explicit_probe')
            if($canaryEntries.Count -eq 1){$canary=$canaryEntries[0];if($canary.canaryState -eq 2){break};if($canary.canaryState -ge 3){throw ('Fresh VHDX canary failed: '+$canary.canaryStatus)}}
            Start-Sleep -Milliseconds 150
        } while([DateTime]::UtcNow -lt $canaryDeadline)
        [void](Add-STOutcome 'FreshVhdxCanary' ($null -ne $canary -and $canary.canaryState -eq 2 -and $canary.canaryChecks -eq 15) `
            ('guid:{'+$script:STVhdxGuid+'};state:'+$(if($canary){$canary.canaryState}else{'missing'})+
                ';checks:'+$(if($canary){$canary.canaryChecks}else{'missing'})+';setup:automatic-new-volume'))
        $lowerAttach=Invoke-STNative 'fltmc.exe' 'attach SafeUploadSectionFault S:' 15
        $result.LowerAttachS=$lowerAttach
        if($lowerAttach.TimedOut -or $lowerAttach.ExitCode -ne 0){throw 'Companion did not attach to fresh S:.'}
        $script:STVhdxFile=[IO.FileStream]::new($script:STTargetPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,
            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        Assert-LowerAttachment $script:STVhdxFile.SafeFileHandle
        [void](Add-STOutcome 'CompanionOrderS' $true 'sameVolume:true;SafeUpload:321410;SectionFault:321409;S:fixed-local-NTFS')
        $inventory=[SafeUploadSectionFaultClient]::Inventory([SafeUploadSectionFaultClient]::VolumeForHandle($script:STVhdxFile.SafeFileHandle))
        $upper=@($inventory|Where-Object Filter -eq 'SafeUpload')
        $upperInstance=$upper[0]
        $voluntaryStatus=Get-STGlobalStatus
        if($voluntaryStatus.writerGlobalUnknown -ne 0){throw 'Global writer state became unknown before teardown setup.'}
        $entryBeforeDismount=Read-STTargetInstance $voluntaryStatus $script:STVhdxGuid
        if($null -eq $entryBeforeDismount){throw 'Initial VHDX instance context is missing.'}
        Reset-UpperTrace
        $vhdxProbe=Invoke-STProbe $script:STTargetPath 'VhdxBeforeAcquireProbe' 0 $false
        [void](Add-STOutcome 'VhdxWriterTrackedBeforeAcquire' ($null -ne $vhdxProbe -and $vhdxProbe.writeObjects -eq 1) `
            ('writeObjects:'+$(if($vhdxProbe){$vhdxProbe.writeObjects}else{'missing'})+';writersUntracked:'+$(if($vhdxProbe){$vhdxProbe.writersUntracked}else{'missing'})))

        # This second writer is opened and retained on its own thread before the forced dismount.
        $script:STSecondWriter=[SafeUploadSectionFaultRetainedWriter]::new($script:STTargetPath)
        $mainThreadId=[SafeUploadSectionFaultRetainedWriter]::CurrentThreadId()
        $secondaryThreadOk=$script:STSecondWriter.IsOpen -and $script:STSecondWriter.OpenThreadId -ne 0 -and
            $script:STSecondWriter.OpenThreadId -ne $mainThreadId
        [void](Add-STOutcome 'SecondaryWriterOnDistinctThread' $secondaryThreadOk `
            ('open:true;openThreadId:'+$script:STSecondWriter.OpenThreadId+';mainThreadId:'+$mainThreadId))
        $script:STVhdxMapping=[IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
            # PowerShell 5.1 converts $null to "" for a string parameter; CreateFromFile rejects "" (run 2).
            $script:STVhdxFile,[NullString]::Value,0,[IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite,
            [IO.HandleInheritability]::None,$true)
        $script:STVhdxView=$script:STVhdxMapping.CreateViewAccessor(
            0,4096,[IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
        $script:STVhdxInitialHash=Get-STShareAllHash $script:STTargetPath
        $multipleWriterProbe=Invoke-STProbe $script:STTargetPath 'VhdxMultipleWriterProbe' 0 $false
        $multipleWritersOk=$null -ne $multipleWriterProbe -and $multipleWriterProbe.writeObjects -ge 2 -and
            -not $multipleWriterProbe.writersUntracked -and $secondaryThreadOk
        [void](Add-STOutcome 'MultipleVhdxWritersBeforeDismount' $multipleWritersOk `
            ('writeObjects:'+$(if($multipleWriterProbe){$multipleWriterProbe.writeObjects}else{'missing'})+
                ';writersUntracked:'+$(if($multipleWriterProbe){$multipleWriterProbe.writersUntracked}else{'missing'})+
                ';mappedViewOpen:true;secondaryThreadId:'+$script:STSecondWriter.OpenThreadId))
        $vhdxBefore=Get-STWriterStats
        $script:STTeardownThread=[SafeUploadSectionFaultThreadMapping]::new($script:STVhdxFile.SafeFileHandle)
        $arm=$script:STClient.Send(2,$script:STVhdxFile.SafeFileHandle.DangerousGetHandle())
        $script:STTeardownThread.Start(4)
        $holdDeadline=[DateTime]::UtcNow.AddSeconds(5)
        do {
            $held=$script:STClient.Send(0,[IntPtr]::Zero)
            $acquireHeld=$held.CurrentHeld -eq 1 -and $held.Held -gt $arm.Held -and
                $held.ArmedFileObject -eq $arm.ArmedFileObject -and $held.ArmGeneration -eq $arm.ArmGeneration -and $script:STTeardownThread.Pending
            if( -not $acquireHeld){Start-Sleep -Milliseconds 10}
        } while( -not $acquireHeld -and [DateTime]::UtcNow -lt $holdDeadline)
        $targetFo=[UInt64]$arm.ArmedFileObject
        $heldTrace=Read-STTargetTrace 'vhdx-held-acquire' $targetFo
        $heldAcquires=@($heldTrace|Where-Object { $_.event -eq 'section_acquire' -and $_.syncType -eq 1 -and $_.pageProtection -eq '0x00000004' })
        $vhdxHeldStats=Get-STWriterStats
        [void](Add-STOutcome 'VhdxAcquireHeld' ($acquireHeld -and $heldAcquires.Count -eq 1 -and $vhdxHeldStats.sectionInFlightNow -eq [int64]$vhdxBefore.sectionInFlightNow+1) `
            ('fileObject:0x'+$targetFo.ToString('X16')+';currentHeld:'+$held.CurrentHeld+';workerPending:'+$script:STTeardownThread.Pending+
                ';sectionInFlightNow:'+$vhdxHeldStats.sectionInFlightNow+';acquireEvents:'+$heldAcquires.Count))
        [void](Invoke-STProbe $script:STTargetPath 'VhdxAcquireHeldProbe' 1 $false)

        $detachArgs='detach SafeUpload S: '+(ConvertTo-STArgument ([string]$upperInstance.Name))
        $veto=Invoke-STNative 'fltmc.exe' $detachArgs 15
        $script:STVoluntaryDetach.ExitCode=$veto.ExitCode
        $script:STVoluntaryDetach.Output=$veto.Output
        $script:STVoluntaryDetach.TimedOut=$veto.TimedOut
        $stillAttached=$false
        try {
            $currentInventory=[SafeUploadSectionFaultClient]::Inventory([SafeUploadSectionFaultClient]::VolumeForHandle($script:STVhdxFile.SafeFileHandle))
            $stillAttached=@($currentInventory|Where-Object { $_.Filter -eq 'SafeUpload' -and $_.Name -eq $upperInstance.Name }).Count -eq 1
        } catch {}
        $heldAfterVeto=$script:STClient.Send(0,[IntPtr]::Zero)
        $script:STVoluntaryDetach.Attached=$stillAttached
        $script:STVoluntaryDetach.AcquireHeld=$heldAfterVeto.CurrentHeld -eq 1 -and $script:STTeardownThread.Pending
        $vetoOk = -not $veto.TimedOut -and $veto.ExitCode -ne 0 -and $stillAttached -and $script:STVoluntaryDetach.AcquireHeld
        [void](Add-STOutcome 'VoluntaryDetachVeto' $vetoOk `
            ('command:fltmc detach SafeUpload S: '+$upperInstance.Name+';exitCode:'+$(if($null -ne $veto.ExitCode){$veto.ExitCode}else{'timeout'})+
                ';timedOut:'+$veto.TimedOut+';elapsedMs:'+$veto.ElapsedMs+';output:'+(($veto.Output -replace '[\r\n]+',' ').Trim())+';stillAttached:'+$stillAttached+
                ';acquireStillHeld:'+$script:STVoluntaryDetach.AcquireHeld+';currentHeld:'+$heldAfterVeto.CurrentHeld))
        [void](Invoke-STProbe $script:STTargetPath 'VhdxAfterVetoProbe' 1 $false)
        $cVetoProbe=Invoke-STProbe $Fixture 'CAfterVetoProbe' 0 $false

        $dismount=Invoke-STNative 'fsutil.exe' 'volume dismount S:' 20
        $result.Dismount=$dismount
        $pendingAfterDismount=$script:STTeardownThread.Pending
        $releasedAfterDismountTimeout=$false
        if($dismount.TimedOut -and $pendingAfterDismount){
            try{[void]$script:STClient.Send(3,[IntPtr]::Zero);$script:STCompanionReleaseSent=$true}catch{$result.Errors+=('Bounded dismount timeout release: '+$_.Exception.Message)}
            $releasedAfterDismountTimeout=$script:STCompanionReleaseSent
            $releaseWaitClock=[Diagnostics.Stopwatch]::StartNew()
            $releasedAfterTimeout=$script:STTeardownThread.Wait(10000)
            $releaseWaitClock.Stop()
            [void](Add-STOutcome 'DismountTimeoutReleased' $false ('releaseSent:'+$script:STCompanionReleaseSent+';workerCompleted:'+$releasedAfterTimeout+
                ';workerWaitElapsedMs:'+$releaseWaitClock.ElapsedMilliseconds+';limitMs:20000'))
        }
        $statusAfterDismount=Get-STGlobalStatus
        $entryAfterDismount=Read-STTargetInstance $statusAfterDismount $script:STVhdxGuid
        $detachedAfterDismount=$null -eq $entryAfterDismount -or (($entryAfterDismount.volumeFlags -band 1) -ne 0)
        $slotAfterDismount=Get-STWriterStats
        $traceAfterDismount=Read-STTargetTrace 'vhdx-after-dismount' $targetFo
        $releaseAfterDismount=@($traceAfterDismount|Where-Object event -eq 'section_release').Count
        [void](Add-STOutcome 'DismountWhileHeld' ( -not $dismount.TimedOut -and $dismount.ExitCode -eq 0) `
            ('method:fsutil-volume-dismount;exitCode:'+$(if($null -ne $dismount.ExitCode){$dismount.ExitCode}else{'timeout'})+
                ';elapsedMs:'+$dismount.ElapsedMs+';workerPendingOnReturn:'+$pendingAfterDismount+
                ';volumeEntry:'+$(if($entryAfterDismount){'flags:'+ $entryAfterDismount.volumeFlags}else{'absent'})+
                ';instanceDetachedAfterDismount:'+$detachedAfterDismount+
                ';writerGlobalUnknown:'+$statusAfterDismount.writerGlobalUnknown+';slotNow:'+$slotAfterDismount.sectionInFlightNow+
                ';slotInserted:'+$slotAfterDismount.sectionInFlightInserted+';slotReleased:'+$slotAfterDismount.sectionInFlightReleased+
                ';sectionReleaseEvents:'+$releaseAfterDismount+
                ';output:'+(($dismount.Output -replace '[\r\n]+',' ').Trim())))
        $dismountWritePayload=[byte[]](0x53,0x54,0x2D,0x44,0x49,0x53,0x4D,0x54)
        $primaryWriteAfterDismount=[SafeUploadSectionFaultRetainedWriter]::TryWrite(
            $script:STVhdxFile.SafeFileHandle,$dismountWritePayload)
        $secondaryWriteAfterDismount=$script:STSecondWriter.AttemptWrite($dismountWritePayload)
        $viewWriteAfterDismount=Invoke-STOldViewWrite 0 ([byte]0xA5)
        $oldHandleRejectedAfterDismount= -not $primaryWriteAfterDismount.Succeeded -and
            -not $secondaryWriteAfterDismount.Succeeded
        [void](Add-STOutcome 'OldHandlesCannotWriteAfterDismount' $oldHandleRejectedAfterDismount `
            ('primary:'+ (Format-STHandleWrite $primaryWriteAfterDismount)+';secondary:'+ (Format-STHandleWrite $secondaryWriteAfterDismount)+
                ';mappedViewWriteReturned:'+$viewWriteAfterDismount.WriteReturned+';mappedViewFlushReturned:'+$viewWriteAfterDismount.FlushReturned+
                ';mappedViewWriteException:'+$viewWriteAfterDismount.WriteException+';mappedViewFlushException:'+$viewWriteAfterDismount.FlushException+
                ';premise:'+$(if($oldHandleRejectedAfterDismount){'holds'}else{'FALSE_OLD_HANDLE_WRITE_SUCCEEDED'})))
        if(-not $oldHandleRejectedAfterDismount){Write-Output 'ST_PREMISE_FALSE=old handle wrote successfully after dismount; scoped teardown assumption is false;FAIL'}
        $pendingBeforeDetach=$script:STTeardownThread.Pending
        Set-Content -LiteralPath $DiskpartPath -Value @("select vdisk file=`"$VhdxPath`"",'detach vdisk') -Encoding Ascii
        $detachDisk=Invoke-STNative 'diskpart.exe' ('/s '+(ConvertTo-STArgument $DiskpartPath)) 20
        $result.VhdxDetach=$detachDisk
        $pendingAtDetachReturn=$script:STTeardownThread.Pending
        $releasedAfterDetachTimeout=$false
        if($detachDisk.TimedOut -and $pendingAtDetachReturn){
            try{[void]$script:STClient.Send(3,[IntPtr]::Zero);$script:STCompanionReleaseSent=$true}catch{$result.Errors+=('Bounded VHDX detach timeout release: '+$_.Exception.Message)}
            $releasedAfterDetachTimeout=$script:STCompanionReleaseSent
        }
        $workerWaitClock=[Diagnostics.Stopwatch]::StartNew()
        $workerCompleted=$script:STTeardownThread.Wait(10000)
        if( -not $workerCompleted){
            try{[void]$script:STClient.Send(3,[IntPtr]::Zero);$script:STCompanionReleaseSent=$true}catch{$result.Errors+=('Explicit hold release: '+$_.Exception.Message)}
            $workerCompleted=$script:STTeardownThread.Wait(10000)
        }
        $workerWaitClock.Stop()
        $workerWaitElapsedMs=$workerWaitClock.ElapsedMilliseconds
        $naturalOrExplicit=if( -not $pendingAfterDismount){'unblocked-by-dismount'}
            elseif($releasedAfterDismountTimeout){'explicit-release-after-dismount-timeout'}
            elseif( -not $pendingBeforeDetach){'unblocked-before-vhdx-detach'}
            elseif( -not $pendingAtDetachReturn){'unblocked-by-vhdx-detach'}
            elseif($releasedAfterDetachTimeout){'explicit-release-after-vhdx-detach-timeout'}
            else{'explicit-release-after-detach-wait'}
        $afterDetachStats=Get-STWriterStats
        $statusAfterDetach=Get-STGlobalStatus
        $entryAfterDetach=Read-STTargetInstance $statusAfterDetach $script:STVhdxGuid
        $detachedAfterDetach=$null -eq $entryAfterDetach -or (($entryAfterDetach.volumeFlags -band 1) -ne 0)
        $traceAfterDetach=Read-STTargetTrace 'vhdx-after-detach' $targetFo
        $releaseAfterDetach=@($traceAfterDetach|Where-Object event -eq 'section_release').Count
        [void](Add-STOutcome 'VhdxDetachBounded' ( -not $detachDisk.TimedOut -and $detachDisk.ExitCode -eq 0 -and $detachedAfterDetach -and $workerCompleted) `
            ('exitCode:'+$(if($null -ne $detachDisk.ExitCode){$detachDisk.ExitCode}else{'timeout'})+';elapsedMs:'+$detachDisk.ElapsedMs+
                ';holdDisposition:'+$naturalOrExplicit+';workerCompleted:'+$workerCompleted+';workerWaitElapsedMs:'+$workerWaitElapsedMs+
                ';sectionReleaseEvents:'+ $releaseAfterDetach+
                ';volumeEntry:'+$(if($entryAfterDetach){'flags:'+ $entryAfterDetach.volumeFlags}else{'absent'})+
                ';writerGlobalUnknown:'+$statusAfterDetach.writerGlobalUnknown+';sectionNow:'+$afterDetachStats.sectionInFlightNow+
                ';inserted:'+$afterDetachStats.sectionInFlightInserted+';released:'+$afterDetachStats.sectionInFlightReleased+
                ';stuck:'+$afterDetachStats.sectionInFlightStuck+';overflow:'+$afterDetachStats.sectionInFlightOverflow))

        $slotDelta=[int64]$afterDetachStats.sectionInFlightNow-[int64]$vhdxBefore.sectionInFlightNow
        $insertDelta=[int64]$afterDetachStats.sectionInFlightInserted-[int64]$vhdxBefore.sectionInFlightInserted
        $releasedDelta=[int64]$afterDetachStats.sectionInFlightReleased-[int64]$vhdxBefore.sectionInFlightReleased
        $failureDelta=[int64]$afterDetachStats.sectionInFlightRemovedOnFailure-[int64]$vhdxBefore.sectionInFlightRemovedOnFailure
        $drainingSignature=$statusAfterDetach.writerGlobalUnknown -eq 1 -and $slotDelta -eq 1 -and $insertDelta -eq 1 -and
            $releasedDelta -eq 0 -and $failureDelta -eq 0 -and $releaseAfterDetach -eq 0
        $normalSuccessSignature=$workerCompleted -and $script:STTeardownThread.Created -and $script:STTeardownThread.Error -eq 0 -and
            $slotDelta -eq 0 -and $insertDelta -eq 1 -and $releasedDelta -eq 1 -and $failureDelta -eq 0 -and $releaseAfterDetach -ge 1
        $normalFailureSignature=$workerCompleted -and -not $script:STTeardownThread.Created -and $script:STTeardownThread.Error -ne 0 -and
            $slotDelta -eq 0 -and $insertDelta -eq 1 -and $releasedDelta -eq 0 -and $failureDelta -eq 1 -and $releaseAfterDetach -eq 0
        $disposition=if($drainingSignature){'draining-compatible-signature'}
            elseif($normalSuccessSignature){'normal-success-counter-signature'}
            elseif($normalFailureSignature){'normal-failed-acquire-counter-signature'}else{'ambiguous-no-direct-postoperation-flag-telemetry'}
        Reset-UpperTrace
        Set-Content -LiteralPath $DiskpartPath -Value @(('select vdisk file="'+$VhdxPath+'"'),'attach vdisk') -Encoding Ascii
        $reattachDisk=Invoke-STNative 'diskpart.exe' ('/s '+(ConvertTo-STArgument $DiskpartPath)) 30
        $result.VhdxReattach=$reattachDisk
        $reattachMounted=$false
        $reattachDeadline=[DateTime]::UtcNow.AddSeconds(20)
        do {
            $reattachImage=Get-DiskImage -ImagePath $VhdxPath -ErrorAction Stop
            $reattachVolumes=@(Get-CimInstance Win32_Volume -Filter "DriveLetter='S:'" -ErrorAction Stop)
            if($reattachImage.Attached -and $reattachVolumes.Count -eq 1 -and
                $reattachVolumes[0].DriveType -eq 3 -and $reattachVolumes[0].FileSystem -eq 'NTFS' -and
                (Test-Path -LiteralPath 'S:\')){$reattachMounted=$true;break}
            Start-Sleep -Milliseconds 100
        } while([DateTime]::UtcNow -lt $reattachDeadline)
        if(-not $reattachMounted -and $reattachImage.Attached -and $reattachVolumes.Count -eq 0 -and
            -not (Test-Path -LiteralPath 'S:\')){
            try {
                Add-PartitionAccessPath -DiskNumber $reattachImage.Number -PartitionNumber 1 -DriveLetter 'S' -ErrorAction Stop
                $reattachDeadline=[DateTime]::UtcNow.AddSeconds(15)
                do {
                    $reattachVolumes=@(Get-CimInstance Win32_Volume -Filter "DriveLetter='S:'" -ErrorAction Stop)
                    if($reattachVolumes.Count -eq 1 -and $reattachVolumes[0].DriveType -eq 3 -and
                        $reattachVolumes[0].FileSystem -eq 'NTFS' -and (Test-Path -LiteralPath 'S:\')){
                        $reattachMounted=$true;break
                    }
                    Start-Sleep -Milliseconds 100
                } while([DateTime]::UtcNow -lt $reattachDeadline)
            } catch {$result.Errors+=('VHDX drive-letter restore: '+$_.Exception.Message)}
        }
        [void](Add-STOutcome 'SameVhdxReattached' ($reattachMounted -and -not $reattachDisk.TimedOut -and $reattachDisk.ExitCode -eq 0) ('exitCode:'+$(if($null -ne $reattachDisk.ExitCode){$reattachDisk.ExitCode}else{'timeout'})+';attached:'+$reattachImage.Attached+';SVolumeCount:'+$reattachVolumes.Count+';mountReady:'+$reattachMounted))
        if(-not $reattachMounted){throw 'Same VHDX did not remount as S: after detach.'}

        $reattachCanary=$null
        $reattachEntry=$null
        $reattachSetupSeen=$false
        $reattachCanaryAck=$null
        $canaryDeadline=[DateTime]::UtcNow.AddSeconds(35)
        do {
            try {$reattachCanaryAck=Invoke-STInspector ('--admission-probe "'+$script:STTargetPath+'"')|ConvertFrom-Json}
            catch {$reattachCanaryAck=$null}
            try {
                $reattachStatus=Get-STGlobalStatus
                $reattachEntry=Read-STTargetInstance $reattachStatus $script:STVhdxGuid
                $reattachRows=Get-STTraceRows ('reattach-canary-'+[guid]::NewGuid().ToString('N'))
                if($null -ne $reattachEntry){
                    $newInstanceTrace='0x'+([string]$reattachEntry.instance)
                    $reattachSetupSeen=@($reattachRows|Where-Object {$_.event -eq 'instance_setup' -and [string]$_.instance -eq $newInstanceTrace}).Count -gt 0
                    $reattachCanary=@($reattachRows|Where-Object {
                        $_.event -eq 'explicit_probe' -and $_.probeStatus -eq '0x00000000' -and $_.canaryState -eq 2 -and $_.canaryChecks -eq 15
                    })|Select-Object -Last 1
                    if($reattachEntry.canaryState -eq 2 -and $reattachEntry.canaryChecks -eq 15 -and $reattachEntry.canaryStatus -eq 0 -and
                        $reattachSetupSeen -and $null -ne $reattachCanary -and $null -ne $reattachCanaryAck -and $reattachCanaryAck.status -eq '0x00000000'){break}
                }
            } catch {}
            Start-Sleep -Milliseconds 150
        } while([DateTime]::UtcNow -lt $canaryDeadline)
        $reattachCanaryOk=$null -ne $reattachEntry -and $reattachEntry.canaryState -eq 2 -and $reattachEntry.canaryChecks -eq 15 -and
            $reattachEntry.canaryStatus -eq 0 -and $reattachSetupSeen -and $null -ne $reattachCanary -and
            $null -ne $reattachCanaryAck -and $reattachCanaryAck.status -eq '0x00000000'
        [void](Add-STOutcome 'FreshVhdxCanaryAfterReattach' $reattachCanaryOk ('sameGuid:{'+$script:STVhdxGuid+'};instanceSetupEvent:'+$reattachSetupSeen+';oldInstance:'+$(if($entryBeforeDismount){$entryBeforeDismount.instance}else{'missing'})+';newInstance:'+$(if($reattachEntry){$reattachEntry.instance}else{'missing'})+';canaryState:'+$(if($reattachEntry){$reattachEntry.canaryState}else{'missing'})+';canaryChecks:'+$(if($reattachEntry){$reattachEntry.canaryChecks}else{'missing'})+';canaryStatus:'+$(if($reattachEntry){$reattachEntry.canaryStatus}else{'missing'})))
        if(-not $reattachCanaryOk){throw 'Reattached VHDX instance did not pass its new canary.'}

        $primaryWriteAfterReattach=[SafeUploadSectionFaultRetainedWriter]::TryWrite($script:STVhdxFile.SafeFileHandle,$dismountWritePayload)
        $secondaryWriteAfterReattach=$script:STSecondWriter.AttemptWrite($dismountWritePayload)
        $viewWriteAfterReattach=Invoke-STOldViewWrite 1 ([byte]0x5A)
        $oldHandlesRejectedAfterReattach= -not $primaryWriteAfterReattach.Succeeded -and -not $secondaryWriteAfterReattach.Succeeded
        [void](Add-STOutcome 'OldHandlesCannotWriteAfterReattach' $oldHandlesRejectedAfterReattach ('primary:'+(Format-STHandleWrite $primaryWriteAfterReattach)+';secondary:'+(Format-STHandleWrite $secondaryWriteAfterReattach)+';mappedViewWriteReturned:'+$viewWriteAfterReattach.WriteReturned+';mappedViewFlushReturned:'+$viewWriteAfterReattach.FlushReturned+';mappedViewWriteException:'+$viewWriteAfterReattach.WriteException+';mappedViewFlushException:'+$viewWriteAfterReattach.FlushException+';premise:'+$(if($oldHandlesRejectedAfterReattach){'holds'}else{'FALSE_OLD_HANDLE_WRITE_SUCCEEDED'})))
        if(-not $oldHandlesRejectedAfterReattach){Write-Output 'ST_PREMISE_FALSE=old handle wrote successfully after reattach; scoped teardown assumption is false;FAIL'}

        $oldHandlesClosed=$true
        if($script:STVhdxView){try{$script:STVhdxView.Dispose();$script:STVhdxView=$null}catch{$oldHandlesClosed=$false;$result.Errors+=('VHDX mapped view close: '+$_.Exception.Message)}}
        if($script:STVhdxMapping){try{$script:STVhdxMapping.Dispose();$script:STVhdxMapping=$null}catch{$oldHandlesClosed=$false;$result.Errors+=('VHDX map close: '+$_.Exception.Message)}}
        if($script:STSecondWriter){try{$script:STSecondWriter.Dispose();$script:STSecondWriter=$null}catch{$oldHandlesClosed=$false;$result.Errors+=('Secondary writer close: '+$_.Exception.Message)}}
        if($script:STVhdxFile){try{$script:STVhdxFile.Dispose();$script:STVhdxFile=$null}catch{$oldHandlesClosed=$false;$result.Errors+=('Original VHDX writer close: '+$_.Exception.Message)}}
        [void](Add-STOutcome 'OldVhdxHandlesClosed' $oldHandlesClosed ('allRetainedHandlesClosed:'+$oldHandlesClosed))

        $hashAfterAttempts=Get-STShareAllHash $script:STTargetPath
        $vhdxBytesUnchanged=$script:STVhdxInitialHash -eq $hashAfterAttempts
        [void](Add-STOutcome 'OldMappedViewDidNotReachDisk' $vhdxBytesUnchanged ('beforeSHA256:'+$script:STVhdxInitialHash+';afterSHA256:'+$hashAfterAttempts+';afterDismountWriteReturned:'+$viewWriteAfterDismount.WriteReturned+';afterDismountFlushReturned:'+$viewWriteAfterDismount.FlushReturned+';afterReattachWriteReturned:'+$viewWriteAfterReattach.WriteReturned+';afterReattachFlushReturned:'+$viewWriteAfterReattach.FlushReturned+';premise:'+$(if($vhdxBytesUnchanged){'holds'}else{'FALSE_OLD_VIEW_CHANGED_DISK_BYTES'})))
        [void](Add-STOutcome 'VhdxHashUnchangedAfterPostDismountAttempts' $vhdxBytesUnchanged ('beforeSHA256:'+$script:STVhdxInitialHash+';afterSHA256:'+$hashAfterAttempts+';oldHandleSuccessAfterDismount:'+$primaryWriteAfterDismount.Succeeded+'/'+$secondaryWriteAfterDismount.Succeeded+';oldHandleSuccessAfterReattach:'+$primaryWriteAfterReattach.Succeeded+'/'+$secondaryWriteAfterReattach.Succeeded))
        if(-not $vhdxBytesUnchanged){Write-Output 'ST_PREMISE_FALSE=post-dismount handle or mapped-view write changed the reattached VHDX bytes;FAIL'}

        $afterOldHandlesClosed=Get-STWriterStats
        $globalAfterTeardown=Get-STGlobalStatus
        $teardownDropDelta=[int64]$afterOldHandlesClosed.writersDroppedAtTeardown-[int64]$vhdxBefore.writersDroppedAtTeardown
        $mountedDropDelta=[int64]$afterOldHandlesClosed.writersDroppedWhileMounted-[int64]$vhdxBefore.writersDroppedWhileMounted
        $scopedDropOk=$oldHandlesClosed -and $afterOldHandlesClosed.writersDroppedAtTeardown -gt 0 -and
            $teardownDropDelta -gt 0 -and $afterOldHandlesClosed.writersDroppedWhileMounted -eq 0 -and
            $mountedDropDelta -eq 0 -and $globalAfterTeardown.writerGlobalUnknown -eq 0
        [void](Add-STOutcome 'ScopedWriterDropAccounting' $scopedDropOk ('writersDroppedAtTeardown:'+$afterOldHandlesClosed.writersDroppedAtTeardown+';teardownDelta:'+$teardownDropDelta+';writersDroppedWhileMounted:'+$afterOldHandlesClosed.writersDroppedWhileMounted+';mountedDelta:'+$mountedDropDelta+';writerGlobalUnknown:'+$globalAfterTeardown.writerGlobalUnknown))
        $cKnownProbe=Invoke-STProbe $Fixture 'CAfterScopedTeardownProbe' 0 $false
        $cKnownOk=$globalAfterTeardown.writerGlobalUnknown -eq 0 -and $null -ne $cKnownProbe -and -not $cKnownProbe.writersUntracked
        [void](Add-STOutcome 'CProbeRemainsKnownAfterTeardown' $cKnownOk ('writerGlobalUnknown:'+$globalAfterTeardown.writerGlobalUnknown+';writersUntracked:'+$(if($cKnownProbe){$cKnownProbe.writersUntracked}else{'missing'})+';writeObjects:'+$(if($cKnownProbe){$cKnownProbe.writeObjects}else{'missing'})))

        $beforeMountedLoss=Get-STWriterStats
        $deleteReply=Invoke-STInspector ('--admission-delete-stream-context "'+$Fixture+'"')|ConvertFrom-Json
        $mountedLossDeadline=[DateTime]::UtcNow.AddSeconds(5)
        $afterMountedLoss=$null
        $statusAfterMountedLoss=$null
        do {
            $afterMountedLoss=Get-STWriterStats
            $statusAfterMountedLoss=Get-STGlobalStatus
            if($afterMountedLoss.writersDroppedWhileMounted -ge ([int64]$beforeMountedLoss.writersDroppedWhileMounted+1) -and $statusAfterMountedLoss.writerGlobalUnknown -eq 1){break}
            Start-Sleep -Milliseconds 50
        } while([DateTime]::UtcNow -lt $mountedLossDeadline)
        $statusAfterMountedLossAgain=Get-STGlobalStatus
        $mountedDropOk=$deleteReply.streamContextDeleted -eq $true -and $deleteReply.status -eq '0x00000000' -and
            $beforeMountedLoss.writersDroppedWhileMounted -eq 0 -and $afterMountedLoss.writersDroppedWhileMounted -eq 1 -and
            ([int64]$afterMountedLoss.writersDroppedWhileMounted-[int64]$beforeMountedLoss.writersDroppedWhileMounted) -eq 1 -and
            $statusAfterMountedLoss.writerGlobalUnknown -eq 1
        $mountedUnknownSticky=$statusAfterMountedLoss.writerGlobalUnknown -eq 1 -and $statusAfterMountedLossAgain.writerGlobalUnknown -eq 1
        [void](Add-STOutcome 'MountedWriterDropPoisonsGlobalState' $mountedDropOk ('deleteCommandStatus:'+$deleteReply.status+';streamContextDeleted:'+$deleteReply.streamContextDeleted+';beforeMounted:'+$beforeMountedLoss.writersDroppedWhileMounted+';afterMounted:'+$afterMountedLoss.writersDroppedWhileMounted+';writerGlobalUnknown:'+$statusAfterMountedLoss.writerGlobalUnknown))
        [void](Add-STOutcome 'MountedLossGlobalUnknownStaysSet' $mountedUnknownSticky ('firstRead:'+$statusAfterMountedLoss.writerGlobalUnknown+';secondRead:'+$statusAfterMountedLossAgain.writerGlobalUnknown))
        $cFaultProbe=Invoke-STProbe $Fixture 'CAfterMountedDropProbe' 0 $true
        $cFaultOk=$null -ne $cFaultProbe -and $cFaultProbe.writersUntracked
        [void](Add-STOutcome 'CProbeUntrackedAfterMountedDrop' $cFaultOk ('writerGlobalUnknown:'+$statusAfterMountedLossAgain.writerGlobalUnknown+';writersUntracked:'+$(if($cFaultProbe){$cFaultProbe.writersUntracked}else{'missing'})))

        # The mounted-loss command and its required status/probe reads are the last exercise steps before finally restores the run.
        $result.Teardown=@{Dismount=$dismount;Detach=$detachDisk;Reattach=$reattachDisk;Disposition=$disposition;
            WriterGlobalUnknownBeforeMountedFault=$globalAfterTeardown.writerGlobalUnknown;
            WriterGlobalUnknownAfterMountedFault=$statusAfterMountedLossAgain.writerGlobalUnknown;
            Before=$vhdxBefore;After=$afterOldHandlesClosed;Guid=$script:STVhdxGuid;Held=$arm;
            VoluntaryDetach=$script:STVoluntaryDetach;WorkerCompleted=$workerCompleted;HoldDisposition=$naturalOrExplicit;
            SlotNowDelta=$slotDelta;InsertedDelta=$insertDelta;ReleasedDelta=$releasedDelta;
            RemovedOnFailureDelta=$failureDelta;ReleaseTraceEvents=$releaseAfterDetach;
            WritersDroppedAtTeardownDelta=$teardownDropDelta;WritersDroppedWhileMountedDelta=$mountedDropDelta;
            BeforeHash=$script:STVhdxInitialHash;AfterHash=$hashAfterAttempts;
            OldHandleWritesAfterDismount=@($primaryWriteAfterDismount,$secondaryWriteAfterDismount);
            OldHandleWritesAfterReattach=@($primaryWriteAfterReattach,$secondaryWriteAfterReattach);
            OldViewWriteAfterDismount=$viewWriteAfterDismount;OldViewWriteAfterReattach=$viewWriteAfterReattach;
            ReattachedInstance=$reattachEntry;MountedLossDeleteReply=$deleteReply;
            PendingAfterDismount=$pendingAfterDismount;PendingBeforeDetach=$pendingBeforeDetach;PendingAtDetachReturn=$pendingAtDetachReturn;
            ReleasedAfterDismountTimeout=$releasedAfterDismountTimeout;ReleasedAfterDetachTimeout=$releasedAfterDetachTimeout}
    }
    catch {
        $message=$_.Exception.ToString()
        $result.Errors+=('Section teardown exercise: '+$message)
        [void](Add-STOutcome 'Execution' $false ($message -replace '[\r\n]+',' '))
    }
    finally {
        if($script:STClient){
            try{
                $finalWorkers=@($script:STNestedThreads)
                if($null -ne $script:STTeardownThread){$finalWorkers+=@($script:STTeardownThread)}
                $preReleasePending=@($finalWorkers|Where-Object { $_.Pending }).Count -gt 0
                [void]$script:STClient.Send(3,[IntPtr]::Zero)
                $script:STCompanionReleaseSent=$true
                $workerDrain=$true
                foreach($finalWorker in $finalWorkers){if( -not $finalWorker.Wait(10000)){$workerDrain=$false}}
                if( -not $workerDrain){
                    [void]$script:STClient.Send(3,[IntPtr]::Zero)
                    $workerDrain=$true
                    foreach($finalWorker in $finalWorkers){if( -not $finalWorker.Wait(10000)){$workerDrain=$false}}
                }
                $result.FinalRelease=@{WasPending=$preReleasePending;Completed=$workerDrain;ExplicitReleaseSent=$script:STCompanionReleaseSent}
                [void](Add-STOutcome 'FinalHoldRelease' ($workerDrain -and $script:STCompanionReleaseSent) `
                    ('wasPending:'+$preReleasePending+';workerCount:'+$finalWorkers.Count+';workerCompleted:'+$workerDrain+';releaseSent:'+$script:STCompanionReleaseSent))
            }catch{$result.Errors+=('Finally release: '+$_.Exception.Message);[void](Add-STOutcome 'FinalHoldRelease' $false ('error:'+($_.Exception.Message -replace '[\r\n]+',' ')))}
            try{
                $result.Disarmed=$script:STClient.Send(4,[IntPtr]::Zero)
                $disarmedOk=$result.Disarmed.Mode -eq 0 -and $result.Disarmed.ArmedFileObject -eq 0 -and $result.Disarmed.CurrentHeld -eq 0
                [void](Add-STOutcome 'FinalDisarm' $disarmedOk ('mode:'+$result.Disarmed.Mode+';armedFileObject:0x'+$result.Disarmed.ArmedFileObject.ToString('X16')+';currentHeld:'+$result.Disarmed.CurrentHeld))
            }
            catch{$result.Errors+=('Finally disarm: '+$_.Exception.Message);[void](Add-STOutcome 'FinalDisarm' $false ('error:'+($_.Exception.Message -replace '[\r\n]+',' ')))}
        }else{
            [void](Add-STOutcome 'FinalHoldRelease' $true 'clientOpened:false;noCompanionHoldCouldExist:true')
            [void](Add-STOutcome 'FinalDisarm' $true 'clientOpened:false;companionCouldNotBeArmed:true')
        }
        $allWorkersDrained=$true
        foreach($worker in @($script:STNestedThreads)+@($script:STTeardownThread)){
            if($null -ne $worker){
                try{if( -not $worker.Wait(10000)){$allWorkersDrained=$false;$result.Errors+='Persistent section worker did not drain in finally.'}}
                catch{$allWorkersDrained=$false;$result.Errors+=('Persistent section worker wait: '+$_.Exception.Message)}
                try{$worker.Dispose()}catch{$allWorkersDrained=$false;$result.Errors+=('Persistent section worker dispose: '+$_.Exception.Message)}
            }
        }
        [void](Add-STOutcome 'FinalWorkersDrained' $allWorkersDrained ('completed:'+ $allWorkersDrained))
        if($script:STVhdxView){try{$script:STVhdxView.Dispose()}catch{$result.Errors+=('VHDX mapped view close: '+$_.Exception.Message)};$script:STVhdxView=$null}
        if($script:STVhdxMapping){try{$script:STVhdxMapping.Dispose()}catch{$result.Errors+=('VHDX map close: '+$_.Exception.Message)};$script:STVhdxMapping=$null}
        if($script:STSecondWriter){try{$script:STSecondWriter.Dispose()}catch{$result.Errors+=('Secondary writer close: '+$_.Exception.Message)};$script:STSecondWriter=$null}
        if($script:STVhdxFile){try{$script:STVhdxFile.Dispose()}catch{$result.Errors+=('VHDX file close: '+$_.Exception.Message)};$script:STVhdxFile=$null}
        if($script:STNestedFile){try{$script:STNestedFile.Dispose()}catch{$result.Errors+=('C fixture file close: '+$_.Exception.Message)};$script:STNestedFile=$null}
        if($script:STClient){try{$script:STClient.Dispose()}catch{$result.Errors+=('Fault port close: '+$_.Exception.Message)};$script:STClient=$null}

        if($script:STDiskOwned -and (Test-Path -LiteralPath $VhdxPath)){
            try{
                $image=Get-DiskImage -ImagePath $VhdxPath -ErrorAction Stop
                if($image.Attached){
                    Set-Content -LiteralPath $DiskpartPath -Value @("select vdisk file=`"$VhdxPath`"",'detach vdisk') -Encoding Ascii
                    $cleanupDisk=Invoke-STNative 'diskpart.exe' ('/s '+(ConvertTo-STArgument $DiskpartPath)) 25
                    if($cleanupDisk.TimedOut -or $cleanupDisk.ExitCode -ne 0){throw 'Finally DiskPart detach failed.'}
                }
                $deadline=[DateTime]::UtcNow.AddSeconds(15)
                do{
                    $image=Get-DiskImage -ImagePath $VhdxPath -ErrorAction Stop
                    $letterPresent=Test-Path -LiteralPath 'S:\'
                    if( -not $image.Attached -and -not $letterPresent){break}
                    Start-Sleep -Milliseconds 100
                }while([DateTime]::UtcNow -lt $deadline)
                if($image.Attached -or (Test-Path -LiteralPath 'S:\')){throw 'Finally VHDX detach could not be proven.'}
                Remove-Item -LiteralPath $VhdxPath -Force
            }catch{$result.Errors+=('VHDX disposal: '+$_.Exception.Message)}
        }
        if(Test-Path -LiteralPath $DiskpartPath){try{Remove-Item -LiteralPath $DiskpartPath -Force}catch{$result.Errors+=('DiskPart script removal: '+$_.Exception.Message)}}
        $diskClean=( -not (Test-Path -LiteralPath $VhdxPath)) -and ( -not (Test-Path -LiteralPath $DiskpartPath)) -and ( -not (Test-Path -LiteralPath 'S:\'))
        [void](Add-STOutcome 'OwnedVhdxFinally' $diskClean ('vhdxAbsent:'+( -not (Test-Path -LiteralPath $VhdxPath))+
            ';diskpartAbsent:'+( -not (Test-Path -LiteralPath $DiskpartPath))+';SAbsent:'+( -not (Test-Path -LiteralPath 'S:\'))))
        if($result.Errors.Count -gt 0){[void](Add-STOutcome 'CleanupErrors' $false ('count:'+$result.Errors.Count))}
        $result.Passed=([int]$result.FailedChecks -eq 0 -and $result.Errors.Count -eq 0 -and $diskClean)
        $result.Summary='passed:'+([int]$result.PassedChecks)+';failed:'+([int]$result.FailedChecks)
    }
    return $result.Passed
}
try {
    if ($EmergencyRelease) {
        if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Emergency hold release requires SYSTEM.' }
        if ((Get-FileHash $ClientSource -Algorithm SHA256).Hash -ne $ExpectedClientSha256) { throw 'Emergency client hash mismatch.' }
        Add-Type -Path $ClientSource
        $client=[SafeUploadSectionFaultClient]::new()
        $released=$client.Send(3,[IntPtr]::Zero)
        $disarmed=$client.Send(4,[IntPtr]::Zero)
        $result.EmergencyRelease=@{ReleaseMode=$released.Mode;Mode=$disarmed.Mode;ArmedFileObject=('0x'+$disarmed.ArmedFileObject.ToString('X16'));CurrentHeld=$disarmed.CurrentHeld}
        $result.Passed=$disarmed.Mode -eq 0 -and $disarmed.ArmedFileObject -eq 0 -and $disarmed.CurrentHeld -eq 0
    } elseif ($SectionTeardown) {
        if ( -not $Verifier) { throw 'Section teardown qualification requires runtime Verifier.' }
        $result.Passed=Invoke-SectionTeardownScenario
    } else {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'SYSTEM required.' }
    if ((Get-FileHash $Inspector -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256 -or
        (Get-FileHash $ClientSource -Algorithm SHA256).Hash -ne $ExpectedClientSha256) { throw 'Exercise source/artifact hash mismatch.' }
    Add-Type -Path $ClientSource
    $file=[IO.FileStream]::new($Fixture,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    if ($file.Length -ne 4096) { throw 'Section fixture length mismatch.' }
    $client=[SafeUploadSectionFaultClient]::new()
    Assert-LowerAttachment
    Reset-UpperTrace
    $before=Get-UpperStats
    if ($before.sectionInFlightNow -ne 0) { throw 'Upper tracker was busy before failure test.' }
    $armed=$client.Send(1,$file.SafeFileHandle.DangerousGetHandle())
    if ($armed.Mode -ne 1 -or $armed.ArmedFileObject -eq 0 -or $armed.CurrentHeld -ne 0) { throw 'Failure arm not established.' }
    $mapping=[SafeUploadSectionFaultMapping]::new($file.SafeFileHandle)
    if ( -not $mapping.Wait(10000)) { throw 'Failure mapping did not finish.' }
    if ($mapping.WorkerError -or $mapping.Created -or $mapping.Error -eq 0) { throw 'Lower failure did not reject mapping.' }
    $failed=$client.Send(0,[IntPtr]::Zero)
    $after=Get-UpperStats
    $faultCount=[UInt64]$failed.Failed-[UInt64]$armed.Failed
    $entries=@(Get-UpperTrace 'failure' $armed.ArmedFileObject)
    $acquires=@($entries|Where-Object { $_.event -eq 'section_acquire' -and $_.syncType -eq 1 -and
        ([Convert]::ToUInt32($_.pageProtection.Substring(2),16) -band 0xCC) -ne 0 })
    $releases=@($entries|Where-Object event -eq 'section_release')
    if ($faultCount -lt 1 -or $acquires.Count -ne $faultCount -or $releases.Count -ne 0 -or
        ([UInt64]$after.sectionInFlightRemovedOnFailure-[UInt64]$before.sectionInFlightRemovedOnFailure) -ne $faultCount -or
        ([UInt64]$after.sectionInFlightInserted-[UInt64]$before.sectionInFlightInserted) -ne $faultCount -or
        ([UInt64]$after.sectionInFlightReleased-[UInt64]$before.sectionInFlightReleased) -ne 0 -or
        $after.sectionInFlightNow -ne 0 -or $failed.TimedOut -ne $armed.TimedOut -or $failed.InvalidIrql -ne $armed.InvalidIrql) {
        throw 'Failed lower acquire did not match exact-FO upper cleanup.'
    }
    $result.Failure=@{Before=$before;After=$after;Arm=$armed;State=$failed;NativeError=$mapping.Error;FaultCount=$faultCount}
    [void]$client.Send(4,[IntPtr]::Zero)
    $mapping=[SafeUploadSectionFaultMapping]::new($file.SafeFileHandle)
    if ( -not $mapping.Wait(10000) -or $mapping.WorkerError -or -not $mapping.Created) { throw 'Mapping did not recover after disarm.' }

    Assert-LowerAttachment
    Reset-UpperTrace
    $before=Get-UpperStats
    if ($before.sectionInFlightNow -ne 0) { throw 'Upper tracker was busy before hold test.' }
    $armed=$client.Send(2,$file.SafeFileHandle.DangerousGetHandle())
    $mapping=[SafeUploadSectionFaultMapping]::new($file.SafeFileHandle)
    $deadline=[DateTime]::UtcNow.AddSeconds(5)
    do {
        $held=$client.Send(0,[IntPtr]::Zero)
        $holdEstablished=$held.CurrentHeld -eq 1 -and $held.Held -gt $armed.Held -and
            $held.ArmGeneration -eq $armed.ArmGeneration -and $held.ArmedFileObject -eq $armed.ArmedFileObject -and
            -not $mapping.Wait(0)
        if ( -not $holdEstablished) { Start-Sleep -Milliseconds 10 }
    } while ( -not $holdEstablished -and [DateTime]::UtcNow -lt $deadline)
    if ($held.CurrentHeld -ne 1 -or $held.Held -le $armed.Held -or $held.ArmGeneration -ne $armed.ArmGeneration -or
        $held.ArmedFileObject -ne $armed.ArmedFileObject -or $mapping.Wait(0)) { throw 'Exact-FO hold not established.' }
    # These inspector modes only read resident counters/trace; no file-ID S probe is allowed here.
    $during=Get-UpperStats -AllowIntentionalHold
    $entries=@(Get-UpperTrace 'held' $armed.ArmedFileObject)
    $acquires=@($entries|Where-Object { $_.event -eq 'section_acquire' -and $_.syncType -eq 1 -and
        ([Convert]::ToUInt32($_.pageProtection.Substring(2),16) -band 0xCC) -ne 0 })
    $stillHeld=$client.Send(0,[IntPtr]::Zero)
    if ($during.sectionInFlightNow -ne 1 -or $acquires.Count -ne 1 -or $stillHeld.CurrentHeld -ne 1 -or
        $stillHeld.ArmedFileObject -ne $armed.ArmedFileObject -or $mapping.Wait(0) -or
        $stillHeld.ArmGeneration -ne $armed.ArmGeneration -or $stillHeld.TimedOut -ne $armed.TimedOut) {
        throw 'Upper C>0 was not observed during the exact-FO hold.'
    }
    [void]$client.Send(3,[IntPtr]::Zero)
    if ( -not $mapping.Wait(10000) -or $mapping.WorkerError -or -not $mapping.Created) { throw 'Held mapping did not complete after release.' }
    $after=Get-UpperStats
    $released=$client.Send(0,[IntPtr]::Zero)
    if ($after.sectionInFlightNow -ne 0 -or
        ([UInt64]$after.sectionInFlightInserted-[UInt64]$before.sectionInFlightInserted) -ne 1 -or
        ([UInt64]$after.sectionInFlightReleased-[UInt64]$before.sectionInFlightReleased) -ne 1 -or
        $after.sectionInFlightRemovedOnFailure -ne $before.sectionInFlightRemovedOnFailure -or
        $released.CurrentHeld -ne 0 -or $released.TimedOut -ne $armed.TimedOut -or $released.InvalidIrql -ne $armed.InvalidIrql) {
        throw 'Held acquire/release did not conserve upper C.'
    }
    $result.Hold=@{Before=$before;During=$during;After=$after;Arm=$armed;Held=$stillHeld;Released=$released}
    if ($Capacity) {
        # Intentionally exceed the production table's 64 slots. This is a separate
        # negative qualification: overflow must remain Unknown after all native work drains.
        Assert-LowerAttachment
        Reset-UpperTrace
        $capacityBefore=Get-UpperStats
        if ($capacityBefore.sectionInFlightNow -ne 0) { throw 'Tracker busy before capacity test.' }
        $capacityArm=$client.Send(2,$file.SafeFileHandle.DangerousGetHandle())
        for ($index=0;$index -lt 66;$index++) {
            $capacityMappings += [SafeUploadSectionFaultMapping]::new($file.SafeFileHandle)
        }
        $deadline=[DateTime]::UtcNow.AddSeconds(10)
        do {
            $capacityHeld=$client.Send(0,[IntPtr]::Zero)
            $established=$capacityHeld.CurrentHeld -eq 66 -and ($capacityHeld.Held-$capacityArm.Held) -eq 66 -and
                $capacityHeld.ArmedFileObject -eq $capacityArm.ArmedFileObject -and
                $capacityHeld.ArmGeneration -eq $capacityArm.ArmGeneration
            if ( -not $established) { Start-Sleep -Milliseconds 10 }
        } while ( -not $established -and [DateTime]::UtcNow -lt $deadline)
        if ( -not $established) { throw 'Capacity callbacks did not establish the exact-FO hold.' }
        foreach ($worker in $capacityMappings) { if ($worker.Wait(0)) { throw 'Capacity mapping escaped hold.' } }
        $capacityDuring=Read-UpperStats
        $capacityEntries=@(Get-UpperTrace 'capacity-held' $capacityArm.ArmedFileObject)
        $capacityAcquires=@($capacityEntries|Where-Object { $_.event -eq 'section_acquire' -and $_.syncType -eq 1 -and
            ([Convert]::ToUInt32($_.pageProtection.Substring(2),16) -band 0xCC) -ne 0 })
        $capacityStillHeld=$client.Send(0,[IntPtr]::Zero)
        if ($capacityAcquires.Count -ne 66 -or $capacityDuring.writerState -ne $true -or
            $capacityDuring.sectionInFlightOverflow -le $capacityBefore.sectionInFlightOverflow -or
            $capacityDuring.sectionInFlightNow -le 0 -or $capacityDuring.sectionInFlightNow -gt 64 -or
            $capacityStillHeld.CurrentHeld -ne 66 -or $capacityStillHeld.ArmedFileObject -ne $capacityArm.ArmedFileObject -or
            $capacityStillHeld.ArmGeneration -ne $capacityArm.ArmGeneration -or
            $capacityStillHeld.TimedOut -ne $capacityArm.TimedOut -or $capacityStillHeld.InvalidIrql -ne $capacityArm.InvalidIrql) {
            throw 'Intentional table overflow was not attributable to the held callbacks.'
        }
        [void]$client.Send(3,[IntPtr]::Zero)
        $drainDeadline=[DateTime]::UtcNow.AddSeconds(10)
        foreach ($worker in $capacityMappings) {
            $remaining=[Math]::Max(0,[int]($drainDeadline-[DateTime]::UtcNow).TotalMilliseconds)
            if ( -not $worker.Wait($remaining) -or $worker.WorkerError -or -not $worker.Created) { throw 'Capacity native worker did not drain successfully.' }
        }
        $capacityReleased=$client.Send(0,[IntPtr]::Zero)
        if ($capacityReleased.CurrentHeld -ne 0 -or $capacityReleased.TimedOut -ne $capacityArm.TimedOut -or
            $capacityReleased.InvalidIrql -ne $capacityArm.InvalidIrql) { throw 'Capacity lower callbacks did not drain.' }
        [void]$client.Send(4,[IntPtr]::Zero)
        # A later successful mapping must not clear sticky uncertainty.
        $mapping=[SafeUploadSectionFaultMapping]::new($file.SafeFileHandle)
        if ( -not $mapping.Wait(10000) -or $mapping.WorkerError -or -not $mapping.Created) { throw 'Post-overflow mapping did not succeed.' }
        $capacityAfter=Read-UpperStats
        if ($capacityAfter.sectionInFlightOverflow -lt $capacityDuring.sectionInFlightOverflow -or
            $capacityAfter.sectionInFlightNow -ne $capacityDuring.sectionInFlightNow -or
            $capacityAfter.sectionInFlightRemovedOnFailure -ne $capacityBefore.sectionInFlightRemovedOnFailure) { throw 'Overflow uncertainty did not remain sticky.' }
        # File-ID S/H/C probes are allowed only after every held callback and mapping has drained.
        Reset-UpperTrace
        [void][SafeUploadSectionFaultClient]::Inspector($Inspector,('--admission-probe "'+$Fixture+'"'))
        [void](Get-UpperTrace 'capacity-probe' $capacityArm.ArmedFileObject)
        $probeRows=@($traces['capacity-probe'] -split '[\r\n]+'|Where-Object { $_.Trim().Length -gt 0 }|ForEach-Object { $_|ConvertFrom-Json })
        $probes=@($probeRows|Where-Object event -eq 'explicit_probe')
        if ($probes.Count -ne 1 -or $probes[0].probeStatus -ne '0x00000000' -or $probes[0].probeStage -ne 8 -or
            $probes[0].pid -ne 4 -or $probes[0].irql -ne 0 -or
            ([UInt64]$probes[0].inFlightSections -band [UInt64]2147483648) -eq 0) { throw 'Post-drain C probe did not report sticky Unknown.' }
        $result.Capacity=@{Workers=66;Before=$capacityBefore;During=$capacityDuring;After=$capacityAfter;
            Arm=$capacityArm;Held=$capacityStillHeld;Released=$capacityReleased;Probe=$probes[0];StickyUnknown=$true}
    }
    $result.Passed=$true
    }
} catch { $exerciseError=$_.Exception.ToString(); $result.Errors+= $exerciseError }
finally {
    if ($client) {
        try { $result.Disarmed=$client.Send(4,[IntPtr]::Zero) }
        catch { $result.Errors+='Disarm: '+$_.Exception.Message }
    }
    if ($mapping -and -not $mapping.Wait(10000)) { $result.Errors+='Mapping worker did not drain.' }
    $drainDeadline=[DateTime]::UtcNow.AddSeconds(10)
    foreach ($worker in $capacityMappings) {
        $remaining=[Math]::Max(0,[int]($drainDeadline-[DateTime]::UtcNow).TotalMilliseconds)
        if ( -not $worker.Wait($remaining)) { $result.Errors+='Capacity mapping worker did not drain.' }
    }
    if ($file) { try { $file.Dispose() } catch { $result.Errors+='File dispose: '+$_.Exception.Message } }
    if ($client) { try { $client.Dispose() } catch { $result.Errors+='Port dispose: '+$_.Exception.Message } }
    foreach($name in $traces.Keys) { [IO.File]::WriteAllText($TracePrefix+'-'+$name+'.jsonl',$traces[$name]) }
    if ($result.Errors.Count -ne 0) { $result.Passed=$false }
    $json=$result|ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($ResultPath+'.next',$json)
    Move-Item -LiteralPath ($ResultPath+'.next') -Destination $ResultPath
    Write-Output $json
}
if ( -not $result.Passed) { exit 1 }
