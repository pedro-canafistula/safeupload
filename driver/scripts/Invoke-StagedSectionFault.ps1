<# SYSTEM-side qualification exercise; launched by the checkpointed admission harness. #>
param([Parameter(Mandatory)][string]$Fixture,
    [Parameter(Mandatory)][string]$Inspector,
    [Parameter(Mandatory)][string]$ClientSource,
    [Parameter(Mandatory)][string]$ResultPath,
    [Parameter(Mandatory)][string]$TracePrefix,
    [Parameter(Mandatory)][string]$ExpectedInspectorSha256,
    [Parameter(Mandatory)][string]$ExpectedClientSha256)
$ErrorActionPreference='Stop'
$result=[ordered]@{ Passed=$false; Mode='live lower-stack resource-failure injection and bounded hold'; Errors=@() }
$client=$null; $file=$null; $mapping=$null; $traces=@{}; $exerciseError=$null
function Assert-LowerAttachment {
    $volume=[SafeUploadSectionFaultClient]::VolumeForHandle($file.SafeFileHandle)
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
function Get-UpperStats([switch]$AllowIntentionalHold) {
    $raw=[SafeUploadSectionFaultClient]::Inspector($Inspector,'--writer-state-status')
    $state=$raw|ConvertFrom-Json
    foreach($field in @('writerState','sectionInFlightNow','sectionInFlightInserted','sectionInFlightReleased',
        'sectionInFlightRemovedOnFailure','sectionInFlightOverflow','sectionInFlightStuck')) {
        if ($state.PSObject.Properties.Name -notcontains $field) { throw ('Missing upper status: '+$field) }
    }
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
try {
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
    if (-not $mapping.Wait(10000)) { throw 'Failure mapping did not finish.' }
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
    if (-not $mapping.Wait(10000) -or $mapping.WorkerError -or -not $mapping.Created) { throw 'Mapping did not recover after disarm.' }

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
        if (-not $holdEstablished) { Start-Sleep -Milliseconds 10 }
    } while (-not $holdEstablished -and [DateTime]::UtcNow -lt $deadline)
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
    if (-not $mapping.Wait(10000) -or $mapping.WorkerError -or -not $mapping.Created) { throw 'Held mapping did not complete after release.' }
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
    $result.Passed=$true
} catch { $exerciseError=$_.Exception.ToString(); $result.Errors+= $exerciseError }
finally {
    if ($client) {
        try { $result.Disarmed=$client.Send(4,[IntPtr]::Zero) }
        catch { $result.Errors+='Disarm: '+$_.Exception.Message }
    }
    if ($mapping -and -not $mapping.Wait(10000)) { $result.Errors+='Mapping worker did not drain.' }
    if ($file) { try { $file.Dispose() } catch { $result.Errors+='File dispose: '+$_.Exception.Message } }
    if ($client) { try { $client.Dispose() } catch { $result.Errors+='Port dispose: '+$_.Exception.Message } }
    foreach($name in $traces.Keys) { [IO.File]::WriteAllText($TracePrefix+'-'+$name+'.jsonl',$traces[$name]) }
    if ($result.Errors.Count -ne 0) { $result.Passed=$false }
    $json=$result|ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($ResultPath+'.next',$json)
    Move-Item -LiteralPath ($ResultPath+'.next') -Destination $ResultPath
    Write-Output $json
}
if (-not $result.Passed) { exit 1 }
