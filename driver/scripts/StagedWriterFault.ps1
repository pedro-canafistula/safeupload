<# SYSTEM qualification exercise, launched only by the checkpointed admission harness. #>
param([Parameter(Mandatory)][string]$Target,[Parameter(Mandatory)][string]$Healthy,
    [Parameter(Mandatory)][string]$Executable,[Parameter(Mandatory)][string]$Inspector,
    [Parameter(Mandatory)][string]$ClientSource,[Parameter(Mandatory)][string]$RawPrefix,
    [Parameter(Mandatory)][string]$ExpectedClientSha256,[Parameter(Mandatory)][string]$ExpectedExecutableSha256,
    [Parameter(Mandatory)][string]$ExpectedInspectorSha256)
$ErrorActionPreference='Stop'
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'SYSTEM required.'}
foreach($item in @(@($Executable,$ExpectedExecutableSha256),@($Inspector,$ExpectedInspectorSha256),@($ClientSource,$ExpectedClientSha256))){
    if((Get-FileHash $item[0] -Algorithm SHA256).Hash -ne $item[1]){throw 'Writer fault source/artifact pin mismatch.'}
}
Add-Type -Path $ClientSource
function ConvertTo-WindowsArgument([string]$Value){
    if($Value.Contains('"') -or $Value.Contains("`r") -or $Value.Contains("`n")){throw 'Invalid qualification argument.'}
    return '"'+$Value+'"'
}
function Get-WriterStateStats {
    return ([SafeUploadSectionFaultClient]::Inspector($Inspector,'--writer-state-status')|ConvertFrom-Json)
}
function Invoke-StagedWriterFaultQualification([string]$Target,[string]$Healthy,[string]$Executable,[string]$RawPrefix) {
    $result=[ordered]@{Passed=$false;PoolTag='SUwH';Application='SUHFail.exe';Errors=@();Probes=@()}
    $workers=New-Object System.Collections.ArrayList
    $pins=New-Object System.Collections.ArrayList
    $faultsMayBeEnabled=$false; $rawRecords=@{}
    function Assert-FaultConfiguration([string]$Raw,[int]$ExitCode) {
        if($ExitCode -ne 0){throw 'Verifier fault configuration failed.'}
        foreach($field in @(@('Probability','10000'),@('Pool Tags','SUwH'),@('Applications','SUHFail.exe'),@('Delay Minutes','0'))){
            $matches=[regex]::Matches($Raw,('(?im)^\s*'+[regex]::Escape($field[0])+':\s*([^\r\n]+)\s*$'))
            if($matches.Count -ne 1 -or $matches[0].Groups[1].Value.Trim() -cne $field[1]){throw 'Verifier did not confirm exact fault filters.'}
        }
    }
    function Read-FaultVerifier([string]$Label,[bool]$ExpectedFaults) {
        $raw=& verifier.exe /query 2>&1|Out-String
        if($LASTEXITCODE -ne 0){throw 'Active Verifier query failed.'}
        $rawRecords[$Label+'-verifier.txt']=$raw
        $flags=[regex]::Matches($raw,'(?im)^Verifier Flags:\s+0x([0-9A-F]+)\s*$')
        $counter=[regex]::Matches($raw,'(?im)^\s*Pool Allocations Failed Deliberately:\s+([0-9]+)\s*$')
        $modules=[regex]::Matches($raw,'(?im)^\s*MODULE:\s+(\S+)\s+\(')
        if($flags.Count -ne 1 -or $counter.Count -ne 1 -or $modules.Count -ne 1 -or $modules[0].Groups[1].Value -ne 'SafeUpload.sys'){throw 'Verifier inventory or counters ambiguous.'}
        $value=[Convert]::ToUInt32($flags[0].Groups[1].Value,16)
        # Win10 19045 (runs 2-3): /volatile /faults replaces the active flags with 0x4 and /volatile /flags resets the
        # filters, so the armed window is LRS-only. Every window with injection off must still read the full 0x13B.
        if((($value -band 4) -ne 0) -ne $ExpectedFaults -or (-not $ExpectedFaults -and ($value -band 0x13B) -ne 0x13B)){throw 'Active Verifier flags mismatch.'}
        return @{Flags=$value;Faults=[UInt64]$counter[0].Groups[1].Value}
    }
    function Assert-FaultProbe([string]$Path,[string]$Label,[int]$Count,[bool]$Unknown,[string]$ExpectedSop='') {
        [void][SafeUploadSectionFaultClient]::Inspector($Inspector,'--admission-trace-clear')
        [void][SafeUploadSectionFaultClient]::Inspector($Inspector,('--admission-probe "'+$Path+'"'))
        $raw=[SafeUploadSectionFaultClient]::Inspector($Inspector,'--admission-trace')
        $rawRecords[$Label+'-probe.jsonl']=$raw
        $rows=@($raw -split '[\r\n]+'|Where-Object {$_.Trim().Length -gt 0}|ForEach-Object {$_|ConvertFrom-Json})
        $probes=@($rows|Where-Object event -eq 'explicit_probe');$summary=@($rows|Where-Object summary -eq $true)
        if($summary.Count -ne 1 -or $summary[0].lostEntries -ne 0 -or $summary[0].cursor -ne ([UInt64]$summary[0].snapshotSequence+1) -or
            $probes.Count -ne 1 -or $probes[0].probeStatus -ne '0x00000000' -or $probes[0].probeStage -ne 8 -or
            $probes[0].pid -ne 4 -or $probes[0].irql -ne 0 -or $probes[0].writeObjects -ne $Count -or
            $probes[0].writersUntracked -ne $Unknown -or $probes[0].mmDoes -ne 'no' -or $probes[0].inFlightSections -ne 0 -or
            $probes[0].canaryState -ne 2 -or $probes[0].canaryChecks -ne 7 -or
            ($ExpectedSop -and $probes[0].sectionObjectPointer -ne $ExpectedSop)){throw ('Writer-fault probe mismatch: '+$Label)}
        $result.Probes+=@{Label=$Label;Probe=$probes[0]}
        return $probes[0]
    }
    function Start-FaultWriter {
        $nonce=[guid]::NewGuid().ToString('N')
        $worker=[pscustomobject]@{Events=@();Process=$null;Identity='';Stderr=$null};[void]$workers.Add($worker)
        foreach($suffix in @('start','ready','close')){$worker.Events+=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,('Local\SafeUpload-HFault-'+$nonce+'-'+$suffix))}
        $arguments=@($Target,('Local\SafeUpload-HFault-'+$nonce+'-start'),('Local\SafeUpload-HFault-'+$nonce+'-ready'),('Local\SafeUpload-HFault-'+$nonce+'-close'))
        $start=[Diagnostics.ProcessStartInfo]::new($Executable,((@($arguments|ForEach-Object {ConvertTo-WindowsArgument $_})) -join ' '))
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        $worker.Process=[Diagnostics.Process]::Start($start);[void]$worker.Process.Handle
        $worker.Stderr=$worker.Process.StandardError.ReadToEndAsync()
        $initialized=$worker.Process.StandardOutput.ReadLineAsync()
        if(-not $initialized.Wait(5000) -or $initialized.Result -ne 'FixtureInitialized=True'){throw 'Writer fixture failed to initialize before injection.'}
        return $worker
    }
    function Open-FaultWriter($Worker,[string]$Identity) {
        [void]$Worker.Events[0].Set()
        if(-not $Worker.Events[1].WaitOne(5000)){throw 'Writer fixture did not open target.'}
        $line=$Worker.Process.StandardOutput.ReadLineAsync()
        if(-not $line.Wait(5000) -or $line.Result -ne ('FixtureOpen=True;Error=0;Identity='+$Identity)){throw 'Writer fixture identity/open mismatch.'}
        $Worker.Identity=$Identity
    }
    function Close-FaultWriter($Worker) {
        [void]$Worker.Events[2].Set()
        if(-not $Worker.Process.WaitForExit(5000) -or $Worker.Process.get_ExitCode() -ne 0 -or
            -not $Worker.Stderr.Wait(5000) -or $Worker.Stderr.Result.Length -ne 0){throw 'Writer fixture did not close cleanly.'}
        $remaining=$Worker.Process.StandardOutput.ReadToEndAsync()
        if(-not $remaining.Wait(5000) -or $remaining.Result.Trim() -ne 'FixtureClosed=True'){throw 'Writer fixture close proof missing.'}
    }
    try {
        foreach($path in @($Target,$Healthy)){
            $pin=[SafeUploadSectionFaultClient]::OpenAttributes($path)
            [void]$pins.Add($pin);if($pin.IsInvalid){throw 'Attribute-only identity pin failed.'}
        }
        $identity=[SafeUploadSectionFaultClient]::Identity($pins[0]);$result.TargetIdentity=$identity
        $targetBefore=Assert-FaultProbe $Target 'target-before' 0 $false
        $healthyBefore=Assert-FaultProbe $Healthy 'healthy-before' 0 $false
        if($targetBefore.sectionObjectPointer -eq $healthyBefore.sectionObjectPointer){throw 'Control stream aliases target.'}
        $first=Start-FaultWriter
        $statsBefore=Get-WriterStateStats
        $verifierBefore=Read-FaultVerifier 'before' $false
        $faultsMayBeEnabled=$true
        $configuration=& verifier.exe /volatile /faults 10000 SUwH SUHFail.exe 0 2>&1|Out-String
        $configurationExit=$LASTEXITCODE;$rawRecords['fault-configuration.txt']=$configuration
        Assert-FaultConfiguration $configuration $configurationExit
        # Do not follow /faults with /volatile /flags: on this Windows build (run 2) that resets the
        # filters to 600/(null)/(null)/8. The armed query must show LRS active; its flags are recorded as evidence.
        $verifierArmed=Read-FaultVerifier 'armed' $true
        Open-FaultWriter $first $identity
        $statsFailed=Get-WriterStateStats
        $verifierFailed=Read-FaultVerifier 'failed-open' $true
        [void](Assert-FaultProbe $Target 'target-failed-open' 0 $true $targetBefore.sectionObjectPointer)
        if(($verifierFailed.Faults-$verifierArmed.Faults) -ne 1 -or
            ([UInt64]$statsFailed.untrackedCreates-[UInt64]$statsBefore.untrackedCreates) -ne 1 -or
            $statsFailed.writeObjectsCounted -ne $statsBefore.writeObjectsCounted -or
            $statsFailed.writeObjectsReleased -ne $statsBefore.writeObjectsReleased){throw 'Injected node allocation failure was not isolated.'}
        & verifier.exe /volatile /flags 0x13B|Out-Host
        if($LASTEXITCODE -ne 0){throw 'Low resources disable failed.'}
        $verifierDisabled=Read-FaultVerifier 'disabled' $false;$faultsMayBeEnabled=$false
        $second=Start-FaultWriter;Open-FaultWriter $second $identity
        [void](Assert-FaultProbe $Target 'target-later-writer' 1 $true $targetBefore.sectionObjectPointer)
        Close-FaultWriter $first
        [void](Assert-FaultProbe $Target 'target-first-cleanup' 1 $true $targetBefore.sectionObjectPointer)
        Close-FaultWriter $second
        [void](Assert-FaultProbe $Target 'target-final-cleanup' 0 $true $targetBefore.sectionObjectPointer)
        $statsAfter=Get-WriterStateStats
        if(([UInt64]$statsAfter.writeObjectsCounted-[UInt64]$statsFailed.writeObjectsCounted) -ne 1 -or
            ([UInt64]$statsAfter.writeObjectsReleased-[UInt64]$statsFailed.writeObjectsReleased) -ne 1 -or
            $statsAfter.untrackedCreates -ne $statsFailed.untrackedCreates){throw 'Real writer did not conserve its counted node.'}
        $healthyWriter=[IO.FileStream]::new($Healthy,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        try {[void](Assert-FaultProbe $Healthy 'healthy-live' 1 $false $healthyBefore.sectionObjectPointer)}finally{$healthyWriter.Dispose()}
        [void](Assert-FaultProbe $Healthy 'healthy-final' 0 $false $healthyBefore.sectionObjectPointer)
        $result.Before=$statsBefore;$result.Failed=$statsFailed;$result.After=$statsAfter
        $result.Verifier=@{Before=$verifierBefore;Armed=$verifierArmed;Failed=$verifierFailed;Disabled=$verifierDisabled}
        $result.Passed=$true
    }catch{$result.Errors+=$_.Exception.ToString()}
    finally {
        # Disable injection before terminating fixture processes, disposing pins or unloading.
        if($faultsMayBeEnabled){
            try {& verifier.exe /volatile /flags 0x13B|Out-Host;if($LASTEXITCODE -ne 0){throw 'Fault flag clear failed.'};[void](Read-FaultVerifier 'cleanup-disabled' $false)}
            catch{$result.Errors+='Disable fault injection: '+$_.Exception.Message}
        }
        foreach($worker in $workers){
            if($worker.Process){
                try{[void]$worker.Events[2].Set();if(-not $worker.Process.HasExited){if(-not $worker.Process.WaitForExit(5000)){$worker.Process.Kill();if(-not $worker.Process.WaitForExit(5000)){throw 'Writer process did not terminate.'}}}}
                catch{$result.Errors+='Writer cleanup: '+$_.Exception.Message}
                finally{try{$worker.Process.Dispose()}catch{$result.Errors+='Writer process disposal: '+$_.Exception.Message}}
            }
            foreach($event in $worker.Events){try{$event.Dispose()}catch{$result.Errors+='Writer event disposal: '+$_.Exception.Message}}
        }
        foreach($pin in $pins){try{$pin.Dispose()}catch{$result.Errors+='Attribute pin disposal: '+$_.Exception.Message}}
        if($result.Errors.Count){$result.Passed=$false}
        # All evidence file writes occur after measured opens/probes and injection cleanup.
        foreach($leaf in $rawRecords.Keys){try{[IO.File]::WriteAllText($RawPrefix+'-'+$leaf,$rawRecords[$leaf])}catch{$result.Errors+='Evidence write '+$leaf+': '+$_.Exception.Message}}
        if($result.Errors.Count){$result.Passed=$false}
        $json=$result|ConvertTo-Json -Depth 10;[IO.File]::WriteAllText($RawPrefix+'-result.json',$json)
        Write-Output ('WriterFaultResult='+($result|ConvertTo-Json -Depth 10 -Compress))
        Write-Output ('WriterFaultRawPrefix='+$RawPrefix)
    }
    if(-not $result.Passed){throw 'Real writer-node allocation failure qualification failed.'}
    Write-Output 'WriterFaultQualification=PASS'
}

try { Invoke-StagedWriterFaultQualification $Target $Healthy $Executable $RawPrefix } catch { Write-Error $_; exit 1 }
