#requires -Version 7.5
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EvidenceDirectory,
    [ValidatePattern('^[a-zA-Z0-9-]*$')][string]$Prefix='',
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($EvidenceDirectory).TrimEnd([IO.Path]::DirectorySeparatorChar)
$output=[IO.Path]::GetFullPath($OutputPath)
if($output.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase) -or $output -eq $root){throw 'Output must be outside the evidence directory.'}
if(Test-Path -LiteralPath $output){throw 'Output already exists.'}
$installed=Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'SafeUpload'
if($root.Equals($installed,[StringComparison]::OrdinalIgnoreCase) -or $root.StartsWith($installed+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Installed data refused.'}
for($d=[IO.DirectoryInfo]::new($root);$null -ne $d;$d=$d.Parent){if($d.Exists -and ($d.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse ancestor refused.'}}
if($output.StartsWith($installed+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Installed output refused.'}
for($d=[IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($output));$null -ne $d;$d=$d.Parent){if($d.Exists -and ($d.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Reparse output ancestor refused.'}}
$issues=[Collections.Generic.List[string]]::new()
$inputs=@{}
$state=@{samples=0L;firstMs=$null;terminalMs=$null;lastMs=0.0;lastCpu=0.0;lastEvents=0L;lastEventAck=0L;lastOverrideAck=0L;maxGapMs=0.0;gapCount=0L;maxWorkingSetBytes=0L;maxPrivateBytes=0L;minFreeBytes=[long]::MaxValue;maxQueueBytes=0L;utcBacksteps=0L;lastUtc=$null;append=0L;ackEvents=0L;ackOverrides=0L;maxOperationMs=0.0}
$gaps=[Collections.Generic.List[object]]::new()
$receipt=$null
function InputFile([string]$name,[bool]$required=$true){
    if($name -notmatch '^[a-zA-Z0-9_.-]+$' -or $name -in @('.','..')){throw 'Unsafe manifest filename.'}
    $path=Join-Path $root ($Prefix+$name)
    if(-not (Test-Path -LiteralPath $path -PathType Leaf)){if($required){throw ('Missing input: '+$name)};return $null}
    $file=Get-Item -LiteralPath $path -Force
    if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse input refused.'}
    # Stream traces, but bound total work and an individual line before parsing it.
    if($file.Length -gt 268435456){throw 'Input exceeds the 256 MiB analysis limit.'}
    $inputs[$name]=[ordered]@{file=$Prefix+$name;bytes=$file.Length;sha256=(Get-FileHash -LiteralPath $path).Hash}
    return $path
}
function Number($record,[string]$name,[bool]$integer=$false){
    $v=$record.$name
    if(-not ($v -is [long] -or $v -is [int] -or $v -is [double] -or $v -is [decimal]) -or
        -not [double]::IsFinite([double]$v) -or $v -lt 0 -or ($integer -and [math]::Floor($v) -ne $v)){throw ('Invalid numeric field: '+$name)}
    return $v
}
function Lines([string]$path,[scriptblock]$visit){
    $reader=[IO.StreamReader]::new($path,[Text.UTF8Encoding]::new($false,$true))
    try{
        # Read bounded characters: ReadLine alone could allocate a very large malformed line.
        $line=[Text.StringBuilder]::new()
        while(($c=$reader.Read()) -ne -1){
            if($c -eq 10){
                if($line.Length -eq 0){throw 'Blank trace line.'}
                $record=$line.ToString() | ConvertFrom-Json -DateKind String
                if($null -eq $record -or $record -is [array]){throw 'Invalid trace object.'}
                & $visit $record
                [void]$line.Clear()
            }else{
                if($line.Length -ge 65536){throw 'Trace line exceeds 64 Ki characters.'}
                [void]$line.Append([char]$c)
            }
        }
        if($line.Length -ne 0){throw 'Unterminated trace tail.'}
    }finally{$reader.Dispose()}
}
function Gap([string]$kind,[double]$from,[double]$to){
    $gap=$to-$from
    $state.maxGapMs=[math]::Max($state.maxGapMs,$gap)
    if($gap -gt $script:intervalMs){
        $state.gapCount++
        if($gaps.Count -lt 20){$gaps.Add([ordered]@{kind=$kind;fromMs=$from;toMs=$to;gapMs=$gap;excessOverIntervalMs=$gap-$script:intervalMs})}
    }
}
try{
    $profilePath=InputFile 'profile.json'
    $profile=Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json -DateKind String
    $script:intervalMs=Number $profile 'sampleIntervalMs' $true
    if($script:intervalMs -le 0){throw 'Invalid collection interval.'}
    $receiptPath=InputFile 'result.json' $false
    if($receiptPath){
        $receipt=Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json -DateKind String
        if($receipt.status -notin @('passed','incomplete')){throw 'Unknown receipt status.'}
        if($receipt.profileSha256 -cne $inputs['profile.json'].sha256){throw 'Profile hash mismatch.'}
        $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        if(@($receipt.files).Count -eq 0){throw 'Empty receipt manifest.'}
        foreach($entry in $receipt.files){
            if(-not $seen.Add($entry.file)){throw 'Duplicate manifest filename.'}
            [void](InputFile $entry.file)
            if($inputs[$entry.file].bytes -ne $entry.bytes -or $inputs[$entry.file].sha256 -cne $entry.sha256){throw 'Receipt manifest mismatch.'}
        }
        if($receipt.status -eq 'passed'){
            foreach($required in @('queue.jsonl','profile.json','samples.jsonl','operations.jsonl','synthetic.marker')){if(-not $seen.Contains($required)){throw 'Incomplete passed manifest.'}}
        }
    }
    $samplesPath=InputFile 'samples.jsonl'
    Lines $samplesPath {
        param($r)
        $at=Number $r 'elapsedMs'
        $cpu=Number $r 'totalCpuMs'
        $events=Number $r 'events' $true
        $ack=Number $r 'eventAck' $true
        $overrides=Number $r 'overrides' $true
        $oack=Number $r 'overrideAck' $true
        if($at -lt $state.lastMs -or $cpu -lt $state.lastCpu -or $events -lt $state.lastEvents -or $ack -lt $state.lastEventAck -or $oack -lt $state.lastOverrideAck){throw 'Nonmonotonic trace counters.'}
        if($ack -gt $events -or $oack -gt $overrides -or $overrides -ne [math]::Floor($events/10) -or
            (Number $r 'pendingEvents' $true) -ne $events-$ack -or (Number $r 'pendingOverrides' $true) -ne $overrides-$oack){throw 'Inconsistent pending counters.'}
        if($r.phase -notin @('offline','recovery','mixed')){throw 'Unknown sample phase.'}
        if($state.samples -eq 0){
            if($null -ne $r.intervalSincePreviousMs){throw 'Unexpected first sample interval.'}
            $state.firstMs=$at
            Gap 'initial' 0 $at
        }else{
            if([math]::Abs((Number $r 'intervalSincePreviousMs')-($at-$state.lastMs)) -gt 0.01){throw 'Sample interval mismatch.'}
            Gap 'between-samples' $state.lastMs $at
        }
        $utc=[DateTimeOffset]::Parse($r.utc,[Globalization.CultureInfo]::InvariantCulture)
        if($null -ne $state.lastUtc -and $utc -lt $state.lastUtc){$state.utcBacksteps++}
        $state.maxWorkingSetBytes=[math]::Max($state.maxWorkingSetBytes,(Number $r 'workingSetBytes' $true))
        $state.maxPrivateBytes=[math]::Max($state.maxPrivateBytes,(Number $r 'privateBytes' $true))
        $state.maxQueueBytes=[math]::Max($state.maxQueueBytes,(Number $r 'queueBytes' $true))
        $state.minFreeBytes=[math]::Min($state.minFreeBytes,(Number $r 'freeBytes' $true))
        $state.samples++;$state.lastMs=$at;$state.lastCpu=$cpu;$state.lastEvents=$events;$state.lastEventAck=$ack;$state.lastOverrideAck=$oack;$state.lastUtc=$utc
    }
    if($state.samples -eq 0){throw 'No complete samples.'}
    $opsPath=InputFile 'operations.jsonl'
    Lines $opsPath {
        param($r)
        $duration=Number $r 'elapsedMs'
        $state.maxOperationMs=[math]::Max($state.maxOperationMs,$duration)
        if($r.operation -eq 'append'){
            $state.append++
            if((Number $r 'index' $true) -ne $state.append){throw 'Append sequence mismatch.'}
        }elseif($r.operation -eq 'synthetic-ack'){
            $state.ackEvents+=Number $r 'events' $true
            $state.ackOverrides+=Number $r 'overrides' $true
        }else{throw 'Unknown operation.'}
    }
    if($receipt){
        $end=(Number $receipt 'elapsedSeconds')*1000
        if($end -lt $state.lastMs){throw 'Receipt ends before final sample.'}
        Gap 'terminal' $state.lastMs $end
        $state.terminalMs=$end-$state.lastMs
        if((Number $receipt 'samples' $true) -ne $state.samples -or
            (Number $receipt 'events' $true) -ne $state.append -or
            (Number $receipt 'eventAck' $true) -ne $state.ackEvents -or
            (Number $receipt 'overrideAck' $true) -ne $state.ackOverrides){throw 'Receipt/trace counter mismatch.'}
        if($state.lastEvents -gt $receipt.events -or $state.lastEventAck -gt $receipt.eventAck -or $state.lastOverrideAck -gt $receipt.overrideAck){throw 'Sample exceeds final receipt counters.'}
        if($receipt.status -eq 'passed'){
            if(@($receipt.phases).Count -ne 3 -or ($receipt.phases.phase -join ',') -cne 'offline,recovery,mixed'){throw 'Missing completed phases.'}
            $phaseSeconds=Number $profile 'phaseSeconds' $true
            if($phaseSeconds -le 0 -or $end -lt 3000*$phaseSeconds){throw 'Duration shorter than requested phases.'}
            foreach($phase in $receipt.phases){if($phase.metadataVerified -ne $true){throw 'Phase verification not declared.'}}
            $last=$receipt.phases[-1]
            if($last.events -ne $receipt.events -or $last.eventAck -ne $receipt.eventAck -or $last.overrideAck -ne $receipt.overrideAck){throw 'Final phase/receipt mismatch.'}
        }
    }
    # Evidence must remain stable while analyzed; no authenticity or adversarial race claim.
    foreach($name in @($inputs.Keys)){
        $path=Join-Path $root $inputs[$name].file
        if((Get-FileHash -LiteralPath $path).Hash -cne $inputs[$name].sha256){throw 'Evidence changed during analysis.'}
    }
}catch{$issues.Add($_.Exception.Message)}
$status=if($issues.Count -gt 0){'invalid-evidence'}elseif($null -eq $receipt -or $receipt.status -ne 'passed'){'incomplete-run'}else{'analyzed-completed-run'}
$report=[ordered]@{schemaVersion=1;status=$status;receiptPresent=($null -ne $receipt);originalRunStatus=if($receipt){$receipt.status}else{$null};issues=@($issues.ToArray());samples=$state.samples;collectionIntervalMs=$script:intervalMs;initialGapMs=$state.firstMs;terminalGapMs=if($issues.Count -eq 0){$state.terminalMs}else{$null};maxObservedGapMs=$state.maxGapMs;gapsOverInterval=$state.gapCount;gapDetails=@($gaps.ToArray());gapDetailsTruncated=($state.gapCount -gt $gaps.Count);terminalGapKnown=($null -ne $receipt -and $issues.Count -eq 0);utcBacksteps=$state.utcBacksteps;maxSampledWorkingSetBytes=$state.maxWorkingSetBytes;maxSampledPrivateBytes=$state.maxPrivateBytes;minSampledFreeBytes=if($state.samples){$state.minFreeBytes}else{$null};maxSampledQueueBytes=$state.maxQueueBytes;appendOperations=$state.append;syntheticallyAcknowledgedEvents=$state.ackEvents;syntheticallyAcknowledgedOverrides=$state.ackOverrides;maxLoggedOperationMs=$state.maxOperationMs;inputFiles=@($inputs.Values | Sort-Object file);qualificationGranted=$false;serviceQualified=$false;realApiQualified=$false;note='Read-only trace consistency analysis, not a replay of queue metadata, authenticity proof, uptime measurement or new product qualification. Every observed interval exceeding the configured sampling interval is counted without assigning a fault or SLA. Gaps include scheduler, logging, queue work and verification; the tail is unknown without a receipt. Resource peaks are sampled values of the whole harness, not process maxima or service-only use. Input limit 256 MiB/file, 64 Ki characters/trace line; use stable controlled synthetic evidence.'}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report | ConvertTo-Json -Depth 10))
$stream=[IO.File]::Open($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
Write-Output ($report | ConvertTo-Json -Depth 10)
if($issues.Count -gt 0){throw 'Evidence analysis failed; inspect the separate report.'}
