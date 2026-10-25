#requires -Version 7.5
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ProfilePath,
    [Parameter(Mandatory)][string]$OutputPath
)
$ErrorActionPreference='Stop'
$output=[IO.Path]::GetFullPath($OutputPath)
if(Test-Path -LiteralPath $output){throw 'Output already exists.'}
$reasons=[Collections.Generic.List[string]]::new()
$model=$null
$hash=$null
function Integer($object,[string]$name,[long]$min,[long]$max){
    $v=$object.$name
    if(-not ($v -is [long] -or $v -is [int]) -or $v -lt $min -or $v -gt $max){throw ('invalid-field:'+ $name)}
    return [long]$v
}
try{
    $path=(Resolve-Path -LiteralPath $ProfilePath).Path
    if((Get-Item -LiteralPath $path).Length -gt 65536){throw 'profile-too-large'}
    $hash=(Get-FileHash -LiteralPath $path).Hash
    $p=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -DateKind String
    $fields=@('phaseSeconds','writeIntervalMs','ackIntervalMs','sampleIntervalMs','batchSize','maxEvents','maxOutputBytes','minFreeBytes','seed')
    if(@($p.PSObject.Properties.Name | Where-Object {$_ -cnotin $fields}).Count -ne 0){throw 'unknown-profile-field'}
    $phase=Integer $p 'phaseSeconds' 1 86400
    $write=Integer $p 'writeIntervalMs' 10 60000
    $ack=Integer $p 'ackIntervalMs' 10 60000
    $sample=Integer $p 'sampleIntervalMs' 10 900000
    $batch=Integer $p 'batchSize' 1 1000
    $maxEvents=Integer $p 'maxEvents' 1 1000000
    $maxOutput=Integer $p 'maxOutputBytes' 1048576 10737418240
    [void](Integer $p 'minFreeBytes' 2147483648 ([long]::MaxValue))
    if($p.seed -isnot [string] -or [string]::IsNullOrWhiteSpace($p.seed) -or $p.seed.Length -gt 128){throw 'invalid-field:seed'}
    # One extra action per phase allows for the loop entering just before its
    # deadline, then executing an operation after a budget/scheduling delay.
    $perProducerPhase=[long][math]::Ceiling($phase*1000.0/$write)+1
    $events=2*$perProducerPhase
    $overrides=[long][math]::Floor($events/10.0)
    $ackCyclesPerPhase=[long][math]::Ceiling($phase*1000.0/$ack)+1
    $ackCycles=2*$ackCyclesPerPhase
    $samples=3*([long][math]::Ceiling($phase*1000.0/$sample)+1)
    # Deliberately padded model for the current fixed synthetic payload. These
    # are sizing assumptions, not limits enforced by the writer/serializer.
    $queueBytes=$events*2048L+$overrides*1024L
    $operationBytes=($events+$ackCycles)*1024L
    $sampleBytes=$samples*2048L
    $overhead=2097152L
    $total=$queueBytes+$operationBytes+$sampleBytes+$overhead
    $analysisLimit=268435456L
    if($events -gt $maxEvents){$reasons.Add('event-budget-below-modeled-demand')}
    if($total -ge $maxOutput){$reasons.Add('output-budget-below-modeled-demand')}
    if($queueBytes -gt $analysisLimit -or $operationBytes -gt $analysisLimit -or $sampleBytes -gt $analysisLimit){$reasons.Add('analysis-file-limit-exceeded')}
    $offlineOverrides=[long][math]::Floor($perProducerPhase/10.0)
    $drainCycles=[long][math]::Ceiling($perProducerPhase/[double]$batch)
    if($drainCycles -gt $ackCyclesPerPhase -or [math]::Ceiling($offlineOverrides/[double]$batch) -gt $ackCyclesPerPhase){$reasons.Add('nominal-recovery-capacity-insufficient')}
    if($batch/[double]$ack -lt 1.0/$write){$reasons.Add('nominal-mixed-consumer-below-producer')}
    $model=[ordered]@{
        modelVersion=1;requestedActiveSeconds=3*$phase;requestedActiveHours=3*$phase/3600.0
        eventsPerProducerPhaseUpper=$perProducerPhase;totalEventsUpper=$events;overridesUpper=$overrides
        collectionSamplesUpper=$samples;ackCyclesUpper=$ackCycles
        assumedEventLineBytes=2048;assumedOverrideLineBytes=1024;assumedOperationLineBytes=1024;assumedSampleLineBytes=2048
        queueBytesUpperUnderAssumptions=$queueBytes;operationsBytesUpperUnderAssumptions=$operationBytes;samplesBytesUpperUnderAssumptions=$sampleBytes
        totalBytesIncludingMetadataReserve=$total;outputBudgetBytes=$maxOutput;outputMarginBytes=$maxOutput-$total
        analyzerPerFileLimitBytes=$analysisLimit;maxTemporaryQueueBytesUnderAssumptions=$queueBytes
        rewriteDestinationBytesVeryLooseUpper=2*$ackCycles*$queueBytes
        nominalRecoveryCycles=$drainCycles;nominalRecoveryWaitMsExcludingWork=$drainCycles*$ack
        minimumFreeBytes=$p.minFreeBytes
    }
    if((Get-FileHash -LiteralPath $path).Hash -cne $hash){throw 'profile-changed-during-check'}
}catch{$reasons.Add($_.Exception.Message)}
$report=[ordered]@{
    schemaVersion=1;status=if($reasons.Count){'profile-rejected'}else{'compatible-under-model-assumptions'}
    sourceProfileSha256=$hash;reasons=@($reasons.ToArray());model=$model
    probeSourceSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Program.cs')).Hash
    analyzerSourceSha256=(Get-FileHash -LiteralPath (Join-Path $PSScriptRoot 'Measure-ProbeEvidence.ps1')).Hash
    executionAuthorized=$false;environmentQualified=$false;qualificationGranted=$false
    note='Static planning only. No queue, workload, drive probe, process, service, VM or network is started. Bounds rely on padded byte assumptions for the current fixed synthetic payload and minimum scheduling intervals; not hard serializer/IO quotas or physical disk writes. The rewrite estimate is a deliberately loose sum of possible destination sizes. Slow operations reduce throughput and can delay sampling or exceed phase deadlines; nominal consumer capacity does not guarantee recovery. Requested duration excludes setup/verification/teardown. An agreed environment, resource budget and actual run remain necessary.'
}
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($report|ConvertTo-Json -Depth 8))
$stream=[IO.File]::Open($output,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
Write-Output ($report|ConvertTo-Json -Depth 8)
if($reasons.Count){throw 'Profile check rejected; inspect its separate report.'}
