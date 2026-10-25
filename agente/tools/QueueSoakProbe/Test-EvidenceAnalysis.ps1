#requires -Version 7.5
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PreservedPilotDirectory,
    [Parameter(Mandatory)][string]$OutputParent
)
$ErrorActionPreference='Stop'
$source=(Resolve-Path -LiteralPath $PreservedPilotDirectory).Path
$root=Join-Path ([IO.Path]::GetFullPath($OutputParent)) ('analysis-cases-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -Force | Out-Null
$names=@('result.json','profile.json','queue.jsonl','samples.jsonl','operations.jsonl','synthetic.marker')
$original=@{}
foreach($name in $names){$original[$name]=(Get-FileHash -LiteralPath (Join-Path $source ('pilot-'+$name))).Hash}
$results=@()
$expectedIssues=@{'partial-tail'='Unterminated trace tail.';'backwards-time'='Nonmonotonic trace counters.';'pending-mismatch'='Inconsistent pending counters.';'hash-mismatch'='Receipt manifest mismatch.';'missing-phase'='Missing completed phases.';'duplicate-manifest'='Duplicate manifest filename.'}
foreach($case in @('preserved','missing-receipt','partial-tail','backwards-time','pending-mismatch','hash-mismatch','synthetic-gap','missing-phase','duplicate-manifest')){
    $dir=Join-Path $root $case
    New-Item -ItemType Directory -Path $dir | Out-Null
    foreach($name in $names){
        if($case -eq 'missing-receipt' -and $name -eq 'result.json'){continue}
        Copy-Item -LiteralPath (Join-Path $source ('pilot-'+$name)) -Destination (Join-Path $dir $name)
    }
    $sampleFile=Join-Path $dir 'samples.jsonl'
    $receiptFile=Join-Path $dir 'result.json'
    if($case -eq 'partial-tail'){[IO.File]::AppendAllText($sampleFile,'{"utc":')}
    if($case -in @('backwards-time','pending-mismatch','synthetic-gap')){
        $samples=@(Get-Content -LiteralPath $sampleFile | ForEach-Object{$_ | ConvertFrom-Json -DateKind String})
        if($case -eq 'backwards-time'){$samples[1].elapsedMs=0}
        if($case -eq 'pending-mismatch'){$samples[0].pendingEvents+=1}
        if($case -eq 'synthetic-gap'){
            for($i=1;$i -lt $samples.Count;$i++){
                $samples[$i].elapsedMs+=10000
                $samples[$i].utc=[DateTimeOffset]::Parse($samples[$i].utc).AddSeconds(10).ToString('o')
            }
            $samples[1].intervalSincePreviousMs+=10000
        }
        $lines=@($samples | ForEach-Object{$_ | ConvertTo-Json -Compress})
        [IO.File]::WriteAllText($sampleFile,($lines -join "`n")+"`n",[Text.UTF8Encoding]::new($false))
    }
    if($case -eq 'hash-mismatch'){[IO.File]::AppendAllText($sampleFile," `n")}
    if($case -notin @('preserved','missing-receipt','hash-mismatch')){
        # Update only the synthetic copy's manifest so parser checks are exercised,
        # rather than merely detecting a stale hash. This is not an authenticity test.
        $receipt=Get-Content -LiteralPath $receiptFile -Raw | ConvertFrom-Json -DateKind String
        $entry=@($receipt.files | Where-Object file -eq 'samples.jsonl')[0]
        $entry.bytes=(Get-Item -LiteralPath $sampleFile).Length
        $entry.sha256=(Get-FileHash -LiteralPath $sampleFile).Hash
        if($case -eq 'synthetic-gap'){
            $receipt.elapsedSeconds+=10
            $receipt.phases[0].elapsedMs+=10000
            $receipt.finishedAtUtc=[DateTimeOffset]::Parse($receipt.finishedAtUtc).AddSeconds(10).ToString('o')
        }
        if($case -eq 'missing-phase'){$receipt.phases=@($receipt.phases | Select-Object -First 2)}
        if($case -eq 'duplicate-manifest'){$receipt.files+=@($receipt.files[0])}
        $receipt | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $receiptFile -Encoding utf8NoBOM
    }
    $reportPath=Join-Path $root ($case+'.json')
    $threw=$false
    try{& (Join-Path $PSScriptRoot 'Measure-ProbeEvidence.ps1') -EvidenceDirectory $dir -OutputPath $reportPath | Out-Null}catch{$threw=$true}
    $report=Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $expected=if($case -eq 'missing-receipt'){'incomplete-run'}elseif($case -in @('preserved','synthetic-gap')){'analyzed-completed-run'}else{'invalid-evidence'}
    if($report.status -cne $expected -or $report.qualificationGranted -ne $false -or $report.serviceQualified -ne $false -or $report.realApiQualified -ne $false -or $threw -ne ($expected -eq 'invalid-evidence')){throw ('Unexpected classification: '+$case)}
    if($expectedIssues.ContainsKey($case) -and ($report.issues.Count -ne 1 -or $report.issues[0] -cne $expectedIssues[$case])){throw ('Unexpected reason: '+$case)}
    if($case -eq 'missing-receipt' -and $report.terminalGapKnown){throw 'Missing receipt incorrectly defines terminal gap'}
    if($case -eq 'synthetic-gap' -and $report.maxObservedGapMs -lt 10000){throw 'Injected collection gap missed'}
    $results+=[ordered]@{case=$case;passed=$true;expected=$expected;observed=$report.status;report=[IO.Path]::GetFileName($reportPath);issues=$report.issues}
}
# A rejected output path must not write into evidence or overwrite a report.
$before=(Get-FileHash -LiteralPath (Join-Path $root 'preserved.json')).Hash
foreach($target in @((Join-Path $root 'preserved.json'),(Join-Path $root 'preserved/analysis.json'))){
    $threw=$false
    try{& (Join-Path $PSScriptRoot 'Measure-ProbeEvidence.ps1') -EvidenceDirectory (Join-Path $root 'preserved') -OutputPath $target | Out-Null}catch{$threw=$true}
    if(-not $threw){throw 'Unsafe output accepted'}
}
if((Test-Path -LiteralPath (Join-Path $root 'preserved/analysis.json')) -or (Get-FileHash -LiteralPath (Join-Path $root 'preserved.json')).Hash -cne $before){throw 'Unsafe output changed files'}
$results+=[ordered]@{case='output-protection';passed=$true;expected='refuse-existing-and-inside';observed='refused'}
foreach($name in $names){if((Get-FileHash -LiteralPath (Join-Path $source ('pilot-'+$name))).Hash -cne $original[$name]){throw 'Preserved source changed'}}
$results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'cases.json') -Encoding utf8NoBOM
Write-Output ('PASS: 10 controls; preserved pilot unchanged; '+$root)
