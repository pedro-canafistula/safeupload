#Requires -Version 5.1
[CmdletBinding()]
param([string]$ResultsPath)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../support/SafeUpload.M2Diagnostics.psm1') -Force
$results = [Collections.Generic.List[object]]::new()
function Assert-True([bool]$Condition) { if (-not $Condition) { throw 'Assertion failed.' } }
function Assert-Rejected([scriptblock]$Operation) {
    $rejected = $false
    try { & $Operation | Out-Null } catch { $rejected = $true }
    Assert-True $rejected
}
function Test-Case([string]$Name,[scriptblock]$Operation) {
    try { & $Operation | Out-Null; $results.Add([pscustomobject]@{name=$Name;passed=$true;error=$null}) }
    catch { $results.Add([pscustomobject]@{name=$Name;passed=$false;error=$_.Exception.Message}) }
}
function New-Fixture {
    $counters = @'
{"profile":"m2-e0df8d1c","referenceDriverCommit":"e0df8d1c1f889418a133d3ae66a87a6c76a7bd5f","protocolVersion":18,"compatibilityVerified":false,"protectionVerified":false,"atomic":false,"snapshot":{"counters":{"prefix":{"structSize":296,"protocolVersion":18,"denyRecorded":18446744073709551615}},"writerState":{"prefix":{"structSize":304,"sectionInFlightNow":7}}}}
'@ | ConvertFrom-Json
    $streams = @'
{"profile":"m2-e0df8d1c","referenceDriverCommit":"e0df8d1c1f889418a133d3ae66a87a6c76a7bd5f","protocolVersion":18,"compatibilityVerified":false,"protectionVerified":false,"atomic":false,"count":1,"total":2,"truncated":true,"records":[{"transferId":"0dd117aa-8924-4433-bbaa-112233445566","flags":2147483649,"fileObjects":1,"shareOpenCount":0,"rpcReferences":0,"ownerProcessId":17,"wait":0,"sectionBits":0,"destinationGeneration":18446744073709551615,"name":"A","nameCodeUnits":[65,0,55296]}]}
'@ | ConvertFrom-Json
    $stage=[pscustomobject]@{liveVersions=1;liveViews=0;tombstones=0;waitingVersions=0}
    foreach($name in @('versionsCreated','versionsReleased','viewsReleased','capRefusals','tombstoneRefusals',
        'workerPasses','wakeCleanup','wakeClose','wakeDispose','wakeConnect','wakeExit','wakeTimer','wakeInline',
        'timerArms','disposeHeld','disposeNotHeld','disposeStale','disposeDeferred','stageDeletes','stageDeleteFailures')) {
        $stage|Add-Member -NotePropertyName $name -NotePropertyValue 0
    }
    $counters.snapshot.counters|Add-Member -NotePropertyName stage -NotePropertyValue $stage
    foreach($name in @('writerGlobalFirstUnknown','writerEntryFirstUnknown','writerSopFirstUnknown','writerSopUnknownCount')) {
        $counters.snapshot.writerState|Add-Member -NotePropertyName $name -NotePropertyValue 0
    }
    return [pscustomobject]@{c=$counters;s=$streams}
}
Test-Case 'Two explicit queries produce only an unqualified receipt and preserve UInt64 JSON' {
    $f=New-Fixture; $calls=[Collections.Generic.List[string]]::new()
    $receipt=Invoke-SafeUploadM2DiagnosticCapture -Query {
        param($name) $calls.Add($name)
        if($name -eq 'm2-counters') { return $f.c }; return $f.s
    }
    Assert-True ($calls.Count -eq 2 -and $calls[0] -ceq 'm2-counters' -and $calls[1] -ceq 'm2-stage-streams')
    Assert-True ($receipt.status -ceq 'diagnostics-only-passed' -and -not $receipt.pairQualified -and -not $receipt.driverIdentityVerified -and -not $receipt.protectionVerified)
    $json=$receipt|ConvertTo-Json -Depth 20
    Assert-True ($json.Contains('18446744073709551615'))
    $round=$json|ConvertFrom-Json
    Test-SafeUploadM2DiagnosticData $round.counters $round.stageStreams
    Assert-True ($round.stageStreams.records[0].nameCodeUnits.Count -eq 3 -and $round.stageStreams.records[0].nameCodeUnits[2] -eq 55296)
}
Test-Case 'Empty stage list and empty WCHAR arrays remain arrays' {
    $f=New-Fixture; $f.s.records[0].nameCodeUnits=@()
    Test-SafeUploadM2DiagnosticData $f.c $f.s
    $f.s.count=0; $f.s.total=0; $f.s.truncated=$false; $f.s.records=@()
    Test-SafeUploadM2DiagnosticData $f.c $f.s
}
Test-Case 'Unknown profiles and versions are rejected' {
    $f=New-Fixture; $f.c.profile='legacy'
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    $f=New-Fixture; $f.s.protocolVersion=19
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
}
Test-Case 'Legacy sizes and missing snapshots are rejected' {
    $f=New-Fixture; $f.c.snapshot.writerState.prefix.structSize=288
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    $f=New-Fixture; $f.c.snapshot=$null
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    $f=New-Fixture; $f.c.snapshot.counters.stage=$null
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
}
Test-Case 'Qualification and atomic metadata cannot be promoted or coerced' {
    foreach($flag in @('compatibilityVerified','protectionVerified','atomic')) {
        $f=New-Fixture; $f.c.$flag=$true
        Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
        $f=New-Fixture; $f.c.$flag='false'
        Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    }
}
Test-Case 'Invalid stage counts and truncation are rejected' {
    foreach($count in @(-1,17,'1',1.5)) {
        $f=New-Fixture; $f.s.count=$count
        Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    }
    $f=New-Fixture; $f.s.total=0
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    $f=New-Fixture; $f.s.truncated=$false
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
}
Test-Case 'Record identifiers, integer ranges and WCHAR limits are checked' {
    $f=New-Fixture; $f.s.records[0].transferId='bad'
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    $f=New-Fixture; $f.s.records[0].flags=4294967296d
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    $f=New-Fixture; $f.s.records[0].destinationGeneration=18446744073709551616d
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    $f=New-Fixture; $f.s.records[0].nameCodeUnits=@(65536)
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
    $f=New-Fixture; $f.s.records[0].nameCodeUnits=@(1..49)
    Assert-Rejected { Test-SafeUploadM2DiagnosticData $f.c $f.s }
}
Test-Case 'A second-query failure emits no partial success' {
    $f=New-Fixture; $emitted=[Collections.Generic.List[object]]::new()
    Assert-Rejected {
        Invoke-SafeUploadM2DiagnosticCapture -Query {
            param($name) if($name -eq 'm2-counters'){return $f.c}; throw 'synthetic disconnect'
        } | ForEach-Object { $emitted.Add($_) }
    }
    Assert-True ($emitted.Count -eq 0)
}
Test-Case 'The real collector parses without errors and keeps its elevation requirement' {
    $tokens=$null; $errors=$null
    $path=Join-Path $PSScriptRoot '../Test-SafeUploadM2Diagnostics.ps1'
    $ast=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $path),[ref]$tokens,[ref]$errors)
    Assert-True ($errors.Count -eq 0 -and $ast.ScriptRequirements.IsElevationRequired)
}
$failed=@($results|Where-Object {-not $_.passed})
$summary=[ordered]@{powershell=$PSVersionTable.PSVersion.ToString();total=$results.Count;passed=$results.Count-$failed.Count;failed=$failed.Count;tests=@($results)}
if($ResultsPath){$summary|ConvertTo-Json -Depth 6|Set-Content -LiteralPath $ResultsPath -Encoding UTF8}
$failed|Format-List|Out-Host
Write-Output "M2DiagnosticsContracts: $($summary.passed)/$($summary.total) passed (PowerShell $($summary.powershell))"
if($failed.Count -ne 0){exit 1}
