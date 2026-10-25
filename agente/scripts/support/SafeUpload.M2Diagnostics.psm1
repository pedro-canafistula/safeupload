#Requires -Version 5.1
Set-StrictMode -Version Latest

function Read-M2Property($Value, [string]$Name) {
    if ($null -eq $Value -or $null -eq $Value.PSObject.Properties[$Name]) {
        throw 'Incomplete M2 diagnostic response.'
    }
    return ,$Value.PSObject.Properties[$Name].Value
}

function Assert-M2Unsigned($Value, [decimal]$Maximum) {
    # ConvertFrom-Json in Windows PowerShell 5.1 uses Decimal above Int64.MaxValue.
    # Reject strings, booleans and floating point; do not coerce rounded values.
    if (($Value -isnot [byte] -and $Value -isnot [int16] -and $Value -isnot [uint16] -and
         $Value -isnot [int32] -and $Value -isnot [uint32] -and $Value -isnot [int64] -and
         $Value -isnot [uint64] -and $Value -isnot [decimal] -and $Value -isnot [System.Numerics.BigInteger]) -or
        $Value -lt 0 -or $Value -gt $Maximum -or [decimal]::Truncate([decimal]$Value) -ne $Value) {
        throw 'Invalid M2 diagnostic unsigned integer.'
    }
}

function Assert-M2Envelope($Value) {
    if ((Read-M2Property $Value 'profile') -cne 'm2-e0df8d1c' -or
        (Read-M2Property $Value 'referenceDriverCommit') -cne 'e0df8d1c1f889418a133d3ae66a87a6c76a7bd5f') {
        throw 'Unsupported M2 diagnostic profile.'
    }
    $version = Read-M2Property $Value 'protocolVersion'
    Assert-M2Unsigned $version 4294967295
    if ($version -ne 18) { throw 'Unsupported M2 diagnostic version.' }
    foreach ($name in @('compatibilityVerified','protectionVerified','atomic')) {
        $flag = Read-M2Property $Value $name
        if ($flag -isnot [bool] -or $flag) { throw 'Unsupported M2 diagnostic qualification metadata.' }
    }
}

function Test-SafeUploadM2DiagnosticData($Counters, $StageStreams) {
    Assert-M2Envelope $Counters
    Assert-M2Envelope $StageStreams
    $snapshot = Read-M2Property $Counters 'snapshot'
    $diag = Read-M2Property (Read-M2Property $snapshot 'counters') 'prefix'
    $writer = Read-M2Property (Read-M2Property $snapshot 'writerState') 'prefix'
    foreach ($pair in @(@($diag,296),@($writer,304))) {
        $size = Read-M2Property $pair[0] 'structSize'
        Assert-M2Unsigned $size 4294967295
        if ($size -ne $pair[1]) { throw 'Unsupported M2 diagnostic structure size.' }
    }
    $version = Read-M2Property $diag 'protocolVersion'
    Assert-M2Unsigned $version 4294967295
    if ($version -ne 18) { throw 'Unsupported M2 counters version.' }
    Assert-M2Unsigned (Read-M2Property $diag 'denyRecorded') 18446744073709551615d
    $stage = Read-M2Property (Read-M2Property $snapshot 'counters') 'stage'
    foreach ($name in @('liveVersions','liveViews','tombstones','waitingVersions')) {
        Assert-M2Unsigned (Read-M2Property $stage $name) 4294967295
    }
    foreach ($name in @('versionsCreated','versionsReleased','viewsReleased','capRefusals','tombstoneRefusals',
        'workerPasses','wakeCleanup','wakeClose','wakeDispose','wakeConnect','wakeExit','wakeTimer','wakeInline',
        'timerArms','disposeHeld','disposeNotHeld','disposeStale','disposeDeferred','stageDeletes','stageDeleteFailures')) {
        Assert-M2Unsigned (Read-M2Property $stage $name) 18446744073709551615d
    }
    $writerSnapshot = Read-M2Property $snapshot 'writerState'
    foreach ($name in @('writerGlobalFirstUnknown','writerEntryFirstUnknown','writerSopFirstUnknown','writerSopUnknownCount')) {
        Assert-M2Unsigned (Read-M2Property $writerSnapshot $name) 4294967295
    }
    $count = Read-M2Property $StageStreams 'count'
    $total = Read-M2Property $StageStreams 'total'
    Assert-M2Unsigned $count 16
    Assert-M2Unsigned $total 4294967295
    $records = Read-M2Property $StageStreams 'records'
    if ($null -eq $records -or $records -isnot [array] -or $records.Count -ne $count -or $total -lt $count) {
        throw 'Invalid M2 stage-stream counts.'
    }
    $truncated = Read-M2Property $StageStreams 'truncated'
    if ($truncated -isnot [bool] -or $truncated -ne ($total -gt $count)) { throw 'Invalid M2 truncation marker.' }
    foreach ($record in $records) {
        $guid = [guid]::Empty
        if (-not [guid]::TryParse([string](Read-M2Property $record 'transferId'), [ref]$guid)) {
            throw 'Invalid M2 transfer identifier.'
        }
        foreach ($name in @('flags','fileObjects','shareOpenCount','rpcReferences','ownerProcessId','wait','sectionBits')) {
            Assert-M2Unsigned (Read-M2Property $record $name) 4294967295
        }
        Assert-M2Unsigned (Read-M2Property $record 'destinationGeneration') 18446744073709551615d
        $units = Read-M2Property $record 'nameCodeUnits'
        if ($null -eq $units -or $units -isnot [array] -or $units.Count -gt 48) { throw 'Invalid M2 WCHAR count.' }
        foreach ($unit in $units) { Assert-M2Unsigned $unit 65535 }
    }
}

function Invoke-SafeUploadM2DiagnosticCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][scriptblock]$Query)
    # Do not emit intermediate results. An error in either query or validation
    # must not leave a success-shaped partial receipt in the output pipeline.
    $counters = & $Query 'm2-counters'
    $streams = & $Query 'm2-stage-streams'
    Test-SafeUploadM2DiagnosticData $counters $streams
    [pscustomobject][ordered]@{
        schemaVersion = 1
        status = 'diagnostics-only-passed'
        capturedUtc = [DateTimeOffset]::UtcNow.ToString('o')
        referenceDriverCommit = 'e0df8d1c1f889418a133d3ae66a87a6c76a7bd5f'
        driverIdentityVerified = $false
        pairQualified = $false
        protectionVerified = $false
        counters = $counters
        stageStreams = $streams
    }
}

Export-ModuleMember -Function Test-SafeUploadM2DiagnosticData,Invoke-SafeUploadM2DiagnosticCapture
