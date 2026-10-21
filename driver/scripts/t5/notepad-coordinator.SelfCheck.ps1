[CmdletBinding()]
param([string]$CoordinatorPath)
# Windows PowerShell 5.1 leaves $PSScriptRoot empty in an advanced script's param() defaults under -File.
if (-not $CoordinatorPath) { $CoordinatorPath = Join-Path $PSScriptRoot 'notepad-coordinator.ps1' }

$ErrorActionPreference = 'Stop'
$script:assertions = 0

function Assert-T5([bool]$Condition, [string]$Message) {
    $script:assertions++
    if (-not $Condition) { throw ('T5 coordinator self-check failed: ' + $Message) }
}
function New-T5Identity([uint64]$FileLow) {
    return [pscustomobject]@{
        VolumeSerialNumber = [uint64]::MaxValue
        FileIdHigh = [uint64]::MaxValue
        FileIdLow = $FileLow
    }
}
function New-T5History([int[]]$States) {
    $origin = [DateTimeOffset]::Parse('2026-10-11T12:00:00+00:00')
    $history = @()
    for ($index = 0; $index -lt $States.Count; ++$index) {
        $history += [pscustomobject]@{
            State = [int]$States[$index]
            OccurredAtUtc = $origin.AddSeconds($index).ToString('o')
        }
    }
    return ,$history
}
function New-T5Entry([int]$State, [string]$Tag, [guid]$DriverId, [string]$SharedPath) {
    $id = [guid]::NewGuid()
    $generation = [long](100 + $State)
    $states = switch ($State) {
        0 { @(0) }
        1 { @(0, 1) }
        2 { @(0, 1, 2) }
        3 { @(0, 1, 2, 3) }
        4 { @(0, 1, 2, 3, 4) }
        5 { @(0, 1, 2, 3, 4, 5) }
        6 { @(0, 1, 2, 6) }
        7 { @(0, 1, 7) }
        8 { @(0, 8) }
        9 { @(0, 9) }
        10 { @(0, 10) }
        11 { @(0, 10, 11) }
        12 { @(0, 12) }
        default { throw 'unknown fixture state' }
    }
    $sealed = ($State -in @(1, 2, 3, 4, 5, 6, 7, 10, 11))
    $sealedLength = if ($State -eq 11) { [long]0 } elseif ($State -in @(1, 2, 3, 4, 5, 6, 7)) { [long]5 } else { $null }
    $digest = if ($State -in @(1, 2, 3, 4, 5, 6, 7)) { 'A' * 64 } else { $null }
    $origin = [DateTimeOffset]::Parse('2026-10-11T12:00:00+00:00')
    $entry = [pscustomobject][ordered]@{
        Transfer = [pscustomobject]@{
            TransferId = $id.ToString()
            StagePath = (Join-Path $env:TEMP ('t5-stage-' + $id.ToString('N')))
            DestinationPath = $SharedPath
            Destination = [int]1
            ProcessName = 'notepad.exe'
            ProcessId = [int]4321
            SessionId = [uint32]3
            RequestorSid = 'S-1-5-21-100-200-300-1000'
            RequestorProcessCreationTime = [long]638957232000000000
        }
        State = [int]$State
        DestinationGeneration = $generation
        Sha256Hex = $digest
        UpdatedAtUtc = $origin.AddSeconds($states.Count).ToString('o')
        StateHistory = (New-T5History $states)
        SealedOnce = [bool]$sealed
        StageIdentity = (New-T5Identity ([uint64]$generation))
        SealedLength = $sealedLength
        ParentVersionIdentity = $null
        DeleteVersionIdentity = $null
        CreateReservationId = $id.ToString()
        CreateAfterReservationId = $null
        AllocationReferenceId = $null
        AllocationReferenceKind = [uint32]0
        DriverInstanceId = $DriverId.ToString()
        ParentDirectoryIdentity = (New-T5Identity ([uint64]1))
        AllocationDisposition = [uint32]2
        AttachmentStateV20 = [uint32]0
        AttachPrepareRequestIdV20 = $null
        AttachCommitRequestIdV20 = $null
        AttachCommitResultV20 = $null
        AttachAbortRequestIdV20 = $null
        CompletionPermitRequestIdV20 = $null
        RetireRequestIdV20 = $null
        HandleObservedRequestIdV20 = $null
        DiscardReservationId = $null
        DiscardKind = $null
        DiscardRequestedAtUtc = $null
        DiscardAcknowledgedAtUtc = $null
        EmptyHeldNotificationAttemptedAtUtc = $null
        EmptyHeldNotificationAttemptedByInstanceId = $null
        EmptyHeldNotificationQueuedAtUtc = $null
        EmptyHeldNotificationQueuedByInstanceId = $null
        StageCleanupStarted = [bool]$false
        StageDeleted = [bool]$false
        NamespaceTombstones = $null
        PendingRename = $null
        LastRenameTransactionId = [uint64]0
        LastRenameDestination = $null
        LastRenameCommitted = [bool]$false
        BlockedPolicyVersion = [int]0
        BlockedInspectionFailure = $null
        JustificationExpiresAtUtc = $null
        JustificationWindowClosed = [bool]$false
        HandbackState = [int]0
        HandbackPath = $null
        HandbackLength = $null
        HandbackFailureReason = $null
        HandbackLastAttemptAtUtc = $null
    }
    if ($State -eq 6) { $entry.BlockedPolicyVersion = [int]1 }
    if ($State -eq 12) {
        $entry.DiscardReservationId = $id.ToString()
        $entry.DiscardKind = [uint32]1
        $entry.DiscardRequestedAtUtc = $origin.AddMinutes(2).ToString('o')
    }
    if ($State -in @(1, 2, 3, 4, 5, 6, 7, 10, 11)) { Set-T5HandleObserved $entry }
    return $entry
}
function Set-T5ExactParent($Child, $Parent) {
    $Child.ParentVersionIdentity = [pscustomobject]@{
        TransferId = $Parent.Transfer.TransferId
        DestinationGeneration = $Parent.DestinationGeneration
        StageIdentity = $Parent.StageIdentity
    }
    $Child.AllocationReferenceId = $Parent.Transfer.TransferId
    $Child.AllocationReferenceKind = [uint32]1
    $Child.DestinationGeneration = [long]($Parent.DestinationGeneration + 1)
    $Child.Transfer.DestinationPath = $Parent.Transfer.DestinationPath
    $Child.Transfer.Destination = $Parent.Transfer.Destination
    $Child.Transfer.ProcessId = $Parent.Transfer.ProcessId
    $Child.Transfer.SessionId = $Parent.Transfer.SessionId
    $Child.Transfer.RequestorSid = $Parent.Transfer.RequestorSid
    $Child.Transfer.RequestorProcessCreationTime = $Parent.Transfer.RequestorProcessCreationTime
    $Child.ParentDirectoryIdentity = $Parent.ParentDirectoryIdentity
}
function Set-T5HandleObserved($Entry) {
    $Entry.AttachmentStateV20 = [uint32]6
    $Entry.AttachPrepareRequestIdV20 = [uint64]12
    $Entry.AttachCommitRequestIdV20 = [uint64]13
    $Entry.AttachCommitResultV20 = [uint32]7
    $Entry.CompletionPermitRequestIdV20 = [uint64]15
    $Entry.HandleObservedRequestIdV20 = [uint64]19
}
function Set-T5DiscardAck($Entry, [uint32]$Kind, [string]$Reservation) {
    $request = [DateTimeOffset]::Parse('2026-10-11T12:20:00+00:00')
    $Entry.DiscardReservationId = $Reservation
    $Entry.DiscardKind = $Kind
    $Entry.DiscardRequestedAtUtc = $request.ToString('o')
    $Entry.DiscardAcknowledgedAtUtc = $request.AddSeconds(1).ToString('o')
}
function Get-T5FixtureErrors($Entry, [switch]$RequireV20) {
    $manifest = (Get-T5GuidText $Entry.Transfer.TransferId) + '.json'
    return @(Get-JournalSchemaErrors $Entry $manifest -RequireStateHistory -RequireV20:$RequireV20)
}

$resolvedCoordinator = (Resolve-Path -LiteralPath $CoordinatorPath).Path
$tokens = $null; $parseErrors = $null
$coordinatorAst = [System.Management.Automation.Language.Parser]::ParseFile($resolvedCoordinator, [ref]$tokens, [ref]$parseErrors)
Assert-T5 (@($parseErrors).Count -eq 0) 'coordinator source must parse without execution'
$functionNames = @(
    'Test-T5HasProperty', 'Test-T5Object', 'Get-T5IntegerText', 'Test-T5IntegerRange',
    'Test-T5NextGeneration', 'Get-T5UInt64Text', 'Test-T5UInt64', 'Get-T5GuidText',
    'Get-T5UtcValue', 'Get-T5StateName', 'Test-T5StateTransition', 'Test-T5NormalizedPath',
    'Test-T5JsonDepthBound', 'Get-T5StageIdentityKey', 'Test-T5StageIdentity',
    'Get-T5VersionIdentityKey', 'Test-T5VersionIdentity', 'Test-T5LifecycleEvidence',
    'Get-JournalSchemaErrors', 'Get-T5Projection', 'Get-T5EntryVersionKey', 'Get-T5StateAtUtc',
    'Test-T5SameWriter', 'Test-T5SameWriterAndEpoch', 'Get-T5TombstonesForPath', 'Test-T5TerminalPrivateVersion',
    'Test-T5DirectEmptyHeldChildTerminal',
    'Get-StableJournalChildren', 'ConvertFrom-ServiceDriverEpoch', 'ConvertFrom-ServiceArchive', 'Read-T5JournalStorage', 'Read-T5StorageFile', 'Sha',
    'Get-T5JournalLineageErrors', 'Get-T5EmptyProbeOutcome', 'Get-JournalFor'
)
$functionAsts = @($coordinatorAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $functionNames -contains $node.Name
}, $true))
$foundNames = @($functionAsts | ForEach-Object { $_.Name } | Sort-Object -Unique)
foreach ($name in $functionNames) { Assert-T5 ($foundNames -contains $name) ('pure helper function missing: ' + $name) }
$definitions = @($functionAsts | ForEach-Object { $_.Extent.Text })
$validationBlock = [scriptblock]::Create(($definitions -join [Environment]::NewLine))
. $validationBlock

Assert-T5 (Test-T5UInt64 ([uint64]::MaxValue)) 'UInt64.MaxValue must survive exact invariant parsing'
Assert-T5 (-not (Test-T5UInt64 ([decimal]::Parse('18446744073709551616')))) 'UInt64 overflow must fail closed'
Assert-T5 (-not (Test-T5UInt64 ([long]-1))) 'negative identity values must fail closed'
Assert-T5 (-not (Test-T5UInt64 ([decimal]::Parse('1.5')))) 'fractional identity values must fail closed'
Assert-T5 (-not (Test-T5UInt64 ([double]9007199254740992))) 'floating point identities must fail closed'
Assert-T5 ($null -ne (Get-T5UtcValue '2026-10-11T12:00:00.0000000+00:00')) 'explicit UTC offset must be accepted'
Assert-T5 ($null -eq (Get-T5UtcValue '2026-10-11T12:00:00')) 'a timezone-free timestamp must not become UTC by host configuration'
Assert-T5 ($null -eq (Get-T5UtcValue '2026-10-11T12:00:00-03:00')) 'a local offset must not pass as exact UTC'
Assert-T5 (Test-T5JsonDepthBound '{"x":"{ [ text ] }","nested":{"v":[1,2]}}' 4) 'quoted brackets must not affect JSON depth'
Assert-T5 (-not (Test-T5JsonDepthBound '{"a":{"b":{"c":{"d":1}}}}' 3)) 'over-depth JSON must be rejected'
Assert-T5 (-not (Test-T5JsonDepthBound '{"a":1' 8)) 'unbalanced JSON must be rejected'

$tempRoot = Join-Path $env:TEMP ('t5-coordinator-selfcheck-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    $driver = [guid]::NewGuid()
    $basePath = Join-Path $tempRoot 'target.txt'
    $stateHistory = @{
        0 = @(0); 1 = @(0, 1); 2 = @(0, 1, 2); 3 = @(0, 1, 2, 3)
        4 = @(0, 1, 2, 3, 4); 5 = @(0, 1, 2, 3, 4, 5); 6 = @(0, 1, 2, 6)
        7 = @(0, 1, 7); 8 = @(0, 8); 9 = @(0, 9); 10 = @(0, 10)
        11 = @(0, 10, 11); 12 = @(0, 12)
    }
    foreach ($state in 0..12) {
        $entry = New-T5Entry $state ('state-' + $state) $driver (Join-Path $tempRoot ('state-' + $state + '.txt'))
        $errors = Get-T5FixtureErrors $entry -RequireV20
        Assert-T5 ($errors.Count -eq 0) ('service state ' + $state + ' must validate: ' + ($errors -join '; '))
        Assert-T5 ((Get-T5StateName $state) -cne ('Unknown(' + $state + ')')) ('state label missing for ' + $state)
        $json = ConvertTo-Json -InputObject $entry -Depth 32 -Compress
        $roundTrip = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        $roundTripErrors = Get-T5FixtureErrors $roundTrip -RequireV20
        Assert-T5 ($roundTripErrors.Count -eq 0) ('service-shaped serialized state ' + $state + ' must round-trip: ' + ($roundTripErrors -join '; '))
        Assert-T5 ((Get-T5StageIdentityKey $roundTrip.StageIdentity) -ceq (Get-T5StageIdentityKey $entry.StageIdentity)) ('UInt64 stage identity must round-trip exactly for state ' + $state)
    }

    $legacy = New-T5Entry 0 'legacy' $driver $basePath
    $legacy.DriverInstanceId = $null
    $legacyErrors = Get-T5FixtureErrors $legacy
    Assert-T5 ($legacyErrors.Count -eq 0) 'a distinct legacy baseline may parse without v20 epoch evidence'
    $strictLegacyErrors = Get-T5FixtureErrors $legacy -RequireV20
    Assert-T5 ($strictLegacyErrors.Count -gt 0) 'a new measured record may not borrow legacy/v18 identity'
    $legacySealed = New-T5Entry 1 'legacy-sealed' $driver $basePath
    $legacySealed.DriverInstanceId = $null
    $legacySealed.StageIdentity = $null
    $legacySealed.SealedLength = $null
    $legacySealed.PSObject.Properties.Remove('StateHistory')
    $legacySealedErrors = @(Get-JournalSchemaErrors $legacySealed ((Get-T5GuidText $legacySealed.Transfer.TransferId) + '.json'))
    Assert-T5 ($legacySealedErrors.Count -eq 0) 'legacy sealed baseline may remain readable without V20 measurement authority'
    Assert-T5 (-not (Get-T5Projection $legacySealed 'legacy.json').IsV20) 'legacy projection stays explicitly separate from V20'

    $legacyParent = New-T5Entry 1 'legacy-chain-parent' $driver $basePath
    $legacyParent.DriverInstanceId = $null
    $legacyChild = New-T5Entry 5 'legacy-chain-child' $driver $basePath
    $legacyChild.DriverInstanceId = $null
    Set-T5ExactParent $legacyChild $legacyParent
    $legacyParentProjection = Get-T5Projection $legacyParent 'legacy-parent.json'
    $legacyChildProjection = Get-T5Projection $legacyChild 'legacy-child.json'
    $legacyParentIdentity = [pscustomobject]@{
        TransferId = $legacyParent.Transfer.TransferId
        DestinationGeneration = $legacyParent.DestinationGeneration
        StageIdentity = $legacyParent.StageIdentity
    }
    $legacyChainSchemaErrors = @(@(Get-T5FixtureErrors $legacyParent) + @(Get-T5FixtureErrors $legacyChild))
    $legacyChainErrors = @(Get-T5JournalLineageErrors @($legacyParentProjection, $legacyChildProjection))
    Assert-T5 (-not $legacyParentProjection.IsV20 -and -not $legacyChildProjection.IsV20 -and
        (Get-T5VersionIdentityKey $legacyChildProjection.ParentVersionIdentity) -ceq (Get-T5VersionIdentityKey $legacyParentIdentity) -and
        $legacyChainSchemaErrors.Count -eq 0 -and
        $legacyChainErrors.Count -eq 0) 'an exact all-legacy ancestry chain remains accepted without V20 measurement authority'

    $mixedChild = New-T5Entry 5 'mixed-v20-child' $driver $basePath
    Set-T5ExactParent $mixedChild $legacyParent
    $mixedChildProjection = Get-T5Projection $mixedChild 'mixed-v20-child.json'
    $mixedChainErrors = @(Get-T5JournalLineageErrors @($legacyParentProjection, $mixedChildProjection))
    Assert-T5 ($mixedChildProjection.IsV20 -and (Get-T5FixtureErrors $mixedChild -RequireV20).Count -eq 0 -and
        $mixedChainErrors.Count -gt 0) 'a measured V20 child may not inherit ancestry from a legacy parent'

    $prepared = New-T5Entry 0 'prepared' $driver $basePath
    $prepared.AttachmentStateV20 = [uint32]1
    $prepared.AttachPrepareRequestIdV20 = [uint64]31
    Assert-T5 ((Get-T5FixtureErrors $prepared -RequireV20).Count -eq 0) 'prepared lifecycle with a null commit pair validates'
    $orphanPreparedResult = $prepared.PSObject.Copy()
    $orphanPreparedResult.AttachCommitResultV20 = [uint32]7
    Assert-T5 ((Get-T5FixtureErrors $orphanPreparedResult -RequireV20).Count -gt 0 -and
        -not (Test-T5LifecycleEvidence $orphanPreparedResult 1 0)) 'orphan commit result is rejected for Prepared'

    $aborted = New-T5Entry 12 'aborted' $driver $basePath
    Set-T5DiscardAck $aborted 5 $aborted.Transfer.TransferId
    $aborted.AttachmentStateV20 = [uint32]4
    $aborted.AttachPrepareRequestIdV20 = [uint64]41
    $aborted.AttachAbortRequestIdV20 = [uint64]42
    Assert-T5 ((Get-T5FixtureErrors $aborted -RequireV20).Count -eq 0) 'exact Aborted receipt without commit validates'
    $orphanAbortedResult = $aborted.PSObject.Copy()
    $orphanAbortedResult.AttachCommitResultV20 = [uint32]9
    Assert-T5 ((Get-T5FixtureErrors $orphanAbortedResult -RequireV20).Count -gt 0 -and
        -not (Test-T5LifecycleEvidence $orphanAbortedResult 4 12)) 'orphan commit result is rejected for Aborted'

    $retiredUnexposed = New-T5Entry 12 'retired-unexposed' $driver $basePath
    Set-T5DiscardAck $retiredUnexposed 6 $retiredUnexposed.Transfer.TransferId
    $retiredUnexposed.AttachmentStateV20 = [uint32]8
    $retiredUnexposed.AttachPrepareRequestIdV20 = [uint64]51
    $retiredUnexposed.AttachCommitRequestIdV20 = [uint64]52
    $retiredUnexposed.AttachCommitResultV20 = [uint32]7
    $retiredUnexposed.RetireRequestIdV20 = [uint64]53
    $retiredUnexposedProjection = Get-T5Projection $retiredUnexposed 'unused-retired-unexposed.json'
    Assert-T5 ((Get-T5FixtureErrors $retiredUnexposed -RequireV20).Count -eq 0 -and
        (Test-T5TerminalPrivateVersion $retiredUnexposedProjection)) 'exact acknowledged RetireUnexposed is terminal private cleanup'

    $retiredAttachedPrivate = New-T5Entry 12 'retired-attached-private' $driver $basePath
    Set-T5DiscardAck $retiredAttachedPrivate 7 $retiredAttachedPrivate.Transfer.TransferId
    $retiredAttachedPrivate.AttachmentStateV20 = [uint32]10
    $retiredAttachedPrivate.AttachPrepareRequestIdV20 = [uint64]61
    $retiredAttachedPrivate.AttachCommitRequestIdV20 = [uint64]62
    $retiredAttachedPrivate.AttachCommitResultV20 = [uint32]7
    $retiredAttachedPrivate.CompletionPermitRequestIdV20 = [uint64]63
    $retiredAttachedPrivate.RetireRequestIdV20 = [uint64]64
    $retiredAttachedProjection = Get-T5Projection $retiredAttachedPrivate 'unused-retired-attached.json'
    Assert-T5 ((Get-T5FixtureErrors $retiredAttachedPrivate -RequireV20).Count -eq 0 -and
        (Test-T5TerminalPrivateVersion $retiredAttachedProjection)) 'exact acknowledged RetireAttachedPrivate is terminal private cleanup'
    $retiredAttachedOutcome = Get-T5EmptyProbeOutcome @($retiredAttachedProjection) $true
    Assert-T5 ($retiredAttachedOutcome.Verified -and $retiredAttachedOutcome.Kind -eq 'PRIVATE_DELETE_ACKNOWLEDGED') 'exact kind-7 retirement ACK classifies only as private cleanup'

    $pendingRetirement = New-T5Entry 12 'pending-retirement' $driver $basePath
    $pendingRetirement.DiscardKind = [uint32]6
    $pendingRetirement.DiscardAcknowledgedAtUtc = $null
    $pendingRetirement.AttachmentStateV20 = [uint32]7
    $pendingRetirement.AttachPrepareRequestIdV20 = [uint64]71
    $pendingRetirement.AttachCommitRequestIdV20 = [uint64]72
    $pendingRetirement.AttachCommitResultV20 = [uint32]7
    $pendingRetirement.RetireRequestIdV20 = [uint64]73
    $pendingRetirementProjection = Get-T5Projection $pendingRetirement 'unused-pending-retirement.json'
    Assert-T5 ((Get-T5FixtureErrors $pendingRetirement -RequireV20).Count -eq 0 -and
        -not (Test-T5TerminalPrivateVersion $pendingRetirementProjection)) 'RetireUnexposed pending receipt is not a terminal ACK'
    $pendingRetirementOutcome = Get-T5EmptyProbeOutcome @($pendingRetirementProjection) $true
    Assert-T5 ($pendingRetirementOutcome.Verified -and $pendingRetirementOutcome.Kind -eq 'PRIVATE_DELETE_PENDING_ACK' -and
        $pendingRetirementOutcome.UnsealedCleanupAcknowledgedRecords.Count -eq 0) 'RetireUnexposed pending receipt stays separately pending'

    $malformedRetirement = New-T5Entry 12 'malformed-retirement' $driver $basePath
    Set-T5DiscardAck $malformedRetirement 6 $malformedRetirement.Transfer.TransferId
    $malformedRetirementProjection = Get-T5Projection $malformedRetirement 'unused-malformed-retirement.json'
    Assert-T5 ((Get-T5FixtureErrors $malformedRetirement -RequireV20).Count -gt 0 -and
        -not (Test-T5TerminalPrivateVersion $malformedRetirementProjection)) 'kind-6 ACK without RetiredUnexposed receipt is malformed'
    $malformedRetirementOutcome = Get-T5EmptyProbeOutcome @($malformedRetirementProjection) $true
    Assert-T5 (-not $malformedRetirementOutcome.Verified -and
        $malformedRetirementOutcome.UnsealedCleanupAcknowledgedRecords.Count -eq 0) 'malformed retirement cannot classify as acknowledged private cleanup'
    $missingRetireRequest = $retiredAttachedPrivate.PSObject.Copy()
    $missingRetireRequest.RetireRequestIdV20 = $null
    $missingRetireProjection = Get-T5Projection $missingRetireRequest 'unused-missing-retire-request.json'
    Assert-T5 ((Get-T5FixtureErrors $missingRetireRequest -RequireV20).Count -gt 0 -and
        -not (Test-T5TerminalPrivateVersion $missingRetireProjection)) 'kind-7 ACK without exact RetireRequestId is malformed'

    $missingIdentity = New-T5Entry 11 'missing-identity' $driver $basePath
    $missingIdentity.StageIdentity = $null
    Assert-T5 ((Get-T5FixtureErrors $missingIdentity -RequireV20).Count -gt 0) 'missing exact stage identity must fail'
    $missingHistory = New-T5Entry 0 'missing-history' $driver $basePath
    $missingHistory.PSObject.Properties.Remove('StateHistory')
    Assert-T5 ((Get-T5FixtureErrors $missingHistory -RequireV20).Count -gt 0) 'a new measured V20 record cannot omit state history'
    $badNotification = New-T5Entry 11 'bad-empty-notification' $driver $basePath
    $badNotification.EmptyHeldNotificationAttemptedAtUtc = '2026-10-11T12:00:00+00:00'
    Assert-T5 ((Get-T5FixtureErrors $badNotification -RequireV20).Count -gt 0) 'empty-held notice attempt requires its exact publisher instance'
    $missingCleanupState = New-T5Entry 11 'missing-cleanup-state' $driver $basePath
    $missingCleanupState.StageCleanupStarted = $null
    Assert-T5 ((Get-T5FixtureErrors $missingCleanupState -RequireV20).Count -gt 0) 'measured cleanup state must be an explicit boolean'
    $unknownState = New-T5Entry 0 'unknown-state' $driver $basePath
    $unknownState.State = 13
    $unknownState.StateHistory = (New-T5History @(0, 13))
    Assert-T5 ((Get-T5FixtureErrors $unknownState -RequireV20).Count -gt 0) 'unknown numeric state must fail'
    $badHistory = New-T5Entry 1 'bad-history' $driver $basePath
    # 10 -> 1 is a valid SealPending completion; 10 -> 2 is not.
    $badHistory.StateHistory = (New-T5History @(0, 10, 2, 1))
    Assert-T5 ((Get-T5FixtureErrors $badHistory -RequireV20).Count -gt 0) 'impossible history transition must fail'
    $longHistory = New-T5Entry 0 'long-history' $driver $basePath
    $longHistory.StateHistory = New-T5History (@(0) + (1..64))
    $longHistoryErrors = Get-T5FixtureErrors $longHistory -RequireV20
    Assert-T5 ($longHistoryErrors -contains 'StateHistory exceeds the service limit of 64 entries') 'history longer than 64 states must fail specifically at the bound'

    $released = New-T5Entry 5 'released' $driver $basePath
    Assert-T5 ((Get-T5FixtureErrors $released -RequireV20).Count -eq 0) 'positive nonempty Released save must validate'
    $emptyReleased = New-T5Entry 5 'empty-released' $driver $basePath
    $emptyReleased.SealedLength = [long]0
    $emptyReleased.Sha256Hex = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'
    Assert-T5 ((Get-T5FixtureErrors $emptyReleased -RequireV20).Count -eq 0) 'ordinary measured-zero Released state must validate with its exact empty digest and identity'
    $emptyReleased.StageDeleted = $true
    Assert-T5 ((Get-T5FixtureErrors $emptyReleased -RequireV20).Count -eq 0) 'ordinary measured-zero Released stage cleanup is authorized'
    $wrongEmptyDigest = $emptyReleased.PSObject.Copy()
    $wrongEmptyDigest.Sha256Hex = 'A' * 64
    Assert-T5 ((Get-T5FixtureErrors $wrongEmptyDigest -RequireV20).Count -gt 0) 'ordinary measured-zero publication with a nonempty digest must fail'
    $missingEmptyIdentity = $emptyReleased.PSObject.Copy()
    $missingEmptyIdentity.StageIdentity = $null
    Assert-T5 ((Get-T5FixtureErrors $missingEmptyIdentity -RequireV20).Count -gt 0) 'ordinary measured-zero publication without exact identity must fail'
    $unmeasuredEmpty = $emptyReleased.PSObject.Copy()
    $unmeasuredEmpty.SealedLength = $null
    Assert-T5 ((Get-T5FixtureErrors $unmeasuredEmpty -RequireV20).Count -gt 0) 'ordinary publication without a measured length must fail'
    $unsealedEmpty = $emptyReleased.PSObject.Copy()
    $unsealedEmpty.SealedOnce = $false
    Assert-T5 ((Get-T5FixtureErrors $unsealedEmpty -RequireV20).Count -gt 0) 'ordinary measured-zero publication without a completed seal must fail'
    $emptyReleasedProjection = Get-T5Projection $emptyReleased 'unused.json'
    $unexpectedEmptyOutcome = Get-T5EmptyProbeOutcome @($emptyReleasedProjection) $true
    Assert-T5 (-not $unexpectedEmptyOutcome.Verified) 'empty Released content must never classify as private'

    $blocked = New-T5Entry 6 'blocked-handback' $driver $basePath
    $blocked.HandbackState = [int]2
    $blocked.HandbackPath = Join-Path $tempRoot 'handback.txt'
    $blocked.HandbackLength = [long]5
    $blocked.BlockedPolicyVersion = [int]1
    $blocked.JustificationWindowClosed = $true
    $blocked.StageDeleted = $true
    Assert-T5 ((Get-T5FixtureErrors $blocked -RequireV20).Count -eq 0) 'verified blocked handback evidence must validate'

    $held = New-T5Entry 11 'held-outcome' $driver $basePath
    $heldProjection = Get-T5Projection $held 'unused-held.json'
    $heldOutcome = Get-T5EmptyProbeOutcome @($heldProjection) $true
    Assert-T5 ($heldOutcome.Verified -and $heldOutcome.Kind -eq 'EMPTY_HELD_PRIVATE') 'EmptyHeld is a valid private empty outcome'
    Assert-T5 (-not $heldOutcome.CleanupAcknowledged) 'an unacknowledged EmptyHeld stage must not claim cleanup'
    $pendingPrivate = New-T5Entry 12 'pending-private-delete' $driver $basePath
    Set-T5HandleObserved $pendingPrivate
    $pendingPrivateProjection = Get-T5Projection $pendingPrivate 'unused-pending-private.json'
    $pendingPrivateOutcome = Get-T5EmptyProbeOutcome @($pendingPrivateProjection) $true
    Assert-T5 ($pendingPrivateOutcome.Verified -and $pendingPrivateOutcome.Kind -eq 'PRIVATE_DELETE_PENDING_ACK' -and
        -not $pendingPrivateOutcome.CleanupAcknowledged) 'a durable unsealed private-delete intent is a private outcome while cleanup remains separately pending'
    $heldAck = New-T5Entry 11 'held-ack' $driver $basePath
    Set-T5DiscardAck $heldAck 3 $heldAck.Transfer.TransferId
    $heldAckProjection = Get-T5Projection $heldAck 'unused-held-ack.json'
    $heldAckOutcome = Get-T5EmptyProbeOutcome @($heldAckProjection) $true
    Assert-T5 ($heldAckOutcome.Verified -and $heldAckOutcome.CleanupAcknowledged) 'EmptyHeld cleanup ACK is reported separately'

    $journalDir = Join-Path $tempRoot 'journal'
    New-Item -ItemType Directory -Path $journalDir -Force | Out-Null
    $script:journalDir = $journalDir
    $parent = New-T5Entry 11 'direct-parent' $driver $basePath
    $child = New-T5Entry 5 'direct-child' $driver $basePath
    $child.StageDeleted = $true
    Set-T5ExactParent $child $parent
    Set-T5HandleObserved $child
    Set-T5DiscardAck $parent 2 $child.Transfer.TransferId
    $parent.UpdatedAtUtc = '2026-10-11T12:22:00.0000000+00:00'
    $parentIdentity = [pscustomobject]@{
        TransferId = $parent.Transfer.TransferId
        DestinationGeneration = $parent.DestinationGeneration
        StageIdentity = $parent.StageIdentity
    }
    $child.ParentVersionIdentity = $parentIdentity
    $parentPath = Join-Path $journalDir ($parent.Transfer.TransferId.Replace('-', '') + '.json')
    $childPath = Join-Path $journalDir ($child.Transfer.TransferId.Replace('-', '') + '.json')
    [IO.File]::WriteAllText($parentPath, ($parent | ConvertTo-Json -Depth 32 -Compress), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($childPath, ($child | ConvertTo-Json -Depth 32 -Compress), [Text.UTF8Encoding]::new($false))
    $releasedPendingParent = $parent.PSObject.Copy()
    $releasedPendingParent.DiscardAcknowledgedAtUtc = $null
    $releasedPendingChild = $child.PSObject.Copy()
    $releasedPendingChild.StageDeleted = $false
    $releasedPendingParentProjection = Get-T5Projection $releasedPendingParent 'unused-released-pending-parent.json'
    $releasedPendingChildProjection = Get-T5Projection $releasedPendingChild 'unused-released-pending-child.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($releasedPendingParentProjection, $releasedPendingChildProjection)).Count -eq 0) 'a released direct child may await gate-confirmed disposal while its EmptyHeld parent cleanup is pending'
    Assert-T5 (Test-T5DirectEmptyHeldChildTerminal $releasedPendingParentProjection $releasedPendingChildProjection $false) 'direct Released child in NotAttempted handback state may await gate-confirmed disposal'
    Assert-T5 (-not (Test-T5DirectEmptyHeldChildTerminal $releasedPendingParentProjection $releasedPendingChildProjection $true)) 'direct Released child cannot satisfy an ACK before StageDeleted'

    $failedHandbackChild = $releasedPendingChildProjection.PSObject.Copy()
    $failedHandbackChild.HandbackState = '3'
    $failedHandbackChild.HandbackFailureReason = 'fixture failure'
    Assert-T5 (-not (Test-T5DirectEmptyHeldChildTerminal $releasedPendingParentProjection $failedHandbackChild $false) -and
        @(Get-T5JournalLineageErrors @($releasedPendingParentProjection, $failedHandbackChild)).Count -gt 0) 'Failed handback Released child is not terminal for EmptyHeld cleanup'

    $pendingRenameChild = $releasedPendingChildProjection.PSObject.Copy()
    $pendingRenameChild.PendingRename = [pscustomobject]@{
        TransactionId = [uint64]91
        DestinationPath = (Join-Path $tempRoot 'pending-rename.txt')
        SealedVersion = [bool]$true
    }
    Assert-T5 (-not (Test-T5DirectEmptyHeldChildTerminal $releasedPendingParentProjection $pendingRenameChild $false) -and
        @(Get-T5JournalLineageErrors @($releasedPendingParentProjection, $pendingRenameChild)).Count -gt 0) 'pending rename prevents direct-child cleanup classification'

    $sameStageChild = $releasedPendingChildProjection.PSObject.Copy()
    $sameStageChild.StageIdentity = $releasedPendingParentProjection.StageIdentity
    Assert-T5 (-not (Test-T5DirectEmptyHeldChildTerminal $releasedPendingParentProjection $sameStageChild $false)) 'direct child must have a distinct exact stage identity from its parent'
    $wrongCreateReservationChild = $releasedPendingChildProjection.PSObject.Copy()
    $wrongCreateReservationChild.CreateReservationId = [guid]::NewGuid().ToString()
    Assert-T5 (-not (Test-T5DirectEmptyHeldChildTerminal $releasedPendingParentProjection $wrongCreateReservationChild $false)) 'direct child create reservation must be its exact transfer ID'
    $wrongAllocationReferenceChild = $releasedPendingChildProjection.PSObject.Copy()
    $wrongAllocationReferenceChild.AllocationReferenceId = [guid]::NewGuid().ToString()
    Assert-T5 (-not (Test-T5DirectEmptyHeldChildTerminal $releasedPendingParentProjection $wrongAllocationReferenceChild $false)) 'direct child allocation reference must name the exact parent'
    $cleanupStartedChild = $releasedPendingChildProjection.PSObject.Copy()
    $cleanupStartedChild.StageCleanupStarted = [bool]$true
    Assert-T5 (-not (Test-T5DirectEmptyHeldChildTerminal $releasedPendingParentProjection $cleanupStartedChild $false)) 'direct child with cleanup already started is not terminal'

    $verifiedHandbackChild = $releasedPendingChildProjection.PSObject.Copy()
    $verifiedHandbackChild.HandbackState = '2'
    $verifiedHandbackChild.HandbackPath = Join-Path $tempRoot 'verified-handback.txt'
    $verifiedHandbackChild.HandbackLength = [long]5
    $verifiedHandbackChild.JustificationWindowClosed = [bool]$true
    $verifiedHandbackChild.StageDeleted = [bool]$true
    Assert-T5 (Test-T5DirectEmptyHeldChildTerminal $releasedPendingParentProjection $verifiedHandbackChild $true) 'Verified handback child is terminal only after justification closes and stage deletion is acknowledged'

    $ownerExitChild = New-T5Entry 11 'direct-owner-exit-child' $driver $basePath
    Set-T5ExactParent $ownerExitChild $parent
    $ownerExitChild.StageIdentity = New-T5Identity ([uint64]500)
    Set-T5DiscardAck $ownerExitChild 3 $ownerExitChild.Transfer.TransferId
    $ownerExitChildProjection = Get-T5Projection $ownerExitChild 'unused-owner-exit-child.json'
    Assert-T5 (Test-T5TerminalPrivateVersion $ownerExitChildProjection) 'valid EmptyHeld owner-exit self-ACK remains terminal cleanup evidence'
    $ownerExitPendingParent = $parent.PSObject.Copy()
    Set-T5DiscardAck $ownerExitPendingParent 2 $ownerExitChild.Transfer.TransferId
    $ownerExitPendingParent.DiscardAcknowledgedAtUtc = $null
    $ownerExitPendingProjection = Get-T5Projection $ownerExitPendingParent 'unused-owner-exit-pending-parent.json'
    Assert-T5 (Test-T5DirectEmptyHeldChildTerminal $ownerExitPendingProjection $ownerExitChildProjection $false) 'exact self-reserved EmptyHeld owner-exit child is a terminal direct successor'
    $ownerExitParent = $ownerExitPendingParent.PSObject.Copy()
    Set-T5DiscardAck $ownerExitParent 2 $ownerExitChild.Transfer.TransferId
    $ownerExitParent.DiscardRequestedAtUtc = '2026-10-11T12:21:00.0000000+00:00'
    $ownerExitParent.DiscardAcknowledgedAtUtc = '2026-10-11T12:21:01.0000000+00:00'
    $ownerExitParentProjection = Get-T5Projection $ownerExitParent 'unused-owner-exit-parent.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($ownerExitParentProjection, $ownerExitChildProjection)).Count -eq 0) 'direct EmptyHeld cleanup may follow exact owner-exit ACK of its child'
    $ownerExitOutcome = Get-T5EmptyProbeOutcome @($ownerExitParentProjection, $ownerExitChildProjection) $true
    Assert-T5 ($ownerExitOutcome.Verified -and $ownerExitOutcome.CleanupAcknowledged -and
        $ownerExitOutcome.PrivateOutcomeCleanupAcknowledgedRecords.Count -eq 2) 'both self cleanup and validated predecessor cleanup ACKs remain visible for private EmptyHeld records'

    $journal = Get-JournalFor -Destination $basePath -BaselineTransferIds @() -RequireHistoryForNewRecords
    Assert-T5 (@($journal.ParseErrors).Count -eq 0 -and @($journal.SchemaErrors).Count -eq 0) ('serialized exact direct HandleObserved chain must validate: ' + (@($journal.SchemaErrors | ForEach-Object Error) -join '; '))
    Assert-T5 (@($journal.Records).Count -eq 2) 'full journal projection retains both exact lineage records'
    foreach ($sourceRecord in @($parent, $child)) {
        $matchingReceipt = @($journal.Records | Where-Object {
            $_.TransferId -eq $sourceRecord.Transfer.TransferId -and $_.AttachmentStateV20 -eq 6 -and
            $_.HandleObservedRequestIdV20 -eq $sourceRecord.HandleObservedRequestIdV20
        })
        Assert-T5 ($matchingReceipt.Count -eq 1) 'projection retains the exact per-transfer HandleObserved receipt for both parent and child'
    }

    $noObserved = New-T5Entry 5 'no-observed-child' $driver $basePath
    $noObserved.StageDeleted = $true
    Set-T5ExactParent $noObserved $parent
    $parent.DiscardReservationId = $noObserved.Transfer.TransferId
    $noObserved.ParentVersionIdentity = [pscustomobject]@{
        TransferId = $parent.Transfer.TransferId
        DestinationGeneration = $parent.DestinationGeneration
        StageIdentity = $parent.StageIdentity
    }
    $noObserved.AttachmentStateV20 = [uint32]5
    $noObserved.AttachPrepareRequestIdV20 = [uint64]20
    $noObserved.AttachCommitRequestIdV20 = [uint64]21
    $noObserved.AttachCommitResultV20 = [uint32]7
    $noObserved.CompletionPermitRequestIdV20 = [uint64]22
    $noObserved.HandleObservedRequestIdV20 = $null
    $noObservedProjection = Get-T5Projection $noObserved 'unused-no-observed.json'
    $parentProjection = Get-T5Projection $parent 'unused-parent.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($parentProjection, $noObservedProjection)).Count -gt 0) 'V1 cleanup ACK without live-child op19 must fail'
    $pendingParent = $parent.PSObject.Copy()
    $pendingParent.DiscardReservationId = $noObserved.Transfer.TransferId
    $pendingParent.DiscardKind = [uint32]2
    $pendingParent.DiscardRequestedAtUtc = '2026-10-11T12:20:00.0000000+00:00'
    $pendingParent.DiscardAcknowledgedAtUtc = $null
    $pendingParentProjection = Get-T5Projection $pendingParent 'unused-pending-parent.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($pendingParentProjection, $noObservedProjection)).Count -gt 0) 'V1 cleanup intent without live-child op19 must remain invalid before ACK'

    $wrongEpoch = New-T5Entry 5 'wrong-epoch-child' ([guid]::NewGuid()) $basePath
    $wrongEpoch.StageDeleted = $true
    Set-T5ExactParent $wrongEpoch $parent
    $wrongEpoch.ParentVersionIdentity = [pscustomobject]@{
        TransferId = $parent.Transfer.TransferId
        DestinationGeneration = $parent.DestinationGeneration
        StageIdentity = $parent.StageIdentity
    }
    $wrongEpochProjection = Get-T5Projection $wrongEpoch 'unused-wrong-epoch.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($parentProjection, $wrongEpochProjection)).Count -gt 0) 'different-epoch successor must fail'
    $wrongAncestry = New-T5Entry 5 'wrong-ancestry-child' $driver $basePath
    $wrongAncestry.StageDeleted = $true
    Set-T5ExactParent $wrongAncestry $parent
    $wrongAncestry.ParentVersionIdentity.StageIdentity.FileIdLow = [uint64]9999
    $wrongAncestryProjection = Get-T5Projection $wrongAncestry 'unused-wrong-ancestry.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($parentProjection, $wrongAncestryProjection)).Count -gt 0) 'mismatched exact parent FileId must fail'
    $wrongReservationParent = New-T5Entry 11 'wrong-reservation-parent' $driver $basePath
    $wrongReservationChild = New-T5Entry 5 'wrong-reservation-child' $driver $basePath
    $wrongReservationChild.StageDeleted = $true
    Set-T5ExactParent $wrongReservationChild $wrongReservationParent
    $wrongReservationChild.ParentVersionIdentity = [pscustomobject]@{
        TransferId = $wrongReservationParent.Transfer.TransferId
        DestinationGeneration = $wrongReservationParent.DestinationGeneration
        StageIdentity = $wrongReservationParent.StageIdentity
    }
    Set-T5DiscardAck $wrongReservationParent 2 ([guid]::NewGuid().ToString())
    $wrongReservationProjection = Get-T5Projection $wrongReservationParent 'unused-reservation-parent.json'
    $wrongReservationChildProjection = Get-T5Projection $wrongReservationChild 'unused-reservation-child.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($wrongReservationProjection, $wrongReservationChildProjection)).Count -gt 0) 'wrong predecessor cleanup reservation must fail'

    $tombstoneOwner = New-T5Entry 1 'rename-owner' $driver (Join-Path $tempRoot 'renamed-target.txt')
    $tombstoneOwner.NamespaceTombstones = [pscustomobject]@{
        DestinationPath = $basePath
        Generation = [long]200
        Previous = $null
    }
    $tombstoneChild = New-T5Entry 0 'rename-successor' $driver $basePath
    $tombstoneChild.DestinationGeneration = [long]201
    $tombstoneChild.AllocationDisposition = [uint32]2
    $tombstoneChild.AllocationReferenceKind = [uint32]2
    $tombstoneChild.AllocationReferenceId = $tombstoneOwner.Transfer.TransferId
    $tombstoneOwnerProjection = Get-T5Projection $tombstoneOwner 'unused-rename-owner.json'
    $tombstoneChildProjection = Get-T5Projection $tombstoneChild 'unused-rename-child.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($tombstoneOwnerProjection, $tombstoneChildProjection)).Count -eq 0) 'exact rename tombstone owner authorizes the next high-water generation across its moved path'
    $tombstoneChild.DestinationGeneration = [long]202
    $badTombstoneProjection = Get-T5Projection $tombstoneChild 'unused-bad-rename-child.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($tombstoneOwnerProjection, $badTombstoneProjection)).Count -gt 0) 'stale tombstone generation cannot authorize a successor'

    $duplicateRequest = New-T5Entry 1 'duplicate-request' $driver $basePath
    Set-T5HandleObserved $duplicateRequest
    $duplicateRequest.HandleObservedRequestIdV20 = $duplicateRequest.CompletionPermitRequestIdV20
    Assert-T5 ((Get-T5FixtureErrors $duplicateRequest -RequireV20).Count -gt 0) 'same RequestId replay across lifecycle phases must fail'

    $deepParent = New-T5Entry 11 'deep-v1' $driver $basePath
    $deepDelete = New-T5Entry 12 'deep-v2' $driver $basePath
    $deepChild = New-T5Entry 0 'deep-v3' $driver $basePath
    Set-T5ExactParent $deepDelete $deepParent
    Set-T5ExactParent $deepChild $deepParent
    $deepDelete.ParentVersionIdentity = [pscustomobject]@{
        TransferId = $deepParent.Transfer.TransferId
        DestinationGeneration = $deepParent.DestinationGeneration
        StageIdentity = $deepParent.StageIdentity
    }
    $deepDelete.CreateAfterReservationId = $deepChild.Transfer.TransferId
    Set-T5HandleObserved $deepDelete
    Set-T5DiscardAck $deepDelete 1 $deepDelete.Transfer.TransferId
    $deepDelete.DiscardAcknowledgedAtUtc = '2026-10-11T12:20:01.0000000+00:00'
    $deepChild.DestinationGeneration = [long]($deepDelete.DestinationGeneration + 1)
    $deepChild.DeleteVersionIdentity = [pscustomobject]@{
        TransferId = $deepDelete.Transfer.TransferId
        DestinationGeneration = $deepDelete.DestinationGeneration
        StageIdentity = $deepDelete.StageIdentity
    }
    $deepChild.AllocationReferenceId = $deepDelete.Transfer.TransferId
    $deepChild.AllocationReferenceKind = [uint32]1
    $deepChild.AllocationDisposition = [uint32]5
    $deepParent.DestinationGeneration = [long]($deepDelete.DestinationGeneration - 1)
    $deepParentIdentity = [pscustomobject]@{
        TransferId = $deepParent.Transfer.TransferId
        DestinationGeneration = $deepParent.DestinationGeneration
        StageIdentity = $deepParent.StageIdentity
    }
    $deepDelete.ParentVersionIdentity = $deepParentIdentity
    $deepChild.ParentVersionIdentity = $deepParentIdentity
    Set-T5DiscardAck $deepParent 2 $deepChild.Transfer.TransferId
    $deepParent.DiscardRequestedAtUtc = '2026-10-11T12:20:02.0000000+00:00'
    $deepParent.DiscardAcknowledgedAtUtc = '2026-10-11T12:20:03.0000000+00:00'
    $deepParentProjection = Get-T5Projection $deepParent 'unused-deep-v1.json'
    $deepDeleteProjection = Get-T5Projection $deepDelete 'unused-deep-v2.json'
    $deepChildProjection = Get-T5Projection $deepChild 'unused-deep-v3.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($deepParentProjection, $deepDeleteProjection, $deepChildProjection)).Count -gt 0) 'V3 without op19 or terminal disposition cannot ACK V1'

    $deepNoDeleteReceipt = $deepDelete.PSObject.Copy()
    $deepNoDeleteReceipt.AttachmentStateV20 = [uint32]5
    $deepNoDeleteReceipt.HandleObservedRequestIdV20 = $null
    $deepNoDeleteReceiptProjection = Get-T5Projection $deepNoDeleteReceipt 'unused-deep-v2-no-op19.json'
    $deepReadyChild = $deepChild.PSObject.Copy()
    Set-T5HandleObserved $deepReadyChild
    $deepReadyChildProjection = Get-T5Projection $deepReadyChild 'unused-deep-v3-ready.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($deepParentProjection, $deepNoDeleteReceiptProjection, $deepReadyChildProjection)).Count -gt 0) 'CREATE_AFTER cannot mutate a v20 delete intent without its exact op15/op19 predecessor receipt'
    $deepNoIntentParent = $deepParent.PSObject.Copy()
    $deepNoIntentParent.DiscardReservationId = $null
    $deepNoIntentParent.DiscardKind = $null
    $deepNoIntentParent.DiscardRequestedAtUtc = $null
    $deepNoIntentParent.DiscardAcknowledgedAtUtc = $null
    $deepNoIntentParentProjection = Get-T5Projection $deepNoIntentParent 'unused-deep-v1-no-cleanup-intent.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($deepNoIntentParentProjection, $deepNoDeleteReceiptProjection, $deepReadyChildProjection)).Count -gt 0) 'a durable CREATE_AFTER reservation cannot hide missing V2 op15/op19 evidence before V1 cleanup begins'

    Set-T5DiscardAck $deepChild 5 $deepChild.Transfer.TransferId
    $deepChild.DiscardAcknowledgedAtUtc = '2026-10-11T12:20:01.0000000+00:00'
    $deepChild.State = 12
    $deepChild.SealedOnce = $false
    $deepChild.SealedLength = $null
    $deepChild.Sha256Hex = $null
    $deepChild.AttachmentStateV20 = [uint32]0
    $deepChild.StateHistory = (New-T5History @(0, 12))
    $deepChild.DiscardKind = [uint32]5
    $deepChild.DiscardReservationId = $deepChild.Transfer.TransferId
    $deepChildProjection = Get-T5Projection $deepChild 'unused-deep-v3-terminal.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($deepParentProjection, $deepDeleteProjection, $deepChildProjection)).Count -eq 0) 'late exact V3 terminal ACK plus V2 ACK permits V1 ACK with original V3 reservation'

    $deepLiveParent = New-T5Entry 11 'deep-live-v1' $driver $basePath
    $deepLiveDelete = New-T5Entry 12 'deep-live-v2' $driver $basePath
    $deepLiveChild = New-T5Entry 0 'deep-live-v3' $driver $basePath
    Set-T5ExactParent $deepLiveDelete $deepLiveParent
    Set-T5ExactParent $deepLiveChild $deepLiveParent
    $deepLiveParent.DestinationGeneration = [long]200
    $deepLiveDelete.DestinationGeneration = [long]201
    $deepLiveChild.DestinationGeneration = [long]202
    $deepLiveDelete.ParentVersionIdentity = [pscustomobject]@{
        TransferId = $deepLiveParent.Transfer.TransferId
        DestinationGeneration = $deepLiveParent.DestinationGeneration
        StageIdentity = $deepLiveParent.StageIdentity
    }
    $deepLiveDelete.CreateAfterReservationId = $deepLiveChild.Transfer.TransferId
    Set-T5HandleObserved $deepLiveDelete
    Set-T5DiscardAck $deepLiveDelete 1 $deepLiveDelete.Transfer.TransferId
    $deepLiveChild.ParentVersionIdentity = $deepLiveDelete.ParentVersionIdentity
    $deepLiveChild.DeleteVersionIdentity = [pscustomobject]@{
        TransferId = $deepLiveDelete.Transfer.TransferId
        DestinationGeneration = $deepLiveDelete.DestinationGeneration
        StageIdentity = $deepLiveDelete.StageIdentity
    }
    $deepLiveChild.AllocationReferenceId = $deepLiveDelete.Transfer.TransferId
    $deepLiveChild.AllocationReferenceKind = [uint32]1
    $deepLiveChild.AllocationDisposition = [uint32]5
    Set-T5HandleObserved $deepLiveChild
    Set-T5DiscardAck $deepLiveParent 2 $deepLiveChild.Transfer.TransferId
    $deepLiveParent.DiscardRequestedAtUtc = '2026-10-11T12:20:02.0000000+00:00'
    $deepLiveParent.DiscardAcknowledgedAtUtc = '2026-10-11T12:20:03.0000000+00:00'
    $deepLiveParentProjection = Get-T5Projection $deepLiveParent 'unused-live-v1.json'
    $deepLiveDeleteProjection = Get-T5Projection $deepLiveDelete 'unused-live-v2.json'
    $deepLiveChildProjection = Get-T5Projection $deepLiveChild 'unused-live-v3.json'
    Assert-T5 (@(Get-T5JournalLineageErrors @($deepLiveParentProjection, $deepLiveDeleteProjection, $deepLiveChildProjection)).Count -eq 0) 'same-epoch V1/V2/V3 HandleObserved receipt chain must validate'

    $journalAfter = Get-JournalFor -Destination $basePath -BaselineTransferIds @() -RequireHistoryForNewRecords
    Assert-T5 (@($journalAfter.ParseErrors).Count -eq 0 -and @($journalAfter.SchemaErrors).Count -eq 0) 'serialized exact manifest projection must validate'
    Assert-T5 (@($journalAfter.Records | Where-Object { $_.TransferId -eq $parent.Transfer.TransferId -and $_.State -eq '11' -and $_.SealedLength -eq 0 }).Count -eq 1) 'projection preserves EmptyHeld state and zero measured length'
    Assert-T5 (@($journalAfter.Records | Where-Object { $_.TransferId -eq $child.Transfer.TransferId -and $_.ParentVersionIdentity -and $_.DriverInstanceId -eq $driver.ToString() }).Count -eq 1) 'projection preserves exact ancestry and epoch'
    $projectedChild = $journalAfter.Records | Where-Object { $_.TransferId -eq $child.Transfer.TransferId } | Select-Object -First 1
    Assert-T5 ((Get-T5StateAtUtc $projectedChild 5) -eq (Get-T5UtcValue $child.StateHistory[-1].OccurredAtUtc)) 'projection preserves the exact Released state timestamp independently of later stage disposal'
    $child.HandleObservedRequestIdV20 = $child.CompletionPermitRequestIdV20
    [IO.File]::WriteAllText($childPath, ($child | ConvertTo-Json -Depth 32 -Compress), [Text.UTF8Encoding]::new($false))
    $badSerializedReplay = Get-JournalFor -Destination $basePath -BaselineTransferIds @() -RequireHistoryForNewRecords
    Assert-T5 (@($badSerializedReplay.SchemaErrors).Count -gt 0) 'serialized duplicate lifecycle RequestId must be rejected'
} finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}

Write-Output ('T5 coordinator schema self-check PASS (' + $script:assertions + ' assertions).')
