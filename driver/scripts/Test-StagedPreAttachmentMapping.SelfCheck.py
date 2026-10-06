#!/usr/bin/env python3
"""Offline structural checks for the pre-attachment mapping repro verdict gate."""
from pathlib import Path
import hashlib
import re


SCRIPTS = Path(__file__).resolve().parent
HARNESS = SCRIPTS / "Test-StagedPreAttachmentMapping.ps1"
HISTORICAL = SCRIPTS.parent / "evidence" / "2026-10-02" / "fence15-repro-a-gate.txt"
OBSERVER = SCRIPTS / "StagedMappingByteObserver.ps1"
M2 = SCRIPTS / "Test-StagedPolicyTransitionMapping.ps1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def verdict(*, write: str, flush: str, source_released: bool,
            view_released: bool, mapping_released: bool,
            post_file_flush: str, buffered: str, uncached: str, raw: str | None,
            raw_samples: int = 20) -> str:
    exposed = buffered == "CHANGED" or uncached == "CHANGED" or raw == "CHANGED"
    if exposed:
        return "REPRODUCED"
    complete = (write == "SUCCESS" and flush == "SUCCESS" and source_released
                and post_file_flush == "SUCCESS" and view_released and mapping_released
                and buffered == "BASELINE"
                and uncached == "BASELINE" and raw == "BASELINE"
                and raw_samples == 20)
    if complete:
        return "BLOCKED"
    return "INCONCLUSIVE"


def cleanup_allowed(*, view_released: bool, mapping_released: bool,
                    file_released: bool) -> bool:
    return view_released and mapping_released and file_released


def main() -> None:
    source = HARNESS.read_text(encoding="utf-8")
    observer = OBSERVER.read_text(encoding="utf-8")
    transition = M2.read_text(encoding="utf-8")
    observer_hash = hashlib.sha256(OBSERVER.read_bytes()).hexdigest()
    required = (
        "function Get-FirstLcn",
        "function Read-RawFixtureBytes",
        "function Flush-IndependentFileBuffers",
        "function Test-BytesEqual",
        "$retrievalInput = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)",
        "FlushFileBuffers($file.SafeFileHandle.DangerousGetHandle())",
        "Flush-IndependentFileBuffers $target",
        "$postWriteFlush.Succeeded",
        "if ($returned -lt 32)",
        "$startingVcn -ne 0 -or $nextVcn -lt 1 -or $lcn -lt 0",
        "Invoke-StagedMappingByteObserver",
        "-ReadBuffered -ReadUncached -RawSamples 20",
        "ConvertFrom-StagedObserverByteRead",
        "ConvertFrom-StagedObserverRawRead $observer $rawBaseline 20",
        "$rawLocationStable -and $rawComparisonAttempts -eq 20",
        "RawBaselineExtent=IDENTICAL_TO_FIXTURE; Bytes=4096; DifferentBytes=0",
        "$view.WriteArray(0, $mapped, 0, $mapped.Length)",
        "$view.Flush(); $viewFlushOutcome = 'SUCCESS'",
        "$viewReleased -and $mappingReleased",
        "$rawComparison.State -eq 'UNEXPECTED_BYTES_CHANGED'",
        "$bufferedObservation.Succeeded -and $uncachedObservation.Succeeded",
        "$rawComparison.State -eq 'IDENTICAL_TO_BASELINE'",
        "$rawComparisonAttempts -eq 20 -and -not $rawComparisonError",
        "elseif ($measurementComplete) { 'UnauthenticatedMappedWriteAfterAttach=BLOCKED' }",
        "else { 'UnauthenticatedMappedWriteAfterAttach=INCONCLUSIVE' }",
    )
    for item in required:
        require(item in source, "Missing mapping verdict invariant: " + item)
    require(f"$expectedObserverHelperSha256 = '{observer_hash}'" in source,
            "M1 does not pin the separate-process observer helper bytes")
    require(re.search(r"\$input\b", source, re.IGNORECASE) is None,
            "Get-FirstLcn reuses PowerShell's automatic $Input variable")
    require("throw 'OWNER_SETUP_API_TODO:" in source,
            "M1 could be run as a new pass without authenticated owner setup")
    require("delay its fixed-NTFS-only test-policy activation until the private mapping and flush" in source and
            "Do not claim USB," in source,
            "M1 no longer documents deferred fixed-NTFS policy activation and its limited scope")
    require(source.index("throw 'OWNER_SETUP_API_TODO:") < source.index("[IO.Directory]::CreateDirectory($fixtureDirectory)"),
            "M1 owner setup gate occurs after the test creates or mutates its fixture")
    require("ParentProcessId = $PID" in observer and "ChildProcessId = $PID" in observer and
            "Start-Process -FilePath $powershellPath" in observer,
            "Byte observer is not a distinct PowerShell process")
    require("FILE_FLAG_NO_BUFFERING" in source or "[uint32]2684354560" in observer,
            "Separate-process uncached reader lost no-buffering/write-through flags")
    require("FSCTL_GET_RETRIEVAL_POINTERS" in observer and "\\\\.\\C:" in observer and
            "if ($sampleLcn -ne [long]$request.ExpectedLcn)" in observer,
            "Child observer lost the direct raw-volume/LCN stability oracle")
    require("$read -ne [uint32]$ClusterSize" in observer and
            "[long]$targetItem.Length -ne [long]$baseline.Length" in observer,
            "Child observer accepts a short raw-cluster read or a changed fixture length")
    require(observer.count("$index -lt $BaselineBytes.Length") == 2 and
            "for ($i = 0; $i -lt $Left.Length; $i++)" in observer,
            "Full byte-array comparisons are missing from the child/result validators")
    worker = observer[observer.index("if (-not [string]::IsNullOrWhiteSpace($ObserverRequestBase64)) {"):]
    for forbidden in ("WriteAllBytes", "Copy-Item", "Set-ItemProperty", "fltmc.exe", "verifier.exe"):
        require(forbidden not in worker, "Observer worker contains an unrelated mutation path: " + forbidden)
    require(f"$expectedObserverHelperSha256 = '{observer_hash}'" in transition,
            "M2 does not pin the separate-process observer helper bytes")
    require("throw 'OWNER_SETUP_API_TODO:" in transition and "if (-not $PolicyRejectionOnly)" in transition,
            "M2 mapping gate is missing or disables the separate rejection-only mode")
    require("$ownerMonitorRoot = 'C:\\SafeUpload\\Escopo Monitorado'" in transition and
            "$ownerCandidateRoot = 'C:\\SafeUpload\\Owner Candidate'" in transition and
            "$fixtureDirectory = Join-Path $ownerCandidateRoot ('policy-transition-' + $id)" in transition and
            "function Assert-OwnerCandidateRoot" in transition and "Assert-OwnerCandidateRoot" in transition,
            "M2 is not fixed to the two bounded C: owner roots or lost its candidate-root guard")
    require("$fixtureDirectory = Join-Path $documents ('SafeUpload-policy-transition-' + $id)" not in transition,
            "M2 fixture still uses the broad Documents subtree")
    for invariant in (
        "function New-PolicyTransitionFixedNtfsPolicy",
        "function Get-PolicyTransitionNonTestScopeFingerprint",
        "function Assert-PolicyTransitionFixedNtfsPolicy",
        "$fixed.monitoredScopes.destinationPaths = @($ownerMonitorRoot)",
        "$fixed.monitoredScopes.removableDrives = $false",
        "$fixed.monitoredScopes.networkPaths = $false",
        "or other non-scope policy fields",
        "@($ownerMonitorRoot, $ownerCandidateRoot)",
        "'TestOnlyScope=FixedNTFS; RemovableAndNetworkScopes=False; USBUNCAndSyncDODQualification=NOT_CLAIMED'",
        "Test-PolicyTransitionBytesEqual $savedProductionPolicyBytes $policyBytes",
        "Test-PolicyTransitionBytesEqual $restoredPolicyBytes $policyBytes",
        "Test-PolicyTransitionBytesEqual $shrunkPolicyBytes $fixedNtfsPolicyBytes",
        "Test-PolicyTransitionBytesEqual $installedExpandedPolicyBytes $updatedPolicyBytes",
        "OriginalProductionPolicyRestoredExactBytes=True; USBUNCAndSyncDODPolicyRestored=True",
    ):
        require(invariant in transition,
                "M2 fixed-NTFS test-policy or exact production-policy preservation is missing: " + invariant)
    require(transition.index("FilterAttached=True; ExpansionAndShrinkMappingsCreatedBeforeFirstPolicyPush") <
            transition.index("[IO.File]::WriteAllBytes($policy, $fixedNtfsPolicyBytes)") <
            transition.index("$agent = Start-TestAgentAndWaitForPolicy $baseLog"),
            "M2 baseline test policy is not installed after mapping creation and before its first policy push")
    require(transition.index("if ($PolicyRejectionOnly)") <
            transition.index("[IO.File]::WriteAllBytes($policy, $fixedNtfsPolicyBytes)"),
            "PolicyRejectionOnly no longer bypasses the test-only fixed-NTFS policy mutation")
    transition_gate = transition.index("throw 'OWNER_SETUP_API_TODO:")
    require(transition_gate < transition.index("$serviceDirectoryCreationAttempted = $true") and
            transition_gate < transition.index("[IO.File]::WriteAllBytes($target, $fixtureBytes)"),
            "M2 owner setup gate occurs after fixture or service mutation")
    require("Read-FreshDestinationBytes" not in transition and "Read-UncachedText" not in transition and
            "Compare-RawFixtureToBaseline" not in transition,
            "M2 still has a same-process post-write byte observer path")
    require(transition.count("Invoke-StagedMappingByteObserver") >= 5,
            "M2 expansion, retained-section, or final raw observations bypass the child observer")
    for invariant in (
        "-ReadBuffered -ReadUncached",
        "-RawSamples 20 -RawSampleDelayMilliseconds 500",
        "-RawSamples 60 -RawSampleDelayMilliseconds 500",
        "$retainedViewWriteOutcome -eq 'SUCCESS'",
        "$retainedViewFlushOutcome -eq 'SUCCESS'",
        "$retainedFileBuffersFlushOutcome -eq 'SUCCESS'",
        "$retainedViewReleased",
        "$retainedMappingReleased -and $retainedFileReleased",
        "$expansionWriteOutcome -eq 'SUCCESS'",
        "$expansionFlushOutcome -eq 'SUCCESS'",
        "$expansionFileBuffersFlushOutcome -eq 'SUCCESS'",
        "$expansionMappingsReleased",
        "$expansionBufferedObservation.Succeeded -and $expansionBufferedObservation.State -eq 'IDENTICAL_TO_BASELINE'",
        "$expansionUncachedObservation.Succeeded -and $expansionUncachedObservation.State -eq 'IDENTICAL_TO_BASELINE'",
        "$expansionRawReadSucceeded -and $expansionRawObservation.Samples -eq 20",
        "$expansionRawReadSucceeded",
        "if ($retainedExposureObserved) { $retainedPrivacyVerdict = 'REPRODUCED' }",
        "if ($expansionExposureObserved) { $expansionPrivacyVerdict = 'REPRODUCED' }",
    ):
        require(invariant in transition, "M2 lost or weakened a mapped-write/privacy predicate: " + invariant)

    order = [
        source.index("RawBaselineExtent=IDENTICAL_TO_FIXTURE"),
        source.index("PreAttachmentFileHandleClosed=True"),
        source.index("FeatureAttachedWhileOriginalWritableSectionRemained=True"),
        source.index("PreAttachmentViewAndSectionReleased="),
        source.index("RawExtentComparison=$($rawComparison.State)"),
        source.index("if ($exposureObserved)"),
    ]
    require(order == sorted(order), "Baseline, attach, release and raw-read ordering changed")
    finalizer = source[source.index("finally {") :]
    release_guard = finalizer.index("if (-not $finalHandlesReleased)")
    restore_call = finalizer.index("Restore-StagedTestDriver")
    fixture_delete = finalizer.index("Remove-Item -LiteralPath $fixtureDirectory")
    require(release_guard < restore_call < fixture_delete,
            "Finalizer restores or removes the fixture before proving all handles were released")
    require("GUEST_RECOVERY_REQUIRED=True" in finalizer and
            "OriginalDriverBackupPreserved=True" in finalizer and
            "OriginalDriverBackupPreserved=False; OriginalDriverBackupPresent=False" in finalizer,
            "Finalizer does not preserve evidence and require recovery after disposal failure")
    require(not cleanup_allowed(view_released=False, mapping_released=False, file_released=True),
            "Finalizer cleanup model accepts a failed disposal retry")
    require(cleanup_allowed(view_released=True, mapping_released=True, file_released=True),
            "Finalizer cleanup model rejects fully released handles")

    # This is the recorded false-pass pattern from fence15: the old script said
    # BLOCKED after both the mapped flush and independent reads had been refused.
    history = HISTORICAL.read_text(encoding="utf-8")
    require("MappedWriteResult=OBSERVED_REFUSED:" in history, "Historical refused-flush control changed")
    require("FreshBufferedObserver=OBSERVED_REFUSED:" in history, "Historical buffered-reader control changed")
    require("FreshUncachedObserver=OBSERVED_REFUSED:" in history, "Historical uncached-reader control changed")
    require("UnauthenticatedMappedWriteAfterAttach=BLOCKED" in history, "Historical false-pass record changed")
    require(verdict(write="REFUSED", flush="REFUSED", source_released=True,
                    view_released=False, mapping_released=False, post_file_flush="REFUSED", buffered="DENIED",
                    uncached="DENIED", raw=None, raw_samples=0) == "INCONCLUSIVE",
            "Historical refused-flush/refused-reader case still qualifies as BLOCKED")
    require(verdict(write="SUCCESS", flush="SUCCESS", source_released=True,
                    view_released=True, mapping_released=True, post_file_flush="SUCCESS", buffered="BASELINE",
                    uncached="BASELINE", raw="BASELINE", raw_samples=20) == "BLOCKED",
            "Complete unchanged-byte evidence does not qualify as BLOCKED")
    require(verdict(write="REFUSED", flush="REFUSED", source_released=True,
                    view_released=False, mapping_released=False, post_file_flush="REFUSED", buffered="DENIED",
                    uncached="DENIED", raw="CHANGED", raw_samples=1) == "REPRODUCED",
            "Raw changed-byte exposure did not take precedence")
    require(verdict(write="SUCCESS", flush="SUCCESS", source_released=True,
                    view_released=True, mapping_released=True, post_file_flush="SUCCESS", buffered="DENIED",
                    uncached="BASELINE", raw="BASELINE", raw_samples=20) == "INCONCLUSIVE",
            "A denied independent observer qualified as BLOCKED")
    require(verdict(write="SUCCESS", flush="SUCCESS", source_released=True,
                    view_released=True, mapping_released=True, post_file_flush="REFUSED",
                    buffered="BASELINE", uncached="BASELINE", raw="BASELINE",
                    raw_samples=20) == "INCONCLUSIVE",
            "Missing post-write FlushFileBuffers still qualifies as BLOCKED")
    print("Pre-attachment mapping harness self-check: PASS (historical false-pass downgraded; post-write FlushFileBuffers, stable raw extents, independent observations and finalizer release gate required).")


if __name__ == "__main__":
    main()
