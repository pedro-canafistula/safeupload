#!/usr/bin/env python3
"""Source-only T5 increment-10 teardown contracts; no compiler, network or VM.

These controls inspect production bodies/ordering and fail on missing hooks.
They do not establish IRQL, callback lifetime, NTFS behavior or WDK qualification.
Run: python3 driver/scripts/t5/teardown-participation-selfcheck.py
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
K = ROOT / 'driver/SafeUpload.Minifilter'


def strip_code(source):
    # Preserve positions/newlines while removing comments and literals.
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source, flags=re.S)


def code(path):
    return strip_code(path.read_text())

def body(file, name, sources=None):
    text = code(K / file) if sources is None else strip_code(sources[file])
    for match in re.finditer(r'\b' + re.escape(name) + r'\s*\(', text):
        i = text.index('(', match.start()); level = 1; i += 1
        while level:
            if text[i] == '(': level += 1
            if text[i] == ')': level -= 1
            i += 1
        while text[i].isspace(): i += 1
        if text[i] != '{': continue
        start = i; level = 1; i += 1
        while level:
            if text[i] == '{': level += 1
            if text[i] == '}': level -= 1
            i += 1
        return text[start:i]
    raise AssertionError(f'Missing production body: {file}:{name}')


def veto_capture_contract(step):
    """Pin disconnect/timeout boundaries before the single-client direct capture."""
    def require(value):
        if not value: raise AssertionError('service-disconnected veto capture contract')
    def order(*parts):
        position = -1
        for part in parts: position = step.index(part, position + 1)

    order('if(-not $unloaded)',
          "$capturePath=if($null -ne $agent){'AfterRestartedAgentStop'}else{'NoServiceRunning'}",
          "$running=Get-CimInstance Win32_Service -Filter \"Name='SafeUploadAgent'\"",
          "if($null -ne $running -and $running.State -ne 'Stopped')",
          "$capturePath='AfterRunningServiceStop'", '& sc.exe stop SafeUploadAgent',
          '$stopDeadline=[Diagnostics.Stopwatch]::GetTimestamp()+[long](30*[Diagnostics.Stopwatch]::Frequency)',
          'do{$running=Get-CimInstance',
          "if($null -eq $running -or ($running.State -eq 'Stopped' -and $running.ProcessId -eq 0)){break}",
          '}while([Diagnostics.Stopwatch]::GetTimestamp() -lt $stopDeadline)',
          "if($null -ne $running -and ($running.State -ne 'Stopped' -or $running.ProcessId -ne 0)){throw",
          "Invoke-ActivationInspector '--writer-state-status'", '45000 -Direct',
          "Write-DurableFile $vetoStatus ('CapturePath='+$capturePath",
          "}catch{Write-DurableFile $vetoStatus ('CapturePath='+$capturePath")
    # The timeout throws inside the same try as capture; its catch records a
    # diagnostic instead of reaching the inspector. PID zero is required too.
    require(re.search(r"if\(\$null -ne \$running -and \(\$running.State -ne 'Stopped' -or \$running.ProcessId -ne 0\)\)"
                      r"\{throw '[^']+';?\}", step) is not None)


def create_retirement_contracts(sources):
    """Source binding for the paused ordinary CREATE / early retirement model.

    Entry references survive retirement; instance/volume pins do not. These
    properties cover both retirement-before-capture and capture-before-retire,
    including failed context lookup and retirement before proof consumption.
    They are regression controls, not Windows callback/IRQL qualification.
    """
    def b(name): return body('StageWriters.c', name, sources)
    def require(value):
        if not value: raise AssertionError('paused-CREATE retirement contract')
    def order(text, *parts):
        position = -1
        for part in parts: position = text.index(part, position + 1)

    proof = b('StageRegistryApplyCreateAliasProof')
    acquire = 'FltAcquirePushLockExclusive(&RegistryLock);'
    unlock = 'FltReleasePushLock(&RegistryLock);'
    first = proof.index(acquire)
    captured = proof.index(unlock, first)
    lookup = proof.index('FltGetInstanceContext(instance,')
    second = proof.index(acquire, captured)
    rejected = proof.index(unlock, second)
    capture = proof[first:captured]
    require(re.search(r'if \(Entry->Listed && !Entry->Retired && Entry->Instance != NULL &&\s*'
                     r'NT_SUCCESS\(FltObjectReference\(Entry->Instance\)\)\)\s*'
                     r'instance = Entry->Instance;', capture) is not None)
    order(proof[captured:], 'if (instance == NULL) return;', 'FltGetInstanceContext(instance,',
          'goto Exit;', acquire, 'if (!Entry->Listed || Entry->Retired || Entry->Instance != instance)',
          unlock, 'goto Exit;', 'SafeUploadPolicyRenameLossGenerationEnter(',
          'StageAcquireSpinLock(', 'Entry->Listed && !Entry->Retired',
          'InterlockedExchange(&Entry->ScopeNameClassification, STAGE_SCOPE_CLASS_OUTSIDE)',
          'StageReleaseSpinLock(', 'SafeUploadPolicyRenameLossGenerationLeave(',
          unlock, 'Exit:', 'if (instanceContext != NULL) FltReleaseContext(instanceContext);',
          'FltObjectDereference(instance);')
    require(captured < lookup < second)
    # Every entry-instance read belongs to one of the two locked regions;
    # lookup and release use the local pin, even if Entry->Instance became NULL.
    for read in re.finditer(r'Entry->Instance\b', proof):
        require(first < read.start() < captured or second < read.start() < rejected)
    require(proof.count('FltObjectReference(') == 1)
    require(proof.count('FltObjectDereference(') == 1)
    require('PAGED_CODE()' not in proof)
    require('#pragma alloc_text(PAGE, StageRegistryApplyCreateAliasProof)' not in sources['StageWriters.c'])

    # Spin-only SOP readers use the map's stable identity token, never a live
    # pin cleared under a different lock. None can wait for a filter reference.
    for name in ('StageRegistryReserveMutatingIoMarker', 'StageRegistryDetachOneInstanceSectionBinding',
                 'StageRegistryMarkSopUnknownAt'):
        text = b(name)
        require('slot->InstanceIdentity == (PVOID)Instance' in text)
        require(re.search(r'->Entry->(?:Instance|Volume)\b', text) is None)
        require('FltObjectReference(' not in text and 'FltObjectDereference(' not in text)
    tracking = b('StageRegistryTrackUnknownWriter')
    order(tracking, acquire, 'StageAcquireSpinLock(&SectionLock',
          'Reservation->BoundEntry->Listed && !Reservation->BoundEntry->Retired',
          'Reservation->BoundEntry->Instance == Reservation->Instance',
          'StageReleaseSpinLock(&SectionLock', unlock, 'node->FileObject = FileObject')
    promote = b('StageRegistryTryPromoteEntry')
    order(promote, 'if (!Entry->Listed || Entry->Retired || Entry->Instance == NULL)',
          'return SAFEUPLOAD_PROMOTE_FAIL_NOT_LISTED;', 'FltGetInstanceContext(Entry->Instance,')
    caller = b('StageRegistryActivationProcess')
    order(caller, acquire, 'StageRegistryTryPromoteEntry(', unlock)
    classify = b('StageRegistryClassifyAllLinkNames')
    snapshot = 'volumeMatches = stable && Entry->Volume == Volume && Entry->VolumeSerial != 0;'
    order(classify, 'FltAcquirePushLockShared(&RegistryLock)', snapshot, unlock,
          'StageRegistryOpenIdentity(', 'noNamesProvenByIdentity && volumeMatches',
          'volumeMatches &&', 'PublishResult:', acquire, 'stable = Entry->Listed && !Entry->Retired;', unlock)
    require(re.search(r'Entry->Volume\b', classify[classify.index('StageRegistryOpenIdentity('):]) is None)
    for name in ('StageRegistryRecordClassificationResult', 'StageRegistryRecordDeferral'):
        text = b(name)
        require('if (Entry->Transient) return;' in text)
        require(re.search(r'Entry->(?:Instance|Volume)\b', text) is None)
    require('identityEntry->Transient = TRUE;' in b('SafeUploadStageWritersClassifyById'))
    awaiter = b('SafeUploadStageWritersAwaitClassification')
    order(awaiter, 'FltAcquirePushLockShared(&RegistryLock)',
          'active = entry->Listed && !entry->Retired && entry->Instance == Instance;',
          unlock, 'if (!active || (!transition && !pending)) break;', 'KeDelayExecutionThread')


def batch1_contracts(sources):
    """Ordering/ownership properties with adversarial production-source mutations.

    Source checks are structural regression controls, not a kernel lifetime proof.
    """
    def b(file, name): return body(file, name, sources)
    def require(value):
        if not value: raise AssertionError('batch-1 obligation/retirement contract')
    def order(text, *parts):
        position = -1
        for part in parts: position = text.index(part, position + 1)
    ready = b('StageWriters.c', 'SafeUploadStageWritersUnloadReady')
    require('return TRUE;' not in ready)
    for guard in ('SafeUploadStageWritersOwnerCount() == 0', 'IsListEmpty(&RegistryReservations)',
                  'entry->W', 'entry->RenameInFlight', 'association->References',
                  'SAFEUPLOAD_TX_ASSOC_PENDING', 'rename->Abandoned', 'SectionSlots[index].AcquirePending',
                  'SectionSlots[index].ReleasePending',
                  'SpilledMutatingIoCount'):
        require(guard in ready)
    for history in ('IsListEmpty(&RegistryEntries)', 'IsListEmpty(&TransactionAssociations)',
                    'SafeUploadStageWritersGlobalUnknown', 'StageRegistryUnknownSopCount', 'entry->H', 'UnknownWriterCount'):
        require(history not in ready)
    prep = b('StageStream.c', 'SafeUploadStagePrepareUnload')
    require(prep.count('SafeUploadStageWritersUnloadReady()') == 2)
    order(prep, 'SafeUploadStageWritersUnloadReady()', 'SafeUploadStageEpochDrainV20',
          'drainResult != SAFEUPLOAD_STAGE_RESULT_EPOCH_DRAINED', 'SafeUploadStageWritersUnloadReady()',
          'SafeUploadStageFenceTryCommitUnload()', 'return STATUS_SUCCESS;')
    require('SafeUploadStageBeginMandatoryTeardown' not in prep)
    unload = b('Filter.c', 'SafeUploadUnload')
    voluntary = unload[unload.index('} else {'):]
    order(voluntary, 'SafeUploadStagePrepareUnload(FALSE)', 'return STATUS_FLT_DO_NOT_DETACH;',
          'SafeUploadStageBeginMandatoryTeardown()', 'SafeUploadCloseCommunicationPortEarly',
          'SafeUploadStageWritersCloseAnchors', '&SafeUploadData.ChannelRundown',
          'SafeUploadStageStopWorker', 'SafeUploadStageDrainMandatoryTeardown',
          'SafeUploadStageWritersRetireHistory', 'FltUnregisterFilter',
          'SafeUploadData.Filter = NULL', 'SafeUploadStageWritersFinishTeardown', 'SafeUploadStageFree')
    committed = voluntary[voluntary.index('SafeUploadStageBeginMandatoryTeardown()'):]
    committed = re.sub(r'#if !SAFEUPLOAD_STAGING_PROTOTYPE.*?#endif', '', committed, flags=re.S)
    for forbidden in ('STATUS_FLT_DO_NOT_DETACH', 'StageRollbackUnloadPreparation',
                      'SafeUploadOpenStageCallbackUnloadAdmission', 'ReopenAdmission'):
        require(forbidden not in committed)
    retire = b('StageWriters.c', 'StageRegistryRetireInstance')
    for pin in ('instance', 'volume'):
        pointer = pin.capitalize()
        require(retire.count(f'entry->{pointer} = NULL') == 1)
        require(retire.count(f'FltObjectDereference({pin}Reference)') == 1)
        order(retire, f'{pin}Reference = entry->{pointer}', f'entry->{pointer} = NULL',
              'FltReleasePushLock(&RegistryLock)', f'FltObjectDereference({pin}Reference)',
              'StageRegistryDereference(entry)')
    order(retire, 'RemoveEntryList(&association->Link)', 'association->Listed = FALSE',
          'SAFEUPLOAD_TX_ASSOC_TERMINAL', 'KeSetEvent', 'FltReleasePushLock(&RegistryLock)',
          'StageRegistryAssociationDereference(association)')
    require('SafeUploadStageMandatoryTeardownActive' in b('StageWriters.c', 'StageAnchorInsert'))
    for name in ('StageRegistryGetOrInsert', 'SafeUploadStageWritersReserveCreate',
                 'SafeUploadStageWritersPrepareRename', 'StageRegistryEnlistTransaction',
                 'SafeUploadStageSectionAcquired', 'StageRegistryQueueReclaimWorkItem'):
        require('SafeUploadStageMandatoryTeardownActive' in b('StageWriters.c', name))
    # Reservations belong exclusively to their own postoperation/cancel path.
    for name in ('StageRegistryRetireInstance', 'SafeUploadStageWritersRetireHistory',
                 'SafeUploadStageWritersFinishTeardown'):
        require('ExFreePoolWithTag(reservation' not in b('StageWriters.c', name))
        require('SafeUploadStageWritersCancelReservation' not in b('StageWriters.c', name))
    detach = b('StageWriters.c', 'StageRegistryDetachOneInstanceSectionBinding')
    require('SectionSlots[' not in detach)
    require('SpilledMutatingIoCount == 0' in detach and 'UnknownWriterCount == 0' in detach)
    acquire = b('StageWriters.c', 'SafeUploadStageSectionAcquired')
    require('slot->AcquirePending = TRUE' in acquire)
    require('slot->AcquirePending = FALSE' in b('StageWriters.c', 'SafeUploadStageSectionAcquireComplete'))
    require('SafeUploadStageSectionAcquireComplete(CompletionContext)' in b('StageWriters.c', 'SafeUploadStageSectionAcquireDraining'))
    require('SafeUploadStageSectionAcquireComplete(CompletionContext)' in b('StageStream.c', 'StagePostOperationCore'))
    require('slot->ReleasePending = FALSE' in b('StageWriters.c', 'SafeUploadStageSectionReleaseComplete'))
    failure = b('StageWriters.c', 'SafeUploadStageSectionAcquireFailed')
    require('if (slot->ReleasePending)' in failure and 'slot->AcquireFailed = TRUE' in failure)
    release = b('StageWriters.c', 'SafeUploadStageSectionReleaseComplete')
    require('Succeeded && !Draining && !slot->AcquirePending' in release)
    require('slot->ReleaseCompleted = TRUE' in release)
    complete = b('StageWriters.c', 'SafeUploadStageSectionAcquireComplete')
    require('slot->ReleaseCompleted && !slot->ReleasePending' in complete)
    require('!Slot->AcquirePending && !Slot->ReleasePending' in b('StageWriters.c', 'StageSectionRemoveSlot'))
    require('!slot->ReleaseCompleted && !slot->AcquireFailed' in b('StageWriters.c', 'SafeUploadStageSectionReleasePrepare'))
    finish = b('StageWriters.c', 'SafeUploadStageWritersFinishTeardown')
    order(finish, 'SafeUploadData.Filter == NULL', 'StageRegistryPurgeAbandonedDirectoryRenamesLocked',
          'IsListEmpty(&RegistryDirectoryRenames)', 'IsListEmpty(&RegistryReservations)',
          'SectionSlots[index].RegistryEntry', 'RtlZeroMemory(&SectionSlots[index]',
          'StageReleaseSpinLock', 'StageRegistryDereference(entry)')
    cleanup = b('StageWriters.c', 'SafeUploadStageWritersFreeContext')
    require('!SafeUploadStageMandatoryTeardownActive()' in cleanup)
    require('if (!naturalEnd) InterlockedExchange(&lifetime->Invalid, 1)' in cleanup)
    require('else InterlockedExchange(&lifetime->Ended, 1)' in cleanup)
    for name in ('SafeUploadStageWritersUnloadReady', 'StageRegistryRetireInstance',
                 'SafeUploadStageWritersRetireHistory', 'SafeUploadStageWritersFinishTeardown'):
        text = b('StageWriters.c', name)
        require('->Ended' not in text)
        require(re.search(r'InterlockedExchange\([^;]*(?:Unknown|Invalid)[^;]*,\s*0\)', text) is None)
    # New direct spin-lock bodies stay resident, even though orchestration is PASSIVE.
    for name in ('SafeUploadStageWritersUnloadReady', 'SafeUploadStageWritersFinishTeardown',
                 'StageRegistryDetachOneInstanceSectionBinding', 'SafeUploadStageSectionAcquireComplete'):
        require(f'#pragma alloc_text(PAGE, {name})' not in sources['StageWriters.c'])
        require('PAGED_CODE()' not in b('StageWriters.c', name))
    stop = b('StageStream.c', 'SafeUploadStageStopWorker')
    order(stop, 'ZwWaitForSingleObject(StageWorkerHandle', 'KeCancelTimer(&StageRetryTimer)',
          'KeFlushQueuedDpcs()', 'StageRetryArmed = FALSE', 'SafeUploadStageAdmissionStopWorker')
    history = b('StageWriters.c', 'SafeUploadStageWritersRetireHistory')
    order(history, 'StageRegistryPurgeAbandonedDirectoryRenamesLocked', 'IsListEmpty(&RegistryDirectoryRenames)',
          'FltReleasePushLock(&RegistryLock)', 'KeDelayExecutionThread', 'while (!renamesDrained)',
          'StageRegistryRetireInstance(NULL, FALSE)')
    require('NT_ASSERT(allReturned)' in b('StageWriters.c', 'SafeUploadStageWritersUninitialize'))


class TeardownParticipation(unittest.TestCase):
    def order(self, text, *parts):
        position = -1
        for part in parts:
            position = text.index(part, position + 1)

    def test_mandatory_selector_and_all_producer_fences(self):
        unload = body('Filter.c', 'SafeUploadUnload')
        branch = unload[unload.index('SafeUploadStageBeginMandatoryTeardown'):]
        self.assertTrue(branch.index('} else {') < branch.index('SafeUploadStagePrepareUnload'))
        begin = body('StageStream.c', 'SafeUploadStageBeginMandatoryTeardown')
        for hook in ('StageMandatoryTeardown, 1', 'StageUnloadAdmissionClosed, 1',
                     'StageAttachAccepting = FALSE', 'CancelRequested, 1',
                     'SafeUploadStageNativeCloseAdmission', 'SafeUploadBoundPublicationCloseAdmission',
                     'SafeUploadStagePublicCloseAdmission', 'StageWorkerStop'):
            self.assertIn(hook, begin)

    def test_close_owned_handles_before_dependent_drains(self):
        unload = body('Filter.c', 'SafeUploadUnload')
        self.order(unload, 'SafeUploadCloseCommunicationPortEarly', 'SafeUploadStageAdmissionBeginTeardown',
                   'SafeUploadStageWritersCloseAnchors', 'SafeUploadStagePublicCloseAllBackends',
                   'SafeUploadWaitForCommunicationDrain', '&SafeUploadData.ChannelRundown',
                   'SafeUploadStageStopWorker', 'SafeUploadStageDrainMandatoryTeardown',
                   'SafeUploadStageWritersRetireHistory', 'SafeUploadStageReleaseInstanceReferences', 'FltUnregisterFilter',
                   '&SafeUploadData.CommunicationCallbackRundown', 'SafeUploadStageWritersFinishTeardown', 'SafeUploadStageFree')

    def test_writer_leases_metadata_and_backend_destructor(self):
        veto = body('StagePublic.c', 'SafeUploadStagePublicTryCloseAdmission')
        for owner in ('StagePublicFactories == 0', 'StageWriterMetadataReaders == 0', 'StagePublicBackendCount'):
            self.assertIn(owner, veto)
        close = body('StagePublic.c', 'SafeUploadStagePublicCloseAllBackends')
        self.order(close, 'SafeUploadStagePublicCloseAdmission', 'StageWriterMetadataReadersDrained',
                   'SafeUploadStagePublicReferenceBackend', 'FltReleasePushLock',
                   'SafeUploadStagePublicCloseBackend', 'SafeUploadStagePublicDereferenceBackend',
                   'ExWaitForRundownProtectionRelease(&StagePublicOpens)', 'StagePublicOpensDrained = TRUE', 'continue;')
        self.order(body('StagePublic.c', 'SafeUploadStagePublicCloseBackend'),
                   'Backend->Operations', 'Backend->PublicHandle', 'StageWriterCloseHandles',
                   'Backend->ParentHandle', 'Backend->RootHandle', 'Backend->Closed')
        self.order(body('StagePublic.c', 'SafeUploadStagePublicDereferenceBackend'),
                   'StageWriterFree', 'FltObjectDereference', 'ExFreePoolWithTag',
                   'SafeUploadStageWritersOwnerRelease', 'StagePublicDrained')

    def test_allocation_and_publication_source_owners_release_before_aggregate_wait(self):
        drain = body('StageStream.c', 'SafeUploadStageDrainMandatoryTeardown')
        self.order(drain, 'SafeUploadBoundPublicationDrainLocal', '&stream->RpcReferences',
                   'StageOwnedCallbackBodies', 'stream->AllocationWriterLease = NULL',
                   'SafeUploadStagePublicReleaseWriter', 'stream->PublicationWriterLease = NULL',
                   'SafeUploadStagePublicReleaseWriter', 'SafeUploadStageNativeDrainLocal',
                   'SafeUploadStagePublicDrainBackends', 'NT_ASSERT(SafeUploadStageWritersOwnerCount() == 0)')
        self.assertEqual(1, drain.count('SafeUploadStageWritersOwnerCount'))
        self.assertNotIn('StageDeleteReleasedStage', drain)
        self.assertNotIn('StageDrain(', drain)

    def test_v26_facts_callbacks_workers_and_namespace_reservation(self):
        self.assertIn('BpCount == 0 && BpFactories == 0 && !BpNamespaceUnknown',
                      body('StageBoundPublication.c', 'SafeUploadBoundPublicationTryCloseAdmission'))
        close = body('StageBoundPublication.c', 'SafeUploadBoundPublicationCloseAdmission')
        for fence in ('BpAccepting = FALSE', 'BpStopping = TRUE', 'BpRevoke', 'BpWake'):
            self.assertIn(fence, close)
        drain = body('StageBoundPublication.c', 'SafeUploadBoundPublicationDrainLocal')
        self.order(drain, 'ZwWaitForSingleObject', 'BpTerminal', 'BpDestroy', 'BpCalls')
        terminal = body('StageBoundPublication.c', 'BpTerminal')
        for owner in ('r->Uses != 1', 'r->Object != NULL', 'r->Callbacks != 0', 'r->Queued', 'r->Working',
                      'InFlightWrites', 'InFlightMutators', 'BP_COVERAGE_LOST', 'BP_LAST_CLEANUP'):
            self.assertIn(owner, terminal)
        self.assertNotIn('NameReserved = FALSE', close + drain)
        self.order(body('StageBoundPublication.c', 'BpDestroy'),
                   'SafeUploadStagePublicationReleaseSource', 'SafeUploadStageWritersOwnerRelease')

    def test_native_factories_and_live_ordinary_records_veto_without_erasure(self):
        reserve = body('StageNativeRecords.c', 'NativeReserve')
        self.order(reserve, 'SafeUploadStageMandatoryTeardownActive', '++NativeFactories',
                   'SafeUploadStagePublicReadMountGuid', 'ExAllocatePool2', 'InsertTailList',
                   '--NativeFactories', 'NativeChanged', 'ExReleaseRundownProtection')
        veto = body('StageNativeRecords.c', 'SafeUploadStageNativeTryCloseAdmission')
        for owner in ('NativeFactories == 0', 'IsListEmpty(&NativeRecords)', 'NativeRecordCount'):
            self.assertIn(owner, veto)
        for destructive in ('RemoveHeadList', 'NativeDestroy', 'FileObject = NULL'):
            self.assertNotIn(destructive, veto)

    def test_native_lifetime_not_service_ack_or_coverage_loss(self):
        drain = body('StageNativeRecords.c', 'SafeUploadStageNativeDrainLocal')
        for owner in ('References != 1', 'FileObject != NULL', 'Backend != NULL', 'CreateCallbackOwned',
                      'CloseCallbackOwned', 'DispositionCallbackOwned', 'LastHandleCleanedUp',
                      'CancelledBeforeHandle', 'CancelledCloseObserved', 'NativeFactories == 0'):
            self.assertIn(owner, drain)
        self.assertNotIn('CleanupCoverageLost', drain)
        self.order(drain, 'NativeRelease', 'NativeDestroy', 'NativeCalls', 'KeWaitForSingleObject')
        close = body('StageNativeRecords.c', 'SafeUploadStageNativeCloseWriter')
        self.order(close, 'record->FileObject = NULL', 'NativeRelease', 'SafeUploadStagePublicCloseBackend',
                   'record->Backend = NULL', 'SafeUploadStagePublicDereferenceBackend')

    def test_sop_anchor_and_witness_participation(self):
        self.assertIn('SafeUploadStageMandatoryTeardownActive', body('StageWriters.c', 'StageAnchorInsert'))
        close = body('StageWriters.c', 'SafeUploadStageWritersCloseAnchors')
        self.order(close, 'FltAcquirePushLockExclusive', 'RemoveHeadList', 'FltReleasePushLock', 'StageAnchorDestroy')
        self.assertNotIn('KeWait', close)
        self.assertIn('SafeUploadStageMandatoryTeardownActive', body('StageWriters.c', 'StageRegistryQueueReclaimWorkItem'))
        veto = body('StageWriters.c', 'SafeUploadStageWritersUnloadReady')
        for owner in ('RegistryEntries', 'RegistryReservations', 'TransactionAssociations', 'RegistryDirectoryRenames',
                      'SafeUploadStageWritersOwnerCount', 'entry->W', 'entry->RenameInFlight',
                      'association->References', 'SAFEUPLOAD_TX_ASSOC_PENDING', 'rename->Abandoned',
                      'SpilledMutatingIoCount'):
            self.assertIn(owner, veto)
        for history in ('IsListEmpty(&RegistryEntries)', 'IsListEmpty(&TransactionAssociations)',
                        'SafeUploadStageWritersGlobalUnknown', 'StageRegistryUnknownSopCount', 'entry->H', 'UnknownWriterCount'):
            self.assertNotIn(history, veto)
        cleanup = body('StageWriters.c', 'SafeUploadStageWritersFreeContext')
        self.assertIn('!SafeUploadStageMandatoryTeardownActive()', cleanup)
        self.assertIn('if (!naturalEnd) InterlockedExchange(&lifetime->Invalid, 1)', cleanup)
        self.assertIn('StageRegistryReleaseLifetime', cleanup)

    def test_voluntary_rollback_and_new_create_fence(self):
        veto = body('StageStream.c', 'SafeUploadStagePrepareUnload')
        for hook in ('SafeUploadBoundPublicationTryCloseAdmission', 'SafeUploadStageNativeTryCloseAdmission',
                     'SafeUploadStagePublicTryCloseAdmission', 'SafeUploadStageWritersUnloadReady',
                     'SafeUploadPolicyPublicationQuiescent', 'StageReservedStreamCount', 'StageFileObjects'):
            self.assertIn(hook, veto)
        rollback = body('StageStream.c', 'StageRollbackUnloadPreparation')
        for reopen in ('SafeUploadStageNativeReopenAdmission', 'SafeUploadBoundPublicationReopenAdmission',
                       'SafeUploadStagePublicReopenAdmission', 'StageSetUnloadAdmissionClosed(FALSE)'):
            self.assertIn(reopen, rollback)
        self.assertIn('StageUnloadAdmissionClosed', body('StageStream.c', 'SafeUploadStageDispatch'))
        self.assertIn('SafeUploadIsAuthenticatedClient()', body('StageStream.c', 'SafeUploadStageDispatch'))
        self.assertEqual(2, veto.count('SafeUploadStageWritersUnloadReady'))

    def test_spin_lock_owners_are_resident_even_with_PASSIVE_entry_contracts(self):
        for file, acquire in (('StageNativeRecords.c', 'NativeAcquire'), ('StageBoundPublication.c', 'BpAcquire')):
            source = (K / file).read_text()
            for name in re.findall(r'#pragma alloc_text\(PAGE, (\w+)\)', source):
                self.assertNotIn(acquire + '(', body(file, name), (file, name))
            # Removing PAGE placement alone leaves PAGED_CODE's function-wide
            # IRQL restriction behind (the increment-5/6 C28150 regression).
            names = set(re.findall(r'(?m)^(?:__declspec\(noinline\) )?(?:static )?\w+ (\w+)\(', code(K / file)))
            for name in names:
                text = body(file, name)
                if acquire + '(' in text:
                    self.assertNotIn('PAGED_CODE()', text, (file, name))

    def test_local_roots_have_no_service_or_timeout_release(self):
        for file, name in (
            ('StageStream.c', 'SafeUploadStageBeginMandatoryTeardown'),
            ('StageStream.c', 'SafeUploadStageDrainMandatoryTeardown'),
            ('StagePublic.c', 'SafeUploadStagePublicCloseAllBackends'),
            ('StagePublic.c', 'SafeUploadStagePublicCloseBackend'),
            ('StageWriters.c', 'SafeUploadStageWritersCloseAnchors'),
            ('StageNativeRecords.c', 'SafeUploadStageNativeDrainLocal'),
            ('StageBoundPublication.c', 'SafeUploadBoundPublicationDrainLocal')):
            text = body(file, name)
            for forbidden in ('FltSendMessage', 'SafeUploadStageEpochDrainV20', 'SafeUploadStagePrepareUnload',
                              'STATUS_TIMEOUT', 'STATUS_IO_TIMEOUT'):
                self.assertNotIn(forbidden, text, (file, name))
        release = body('StageStream.c', 'SafeUploadStageReleaseInstanceReferences')
        self.order(release, 'StageMandatoryLocalDrained', 'stream->PagingRundown', 'StageCloseBacking', 'FltObjectDereference')


    def test_paused_create_teardown_pin_interleavings(self):
        sources = {'StageWriters.c': (K / 'StageWriters.c').read_text()}
        create_retirement_contracts(sources)
        # Abstract the source-checked locked capture, unlocked lookup, locked
        # retired recheck/application, and unlocked release. Retirement cannot
        # interleave within either RegistryLock region. Model the entry's pin
        # independently from its still-owned callback entry reference.
        for pause in range(5):
            for lookup_succeeds in (False, True):
                with self.subTest(retire_at=pause, lookup_succeeds=lookup_succeeds):
                    state = {'entry_instance': 'instance', 'pins': 1, 'retired': False,
                             'local': None, 'context': False, 'applied': False}

                    def retire():
                        state['retired'] = True
                        state['entry_instance'] = None
                        state['pins'] -= 1

                    for step in range(5):
                        if step == pause: retire()
                        if step == 0:  # capture under RegistryLock
                            if not state['retired'] and state['entry_instance'] is not None:
                                state['local'] = state['entry_instance']
                                state['pins'] += 1
                        elif step == 1 and state['local'] is not None:  # context lookup
                            self.assertEqual('instance', state['local'])
                            self.assertGreater(state['pins'], 0)
                            state['context'] = lookup_succeeds
                        elif step == 2:  # validate/apply under RegistryLock
                            if state['context'] and not state['retired']:
                                self.assertEqual(state['entry_instance'], state['local'])
                                state['applied'] = True
                        elif step == 3 and state['local'] is not None:  # every exit releases
                            state['context'] = False
                            state['pins'] -= 1
                            state['local'] = None
                        self.assertGreaterEqual(state['pins'], 0)
                    self.assertEqual(0, state['pins'])
                    self.assertIsNone(state['local'])
                    self.assertFalse(state['context'])
                    self.assertEqual(lookup_succeeds and pause > 2, state['applied'])

    def test_paused_create_teardown_mutations_are_rejected(self):
        sources = {'StageWriters.c': (K / 'StageWriters.c').read_text()}
        alias = 'StageRegistryApplyCreateAliasProof'
        mutations = (
            ('unlocked-pointer-read', alias, 'FltGetInstanceContext(instance,', 'FltGetInstanceContext(Entry->Instance,'),
            ('unlocked-capture', alias, '    FltAcquirePushLockExclusive(&RegistryLock);', ''),
            ('missing-retired-check', alias, 'Entry->Listed && !Entry->Retired && Entry->Instance != NULL',
             'Entry->Listed && Entry->Instance != NULL'),
            ('missing-reference', alias, 'NT_SUCCESS(FltObjectReference(Entry->Instance))', 'TRUE'),
            ('missing-release', alias, '    FltObjectDereference(instance);', ''),
            ('release-under-lock', alias, '    FltObjectDereference(instance);', ''),
            ('missing-post-lookup-recheck', alias, '!Entry->Listed || Entry->Retired || Entry->Instance != instance', 'FALSE'),
            ('missing-failed-lookup-exit', alias, 'FltGetInstanceContext(instance, (PFLT_CONTEXT *)&instanceContext))) goto Exit;',
             'FltGetInstanceContext(instance, (PFLT_CONTEXT *)&instanceContext))) return;'),
            ('spin-reader-live-pin', 'StageRegistryReserveMutatingIoMarker', 'slot->InstanceIdentity == (PVOID)Instance',
             'slot->Entry->Instance == Instance'),
            ('unknown-writer-unlocked-pin', 'StageRegistryTrackUnknownWriter', '    FltAcquirePushLockExclusive(&RegistryLock);', ''),
            ('promotion-retired-lookup', 'StageRegistryTryPromoteEntry',
             'if (!Entry->Listed || Entry->Retired || Entry->Instance == NULL)', 'if (FALSE)'),
            ('unlocked-volume-match', 'StageRegistryClassifyAllLinkNames', 'noNamesProvenByIdentity && volumeMatches',
             'noNamesProvenByIdentity && Entry->Volume == Volume'),
            ('unlocked-waiter-instance', 'SafeUploadStageWritersAwaitClassification',
             '            FltAcquirePushLockShared(&RegistryLock);', ''),
        )
        for label, name, before, after in mutations:
            with self.subTest(mutation=label):
                fragment = body('StageWriters.c', name, sources)
                start = strip_code(sources['StageWriters.c']).index(fragment)
                original = sources['StageWriters.c'][start:start + len(fragment)]
                self.assertIn(before, original, label)
                mutated = original.replace(before, after, 1)
                if label == 'release-under-lock':
                    # Move, rather than duplicate, the sole release into the
                    # capture region: both ownership and lock ordering break.
                    mutated = mutated.replace('    FltReleasePushLock(&RegistryLock);',
                                              '    FltObjectDereference(instance);\n    FltReleasePushLock(&RegistryLock);', 1)
                changed = {'StageWriters.c': sources['StageWriters.c'][:start] + mutated +
                           sources['StageWriters.c'][start + len(fragment):]}
                self.assertNotEqual(sources, changed, label)
                with self.assertRaises((AssertionError, ValueError)):
                    create_retirement_contracts(changed)

    def test_batch1_obligation_and_retirement_properties(self):
        sources = {name: (K / name).read_text() for name in ('Filter.c', 'StageStream.c', 'StageWriters.c')}
        batch1_contracts(sources)

    def test_batch1_mutations_are_rejected(self):
        sources = {name: (K / name).read_text() for name in ('Filter.c', 'StageStream.c', 'StageWriters.c')}
        mutations = (
            ('unconditional-ready', 'StageWriters.c', '    return ready;', '    return TRUE;'),
            ('owner-guard', 'StageWriters.c', 'SafeUploadStageWritersOwnerCount() == 0 && IsListEmpty(&RegistryReservations)', 'IsListEmpty(&RegistryReservations)'),
            ('write-callback-guard', 'StageWriters.c', 'InterlockedCompareExchange(&entry->W, 0, 0) != 0 ||', ''),
            ('reservation-guard', 'StageWriters.c', '&& IsListEmpty(&RegistryReservations)', ''),
            ('second-snapshot', 'StageStream.c', 'if (!SafeUploadPolicyPublicationQuiescent() || !SafeUploadStageWritersUnloadReady())', 'if (!SafeUploadPolicyPublicationQuiescent())'),
            ('teardown-before-ACK', 'StageStream.c', 'status = SafeUploadStageEpochDrainV20', 'SafeUploadStageBeginMandatoryTeardown();\n    status = SafeUploadStageEpochDrainV20'),
            ('post-commit-reopen', 'Filter.c', '    SafeUploadStageWritersRetireHistory();', '    SafeUploadStageWritersRetireHistory();\n    SafeUploadOpenStageCallbackUnloadAdmission();'),
            ('post-commit-rollback', 'Filter.c', '    SafeUploadStageWritersRetireHistory();', '    SafeUploadStageWritersRetireHistory();\n    StageRollbackUnloadPreparation();'),
            ('post-commit-veto', 'Filter.c', '    SafeUploadStageWritersRetireHistory();', '    SafeUploadStageWritersRetireHistory();\n    return STATUS_FLT_DO_NOT_DETACH;'),
            ('missing-pin-release', 'StageWriters.c', 'if (instanceReference != NULL) FltObjectDereference(instanceReference);', ''),
            ('missing-volume-release', 'StageWriters.c', 'if (volumeReference != NULL) FltObjectDereference(volumeReference);', ''),
            ('double-instance-release', 'StageWriters.c', 'if (instanceReference != NULL) FltObjectDereference(instanceReference);', 'if (instanceReference != NULL) FltObjectDereference(instanceReference);\n        FltObjectDereference(instanceReference);'),
            ('double-pin-release', 'StageWriters.c', 'if (volumeReference != NULL) FltObjectDereference(volumeReference);', 'if (volumeReference != NULL) FltObjectDereference(volumeReference);\n        FltObjectDereference(volumeReference);'),
            ('retained-association', 'StageWriters.c', 'StageRegistryAssociationDereference(association); /* Drop the table reference. */', ''),
            ('anchor-reinsertion', 'StageWriters.c', 'if (!SafeUploadStageMandatoryTeardownActive() &&\n        StageAnchorCount', 'if (StageAnchorCount'),
            ('free-active-reservation', 'StageWriters.c', 'StageRegistryRetireInstance(NULL, FALSE);', 'ExFreePoolWithTag(reservation, SAFEUPLOAD_REGISTRY_POOL_TAG);\n    StageRegistryRetireInstance(NULL, FALSE);'),
            ('free-active-section', 'StageWriters.c', '    *Detached = FALSE;', '    *Detached = FALSE;\n    RtlZeroMemory(&SectionSlots[0], sizeof(SectionSlots[0]));'),
            ('missing-acquire-owner', 'StageWriters.c', 'SectionSlots[index].AcquirePending || ', ''),
            ('missing-release-owner', 'StageWriters.c', ' || SectionSlots[index].ReleasePending', ''),
            ('free-active-acquire-on-release', 'StageWriters.c', 'Succeeded && !Draining && !slot->AcquirePending', 'Succeeded && !Draining'),
            ('free-active-release-on-acquire-failure', 'StageWriters.c', 'if (slot->ReleasePending)', 'if (FALSE)'),
            ('forced-Ended', 'StageWriters.c', 'if (!naturalEnd) InterlockedExchange(&lifetime->Invalid, 1)', 'if (!naturalEnd) InterlockedExchange(&lifetime->Ended, 1)'),
            ('clear-Unknown', 'StageWriters.c', 'StageRegistryRetireInstance(NULL, FALSE);', 'InterlockedExchange(&WriterGlobalUnknown, 0);\n    StageRegistryRetireInstance(NULL, FALSE);'),
            ('paged-spin-body', 'StageWriters.c', 'BOOLEAN SafeUploadStageWritersUnloadReady(VOID)\n{', 'BOOLEAN SafeUploadStageWritersUnloadReady(VOID)\n{\n    PAGED_CODE();'),
            ('timer-survives', 'StageStream.c', '(VOID)KeCancelTimer(&StageRetryTimer);', ''),
            ('directory-completion-survives', 'StageWriters.c', 'renamesDrained = IsListEmpty(&RegistryDirectoryRenames);', 'renamesDrained = TRUE;'),
            ('worker-survives', 'Filter.c', '    SafeUploadStageStopWorker();', ''),
        )
        for label, file, before, after in mutations:
            with self.subTest(mutation=label):
                self.assertTrue(before in sources[file], label)
                changed = dict(sources)
                # Mutate the production function, never an earlier startup/error
                # helper containing the same call. A no-op mutation is a failure.
                target = {'post-commit-reopen': 'SafeUploadUnload',
                          'post-commit-veto': 'SafeUploadUnload',
                          'post-commit-rollback': 'SafeUploadUnload',
                          'timer-survives': 'SafeUploadStageStopWorker',
                          'worker-survives': 'SafeUploadUnload'}.get(label)
                if target:
                    fragment = body(file, target, sources)
                    start = strip_code(sources[file]).index(fragment)
                    original = sources[file][start:start + len(fragment)]
                    self.assertTrue(before in original, label)
                    changed[file] = sources[file][:start] + original.replace(before, after, 1) + sources[file][start + len(fragment):]
                else:
                    changed[file] = sources[file].replace(before, after, 1)
                with self.assertRaises((AssertionError, ValueError)):
                    batch1_contracts(changed)

    def test_agent_completed_projection_and_lexical_history_keep_live_authority(self):
        agent = ROOT / 'agente/SafeUpload.Agent.Service/Interception'
        journal = str(agent / 'StagedTransferJournal.cs')
        validate = body(journal, 'ValidateEntry')
        self.assertIn('RequireManifestPath(transfer.StagePath)', validate)
        self.assertIn('RequireManifestPath(transfer.DestinationPath)', validate)
        self.assertIn('ValidateRenameSourceV20(entry, receipt.Source, historical: true)', validate)
        for path in ('receipt.SourcePath', 'receipt.DestinationPath', 'name.DestinationPath', 'entry.LastRenameDestination'):
            self.assertIn('RequireHistoricalManifestPath(' + path + ')', validate)
        lexical = body(journal, 'RequireHistoricalManifestPath')
        for lookup in ('Path.GetFullPath', 'File.', 'Directory.', 'GetLongPathName', 'StagedStageFile.'):
            self.assertNotIn(lookup, lexical)
        source = code(Path(journal))
        for guard in ('entry.StageDeleted && !entry.StageCleanupStarted', 'entry.PendingRename is null',
                      'MatchesBlockedDeletionReceipt(entry)', '!BlockedCleanupComplete(entry)',
                      'pendingProjection && !PendingDispatchRequired(cached.Entry)'):
            self.assertIn(guard, source)
        pending = body(journal, 'ReadPendingAsync')
        self.assertIn('PendingDispatchRequired(entry)', pending)
        self.assertIn('pendingProjection: true', pending)
        bound_receipts = body(str(agent / 'StagedTransferRecovery.cs'), 'RecoverBoundReceiptsAsync')
        self.assertIn('receiptRecovery: true', bound_receipts)
        recovery = body(str(agent / 'StagedTransferRecovery.cs'), 'RecoverPendingTransferAsync')
        self.assertIn('!receiptRecovery', recovery)
        self.order(recovery, 'BlockedCleanupComplete(entry)', 'return;', 'RecoveryTimestamp() < retry.RetryAt',
                   '_journal.ReadAsync', 'ProcessBlockedCleanupAsync', 'ScheduleRecoveryRetry(id)')
        # Verified may reach disk before notification/justification progress.
        # Full recovery must still rehydrate it; the live cleanup scan keeps
        # bounded retries without repeating that completed progress.
        self.assertIn('!cleanupOnly || entry.HandbackState is', recovery)
        self.order(recovery, 'out interruptedProgress', 'RecoverBlockedAsync(entry, token)',
                   'ReferenceEquals(pending, interruptedProgress)', '_pendingJournalProgress.Remove(id)')
        self.assertIn('receiptRecovery || !(entry.State == TransferJournalState.Released &&', recovery)
        self.assertIn('entry.HandbackState == StagedHandbackState.Verified))', recovery)
        self.assertIn('RecoveryRetries(receiptRecovery).TryGetValue', recovery)
        self.assertIn('_boundReceiptRetries.TryGetValue', recovery)
        self.assertIn('ScheduleRecoveryRetry(id, boundReceipt: true)', recovery)
        self.assertNotIn('bound.Diagnostic is not null && unfinished', recovery)
        core = body(str(agent / 'StagedTransferPublisher.cs'), 'ProcessBlockedCleanupCoreAsync')
        self.order(core, 'BlockedCleanupComplete(entry)', 'return;', '_journal.ReadAsync', 'StagedStageFile.OpenBlockedDeletion')
        loop = body(str(agent / 'MinifilterInterceptor.cs'), 'PublishSealedLoopAsync')
        self.assertIn('RecoverPendingTransferAsync', loop)
        self.assertIn('cleanupOnly: entry.HandbackState == StagedHandbackState.Verified', loop)
        self.assertNotIn('ProcessBlockedCleanupAsync', loop)

    def test_veto_diagnostic_preserves_restoration_and_direct_inspector_route(self):
        path = ROOT / 'driver/scripts/Test-StagedInvariantSuite.ps1'
        raw = path.read_bytes()
        self.assertFalse(raw.startswith(b'\xef\xbb\xbf'))
        self.assertTrue(all(c < 128 for c in raw))
        source = raw.decode('ascii')
        step = source[source.index("@{Name='driver-with-service'"):source.index("@{Name='cached-agent'")]
        self.order(step, 'fltmc.exe unload SafeUpload', 'driver-unload-with-service.txt',
                   'Stop-StagedTestAgent $agent', 'if(-not $unloaded)', 'driver-unload-veto-status.txt',
                   "Invoke-ActivationInspector '--writer-state-status'", '45000 -Direct', 'Write-DurableFile $vetoStatus')
        self.assertIn('WriterStateStatusError=', step)
        veto_capture_contract(step)
        wait = re.search(r'do\{\$running=Get-CimInstance.*?\}while\(\[Diagnostics.Stopwatch\]::GetTimestamp\(\) -lt \$stopDeadline\)',
                         step, re.S)
        self.assertIsNotNone(wait)
        mutations = (
            ('removed-disconnect-wait', step.replace(wait[0], '', 1)),
            ('missing-process-zero-proof', step.replace("$running.State -eq 'Stopped' -and $running.ProcessId -eq 0",
                                                      "$running.State -eq 'Stopped'", 1)),
            ('timeout-still-captures', step.replace("{throw 'SafeUploadAgent did not disconnect within 30 s; no direct capture attempted.'}",
                                                  '{}', 1)),
        )
        for label, changed in mutations:
            with self.subTest(mutation=label):
                self.assertNotEqual(step, changed)
                with self.assertRaises((AssertionError, ValueError)):
                    veto_capture_contract(changed)
        self.assertIn("@{Name='driver';Action={Set-DemandStartAndRestoreDriver}}", source)
        helper = source[source.index('function Invoke-ActivationInspector('):source.index('function Invoke-ActivationTraceControlUntilAcknowledged')]
        self.assertIn('$state.AgentServiceStarted -and -not $Direct', helper)
        self.assertIn('Invoke-CapturedProcess $inspectorPath', helper)

    def test_initialize_failure_releases_everything_acquired(self):
        # A failed DriverEntry gets no unload callback; StageFree returns early
        # while StageInitialized is FALSE (pre-boot review finding 1). Each
        # failure releases exactly what was acquired before it, in reverse order.
        init = body('StageStream.c', 'SafeUploadStageInitialize')
        tail = init[init.index('SafeUploadStageWritersInitialize()'):init.index('StageInitialized = TRUE')]
        failures = [f[f.rindex('if (!NT_SUCCESS(status))'):] for f in tail.split('return status;')[:-1]]
        self.assertEqual(2, len(failures))
        releases = ('SafeUploadStageNativeUninitialize()', 'SafeUploadStageFenceFree()',
                    'SafeUploadStageWritersUninitialize()', 'ExDeleteResourceLite(&StageNamespaceResource)')
        fence, publication = failures
        self.assertLess(tail.index('SafeUploadStageFenceInitialize()'), tail.index(fence))
        self.order(fence, *releases[2:])
        for absent in releases[:2]:
            self.assertNotIn(absent, fence)
        self.assertLess(tail.index('SafeUploadBoundPublicationInitialize('), tail.index(publication))
        self.order(publication, *releases)
        for release in releases:
            self.assertEqual(1, publication.count(release), release)
        for release in releases[2:]:
            self.assertEqual(1, fence.count(release), release)

    def test_native_lock_touches_only_resident_caller_memory(self):
        # Pageable memory must not be touched under NativeLock (findings 2 and re-review 1/2).
        reader = body('StageNativeRecords.c', 'NativeReadPage')
        self.assertNotIn('ExAllocatePool2', reader)  # no new failure inside a multi-page pass
        locked = reader[reader.index('NativeAcquire('):reader.index('NativeRelease(')]
        for output in ('*Count', '*Revision', '*Complete'):
            self.assertNotIn(output, locked, output)
        identity = body('StageNativeRecords.c', 'SafeUploadStageNativeReadIdentity')
        locked = identity[identity.index('NativeAcquire('):identity.index('NativeRelease(')]
        self.assertNotIn('*DriverInstanceId', locked); self.assertNotIn('*OsBootSequence', locked)
        forwarded = body('StageNativeRecords.c', 'SafeUploadStageNativeMarkForwarded')
        locked = forwarded[forwarded.index('NativeAcquire('):forwarded.index('NativeRelease(')]
        self.assertNotIn('PublicOpenReceipt->', locked)
        reserve = body('StageNativeRecords.c', 'NativeReserve')
        for locked in re.findall(r'NativeAcquire\(.*?NativeRelease\(', reserve, re.S):
            self.assertNotIn('Binding->', locked)
        # Every reader caller, in any kernel source, passes rows from a nonpaged
        # allocation made in the enclosing function itself.
        callers = 0
        for path in sorted(K.glob('*.c')):
            text = code(path)
            for match in re.finditer(r'\b(SafeUploadStageNativeReadPage|SafeUploadStagePublicOpenReadPage|NativeReadPage)\s*\(([^;]*?)\);', text, re.S):
                args = [a.strip() for a in match.group(2).split(',')]
                rows = args[2]
                if ' ' in rows or rows == 'Rows':
                    continue  # a definition, or an exported wrapper forwarding its caller's rows
                opening = text.rfind('\n{', 0, match.start())
                level, i = 1, opening + 2
                while level:
                    level += (text[i] == '{') - (text[i] == '}'); i += 1
                function = text[opening:i]
                self.assertLess(match.start(), i, (path.name, rows))
                if rows.endswith('->RevisionProbe'):
                    allocations = re.findall(r'work->RevisionProbe\s*=\s*ExAllocatePool2\(\s*(POOL_FLAG_\w+)', function)
                else:
                    base = re.match(r'&?(\w+)', rows).group(1)
                    allocations = re.findall(r'\b' + base + r'\s*=\s*ExAllocatePool2\(\s*(POOL_FLAG_\w+)', function)
                self.assertEqual(['POOL_FLAG_NON_PAGED'], allocations, (path.name, rows))
                callers += 1
        self.assertEqual(9, callers)

    def test_facts_workers_mark_attempts_only_after_a_successful_first_page(self):
        # An allocation failure must not record the revision as attempted, or a
        # later event would skip its facts (second re-review, finding 5).
        for name in ('StagePublicOpenFlushFacts', 'StageNativeFlushFacts'):
            worker = body('StageStream.c', name)
            allocation = worker.index('ExAllocatePool2(POOL_FLAG_NON_PAGED')
            self.assertEqual(1, worker.count('ExAllocatePool2('), name)
            self.assertIsNone(re.search(r'attempted\w+\s*=', worker[:allocation]), name)
            after = worker[allocation:]
            self.assertTrue(re.match(r'ExAllocatePool2\(POOL_FLAG_NON_PAGED,[^;]*;\s*if \(rows == NULL\) return;', after, re.S), name)
            loop = after[after.index('do {'):]
            self.order(loop, 'ReadPage(', 'if (!NT_SUCCESS(status)) break;', 'if (offset == 0)', 'attemptedRevision =')

    def test_attach_capture_reserved_before_any_capture(self):
        # Capacity covers captures in progress, not only visible transactions (finding 3).
        create = body('StageStream.c', 'StageAttachQueueCreate')
        reserve = create.index('StageAttachReserveCapture(')
        for first in ('StageAttachSnapshotName(', 'ExAllocatePool2(', 'FltObjectReference(', 'ObReferenceObject(',
                      'SafeUploadStagePublicCaptureCreateSubject(', 'StageAttachCaptureCreateInput('):
            self.assertLess(reserve, create.index(first), first)
        self.assertEqual(3, create.count('StageAttachReturnCapture(captureSlot)'))
        self.order(create[create.index('Fail:'):], 'StageAttachTransactionDereference(transaction)',
                   'StageAttachReturnCapture(captureSlot)')
        convert = create[create.index('InsertTailList(&StageAttachLookup'):]
        self.order(convert, 'StageAttachCaptures[captureSlot] = NULL', '--StageAttachCaptureCount',
                   'captureReserved = FALSE', 'InterlockedIncrement(&StageAttachActiveCount)',
                   'StageStreamReleaseSpinLock(&StageAttachLock')
        reserving = body('StageStream.c', 'StageAttachReserveCapture')
        self.assertIn('StageAttachActiveCount + StageAttachCaptureCount >= STAGE_ATTACH_LIMIT_GLOBAL', reserving)
        self.assertIn('instanceCount >= STAGE_ATTACH_LIMIT_PER_INSTANCE', reserving)
        self.order(reserving, 'StageStreamAcquireSpinLock(&StageAttachLock', 'StageAttachCaptures[freeSlot] = Instance',
                   '++StageAttachCaptureCount', 'StageStreamReleaseSpinLock(&StageAttachLock')
        returning = body('StageStream.c', 'StageAttachReturnCapture')
        self.order(returning, 'StageStreamAcquireSpinLock(&StageAttachLock', 'StageAttachCaptures[Slot] = NULL',
                   '--StageAttachCaptureCount', 'KeSetEvent(&StageAttachDrained', 'StageStreamReleaseSpinLock(&StageAttachLock')
        self.assertIn('StageAttachActiveCount) == 0 && StageAttachCaptureCount == 0',
                      body('StageStream.c', 'StageAttachReleaseActive'))
        self.assertIn('StageAttachActiveCount == 0 && StageAttachCaptureCount == 0',
                      body('StageStream.c', 'SafeUploadStageStopWorker'))
        detach = body('StageStream.c', 'SafeUploadStageCanDetach')
        self.order(detach, 'StageStreamAcquireSpinLock(&StageAttachLock', 'StageAttachCaptureCount',
                   'StageStreamReleaseSpinLock(&StageAttachLock')
        self.assertIn('InterlockedCompareExchange(&StageAttachCaptureCount, 0, 0) != 0',
                      body('StageStream.c', 'SafeUploadStagePrepareUnload'))
        self.assertIn('StageAttachCaptures[index] == Instance', body('StageStream.c', 'StageAttachHasInstance'))

    def test_epoch_operations_exclude_only_nonmutating_pending_fsctls(self):
        # m2t5boot6: every FSCTL held an epoch token through lower completion, so
        # pending oplock requests pinned the boot epoch and the first SetPolicy
        # drain timed out. Mutating FSCTLs still drain with the policy snapshot.
        epoch = body('StageStream.c', 'StageEpochOperation')
        fsctl = epoch[epoch.index('case IRP_MJ_FILE_SYSTEM_CONTROL:'):]
        fsctl = fsctl[:fsctl.index('    default:\n        return FALSE;')]
        self.order(fsctl, 'IRP_MN_USER_FS_REQUEST', 'IRP_MN_KERNEL_CALL', 'return TRUE;',
                   'FsControlCode', 'return FALSE;', 'default:', 'return TRUE;')
        excluded = set(re.findall(r'case (FSCTL_\w+):', fsctl))
        self.assertEqual({'FSCTL_REQUEST_OPLOCK_LEVEL_1', 'FSCTL_REQUEST_OPLOCK_LEVEL_2', 'FSCTL_REQUEST_BATCH_OPLOCK',
                          'FSCTL_REQUEST_FILTER_OPLOCK', 'FSCTL_REQUEST_OPLOCK', 'FSCTL_OPLOCK_BREAK_ACKNOWLEDGE',
                          'FSCTL_OPBATCH_ACK_CLOSE_PENDING', 'FSCTL_OPLOCK_BREAK_NOTIFY', 'FSCTL_OPLOCK_BREAK_ACK_NO_2',
                          'FSCTL_READ_USN_JOURNAL', 'FSCTL_WAIT_FOR_REPAIR'}, excluded)
        for mutating in ('FSCTL_SET_REPARSE_POINT', 'FSCTL_DELETE_REPARSE_POINT', 'FSCTL_SET_ZERO_DATA',
                         'FSCTL_DUPLICATE_EXTENTS_TO_FILE', 'FSCTL_SET_SPARSE'):
            self.assertNotIn(mutating, excluded)
        self.assertIn('case IRP_MJ_SET_SECURITY:\n        return TRUE;', epoch)

    def test_successful_v20_attachment_releases_the_allocation_name_reservation(self):
        # m2t5boot8: the reservation survived attachment, refused other processes' reads
        # with DELETE_PENDING and parked the worker before seal.
        text = code(K / 'StageStream.c')
        start = text.index('stream->AttachCompletionFence = FALSE;', text.index('FltCompletePendedPreOperation(Transaction->CallbackData'))
        block = text[text.rindex('StageAcquire(&StageNamespaceResource)', 0, start):]
        block = block[:block.index('StageRelease(&StageNamespaceResource);')]
        self.order(block, 'StageAcquire(&StageNamespaceResource)', 'AttachCompletionFence = FALSE',
                   '!stream->DiscardOnClose && !stream->Discarded', 'StageClearPrivateDelete(stream)',
                   'StageQueueStream(stream')
        clear = body('StageStream.c', 'StageClearPrivateDelete')
        for held in ('AllocationRpcInFlight', 'AllocationReceiptPending', 'DiscardRpcInFlight'):
            self.assertIn(held, clear)

if __name__ == '__main__':
    unittest.main(verbosity=2)
