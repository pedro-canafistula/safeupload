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


def code(path):
    source = path.read_text()
    # Preserve positions/newlines while removing comments and literals.
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source, flags=re.S)


def body(file, name):
    text = code(K / file)
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
                   'SafeUploadStageReleaseInstanceReferences', 'FltUnregisterFilter',
                   '&SafeUploadData.CommunicationCallbackRundown', 'SafeUploadStageFree')

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
                      'SafeUploadStageWritersOwnerCount', 'SafeUploadStageWritersGlobalUnknown', 'StageRegistryUnknownSopCount'):
            self.assertIn(owner, veto)
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


    def test_initialize_failure_releases_everything_acquired(self):
        # A failed DriverEntry gets no unload callback; StageFree returns early
        # while StageInitialized is FALSE (pre-boot review finding 1).
        init = body('StageStream.c', 'SafeUploadStageInitialize')
        tail = init[init.index('SafeUploadStageWritersInitialize()'):init.index('StageInitialized = TRUE')]
        failures = tail.split('return status;')[:-1]
        self.assertGreaterEqual(len(failures), 2)
        for failure in failures:
            block = failure[failure.rindex('if (!NT_SUCCESS(status))'):]
            self.order(block, 'SafeUploadStageWritersUninitialize()', 'ExDeleteResourceLite(&StageNamespaceResource)')

    def test_native_page_reader_fills_nonpaged_page_under_lock(self):
        # Callers pass paged rows; nothing pageable is written under NativeLock (finding 2).
        reader = body('StageNativeRecords.c', 'NativeReadPage')
        self.order(reader, 'POOL_FLAG_NON_PAGED', 'NativeAcquire(', 'NativeRelease(', 'RtlCopyMemory(Rows')
        locked = reader[reader.index('NativeAcquire('):reader.index('NativeRelease(')]
        self.assertNotIn('Rows[', locked)
        self.assertNotIn('Rows,', locked)

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
        self.order(convert, 'StageAttachCaptures[captureSlot] = NULL', 'captureReserved = FALSE',
                   'InterlockedIncrement(&StageAttachActiveCount)', 'StageStreamReleaseSpinLock(&StageAttachLock')
        for file, name in (('StageStream.c', 'StageAttachReleaseActive'), ('StageStream.c', 'SafeUploadStageCanDetach'),
                           ('StageStream.c', 'SafeUploadStagePrepareUnload'), ('StageStream.c', 'StageAttachReturnCapture')):
            self.assertIn('StageAttachCaptureCount', body(file, name), name)
        self.assertIn('StageAttachCaptures[index] == Instance', body('StageStream.c', 'StageAttachHasInstance'))

if __name__ == '__main__':
    unittest.main(verbosity=2)
