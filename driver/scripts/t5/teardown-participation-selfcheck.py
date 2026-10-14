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

if __name__ == '__main__':
    unittest.main(verbosity=2)
