#!/usr/bin/env python3
"""Offline boot14 allocation replay/terminal authority controls and negative mutations."""
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('retry', Path(__file__).with_name('reconcile-retry-selfcheck.py'))
retry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retry)
code, body = retry.code, retry.body


def require(condition, reason):
    if not condition:
        raise AssertionError(reason)


def allocation_contract(stream):
    process = body(stream, 'StageProcessStream')
    collect = body(stream, 'StageCollectAllocationRecoveryRpcs')
    apply = body(stream, 'StagePerformAllocationRecoveryRpcs')
    timer = body(stream, 'StageUpdateRetryTimer')
    sweep = body(stream, 'StageWorkerPass')
    retain = body(stream, 'StageRetainAllocationReceipt')
    deadline = body(stream, 'StageAllocationRetryDeadline')
    require('StageRetryMs < STAGE_RETRY_FIRST_MS ? STAGE_RETRY_FIRST_MS : StageRetryMs' in deadline and
            'KeQueryInterruptTime() + (ULONGLONG)delay * 10000ULL' in deadline and
            'StageRetryDueTime > deadline ? StageRetryDueTime : deadline' in deadline,
            'an almost-expired unrelated arm cannot shorten this failed attempt backoff')
    require('if (Stream->AllocationTupleKnown) StageQueueStream(Stream, &StageCounters.WakeInline);' in retain,
            'initial unresolved failure must wait instead of immediate replay')
    require(retain.index('StageUpdateRetryTimer();') < retain.index('Stream->AllocationRecoveryRetryAfter = StageAllocationRetryDeadline();') <
            retain.index('StageQueueStream(Stream, &StageCounters.WakeInline);'),
            'the initial failed allocation must back off before its first replay too')
    require('Stream->AllocationRecoveryWait == STAGE_WAIT_SERVICE ? STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE' in process,
            'an unrelated wake must preserve refusal parking')
    require('stream->AllocationRecoveryWait == STAGE_WAIT_SERVICE' in collect, 'collector must skip parked receipts')
    require('KeQueryInterruptTime() < stream->AllocationRecoveryRetryAfter' in collect,
            'collector must enforce monotonic deadline through unrelated/stale-DPC wakes')
    require(collect.index('stream->AllocationRecoveryPending = FALSE;') <
            collect.index('stream->AllocationRecoveryInFlight = TRUE;') <
            collect.index('stream->AllocationRecoveryWait = STAGE_WAIT_EXCHANGE;') <
            collect.index('stream->Wait = STAGE_WAIT_EXCHANGE;') < collect.index('InterlockedIncrement(&stream->RpcReferences);'),
            'collection must keep counted ownership and exchange cause in flight')
    require('|| stream->AllocationRecoveryInFlight' in timer, 'in-flight work cannot empty/reset backoff')
    require('STAGE_WAIT_SERVICE : StageWaitFor(status);' in apply, 'semantic refusal differs from transient failure')
    require(apply.index('StageUpdateRetryTimer();') < apply.index('stream->AllocationRecoveryRetryAfter = StageAllocationRetryDeadline();'),
            'deadline must use the failed attempt timer arm')
    require('if (stream->AllocationRecoveryPending && stream->AllocationRecoveryWait == STAGE_WAIT_EXCHANGE)' in apply,
            'only unfinished eligible work receives a retry deadline')
    require('if (sweep)' in sweep and stream.count('if (stream->AllocationRecoveryWait == STAGE_WAIT_SERVICE) stream->AllocationRecoveryWait = STAGE_WAIT_EXCHANGE;') == 1,
            'only reconciled reconnect may unpark allocation refusal')
    unpark = sweep.index('if (stream->AllocationRecoveryWait == STAGE_WAIT_SERVICE)')
    require(sweep.rfind('if (sweep) {', 0, unpark) >= 0, 'unpark is inside reconnect sweep')
    require('if (stream->AllocationRecoveryWait == STAGE_WAIT_EXCHANGE) stream->AllocationRecoveryWait = STAGE_WAIT_SERVICE;' in
            body(stream, 'SafeUploadStageServiceDisconnected'), 'disconnect retains and parks allocation cause')
    # The tuple-success block may queue exact cleanup. Failure and stale blocks
    # must park/back off without any inline event or queue call.
    failure = apply[apply.index('stream->AllocationRecoveryWait = status == STATUS_INVALID_DEVICE_STATE'):]
    require('StageQueueStream(' not in failure and 'KeSetEvent(' not in failure, 'failed reply cannot unconditionally requeue')
    require(apply.count('StageQueueStream(') == 1, 'only successful tuple resolution queues immediate cleanup')
    require('StageRetryMs = 0;' not in apply and 'StageRetryMs = 0;' not in collect, 'attempt must not reset backoff')
    require('StageServiceAvailable && serviceGeneration == InterlockedCompareExchange(&StageServiceGeneration, 0, 0)' in apply,
            'late disconnected/replaced-channel result has no release authority')
    retry.disconnect_contract(stream)


def release_contract(stream, protocol):
    apply = body(stream, 'StagePerformAllocationRecoveryRpcs')
    resolve = body(stream, 'StageResolveUncommittedAllocation')
    send = body(protocol, 'StageSendV19Exchange')
    direct = body(protocol, 'StageAllocateInternal')
    replay = body(protocol, 'SafeUploadStageReplayAllocationV19')
    require('reply->Result == SAFEUPLOAD_STAGE_RESULT_NO_ALLOCATION_COMMITTED' in send and
            'RtlEqualMemory(&reply->OriginalRequest, &Exchange->Request, sizeof(Exchange->Request))' in send,
            'terminal receipt must echo every original request byte')
    require('if (channelCurrent && status == STATUS_SUCCESS && *Answered && *Verdict == SAFEUPLOAD_VERDICT_ALLOW &&' in send,
            'no generic DENY or stale channel can authorize release')
    require(re.search(r'if \(Version19 && status == STATUS_SUCCESS && answered && exchange->AllocationNotCommitted\) \{\s*'
                      r'\*AllocationMayExist = FALSE;', direct), 'only validated terminal result clears MayHaveReachedService')
    require('if (NT_SUCCESS(status) && exchange->AllocationNotCommitted) *NoAllocationCommitted = TRUE;' in replay,
            'replay must export terminal proof separately from generic denial')
    for guard in ('stream->AllocationRequest.RequestId == requestId',
                  'RtlEqualMemory(&stream->TransferId, &expectedId, sizeof(GUID))',
                  'RtlEqualMemory(&stream->AllocationIntent.AllocationReservationId, &expectedId, sizeof(GUID))',
                  'NT_SUCCESS(status) && noAllocationCommitted && !stream->BoundAllocation',
                  '!stream->AllocationTupleKnown && !stream->AttachCompletionMayExist && !stream->AttachCompletionKnown',
                  'stream->BackingObject == NULL', 'stream->Sections.SharedCacheMap == NULL',
                  'stream->Sections.DataSectionObject == NULL', 'stream->Sections.ImageSectionObject == NULL'):
        require(guard in apply, 'terminal shell release missing exact/local guard: ' + guard)
    require(apply.count('StageResolveUncommittedAllocation(stream);') == 1,
            'only terminal successful branch may release shell')
    proof = apply[apply.index('if (NT_SUCCESS(status) && noAllocationCommitted'):apply.index('} else if (noAllocationCommitted)')]
    require('StageResolveUncommittedAllocation(stream);' in proof, 'release must be inside the exact terminal branch')
    for clear in ('Stream->AllocationReceiptPending = FALSE;', 'Stream->AllocationRecoveryPending = FALSE;',
                  'if (Stream->ReservationLinked) StageRemoveAllocationNameReservation(Stream);',
                  'StageClearPrivateDelete(Stream);', '--parent->AllocationReceiptReferences;',
                  'Stream->AllocationReceiptParent = NULL;', 'StageQueueStream(parent, &StageCounters.WakeInline);'):
        require(clear in resolve, 'release only this shell reservation and its pinned predecessor: ' + clear)
    require(resolve.index('Stream->AllocationReceiptPending = FALSE;') < resolve.index('StageClearPrivateDelete(Stream);'),
            'private delete guard must clear only after the terminal receipt ends')
    require('StageClearPrivateDelete(parent)' not in resolve and 'parent->View->Detached' not in resolve,
            'terminal rejection must not mutate predecessor namespace/delete authority')


class AllocationRecovery(unittest.TestCase):
    def setUp(self):
        self.stream = code(ROOT / 'driver/SafeUpload.Minifilter/StageStream.c')
        self.protocol = code(ROOT / 'driver/SafeUpload.Minifilter/StageProtocol.c')

    def test_allocation_parking_deadline_inflight_accounting_disconnect_and_success_wake(self):
        allocation_contract(self.stream)

    def test_only_exact_terminal_receipt_releases_matching_reservation_and_predecessor_pin(self):
        release_contract(self.stream, self.protocol)

    def test_allocation_retry_negative_mutations(self):
        mutations = [
            ('Stream->AllocationRecoveryWait == STAGE_WAIT_SERVICE ? STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE', 'STAGE_WAIT_EXCHANGE'),
            ('stream->AllocationRecoveryWait == STAGE_WAIT_SERVICE ||', 'FALSE ||'),
            ('KeQueryInterruptTime() < stream->AllocationRecoveryRetryAfter', 'FALSE'),
            ('|| stream->AllocationRecoveryInFlight', '|| FALSE'),
            ('stream->AllocationRecoveryWait = STAGE_WAIT_EXCHANGE;\n        stream->Wait = STAGE_WAIT_EXCHANGE;', 'stream->Wait = STAGE_WAIT_NONE;'),
            ('stream->AllocationRecoveryRetryAfter = StageAllocationRetryDeadline();', 'stream->AllocationRecoveryRetryAfter = 0;'),
            ('Stream->AllocationRecoveryRetryAfter = StageAllocationRetryDeadline();', 'Stream->AllocationRecoveryRetryAfter = 0;'),
            ('stream->AllocationRecoveryWait = status == STATUS_INVALID_DEVICE_STATE ?', 'StageQueueStream(stream, NULL); stream->AllocationRecoveryWait = status == STATUS_INVALID_DEVICE_STATE ?'),
            ('if (stream->AllocationRecoveryWait == STAGE_WAIT_EXCHANGE)', 'if (FALSE)'),
            ('StageServiceAvailable && serviceGeneration ==', 'TRUE && serviceGeneration =='),
            ('StageRetryMs < STAGE_RETRY_FIRST_MS ? STAGE_RETRY_FIRST_MS : StageRetryMs', '0'),
            ('if (Stream->AllocationTupleKnown) StageQueueStream', 'StageQueueStream'),
        ]
        for old, new in mutations:
            with self.subTest(mutation=old):
                require(old in self.stream, 'mutation must hit production')
                with self.assertRaises((AssertionError, ValueError)):
                    allocation_contract(self.stream.replace(old, new))

    def test_terminal_authority_and_exact_release_negative_mutations(self):
        for old in ('stream->AllocationRequest.RequestId == requestId',
                    'RtlEqualMemory(&stream->AllocationIntent.AllocationReservationId, &expectedId, sizeof(GUID))',
                    'NT_SUCCESS(status) && noAllocationCommitted && !stream->BoundAllocation',
                    'stream->BackingObject == NULL', '--parent->AllocationReceiptReferences;',
                    'if (Stream->ReservationLinked) StageRemoveAllocationNameReservation(Stream);'):
            with self.subTest(mutation=old):
                require(old in self.stream, 'mutation must hit production')
                with self.assertRaises((AssertionError, ValueError)):
                    release_contract(self.stream.replace(old, 'FALSE'), self.protocol)
        for old in ('reply->Result == SAFEUPLOAD_STAGE_RESULT_NO_ALLOCATION_COMMITTED',
                    'RtlEqualMemory(&reply->OriginalRequest, &Exchange->Request, sizeof(Exchange->Request))',
                    '*Verdict == SAFEUPLOAD_VERDICT_ALLOW &&',
                    'Version19 && status == STATUS_SUCCESS && answered && exchange->AllocationNotCommitted'):
            with self.subTest(mutation=old):
                require(old in self.protocol, 'mutation must hit production')
                with self.assertRaises((AssertionError, ValueError)):
                    release_contract(self.stream, self.protocol.replace(old, 'FALSE'))

    def test_wire_sizes_capability_and_separate_legacy_layout(self):
        header = (ROOT / 'driver/SafeUpload.Minifilter/Protocol.h').read_text()
        cs = (ROOT / 'agente/SafeUpload.Agent.Minifilter/Protocol.cs').read_text()
        for name, size in [('ALLOCATE_V19', 64), ('ALLOCATE_V20', 72), ('ALLOCATION_RESOLUTION_REPLY_V20', 1216)]:
            require(f'C_ASSERT( sizeof( SAFEUPLOAD_STAGE_{name} ) == {size} );' in header, 'native exact layout')
        require('StageAllocateV19Size = 64;' in cs and 'StageAllocateV20Size = 72;' in cs and
                'StageAllocationResolutionReplyV20Size = 1216;' in cs, 'managed exact layouts')
        require('AllocationResolution = 0x100' in cs and '0x000001BF' in header, 'explicit negotiation')

    def test_blocked_retirement_exclusions_and_retryable_create_stay_intact(self):
        retire = body(self.stream, 'StageRetireDeletedStream')
        for guard in ('Stream->ShareAccess.OpenCount == 0', 'Stream->FileObjects, 0, 0) == 0',
                      'Stream->Sections.SharedCacheMap == NULL', 'Stream->Sections.DataSectionObject == NULL',
                      'Stream->Sections.ImageSectionObject == NULL', 'standard.DeletePending',
                      'ExWaitForRundownProtectionRelease(&Stream->PagingRundown)'):
            self.assertIn(guard, retire)
        self.assertIn('if (pending.DeletePending) { status = STATUS_SHARING_VIOLATION; goto Exit; }',
                      body(self.stream, 'StageCreate'))


if __name__ == '__main__':
    unittest.main()
