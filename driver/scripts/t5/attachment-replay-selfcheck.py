#!/usr/bin/env python3
"""Source-only exact v20 attachment replay contracts and mutation controls.

No compiler/network/VM. These checks prove source structure, not Windows
lifetime, IRQL, service-restart recovery or WDK qualification. Run with python3.
"""
from pathlib import Path
import io
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
K = ROOT / 'driver/SafeUpload.Minifilter'
OVERRIDES = {}


def code(file):
    source = OVERRIDES.get(file, (K / file).read_text())
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source, flags=re.S)


def body(file, name):
    text = code(file)
    for match in re.finditer(r'\b' + re.escape(name) + r'\s*\(', text):
        i = text.index('(', match.start()); level = 1; i += 1
        while level:
            level += (text[i] == '(') - (text[i] == ')'); i += 1
        while text[i].isspace(): i += 1
        if text[i] != '{': continue
        start = i; level = 1; i += 1
        while level:
            level += (text[i] == '{') - (text[i] == '}'); i += 1
        return text[start:i]
    raise AssertionError(f'Missing production body: {file}:{name}')


def stream(name):
    return body('StageStream.c', name)


def op15_block():
    text = stream('StageAttachRunLifecycle')
    start = text.index('if (!Stream->AttachCompletionKnown)')
    return text[start:]


class AttachmentReplay(unittest.TestCase):
    def order(self, text, *parts):
        position = -1
        for part in parts:
            position = text.index(part, position + 1)

    def test_owner_gate_precedes_reservation_refusal(self):
        text = stream('StageCreate')
        self.order(text, 'StageFindPrivateDeleteReservation(',
                   'privateDelete != NULL && (!AllowAttachResume ||',
                   '!StageAttachOwnerCanResume(privateDelete, transaction, owner)',
                   'status = STATUS_DELETE_PENDING;', 'view = StageFindView(owner,')
        # There is no name-only exemption or new allocation in the barrier block.
        block = text[text.index('privateDelete = StageFindPrivateDeleteReservation'):text.index('for (;;)')]
        self.assertEqual(1, block.count('goto Exit;'))
        self.assertNotIn('StageClearPrivateDelete', block)
        self.assertNotIn('StageReserveAllocationName', block)

    def test_resume_is_bound_to_process_view_and_allocation(self):
        text = stream('StageAttachOwnerCanResume')
        for condition in (
            'Owner != Transaction->RequestorProcess', 'view->Owner != Owner',
            'view->OwnerProcessId != Transaction->RequestorProcessId',
            'view->Generation != Transaction->ExpectedGeneration', 'view->Current != Stream',
            'view->Detached', 'Stream->OwnerExited',
            'Stream->OriginalInstance != Transaction->InstanceIdentity',
            '!Stream->AttachCompletionPending', 'Stream->AttachLifecycleInFlight',
            'Stream->AttachCompletionFence', 'Stream->AttachTerminalPending', 'Stream->AttachRetirePending',
            'Stream->DiscardOnClose', 'Stream->Discarded', 'Stream->Sealed',
            '!Stream->AllocationReceiptPending', '!Stream->AllocationTupleKnown',
            'Stream->AllocationRecoveryPending', 'Stream->AllocationRecoveryInFlight',
            '!Stream->ExpectedStageIdentityValid',
            'Stream->AllocationRecoveryProcessId != Transaction->RequestorProcessId',
            '&Stream->TransferId, &Stream->AllocationIntent.AllocationReservationId',
            '&Stream->StageIdentity, &Stream->ExpectedStageIdentity',
            '&Stream->DriverInstanceId, &Transaction->DriverInstanceId',
            '&Stream->DriverInstanceId, &StageDriverInstanceId',
            '&view->ParentIdentity.FileId'):
            self.assertIn(condition, text, condition)
        self.order(text, '!Stream->AttachCompletionMayExist || Stream->AttachCompletionRequest.RequestId == 0',
                   'return FALSE;',
                   '!SafeUploadStageAttachmentRequestV20Matches(&Stream->AttachCompletionRequest,',
                   'SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED, &Stream->TransferId,',
                   'Stream->DestinationGeneration, &Stream->StageIdentity, &Stream->DriverInstanceId,',
                   '&Stream->AllocationParentDirectoryIdentity)', 'return TRUE;')

    def test_lost_op15_replays_the_stored_request(self):
        text = op15_block()
        self.order(text, 'Stream->AttachCompletionMayExist && Stream->AttachCompletionRequest.RequestId == 0',
                   'return STATUS_INVALID_DEVICE_STATE;',
                   'status = StageAttachExchangeRetry(Transaction,',
                   'SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED,',
                   '&Stream->AttachCompletionRequest, &result)',
                   'if (!NT_SUCCESS(status))', 'if (!Stream->AttachCompletionMayExist)',
                   'Transaction->UnexposedRetirementAllowed = TRUE;', 'Stream->DrainStatus = status;',
                   'return status;', 'result != SAFEUPLOAD_STAGE_RESULT_COMPLETION_PERMITTED',
                   'Stream->AttachCompletionKnown = TRUE;')
        self.assertNotIn('RtlZeroMemory', text)
        self.assertNotIn('StageClearPrivateDelete', text)
        protocol = body('StageProtocol.c', 'StageProtocolPrepareAttachRequestV20')
        self.order(protocol, 'expected->RequestId = Request->RequestId;',
                   'if (expected->RequestId == 0)', 'InterlockedIncrement64',
                   'if (Request->RequestId == 0)', '*Request = *expected;',
                   'RtlEqualMemory(Request, expected, sizeof(*expected))')
        exchange = body('StageProtocol.c', 'SafeUploadStageAttachmentExchangeV20')
        self.order(exchange, 'StageProtocolPrepareAttachRequestV20(',
                   'exchange->Request = *RequestSnapshot;', 'StageSendV19Exchange(',
                   'SafeUploadStageExchangeResult(', 'StageProtocolReadAttachReplyV20(')

    def test_only_exact_reply_resolves_completion(self):
        reply = body('StageProtocol.c', 'StageProtocolReadAttachReplyV20')
        for field in ('reply.Operation != Expected->Operation', 'reply.RequestId != Expected->RequestId',
                      '&reply.TransferId, &Expected->TransferId',
                      'reply.DestinationGeneration != Expected->DestinationGeneration',
                      '&reply.StageIdentity, &Expected->StageIdentity',
                      '&reply.DriverInstanceId, &Expected->DriverInstanceId',
                      '&reply.ParentDirectoryIdentity, &Expected->ParentDirectoryIdentity'):
            self.assertIn(field, reply, field)
        valid = body('StageProtocol.c', 'StageProtocolStatusResultValid')
        branch = valid[valid.index('case SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED:'):]
        branch = branch[:branch.index('case SAFEUPLOAD_OPERATION_STAGE_RETIRE_UNEXPOSED:')]
        self.assertRegex(branch, r'return Result == SAFEUPLOAD_STAGE_RESULT_COMPLETION_PERMITTED;\s*$')

    def test_one_lifecycle_claim_through_completion(self):
        create = stream('StageCreate')
        self.order(create, 'stream->AttachLifecycleInFlight ||',
                   'InterlockedIncrement(&stream->FileObjects)',
                   'if (stream->AttachCompletionPending) stream->AttachLifecycleInFlight = TRUE;',
                   'StageRelease(&StageNamespaceResource);\n    return status;')
        self.assertIn('NT_ASSERT(Stream->AttachLifecycleInFlight)', stream('StageAttachRunLifecycle'))
        drain = stream('StageAttachDrainTransaction')
        self.order(drain, 'StageAttachComplete(Transaction, status)',
                   'StageAcquire(&StageNamespaceResource)',
                   'Transaction->Stream->AttachLifecycleInFlight = FALSE;',
                   'InterlockedDecrement(&Transaction->Stream->RpcReferences)',
                   'StageRelease(&StageNamespaceResource)')
        source = code('StageStream.c')
        self.assertEqual(1, source.count('AttachLifecycleInFlight = TRUE;'))
        self.assertEqual(1, source.count('AttachLifecycleInFlight = FALSE;'))

    def test_cancelled_replay_is_held_and_diagnosed(self):
        exchange = stream('StageAttachExchangeRetry')
        self.order(exchange, 'SafeUploadStageMandatoryTeardownActive()',
                   'Operation == SAFEUPLOAD_OPERATION_STAGE_ATTACH_COMPLETION_PERMITTED &&',
                   'Transaction->CancelRequested', '!StageAttachRetryAllowed(Transaction)',
                   'return STATUS_CANCELLED;', 'SafeUploadStageAttachmentExchangeV20(')
        retry = stream('StageAttachRetryAllowed')
        for stop in ('Transaction->TeardownRequested', 'FltIsIoCanceled',
                     'StageAttachIsInstanceTearingDown', 'SafeUploadStageProtocolIsReady',
                     'KeWaitForSingleObject(Transaction->RequestorProcess'):
            self.assertIn(stop, retry)
        drain = stream('StageAttachDrainTransaction')
        self.order(drain, 'AttachCompletionPending || Transaction->Stream->AttachCompletionFence',
                   'DrainStatus = NT_SUCCESS(status) ? STATUS_CANCELLED : status;',
                   'Wait = STAGE_WAIT_SERVICE;')
        complete = stream('StageAttachComplete')
        self.order(complete, 'if (NT_SUCCESS(Status) && cancelled) Status = STATUS_CANCELLED;',
                   'if (NT_SUCCESS(Status) && Transaction->NeedsAttachCommit',
                   'FltCompletePendedPreOperation(Transaction->CallbackData, FLT_PREOP_COMPLETE, NULL)',
                   'if (NT_SUCCESS(Status) && Transaction->NeedsAttachCommit',
                   'StageClearPrivateDelete(stream)')
        for name in ('StageAttachExchangeRetry', 'StageAttachDrainTransaction', 'StageAttachRunLifecycle'):
            self.assertNotIn('StageClearPrivateDelete(', stream(name))
            self.assertNotIn('PrivateDeleteReserved = FALSE', stream(name))

    def test_maintenance_worker_cannot_seal_pending_attachment(self):
        text = stream('StageProcessStream')
        start = text.index('if (Stream->AttachCompletionPending ||')
        block = text[start:text.index('if (Stream->HandleReceiptPending', start)]
        self.assertIn('return;', block)
        self.assertNotIn('StageSealVersion', block)
        self.assertNotIn('SafeUploadStageAttachmentExchangeV20', text)
        self.assertIn('Stream->AttachCompletionPending ||', stream('StageSealVersion'))

    def test_existing_exact_retirement_branches_remain(self):
        lifecycle = stream('StageAttachRunLifecycle')
        branch = lifecycle[lifecycle.index('if (Stream->AttachCommitResult == SAFEUPLOAD_STAGE_RESULT_ATTACH_COMMIT_DENIED)'):]
        branch = branch[:branch.index('if (FltIsIoCanceled')]
        self.order(branch, 'SAFEUPLOAD_OPERATION_STAGE_ATTACH_ABORT',
                   '&Stream->AttachAbortRequest', 'if (!NT_SUCCESS(status)) return status;',
                   'result != SAFEUPLOAD_STAGE_RESULT_ATTACH_ABORTED',
                   'StageAttachQueueUnattachedAllocation(Stream)', 'return STATUS_ACCESS_DENIED;')
        retire = stream('StageAttachRetireUnexposed')
        self.order(retire, 'Stream->AttachCompletionMayExist ||', 'return STATUS_DEVICE_BUSY;',
                   'StageRelease(&StageNamespaceResource);',
                   'SAFEUPLOAD_OPERATION_STAGE_RETIRE_UNEXPOSED',
                   '&Stream->AttachRetireRequest', 'if (!NT_SUCCESS(status)) return status;',
                   'result != SAFEUPLOAD_STAGE_RESULT_ATTACH_RETIRED_UNEXPOSED',
                   'StageClearPrivateDelete(Stream)')
        queued = stream('StageAttachQueueUnattachedAllocation')
        self.assertIn('SAFEUPLOAD_STAGE_DISCARD_KIND_UNATTACHED_ALLOCATION', queued)
        self.assertNotIn('StageClearPrivateDelete', queued)

    def test_no_new_reservation_release_sites(self):
        # Pre-existing non-attachment disposition/cleanup/owner-exit behavior
        # is preserved. No new direct clear or helper call is allowed anywhere.
        expected = {'StageRetainAllocationReceipt': 1, 'StageCreate': 1,
                    'StageAttachRetireUnexposed': 1, 'StageAttachComplete': 1,
                    'StageSetDisposition': 1, 'StagePerformDiscardRpcs': 1, 'StageOwnersExited': 1}
        source = code('StageStream.c')
        self.assertEqual(8, len(re.findall(r'\bStageClearPrivateDelete\s*\(', source)))
        for name, count in expected.items():
            self.assertEqual(count, stream(name).count('StageClearPrivateDelete('), name)
        self.assertEqual(2, len(re.findall(r'PrivateDeleteReserved\s*=\s*FALSE\s*;', source)))
        self.assertIn('Stream->PrivateDeleteReserved = FALSE;', stream('StageClearPrivateDelete'))
        self.assertIn('stream->PrivateDeleteReserved = FALSE;', stream('StagePreOperationCore'))
        clear = stream('StageClearPrivateDelete')
        self.order(clear, 'Stream->AllocationRpcInFlight || Stream->AllocationReceiptPending ||',
                   'Stream->DiscardRpcInFlight) return;', 'Stream->PrivateDeleteReserved = FALSE;')

    def test_passive_sends_and_no_wait_under_namespace_or_spin(self):
        for name in ('StageAttachOwnerCanResume', 'StageAttachExchangeRetry', 'StageAttachRunLifecycle'):
            self.assertIn('NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)', stream(name), name)
        for name in ('StageAttachOwnerCanResume', 'StageAttachExchangeRetry'):
            self.assertNotIn('StageStreamAcquireSpinLock', stream(name))
        owner = stream('StageAttachOwnerCanResume')
        for wait in ('KeWait', 'FltSendMessage', 'SafeUploadStageAttachmentExchangeV20'):
            self.assertNotIn(wait, owner)
        exchange = stream('StageAttachExchangeRetry')
        # Its only explicit namespace acquisition is after the service send.
        self.order(exchange, 'SafeUploadStageAttachmentExchangeV20(', 'StageAcquire(&StageNamespaceResource)')
        lifecycle = stream('StageAttachRunLifecycle')
        held = False
        for token in re.findall(r'StageAcquire\(&StageNamespaceResource\)|StageRelease\(&StageNamespaceResource\)|StageAttachExchangeRetry\(', lifecycle):
            if token.startswith('StageAcquire'): held = True
            elif token.startswith('StageRelease'): held = False
            else: self.assertFalse(held)
        for name in ('SafeUploadStageBeginMandatoryTeardown', 'SafeUploadStageDrainMandatoryTeardown'):
            text = stream(name)
            self.assertNotIn('StageAttachExchangeRetry(', text)
            self.assertNotIn('SafeUploadStageAttachmentExchangeV20(', text)

    def test_new_state_and_hooks_compile_out_of_normal_builds(self):
        source = code('StageStream.c')
        stack = []
        for line in source.splitlines():
            if re.match(r'\s*#if(?:def|ndef)?\b', line): stack.append(line.strip())
            elif line.strip().startswith('#endif'): stack.pop()
            elif line.strip().startswith('#else') and stack: stack[-1] = '#else ' + stack[-1]
            if 'AttachLifecycleInFlight' in line or 'StageAttachOwnerCanResume' in line:
                self.assertIn('#if SAFEUPLOAD_STAGING_PROTOTYPE', stack, line)


# Mutations are applied only to in-memory text, never to the checkout. Each
# must make the production contract suite fail, rather than merely testing the
# assertion implementation against itself. See attachment-replay.md for intent.
MUTATIONS = (
    ('fresh_op15', 'StageStream.c', '&Stream->AttachCompletionRequest, &result);', '&Stream->AttachRetireRequest, &result);'),
    ('reset_request', 'StageStream.c', 'if (!Stream->AttachCompletionKnown) {',
     'if (!Stream->AttachCompletionKnown) {\n        RtlZeroMemory(&Stream->AttachCompletionRequest, sizeof(Stream->AttachCompletionRequest));'),
    ('owner_pid_only', 'StageStream.c', 'view->Owner != Owner || view->OwnerProcessId != Transaction->RequestorProcessId ||',
     'view->OwnerProcessId != Transaction->RequestorProcessId ||'),
    ('wrong_generation', 'StageStream.c', 'view->Generation != Transaction->ExpectedGeneration || Stream->OwnerExited ||', 'Stream->OwnerExited ||'),
    ('wrong_allocation', 'StageStream.c', '!RtlEqualMemory(&Stream->TransferId, &Stream->AllocationIntent.AllocationReservationId, sizeof(GUID)) ||', ''),
    ('fresh_owner_resume', 'StageStream.c',
     'if (!Stream->AttachCompletionMayExist || Stream->AttachCompletionRequest.RequestId == 0) return FALSE;', ''),
    ('foreign_bypass', 'StageStream.c', '!StageAttachOwnerCanResume(privateDelete, transaction, owner)', 'FALSE'),
    ('cancel_send', 'StageStream.c', 'InterlockedCompareExchange(&Transaction->CancelRequested, 0, 0) != 0 ||\n         !StageAttachRetryAllowed(Transaction)', 'FALSE'),
    ('lost_diagnostic', 'StageStream.c', 'Transaction->Stream->DrainStatus = NT_SUCCESS(status) ? STATUS_CANCELLED : status;', ''),
    ('missing_claim', 'StageStream.c', 'if (stream->AttachCompletionPending) stream->AttachLifecycleInFlight = TRUE;', ''),
    ('early_release', 'StageStream.c', 'Stream->DrainStatus = status;\n            Stream->Wait = STAGE_WAIT_SERVICE;',
     'Stream->DrainStatus = status;\n            StageClearPrivateDelete(Stream);\n            Stream->Wait = STAGE_WAIT_SERVICE;'),
    ('early_seal', 'StageStream.c', 'Stream->Wait = STAGE_WAIT_NONE;\n        return;\n    }\n    if (Stream->HandleReceiptPending',
     'Stream->Wait = STAGE_WAIT_NONE;\n        StageSealVersion(Stream);\n    }\n    if (Stream->HandleReceiptPending'),
    ('synthetic_op15_result', 'StageProtocol.c', 'return Result == SAFEUPLOAD_STAGE_RESULT_COMPLETION_PERMITTED;', 'return TRUE;'),
    ('changed_replay_bytes', 'StageProtocol.c', 'status = RtlEqualMemory(Request, expected, sizeof(*expected)) ? STATUS_SUCCESS :', 'status = TRUE ? STATUS_SUCCESS :'),
)


class MutationControls(unittest.TestCase):
    def test_contracts_reject_each_mutation(self):
        baseline = unittest.TextTestRunner(stream=io.StringIO()).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(AttachmentReplay))
        self.assertTrue(baseline.wasSuccessful(), 'Production contracts must pass before mutation testing')
        for name, file, before, after in MUTATIONS:
            with self.subTest(mutation=name):
                source = (K / file).read_text()
                self.assertEqual(1, source.count(before), name)
                OVERRIDES[file] = source.replace(before, after, 1)
                try:
                    result = unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.defaultTestLoader.loadTestsFromTestCase(AttachmentReplay))
                    self.assertFalse(result.wasSuccessful(), name)
                finally:
                    OVERRIDES.clear()


if __name__ == '__main__':
    unittest.main(verbosity=2)
