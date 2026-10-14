#!/usr/bin/env python3
"""Source-only T5 retry-timer and startup-reconcile contract; no compiler, network or VM.

m2t5boot11/12: the timer fired while the startup reconcile was pending, but the
armed flag was cleared only by StageWorkerPass (skipped while reconciling), so the
reconcile was never retried after the service's EpochBusy reply. Two reviewed
attempts that derived the armed state from the expiry flag were rejected: a stale
expiry or delayed DPC could disarm a later arm, leaving it uncancelled. The timer's
own signal state (KeSetTimer resets it; expiry sets it) is the only expiry source.
These controls inspect production source only.
Run: python3 driver/scripts/t5/reconcile-retry-selfcheck.py
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'driver/SafeUpload.Minifilter/StageStream.c'


def code(path):
    source = path.read_text()
    return re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                  lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source, flags=re.S)


def body(text, name):
    for match in re.finditer(r'\b' + re.escape(name) + r'\s*\(', text):
        i = text.index('(', match.start()) + 1; level = 1
        while level:
            level += {'(': 1, ')': -1}.get(text[i], 0); i += 1
        while text[i].isspace(): i += 1
        if text[i] != '{': continue
        start = i; level = 1; i += 1
        while level:
            level += {'{': 1, '}': -1}.get(text[i], 0); i += 1
        return text[start:i]
    raise AssertionError('Missing production body: ' + name)


def exchange_contract(source):
    def require(condition, message):
        if not condition: raise AssertionError(message)
    process = body(source, 'StageProcessStream')
    collect = body(source, 'StageCollectHandleReceiptRpcs')
    reply = body(source, 'StagePerformHandleReceiptRpcs')
    timer = body(source, 'StageUpdateRetryTimer')
    for condition in ('stream->HandleReceiptInFlight', 'stream->RenameRpcInFlight'):
        require(condition in timer, 'census must retain in-flight obligations')
    require('Stream->HandleReceiptWait == STAGE_WAIT_SERVICE ? STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE' in process,
            'pending attempt must preserve eligible EXCHANGE or permanent SERVICE')
    require('stream->HandleReceiptWait == STAGE_WAIT_SERVICE' in collect, 'unrelated wake must not resend parked op19')
    require('stream->Wait = STAGE_WAIT_EXCHANGE;' in collect, 'collection must not temporarily empty the waiting set')
    require('KeQueryInterruptTime() < stream->HandleReceiptRetryAfter' in collect,
            'unrelated event must not bypass op19 backoff')
    require('KeQueryInterruptTime() < stream->RenameRetryAfter' in body(source, 'StageCollectRenameRpcs'),
            'unrelated event must not bypass rename backoff')
    require(reply.index('StageUpdateRetryTimer();') < reply.index('stream->HandleReceiptRetryAfter = StageRetryDueTime;'),
            'failed attempt deadline must use the current timer arm')
    rename_reply = body(source, 'StagePerformRenameRpcs')
    require(rename_reply.index('StageUpdateRetryTimer();') < rename_reply.index('stream->RenameRetryAfter = StageRetryDueTime;'),
            'rename retry deadline must use the current timer arm')
    require(timer.count('StageRetryDueTime = KeQueryInterruptTime() + (ULONGLONG)(-due.QuadPart);') == 2,
            'both arm paths must publish monotonic deadlines')
    require(not re.search(r'if \([^;{}]*StageRetryDueTime', timer), 'deadline must never control timer arming')
    require('stream->HandleReceiptWait = StageWaitFor(status);' in reply, 'refusal and transient failure differ')
    require('Stream->RenameWait == STAGE_WAIT_SERVICE' in body(source, 'StageFinishRename'), 'rename refusal must stay parked')
    require('stream->RenameWait == STAGE_WAIT_SERVICE' in body(source, 'StageCollectRenameRpcs'), 'rename collector must respect parking')
    wait = body(source, 'StageWaitFor')
    require('Status == STATUS_ACCESS_DENIED' in wait and 'STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE' in wait,
            'answered refusal must park')
    require('STATUS_DEVICE_BUSY' not in wait, 'typed transient service failure remains an exchange')
    require('StageRetryMs = 0;' in timer[timer.index('if (waiting == 0)'):timer.index('if (StageRetryArmed &&')],
            'reset only after the obligation ends')
    require(source.count('StageRetryMs = 0;') == 1, 'attempts must not reset backoff elsewhere')


def disconnect_contract(source):
    def require(condition, message):
        if not condition: raise AssertionError(message)
    disconnected = body(source, 'SafeUploadStageServiceDisconnected')
    connected = body(source, 'SafeUploadStageServiceConnected')
    timer = body(source, 'StageUpdateRetryTimer')
    worker = body(source, 'StageWorker')
    pass_ = body(source, 'StageWorkerPass')
    require(disconnected.index('StageAcquire(&StageNamespaceResource);') <
            disconnected.index('StageServiceAvailable = FALSE;') <
            disconnected.index('StageStreamAcquireSpinLock(&StageListLock, &irql);') <
            disconnected.index('StageStreamReleaseSpinLock(&StageListLock, irql);') <
            disconnected.index('StageUpdateRetryTimer();') <
            disconnected.index('StageRelease(&StageNamespaceResource);'), 'park then cancel under the owning locks')
    for field in ('HandleReceiptWait', 'RenameWait', 'Wait'):
        require(f'if (stream->{field} == STAGE_WAIT_EXCHANGE) stream->{field} = STAGE_WAIT_SERVICE;' in disconnected,
                'disconnect parks exchange causes without changing genuine drain waits')
    writes = re.findall(r'stream->(\w+)\s*=(?!=)', disconnected)
    require(sorted(writes) == sorted(['HandleReceiptWait', 'RenameWait', 'Wait']),
            'disconnect must retain pending/in-flight/exact-request bookkeeping')
    require(re.search(r'if \(stream->Wait == STAGE_WAIT_DRAIN\) \{ drain = TRUE; \+\+waiting; \}\s*'
                      r'else if \(\s*#if SAFEUPLOAD_STAGING_PROTOTYPE\s*StageServiceAvailable &&\s*#endif\s*'
                      r'\(stream->Wait == STAGE_WAIT_EXCHANGE\s*#if SAFEUPLOAD_STAGING_PROTOTYPE\s*'
                      r'\|\| stream->HandleReceiptInFlight \|\| stream->RenameRpcInFlight\s*#endif\s*\)\) \+\+waiting;', timer),
            'disconnected pending AND late in-flight replies cannot count; drain still counts')
    require('if (StageServiceAvailable && InterlockedCompareExchange(&StageReconcileNeeded, 0, 0) &&' in timer,
            'disconnected reconciliation cannot count')
    require('if (StageServiceAvailable && !SafeUploadStageMandatoryTeardownActive()' in worker,
            'unrelated drain/overflow/stale-DPC wakes cannot send disconnected reconciliation')
    require(re.search(r'\(!StageServiceAvailable \|\| !InterlockedCompareExchange\(&StageReconcileNeeded, 0, 0\)\)\) \{\s*'
                      r'StageWorkerPass\(', worker), 'disconnected wakes must still perform local drain/overflow work')
    require('if (!StageServiceAvailable || InterlockedCompareExchange(&StageReconcileNeeded, 0, 0)) sweep = FALSE;' in pass_
            and 'if (sweep) StageSweepRequested = FALSE;' in pass_, 'only a reconciled channel consumes the unpark sweep')
    require(re.search(r'if \(StageServiceAvailable && !InterlockedCompareExchange\(&StageReconcileNeeded, 0, 0\) &&\s*'
                      r'SafeUploadStageProtocolIsReady\(\)\) \{\s*StageCollectHandleReceiptRpcs\(HandleRpcs\);\s*'
                      r'StageCollectRenameRpcs\(RenameRpcs\);\s*StageCollectSealRpcs\(SealRpcs\);\s*'
                      r'StageCollectDiscardRpcs\(Rpcs\);\s*StageCollectAllocationRecoveryRpcs\(RecoveryRpcs\);\s*\}', pass_),
            'disconnected local work must not collect any service RPC')
    require(pass_.rfind('StageUpdateRetryTimer();') > pass_.index('StageProcessStream('),
            'local drain/overflow work maintains or cancels its timer at the end of the pass')
    require(connected.index('StageAcquire(&StageNamespaceResource);') <
            connected.index('StageServiceAvailable = TRUE;') < connected.index('StageReconcileWait = STAGE_WAIT_EXCHANGE;') <
            connected.index('StageSweepRequested = TRUE;') < connected.index('KeSetEvent('),
            'connect wakes reconciliation before the unpark sweep')
    require('StageServiceAvailable = FALSE;' in body(source, 'SafeUploadStageInitialize'), 'start disconnected')


class RetryTimer(unittest.TestCase):
    def setUp(self):
        self.text = code(SOURCE)
        self.timer = body(self.text, 'StageUpdateRetryTimer')
        self.worker = body(self.text, 'StageWorker')
        self.pass_ = body(self.text, 'StageWorkerPass')

    def test_op19_and_rename_keep_exchange_accounting_through_pending_inflight_reply(self):
        exchange_contract(self.text)

    def test_accounting_and_parking_mutations_are_caught(self):
        mutations = [
            ('|| stream->HandleReceiptInFlight || stream->RenameRpcInFlight', '|| FALSE'),
            ('Stream->HandleReceiptWait == STAGE_WAIT_SERVICE ? STAGE_WAIT_SERVICE : STAGE_WAIT_EXCHANGE',
             'STAGE_WAIT_SERVICE'),
            ('if (stream->HandleReceiptWait == STAGE_WAIT_SERVICE ||', 'if (FALSE ||'),
            ('stream->HandleReceiptWait = StageWaitFor(status);', 'stream->HandleReceiptWait = STAGE_WAIT_EXCHANGE;'),
            ('Status == STATUS_ACCESS_DENIED', 'Status == STATUS_DEVICE_BUSY'),
            ('KeQueryInterruptTime() < stream->HandleReceiptRetryAfter', 'FALSE'),
            ('KeQueryInterruptTime() < stream->RenameRetryAfter', 'FALSE'),
            ('stream->HandleReceiptPending = FALSE;', 'StageRetryMs = 0; stream->HandleReceiptPending = FALSE;'),
        ]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, self.text)
                with self.assertRaises(AssertionError): exchange_contract(self.text.replace(old, new))

    def test_exchange_backoff_progression_and_idle_cancellation_derive_from_production(self):
        first = int(re.search(r'#define STAGE_RETRY_FIRST_MS (\d+)', self.text)[1])
        maximum = int(re.search(r'#define STAGE_RETRY_EXCHANGE_MAX_MS (\d+)', self.text)[1])
        self.assertIn('StageRetryMs = StageRetryMs == 0 ? STAGE_RETRY_FIRST_MS : StageRetryMs * 2;', self.timer)
        self.assertIn('if (StageRetryMs > cap) StageRetryMs = cap;', self.timer)
        delay = 0
        observed = []
        for _ in range(8):
            delay = min(first if delay == 0 else delay * 2, maximum)
            observed.append(delay)
        self.assertEqual(observed, [250, 500, 1000, 2000, 4000, 8000, 8000, 8000])
        self.assertRegex(self.timer, r'if \(waiting == 0\) \{\s*if \(StageRetryArmed\) \(VOID\)KeCancelTimer')

    def test_only_reconciliation_sweep_reenables_parked_receipts(self):
        reset = re.search(r'if \(sweep\) \{\s*stream->HandleReceiptRetryAfter = 0;\s*stream->RenameRetryAfter = 0;\s*'
                          r'if \(stream->HandleReceiptWait == STAGE_WAIT_SERVICE\) stream->HandleReceiptWait = STAGE_WAIT_EXCHANGE;\s*'
                          r'if \(stream->RenameWait == STAGE_WAIT_SERVICE\) stream->RenameWait = STAGE_WAIT_EXCHANGE;', self.pass_)
        self.assertIsNotNone(reset)
        self.assertEqual(self.text.count('if (stream->HandleReceiptWait == STAGE_WAIT_SERVICE) stream->HandleReceiptWait = STAGE_WAIT_EXCHANGE;'), 1)

    def test_arming_reads_the_timer_state_not_an_expiry_flag(self):
        self.assertRegex(self.timer, r'if \(StageRetryArmed && !KeReadStateTimer\(&StageRetryTimer\)\) return;')
        self.assertNotIn('StageRetryFired', self.timer)
        self.assertRegex(self.text, r'KeInitializeTimer\(&StageRetryTimer\);')  # notification timer

    def test_only_cancellation_clears_the_armed_flag(self):
        clears = [m.start() for m in re.finditer(r'StageRetryArmed = FALSE;', self.text)]
        self.assertEqual(len(clears), 2)
        self.assertRegex(self.timer, r'if \(waiting == 0\) \{\s*if \(StageRetryArmed\) \(VOID\)KeCancelTimer\(&StageRetryTimer\);'
                                     r'\s*StageRetryArmed = FALSE;')
        stop = body(self.text, 'SafeUploadStageStopWorker')
        self.assertRegex(stop, r'KeCancelTimer\(&StageRetryTimer\);\s*KeFlushQueuedDpcs\(\);\s*StageRetryArmed = FALSE;')
        for name, text in (('StageWorkerPass', self.pass_), ('StageWorker', self.worker)):
            self.assertNotIn('StageRetryArmed', text, name + ' must not change the armed state')

    def test_the_expiry_is_consumed_once_by_the_pass_for_stream_retries(self):
        self.assertEqual(len(re.findall(r'InterlockedExchange\(&StageRetryFired, 0\)', self.text)), 1)
        self.assertIn('fired = InterlockedExchange(&StageRetryFired, 0) != 0;', self.pass_)
        self.assertRegex(self.pass_, r'if \(sweep \|\| fired\)')

    def result_section(self):
        reply = self.worker[self.worker.index('SafeUploadStageReconcileV20('):]
        return reply[:reply.index('StageUpdateRetryTimer();')]

    def test_every_outcome_is_applied_only_for_the_current_generation(self):
        result = self.result_section()
        current = re.search(r'reconcileCurrent = reconcileServiceGeneration ==\s*'
                            r'InterlockedCompareExchange\(&StageServiceGeneration, 0, 0\);\s*if \(!reconcileCurrent\) \{\s*\}', result)
        self.assertIsNotNone(current, 'generation must be checked first and a stale reply must change nothing')
        before = result[:current.start()]
        self.assertNotRegex(before, r'StageReconcile(Wait|Needed)|reconcileAgain')
        after = result[current.end():]
        self.assertTrue(after.lstrip().startswith('else if (NT_SUCCESS(reconcileStatus) ||'))
        self.assertEqual(len(re.findall(r'StageReconcileWait = ', after)), 2)  # accepted NONE, current failure
        self.assertRegex(after, r'\} else \{\s*StageReconcileWait = StageWaitFor\(reconcileStatus\);\s*\}\s*$')
        self.assertNotIn('StageReconcileWait = STAGE_WAIT_EXCHANGE', after)

    def test_either_acceptance_wakes_one_pass_but_only_success_sweeps(self):
        result = self.result_section()
        accepted = result[result.index('else if (NT_SUCCESS(reconcileStatus) ||'):result.rindex('} else {')]
        success = accepted[accepted.index('if (NT_SUCCESS(reconcileStatus)) {'):]
        success = success[:success.index('}') + 1]
        self.assertIn('StageSweepRequested = TRUE;', success)
        self.assertNotIn('reconcileAgain = TRUE;', success)
        self.assertIn('reconcileAgain = TRUE;', accepted.replace(success, ''))
        self.assertIn('InterlockedExchange(&StageReconcileNeeded, 0);', accepted)

    def test_disconnect_updates_the_timer_under_the_namespace_lock(self):
        disconnect_contract(self.text)

    def test_disconnect_eligibility_and_bookkeeping_mutations_are_caught(self):
        mutations = [
            ('StageServiceAvailable &&', 'TRUE &&'),
            ('StageServiceAvailable = FALSE;', 'StageServiceAvailable = TRUE;'),
            ('if (stream->HandleReceiptWait == STAGE_WAIT_EXCHANGE)', 'if (FALSE)'),
            ('if (stream->RenameWait == STAGE_WAIT_EXCHANGE)', 'if (FALSE)'),
            ('if (stream->Wait == STAGE_WAIT_EXCHANGE) stream->Wait = STAGE_WAIT_SERVICE;',
             'stream->Wait = STAGE_WAIT_SERVICE;'),
            ('StageServiceAvailable = FALSE;', 'StageServiceAvailable = FALSE; stream->HandleReceiptPending = FALSE;'),
            ('StageServiceAvailable = FALSE;', 'StageServiceAvailable = FALSE; stream->RenameRpcInFlight = FALSE;'),
            ('StageServiceAvailable = FALSE;', 'StageServiceAvailable = FALSE; stream->RenameExchange = NULL;'),
            ('if (stream->Wait == STAGE_WAIT_DRAIN)', 'if (StageServiceAvailable && stream->Wait == STAGE_WAIT_DRAIN)'),
            ('if (StageServiceAvailable && !SafeUploadStageMandatoryTeardownActive()',
             'if (!SafeUploadStageMandatoryTeardownActive()'),
            ('(!StageServiceAvailable || !InterlockedCompareExchange(&StageReconcileNeeded, 0, 0))',
             '(!InterlockedCompareExchange(&StageReconcileNeeded, 0, 0))'),
            ('if (sweep) StageSweepRequested = FALSE;', 'StageSweepRequested = FALSE;'),
            ('if (!StageServiceAvailable || InterlockedCompareExchange(&StageReconcileNeeded, 0, 0)) sweep = FALSE;', ''),
            ('if (StageServiceAvailable && !InterlockedCompareExchange(&StageReconcileNeeded, 0, 0) &&',
             'if (TRUE &&'),
        ]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, self.text)
                with self.assertRaises((AssertionError, ValueError)): disconnect_contract(self.text.replace(old, new))

    def test_transient_disconnect_idle_late_reply_and_reconnect_census(self):
        disconnect_contract(self.text)
        # Evaluate the production feature-profile census expression, not a
        # second copy of its boolean logic. Lifecycle writes/locks, unpark and
        # idle cancellation are checked separately above against production.
        expression = re.search(r'else if \((.*?)\) \+\+waiting;', self.timer, re.S)[1]
        expression = re.sub(r'^\s*#(?:if|endif)[^\n]*', '', expression, flags=re.M)
        expression = expression.replace('&&', ' and ').replace('||', ' or ').replace('stream->', '')
        expression = ' '.join(expression.split())
        self.assertRegex(expression, r'^[-\w\s()=]+$')
        def waiting(available, wait, handle=False, rename=False):
            variables = dict(StageServiceAvailable=available, Wait=wait, STAGE_WAIT_EXCHANGE=2,
                             HandleReceiptInFlight=handle, RenameRpcInFlight=rename)
            return int(wait == 1 or eval(expression, {'__builtins__': {}}, variables))
        self.assertEqual(1, waiting(True, 2))  # typed transient -> EXCHANGE/backoff
        self.assertEqual(0, waiting(False, 3))  # disconnect -> SERVICE -> idle cancellation
        self.assertEqual(0, waiting(False, 3, True, True))  # retain in-flight ownership
        self.assertEqual(0, waiting(False, 2, True, True))  # late transient cannot rearm
        self.assertEqual(1, waiting(False, 1, True, True))  # genuine drain remains owed
        self.assertEqual(0, waiting(True, 3))  # connect alone does not unpark an answered refusal
        self.assertEqual(1, waiting(True, 2))  # reconciliation sweep -> EXCHANGE
        self.assertEqual(0, waiting(True, 0))  # exact ACK ends the obligation
        self.assertRegex(self.timer, r'if \(waiting == 0\) \{\s*if \(StageRetryArmed\) \(VOID\)KeCancelTimer')

    def test_the_dpc_only_records_the_expiry_and_wakes_the_worker(self):
        dpc = body(self.text, 'StageRetryDpcRoutine')
        self.assertIn('InterlockedExchange(&StageRetryFired, 1);', dpc)
        self.assertIn('KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);', dpc)
        self.assertNotIn('StageRetryArmed', dpc)
        self.assertNotRegex(dpc, r'Ke\w*Timer')

    def test_each_reconcile_result_updates_the_timer_and_busy_waits_on_exchange(self):
        reply = self.worker[self.worker.index('SafeUploadStageReconcileV20('):]
        self.assertLess(reply.index('StageReconcileWait = StageWaitFor(reconcileStatus)'),
                        reply.index('StageUpdateRetryTimer()'))
        self.assertRegex(self.timer, r'StageReconcileWait == STAGE_WAIT_EXCHANGE\) \+\+waiting')
        self.assertNotIn('STATUS_DEVICE_BUSY', body(self.text, 'StageWaitFor'))


if __name__ == '__main__':
    unittest.main()
