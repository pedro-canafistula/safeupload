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


class RetryTimer(unittest.TestCase):
    def setUp(self):
        self.text = code(SOURCE)
        self.timer = body(self.text, 'StageUpdateRetryTimer')
        self.worker = body(self.text, 'StageWorker')
        self.pass_ = body(self.text, 'StageWorkerPass')

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

    def test_either_acceptance_wakes_one_pass_but_only_success_sweeps(self):
        reply = self.worker[self.worker.index('SafeUploadStageReconcileV20('):]
        accepted = reply[reply.index('InterlockedExchange(&StageReconcileNeeded, 0);'):
                         reply.index('} else if (!NT_SUCCESS(reconcileStatus))')]
        success = accepted[accepted.index('if (NT_SUCCESS(reconcileStatus)) {'):]
        success = success[:success.index('}') + 1]
        self.assertIn('StageSweepRequested = TRUE;', success)
        self.assertNotIn('reconcileAgain = TRUE;', success)
        self.assertIn('reconcileAgain = TRUE;', accepted.replace(success, ''))

    def test_disconnect_updates_the_timer_under_the_namespace_lock(self):
        disconnected = body(self.text, 'SafeUploadStageServiceDisconnected')
        self.assertRegex(disconnected, r'StageReconcileWait = STAGE_WAIT_SERVICE;\s*StageUpdateRetryTimer\(\);\s*'
                                       r'StageRelease\(&StageNamespaceResource\);')
        self.assertLess(disconnected.index('StageAcquire(&StageNamespaceResource)'), disconnected.index('StageUpdateRetryTimer()'))

    def test_the_dpc_only_records_the_expiry_and_wakes_the_worker(self):
        dpc = body(self.text, 'StageRetryDpcRoutine')
        self.assertIn('InterlockedExchange(&StageRetryFired, 1);', dpc)
        self.assertIn('KeSetEvent(&StageWorkEvent, IO_NO_INCREMENT, FALSE);', dpc)
        self.assertNotIn('StageRetryArmed', dpc)
        self.assertNotIn('KeSetTimer', dpc)

    def test_each_reconcile_result_updates_the_timer_and_busy_waits_on_exchange(self):
        reply = self.worker[self.worker.index('SafeUploadStageReconcileV20('):]
        self.assertLess(reply.index('StageReconcileWait = StageWaitFor(reconcileStatus)'),
                        reply.index('StageUpdateRetryTimer()'))
        self.assertRegex(self.timer, r'StageReconcileWait == STAGE_WAIT_EXCHANGE\) \+\+waiting')
        self.assertNotIn('STATUS_DEVICE_BUSY', body(self.text, 'StageWaitFor'))


if __name__ == '__main__':
    unittest.main()
