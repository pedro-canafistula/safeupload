#!/usr/bin/env python3
"""Source-only T5 attach-transaction stream pin contract; no compiler, network or VM.

An attach transaction that installs Transaction->Stream owns exactly one
RpcReferences pin on it, released only by StageAttachDrainTransaction. The op16
resume path in StageAttachResumeOrRun also released it, driving RpcReferences
to -1 (t5-replay review, finding 1), and the drain then resent op16 for an
already-retired stream. These controls inspect production source only.
Run: python3 driver/scripts/t5/attach-pin-selfcheck.py
"""
from pathlib import Path
import io
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'driver/SafeUpload.Minifilter/StageStream.c'
OVERRIDE = None


def code(path):
    source = path.read_text() if OVERRIDE is None else OVERRIDE
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


class AttachPin(unittest.TestCase):
    def setUp(self):
        self.text = code(SOURCE)

    def test_only_the_common_drain_releases_the_transaction_pin(self):
        releases = re.findall(r'InterlockedDecrement\(&Transaction->Stream->RpcReferences\)', self.text)
        self.assertEqual(len(releases), 1)
        drain = body(self.text, 'StageAttachDrainTransaction')
        self.assertIn('InterlockedDecrement(&Transaction->Stream->RpcReferences)', drain)
        self.assertLess(drain.index('InterlockedDecrement(&Transaction->Stream->RpcReferences)'),
                        drain.index('Transaction->Stream = NULL'))

    def test_every_installed_stream_takes_one_pin(self):
        text = body(self.text, 'StageAttachResumeOrRun')
        # Require both handoffs, not a vacuous loop over whichever survive a
        # mutation. Each branch owns one pin; neither releases it locally.
        self.assertEqual(['current', 'stream'], re.findall(r'Transaction->Stream\s*=\s*(\w+)\s*;', text))
        self.assertEqual(['current', 'stream'], re.findall(r'InterlockedIncrement\(&([\w]+)->RpcReferences\)', text))
        self.assertNotRegex(text, r'InterlockedDecrement\([^)]*RpcReferences\)')
        self.assertRegex(text, r'InterlockedIncrement\(&current->RpcReferences\);\s*Transaction->Stream = current;')
        installed = text[text.index('Transaction->Stream = stream;'):]
        self.assertRegex(installed, r'Transaction->Stream = stream;\s*if \(stream->View != NULL\) Transaction->ExpectedGeneration = stream->View->Generation;\s*Transaction->BindingInstalled = TRUE;\s*InterlockedIncrement\(&stream->RpcReferences\);')

    def test_handoffs_stay_locked_until_pin_is_owned(self):
        text = body(self.text, 'StageAttachResumeOrRun')
        for owner in ('current', 'stream'):
            handoff = text.index('Transaction->Stream = ' + owner + ';')
            acquire = text.rindex('StageAcquire(&StageNamespaceResource);', 0, handoff)
            before = text[acquire:handoff]
            if owner == 'stream':
                # The sole earlier unlock is in the NULL lookup branch,
                # which returns before it can reach this handoff.
                null_exit = r'if \(stream == NULL\)\s*{\s*StageRelease\(&StageNamespaceResource\);\s*return STATUS_INVALID_DEVICE_STATE;\s*}'
                self.assertRegex(before, null_exit)
                before = re.sub(null_exit, '', before)
            self.assertNotIn('StageRelease(&StageNamespaceResource)', before)
            pin = text.index('InterlockedIncrement(&' + owner + '->RpcReferences)', acquire)
            self.assertNotIn('StageRelease(&StageNamespaceResource)', text[min(handoff, pin):max(handoff, pin)])

    def test_all_replay_outcomes_keep_the_pin_for_common_drain(self):
        resume = body(self.text, 'StageAttachResumeOrRun')
        # Op16 success/lost reply return from one branch; initial attachment,
        # ambiguous/cached op15 and ordinary attached opens use the other.
        # Require the real production return edges after each handoff.
        retire = resume[resume.index('if (Transaction->Stream != NULL)'):resume.index('if (SafeUploadStageProtocolBoundAllocationReady())')]
        self.assertRegex(retire, r'return NT_SUCCESS\(status\) \? STATUS_DELETE_PENDING : status;\s*}')
        attached = resume[resume.index('Transaction->Stream = stream;'):]
        self.assertEqual(3, len(re.findall(r'\breturn\b', attached)))
        for exit in ('return STATUS_SUCCESS;', 'return STATUS_INVALID_DEVICE_STATE;',
                     'return StageAttachRunLifecycle(Transaction, stream);'):
            self.assertIn(exit, attached)
        worker = body(self.text, 'StageAttachWorkerBody')
        self.assertIn('status = StageAttachResumeOrRun(Transaction, &newBinding);', worker)
        self.assertRegex(worker, r'return status;\s*}')
        # Lifecycle can return for live validation failure, known permit,
        # lost/malformed/cancelled RPC or terminal denial. None of its exits,
        # rollback or completion arbitration may replace/release the pin.
        for name in ('StageAttachWorkerBody', 'StageAttachRunLifecycle', 'StageAttachExchangeRetry',
                     'StageAttachRetireUnexposed', 'StageAttachRollbackBinding', 'StageAttachComplete'):
            text = body(self.text, name)
            self.assertNotRegex(text, r'Transaction->Stream\s*=(?!=)', name)
            self.assertNotRegex(text, r'Interlocked(?:Increment|Decrement)\([^)]*RpcReferences\)', name)

    def test_common_drain_balances_both_acquisition_paths(self):
        drain = body(self.text, 'StageAttachDrainTransaction')
        self.assertEqual(['if (Transaction == NULL) return;'],
                         re.findall(r'if \(Transaction == NULL\) return;|\breturn\s*;', drain))
        self.assertEqual(['NULL'], re.findall(r'Transaction->Stream\s*=\s*(\w+)\s*;', drain))
        start = drain.index('if (Transaction->Stream != NULL) {', drain.index('StageAttachComplete(Transaction, status);'))
        tail = drain[start:drain.index('StageAttachReleaseRelatedObjects(Transaction);')]
        self.assertRegex(tail, r'if \(InterlockedDecrement\(&Transaction->Stream->RpcReferences\) == 0\)\s*StageQueueStream\(Transaction->Stream, &StageCounters.WakeInline\);\s*StageRelease\(&StageNamespaceResource\);\s*Transaction->Stream = NULL;\s*}')
        self.assertLess(drain.index('StageAttachComplete(Transaction, status);'), start)
        self.assertLess(tail.index('StageAcquire(&StageNamespaceResource)'), tail.index('InterlockedDecrement'))
        # Inventory the source edges: each acquisition +1, common drain -1.
        # This is a source lifetime obligation, not a Windows execution model.
        resume = body(self.text, 'StageAttachResumeOrRun')
        for owner in ('current', 'stream'):
            with self.subTest(owner=owner):
                acquired = len(re.findall(r'InterlockedIncrement\(&' + owner + r'->RpcReferences\)', resume))
                released = tail.count('InterlockedDecrement(&Transaction->Stream->RpcReferences)')
                self.assertEqual(1, acquired)
                self.assertEqual(0, acquired - released)

    def test_resume_makes_one_op16_attempt(self):
        text = body(self.text, 'StageAttachResumeOrRun')
        retire = text.index('StageAttachRetireUnexposed(Transaction, Transaction->Stream)')
        self.assertRegex(text[retire:retire + 300], r'Transaction->UnexposedRetirementAllowed\s*=\s*FALSE\s*;')
        drain = body(self.text, 'StageAttachDrainTransaction')
        self.assertRegex(drain, r'Transaction->UnexposedRetirementAllowed\s*&&')

    def test_every_installed_stream_takes_exactly_one_pin(self):
        # Both acquisition paths (op16 resume and the ordinary attach binding) live in this function.
        text = body(self.text, 'StageAttachResumeOrRun')
        handoffs = list(re.finditer(r'Transaction->Stream\s*=\s*(\w+)\s*;', text))
        self.assertEqual([m.group(1) for m in handoffs], ['current', 'stream'])
        for match in handoffs:
            window = text[max(0, match.start() - 200):match.end() + 300]
            pins = re.findall(r'InterlockedIncrement\(&' + match.group(1) + r'->RpcReferences\)', window)
            self.assertEqual(len(pins), 1, 'handoff of ' + match.group(1) + ' must take exactly one pin')
        self.assertEqual(len(re.findall(r'InterlockedIncrement\(&\w+->RpcReferences\)', text)), 2)
        self.assertNotRegex(text, r'InterlockedDecrement\([^)]*RpcReferences\)')

    def test_drain_requeues_at_zero_and_forgets_the_stream(self):
        drain = body(self.text, 'StageAttachDrainTransaction')
        self.assertRegex(drain, r'if \(InterlockedDecrement\(&Transaction->Stream->RpcReferences\) == 0\)\s*'
                                r'StageQueueStream\(Transaction->Stream,')


MUTATIONS = (
    ('missing_attach_handoff', 'Transaction->Stream = stream;', ''),
    ('missing_attach_pin', 'Transaction->BindingInstalled = TRUE;\n    InterlockedIncrement(&stream->RpcReferences);',
     'Transaction->BindingInstalled = TRUE;'),
    ('missing_resume_handoff', 'Transaction->Stream = current;', ''),
    ('missing_resume_pin', 'InterlockedIncrement(&current->RpcReferences);', ''),
    ('double_resume_release', 'Transaction->UnexposedRetirementAllowed = FALSE;\n        return NT_SUCCESS(status)',
     'InterlockedDecrement(&Transaction->Stream->RpcReferences);\n        Transaction->UnexposedRetirementAllowed = FALSE;\n        return NT_SUCCESS(status)'),
    ('lost_common_release', 'InterlockedDecrement(&Transaction->Stream->RpcReferences) == 0', 'TRUE'),
    ('lost_common_reset', 'Transaction->Stream = NULL;', ''),
    ('early_drain_exit', 'StageAttachComplete(Transaction, status);', 'StageAttachComplete(Transaction, status);\n    return;'),
    ('completion_releases_pin', 'stream = Transaction->Stream;',
     'stream = Transaction->Stream;\n    InterlockedDecrement(&stream->RpcReferences);'),
    ('extra_attach_pin', 'Transaction->BindingInstalled = TRUE;\n    InterlockedIncrement(&stream->RpcReferences);',
     'Transaction->BindingInstalled = TRUE;\n    InterlockedIncrement(&stream->RpcReferences);\n    InterlockedIncrement(&stream->RpcReferences);'),
    ('completion_loses_handoff', 'stream = Transaction->Stream;',
     'stream = Transaction->Stream;\n    Transaction->Stream = NULL;'),
)


class MutationControls(unittest.TestCase):
    def test_contracts_reject_each_mutation(self):
        global OVERRIDE
        baseline = unittest.TextTestRunner(stream=io.StringIO()).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(AttachPin))
        self.assertTrue(baseline.wasSuccessful(), 'Production contracts must pass before mutation testing')
        for name, before, after in MUTATIONS:
            with self.subTest(mutation=name):
                source = SOURCE.read_text()
                self.assertEqual(1, source.count(before), name)
                OVERRIDE = source.replace(before, after, 1)
                try:
                    result = unittest.TextTestRunner(stream=io.StringIO()).run(
                        unittest.defaultTestLoader.loadTestsFromTestCase(AttachPin))
                    self.assertFalse(result.wasSuccessful(), name)
                finally:
                    OVERRIDE = None


if __name__ == '__main__':
    unittest.main(verbosity=2)
