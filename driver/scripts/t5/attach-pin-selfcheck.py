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

    def test_resume_makes_one_op16_attempt(self):
        text = body(self.text, 'StageAttachResumeOrRun')
        retire = text.index('StageAttachRetireUnexposed(Transaction, Transaction->Stream)')
        self.assertRegex(text[retire:retire + 300], r'Transaction->UnexposedRetirementAllowed\s*=\s*FALSE\s*;')
        drain = body(self.text, 'StageAttachDrainTransaction')
        self.assertRegex(drain, r'Transaction->UnexposedRetirementAllowed\s*&&')


if __name__ == '__main__':
    unittest.main()
