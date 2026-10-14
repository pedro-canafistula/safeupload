#!/usr/bin/env python3
"""Source-only T5 stream-list membership contract; no compiler, network or VM.

Exact-reply revalidation (the op19 HANDLE_OBSERVED receipt and allocation
recovery) accepts a reply only for a stream whose Listed flag is set. m2t5boot9:
the ordinary CREATE insertion never set it, so every attached version discarded
its ACK and never sealed. These controls inspect production source only.
Run: python3 driver/scripts/t5/stream-listing-selfcheck.py
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


class StreamListing(unittest.TestCase):
    def setUp(self):
        self.text = code(SOURCE)

    def test_every_stream_list_insertion_sets_listed_under_the_list_lock(self):
        inserts = list(re.finditer(r'InsertTailList\(&StageStreams,\s*&(\w+)->Link\)', self.text))
        self.assertGreaterEqual(len(inserts), 2, 'expected the ordinary and the receipt-retention insertions')
        for match in inserts:
            name = match.group(1)
            acquire = self.text.rfind('StageStreamAcquireSpinLock(&StageListLock', 0, match.start())
            release = self.text.find('StageStreamReleaseSpinLock(&StageListLock', match.end())
            self.assertNotEqual(acquire, -1)
            self.assertNotEqual(release, -1)
            block = self.text[acquire:release]
            self.assertRegex(block, r'\b' + name + r'->Listed\s*=\s*TRUE\s*;',
                             'insertion at offset %d does not mark the stream listed under StageListLock' % match.start())

    def test_listed_is_never_cleared(self):
        self.assertNotRegex(self.text, r'->Listed\s*=\s*FALSE')

    def test_exact_reply_revalidations_still_depend_on_listed(self):
        # If these checks change, revisit this control rather than letting it pass vacuously.
        self.assertRegex(self.text, r'stream->Listed && stream->HandleReceiptInFlight')
        self.assertRegex(self.text, r'stream->Listed && stream->AllocationReceiptPending')


if __name__ == '__main__':
    unittest.main()
