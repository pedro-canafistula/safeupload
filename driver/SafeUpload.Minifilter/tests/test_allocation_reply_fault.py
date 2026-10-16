#!/usr/bin/env python3
"""Compile production lost-Prepare and cleanup decisions against OS edge shims.

Host diagnostic only: no Windows lifetime, WDK/PREfast or VM qualification.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('directory', HERE / 'test_directory_ux.py')
directory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(directory)
function = directory.function


class AllocationReplyFault(unittest.TestCase):
    def test_compiled_production_fault_recovery(self):
        source = (HERE.parent / 'StageStream.c').read_text()
        functions = ''.join(function(source, name) for name in (
            'StageAttachQueueUnattachedAllocation', 'StageAttachRunLifecycle',
            'StageAbortUnattachedAllocation', 'StagePerformDiscardRpcs'))
        fixture = (HERE / 'allocation_reply_fault_fixture.c').read_text()
        scratch = Path(os.environ.get('TMPDIR', ROOT / '.scratch'))
        scratch.mkdir(parents=True, exist_ok=True)
        compilers = list(dict.fromkeys(filter(None, (shutil.which('cc'), shutil.which('clang')))))
        self.assertTrue(compilers)
        with tempfile.TemporaryDirectory(prefix='allocation-reply-', dir=scratch) as temp:
            cfile, binary = Path(temp) / 'fault.c', Path(temp) / 'fault'
            cfile.write_text(fixture.replace('/* PRODUCTION */', functions))
            for compiler in compilers:
                with self.subTest(compiler=compiler):
                    subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=undefined', str(cfile), '-o', str(binary)], check=True)
                    subprocess.run([str(binary)], check=True, timeout=30)

    def test_recovery_gates_preserve_retry_and_terminal_authority(self):
        source = (HERE.parent / 'StageStream.c').read_text()
        for name, pointer in (('StageCreate', 'privateDelete'), ('StageAttachResumeOrRun', 'current')):
            body = function(source, name)
            proof = (f'if ({pointer}->AllocationReceiptPending &&\n'
                     f'                !{pointer}->AttachCompletionMayExist && !{pointer}->AttachCompletionKnown)')
            self.assertIn(''.join(proof.split()), ''.join(body.split()))
            start = body.index(f'{pointer}->AllocationReceiptPending &&')
            self.assertIn('status = STATUS_SHARING_VIOLATION;', body[start:start + 230])
        helper = function(source, 'StageAbortUnattachedAllocation')
        self.assertIn('PAGED_CODE();', helper)
        self.assertIn('#pragma alloc_text(PAGE, StageAbortUnattachedAllocation)', source)
        self.assertNotIn('StageAcquire(', helper)
        collect = function(source, 'StageCollectDiscardRpcs')
        for guard in ('stream->AttachLifecycleInFlight', 'stream->AttachCompletionMayExist',
                      'stream->AttachCompletionKnown', 'stream->BackingObject == NULL',
                      'stream->Sections.SharedCacheMap == NULL', 'stream->Sections.DataSectionObject == NULL',
                      'stream->Sections.ImageSectionObject == NULL', 'InterlockedIncrement(&stream->RpcReferences)'):
            self.assertIn(guard, collect)
        worker = function(source, 'StagePerformDiscardRpcs')
        self.assertLess(worker.index('StageAbortUnattachedAllocation(stream)'), worker.index('SafeUploadStageDiscardVersionV19('))
        self.assertLess(worker.index('SafeUploadStageDiscardVersionV19('), worker.index('StageAcquire(&StageNamespaceResource)'))
        self.assertLess(worker.index('SAFEUPLOAD_STAGE_REPLY_DISCARD_ACKNOWLEDGED'), worker.index('StageClearPrivateDelete(stream)'))


if __name__ == '__main__':
    unittest.main()
