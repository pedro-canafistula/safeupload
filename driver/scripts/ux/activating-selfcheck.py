#!/usr/bin/env python3
"""Compile actual activation/promotion/admission bodies with deterministic DDIs.

Host diagnostics only: no Windows lifetime, sharing, IRQL or qualification claim.
Scratch and failed compilations stay under .scratch.
"""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
K = ROOT / 'driver/SafeUpload.Minifilter'
spec = importlib.util.spec_from_file_location('contracts', ROOT / 'driver/scripts/t5/teardown-participation-selfcheck.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)

SIGNATURES = {
    'StageRegistryOriginalContext': 'static BOOLEAN StageRegistryOriginalContext(PSTAGE_REGISTRY_ENTRY Entry, PSAFEUPLOAD_STREAM_CONTEXT Context, PVOID Sop)',
    'StageRegistryEntryHoldsNoWriterState': 'static BOOLEAN StageRegistryEntryHoldsNoWriterState(PSTAGE_REGISTRY_ENTRY Entry)',
    'StageRegistryTryPromoteEntry': 'static ULONG StageRegistryTryPromoteEntry(PSTAGE_REGISTRY_ENTRY Entry, BOOLEAN NameMatches, USHORT NameSnapshotChars, ULONG RenameVersion, ULONG CurrentGeneration, BOOLEAN SopEmpty, ULONGLONG ExpectedSopMarkerGeneration, ULONG PolicyGeneration, ULONG PolicyFlags, BOOLEAN CacheFlushed)',
    'StageRegistryActivationProcess': 'static VOID StageRegistryActivationProcess(PSTAGE_REGISTRY_ENTRY Entry, PFLT_INSTANCE Instance, PFLT_VOLUME Volume, PULONG WorkBudget, PBOOLEAN MoreWork)',
    'SafeUploadStageWritersNameActivating': 'static BOOLEAN SafeUploadStageWritersNameActivating(PFLT_INSTANCE Instance, PCUNICODE_STRING Name)',
    'SafeUploadStageWritersAwaitNameActivation': 'static VOID SafeUploadStageWritersAwaitNameActivation(PFLT_INSTANCE Instance, PCUNICODE_STRING Name)',
}


def program(source):
    protocol = (K / 'Protocol.h').read_text() + '\n' + (K / 'Filter.h').read_text()
    fixture = Path(__file__).with_name('activating_fixture.c').read_text()
    names = set(re.findall(r'\bSAFEUPLOAD_[A-Z_0-9]+\b', fixture + '\n'.join(
        t.body('StageWriters.c', n, {'StageWriters.c': source}) for n in SIGNATURES)))
    constants = '\n'.join(line for line in protocol.splitlines()
                          if any(line.startswith('#define ' + n + ' ') for n in names))
    bodies = '\n'.join(signature + t.body('StageWriters.c', name, {'StageWriters.c': source})
                       for name, signature in SIGNATURES.items())
    if 'BOOLEAN cacheFlushedAndPurged = FALSE;' in source:
        bodies = bodies.replace('BOOLEAN CacheFlushed)', 'BOOLEAN CacheFlushedAndPurged)')
        fixture = fixture.replace('assert(type==0);', 'assert(type==FLT_FLUSH_TYPE_FLUSH_AND_PURGE);')
    return fixture.replace('/* PRODUCTION_CONSTANTS */', constants).replace('/* PRODUCTION_BODIES */', bodies)


def run(source, compiler):
    scratch = Path(os.environ.get('TMPDIR', ROOT / '.scratch'))
    scratch.mkdir(parents=True, exist_ok=True)
    # Preserve the first failed setup or assertion for diagnosis.
    temp = Path(tempfile.mkdtemp(prefix='activating-', dir=scratch))
    (temp / 'fixture.c').write_text(program(source))
    build = subprocess.run([compiler, '-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=undefined', str(temp / 'fixture.c'), '-o', str(temp / 'fixture')],
                           capture_output=True, text=True)
    (temp / 'build.txt').write_text(build.stdout + build.stderr)
    if build.returncode:
        raise AssertionError(f'{temp}: {build.stderr}')
    result = subprocess.run([str(temp / 'fixture')], cwd=temp, capture_output=True, text=True, timeout=15)
    (temp / 'run.txt').write_text(result.stdout + result.stderr)
    if result.returncode == 0:
        shutil.rmtree(temp)
    return result


class Activating(unittest.TestCase):
    def test_production_activation_and_on_demand_recheck(self):
        compilers = list(dict.fromkeys(filter(None, (shutil.which('cc'), shutil.which('clang')))))
        self.assertTrue(compilers)
        for compiler in compilers:
            with self.subTest(compiler=compiler):
                result = run((K / 'StageWriters.c').read_text(), compiler)
                self.assertEqual(0, result.returncode, result.stderr)

    def test_missing_flush_and_false_empty_mutations_fail(self):
        source = (K / 'StageWriters.c').read_text()
        mutations = (
            ('status = FltFlushBuffers2(Instance, object, 0, NULL);', '(void)&FltFlushBuffers2; status = STATUS_SUCCESS;'),
            ('if (status != STATUS_SUCCESS) goto Exit;\n    cacheFlushed', 'if (FALSE) goto Exit;\n    cacheFlushed'),
            ('if (userWritable || !MmCanFileBeTruncated(sop, NULL)) STAGE_ACT_EXIT();',
             'if (!MmCanFileBeTruncated(sop, NULL)) STAGE_ACT_EXIT();'),
            ('if (userWritable || !MmCanFileBeTruncated(sop, NULL)) STAGE_ACT_EXIT();',
             'if (userWritable) STAGE_ACT_EXIT();'),
            ('MmCanFileBeTruncated(sop, NULL)', '(TRUE)'),
            ('(SopEmpty ? SAFEUPLOAD_PROMOTION_BASIS_SOP_EMPTY : 0)', '(SopEmpty ? SAFEUPLOAD_PROMOTION_BASIS_SOP_EMPTY : SAFEUPLOAD_PROMOTION_BASIS_SOP_EMPTY)'),
            ('SafeUploadStageWritersQueueRecheck();\n        while (SafeUploadStageWritersNameActivating', '(void)&SafeUploadStageWritersQueueRecheck;\n        while (SafeUploadStageWritersNameActivating'),
        )
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                result = run(source.replace(old, new), shutil.which('cc'))
                self.assertNotEqual(0, result.returncode)

    def test_original_base_fails_retained_reader_regression(self):
        base = subprocess.run(['git', 'show', '59c7e319:driver/SafeUpload.Minifilter/StageWriters.c'],
                              cwd=ROOT, check=True, capture_output=True, text=True).stdout
        # The request-wake helper was absent on the base. Add just its current
        # body for compilation; the original worker must still fail first.
        current = (K / 'StageWriters.c').read_text()
        base += '\n' + SIGNATURES['SafeUploadStageWritersAwaitNameActivation'] + t.body(
            'StageWriters.c', 'SafeUploadStageWritersAwaitNameActivation', {'StageWriters.c': current})
        result = run(base, shutil.which('cc'))
        self.assertNotEqual(0, result.returncode)
        self.assertIn('promotes==1&&flushes==1', result.stderr)

    def test_create_still_stages_and_retirement_still_requires_its_proof(self):
        source = (K / 'StageWriters.c').read_text()
        activation = t.body('StageWriters.c', 'StageRegistryActivationProcess')
        self.assertEqual(2, activation.count('MmCanFileBeTruncated(sop, NULL)'))
        self.assertLess(activation.index('MmCanFileBeTruncated'), activation.index('FltFlushBuffers2('))
        self.assertLess(activation.index('FltFlushBuffers2('), activation.rindex('MmCanFileBeTruncated'))
        self.assertIn('MmCanFileBeTruncated', t.body('StageWriters.c', 'StageRegistryEntryQuiescent'))
        self.assertIn('SAFEUPLOAD_REGISTRY_STATE_UNKNOWN', t.body('StageWriters.c', 'StageRegistryPruneLocked'))
        admit = t.body('StageStream.c', 'StageAdmit')
        wait = admit.index('SafeUploadStageWritersAwaitNameActivation(')
        self.assertLess(wait, admit.index('SafeUploadStageWritersNameActivating(', wait))
        self.assertLess(wait, admit.index('StageAttachQueueCreate(Data, Objects, name'))
        self.assertIn('#pragma alloc_text(PAGE, SafeUploadStageWritersAwaitNameActivation)', source)
        awaiter = t.body('StageWriters.c', 'SafeUploadStageWritersAwaitNameActivation')
        self.assertEqual(1, awaiter.count('SafeUploadStageWritersQueueRecheck();'))
        self.assertLess(awaiter.index('FltReleasePushLock(&RegistryLock)'), awaiter.index('KeDelayExecutionThread'))
        self.assertIn('KeQueryInterruptTime() < deadline', awaiter)
        for name in ('StageMvpNamespaceOpen',):
            self.assertIn('FILE_WRITE_DATA', t.body('StageStream.c', name))
        allocator = (ROOT / 'agente/SafeUpload.Agent.Service/Interception/StagedTransferAllocator.cs').read_text()
        self.assertIn('bool copyExisting = disposition is 1 or 3 && sourceExists;', allocator)
        self.assertIn('StagedBackingFile.CreateAsync(copyExisting ? source ?? fullDestination : null,', allocator)


if __name__ == '__main__':
    unittest.main()
