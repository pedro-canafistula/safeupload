#!/usr/bin/env python3
"""Host compilation of production directory decisions with injectable OS edges.

Not WDK/PREfast, native Windows or protected-pair qualification. Scratch stays
under .scratch (or an explicitly supplied TMPDIR). No VM/network access.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
STREAM = HERE.parent / 'StageStream.c'
POLICY = HERE.parent / 'Policy.c'


def function(source, name):
    match = re.search(r'(?m)^(?:__declspec\(noinline\)\s+)?(?:static\s+)?(?:BOOLEAN|VOID|NTSTATUS|FLT_PREOP_CALLBACK_STATUS)\s+' +
                      re.escape(name) + r'\s*\([^;]*?\)\s*\{', source)
    assert match, name
    end = source.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end] + '\n'


class DirectoryUx(unittest.TestCase):
    def test_compiled_production_directory_cases(self):
        stream, policy = STREAM.read_text(), POLICY.read_text()
        helpers = ''.join(function(stream, name) for name in (
            'StageNamespaceCaptureBindings', 'StageNamespaceRevalidateBindings', 'StageNamespaceBeginMutation',
            'StageDirectoryContains', 'StageDirectoryStreamPending', 'StageDirectoryPendingLocked',
            'StageDirectoryBeginMutation', 'StageDirectoryEndMutation', 'StageDirectoryPlainPath',
            'StageDirectoryPlainName', 'StageDirectoryCreateCanMutate', 'StageNameLookupProvesAbsent',
            'StageDirectoryCollisionComplete', 'StageAdmitDirectoryMutation', 'StageExistingDirectory', 'StageNativeDirectoryInformation',
            'StageExternalRename'))
        policies = ''.join(function(policy, name) for name in (
            'SafeUploadPathUnderPrefix', 'SafeUploadPolicyDirectoryIsScopeAnchor'))
        fixture = (HERE / 'directory_ux_fixture.c').read_text()
        types = stream[stream.index('typedef struct _STAGE_NAMESPACE_BINDINGS {'):stream.index('_IRQL_requires_(PASSIVE_LEVEL)', stream.index('typedef struct _STAGE_NAMESPACE_BINDINGS {'))]
        source = fixture.replace('/* PRODUCTION_NAMESPACE_TYPES */', types).replace('/* PRODUCTION_POLICY */', policies).replace('/* PRODUCTION_DIRECTORY */', helpers)
        scratch = Path(os.environ.get('TMPDIR', ROOT / '.scratch'))
        scratch.mkdir(parents=True, exist_ok=True)
        compilers = list(dict.fromkeys(filter(None, (shutil.which(os.environ.get('CC', 'cc')), shutil.which('clang')))))
        self.assertTrue(compilers, 'a C compiler is required')
        with tempfile.TemporaryDirectory(prefix='directory-ux-', dir=scratch) as temp:
            cfile, binary = Path(temp) / 'directory.c', Path(temp) / 'directory'
            cfile.write_text(source)
            for compiler in compilers:
                with self.subTest(compiler=compiler):
                    subprocess.run([compiler, '-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror',
                                    '-fsanitize=undefined', '-fno-sanitize-recover=all', str(cfile), '-o', str(binary)], check=True)
                    subprocess.run([str(binary)], check=True, timeout=30)

    def test_staging_and_completion_fence_wiring(self):
        source = STREAM.read_text()
        create = function(source, 'StageCreate')
        self.assertLess(create.index('StageDirectoryMutationActive'), create.index('StageFindPrivateDeleteReservation('))
        self.assertIn('transaction->DirectorySequence !=', create)
        queue = function(source, 'StageAttachQueueCreate')
        self.assertIn('transaction->DirectorySequence = AdmissionSlot->DirectorySequence;', queue)
        rename = function(source, 'StageRename')
        self.assertLess(rename.index('StageDirectoryMutationActive'), rename.index('FltGetDestinationFileNameInformation('))
        dispatch = function(source, 'StageDispatchEpoch')
        self.assertLess(dispatch.index('slot.DirectorySequence ='), dispatch.index('StageDispatchCore('))
        self.assertIn('token->DirectoryMutation = slot.DirectoryMutation;', dispatch)
        self.assertIn('if (slot.DirectoryMutation) StageDirectoryEndMutation(FALSE);', dispatch)
        post = STREAM.read_text()[STREAM.read_text().index('FLT_POSTOP_CALLBACK_STATUS SafeUploadStagePostOperation('):]
        self.assertIn('if (token->DirectoryMutation)', post)
        self.assertIn('StageDirectoryEndMutation(FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))', post)
        admit = function(source, 'StageAdmit')
        self.assertIn('StageExistingDirectory(Data, Objects, name)', admit)
        self.assertIn('StageAttachQueueCreate(Data, Objects, name', admit)
        self.assertIn('SafeUploadStageProtectedName(name, kind)', admit)
        # All new paged decision helpers remain annotated and placed in PAGE.
        for name in ('StageNamespaceCaptureBindings', 'StageNamespaceRevalidateBindings', 'StageNamespaceBeginMutation',
            'StageDirectoryContains', 'StageDirectoryStreamPending', 'StageDirectoryPendingLocked',
                     'StageDirectoryBeginMutation', 'StageDirectoryPlainPath', 'StageDirectoryPlainName',
                     'StageDirectoryCollisionComplete', 'StageAdmitDirectoryMutation', 'StageExistingDirectory', 'StageNativeDirectoryInformation'):
            self.assertIn('PAGED_CODE();', function(source, name))
            self.assertIn('#pragma alloc_text(PAGE, ' + name + ')', source)
        self.assertNotIn('PAGED_CODE', function(source, 'StageDirectoryEndMutation'))


if __name__ == '__main__':
    unittest.main()
