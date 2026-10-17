#!/usr/bin/env python3
"""Compile production native namespace pre/post plus shared folder controls.

Deterministic injected DDIs; no NTFS, WDK/PREfast, Windows access or VM claim.
Keep first failures under .scratch; mutations must fail real controls.
"""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('directories', HERE / 'test_directory_ux.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


def program(stream):
    policy = d.POLICY.read_text()
    names = ('StageNamespaceCaptureBindings', 'StageNamespaceRevalidateBindings', 'StageNamespaceBeginMutation',
             'StageDirectoryContains', 'StageDirectoryStreamPending', 'StageDirectoryPendingLocked',
             'StageDirectoryBeginMutation', 'StageDirectoryEndMutation', 'StageDirectoryPlainPath',
             'StageDirectoryPlainName', 'StageDirectoryCreateCanMutate', 'StageNameLookupProvesAbsent',
             'StageDirectoryCollisionComplete', 'StageAdmitDirectoryMutation', 'StageExistingDirectory',
             'StageNativeDirectoryInformation', 'StageExternalRename')
    helpers = ''.join(d.function(stream, name) for name in names)
    native = ''.join(d.function(stream, name) for name in (
        'StageMvpNamespaceOpen', 'StageMvpNamespaceCreateEligible', 'StageNamespacePostStatus',
        'StageMvpNamespaceCreateOpened', 'StageInstallRenameExchange', 'StageMvpRenameNeedsCopy', 'StageRenameAuthorizeReplacement',
        'StageMvpNamespacePre', 'StageMvpNamespacePostCreate', 'StageMvpNamespacePost'))
    types = stream[stream.index('typedef struct _STAGE_NAMESPACE_BINDINGS {'):stream.index(
        '_IRQL_requires_(PASSIVE_LEVEL)', stream.index('typedef struct _STAGE_NAMESPACE_BINDINGS {'))]
    policies = ''.join(d.function(policy, name) for name in (
        'SafeUploadPathUnderPrefix', 'SafeUploadPolicyDirectoryIsScopeAnchor'))
    admit = d.function(stream, 'StageAdmit')
    demotion = re.search(r'    if \(KeGetCurrentIrql\(\) == PASSIVE_LEVEL && disposition == FILE_OPEN &&\n.*?writer = FALSE;', admit, re.S)
    assert demotion, 'shared writer demotion'
    create = d.function(stream, 'StageCreate')
    a = create.index('    if (view == NULL && !Writer) {')
    b = create.index('    if (Name->Name.Length', a)
    fallback = create[a:b]
    fixture = (HERE / 'directory_ux_fixture.c').read_text()
    extra = (HERE / 'namespace_ux_fixture.c').read_text()
    globals_, rest = extra.split('/* GLOBALS */')[1].split('/* STUBS */')
    stubs, tests = rest.split('/* TESTS */')
    return (fixture.replace('/* PRODUCTION_NAMESPACE_TYPES */', types)
            .replace('/* PRODUCTION_POLICY */', policies).replace('/* PRODUCTION_DIRECTORY */', helpers)
            .replace('/* NATIVE_GLOBALS */', globals_).replace('/* NATIVE_STUBS */', stubs)
            .replace('/* NATIVE_PRODUCTION */', native).replace('/* NATIVE_TESTS */', tests)
            .replace('/* NATIVE_LOOKUP_HOOK */', 'if(LookupHook)LookupHook();')
            .replace('/* NATIVE_TEST_CALL */', 'namespace_tests();')
            .replace('/* PRODUCTION_DEMOTION */', demotion[0])
            .replace('/* PRODUCTION_PRIVATE_FALLBACK */', fallback))


def registry_program(source):
    fixture = (HERE / 'namespace_registry_fixture.c').read_text()
    production = ''.join(d.function(source, name) for name in (
        'StageRegistryNameHasPathPrefix', 'StageRegistryDirectoryRenameInFlightLocked', 'StageRegistryCompleteDirectoryRename',
        'SafeUploadStageWritersCompleteRename', 'StageRegistryRenameWorker', 'SafeUploadStageWritersNameActivating'))
    return fixture.replace('/* PRODUCTION */', production)


def run(source, compiler, registry=False):
    scratch = Path(os.environ.get('TMPDIR', ROOT / '.scratch'))
    scratch.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix='namespace-ux-', dir=scratch))
    (temp / 'fixture.c').write_text(registry_program(source) if registry else program(source))
    build = subprocess.run([compiler, '-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=undefined', '-fno-sanitize-recover=all',
                            str(temp / 'fixture.c'), '-o', str(temp / 'fixture')], capture_output=True, text=True)
    (temp / 'build.txt').write_text(build.stdout + build.stderr)
    if build.returncode:
        raise AssertionError(f'{temp}: {build.stderr[:12000]}')
    result = subprocess.run([str(temp / 'fixture')], cwd=temp, capture_output=True, text=True, timeout=30)
    (temp / 'run.txt').write_text(result.stdout + result.stderr)
    if result.returncode == 0:
        shutil.rmtree(temp)
    return result


class NamespaceUx(unittest.TestCase):
    def test_compiled_native_pre_post_and_races(self):
        for compiler in ('cc', 'clang'):
            with self.subTest(compiler=compiler):
                self.assertIsNotNone(shutil.which(compiler))
                result = run(d.STREAM.read_text(), compiler)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_security_mutations_fail(self):
        source = d.STREAM.read_text()
        mutations = (
            ('Slot->DirectorySequence == InterlockedCompareExchange64(&StageDirectorySequence, 0, 0)', 'TRUE'),
            ('!RtlEqualMemory(&objectIdentity, &Bindings->Source, sizeof(objectIdentity))', 'FALSE'),
            ('!RtlEqualUnicodeString(&current->Name, &Source->Name, TRUE)', 'FALSE'),
            ('!RtlEqualMemory(&current.Parent, &Bindings->Parent, sizeof(current.Parent))', 'FALSE'),
            ('StageMvpNamespaceCreateOpened(Data, Objects)) {\n        if (name != NULL', 'TRUE) {\n        if (name != NULL'),
            ('return NT_SUCCESS(Data->IoStatus.Status) && Data->IoStatus.Status != STATUS_REPARSE', 'return Data->IoStatus.Status == STATUS_SUCCESS && Data->IoStatus.Status != STATUS_REPARSE'),
            ('FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID | FILE_OPEN_REPARSE_POINT) &&', 'FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID) &&'),
            ('StageMvpNamespaceCreateEligible(Data, Objects)) writer = FALSE;', 'StageMvpNamespaceOpen(Data)) writer = FALSE;'),
            ('(MajorFunction == IRP_MJ_SET_INFORMATION && Mutation)', '((void)MajorFunction, FALSE && Mutation)'),
            ('status = SafeUploadStageCheckSubjectAccess(Data, Target->Security, DELETE);', 'status = STATUS_SUCCESS; (void)&SafeUploadStageCheckSubjectAccess; (void)Target;'),
            ('StageMvpNamespaceRegistryContext = registryRenameContext != NULL ? registryRenameContext : mutatingIoContext;', 'StageMvpNamespaceRegistryContext = NULL;'),
        )
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                result = run(source.replace(old, new), 'cc')
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_registry_completion_keeps_renamed_unknown_held(self):
        source = (HERE.parent / 'StageWriters.c').read_text()
        for compiler in ('cc', 'clang'):
            with self.subTest(compiler=compiler):
                result = run(source, compiler, registry=True)
                self.assertEqual(result.returncode, 0, result.stderr)
        for old, new in (
            ('RtlCopyMemory(entry->Name, rename->Name, rename->NameChars * sizeof(WCHAR));', '(void)0;'),
            ('if (Draining || (Succeeded && rename->Ambiguous)) {', 'if (FALSE) {'),
            ('InterlockedIncrement(&entry->RenameVersion);', '(void)&InterlockedIncrement;'),
            ('activating = StageRegistryDirectoryRenameInFlightLocked(Instance, &baseName);', 'activating = FALSE; (void)&StageRegistryDirectoryRenameInFlightLocked;'),
        ):
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                self.assertNotEqual(run(source.replace(old, new), 'cc', registry=True).returncode, 0)

    def test_shared_routing_and_synchronized_epoch_wiring(self):
        source = d.STREAM.read_text()
        admit = d.function(source, 'StageAdmit')
        native = d.function(source, 'StageMvpNamespacePre')
        self.assertIn('StageMvpNamespaceCreateEligible(Data, Objects)) writer = FALSE;', admit)
        self.assertIn('if (!StageMvpNamespaceCreateEligible(Data, Objects)) return result;', native)
        self.assertNotIn('StageMvpNamespaceOpen(Data)', admit[:admit.index('writer = FALSE;')])
        epoch = d.function(source, 'StageDispatchEpoch')
        self.assertIn('return StageNamespacePostStatus(Data->Iopb->MajorFunction, slot.DirectoryMutation, result);', epoch)
        self.assertLess(epoch.index('token->DirectoryMutation = slot.DirectoryMutation;'), epoch.index('return StageNamespacePostStatus('))

    def test_private_authority_precedes_cancel_and_retains_evidence(self):
        source = d.STREAM.read_text()
        rename = d.function(source, 'StageRename')
        first = rename.index('StageRenameAuthorizeReplacement(')
        cancel = rename.index('StageCancelSealedPrivate(')
        self.assertLess(rename.index('StageRenameShareAllowed('), first)
        self.assertLess(first, cancel)
        self.assertIn('if (!NT_SUCCESS(status)) goto Exit; /* No cancel', rename[first:cancel])
        self.assertIn('StageFindView(view->Owner, &destination->Name) != target', rename[first:cancel])
        second = rename.index('StageRenameAuthorizeReplacement(', cancel)
        release = rename.index('InterlockedDecrement(&targetStream->RpcReferences)', second)
        self.assertLess(second, release)
        self.assertIn('target->Current != targetStream', rename[second:release])
        cancel_body = d.function(source, 'StageCancelSealedPrivate')
        self.assertLess(cancel_body.index('Stream->ShareAccess.OpenCount == 0'), cancel_body.index('Stream->PrivateCancellationBusy = TRUE'))
        create = d.function(source, 'StageCreate')
        self.assertLess(create.index('view->Current->PrivateCancellationBusy'), create.index('IoUpdateShareAccess('))
        # The exact pinned descriptor stays reachable through post-RPC checks.
        self.assertGreater(rename.index('targetStream = NULL;', cancel), release)
        for name in ('StageNamespaceCaptureBindings', 'StageNamespaceRevalidateBindings',
                     'StageNamespaceBeginMutation', 'StageMvpNamespaceCreateEligible', 'StageMvpNamespacePre', 'StageMvpNamespacePostCreate',
                     'StageRenameAuthorizeReplacement'):
            fn = d.function(source, name)
            definition = source.index(fn)
            self.assertIn('#pragma alloc_text(PAGE, '+name+')', source[:definition])
            self.assertTrue(source[:definition].rstrip().endswith('_IRQL_requires_(PASSIVE_LEVEL)'))
            self.assertIn('PAGED_CODE();', fn)


if __name__ == '__main__':
    unittest.main()
