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
        'StageMvpReparseOpenTrack', 'StageMvpReparseOpenTake', 'StageMvpNamespaceOpen', 'StageMvpNamespaceReparseOpen',
        'StageMvpNamespaceCreateEligible', 'StageNamespacePostStatus', 'StageMvpRequireRegularObject',
        'StageMvpReparseOpenPre', 'StageMvpReparseOpenPost', 'StageMvpReparseOpenDispatchPost',
        'StageMvpNamespaceCreateOpened', 'StageInstallRenameExchange', 'StageMvpRenameNeedsCopy', 'StageRenameAuthorizeReplacement',
        'StageMvpNamespacePre', 'StageMvpNamespacePostCreate', 'StageMvpNamespacePost'))
    types = stream[stream.index('typedef struct _STAGE_NAMESPACE_BINDINGS {'):stream.index(
        '_IRQL_requires_(PASSIVE_LEVEL)', stream.index('typedef struct _STAGE_NAMESPACE_BINDINGS {'))]
    policies = ''.join(d.function(policy, name) for name in (
        'SafeUploadPathUnderPrefix', 'SafeUploadPolicyDirectoryIsScopeAnchor'))
    admit = d.function(stream, 'StageAdmit')
    demotion = re.search(r'    if \(KeGetCurrentIrql\(\) == PASSIVE_LEVEL && disposition == FILE_OPEN &&\n.*?writer = FALSE;', admit, re.S)
    assert demotion, 'shared writer demotion'
    readmit = admit[admit.index('Readmit:\n') + len('Readmit:\n'):]
    readmit = readmit[:readmit.index('    if (!service) {')]
    create = d.function(stream, 'StageCreate')
    a = create.index('    if (view == NULL && !Writer) {')
    b = create.index('    if (Name->Name.Length', a)
    fallback = create[a:b]
    fixture = (HERE / 'directory_ux_fixture.c').read_text()
    extra = (HERE / 'namespace_ux_fixture.c').read_text()
    globals_, rest = extra.split('/* GLOBALS */')[1].split('/* STUBS */')
    first = stream.index('typedef struct _STAGE_MVP_REPARSE_OPEN {')
    last = stream.index('static LIST_ENTRY StageMvpReparseOpens;', first) + len('static LIST_ENTRY StageMvpReparseOpens;')
    globals_ = stream[first:last] + '\n' + globals_
    stubs, tests = rest.split('/* TESTS */')
    return (fixture.replace('/* PRODUCTION_NAMESPACE_TYPES */', types)
            .replace('/* PRODUCTION_POLICY */', policies).replace('/* PRODUCTION_DIRECTORY */', helpers)
            .replace('/* NATIVE_GLOBALS */', globals_).replace('/* NATIVE_STUBS */', stubs)
            .replace('/* NATIVE_PRODUCTION */', native).replace('/* NATIVE_TESTS */', tests)
            .replace('/* NATIVE_LOOKUP_HOOK */', 'if(LookupHook)LookupHook();')
            .replace('/* NATIVE_TEST_CALL */', 'namespace_tests();')
            .replace('/* PRODUCTION_DEMOTION */', demotion[0])
            .replace('/* PRODUCTION_READMISSION */', readmit)
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
            # D7: every OPEN_REPARSE_POINT open other than a D7 request (DOC included) stays excluded.
            ('(!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_REPARSE_POINT) || StageMvpNamespaceReparseOpen(Data)) &&', 'TRUE &&'),
            ('!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE) &&\n        !FlagOn(security->DesiredAccess, FILE_DELETE_CHILD) &&', '!FlagOn(security->DesiredAccess, FILE_DELETE_CHILD) &&'),
            ('!FlagOn(security->DesiredAccess, FILE_DELETE_CHILD) &&\n        FlagOn(security->DesiredAccess, DELETE | FILE_WRITE_ATTRIBUTES);', 'FlagOn(security->DesiredAccess, DELETE | FILE_WRITE_ATTRIBUTES);'),
            # D7 pre: unload recheck, refusals of declines, absent-name zero identity.
            ('if (reparseOpen && (InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||', 'if (FALSE && (InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||'),
            ('if (reparseOpen) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; } /* D7 late decline */', '/* D7 late decline */'),
            ('StageMvpReparseOpenTake(CompletionContext) : NULL;\n    if (open == NULL) return FALSE;', 'StageMvpReparseOpenTake(CompletionContext) : NULL;\n    if (open != NULL) { open->Link.Flink = NULL; ExFreePoolWithTag(open, STAGE_TAG); } return FALSE;'),
            ('if (reparseOpen) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; }\n        goto Exit;', 'goto Exit;'),
            ('if (source->Stream.Length != 0) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; } /* D7 */', '/* D7 */'),
            ('if (!StageNameLookupProvesAbsent(status)) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; }', 'if (FALSE) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; }'),
            ('RtlZeroMemory(&identity, sizeof(identity));\n        }', 'identity.FileId = 1; identity.VolumeSerialNumber = 1;\n        }'),
            # D7 post: every outcome class and both object checks.
            ('if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) goto Free;', 'if (FALSE) goto Free;'),
            ('if (status == STATUS_PENDING) goto Deny; /* not a completed outcome */', '/* pending */'),
            ('if (Data->IoStatus.Information != FILE_OPENED) goto Cancel;', 'if (FALSE) goto Cancel;'),
            ('if (file == NULL || file->FsContext == NULL) goto Deny;', 'if (file == NULL) goto Deny;'),
            ('if (!NT_SUCCESS(StageMvpRequireRegularObject(Objects->Instance, file))) goto Cancel;', '(void)&StageMvpRequireRegularObject;'),
            ('!RtlEqualMemory(&identity, &Open->Identity, sizeof(identity))) goto Cancel; /* substituted object */', 'FALSE) goto Cancel; /* substituted object */'),
            ('if (!NT_SUCCESS(status) || returned != sizeof(tag) || FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT))', 'if (!NT_SUCCESS(status) || FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT))'),
            # D7 SET: the regular-object check precedes cancellation.
            ('status = StageMvpRequireRegularObject(Objects->Instance, file);\n        if (!NT_SUCCESS(status)) goto Refuse;', 'status = STATUS_SUCCESS;'),
            ('StageMvpNamespaceCreateEligible(Data, Objects)) writer = FALSE;', 'StageMvpNamespaceOpen(Data)) writer = FALSE;'),
            ('!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE) &&\n        StageMvpNamespaceCreateEligible', 'StageMvpNamespaceCreateEligible'),
            ('writer = requestedWriter;', '(void)requestedWriter;'),
            ('if (mutation && !StageNameLookupProvesAbsent(status)) {', 'if (FALSE) {'),
            ('(MajorFunction == IRP_MJ_SET_INFORMATION && Mutation)', '((void)MajorFunction, FALSE && Mutation)'),
            ('status = SafeUploadStageCheckSubjectAccess(Data, Target->Security, DELETE);', 'status = STATUS_SUCCESS; (void)&SafeUploadStageCheckSubjectAccess; (void)Target;'),
            ('StageMvpNamespaceRegistryContext = registryRenameContext != NULL ? registryRenameContext : mutatingIoContext;', 'StageMvpNamespaceRegistryContext = NULL;'),
        )
        receipts = []
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                result = run(source.replace(old, new), 'cc')
                killed = [line for line in result.stderr.splitlines() if 'Assertion' in line or 'runtime error' in line]
                receipts.append({'mutation': old.splitlines()[0][:120], 'returncode': result.returncode,
                                 'killed_by': killed[-1][-220:] if killed else result.stderr.strip()[-220:]})
                self.assertNotEqual(result.returncode, 0, result.stdout)
        # Per-mutant receipt: which assertion killed each mutant (build failures raise in run() and never count).
        receipt = Path(os.environ.get('TMPDIR', ROOT / '.scratch')) / 'namespace-ux-mutants.json'
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(__import__('json').dumps(receipts, indent=1))

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
        self.assertIn('writer = requestedWriter;', admit[admit.index('Readmit:'):])
        self.assertNotIn('StageMvpNamespaceOpen(Data)', admit)
        dispatch = d.function(source, 'StageDispatchCore')
        guard = dispatch.index('if (nativeMutationRequired) return StageCompleteAccessDenied(Data);')
        self.assertLess(guard, dispatch.index('result = SafeUploadPreCreate(Data, Objects, &legacyCompletionContext);'))
        self.assertLess(dispatch.index('&nativeMutationRequired);'), guard)
        self.assertIn('if (!StageMvpNamespaceCreateEligible(Data, Objects)) return result;', native)
        self.assertNotIn('StageMvpNamespaceOpen(Data)', admit[:admit.index('writer = FALSE;')])
        epoch = d.function(source, 'StageDispatchEpoch')
        self.assertIn('return StageNamespacePostStatus(Data->Iopb->MajorFunction, slot.DirectoryMutation, result);', epoch)
        self.assertLess(epoch.index('token->DirectoryMutation = slot.DirectoryMutation;'), epoch.index('return StageNamespacePostStatus('))

    def test_d7_integration_wiring(self):
        source = d.STREAM.read_text()
        admit = d.function(source, 'StageAdmit')
        start = admit.index('*NativeMutationRequired = !service &&')
        obligation = admit[start:admit.index(';', start)]
        # A D7 request keeps the DOC refusal obligation until native, private or outside-scope handling owns it.
        self.assertIn('StageMvpNamespaceReparseOpen(Data)', obligation)
        self.assertIn('FILE_DELETE_ON_CLOSE', obligation)
        dispatch = d.function(source, 'StageDispatchCore')
        self.assertLess(dispatch.index('if (nativeMutationRequired) return StageCompleteAccessDenied(Data);'),
                        dispatch.index('result = SafeUploadPreCreate(Data, Objects, &legacyCompletionContext);'))
        core = source[source.index('static FLT_POSTOP_CALLBACK_STATUS StagePostOperationCore('):]
        create = core[core.index('if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {'):]
        self.assertLess(create.index('StageMvpReparseOpenDispatchPost(Data, Objects, CompletionContext, Flags)'),
                        create.index('SafeUploadStageNativePostCreate(Data, Objects, CompletionContext, Flags)'))
        post = source[source.index('FLT_POSTOP_CALLBACK_STATUS SafeUploadStagePostOperation(PFLT_CALLBACK_DATA Data,'):]
        inner = post.index('result = StagePostOperationCore(Data, Objects, token->InnerCompletionContext, Flags);')
        self.assertLess(inner, post.index('SafeUploadPolicyAdmissionRelease(token);\n            return result;'))
        epoch = d.function(source, 'StageDispatchEpoch')
        self.assertLess(epoch.index('status = SafeUploadPolicyAdmissionAcquire(&token);'),
                        epoch.index('result = StageDispatchCore(Data, Objects, &innerContext, &slot);'))
        unload = d.function(source, 'SafeUploadStagePrepareUnload')
        self.assertLess(unload.index('StageSetUnloadAdmissionClosed(TRUE);'), unload.index('SafeUploadPolicyPublicationQuiescent()'))
        native = d.function(source, 'StageMvpNamespacePre')
        recheck = native.index('if (reparseOpen && (InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||')
        self.assertLess(recheck, native.index('FltGetFileNameInformation(Data,'))
        self.assertLess(recheck, native.index('SafeUploadStageQueryIdentity('))
        self.assertNotIn('StageUnloadAdmissionClosed', d.function(source, 'StageMvpReparseOpenPre'))

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
