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
    writers = (HERE.parent / 'StageWriters.c').read_text()
    classifier = ''.join(d.function(writers, name) for name in ('StageWriterCreateCanMutate', 'SafeUploadStageWritersWantPostCreate'))
    native = classifier + ''.join(d.function(stream, name) for name in (
        'StageMvpReparseOpenTrack', 'StageMvpReparseOpenTake', 'StageMvpNamespaceOpen', 'StageMvpNamespaceReparseOpen',
        'StageMvpNamespaceCreateEligible', 'StageNamespacePostStatus', 'StageMvpRequireRegularObject',
        'StageMvpWriterReserve', 'StageMvpWriterPost', 'StageMvpReparseOpenPre', 'StageMvpReparseOpenPost',
        'StageMvpReparseOpenDispatchPost',
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
            ('!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE) &&\n        /* The same parameter-level exclusions', '/* The same parameter-level exclusions'),
            ('!FlagOn(security->DesiredAccess, FILE_DELETE_CHILD) &&\n        FlagOn(security->DesiredAccess, DELETE | FILE_WRITE_ATTRIBUTES);', 'FlagOn(security->DesiredAccess, DELETE | FILE_WRITE_ATTRIBUTES);'),
            ('!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID) &&\n        !FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY) &&\n        !FlagOn(security->DesiredAccess, FILE_DELETE_CHILD)', '!FlagOn(security->DesiredAccess, FILE_DELETE_CHILD)'),
            # D7 pre: unload recheck, refusals of declines, absent-name zero identity.
            ('if ((reparseOpen || writerCreate) && (InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||', 'if (FALSE && (InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||'),
            ('if ((reparseOpen || writerCreate) && (InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||', 'if (reparseOpen && (InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||'),
            ('if (reparseOpen) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; } /* D7 late decline */', '/* D7 late decline */'),
            ('StageMvpReparseOpenTake(CompletionContext) : NULL;\n    if (open == NULL) return FALSE;', 'StageMvpReparseOpenTake(CompletionContext) : NULL;\n    if (open != NULL) { open->Link.Flink = NULL; ExFreePoolWithTag(open, STAGE_TAG); } return FALSE;'),
            ('if (reparseOpen) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; }\n        goto Exit;', 'goto Exit;'),
            ('if (source->Stream.Length != 0) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; } /* D7 */', '/* D7 */'),
            ('if (!StageNameLookupProvesAbsent(status)) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; }', 'if (FALSE) { *Handled = TRUE; status = STATUS_ACCESS_DENIED; goto Refuse; }'),
            ('RtlZeroMemory(&identity, sizeof(identity));\n        }', 'identity.FileId = 1; identity.VolumeSerialNumber = 1;\n        }'),
            # D7 post: every outcome class and both object checks.
            ('if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) { legacyPost = FALSE; goto Registry; }', 'if (FALSE) goto Registry;'),
            ('if (status == STATUS_PENDING) goto Deny; /* not a completed outcome */', '/* pending */'),
            ('if (Data->IoStatus.Information != FILE_OPENED) goto Cancel;', 'if (FALSE) goto Cancel;'),
            ('if (file == NULL || file->FsContext == NULL) goto Deny;', 'if (file == NULL) goto Deny;'),
            ('if (!NT_SUCCESS(StageMvpRequireRegularObject(Objects->Instance, file))) goto Cancel;', '(void)&StageMvpRequireRegularObject;'),
            ('!RtlEqualMemory(&identity, &Open->Identity, sizeof(identity))) goto Cancel; /* substituted object */', 'FALSE) goto Cancel; /* substituted object */'),
            ('if (!NT_SUCCESS(status) || returned != sizeof(tag) || FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT))', 'if (!NT_SUCCESS(status) || FlagOn(tag.FileAttributes, FILE_ATTRIBUTE_REPARSE_POINT))'),
            # D7 SET: the regular-object check precedes cancellation.
            ('status = StageMvpRequireRegularObject(Objects->Instance, file);\n        if (!NT_SUCCESS(status)) goto Refuse;', 'status = STATUS_SUCCESS;'),
            # D7 rev 4: native-route writers take the writer-registry reservation and the registry post consumes it.
            ('open->WriterReservation = StageMvpWriterReserve(Data, Objects);', 'open->WriterReservation = NULL;'),
            ('open->WriterReservation = StageMvpWriterReserve(Data, Objects);', 'open->WriterReservation = StageMvpWriterReserve(Data, Objects); (VOID)StageMvpWriterReserve(Data, Objects);'),
            ('legacy = SafeUploadPreCreate(Data, Objects, &open->LegacyContext);\n    if (legacy == FLT_PREOP_COMPLETE) {', '(VOID)StageMvpWriterReserve(Data, Objects);\n    legacy = SafeUploadPreCreate(Data, Objects, &open->LegacyContext);\n    if (legacy == FLT_PREOP_COMPLETE) {'),
            ('(VOID)SafeUploadStageWritersPostCreate(Data, Objects, Flags, Reservation, NULL, NULL);', '(VOID)Data; (VOID)Objects; (VOID)Flags; (VOID)&SafeUploadStageWritersPostCreate;'),
            ('if (Reservation == NULL) return;\n    (VOID)SafeUploadStageWritersPostCreate(Data, Objects, Flags, Reservation, NULL, NULL);', '(VOID)SafeUploadStageWritersPostCreate(Data, Objects, Flags, Reservation, NULL, NULL);'),
            ('Registry:\n    StageMvpWriterPost(Data, Objects, Flags, reservation);', 'Registry:\n    (VOID)reservation;'),
            # registry post BEFORE the legacy post / before the deny status: the cancelled-after-registered defect.
            ('Legacy:\n    /* A legacy-post denial cancels the open itself; D7 cancels nothing further. */\n    if (legacyPost && Open->LegacyCallback)', 'Legacy:\n    StageMvpWriterPost(Data, Objects, Flags, reservation); reservation = NULL;\n    if (legacyPost && Open->LegacyCallback)'),
            ('Deny:\n    Data->IoStatus.Status = STATUS_ACCESS_DENIED;\n    Data->IoStatus.Information = 0;\n    legacyPost = FALSE;\nLegacy:', 'Deny:\n    StageMvpWriterPost(Data, Objects, Flags, reservation); reservation = NULL;\n    Data->IoStatus.Status = STATUS_ACCESS_DENIED;\n    Data->IoStatus.Information = 0;\n    legacyPost = FALSE;\nLegacy:'),
            ('    legacyPost = FALSE;\nLegacy:', '    legacyPost = TRUE;\nLegacy:'),
            ('if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) { legacyPost = FALSE; goto Registry; }', 'if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) { legacyPost = FALSE; reservation = NULL; goto Registry; }'),
            ('if (!Open->Reparse) goto Legacy; /* D1 writer open: no D7 object validation */', '/* D1 validated like D7 */'),
            ('open->Reparse = Reparse;', '(VOID)Reparse; open->Reparse = TRUE;'),
            ('writerCreate = SafeUploadStageWritersWantPostCreate(Data);', 'writerCreate = FALSE;'),
            ('result = reparseOpen || writerCreate ?', 'result = reparseOpen ?'),
            ('if (reservation != NULL) SafeUploadStageWritersCancelReservation(reservation);\n        SafeUploadStageWritersTrackingLost(Objects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);\n        return NULL;', '(VOID)&SafeUploadStageWritersCancelReservation;\n        SafeUploadStageWritersTrackingLost(Objects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);\n        return NULL;'),
            ('if (required && reservation == NULL)\n        SafeUploadStageWritersTrackingLost(Objects->Instance, SAFEUPLOAD_REGISTRY_UNKNOWN_ALLOCATION);\n    return reservation;', 'return reservation;'),
            ('StageMvpNamespaceCreateReservation = StageMvpWriterReserve(Data, Objects);', '(VOID)StageMvpWriterReserve(Data, Objects);'),
            ('StageMvpNamespaceCreateReservation = NULL;\n    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {', 'if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {'),
            ('    StageMvpWriterPost(Data, Objects, Flags, WriterReservation);\n    if (name != NULL) FltReleaseFileNameInformation(name);', '    (VOID)WriterReservation;\n    if (name != NULL) FltReleaseFileNameInformation(name);'),
            # DOC: registry post before the legacy post and the identity/cancellation steps registers an open this filter later cancels.
            ('    if (LegacyCallback) (VOID)SafeUploadPostCreate(Data, Objects, LegacyContext, Flags);\n', '    StageMvpWriterPost(Data, Objects, Flags, WriterReservation); WriterReservation = NULL;\n    if (LegacyCallback) (VOID)SafeUploadPostCreate(Data, Objects, LegacyContext, Flags);\n'),
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
        recheck = native.index('if ((reparseOpen || writerCreate) && (InterlockedCompareExchange(&StageUnloadAdmissionClosed, 0, 0) != 0 ||')
        self.assertLess(recheck, native.index('FltGetFileNameInformation(Data,'))
        self.assertLess(recheck, native.index('SafeUploadStageQueryIdentity('))
        self.assertNotIn('StageUnloadAdmissionClosed', d.function(source, 'StageMvpReparseOpenPre'))

    def test_d7_rev4_writer_registry_wiring(self):
        source = d.STREAM.read_text()
        pre = d.function(source, 'StageMvpReparseOpenPre')
        # The reservation follows the legacy pre (a legacy COMPLETE reserves nothing) and precedes publication of the context.
        self.assertLess(pre.index('SafeUploadPreCreate(Data, Objects, &open->LegacyContext)'),
                        pre.index('open->WriterReservation = StageMvpWriterReserve(Data, Objects);'))
        self.assertLess(pre.index('open->WriterReservation = StageMvpWriterReserve(Data, Objects);'),
                        pre.index('StageMvpReparseOpenTrack(open);'))
        native = d.function(source, 'StageMvpNamespacePre')
        legacy = native.index('result = SafeUploadPreCreate(Data, Objects, &legacyContext);')
        reserve = native.index('StageMvpNamespaceCreateReservation = StageMvpWriterReserve(Data, Objects);')
        self.assertLess(legacy, reserve)
        # Nothing between the DOC reservation and the returned callback can refuse the CREATE.
        tail = native[reserve:native.index('goto Exit;', reserve)]
        self.assertNotIn('goto Refuse', tail)
        self.assertNotIn('return', tail)
        # D7 refusals set the failure status, then the legacy post, then the registry post last with the final status.
        post = d.function(source, 'StageMvpReparseOpenPost')
        deny = post.index('Data->IoStatus.Status = STATUS_ACCESS_DENIED;')
        legacy_post = post.index('SafeUploadPostCreate(Data, Objects, Open->LegacyContext, Flags)')
        registry_post = post.index('StageMvpWriterPost(Data, Objects, Flags, reservation)')
        self.assertLess(deny, legacy_post)
        self.assertLess(legacy_post, registry_post)
        self.assertLess(post.index('FltCancelFileOpen(Objects->Instance, file)'), registry_post)
        # Fenced DOC: legacy post, identity validation and the single pending-version cancellation, then the registry post last.
        doc = d.function(source, 'StageMvpNamespacePostCreate')
        legacy_doc = doc.index('SafeUploadPostCreate(Data, Objects, LegacyContext, Flags)')
        cancel_names = doc.index('StageMvpCancelNames(Objects->Instance, &name->Name, NULL, TRUE, NULL)')
        cancel_open = doc.index('FltCancelFileOpen(Objects->Instance, Objects->FileObject)')
        registry_doc = doc.index('StageMvpWriterPost(Data, Objects, Flags, WriterReservation)')
        self.assertLess(legacy_doc, cancel_names)
        self.assertLess(cancel_names, registry_doc)
        self.assertLess(cancel_open, registry_doc)
        self.assertEqual(doc.count('StageMvpWriterPost('), 1)
        self.assertEqual(post.count('StageMvpWriterPost('), 1)
        # The registry post is called only with a reservation and the registry is never given an alias proof here.
        writer_post = d.function(source, 'StageMvpWriterPost')
        self.assertLess(writer_post.index('if (Reservation == NULL) return;'), writer_post.index('SafeUploadStageWritersPostCreate('))
        self.assertIn('&required, NULL)', d.function(source, 'StageMvpWriterReserve'))
        for name in ('StageMvpWriterReserve', 'StageMvpWriterPost'):
            self.assertIn('#pragma alloc_text(PAGE, ' + name + ')', source)
            self.assertIn('PAGED_CODE();', d.function(source, name))

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
