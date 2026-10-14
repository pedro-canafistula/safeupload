#!/usr/bin/env python3
"""Source-only exact rename ACK contract plus negative mutations; no build/VM.

boot13: occupied-name rename committed a journal generation that the kernel
never adopted. Controls inspect production source, and reject deleted tuple
checks, fence release before adoption, a local increment, and changed aborts.
"""
from pathlib import Path
import importlib.util
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('retry_contract', Path(__file__).with_name('reconcile-retry-selfcheck.py'))
retry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retry)
body, code = retry.body, retry.code
STREAM = ROOT / 'driver/SafeUpload.Minifilter/StageStream.c'
PROTOCOL = ROOT / 'driver/SafeUpload.Minifilter/StageProtocol.c'
AGENT = ROOT / 'agente/SafeUpload.Agent.Service/Interception/StagedTransferJournal.cs'
STAGE_FILE = ROOT / 'agente/SafeUpload.Agent.Service/Interception/StagedStageFile.cs'
MINIFILTER_PROJECT = ROOT / 'agente/SafeUpload.Agent.Minifilter/SafeUpload.Agent.Minifilter.csproj'
ATTACHMENT_TESTS = ROOT / 'agente/SafeUpload.Agent.Tests/StagedAttachmentV20Tests.cs'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def adoption_contract(source):
    apply = body(source, 'StageApplyRenameReply')
    adopt = 'Stream->DestinationGeneration = Exchange->RenameDestinationGeneration;'
    require(apply.count(adopt) == 1, 'only an exact receipt may assign generation')
    require(apply.index(adopt) < apply.index('Stream->RenameExchange = NULL;'), 'adopt before fence release')
    require(len(re.findall(r'Stream->DestinationGeneration\s*(?:=|\+\+|\+=)', apply)) == 1,
            'abort must never change generation')
    require(apply.index('if (Exchange->Request.Operation == SAFEUPLOAD_OPERATION_STAGE_RENAME_COMMIT) {') < apply.index(adopt),
            'commit-only adoption')
    for check in ('!Stream->Listed', 'source->RequestId != Exchange->Request.RequestId',
                  'source->Operation != Exchange->Request.Operation',
                  'source->OwnerProcessId != Stream->View->OwnerProcessId',
                  'source->ViewGeneration != (UINT64)Stream->View->Generation',
                  'source->SourceGeneration != Stream->DestinationGeneration',
                  '&source->TransferId, &Stream->TransferId', '&source->StageIdentity, &Stream->StageIdentity',
                  '&source->DriverInstanceId, &Stream->DriverInstanceId',
                  '&Stream->DriverInstanceId, &StageDriverInstanceId',
                  '&source->ParentDirectoryIdentity, &Stream->AllocationParentDirectoryIdentity',
                  '!Exchange->RenameReceiptValid', 'Exchange->RenameAck.RequestId != source->RequestId',
                  'Exchange->RenameAck.SourceGeneration != source->SourceGeneration',
                  'Exchange->RenameAck.OwnerProcessId != source->OwnerProcessId',
                  'Exchange->RenameAck.ViewGeneration != source->ViewGeneration',
                  '&Exchange->RenameAck.TransferId, &source->TransferId',
                  '&Exchange->RenameAck.StageIdentity, &source->StageIdentity',
                  '&Exchange->RenameAck.DriverInstanceId, &source->DriverInstanceId',
                  '&Exchange->RenameAck.ParentDirectoryIdentity, &source->ParentDirectoryIdentity',
                  'Stream->Name.Length != Exchange->Request.PathLength',
                  'Stream->Name.Buffer, Exchange->Request.Path, Stream->Name.Length'):
        require(check in apply[:apply.index(adopt)], 'missing ACK authority: ' + check)
    require('Stream->RenameWait = STAGE_WAIT_SERVICE;' in apply, 'bad ACK must park')
    require('Stream->RenameWait = StageWaitFor(Status);' in apply, 'transport outcome classification')
    require(not re.search(r'RenameDestinationGeneration\s*[<>]=?\s*.*DestinationGeneration', apply),
            'generations belong to independent names')
    process = body(source, 'StageProcessStream')
    require(process.index('Stream->RenameExchange != NULL') < process.index('Stream->HandleReceiptPending'),
            'resolve rename before op19')
    for name in ('StageCollectHandleReceiptRpcs', 'StageCollectSealRpcs'):
        require('stream->RpcGenerationSnapshot = stream->DestinationGeneration;' in body(source, name),
                'op19/seal must use adopted current generation')
    perform = body(source, 'StagePerformRenameRpcs')
    for check in ('stream->RenameExchange == exchange', 'stream->View->Generation == stream->RpcViewGenerationSnapshot',
                  'stream->DestinationGeneration == stream->RpcGenerationSnapshot',
                  '&stream->DriverInstanceId, &StageDriverInstanceId'):
        require(check in perform[:perform.index('StageApplyRenameReply(')], 'missing local RPC revalidation')


def wire_contract(source):
    read = body(source, 'StageProtocolReadRenameReplyV20')
    for check in ('Exchange->ReplyLength != sizeof(*outer)', 'outer->StructSize != sizeof(*outer)',
                  'outer->RequestId != Exchange->Request.RequestId', 'outer->Verdict != SAFEUPLOAD_VERDICT_ALLOW',
                  'outer->PayloadLength != sizeof(*reply)', 'reply->Source.Version != SAFEUPLOAD_STAGE_EXTENSION_VERSION',
                  'reply->Source.StructSize != sizeof(*reply)', 'reply->Reserved != 0',
                  'reply->DestinationNameLength != Exchange->Request.PathLength',
                  'reply->DestinationName, Exchange->Request.Path, reply->DestinationNameLength',
                  'StageProtocolBytesZero(', '!RtlEqualMemory(&source, &expected, sizeof(source))',
                  'reply->Source.Result != SAFEUPLOAD_STAGE_RESULT_RENAME_COMMITTED',
                  'reply->DestinationGeneration == 0', 'reply->DestinationGeneration > MAXLONGLONG'):
        require(check in read[:read.index('Exchange->RenameReceiptValid = TRUE;')], 'missing wire validation: ' + check)
    require('return STATUS_DEVICE_BUSY;' in read, 'typed transient failure must remain EXCHANGE eligible')
    send = body(source, 'SafeUploadStageRenameExchangeV19')
    require('StageSendV19Exchange(' in send, 'renames require authenticated channel revalidation')
    require('STATUS_INVALID_BUFFER_SIZE : SafeUploadStageExchangeResult(status, answered, verdict)' in send,
            'outer wire faults must not become legacy timeouts')
    attach = body(source, 'SafeUploadStageAttachmentExchangeV20')
    require('Operation == SAFEUPLOAD_OPERATION_STAGE_ATTACH_HANDLE_OBSERVED &&' in attach and
            'STATUS_INVALID_BUFFER_SIZE : SafeUploadStageExchangeResult(status, answered, verdict)' in attach,
            'op19 must preserve outer wire fault parking')
    require('ExFreePoolWithTag(Exchange->RenameReply, SAFEUPLOAD_POOL_TAG);' in send and
            'Exchange->RenameReply = NULL;' in send, 'commit buffer freed on every result')


def structural_refusal_contract(source):
    for name in ('ReadAttachedMetadata', 'OpenWindows'):
        require(re.search(r'if \(\(basic.Attributes & \(AttributeDirectory \| AttributeReparsePoint\)\) != 0 \|\| basic.LinkCount != 1\)\s*'
                          r'throw StagedRequestRefusal.Create\(', body(source, name)),
                name + ' must distinguish structural refusal from native IO failure')
    require(re.search(r'FileAttributes.ReparsePoint\) != 0\)\s*throw StagedRequestRefusal.Create\(',
                      body(source, 'ReadDirectoryIdentity')), 'parent reparse must park')
    require(re.search(r'if \(\(basic.Attributes & AttributeDirectory\) == 0 \|\| \(basic.Attributes & AttributeReparsePoint\) != 0\)\s*'
                      r'throw StagedRequestRefusal.Create\(', body(source, 'ReadWindowsDirectoryIdentity')),
            'parent handle structural check must park even after the pathname scan')
    require(re.search(r'FileAttributes.ReparsePoint\)\) != 0\)\s*throw StagedRequestRefusal.Create\(',
                      body(source, 'OpenPortable')), 'portable structural refusal must also park')
    for name in ('ReadAttachedMetadata', 'OpenWindows', 'ReadWindowsDirectoryIdentity'):
        require(re.search(r'if \(!GetFileInformationByHandle\(handle, out ByHandleFileInformation basic\)\)\s*'
                          r'throw new IOException\(', body(source, name)), name + ' native read failure remains transient')


def profile_compile_contract(project, tests):
    root = ET.fromstring(project)
    friends = [(group, friend) for group in root.findall('ItemGroup')
               for friend in group.findall('InternalsVisibleTo') if friend.get('Include') == 'SafeUpload.Agent.Tests']
    require(any(not group.get('Condition') and not friend.get('Condition') for group, friend in friends),
            'normal-profile tests need internal wire validator visibility')
    for group in root.findall('PropertyGroup'):
        for define in group.findall('DefineConstants'):
            if 'SAFEUPLOAD_ADMISSION_EVIDENCE' in (define.text or ''):
                require(group.get('Condition') == "'$(SafeUploadAdmissionEvidence)' == 'true'",
                        'friend access must not compile feature APIs into normal builds')
    # Inspect each actual constructor call, including callbacks with nested
    # parentheses, so omission of either non-optional internal argument fails.
    for call in re.finditer(r'new StagedTransferJournal\(', tests):
        start = call.end(); end = start; depth = 1
        while depth:
            depth += {'(': 1, ')': -1}.get(tests[end], 0); end += 1
        arguments = tests[start:end]
        if 'writeObserver:' in arguments:
            require('requireProtectedParent: false,' in arguments and 'scanCacheCapacity: 4,' in arguments,
                    'fault-injection overload requires both parent protection and cache capacity')


class RenameReceipt(unittest.TestCase):
    def setUp(self):
        self.stream, self.protocol = code(STREAM), code(PROTOCOL)

    def test_production_adopts_only_exact_commit_before_fence_release(self):
        adoption_contract(self.stream)

    def test_production_checks_sized_reply_and_every_source_byte(self):
        wire_contract(self.protocol)

    def test_negative_adoption_and_ack_mutations_are_caught(self):
        adopt = 'Stream->DestinationGeneration = Exchange->RenameDestinationGeneration;'
        mutations = [
            (adopt, 'Stream->DestinationGeneration++;'),
            (adopt, 'Stream->RenameExchange = NULL; ' + adopt),
            ('Stream->RenameWait = STAGE_WAIT_NONE;', 'Stream->DestinationGeneration = 1; Stream->RenameWait = STAGE_WAIT_NONE;'),
            ('source->SourceGeneration != Stream->DestinationGeneration', 'FALSE'),
            ('source->ViewGeneration != (UINT64)Stream->View->Generation', 'FALSE'),
            ('source->RequestId != Exchange->Request.RequestId', 'FALSE'),
            ('!Exchange->RenameReceiptValid', 'FALSE'),
            ('Stream->Name.Length != Exchange->Request.PathLength', 'FALSE'),
            ('&Exchange->RenameAck.StageIdentity, &source->StageIdentity', '&source->StageIdentity, &source->StageIdentity'),
        ]
        for old, new in mutations:
            with self.subTest(mutation=old):
                require(old in self.stream, 'mutation must hit production')
                with self.assertRaises(AssertionError):
                    adoption_contract(self.stream.replace(old, new))

    def test_negative_wire_mutations_are_caught(self):
        for old in ('Exchange->ReplyLength != sizeof(*outer)', 'reply->Source.Version != SAFEUPLOAD_STAGE_EXTENSION_VERSION',
                    'reply->DestinationNameLength != Exchange->Request.PathLength',
                    '!RtlEqualMemory(&source, &expected, sizeof(source))', 'reply->Reserved != 0'):
            with self.subTest(mutation=old):
                require(old in self.protocol, 'mutation must hit production')
                with self.assertRaises(AssertionError):
                    wire_contract(self.protocol.replace(old, 'FALSE'))

    def test_agent_receipt_and_namespace_update_share_one_atomic_replacement(self):
        source = code(AGENT)
        complete = body(source, 'CompleteRenameAsync')
        require(complete.index('receipt.Source != exactRequest') < complete.index('long generation = current.DestinationGeneration'),
                'resolve original receipt before inspecting retargeted source')
        update = complete[complete.index('var updated = current with'):]
        for field in ('Transfer = commit', 'DestinationGeneration = generation', 'NamespaceTombstones = tombstones',
                      'LastRenameReceiptV20 = exactRequest is null ? null : new StagedRenameReceiptV20('):
            self.assertIn(field, update)
        self.assertEqual(complete.count('await ReplaceAsync('), 1)
        self.assertIn('pending.SourceV20 != exactRequest', complete)

    def test_both_wire_mirrors_keep_exact_sizes_offsets_and_capability(self):
        header = (ROOT / 'driver/SafeUpload.Minifilter/Protocol.h').read_text()
        managed = (ROOT / 'agente/SafeUpload.Agent.Minifilter/Protocol.cs').read_text()
        for native, cs, size in [('RENAME_V20', 'StageRenameV20', 128),
                                ('RENAME_COMMIT_V20', 'StageRenameCommitV20', 1168),
                                ('RENAME_REPLY_V20', 'StageRenameReplyV20', 1192)]:
            self.assertIn(f'C_ASSERT( sizeof( SAFEUPLOAD_STAGE_{native} ) == {size} );', header)
            self.assertIn(f'{cs}Size = {size};', managed)
        self.assertIn('SAFEUPLOAD_STAGE_CAPABILITY_REQUIRED ((UINT32) 0x000001BF)', header)
        self.assertIn('RenameCommitReceipt = 0x80', managed)

    def test_structural_refusal_guards_and_native_io_classification(self):
        source = code(STAGE_FILE)
        structural_refusal_contract(source)
        for match in list(re.finditer('throw StagedRequestRefusal.Create', source)):
            with self.subTest(offset=match.start()):
                changed = source[:match.start()] + source[match.start():].replace(
                    'throw StagedRequestRefusal.Create', 'throw new IOException', 1)
                with self.assertRaises(AssertionError): structural_refusal_contract(changed)
        with self.assertRaises(AssertionError):
            structural_refusal_contract(source.replace('throw new IOException', 'throw StagedRequestRefusal.Create'))

    def test_normal_and_feature_test_visibility_and_fault_injection_arguments(self):
        project, tests = MINIFILTER_PROJECT.read_text(), code(ATTACHMENT_TESTS)
        profile_compile_contract(project, tests)
        with self.assertRaises(AssertionError):
            profile_compile_contract(project.replace('<ItemGroup>', '<ItemGroup Condition="feature-only">'), tests)
        for argument in ('requireProtectedParent: false,', 'scanCacheCapacity: 4,'):
            with self.subTest(argument=argument), self.assertRaises(AssertionError):
                profile_compile_contract(project, tests.replace(argument, ''))


if __name__ == '__main__':
    unittest.main()
