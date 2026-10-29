#!/usr/bin/env python3
"""Exercise actual workflow verdicts with complete and adversarial offline receipts."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile

root = Path(__file__).resolve().parent
launcher = root.parent / 'Invoke-StageNotepad.sh'
required_cases = [c for c in json.loads((root / 'notepad-cases.json').read_text()) if not c.get('Office')]
assert len(required_cases) == 25 and len({c['Kind'] for c in required_cases}) == 25
spec = importlib.util.spec_from_file_location('original_verdict_controls', root / 'notepad-verdict.SelfCheck.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
names = {'workflow_observed_bytes_match', 'workflow_spec', 'workflow_expected', 'workflow_steps_match', 'workflow_order_matches',
         'workflow_handback_matches', 'workflow_journal_matches', 'raw_case_final_matches'}
functions = [n for b in re.findall(r"<<'PY'\n(.*?)\nPY\n", launcher.read_text(), re.S)
             for n in ast.parse(b).body if isinstance(n, ast.FunctionDef) and n.name in names]
assert {n.name for n in functions} == names
scope = r'c:\protected\t5'
sid = 'S-1-5-21-100-200-300-1000'
env = dict(module.environment, hashlib=hashlib, json=json, required_cases=required_cases,
           result={'ActorSid': sid, 'HandbackDirectory': r'C:\Users\t5actor\SafeUpload\_bloqueados'})
exec(compile(ast.Module(body=functions, type_ignores=[]), str(launcher), 'exec'), env)
checks = 0

def check(condition, message):
    global checks
    checks += 1
    assert condition, message

save = ('native-create', 'open=0 write=0 close=0')
flows = {
    'explorer-empty': [save, ('shell-rename-empty', 'shell-rename=0'), ('second-open-empty', 'second-open=0')],
    'empty-copy': [('empty-copy', 'copy=0')],
    'empty-move': [('empty-move', 'move=0')],
    'native-clear': [save, ('native-clear', 'open=0 write=0 close=0')],
    'remove-item': [save, ('remove-item', 'remove=0')],
    'shell-delete': [save, ('shell-delete', 'shell-item-hr=0 shell-flags-hr=0 shell-delete-item-hr=0 shell-perform-hr=0 shell-abort-hr=0 shell-aborted=0')],
    'deny-acl': [save, save, ('native-delete', 'delete=5'), ('native-delete', 'delete=5')],
    'deny-share': [save, save] + [('hold-no-share-delete', 'hold-open=0'), ('native-delete', 'delete=32'), ('close-held', 'hold-close=0')] * 2,
    'inflight-before': [save, ('inflight-before', 'hold-open=0 hold-write=0 delete=32 hold-close=0')],
    'inflight-after': [save, ('inflight-after', 'hold-open=0 hold-write=0 hold-close=0 delete=0')],
    'delete-cpf': [save, ('native-delete', 'delete=0'), save],
    'native-append': [save, ('native-append', 'open=0 seek=0 write=0 close=0')],
    'notepad-edit': [save, ('notepad-edit', 'notepad-edit=0')],
    'native-read': [save, save, ('native-read', 'read-open=0 read=0 read-close=0'), ('native-read', 'read-open=5')],
}
shell_steps = 'shell-item-hr=0 shell-folder-hr=0 shell-flags-hr=0 shell-transfer-item-hr=0 shell-perform-hr=0 shell-abort-hr=0 shell-aborted=0'
flows.update({'shell-copy-in': [('shell-copy-in', shell_steps)], 'shell-move-in': [('shell-move-in', shell_steps)],
              'shell-move-within': [save, ('shell-move-within', shell_steps)]})

# Assert each leaf's complete approval set, including all original leaves: adding
# a newer payload for a new case must never authorize it under another name.
approved = env['approved_public_hash_map']()
for spec in required_cases:
    payloads = []
    if spec.get('Workflow'):
        if spec['Op'] in ('notepad-edit', 'native-read', 'shell-move-within', 'native-clear', 'remove-item', 'shell-delete',
                          'deny-acl', 'deny-share', 'inflight-before', 'inflight-after', 'delete-cpf', 'native-append'):
            payloads.append(('T5 '+spec['Kind']+' published clean prior').encode())
        if spec['Op'] in ('notepad-edit', 'shell-copy-in', 'shell-move-in', 'inflight-before', 'inflight-after'):
            payloads.append(('T5 '+spec['Kind']+' inspected newer save').encode())
    elif not spec['Sensitive']:
        payloads.append(('T5 '+spec['Kind']+' clean text').encode())
    hashes = {hashlib.sha256(payload).hexdigest().upper() for payload in payloads}
    for leaf in [spec['Leaf'], *spec.get('AuxiliaryLeaves', [])]:
        check(approved[leaf] == hashes, leaf+' exact approval set')
        newer_digest = hashlib.sha256(b'T5 ShellCopyIn inspected newer save').hexdigest().upper()
        if spec['Kind'] != 'ShellCopyIn':
            check(newer_digest not in approved[leaf], leaf+' never approves another leaf newer bytes')

with tempfile.TemporaryDirectory(prefix='t5-workflow-controls-') as temp:
    env['raw_dir'] = temp + '/row-raw'
    handbacks = Path(temp, 'row-handback-evidence'); handbacks.mkdir()
    for spec in required_cases:
        if not spec.get('Workflow'):
            continue
        case = dict(spec, Path=scope+'\\'+spec['Leaf'], NativeStepsChecked=True, NativeStepsOk=True,
                    JournalParseErrors=[], JournalSchemaErrors=[], NoPrivateCancellation=True,
                    FinalJournalOutcomeVerified=True, SettlementStatus='PASS')
        expected = env['workflow_expected'](case)
        if expected is not None:
            case.update(ExpectedLength=len(expected), ExpectedSha256=hashlib.sha256(expected).hexdigest().upper())
        acks = []
        for index, (op, steps) in enumerate(flows[spec['Op']]):
            path = case['Path']
            if spec['Op'] in ('explorer-empty', 'shell-move-within') and index == 0:
                path = scope+'\\'+spec['AuxiliaryLeaves'][0]
            if spec['Op'] == 'native-read' and index in (1, 3):
                path = scope+'\\'+spec['AuxiliaryLeaves'][0]
            if spec['Op'] in ('deny-acl', 'deny-share') and index in ((1, 2) if spec['Op'] == 'deny-acl' else (1, 2, 3, 4)):
                path = r'C:\T5\control\native-fixture\file.txt'
            ack = dict(N=index+1, Op=op, Path=path, Steps=steps, ActorPid=500, ActorSid=sid, Ui={})
            if op in ('native-delete', 'second-open-empty', 'inflight-before', 'inflight-after'):
                ack['Child'] = dict(Pid=600, Sid=sid, Path=path, Length=0, FirstByte=-1, ReadWrite=True)
            if op == 'empty-move': ack['SourceGone'] = True
            if op == 'empty-copy': ack['SourceLength'] = 0
            if op == 'notepad-edit':
                ack['Ui'] = dict(DirtyObserved=True, SaveCompleted=True, NoPromptClosed=True, Title='notepad-edit.txt - Notepad',
                                 OpenedExistingTitle='notepad-edit.txt - Notepad',
                                 WindowsAfterSave=['notepad-edit.txt - Notepad'], WindowsAtExit=[], MenuPath='command-save')
            if op in ('shell-copy-in', 'shell-move-in', 'shell-move-within'):
                ack.update(Source=scope+'\\'+spec['AuxiliaryLeaves'][0] if op == 'shell-move-within' else r'C:\Users\t5actor\AppData\Local\Temp\t5-shell.txt',
                           SourceInActorTemp=op != 'shell-move-within', SourceGone=op != 'shell-copy-in',
                           SourceRead=dict(Code=0, Length=len(expected), Sha256=hashlib.sha256(expected).hexdigest().upper(),
                                           Steps='read-open=0 read=0 read-close=0'))
            if op == 'native-read':
                ack['Read'] = (dict(Code=0, Length=len(expected), Sha256=hashlib.sha256(expected).hexdigest().upper()) if index == 2
                               else dict(Code=5, Length=0, Sha256=None))
            acks.append(ack)
        case['WorkflowAcks'] = acks
        check(env['workflow_steps_match'](case), spec['Kind']+' complete native steps')
        for mutate in ('missing', 'failed', 'wrong-path', 'system'):
            bad = copy.deepcopy(case)
            if mutate == 'missing': bad['WorkflowAcks'].pop()
            if mutate == 'failed': bad['WorkflowAcks'][-1]['Steps'] = 'failed=5'
            if mutate == 'wrong-path': bad['WorkflowAcks'][-1]['Path'] = r'C:\outside.txt'
            if mutate == 'system': bad['WorkflowAcks'][-1]['ActorSid'] = 'S-1-5-18'
            check(not env['workflow_steps_match'](bad), spec['Kind']+' reject '+mutate)
        if spec['Op'] in ('shell-copy-in', 'shell-move-in', 'shell-move-within'):
            bad = copy.deepcopy(case); bad['WorkflowAcks'][-1]['SourceRead']['Sha256'] = '0'*64
            check(not env['workflow_steps_match'](bad), spec['Kind']+' rejects wrong source bytes')
            if spec['Op'] != 'shell-copy-in':
                bad = copy.deepcopy(case); bad['WorkflowAcks'][-1]['SourceGone'] = False
                check(not env['workflow_steps_match'](bad), spec['Kind']+' rejects source not gone')
            if spec['Op'] != 'shell-move-within':
                bad = copy.deepcopy(case); bad['WorkflowAcks'][-1]['SourceInActorTemp'] = False
                check(not env['workflow_steps_match'](bad), spec['Kind']+' rejects source outside actor TEMP')
        if spec['Op'] == 'notepad-edit':
            for field in ('DirtyObserved', 'SaveCompleted', 'NoPromptClosed'):
                bad = copy.deepcopy(case); bad['WorkflowAcks'][-1]['Ui'][field] = False
                check(not env['workflow_steps_match'](bad), spec['Kind']+' rejects '+field)
        if spec['Op'] == 'native-read':
            bad = copy.deepcopy(case); bad['WorkflowAcks'][2]['Read']['Sha256'] = '0'*64
            check(not env['workflow_steps_match'](bad), 'ReadExisting rejects wrong actor read hash')
            bad = copy.deepcopy(case); bad['WorkflowAcks'][-1]['Read']['Length'] = 1
            check(not env['workflow_steps_match'](bad), 'ReadExisting rejects denied byte export')
        observation = module.sample(1, spec['Leaf'], expected is not None)
        if expected is not None:
            digest = hashlib.sha256(expected).hexdigest().upper()
            for key in ('CurrentImages', 'PublicReaders', 'ObserverReaders'):
                for row in observation[key]:
                    if row['Path'].lower() == case['Path'].lower():
                        row.update(Length=len(expected), Sha256=digest)
                        if row.get('LogicalArtifact'): row['LogicalArtifact'].update(Length=len(expected), Sha256=digest)
        check(env['workflow_observed_bytes_match'](observation), spec['Kind']+' observed fixture whitelist')
        check(env['raw_case_final_matches'](case, [observation]), spec['Kind']+' exact raw final')
        bad_observation = copy.deepcopy(observation)
        target = next(i for i in bad_observation['CurrentImages'] if i['Path'].lower() == case['Path'].lower())
        target.update(Absent=False, Length=1, Sha256='0'*64)
        check(not env['workflow_observed_bytes_match'](bad_observation), spec['Kind']+' rejects unknown intermediate content')
        check(not env['raw_case_final_matches'](case, [bad_observation]), spec['Kind']+' unexpected public byte fails')
        if spec['Op'] == 'shell-move-within':
            case.update(OldNameAbsent=True, SourceGone=True)
            check(env['workflow_order_matches'](case, [observation]), 'ShellMoveWithin auxiliary name absent')
            bad = copy.deepcopy(observation)
            next(i for i in bad['CurrentImages'] if i['Path'].lower().endswith('\\'+spec['AuxiliaryLeaves'][0]))['Absent'] = False
            check(not env['workflow_order_matches'](case, [bad]), 'ShellMoveWithin old name survived')
        if spec['Op'].startswith('inflight-'):
            before = spec['Op'] == 'inflight-before'
            gate_content = ('T5 '+case['Kind']+(' published clean prior' if before else ' inspected newer save')).encode()
            digest = hashlib.sha256(gate_content).hexdigest().upper()
            samples = [module.sample(n, spec['Leaf'], True) for n in (1, 2)]
            for sample in samples:
                for key in ('CurrentImages','PublicReaders','ObserverReaders'):
                    for row in sample[key]:
                        if row['Path'].lower() == case['Path'].lower():
                            row.update(Length=len(gate_content), Sha256=digest)
                            if row.get('LogicalArtifact'): row['LogicalArtifact'].update(Length=len(gate_content), Sha256=digest)
            target = next(i for i in samples[-1]['CurrentImages'] if i['Path'].lower()==case['Path'].lower())
            version = dict(IsV20=True, ProcessId=500, TransferId='new', DriverInstanceId='driver', DestinationPath=case['Path'],
                           StageIdentity=dict(VolumeSerialNumber=1,FileIdHigh=2,FileIdLow=3), State='0' if before else '5',
                           SealedOnce=not before, SealedLength=None if before else len(gate_content), Sha256Hex=None if before else digest)
            case['ForcedOrderProof'] = dict(Verified=True, Op=spec['Op'], ActorReady=dict(N=2, Op=spec['Op'], ActorPid=500, ProbeCreated=True, WritableProbeHandleHeld=before),
                                           RawSequences=[1,2], FinalRawSequence=2, CapturedBeforeGoQpc=250, Target=target, Journal=[version])
            check(env['workflow_order_matches'](case,samples), spec['Kind']+' deterministic gate')
            for mutation in ('wrong-handle', 'late', 'already-baseline', 'changed-object', 'wrong-order'):
                bad=copy.deepcopy(case)
                if mutation=='wrong-handle':bad['ForcedOrderProof']['ActorReady']['WritableProbeHandleHeld']=not before
                if mutation=='late':bad['ForcedOrderProof']['CapturedBeforeGoQpc']=210
                if mutation=='already-baseline':bad['WorkflowBaseline']=[version]
                if mutation=='changed-object':bad['ForcedOrderProof']['Journal'][0]['StageIdentity']=None
                if mutation=='wrong-order':bad['WorkflowAcks'][-1]['Steps']='hold-open=0 hold-write=0 '+('hold-close=0 delete=32' if before else 'delete=0 hold-close=0')
                check(not env['workflow_order_matches'](bad,samples), spec['Kind']+' rejects '+mutation)
        content = expected or b''
        journal = dict(TransferId='seed', State='5', StageDeleted=True, SealedLength=len(content),
                       Sha256Hex=hashlib.sha256(content).hexdigest().upper(), DestinationPath=case['Path'])
        records = [journal]
        if spec['Op'] == 'notepad-edit':
            prior = ('T5 '+case['Kind']+' published clean prior').encode()
            case['WorkflowBaseline'] = [dict(journal, TransferId='prior', SealedLength=len(prior),
                                             Sha256Hex=hashlib.sha256(prior).hexdigest().upper())]
        if spec['Op'] == 'explorer-empty':
            journal['DestinationPath'] = scope+'\\'+spec['AuxiliaryLeaves'][0]
            case['WorkflowJournalSnapshots'] = [[journal]]
            records = []
        if spec['Op'] in ('shell-move-within', 'native-read'):
            seed = dict(journal, DestinationPath=scope+'\\'+spec['AuxiliaryLeaves'][0])
            case['WorkflowJournalSnapshots'] = [[seed]]
            if spec['Op'] == 'shell-move-within': records = []  # native rename emits no new Release
            else:
                case['Fixtures'] = [dict(Path=seed['DestinationPath'], Sid=sid, Restored=True, FileBefore='old', FileDenied='deny')]
        if spec.get('Handback'):
            prior = ('T5 '+case['Kind']+' published clean prior').encode()
            blocked = prior+b'\r\nT5 notepad CPF: 529.982.247-25' if spec['Op'] == 'native-append' else b'T5 notepad CPF: 529.982.247-25'
            digest = hashlib.sha256(blocked).hexdigest().upper()
            (handbacks/(digest+'.bin')).write_bytes(blocked)
            case.update(ExpectedHandbackLength=len(blocked), ExpectedHandbackSha256=digest, HandedBack=True,
                        Handback=dict(Status='PASS', NewFileCount=1, Path=env['result']['HandbackDirectory']+'\\blocked.txt',
                                      Length=len(blocked), Sha256=digest, Artifact=digest+'.bin',
                                      Readers=[dict(Unbuffered=u, Status='OK', Length=len(blocked), Sha256=digest) for u in (False, True)]))
            records.append(dict(TransferId='blocked', State='6', HandbackState='2', SealedLength=len(blocked), Sha256Hex=digest))
        if spec['Op'] in ('deny-acl', 'deny-share'):
            case.update(NativeControlCode=5 if spec['Op']=='deny-acl' else 32, ProtectedDeleteCode=5 if spec['Op']=='deny-acl' else 32)
        if spec['Op']=='deny-acl':
            case['Fixtures'] = [dict(Restored=True, FileBefore='old', FileDenied='deny', ParentBefore='old', ParentDenied='deny')] * 2
        case['Journal'] = records
        case['StageEvidence'] = [dict(TransferId=j['TransferId'], Exists=False) for j in records]
        check(env['workflow_journal_matches'](case), spec['Kind']+' complete journal')
        bad = copy.deepcopy(case); bad['JournalParseErrors'] = ['lost frame']
        check(not env['workflow_journal_matches'](bad), spec['Kind']+' corrupt journal cannot pass')
        if spec['Op'] in ('shell-move-within', 'native-read'):
            bad = copy.deepcopy(case); bad['WorkflowJournalSnapshots'] = []
            check(not env['workflow_journal_matches'](bad), spec['Kind']+' missing auxiliary seed Release fails')
        if spec['Op'] in ('notepad-edit', 'shell-copy-in', 'shell-move-in', 'native-read'):
            bad = copy.deepcopy(case); bad['Journal'][0]['Sha256Hex'] = '0'*64
            check(not env['workflow_journal_matches'](bad), spec['Kind']+' wrong Released bytes fail')
            bad = copy.deepcopy(case); bad['Journal'][0]['DestinationPath'] = r'C:\outside.txt'
            check(not env['workflow_journal_matches'](bad), spec['Kind']+' wrong Release destination fails')
        if spec['Op'] == 'notepad-edit':
            bad = copy.deepcopy(case); bad['WorkflowBaseline'] = []
            check(not env['workflow_journal_matches'](bad), 'Notepad edit requires prior publication before editing')
            bad = copy.deepcopy(case); bad['Journal'][0]['TransferId'] = 'prior'
            bad['StageEvidence'][0]['TransferId'] = 'prior'
            check(not env['workflow_journal_matches'](bad), 'Notepad edit requires a distinct newer Release')
        if spec.get('Handback'):
            (handbacks/(digest+'.bin')).write_bytes(b'')
            check(not env['workflow_journal_matches'](case), spec['Kind']+' missing full-content handback fails')

print(f'T5WorkflowVerdictSelfCheck=PASS;Assertions={checks};ProductQualified=False')
