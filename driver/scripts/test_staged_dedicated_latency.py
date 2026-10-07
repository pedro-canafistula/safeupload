"""Host exporter controls; synthetic receipts are never qualification evidence."""
import copy
import importlib.util
import json
import hashlib
import tempfile
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('qualification', Path(__file__).with_name('Invoke-StagedInvariantQualification.py'))
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)
CLASSES = {
 'C01-approve-absent': ['writer-open', 'cached-write', 'flush', 'close'],
 'C02-approve-absent': ['writer-open', 'create-mapping', 'map-view', 'close-source', 'mapped-store', 'flush-view', 'unmap-view', 'close-section'],
 'C03-approve-existing': ['writer-open', 'cached-write', 'flush', 'close'],
 'C04-approve': ['writer-open', 'cached-write', 'flush', 'rename-ex', 'close'],
 'C05-denied-external-rename': ['writer-open', 'rename-ex', 'close'],
}


def fixture(case='C01-approve-absent'):
    actor = dict(Pid=1234, Sid='S-1-5-21-1-2-3-1001', SessionId=0, BootId='active', Elevated=False, IsAdministrator=False)
    observation = dict(Complete=True, Held=False, Rounds=[], Digest='A'*64, Length=12288, QpcFrequency=1000)
    calls, qpc = [], 1
    for n in range(101):
        target = 'C:\\fixture\\'+(f'latency-{n:03}.txt' if case.startswith(('C01-', 'C02-')) else 'cached.txt')
        open_path = (f'C:\\fixture\\latency-{n:03}.tmp.txt' if case == 'C04-approve'
                     else 'C:\\external\\source.txt' if case == 'C05-denied-external-rename' else target)
        native = []
        for cls in CLASSES[case]:
            code = 5 if case == 'C05-denied-external-rename' and cls == 'rename-ex' else 0
            native.append(dict(Class=cls, Trial=n, Cold=n == 0, NativeCode=code, StartQpc=qpc, EndQpc=qpc+1));qpc+=2
        common = dict(Pid=1234, Sid=actor['Sid'], BootId='active', PrivateSha256='A'*64, Token='a'*32, Qpc=qpc)
        receipt = dict(common, Calls=native, Trial=n, Held=False, Target=target, OpenPath=open_path)
        private = dict(common, SourceClosed=True, ViewLive=True, SectionLive=True)
        transfer = dict(State=5, SealedOnce=True, Sha256Hex='A'*64, StateHistory=[dict(State=i) for i in range(6)],
                Transfer=dict(ProcessId=1234, SessionId=0, RequestorSid=actor['Sid'], TransferId=f'id-{n}', DestinationPath=target))
        terminal = dict(StateName='Released', SealedOnce=True, Sha256Hex='A'*64,
                History=['Allocated','Sealed','Inspecting','Approved','Publishing','Released'], TransferId=f'id-{n}',
                StartQpc=qpc, EndQpc=qpc+1, Record=dict(Bytes=list(json.dumps(transfer).encode())))
        record=dict(Trial=n, Receipt=receipt, PrivateReceipt=private, Terminal=terminal, PublicationVerifiedQpc=qpc+2)
        if case == 'C05-denied-external-rename':
            def raw_sample(path, absent):
                time=dict(BootId='active', QpcFrequency=1000, Qpc=qpc+1)
                return dict(Status='OK', Start=time.copy(), End=time.copy(), Captures=[dict(Images=[
                    dict(Role='Current', Path=path, Absent=absent), dict(Role='Parent')])])
            record.update(Terminal=None, NativeNotBeforeQpc=n*9,
                ObservationVerifiedQpc=qpc+2, IoCompletedQpc=qpc+2,
                ValidationStatus='Complete', Snapshot=dict(Status='OK'),
                JournalProof=dict(Complete=True, NewEntries=[], Findings=[]),
                SampleAssertions=[dict(Name='RawSourceAndAbsentTarget', Verdict='PASS')],
                DestinationSample=raw_sample(target, True), SourceSample=raw_sample(open_path, False))
        observation['Rounds'].append(record)
        qpc+=3;calls.extend(native)
    return dict(Schema='StagedInvariantSuite/2', AuthoritativeCaseExport=True, CaseId=case, RunName='synthetic-only', Mode='runtime-verifier', Verdict='INCONCLUSIVE',
            InputHashes={k:'B'*64 for k in Q.MVP_BUILD_HASHES}, Restoration=dict(Known=True, GuestChecks=True), BootIds=dict(Active='active'),
            Trials=[dict(Errors=[], Disposal=dict(Status='OK'), DedicatedLatency=observation, Actor=actor,
                Platform=dict(Build='19045.2965', BootId='active'), ActorProvenance=dict(Pid=1234, OwnerSid=actor['Sid'], SessionId=0),
                ImageA=dict(Sha256='A'*64, Length=12288), Assertions=[dict(Name='DedicatedLatencyOnly', Verdict='INCONCLUSIVE'),
                    dict(Name='LiveTaintFlags', Verdict='PASS')], Operations=calls)])


class DedicatedLatencyTests(unittest.TestCase):
    def test_real_cli_selection_accepts_denied_rename_and_rejects_other_variants(self):
        self.assertEqual(set(CLASSES), Q.DEDICATED_LATENCY_CASES)
        for case in CLASSES:
            self.assertTrue(Q.dedicated_latency_selection_valid([case], ['runtime-verifier']))
        for cases, modes, diagnostic, evidence in ((['C05'], ['ordinary'], 0, None),
                (['C05-denied-external-rename'], ['ordinary', 'boot-verifier'], 0, None),
                (list(CLASSES), ['ordinary'], 0, None),
                (['C05-denied-external-rename'], ['ordinary'], 600, None),
                (['C05-denied-external-rename'], ['ordinary'], 0, Path('receipt.json'))):
            self.assertFalse(Q.dedicated_latency_selection_valid(cases, modes, diagnostic, evidence))

    def test_dedicated_receipt_requires_unique_pass_live_taint(self):
        for kind in ('missing', 'duplicate', 'inconclusive', 'fail'):
            result=fixture();assertions=result['Trials'][0]['Assertions']
            if kind=='missing': assertions.pop()
            elif kind=='duplicate': assertions.append(assertions[-1].copy())
            else: assertions[-1]['Verdict']=kind.upper()
            with self.subTest(kind=kind):
                self.assertNotEqual('PASS', Q.export_dedicated_latency(result)['Verdict'])

    def test_denied_rename_requires_exact_status_and_every_independent_round_proof(self):
        changes = [lambda r: r['Receipt']['Calls'][1].update(NativeCode=0),
                   lambda r: r['Receipt']['Calls'][1].update(NativeCode=32),
                   lambda r: r['JournalProof'].update(NewEntries=[{'TransferId':'unexpected'}]),
                   lambda r: r['JournalProof'].update(Complete=False),
                   lambda r: r['SourceSample'].update(Status='INCONCLUSIVE'),
                   lambda r: r['SourceSample'].update(Captures=[]),
                   lambda r: r['DestinationSample']['Captures'][0]['Images'][0].update(Absent=False),
                   lambda r: r['SampleAssertions'][0].update(Verdict='FAIL'),
                   lambda r: r.update(IoCompletedQpc=0),
                   lambda r: r['Receipt'].update(OpenPath=r['Receipt']['Target'])]
        for change in changes:
            result=fixture('C05-denied-external-rename');change(result['Trials'][0]['DedicatedLatency']['Rounds'][40])
            with self.subTest(change=change):
                self.assertNotEqual('PASS', Q.export_dedicated_latency(result)['Verdict'])

    def test_all_write_paths(self):
        for case in CLASSES:
            with self.subTest(case=case):
                self.assertEqual(Q.export_dedicated_latency(fixture(case))['Verdict'], 'PASS')

    def test_missing_cold_warm_round_and_native_class_rejected(self):
        for kind in ('missing', 'repeat', 'class', 'cold', 'native', 'held', 'token', 'QPC'):
            with self.subTest(kind=kind):
                result=fixture();o=result['Trials'][0]['DedicatedLatency'];r=o['Rounds'][4];c=r['Receipt']['Calls'][0]
                if kind=='missing': o['Rounds'].pop()
                elif kind=='repeat': r['Trial']=3
                elif kind=='class': c['Class']='wrong'
                elif kind=='cold': c['Cold']=True
                elif kind=='native': c['NativeCode']=5
                elif kind=='held': r['Receipt']['Held']=True
                elif kind=='token': r['Receipt']['Token']='b'*32;r['PrivateReceipt']['Token']='b'*32
                else: c['StartQpc']=0
                self.assertTrue(Q.export_dedicated_latency(result)['Errors'])

    def test_actual_transfer_bytes_must_match_receipts(self):
        for field in ('State','Sha256Hex','ProcessId','SessionId','RequestorSid','StateHistory','DestinationPath'):
            result=fixture();r=result['Trials'][0]['DedicatedLatency']['Rounds'][4];record=r['Terminal']['Record'];d=json.loads(bytes(record['Bytes']))
            if field=='StateHistory': d[field]=[dict(State=5)]
            elif field=='State': d[field]=6
            elif field=='Sha256Hex': d[field]='C'*64
            else: d['Transfer'][field]=666 if field in ('ProcessId','SessionId') else 'wrong'
            record['Bytes']=list(json.dumps(d).encode())
            with self.subTest(field=field): self.assertTrue(Q.export_dedicated_latency(result)['Errors'])

    def test_duplicate_transfer_and_absent_path_rejected(self):
        for field in ('transfer','path'):
            result=fixture();r=result['Trials'][0]['DedicatedLatency']['Rounds'][4]
            if field=='transfer': r['Terminal']['TransferId']='id-3'
            else: r['Receipt']['Target']='C:\\fixture\\latency-003.txt';r['Receipt']['OpenPath']=r['Receipt']['Target']
            self.assertTrue(Q.export_dedicated_latency(result)['Errors'])

    def test_mapping_requires_view_after_source_close(self):
        result=fixture('C02-approve-absent');result['Trials'][0]['DedicatedLatency']['Rounds'][4]['PrivateReceipt']['SourceClosed']=False
        self.assertTrue(Q.export_dedicated_latency(result)['Errors'])

    def test_budget_failure_preserves_samples(self):
        result=fixture();trial=result['Trials'][0];o=trial['DedicatedLatency']
        # One cold operation >1s; shift all later times, preserving ordering.
        o['Rounds'][0]['Receipt']['Calls'][0]['EndQpc']+=1001
        for r in o['Rounds']:
            for c in r['Receipt']['Calls']:
                if c is not o['Rounds'][0]['Receipt']['Calls'][0]: c['StartQpc']+=1001;c['EndQpc']+=1001
            r['Receipt']['Qpc']+=1001;r['PrivateReceipt']['Qpc']+=1001
            r['Terminal']['StartQpc']+=1001;r['Terminal']['EndQpc']+=1001;r['PublicationVerifiedQpc']+=1001
        result['Verdict']='FAIL'
        actual=Q.export_dedicated_latency(result)
        self.assertEqual(actual['Verdict'],'FAIL');self.assertFalse(actual['Errors']);self.assertEqual(len(actual['Latency'][0]['Samples']),101)

    def test_partial_rounds_and_native_failure_samples_retained(self):
        result=fixture();t=result['Trials'][0];o=t['DedicatedLatency']
        o['Complete']=False;o['Rounds']=o['Rounds'][:4]
        o['Rounds'][-1]['Receipt']['Calls'][0]['NativeCode']=5
        o['Rounds'][-1]['Terminal']=None
        t['Errors']=['native failure'];result['Verdict']='FAIL'
        actual=Q.export_dedicated_latency(result)
        self.assertNotEqual(actual['Verdict'],'PASS');self.assertTrue(actual['Errors'])
        self.assertEqual(len(actual['ObservedRounds']),4)
        record=next(c for c in actual['Latency'] if c['Class']=='writer-open')
        self.assertEqual(len(record['Samples']),4);self.assertEqual(record['Samples'][-1]['NativeCode'],5)
        self.assertEqual(record['Verdict'],'FAIL')

    def test_native_success_samples_survive_missing_terminal(self):
        result=fixture();o=result['Trials'][0]['DedicatedLatency'];o['Complete']=False;o['Rounds']=o['Rounds'][:3]
        o['Rounds'][-1]['Terminal']=None
        actual=Q.export_dedicated_latency(result)
        self.assertNotEqual(actual['Verdict'],'PASS');self.assertTrue(actual['Errors'])
        self.assertTrue(all(len(c['Samples'])==3 for c in actual['Latency']))

    def test_terminal_record_bytes_are_bound_to_copied_artifact(self):
        result=fixture();t=result['Trials'][0]
        t['DedicatedLatency']['Rounds']=t['DedicatedLatency']['Rounds'][:1]
        record=t['DedicatedLatency']['Rounds'][0]['Terminal']['Record']
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);data=bytes(record['Bytes']);(root/'terminal.json').write_bytes(data)
            record.update(Artifact='guest-root/terminal.json',Length=len(data),Sha256=hashlib.sha256(data).hexdigest().upper())
            Q.validate_service_artifacts(result,root,'guest-root/')
            record['Bytes'][0]=ord(' ')
            with self.assertRaisesRegex(RuntimeError,'artifact bytes differ'):
                Q.validate_service_artifacts(result,root,'guest-root/')

    def test_incomplete_lifecycle_and_errors_rejected(self):
        for kind in ('restoration','disposal','error','marker','assertion','pin'):
            result=fixture();t=result['Trials'][0]
            if kind=='restoration': result['Restoration']['Known']=False
            elif kind=='disposal': t['Disposal']['Status']='ERROR'
            elif kind=='error': t['Errors']=['unavailable']
            elif kind=='marker': t['Assertions']=[]
            elif kind=='assertion': t['Assertions'].append(dict(Verdict='FAIL'))
            else: result['InputHashes']['Feature']='wrong'
            self.assertNotEqual(Q.export_dedicated_latency(result)['Verdict'],'PASS')


if __name__=='__main__': unittest.main()
