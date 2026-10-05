"""Host-only synthetic proof tests; never executes the orchestrator or Windows."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('Invoke-StagedInvariantQualification.py')
SPEC = importlib.util.spec_from_file_location('qualification', SCRIPT)
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)


def fixture():
    actor = {'Sid': 'S-1-5-21-1-2-3-1000', 'Pid': 22, 'SessionId': 0,
             'Elevated': False, 'IsAdministrator': False, 'BootId': 'active'}
    provenance = {'OwnerSid': actor['Sid'], 'Pid': 22, 'SessionId': 0}
    operations = [{'Class': 'writer-open-deny', 'Trial': n, 'NativeCode': 5,
                   'StartQpc': 100 + n * 10, 'EndQpc': 101 + n * 10} for n in range(101)]
    sample = {'Status': 'OK', 'Sequence': 1,
              'Start': {'Qpc': 5000, 'QpcFrequency': 1000, 'BootId': 'active'},
              'End': {'Qpc': 5100, 'QpcFrequency': 1000, 'BootId': 'active'}}
    trial = {'Baseline': {'CaseId': 'S00-observer-control', 'Build': '19045.2965', 'ObserverPid': 11,
                         'ObserverSid': 'S-1-5-18', 'Time': {'Qpc': 4900, 'QpcFrequency': 1000, 'BootId': 'active'}},
             'WriterFence': {'Complete': True, 'BootId': 'active', 'QpcFrequency': 1000,
                             'ExpectedAttempts': 101, 'ReleasedQpc': 50, 'CompletedQpc': 2000},
             'Operations': operations, 'Samples': [sample], 'Actor': actor, 'ActorProvenance': provenance,
             'Platform': {'ObserverProcess': {'OwnerSid': 'S-1-5-18', 'Pid': 11}},
             'ExpectedTimeline': {'WriterIdentities': [actor], 'ExternalEvidence': {
                 'Build': '19045.2965', 'ObserverPid': 11, 'ObserverSid': 'S-1-5-18',
                 'PrepareBootId': 'prepare', 'ActiveBootId': 'active'}},
             'Assertions': [{'Name': 'LiveTaintFlags', 'Verdict': 'INCONCLUSIVE'},
                            {'Name': 'ExternalCoverage', 'Verdict': 'INCONCLUSIVE'}],
             'Predicate': {'Assertions': [{'Name': 'PredicateCoverage', 'Verdict': 'INCONCLUSIVE'},
                                          {'Name': 'NoUnapprovedByte', 'Verdict': 'INCONCLUSIVE'},
                                          {'Name': 'ExternalCoverage', 'Verdict': 'INCONCLUSIVE'}]},
             'Errors': [], 'Latency': [{'Verdict': 'PASS'}]}
    return {'BootIds': {'Prepare': 'prepare', 'Active': 'active', 'Final': 'final'},
            'Restoration': {'Known': True, 'GuestChecks': True, 'IndependentBaseline': 'baseline.txt',
                            'IndependentBaselineSha256': 'A' * 64}, 'Trials': [trial]}


class ProofTests(unittest.TestCase):
    def test_independent_audit_restoration(self):
        with tempfile.TemporaryDirectory(prefix='audit-policy-proof-', dir='/tmp') as directory:
            before, after = (Path(directory) / name for name in ('before.txt', 'after.txt'))
            baseline = 'ProcessCreationAuditFlags=2\nProcessCreationAuditPerUserCount=0\n'
            before.write_text(baseline)
            after.write_text(baseline)
            policy = {'CreationFlags': 2, 'PerUserPolicyCount': 0}
            result = {'Restoration': {'ProcessCreationAudit': {
                'Restored': True, 'Original': dict(policy), 'Final': dict(policy)}}}
            Q.validate_audit_restoration(result, before, after)
            after.write_text(baseline.replace('Flags=2', 'Flags=3'))
            with self.assertRaisesRegex(RuntimeError, 'restoration mismatch'):
                Q.validate_audit_restoration(result, before, after)
            after.write_text(baseline)
            result['Restoration']['ProcessCreationAudit']['Final']['CreationFlags'] = 3
            with self.assertRaisesRegex(RuntimeError, 'differs from independent baseline'):
                Q.validate_audit_restoration(result, before, after)
            after.write_text(baseline + 'ProcessCreationAuditFlags=2\n')
            with self.assertRaisesRegex(RuntimeError, 'Missing/duplicate independent audit value'):
                Q.baseline_audit(after)
            after.write_text('BaselineClean=True\n')
            with self.assertRaisesRegex(RuntimeError, 'Missing/duplicate independent audit value'):
                Q.baseline_audit(after)

    def test_only_external_promoted_after_restoration(self):
        result = fixture()
        Q.attest_external_coverage(result)
        trial = result['Trials'][0]
        self.assertEqual('INCONCLUSIVE', result['Verdict'])
        self.assertEqual('INCONCLUSIVE', trial['Predicate']['Verdict'])
        for container in (trial, trial['Predicate']):
            external = [a for a in container['Assertions'] if a['Name'] == 'ExternalCoverage']
            self.assertEqual(1, len(external))
            self.assertEqual('PASS', external[0]['Verdict'])
            self.assertEqual('final', external[0]['Evidence']['Restoration']['FinalBootId'])

    def test_missing_restoration_stays_inconclusive(self):
        result = fixture()
        result['Restoration']['Known'] = False
        Q.attest_external_coverage(result)
        self.assertEqual('INCONCLUSIVE', result['Trials'][0]['Assertions'][-1]['Verdict'])

    def test_cadence_cannot_be_claimed_by_flag(self):
        result = fixture()
        trial = result['Trials'][0]
        trial['CadenceProof'] = {'Complete': True}
        trial['Baseline']['Time']['Qpc'] = 90
        trial['Samples'][0]['Start']['Qpc'] = 100
        Q.attest_external_coverage(result)
        self.assertEqual('INCONCLUSIVE', trial['Assertions'][-1]['Verdict'])

    def test_missing_call_cross_boot_and_unobserved_tail(self):
        original = fixture()['Trials'][0]
        for mutation in ('missing', 'boot', 'tail', 'prebaseline'):
            trial = copy.deepcopy(original)
            if mutation == 'missing':
                trial['Operations'].pop()
            elif mutation == 'boot':
                trial['Samples'][0]['End']['BootId'] = 'other'
            elif mutation == 'tail':
                trial['Operations'][-1].update(StartQpc=6000, EndQpc=6001)
                trial['WriterFence']['CompletedQpc'] = 7000
            else:
                trial['Baseline']['CaseId'] = 'S01-denied-write-after-boot'
            self.assertFalse(Q.actor_cadence_complete(trial), mutation)

    def test_observer_provenance_and_writer_elevation_required(self):
        for field in ('observer', 'writer'):
            result = fixture()
            trial = result['Trials'][0]
            if field == 'observer':
                trial['Platform']['ObserverProcess']['OwnerSid'] = trial['Actor']['Sid']
            else:
                trial['Actor']['Elevated'] = True
            Q.attest_external_coverage(result)
            self.assertEqual('INCONCLUSIVE', trial['Assertions'][-1]['Verdict'])

    def test_fail_precedence_preserved(self):
        result = fixture()
        result['Trials'][0]['Assertions'].append({'Name': 'ForbiddenBlock', 'Verdict': 'FAIL'})
        Q.attest_external_coverage(result)
        self.assertEqual('FAIL', result['Verdict'])

    def test_old_s00_has_no_new_proof(self):
        path = Q.ROOT / 'driver/evidence/2026-10-04/boot-start-invariant-S00-observer-control-ordinary-wp3s00g-artifacts/case.json'
        self.assertFalse(Q.actor_cadence_complete(json.loads(path.read_text())['Trials'][0]))

    def test_service_bytes_bound_to_result(self):
        with tempfile.TemporaryDirectory(prefix='wp4-proof-', dir='/tmp') as directory:
            root = Path(directory)
            artifact = root / 'journal.json'
            artifact.write_text('{"State": 0}\n')
            record = {'Artifact': 'guest\\journal.json', 'Length': artifact.stat().st_size,
                      'Sha256': Q.sha(artifact), 'Entry': {'State': 0}}
            result = {'Trials': [{'ServiceBefore': {'Journal': [record]}}]}
            Q.validate_service_artifacts(result, root, 'guest\\')
            artifact.write_text('{"State": 5}\n')
            with self.assertRaises(RuntimeError):
                Q.validate_service_artifacts(result, root, 'guest\\')
            record['Artifact'] = 'guest\\..\\outside.json'
            with self.assertRaises(RuntimeError):
                Q.validate_service_artifacts(result, root, 'guest\\')

    def test_stale_notification_bytes_remain_bound(self):
        with tempfile.TemporaryDirectory(prefix='notification-proof-', dir='/tmp') as directory:
            root = Path(directory)
            artifact = root / 'notifications-before-emissions.jsonl'
            artifact.write_text('{"Kind":"Stop"}\n')
            record = {'Artifact': 'guest\\' + artifact.name, 'Length': artifact.stat().st_size,
                      'Sha256': Q.sha(artifact)}
            result = {'Trials': [{'ServiceBefore': {'Notifications': {
                'Status': 'INCONCLUSIVE', 'Reason': 'Notification tail boot mismatch', 'Artifacts': [record]}}}]}
            Q.validate_service_artifacts(result, root, 'guest\\')
            artifact.write_text('{"Kind":"Start"}\n')
            with self.assertRaises(RuntimeError):
                Q.validate_service_artifacts(result, root, 'guest\\')
            record['Artifact'] = 'guest\\..\\outside.jsonl'
            with self.assertRaises(RuntimeError):
                Q.validate_service_artifacts(result, root, 'guest\\')


    def test_notification_location_bytes_bound_to_artifact(self):
        with tempfile.TemporaryDirectory(prefix='notification-location-proof-', dir='/tmp') as directory:
            root = Path(directory)
            artifact = root / 'notifications-before-head.json'
            artifact.write_bytes(b'stale bytes')
            record = {'Artifact': 'guest\\' + artifact.name, 'Length': artifact.stat().st_size,
                      'Sha256': Q.sha(artifact), 'Name': 'head.json'}
            location = {'Name': 'head.json', 'Bytes': list(artifact.read_bytes())}
            snapshot = {'Notifications': {'LocationStatus': 'OK', 'DirectoryExists': True,
                        'Artifacts': [record], 'LocationFiles': [location, {'Name': 'writer.lock', 'Bytes': []}]}}
            result = {'Trials': [{'ServiceBefore': snapshot}]}
            Q.validate_service_artifacts(result, root, 'guest\\')
            location['Bytes'] = list(b'forged bytes')
            with self.assertRaisesRegex(RuntimeError, 'location bytes differ'):
                Q.validate_service_artifacts(result, root, 'guest\\')
            location['Bytes'] = list(artifact.read_bytes())
            snapshot['Notifications']['LocationFiles'][1]['Bytes'] = [1]
            with self.assertRaisesRegex(RuntimeError, 'writer lock bytes mismatch'):
                Q.validate_service_artifacts(result, root, 'guest\\')

    def test_agent_absence_raw_xml_bound_to_artifact(self):
        with tempfile.TemporaryDirectory(prefix='agent-absence-proof-', dir='/tmp') as directory:
            root = Path(directory)
            artifact = root / 'agent-absence-System.json'
            xmls = ['<Event>SCM anchor</Event>', '<Event>SCM record</Event>']
            artifact.write_text(json.dumps(xmls))
            record = {'Artifact': 'guest\\' + artifact.name, 'Length': artifact.stat().st_size,
                      'Sha256': Q.sha(artifact), 'Xmls': xmls}
            result = {'Trials': [{'ServiceEvidence': {'AgentAbsenceProof': {'SystemLog': record}}}]}
            Q.validate_service_artifacts(result, root, 'guest\\')
            record['Xmls'] = ['<Event>forged projection</Event>']
            with self.assertRaisesRegex(RuntimeError, 'event XML differs'):
                Q.validate_service_artifacts(result, root, 'guest\\')
            record['Xmls'] = xmls
            artifact.write_text('[]')
            with self.assertRaisesRegex(RuntimeError, 'hash/length mismatch'):
                Q.validate_service_artifacts(result, root, 'guest\\')
            record['Artifact'] = 'guest\\..\\outside.json'
            with self.assertRaisesRegex(RuntimeError, 'Invalid agent absence artifact path'):
                Q.validate_service_artifacts(result, root, 'guest\\')


if __name__ == '__main__':
    unittest.main()
