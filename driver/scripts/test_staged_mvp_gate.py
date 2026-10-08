"""Synthetic MVP-gate tests; these are not Windows qualification evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('qualification', Path(__file__).with_name('Invoke-StagedInvariantQualification.py'))
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)


def fixture():
    return {'Schema': 'StagedInvariantSuite/2', 'AuthoritativeCaseExport': True,
            'CaseId': 'C01-approve-absent', 'Mode': 'runtime-verifier', 'CaseStatus': 'READY',
            'Verdict': 'INCONCLUSIVE', 'ForbiddenByteCount': 0,
            'InputHashes': {k: 'A' * 64 for k in Q.MVP_BUILD_HASHES},
            'Restoration': {'Known': True, 'GuestChecks': True, 'IndependentBaseline': 'baseline.txt',
                            'IndependentBaselineSha256': 'B' * 64},
            'Trials': [{'Verdict': 'INCONCLUSIVE', 'ForbiddenByteCount': 0,
                        'Disposal': {'Status': 'OK'}, 'Errors': [], 'Assertions': [
                            {'Name': 'DestinationImage', 'Verdict': 'PASS'},
                            {'Name': 'LiveTaintFlags', 'Verdict': 'PASS'}],
                        'Predicate': {'Verdict': 'INCONCLUSIVE', 'Assertions': []}, 'Latency': []}]}


def latency(result):
    return {'Schema': 'StagedInvariantLatency/1', 'RunName': 'dedicated-real-run',
            'WritePath': 'cached-write', 'Mode': result['Mode'], 'RestorationClean': True,
            'LiveTaintFlagsPassed': True,
            'InputHashes': result['InputHashes'].copy(), 'Errors': [],
            'Latency': [{'Class': 'cached-write', 'Verdict': 'PASS', 'Samples': [
                {'Cold': n == 0, 'Held': False, 'Ms': 10} for n in range(101)]}]}


class MvpGateTests(unittest.TestCase):
    def assess(self, result, evidence=None):
        return Q.mvp_case_gate(result, evidence)

    def test_c02_block_requires_unique_family_handback_contracts(self):
        result = fixture()
        result['CaseId'] = 'C02-block-absent'
        assertions = result['Trials'][0]['Assertions']
        assertions.extend({'Name': name, 'Verdict': 'PASS'}
                          for name in sorted(Q.C02_BLOCK_REQUIRED_ASSERTIONS))
        self.assertTrue(self.assess(result)['MvpGatePassed'])
        for name in sorted(Q.C02_BLOCK_REQUIRED_ASSERTIONS):
            for change in ('missing', 'duplicate', 'c01-prefix', 'fail'):
                bad = copy.deepcopy(result)
                items = bad['Trials'][0]['Assertions']
                item = next(a for a in items if a['Name'] == name)
                if change == 'missing':
                    items.remove(item)
                elif change == 'duplicate':
                    items.append(item.copy())
                elif change == 'c01-prefix':
                    item['Name'] = 'C01' + name[3:]
                else:
                    item['Verdict'] = 'FAIL'
                with self.subTest(name=name, change=change):
                    assessment = self.assess(bad)
                    self.assertFalse(assessment['MvpGatePassed'])
                    finding = ('Duplicate:' if change == 'duplicate' else
                               '' if change == 'fail' else 'Missing:') + name
                    self.assertIn(finding, assessment['MvpBlockers'])
        for name in ('C02HandBackSecondUserAccess', 'C02HandBackWindowClosureAndRestart'):
            bad = copy.deepcopy(result)
            next(a for a in bad['Trials'][0]['Assertions'] if a['Name'] == name)['Verdict'] = 'INCONCLUSIVE'
            self.assertFalse(self.assess(bad)['MvpGatePassed'])

    def test_live_taint_must_be_present_unique_and_pass(self):
        for kind in ('missing', 'duplicate', 'inconclusive', 'fail'):
            result = fixture()
            assertions = result['Trials'][0]['Assertions']
            if kind == 'missing':
                assertions.pop()
            elif kind == 'duplicate':
                assertions.append(assertions[-1].copy())
            else:
                assertions[-1]['Verdict'] = kind.upper()
            with self.subTest(kind=kind):
                actual = self.assess(result)
                self.assertFalse(actual['MvpGatePassed'])
                self.assertIn('LiveTaintFlags', actual['MvpBlockers'])

    def test_each_fixed_allowlist_assertion(self):
        for name in (*Q.MVP_DEFERRED_EXACT, 'C01PublicationAndTemporalCoverage'):
            with self.subTest(name=name):
                result = fixture()
                result['Trials'][0]['Assertions'].append({'Name': name, 'Verdict': 'INCONCLUSIVE'})
                actual = self.assess(result)
                self.assertTrue(actual['MvpGatePassed'])
                self.assertEqual([name], actual['MvpDeferred'])

    def test_c05_source_uses_the_existing_exact_deferred_allowlist(self):
        for container in ('Assertions', 'Predicate'):
            for proof in Q.MVP_DEFERRED_EXACT:
                name = 'C05Source' + proof
                with self.subTest(container=container, name=name):
                    result = fixture()
                    result['CaseId'] = 'C05-denied-external-rename'
                    assertions = result['Trials'][0][container]
                    if container == 'Predicate':
                        assertions = assertions['Assertions']
                    assertions.append({'Name': name, 'Verdict': 'INCONCLUSIVE'})
                    actual = self.assess(result)
                    self.assertTrue(actual['MvpGatePassed'])
                    self.assertEqual([name], actual['MvpDeferred'])
                    assertions[-1]['Verdict'] = 'FAIL'
                    actual = self.assess(result)
                    self.assertFalse(actual['MvpGatePassed'])
                    self.assertIn(name, actual['MvpBlockers'])

    def test_c05_source_does_not_defer_other_proofs_or_prefixes(self):
        for name in ('C05SourceDirectoryMetadata', 'C05SourceCoverage', 'C05SourceDisposal',
                     'C05SourceFileMetadata', 'C05SourceNoUnapprovedByteX',
                     'C05SourceAlmostCadenceCoverage', 'OtherSourceCadenceCoverage',
                     'C05SourceC05SourceCadenceCoverage', 'C05Source', 'C05SourceDenialLedger'):
            with self.subTest(name=name):
                result = fixture()
                result['CaseId'] = 'C05-denied-external-rename'
                result['Trials'][0]['Assertions'].append({'Name': name, 'Verdict': 'INCONCLUSIVE'})
                actual = self.assess(result)
                self.assertFalse(actual['MvpGatePassed'])
                self.assertIn(name, actual['MvpBlockers'])
        result = fixture()
        result['Trials'][0]['Assertions'].append({'Name': 'C05SourceCadenceCoverage', 'Verdict': 'INCONCLUSIVE'})
        self.assertFalse(self.assess(result)['MvpGatePassed'])

    def test_c05_denial_ledger_deferred_only_for_c05_by_owner_decision(self):
        # Owner decision 2026-10-07: no driver rename-denial event exists; attribution is behavioral.
        result = fixture()
        result['CaseId'] = 'C05-denied-external-rename'
        result['Trials'][0]['Assertions'].append({'Name': 'C05DenialLedger', 'Verdict': 'INCONCLUSIVE'})
        actual = self.assess(result)
        self.assertTrue(actual['MvpGatePassed'])
        self.assertEqual(['C05DenialLedger'], actual['MvpDeferred'])
        result['Trials'][0]['Assertions'][-1]['Verdict'] = 'FAIL'
        self.assertFalse(self.assess(result)['MvpGatePassed'])
        for case in ('C01-approve-absent', 'C04-block', 'B01'):
            with self.subTest(case=case):
                other = fixture()
                other['CaseId'] = case
                other['Trials'][0]['Assertions'].append({'Name': 'C05DenialLedger', 'Verdict': 'INCONCLUSIVE'})
                actual = self.assess(other)
                self.assertFalse(actual['MvpGatePassed'])
                self.assertIn('C05DenialLedger', actual['MvpBlockers'])

    def test_handback_safe_creation_deferred_only_by_exact_suffix(self):
        result = fixture()
        result['Trials'][0]['Assertions'].append({'Name': 'C01HandBackSafeRelativeCreation', 'Verdict': 'INCONCLUSIVE'})
        actual = self.assess(result)
        self.assertTrue(actual['MvpGatePassed'])
        self.assertEqual(['C01HandBackSafeRelativeCreation'], actual['MvpDeferred'])
        for name, verdict in (('HandBackSafeRelativeCreation', 'INCONCLUSIVE'),
                              ('C01HandBackSafeRelativeCreationX', 'INCONCLUSIVE'),
                              ('C01HandBackSafeRelativeCreation', 'FAIL')):
            with self.subTest(name=name, verdict=verdict):
                bad = fixture()
                bad['Trials'][0]['Assertions'].append({'Name': name, 'Verdict': verdict})
                self.assertFalse(self.assess(bad)['MvpGatePassed'])

    def test_unheld_latency_requires_matching_dedicated_evidence(self):
        result = fixture()
        result['Trials'][0]['Assertions'].append({'Name': 'C01UnheldLatency', 'Verdict': 'INCONCLUSIVE'})
        result['Trials'][0]['Latency'] = [{'Class': 'cached-write', 'Verdict': 'INCONCLUSIVE'}]
        self.assertFalse(self.assess(result)['MvpGatePassed'])
        actual = self.assess(result, latency(result))
        self.assertTrue(actual['MvpGatePassed'])
        self.assertEqual(['C01UnheldLatency'], actual['MvpDeferred'])

    def test_latency_rejects_count_budget_hold_nan_and_binding(self):
        result = fixture()
        result['Trials'][0]['Latency'] = [{'Class': 'cached-write', 'Verdict': 'INCONCLUSIVE'}]
        mutations = [lambda e: e['Latency'][0]['Samples'].pop(),
                     lambda e: e['Latency'][0]['Samples'][0].update(Ms=1001),
                     lambda e: [s.update(Ms=251) for s in e['Latency'][0]['Samples']],
                     lambda e: e['Latency'][0]['Samples'][0].update(Held=True),
                     lambda e: e['Latency'][0]['Samples'][0].update(Ms=float('nan')),
                     lambda e: e.update(WritePath='mapped-write'),
                     lambda e: e.update(Mode='ordinary'),
                     lambda e: e['InputHashes'].update(Feature='C' * 64),
                     lambda e: e.update(RestorationClean=False),
                     lambda e: e.update(LiveTaintFlagsPassed=False),
                     lambda e: e.pop('LiveTaintFlagsPassed'),
                     lambda e: e.update(LiveTaintFlagsPassed=1),
                     lambda e: [s.update(Cold=False) for s in e['Latency'][0]['Samples']]]
        for change in mutations:
            evidence = latency(result)
            change(evidence)
            with self.subTest(change=change):
                self.assertFalse(self.assess(result, evidence)['MvpGatePassed'])

    def test_any_other_inconclusive_fails(self):
        for name in ('C01BlockedStageRetained', 'C01RawCapture', 'C01OutcomeNotification',
                     'C01ReleasedNotificationDigest', 'Disposal', 'AlmostCadenceCoverage', ''):
            result = fixture()
            result['Trials'][0]['Assertions'].append({'Name': name, 'Verdict': 'INCONCLUSIVE'})
            self.assertFalse(self.assess(result)['MvpGatePassed'])

    def test_any_fail_fails_even_allowlisted_or_nested(self):
        for container in ('Assertions', 'Predicate'):
            for name in (*Q.MVP_DEFERRED_EXACT, 'C01PublicationAndTemporalCoverage', 'C01UnheldLatency'):
                result = fixture()
                assertions = result['Trials'][0][container]
                if container == 'Predicate':
                    assertions = assertions['Assertions']
                assertions.append({'Name': name, 'Verdict': 'FAIL'})
                self.assertFalse(self.assess(result)['MvpGatePassed'])

    def test_prerequisites_cannot_be_deferred(self):
        mutations = [lambda r: r.update(ForbiddenByteCount=1),
                     lambda r: r.update(Errors=['failed']), lambda r: r.update(Verdict='FAIL'),
                     lambda r: r.update(AuthoritativeCaseExport=False),
                     lambda r: r['Restoration'].update(Known=False),
                     lambda r: r['Restoration'].pop('IndependentBaselineSha256'),
                     lambda r: r['Trials'][0].update(ForbiddenByteCount=1),
                     lambda r: r['Trials'][0].update(Errors=['failed']),
                     lambda r: r['Trials'][0]['Disposal'].update(Status='ERROR'),
                     lambda r: r['Trials'][0].update(Assertions=[]),
                     lambda r: r.update(Trials=[])]
        for change in mutations:
            result = fixture()
            change(result)
            self.assertFalse(self.assess(result)['MvpGatePassed'])

    def test_mvp_suite_requires_all_rows_and_modes(self):
        rows = Q.table_rows(Q.SCRIPTS / 'StagedInvariantCases.psd1')
        required = Q.mvp_required_rows(rows)
        self.assertTrue({'A04', 'A05', 'B01', 'B02', 'R01', 'R02', 'R03', 'X01'} <= required)
        self.assertFalse({'P01', 'C01', 'C05'} & required)
        outcomes = [{'CaseId': case, 'Mode': mode, 'MvpGatePassed': True}
                    for case in required for mode in Q.MODES]
        self.assertTrue(Q.mvp_suite_passed(outcomes, rows))
        self.assertFalse(Q.mvp_suite_passed(outcomes[:-1], rows))
        outcomes[0]['MvpGatePassed'] = False
        self.assertFalse(Q.mvp_suite_passed(outcomes, rows))


if __name__ == '__main__':
    unittest.main()
