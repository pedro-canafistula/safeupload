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
                            {'Name': 'DestinationImage', 'Verdict': 'PASS'}],
                        'Predicate': {'Verdict': 'INCONCLUSIVE', 'Assertions': []}, 'Latency': []}]}


def latency(result):
    return {'Schema': 'StagedInvariantLatency/1', 'RunName': 'dedicated-real-run',
            'WritePath': 'cached-write', 'Mode': result['Mode'], 'RestorationClean': True,
            'InputHashes': result['InputHashes'].copy(), 'Errors': [],
            'Latency': [{'Class': 'cached-write', 'Verdict': 'PASS', 'Samples': [
                {'Cold': n == 0, 'Held': False, 'Ms': 10} for n in range(101)]}]}


class MvpGateTests(unittest.TestCase):
    def assess(self, result, evidence=None):
        return Q.mvp_case_gate(result, evidence)

    def test_each_fixed_allowlist_assertion(self):
        for name in (*Q.MVP_DEFERRED_EXACT, 'C01PublicationAndTemporalCoverage'):
            with self.subTest(name=name):
                result = fixture()
                result['Trials'][0]['Assertions'].append({'Name': name, 'Verdict': 'INCONCLUSIVE'})
                actual = self.assess(result)
                self.assertTrue(actual['MvpGatePassed'])
                self.assertEqual([name], actual['MvpDeferred'])

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
