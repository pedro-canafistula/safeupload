"""Synthetic tests of the two-tier MVP gate in Get-StagedMvpStatus.py; these are not Windows qualification evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('status', Path(__file__).with_name('Get-StagedMvpStatus.py'))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)
Q = S.Q


def passing(case_id='C01-approve-absent', mode='ordinary'):
    return {'Schema': 'StagedInvariantSuite/2', 'AuthoritativeCaseExport': True, 'CaseId': case_id, 'Mode': mode,
            'CaseStatus': 'READY', 'Verdict': 'PASS', 'ForbiddenByteCount': 0,
            'InputHashes': {k: 'A' * 64 for k in Q.MVP_BUILD_HASHES},
            'Restoration': {'Known': True, 'GuestChecks': True, 'IndependentBaseline': 'baseline.txt',
                            'IndependentBaselineSha256': 'B' * 64},
            'Trials': [{'Verdict': 'PASS', 'ForbiddenByteCount': 0, 'Disposal': {'Status': 'OK'}, 'Errors': [],
                        'Assertions': [{'Name': 'C01RawFinalAbsent', 'Verdict': 'PASS'},
                                       {'Name': 'LiveTaintFlags', 'Verdict': 'PASS'}],
                        'Predicate': {'Verdict': 'PASS', 'Assertions': []}, 'Latency': []}]}


def with_assertion(result, name, verdict):
    result = copy.deepcopy(result)
    result['Trials'][0]['Assertions'].append({'Name': name, 'Verdict': verdict})
    return result


def latency_fail(result):
    """The result the harness writes when only a latency budget is missed: latency evidence FAIL, trial and case verdicts FAIL."""
    result = copy.deepcopy(result)
    result['Verdict'] = 'FAIL'
    result['Trials'][0]['Verdict'] = 'FAIL'
    result['Trials'][0]['Latency'] = [{'Class': 'close', 'Verdict': 'FAIL', 'Samples': []}]
    return result


class TierOneTests(unittest.TestCase):
    def test_clean_result_passes(self):
        self.assertEqual(S.tier1_blockers(passing()), [])

    def test_leaked_bytes_block_at_case_and_trial_level(self):
        for where in ('case', 'trial'):
            result = passing()
            (result if where == 'case' else result['Trials'][0])['ForbiddenByteCount'] = 1
            self.assertTrue(S.tier1_blockers(result), where)

    def test_unclean_restoration_blocks(self):
        result = passing()
        result['Restoration']['GuestChecks'] = False
        self.assertIn('RestorationClean', S.tier1_blockers(result))

    def test_any_fail_blocks_even_a_proof_depth_assertion(self):
        for name in ('NoUnapprovedByte', 'ActualServiceTimelines', 'C01PublicationAndTemporalCoverage', 'C01RawFinalAbsent'):
            self.assertTrue(S.tier1_blockers(with_assertion(passing(), name, 'FAIL')), name)

    def test_proof_depth_inconclusive_is_tolerated(self):
        for name in ('ActualServiceTimelines', 'NotificationExpectation', 'CadenceCoverage', 'PredicateCoverage',
                     'C01PublicationAndTemporalCoverage', 'C01UnheldLatency', 'C05DenialLedger'):
            self.assertEqual(S.tier1_blockers(with_assertion(passing(), name, 'INCONCLUSIVE')), [], name)

    def test_unfinished_case_or_outcome_proof_blocks(self):
        for name in ('C01Execution', 'C01RawFinalAbsent', 'C01ReleasedImage', 'AgentAbsenceScm', 'Disposal', 'SomethingNew'):
            self.assertTrue(S.tier1_blockers(with_assertion(passing(), name, 'INCONCLUSIVE')), name)

    def test_taint_flags_must_pass(self):
        result = passing()
        result['Trials'][0]['Assertions'] = [a for a in result['Trials'][0]['Assertions'] if a['Name'] != 'LiveTaintFlags']
        self.assertIn('LiveTaintFlags', S.tier1_blockers(result))

    def test_errors_and_disposal_block(self):
        result = passing()
        result['Trials'][0]['Disposal'] = {'Status': 'FAILED'}
        self.assertIn('TrialPrerequisites', S.tier1_blockers(result))
        result = passing()
        result['Trials'][0]['Errors'] = ['x']
        self.assertTrue(S.tier1_blockers(result))

    def test_c05_source_prefix_follows_the_same_depth_rule(self):
        base = passing('C05-denied-external-rename')
        self.assertEqual(S.tier1_blockers(with_assertion(base, 'C05SourceExternalCoverage', 'INCONCLUSIVE')), [])
        # the prefix is resolved only on the C05 row; elsewhere the name is not proof depth
        self.assertTrue(S.tier1_blockers(with_assertion(passing(), 'C05SourceExternalCoverage', 'INCONCLUSIVE')))
        self.assertTrue(S.tier1_blockers(with_assertion(base, 'C05SourceRawFinalAbsent', 'INCONCLUSIVE')))

    def test_activation_rows_need_their_outcome_assertions(self):
        result = passing('A01')
        self.assertTrue(any(b.startswith('Missing:') for b in S.tier1_blockers(result)))
        required = S.ACTIVATION_OUTCOME & Q.activation_required_assertions('A01')
        self.assertTrue(required)
        for name in required:
            result = with_assertion(result, name, 'PASS')
        self.assertEqual(S.tier1_blockers(result), [])
        self.assertEqual(S.tier1_blockers(with_assertion(result, 'PromotionTraceForSameFileId', 'INCONCLUSIVE')), [])
        self.assertTrue(S.tier1_blockers(with_assertion(result, 'NewWritableOpenDenied', 'INCONCLUSIVE')))
        self.assertTrue(S.tier1_blockers(with_assertion(result, 'PromotionTraceForSameFileId', 'FAIL')))

    def test_latency_failures_never_block(self):
        result = passing()
        result['Trials'][0]['Latency'] = [{'Class': 'close', 'Verdict': 'FAIL', 'Samples': []}]
        self.assertEqual(S.tier1_blockers(with_assertion(result, 'C01UnheldLatency', 'FAIL')), [])

    def test_latency_only_fail_verdicts_do_not_block(self):
        # The harness folds a latency budget miss into the trial and case verdicts (S00 boot-verifier w13220521: flush max 2246 ms).
        result = latency_fail(passing())
        self.assertEqual(S.tier1_blockers(result), [])
        shaped_like_the_harness = latency_fail(passing())
        shaped_like_the_harness['Trials'][0]['Latency'] = {'Verdict': 'FAIL', 'P95Ms': 56.9, 'MaxMs': 2246.8}
        self.assertEqual(S.tier1_blockers(shaped_like_the_harness), [])

    def test_a_fail_with_any_other_cause_still_blocks(self):
        result = with_assertion(latency_fail(passing()), 'C01RawFinalAbsent', 'FAIL')
        self.assertTrue(S.tier1_blockers(result))
        result = latency_fail(passing())
        result['Trials'][0]['Errors'] = ['x']
        self.assertTrue(S.tier1_blockers(result))
        result = latency_fail(passing())
        result['Trials'][0]['Predicate']['Verdict'] = 'FAIL'
        self.assertTrue(S.tier1_blockers(result))
        result = latency_fail(passing())
        result['Errors'] = ['x']
        self.assertTrue(S.tier1_blockers(result))
        result = latency_fail(passing())
        result['ForbiddenByteCount'] = 1
        self.assertTrue(S.tier1_blockers(result))

    def test_a_fail_verdict_without_latency_evidence_is_not_downgraded(self):
        result = passing()
        result['Trials'][0]['Verdict'] = 'FAIL'
        self.assertTrue(S.tier1_blockers(result))
        result = passing()
        result['Verdict'] = 'FAIL'
        self.assertTrue(S.tier1_blockers(result))
        # a case-level FAIL that no latency downgrade explains stays FAIL even when a trial carries latency evidence
        result = passing()
        result['Verdict'] = 'FAIL'
        result['Trials'][0]['Latency'] = [{'Class': 'close', 'Verdict': 'PASS', 'Samples': []}]
        self.assertTrue(S.tier1_blockers(result))


class TierTwoTests(unittest.TestCase):
    def test_latency_is_excluded_but_everything_else_is_not(self):
        result = passing(mode='runtime-verifier')
        self.assertEqual(S.tier2_blockers(result), [])
        result['Trials'][0]['Latency'] = [{'Class': 'close', 'Verdict': 'FAIL', 'Samples': []}]
        self.assertEqual(S.tier2_blockers(with_assertion(result, 'C01UnheldLatency', 'INCONCLUSIVE')), [])
        self.assertTrue(S.tier2_blockers(with_assertion(passing(mode='runtime-verifier'), 'ActualServiceTimelines', 'INCONCLUSIVE')))
        self.assertTrue(S.tier2_blockers(with_assertion(passing(mode='runtime-verifier'), 'C01RawFinalAbsent', 'FAIL')))

    def test_latency_only_fail_verdicts_are_excluded_but_other_fails_are_not(self):
        self.assertEqual(S.tier2_blockers(latency_fail(passing(mode='runtime-verifier'))), [])
        self.assertTrue(S.tier2_blockers(with_assertion(latency_fail(passing(mode='runtime-verifier')), 'C01RawFinalAbsent', 'FAIL')))


class LatencyReportTests(unittest.TestCase):
    def test_report_uses_unheld_non_cold_samples_only(self):
        result = passing()
        samples = [{'Cold': True, 'Held': False, 'Ms': 9999}, {'Cold': False, 'Held': True, 'Ms': 9999}]
        samples += [{'Cold': False, 'Held': False, 'Ms': n} for n in range(1, 101)]
        result['Trials'][0]['Latency'] = [{'Class': 'close', 'Verdict': 'PASS', 'Samples': samples}]
        self.assertEqual(S.latency_report(result), {'close': {'N': 100, 'P50': 51, 'P95': 96, 'Max': 100}})


if __name__ == '__main__':
    unittest.main()
