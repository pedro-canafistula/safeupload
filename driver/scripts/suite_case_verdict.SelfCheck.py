#!/usr/bin/env python3
"""Exercise batch verdicts and stop rules using synthetic evidence, never the lab."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
HELPER = SCRIPTS / 'suite_case_verdict.py'
WRAPPER = SCRIPTS / 'Invoke-StagedSuiteBatch.sh'
TAG, CASE, MODE = 'batchcheck1', 'C01-approve-existing', 'ordinary'


def passing_index(tag=TAG, case=CASE, mode=MODE):
    outcome = dict(CaseId=case, Mode=mode, RunName=f'boot-start-invariant-{case}-{mode}-{tag}',
                   Verdict='PASS', GatePassed=True, MvpGatePassed=True,
                   RestorationClean=True, ForbiddenByteCount=0)
    # Real index framing from main(); synthetic exit-zero evidence does not qualify a VM row.
    return ('Schema=StagedInvariantSuiteIndex/1\n' + json.dumps({'SourceCommit': 'synthetic'}) + '\n'
            + json.dumps(outcome) + '\nSelectedInvariantGate=PASS\nPhase4Suite=PASS\n'
            'CompleteTableAndModes=True\nSelectedMvpGate=PASS\nMvpSuite=FAIL\n')


class CaseVerdictControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='suite-case-verdict-')
        self.addCleanup(temporary.cleanup)
        self.evidence = Path(temporary.name)
        day = self.evidence / '2026-10-13'
        day.mkdir()
        self.index = day / f'phase4-suite-{TAG}-index.txt'
        self.index.write_text(passing_index(), encoding='utf-8')
        self.restored = day / f'boot-start-invariant-{CASE}-{MODE}-{TAG}-final-restored-state.txt'
        self.restored.write_text('BaselineClean=True\nProcessCreationAuditRestored=True\n', encoding='utf-8')

    def check(self, status, runner_exit=0, reason=None):
        run = subprocess.run([sys.executable, str(HELPER), str(runner_exit), TAG, CASE, MODE,
                              '--evidence-root', str(self.evidence)], text=True, capture_output=True)
        self.assertEqual(0 if status == 'PASS' else 1, run.returncode, run.stderr + run.stdout)
        self.assertEqual('', run.stderr)
        self.assertEqual(1, len(run.stdout.splitlines()))
        self.assertTrue(run.stdout.startswith(f'CaseVerdict={status} reason='), run.stdout)
        if reason:
            self.assertIn(reason, run.stdout)

    def change_outcome(self, **changes):
        lines = passing_index().splitlines()
        outcome = json.loads(lines[2])
        outcome.update(changes)
        lines[2] = json.dumps(outcome)
        self.index.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    def test_pass(self):
        self.check('PASS')

    def test_runner_exit_one_with_pass_index(self):
        self.check('FAIL', runner_exit=1, reason='runner exit 1 requires')

    def single_case_table(self, selected='PASS', mvp='PASS'):
        text = passing_index().replace('SelectedInvariantGate=PASS', 'SelectedInvariantGate=' + selected)
        text = text.replace('Phase4Suite=PASS\nCompleteTableAndModes=True', 'Phase4Suite=FAIL\nCompleteTableAndModes=False')
        self.index.write_text(text.replace('SelectedMvpGate=PASS', 'SelectedMvpGate=' + mvp), encoding='utf-8')

    def test_single_case_runner_exit_one_passes(self):
        # The actual runner exits 1 for every single-case selection: the table is incomplete.
        self.single_case_table()
        self.check('PASS', runner_exit=1)

    def test_single_case_exit_zero_contradicts_table(self):
        self.single_case_table()
        self.check('FAIL', runner_exit=0, reason='runner exit 0 requires')

    def test_single_case_selected_gate_failed(self):
        self.single_case_table(selected='FAIL')
        self.check('FAIL', runner_exit=1, reason='SelectedInvariantGate=PASS')

    def test_single_case_mvp_gate_failed(self):
        self.single_case_table(mvp='FAIL')
        self.check('FAIL', runner_exit=1, reason='SelectedMvpGate=PASS')

    def test_runner_exit_two(self):
        self.check('FAIL', runner_exit=2, reason='runner exit 2')

    def test_missing_index(self):
        self.index.unlink()
        self.check('FAIL', reason='index, found 0')

    def test_duplicate_index(self):
        day = self.evidence / '2026-10-14'
        day.mkdir()
        (day / self.index.name).write_text(passing_index(), encoding='utf-8')
        self.check('FAIL', reason='index, found 2')

    def test_truncated_json(self):
        lines = passing_index().splitlines()
        lines[2] = '{"Verdict":'
        self.index.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        self.check('FAIL', reason='Expecting value')

    def test_failed_verdict_with_pass_in_explanation(self):
        self.change_outcome(Verdict='FAIL', Reason='purge NTSTATUS PASS')
        self.check('FAIL', reason='Verdict must be')

    def test_recovery_required_marker(self):
        marker = self.restored.with_name(self.restored.name.replace('final-restored-state', 'recovery-required'))
        marker.touch()
        self.check('FAIL', reason='recovery-required marker')

    def test_restoration_missing(self):
        self.restored.unlink()
        self.check('FAIL', reason='restoration file, found 0')

    def test_restoration_baseline_false(self):
        self.restored.write_text('BaselineClean=False\nProcessCreationAuditRestored=True\n', encoding='utf-8')
        self.check('FAIL', reason='BaselineClean must be')

    def test_each_required_field_rejects_wrong_values_and_types(self):
        invalid = {'Verdict': ('INCONCLUSIVE', 'NOT_PASS'),
                   'GatePassed': (False, 'true', 1), 'MvpGatePassed': (False, 'true', 1),
                   'RestorationClean': (False, 'true', 1), 'ForbiddenByteCount': (1, False, '0', 0.0),
                   'CaseId': ('wrong-case',), 'Mode': ('wrong-mode',), 'RunName': ('wrong-tag',)}
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.change_outcome(**{field: value})
                    self.check('FAIL', reason=field + ' must be')
            with self.subTest(missing=field):
                lines = passing_index().splitlines()
                outcome = json.loads(lines[2])
                del outcome[field]
                lines[2] = json.dumps(outcome)
                self.index.write_text('\n'.join(lines) + '\n', encoding='utf-8')
                self.check('FAIL', reason=field + ' must be')

    def test_duplicate_json_field(self):
        self.index.write_text(passing_index().replace('"GatePassed": true',
                              '"GatePassed": false, "GatePassed": true'), encoding='utf-8')
        self.check('FAIL', reason='duplicate JSON field: GatePassed')

    def test_incomplete_or_duplicate_index_records(self):
        lines = passing_index().splitlines()
        for changed in (lines[:-1], lines[:3], lines[:3] + [lines[2]] + lines[3:]):
            with self.subTest(lines=len(changed)):
                self.index.write_text('\n'.join(changed) + '\n', encoding='utf-8')
                self.check('FAIL', reason='index records')

    def test_failed_summaries_cannot_pass(self):
        for field in ('SelectedInvariantGate', 'Phase4Suite', 'CompleteTableAndModes', 'SelectedMvpGate'):
            with self.subTest(field=field):
                passing = 'True' if field == 'CompleteTableAndModes' else 'PASS'
                self.index.write_text(passing_index().replace(field + '=' + passing, field + '=FAIL'), encoding='utf-8')
                table = field in ('Phase4Suite', 'CompleteTableAndModes')
                self.check('FAIL', reason='runner exit 0 requires' if table else 'index summary must be ' + field)

    def test_duplicate_or_truncated_restoration(self):
        for text in ('BaselineClean=True\n', 'BaselineClean=True\nProcessCreationAuditRestored=False\n',
                     'BaselineClean=True\nProcessCreationAuditRestored=True;PASS\n',
                     'BaselineClean=True\nBaselineClean=False\nProcessCreationAuditRestored=True\n',
                     'BaselineClean=True\nProcessCreationAuditRestored=True\nProcessCreationAuditRestored=True\n'):
            with self.subTest(text=text):
                self.restored.write_text(text, encoding='utf-8')
                self.check('FAIL', reason='restoration line')
        self.restored.write_text('BaselineClean=True\nProcessCreationAuditRestored=True\n', encoding='utf-8')
        day = self.evidence / '2026-10-14'
        day.mkdir()
        (day / self.restored.name).write_bytes(self.restored.read_bytes())
        self.check('FAIL', reason='restoration file, found 2')

    def test_restoration_bom_and_crlf(self):
        self.restored.write_bytes(b'\xef\xbb\xbfBaselineClean=True\r\nProcessCreationAuditRestored=True\r\n')
        self.check('PASS')


class BatchWrapperControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='suite-batch-wrapper-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        scripts = self.root / 'driver/scripts'
        scripts.mkdir(parents=True)
        for path in (WRAPPER, HELPER, SCRIPTS / 'debuggees.txt'):
            shutil.copyfile(path, scripts / path.name)
        (scripts / 'image-store.sh').write_text('# Offline fixture; no image access.\n')
        (scripts / 'run-disk.sh').write_text('''# Offline fixture; no VM or disk access.
run_disk_begin() { echo "begin $2" >> calls.txt; }
run_disk_end() { echo "end $2" >> calls.txt; echo "RunDiskBaseUntouched=${MOCK_BASE_UNTOUCHED:-True}"; }
''')
        (scripts / 'remote_ps.py').write_text("import sys\nsys.stdin.read()\nprint('BaselineClean=True\\nGuestClockSynced=True')\n")
        (scripts / 'Invoke-StagedInvariantQualification.py').write_text('''import json, os, pathlib, sys
tag = sys.argv[1]
case = sys.argv[sys.argv.index('--cases') + 1]
mode = sys.argv[sys.argv.index('--modes') + 1]
with open('calls.txt', 'a') as stream: stream.write('runner ' + tag + '\\n')
evidence = pathlib.Path('driver/evidence/synthetic')
evidence.mkdir(exist_ok=True)
name = f'boot-start-invariant-{case}-{mode}-{tag}'
outcome = dict(CaseId=case, Mode=mode, RunName=name, Verdict=os.environ.get('MOCK_VERDICT', 'PASS'),
               GatePassed=True, MvpGatePassed=True, RestorationClean=True, ForbiddenByteCount=0)
text = 'Schema=StagedInvariantSuiteIndex/1\\n{}\\n' + json.dumps(outcome) + '\\n'
text += 'SelectedInvariantGate=PASS\\nPhase4Suite=PASS\\nCompleteTableAndModes=True\\nSelectedMvpGate=PASS\\nMvpSuite=FAIL\\n'
(evidence / f'phase4-suite-{tag}-index.txt').write_text(text)
(evidence / (name + '-final-restored-state.txt')).write_text('BaselineClean=True\\nProcessCreationAuditRestored=True\\n')
sys.exit(int(os.environ.get('MOCK_RUNNER_EXIT', '0')))
''')
        # A shell function intercepts every virsh call, so the real command is never executed.
        self.mock = self.root / 'offline-shell.sh'
        self.mock.write_text('''virsh() {
    echo "$*" >> peer-checks.txt
    [ "$*" = '-c qemu:///system domstate win10-debug2' ] || return 99
    [ "${MOCK_PEER_STATE:-shut off}" != unreadable ] || return 1
    echo "${MOCK_PEER_STATE:-shut off}"
}
''')

    def run_batch(self, expected_code, target='win10-debug3', **changes):
        env = os.environ.copy()
        for key in ('SAFEUPLOAD_DEBUGGEE', 'EXTRA_RUNNER_ARGS'):
            env.pop(key, None)
        env.update(BASH_ENV=str(self.mock))
        if target is not None:
            env['SAFEUPLOAD_DEBUGGEE'] = target
        env.update(changes)
        run = subprocess.run(['bash', str(self.root / 'driver/scripts' / WRAPPER.name),
                              'driver-label', 'driver-commit', 'agent-label', 'agent-commit', MODE,
                              'batchcheck', CASE, CASE], cwd=self.root, env=env, text=True, capture_output=True)
        self.assertEqual(expected_code, run.returncode, run.stdout + run.stderr)
        calls = self.root / 'calls.txt'
        return run.stdout, calls.read_text().splitlines() if calls.exists() else []

    def test_bash_syntax(self):
        run = subprocess.run(['bash', '-n', str(WRAPPER)], text=True, capture_output=True)
        self.assertEqual(0, run.returncode, run.stderr)

    def test_all_cases_pass(self):
        output, calls = self.run_batch(0)
        self.assertIn('batch complete: 2/2 PASS', output)
        self.assertEqual(['begin batchcheck1', 'runner batchcheck1', 'end batchcheck1',
                          'begin batchcheck2', 'runner batchcheck2', 'end batchcheck2'], calls)

    def test_failed_verdict_discards_disk_then_stops(self):
        output, calls = self.run_batch(1, MOCK_VERDICT='FAIL')
        self.assertIn(f'STOP: {TAG} {CASE} failed: Verdict must be', output)
        self.assertNotIn('batch complete', output)
        self.assertEqual(['begin batchcheck1', 'runner batchcheck1', 'end batchcheck1'], calls)

    def test_failed_case_captures_guest_evidence_without_changing_the_outcome(self):
        # Diagnostic capture runs only for a failed case, before its disk is discarded; exit code and call order are unchanged.
        output, calls = self.run_batch(1, MOCK_VERDICT='FAIL')
        self.assertEqual(['begin batchcheck1', 'runner batchcheck1', 'end batchcheck1'], calls)
        self.assertIn(f'failure evidence for {TAG} {CASE}', output)
        self.assertLess(output.index('failure evidence for'), output.index('STOP:'))
        evidence = list((self.root / 'driver/evidence').glob(f'*/batch-{TAG}-failure-guest.txt'))
        self.assertEqual(1, len(evidence))
        self.assertTrue(list((self.root / 'driver/evidence').glob(f'*/batch-{TAG}-failure-domstate.txt')))

    def test_runner_exit_one_discards_disk_then_stops(self):
        output, calls = self.run_batch(1, MOCK_RUNNER_EXIT='1')
        self.assertIn('failed: runner exit 1', output)
        self.assertEqual(['begin batchcheck1', 'runner batchcheck1', 'end batchcheck1'], calls)

    def test_failed_cleanup_preserves_exit_three(self):
        output, calls = self.run_batch(3, MOCK_VERDICT='FAIL', MOCK_BASE_UNTOUCHED='False')
        self.assertIn('not discarded cleanly', output)
        self.assertEqual(['begin batchcheck1', 'runner batchcheck1', 'end batchcheck1'], calls)

    def test_missing_or_unapproved_target_refused_before_lab_calls(self):
        for target in (None, '', 'win10-debug', 'win10-debug2', 'win10-debug4'):
            with self.subTest(target=target):
                output, calls = self.run_batch(2, target=target)
                self.assertIn('approved: win10-debug3', output)
                self.assertEqual([], calls)
                self.assertFalse((self.root / 'peer-checks.txt').exists())

    def test_running_shared_address_peer_refused(self):
        output, calls = self.run_batch(2, MOCK_PEER_STATE='running')
        self.assertIn('win10-debug2 is running and shares 192.168.122.52 with win10-debug3', output)
        self.assertEqual([], calls)

    def test_unreadable_shared_address_peer_refused(self):
        output, calls = self.run_batch(2, MOCK_PEER_STATE='unreadable')
        self.assertIn('cannot determine state', output)
        self.assertEqual([], calls)

    def test_reused_tag_preserves_exit_six(self):
        evidence = self.root / 'driver/evidence/synthetic'
        evidence.mkdir(parents=True)
        (evidence / f'phase4-suite-{TAG}-index.txt').touch()
        output, calls = self.run_batch(6)
        self.assertIn('suite index already exists', output)
        self.assertEqual([], calls)
        self.assertFalse((self.root / 'peer-checks.txt').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
