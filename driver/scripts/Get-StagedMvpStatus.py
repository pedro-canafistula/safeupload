#!/usr/bin/env python3
"""MVP gate status across every suite run of one build pair (driver + service).

Usage: Get-StagedMvpStatus.py <driver source commit> <agent source commit> [--strict] [--json OUT]

Default is the two-tier gate the owner chose on 2026-10-08 (MVP-PLAN "two-tier MVP gate"); --strict
keeps the earlier all-proofs-in-all-modes verdict (latency still needs its dedicated evidence).
  Tier 1, every cell (ordinary, runtime-verifier, boot-verifier): identity/provenance of the run, clean
    restoration, ForbiddenByteCount 0, no error, no FAIL anywhere, and the row's outcome proofs PASS: every
    assertion must PASS except the trace and coverage depth proofs (INCONCLUSIVE tolerated); for A01-A04 only
    the activation outcome assertions are required.
  Tier 2, runtime-verifier cells: the full recomputed MVP gate (all proofs), except latency.
  Latency never blocks; it is reported from the retained case.json files.

Batches run one case per runner invocation, possibly on several debuggees, so no single suite
index can show MvpSuite=PASS. A cell (row, mode) passes when some run of that exact build pair
(source commits and signed driver, Inspector, service package and tree hashes) has a retained
case.json whose hash matches its index entry, whose row revision equals the current table's,
whose restoration is clean, ForbiddenByteCount is 0, and whose MVP gate, recomputed here with the
run's own pinned latency evidence, passes. Harness-only fixes therefore keep earlier passes of
an unchanged row contract; a product rebuild or a row revision change does not.

Dedicated unheld latency is a separate experiment. When a run passes everything but its latency
rows, a retained dedicated-latency.json of the same write path, mode and build hashes (checked by
the runner's own mvp_latency_passed) may be joined here; the joined file is named in the output.
"""
import argparse
import copy
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('runner', ROOT / 'driver/scripts/Invoke-StagedInvariantQualification.py')
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)
PAIR_KEYS = ('SourceCommit', 'AgentSourceCommit', 'SignedSha256', 'ServiceTreeSha256')


def latency_only(item):
    blockers = item.get('MvpBlockers') or []
    return bool(blockers) and all(b.endswith('UnheldLatency') or b.startswith('Latency:') for b in blockers)

PROOF_DEPTH = frozenset(Q.MVP_DEFERRED_EXACT | {'ActualServiceTimelines', 'NotificationExpectation', 'DedicatedLatencyOnly', 'C05DenialLedger'})
PROOF_DEPTH_SUFFIXES = ('PublicationAndTemporalCoverage', 'HandBackSafeRelativeCreation', 'UnheldLatency')
ACTIVATION_OUTCOME = frozenset(('NewWritableOpenDenied', 'NewWritableSectionDenied', 'PostPromotionRawDestinationUnchanged',
                                'PostPromotionUnapprovedWriteRoutedToOwnedStream', 'ServiceReadinessReadyAfterPromotion',
                                'FreeAndProtectedAfterLastHolder', 'NoObservedReadyWhileHolderLives'))
ACTIVATION_ROWS = ('A01', 'A02', 'A03', 'A04')


def is_latency(name):
    return name.endswith('UnheldLatency') or name.startswith('Latency:') or name == 'DedicatedLatencyOnly'


def without_latency(result):
    """Copy of a case result with every latency measurement and latency assertion removed (latency is reported, never gating)."""
    result = copy.deepcopy(result)
    for trial in result.get('Trials', []):
        trial['Latency'] = []
        trial['Assertions'] = [a for a in trial.get('Assertions', []) if not is_latency(a.get('Name', ''))]
        predicate = trial.get('Predicate')
        if isinstance(predicate, dict):
            predicate['Assertions'] = [a for a in predicate.get('Assertions', []) if not is_latency(a.get('Name', ''))]
    return result


def proof_depth(name, case_id):
    """True when an INCONCLUSIVE verdict of this assertion is a missing trace/coverage proof, not a missing outcome."""
    base = name[len('C05Source'):] if case_id == 'C05-denied-external-rename' and name.startswith('C05Source') else name
    if base in PROOF_DEPTH or any(base != s and base.endswith(s) for s in PROOF_DEPTH_SUFFIXES):
        return True
    return case_id in ACTIVATION_ROWS and base not in ACTIVATION_OUTCOME and base not in ('LiveTaintFlags', 'Disposal')


def has_failure(value):
    if isinstance(value, dict):
        return value.get('Verdict') == 'FAIL' or bool(value.get('Errors')) or any(has_failure(v) for v in value.values())
    return isinstance(value, list) and any(has_failure(v) for v in value)


def tier1_blockers(result):
    """Blockers of the all-cells tier: no leak, clean restoration, no error or FAIL, and the row's outcome proofs pass."""
    result = without_latency(result)
    case_id = result.get('CaseId')
    blockers = set()
    restoration = result.get('Restoration') or {}
    if (result.get('Schema') != 'StagedInvariantSuite/2' or result.get('AuthoritativeCaseExport') is not True
            or result.get('CaseStatus') != 'READY' or result.get('Verdict') not in ('PASS', 'INCONCLUSIVE')
            or type(result.get('ForbiddenByteCount')) is not int or result['ForbiddenByteCount'] != 0 or result.get('Errors')):
        blockers.add('CasePrerequisites')
    if (restoration.get('Known') is not True or restoration.get('GuestChecks') is not True or not restoration.get('IndependentBaseline')
            or not re.fullmatch(r'[A-F0-9]{64}', restoration.get('IndependentBaselineSha256', ''))):
        blockers.add('RestorationClean')
    trials = result.get('Trials', [])
    if len(trials) != 1:
        blockers.add('Trials')
    for trial in trials:
        if (trial.get('Verdict') not in ('PASS', 'INCONCLUSIVE') or type(trial.get('ForbiddenByteCount')) is not int
                or trial['ForbiddenByteCount'] != 0 or trial.get('Disposal', {}).get('Status') != 'OK' or trial.get('Errors')):
            blockers.add('TrialPrerequisites')
        predicate = trial.get('Predicate') or {}
        if predicate.get('Verdict', 'PASS') not in ('PASS', 'INCONCLUSIVE') or predicate.get('Errors'):
            blockers.add('PredicatePrerequisites')
        assertions = trial.get('Assertions', []) + predicate.get('Assertions', [])
        if not assertions:
            blockers.add('Assertions')
        taint = [a for a in trial.get('Assertions', []) if a.get('Name') == 'LiveTaintFlags']
        if len(taint) != 1 or taint[0].get('Verdict') != 'PASS':
            blockers.add('LiveTaintFlags')
        for assertion in assertions:
            name = assertion.get('Name', '')
            if assertion.get('Verdict') == 'PASS' or (assertion.get('Verdict') == 'INCONCLUSIVE' and proof_depth(name, case_id)):
                continue
            blockers.add(name or 'UnnamedAssertion')
        if case_id in ACTIVATION_ROWS:
            required = ACTIVATION_OUTCOME & Q.activation_required_assertions(case_id)
            blockers.update('Missing:' + n for n in required - {a.get('Name') for a in assertions})
    if has_failure(result):
        blockers.add('FailureOrErrorsInEvidence')
    return sorted(blockers)


def tier2_blockers(result):
    """Blockers of the runtime-verifier tier: the full recomputed MVP gate, latency excluded."""
    return Q.mvp_case_gate(without_latency(result), None)['MvpBlockers']


def latency_report(result):
    """Per write-path class: sample count, median, p95 and max in ms over unheld, non-cold samples (informational)."""
    report = {}
    for trial in result.get('Trials', []):
        for item in trial.get('Latency', []):
            ms = sorted(s['Ms'] for s in item.get('Samples', []) if not s.get('Cold') and not s.get('Held') and isinstance(s.get('Ms'), (int, float)))
            if ms:
                report[str(item.get('Class'))] = {'N': len(ms), 'P50': ms[len(ms) // 2], 'P95': ms[min(len(ms) - 1, int(len(ms) * 0.95))], 'Max': ms[-1]}
    return report


def verified_result(item, rows):
    """(parsed case.json, None) when it is the retained, hash-matching, current-revision result of the index entry, else (None, reason)."""
    path = Path(item.get('Result', ''))
    if not path.is_file() or Q.sha(path) != item.get('ResultSha256'):
        return None, 'case.json missing or hash differs from index'
    result = json.loads(path.read_text('utf-8-sig'))
    if result.get('CaseId') != item['CaseId'] or result.get('Mode') != item['Mode']:
        return None, 'case.json identity differs from index'
    if result.get('CaseRevision') != rows[item['CaseId']]['Revision']:
        return None, f"row revision {result.get('CaseRevision')} is not current {rows[item['CaseId']]['Revision']}"
    if result.get('ForbiddenByteCount') != 0 or result.get('Restoration', {}).get('Known') is not True:
        return None, 'forbidden bytes or restoration not proven'
    return result, None


def tiered_cell(item, rows):
    """(None, latency report) when the result qualifies its cell under the two-tier gate, else (reason, report)."""
    result, reason = verified_result(item, rows)
    if result is None:
        return reason, {}
    runtime = item['Mode'] == 'runtime-verifier'
    blockers = tier2_blockers(result) if runtime else tier1_blockers(result)
    report = latency_report(result)
    if blockers:
        return ('Tier2' if runtime else 'Tier1') + 'Blockers=' + ','.join(blockers), report
    return None, report


def cell_pass(item, index, rows, latency_files):
    """(None, joined latency file or None) when the outcome qualifies its cell, else (reason, None)."""
    if item.get('MvpGatePassed') is not True and not latency_only(item):
        return 'MvpBlockers=' + ','.join(item.get('MvpBlockers') or [item.get('Reason') or item.get('Verdict', '?')]), None
    result, reason = verified_result(item, rows)
    if result is None:
        return reason, None
    pinned = index.parent / (index.name.replace('-index.txt', '-inputs')) / 'mvp-latency-evidence.json'
    record = json.loads(pinned.read_text('utf-8-sig')) if pinned.is_file() else None
    if Q.mvp_case_gate(result, record).get('MvpGatePassed') is True:
        return None, None
    for candidate in latency_files:
        if Q.mvp_case_gate(result, json.loads(candidate.read_text('utf-8-sig'))).get('MvpGatePassed') is True:
            return None, str(candidate.relative_to(ROOT))
    return 'MvpBlockers=' + ','.join(item.get('MvpBlockers') or []) + ' (no matching dedicated latency)', None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('source_commit')
    parser.add_argument('agent_commit')
    parser.add_argument('--json', type=Path)
    parser.add_argument('--strict', action='store_true', help='all proofs in all modes, latency needs dedicated evidence')
    args = parser.parse_args()
    source = Q.git('rev-parse', '--verify', args.source_commit + '^{commit}').decode().strip()
    agent = Q.git('rev-parse', '--verify', args.agent_commit + '^{commit}').decode().strip()
    rows = Q.table_rows(Q.SCRIPTS / 'StagedInvariantCases.psd1')
    required = sorted(Q.mvp_required_rows(rows))
    cells = {(case, mode): {'Pass': None, 'Last': None} for case in required for mode in Q.MODES}
    pair = None
    latency_files = sorted((ROOT / 'driver/evidence').glob('*/*-artifacts/dedicated-latency.json'))
    indices = sorted((ROOT / 'driver/evidence').glob('*/phase4-suite-*-index.txt'), key=lambda p: p.stat().st_mtime)
    for index in indices:
        lines = index.read_text().splitlines()
        if len(lines) < 2 or lines[0] != 'Schema=StagedInvariantSuiteIndex/1':
            continue
        provenance = json.loads(lines[1])
        if provenance.get('SourceCommit') != source or provenance.get('AgentSourceCommit') != agent:
            continue
        identity = {k: provenance.get(k) for k in PAIR_KEYS}
        if pair is None:
            pair = identity
        Q.require(identity == pair, 'Two different builds claim the same source commits: ' + str(index))
        for line in lines[2:]:
            if not line.startswith('{'):
                continue
            item = json.loads(line)
            key = (item.get('CaseId'), item.get('Mode'))
            if key not in cells:
                continue
            run = item.get('RunName') or index.name
            run_provenance = index.parent / (run + '-provenance.txt')
            if run_provenance.is_file() and json.loads(run_provenance.read_text()).get('Parameters', {}).get('DedicatedUnheldLatency'):
                continue  # a dedicated latency experiment never qualifies a functional cell; it is joined above
            if args.strict:
                reason, joined = cell_pass(item, index, rows, latency_files)
                report = {}
            else:
                reason, report = tiered_cell(item, rows)
                joined = None
            entry = {'Run': run, 'Debuggee': provenance.get('Debuggee', {}).get('Domain', 'win10-debug'), 'Index': str(index.relative_to(ROOT)),
                     'JoinedLatency': joined, 'Latency': report}
            if reason is None:
                cells[key]['Pass'] = entry
            cells[key]['Last'] = dict(entry, Verdict=item.get('Verdict'), Reason=reason)
    passed = sum(1 for c in cells.values() if c['Pass'])
    for mode in Q.MODES:
        done = sum(1 for case in required if cells[(case, mode)]['Pass'])
        tier = 'strict' if args.strict else ('tier 2: all proofs, latency excluded' if mode == 'runtime-verifier' else 'tier 1: outcome proofs')
        print(f'== {mode} ({tier}) {done}/{len(required)}')
        for case in required:
            cell = cells[(case, mode)]
            if cell['Pass']:
                joined = f" + latency {cell['Pass']['JoinedLatency']}" if cell['Pass']['JoinedLatency'] else ''
                print(f"  [x] {case}: {cell['Pass']['Run']} ({cell['Pass']['Debuggee']}){joined}")
            elif cell['Last']:
                print(f"  [ ] {case}: last {cell['Last']['Run']} {cell['Last']['Verdict']} - {cell['Last']['Reason']}"[:300])
            else:
                print(f'  [ ] {case}: not run on this build pair')
    print(f'MvpCells={passed}/{len(cells)}')
    print('MvpSuite=' + ('PASS' if passed == len(cells) else 'FAIL') + ('' if args.strict else ' (two-tier gate; --strict for the all-proofs verdict)'))
    if not args.strict:  # latency is informational: worst p95 and max per write-path class over the qualifying cells
        worst = {}
        for cell in cells.values():
            for name, stats in ((cell['Pass'] or {}).get('Latency') or {}).items():
                w = worst.setdefault(name, {'P95': 0, 'Max': 0, 'Cells': 0})
                w['P95'], w['Max'], w['Cells'] = max(w['P95'], stats['P95']), max(w['Max'], stats['Max']), w['Cells'] + 1
        for name, w in sorted(worst.items()):
            print(f"Latency {name}: worst p95 {w['P95']} ms, worst max {w['Max']} ms over {w['Cells']} cells (informational)")
    if args.json:
        Q.write_new(args.json, json.dumps({'Schema': 'StagedMvpStatus/1', 'BuildPair': pair,
                                           'Cells': [dict(CaseId=c, Mode=m, **v) for (c, m), v in cells.items()],
                                           'MvpCells': passed, 'Required': len(cells),
                                           'MvpSuite': passed == len(cells)}, indent=2) + '\n')
    return 0 if passed == len(cells) else 1


if __name__ == '__main__':
    raise SystemExit(main())
