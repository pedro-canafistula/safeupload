#!/usr/bin/env python3
"""MVP gate status across every suite run of one build pair (driver + service).

Usage: Get-StagedMvpStatus.py <driver source commit> <agent source commit> [--json OUT]

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
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('runner', ROOT / 'driver/scripts/Invoke-StagedInvariantQualification.py')
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)
PAIR_KEYS = ('SourceCommit', 'AgentSourceCommit', 'SignedSha256', 'ServiceTreeSha256')


def latency_only(item):
    blockers = item.get('MvpBlockers') or []
    return bool(blockers) and all(b.endswith('UnheldLatency') or b.startswith('Latency:') for b in blockers)


def cell_pass(item, index, rows, latency_files):
    """(None, joined latency file or None) when the outcome qualifies its cell, else (reason, None)."""
    if item.get('MvpGatePassed') is not True and not latency_only(item):
        return 'MvpBlockers=' + ','.join(item.get('MvpBlockers') or [item.get('Reason') or item.get('Verdict', '?')]), None
    path = Path(item.get('Result', ''))
    if not path.is_file() or Q.sha(path) != item.get('ResultSha256'):
        return 'case.json missing or hash differs from index', None
    result = json.loads(path.read_text('utf-8-sig'))
    if result.get('CaseId') != item['CaseId'] or result.get('Mode') != item['Mode']:
        return 'case.json identity differs from index', None
    if result.get('CaseRevision') != rows[item['CaseId']]['Revision']:
        return f"row revision {result.get('CaseRevision')} is not current {rows[item['CaseId']]['Revision']}", None
    if result.get('ForbiddenByteCount') != 0 or result.get('Restoration', {}).get('Known') is not True:
        return 'forbidden bytes or restoration not proven', None
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
            reason, joined = cell_pass(item, index, rows, latency_files)
            entry = {'Run': run, 'Debuggee': provenance.get('Debuggee', {}).get('Domain', 'win10-debug'), 'Index': str(index.relative_to(ROOT)),
                     'JoinedLatency': joined}
            if reason is None:
                cells[key]['Pass'] = entry
            cells[key]['Last'] = dict(entry, Verdict=item.get('Verdict'), Reason=reason)
    passed = sum(1 for c in cells.values() if c['Pass'])
    for mode in Q.MODES:
        print(f'== {mode}')
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
    print('MvpSuite=' + ('PASS' if passed == len(cells) else 'FAIL'))
    if args.json:
        Q.write_new(args.json, json.dumps({'Schema': 'StagedMvpStatus/1', 'BuildPair': pair,
                                           'Cells': [dict(CaseId=c, Mode=m, **v) for (c, m), v in cells.items()],
                                           'MvpCells': passed, 'Required': len(cells),
                                           'MvpSuite': passed == len(cells)}, indent=2) + '\n')
    return 0 if passed == len(cells) else 1


if __name__ == '__main__':
    raise SystemExit(main())
