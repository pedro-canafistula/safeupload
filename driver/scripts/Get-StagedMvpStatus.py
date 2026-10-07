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


def cell_pass(item, index, rows):
    """None when the outcome qualifies its cell, else the reason it does not."""
    if item.get('MvpGatePassed') is not True:
        return 'MvpBlockers=' + ','.join(item.get('MvpBlockers') or [item.get('Reason') or item.get('Verdict', '?')])
    path = Path(item.get('Result', ''))
    if not path.is_file() or Q.sha(path) != item.get('ResultSha256'):
        return 'case.json missing or hash differs from index'
    result = json.loads(path.read_text('utf-8-sig'))
    if result.get('CaseId') != item['CaseId'] or result.get('Mode') != item['Mode']:
        return 'case.json identity differs from index'
    if result.get('CaseRevision') != rows[item['CaseId']]['Revision']:
        return f"row revision {result.get('CaseRevision')} is not current {rows[item['CaseId']]['Revision']}"
    if result.get('ForbiddenByteCount') != 0 or result.get('Restoration', {}).get('Known') is not True:
        return 'forbidden bytes or restoration not proven'
    latency = index.parent / (index.name.replace('-index.txt', '-inputs')) / 'mvp-latency-evidence.json'
    record = json.loads(latency.read_text('utf-8-sig')) if latency.is_file() else None
    if Q.mvp_case_gate(result, record).get('MvpGatePassed') is not True:
        return 'recomputed MVP gate fails'
    return None


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
            reason = cell_pass(item, index, rows)
            entry = {'Run': run, 'Debuggee': provenance.get('Debuggee', {}).get('Domain', 'win10-debug'), 'Index': str(index.relative_to(ROOT))}
            if reason is None:
                cells[key]['Pass'] = entry
            cells[key]['Last'] = dict(entry, Verdict=item.get('Verdict'), Reason=reason)
    passed = sum(1 for c in cells.values() if c['Pass'])
    for mode in Q.MODES:
        print(f'== {mode}')
        for case in required:
            cell = cells[(case, mode)]
            if cell['Pass']:
                print(f"  [x] {case}: {cell['Pass']['Run']} ({cell['Pass']['Debuggee']})")
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
