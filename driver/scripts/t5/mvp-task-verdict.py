#!/usr/bin/env python3
"""Derive MVP drop-1 A/C/D or Office B from exact T5 lines; never rewrite the full row.

Usage: mvp-task-verdict.py <tag-verdict.txt>
The launcher calls this after separate restoration, including when the full row
exits nonzero. PASS here describes this run's tasks, not final-pair qualification
in both modes. T5RunProfile selects BasicTasks (A/C/D) or OfficeExcel (B).
Legacy receipts without that line retain A/C/D. Word is a drop-1 limitation.
"""
import argparse
from pathlib import Path


COMMON = (
    'T5PairHashes', 'T5ModeReadback', 'T5GuestAlive', 'T5DriverLoaded',
    'T5ResultEvidence', 'T5ActorTaskStart', 'T5CasesCompleted',
    'T5RawObserver', 'T5RawEvidenceRetained', 'T5ObservedNoUnapprovedBytes',
    'T5JournalArchiveEvidence', 'T5WriterRegistryKnown',
    'T5StagingEmptyAfterRun', 'T5JournalSettledAfterRun', 'T5Restoration',
)
TASK_CASES = {
    'A': ('NotepadApprove', 'NotepadHandBack', 'NotepadEditApprove'),
    'B': ('ExcelSaveAsApprove', 'ExcelInPlaceApprove', 'ExcelCpfHandBack'),
    'C': ('ShellCopyIn', 'ShellMoveIn', 'ShellMoveWithin', 'PublicDeleteExplorer'),
    'D': ('ReadExisting',),
}


def dependencies(task):
    names = list(COMMON)
    if task == 'B':
        names.extend(('T5OfficeBase', 'T5OfficeAccount'))
    for case in TASK_CASES[task]:
        names.extend(('T5' + case, 'T5' + case + 'NoEmptyLeftover'))
        # Original Save As cases fold journal checks into their task line; their
        # Journal lines are INFO records. Workflow cases have a PASS/FAIL Journal.
        if case not in ('NotepadApprove', 'NotepadHandBack'):
            names.append('T5' + case + 'Journal')
    return tuple(names)


def evaluate(text, tasks=None):
    lines = {}
    for line in text.splitlines():
        fields = line.split(maxsplit=2)
        if fields:
            lines.setdefault(fields[0], []).append(line)
    outcomes = {}
    profiles = lines.get('T5RunProfile', [])
    profile_ok = not profiles or profiles in (['T5RunProfile INFO BasicTasks'], ['T5RunProfile INFO OfficeExcel'])
    if tasks is None:
        tasks = ('B',) if profiles == ['T5RunProfile INFO OfficeExcel'] else ('A', 'C', 'D') if profile_ok else tuple(TASK_CASES)
    report = [
        'MVPDrop1 INFO Per-run task outcomes; final matched pair still needs ordinary and runtime Verifier runs.',
        'HistoricalFullRow INFO The historical full-row verdict and its INCONCLUSIVE proof lines are unchanged and are not MVP task outcomes.',
        'HistoricalProof INFO T5CanonicalNoUnapprovedByte and *DeleteBarrier stay full-row requirements; sampled byte observations do not establish a canonical never-public proof.',
        'MVPScope INFO OfficeExcel runs only B on the Office base; BasicTasks runs A/C/D. Word is a documented drop-1 limitation.',
    ]
    for task in TASK_CASES:
        if task not in tasks:
            report.append(f'MVP{task} NOT_RUN outside this run profile')
            continue
        used = []
        statuses = []
        if not profile_ok:
            statuses.append('FAIL')
            used.append(f'MVP{task}Use FAIL T5RunProfile: unknown or duplicate profile')
        for name in dependencies(task):
            matches = lines.get(name, [])
            if len(matches) != 1:
                statuses.append('FAIL')
                used.append(f'MVP{task}Use FAIL {name}: expected exactly one line, found {len(matches)}')
                used.extend(f'MVP{task}Use SOURCE {line}' for line in matches)
                continue
            fields = matches[0].split(maxsplit=2)
            status = fields[1] if len(fields) > 1 else ''
            statuses.append(status if status in ('PASS', 'FAIL', 'INCONCLUSIVE') else 'FAIL')
            used.append(f'MVP{task}Use SOURCE {matches[0]}')
        outcome = 'FAIL' if 'FAIL' in statuses else 'INCONCLUSIVE' if 'INCONCLUSIVE' in statuses else 'PASS'
        outcomes[task] = outcome
        report.append(f'MVP{task} {outcome} cases={",".join(TASK_CASES[task])}; all listed dependencies must PASS')
        report.extend(used)
    return outcomes, '\n'.join(report) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('verdict', type=Path)
    args = parser.parse_args()
    try:
        text = args.verdict.read_text(encoding='utf-8')
    except OSError as exc:
        print('MVPInput FAIL ' + str(exc))
        text = ''
    outcomes, report = evaluate(text)
    print(report, end='')
    return 0 if all(status == 'PASS' for status in outcomes.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
