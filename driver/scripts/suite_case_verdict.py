#!/usr/bin/env python3
"""Classify one batch case from local evidence; never contact the lab."""
import argparse
import json
from pathlib import Path


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field: ' + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('invalid JSON constant: ' + value)


def read_object(line):
    value = json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
    require(isinstance(value, dict), 'index JSON record must be an object')
    return value


def classify(evidence, runner_exit, tag, case, mode):
    require(runner_exit in (0, 1), f'runner exit {runner_exit}')
    # Match the wrapper's evidence/*/ filenames, without treating identifiers as glob syntax.
    for value in (tag, case, mode):
        require(value and not any(c in value for c in '/\\*?[]\r\n'), 'invalid case identifier')
    indexes = sorted(evidence.glob(f'*/phase4-suite-{tag}-index.txt'))
    require(len(indexes) == 1, f'expected exactly one index, found {len(indexes)}')
    lines = indexes[0].read_text(encoding='utf-8-sig').splitlines()
    # main() writes Schema, JSON provenance, one JSON outcome per case/mode, then five summary lines.
    # A batch invocation selects exactly one case/mode; missing or extra records are ambiguous evidence.
    require(len(lines) == 8 and lines[0] == 'Schema=StagedInvariantSuiteIndex/1',
            'missing, truncated or duplicate index records')
    read_object(lines[1])
    outcome = read_object(lines[2])
    name = f'boot-start-invariant-{case}-{mode}-{tag}'
    for field, expected in (('CaseId', case), ('Mode', mode), ('RunName', name),
                            ('Verdict', 'PASS'), ('GatePassed', True), ('MvpGatePassed', True),
                            ('RestorationClean', True), ('ForbiddenByteCount', 0)):
        require(type(outcome.get(field)) is type(expected) and outcome[field] == expected,
                f'{field} must be {expected!r}')
    # The selected gates summarize this case. The runner exits 0 only for the complete table and modes, which one
    # case per invocation never is: exit 1 is accepted only when that incomplete selection is the sole failure.
    require(lines[3] == 'SelectedInvariantGate=PASS', 'index summary must be SelectedInvariantGate=PASS')
    require(lines[6] == 'SelectedMvpGate=PASS', 'index summary must be SelectedMvpGate=PASS')
    table = ('Phase4Suite=PASS', 'CompleteTableAndModes=True') if runner_exit == 0 else \
        ('Phase4Suite=FAIL', 'CompleteTableAndModes=False')
    require(tuple(lines[4:6]) == table, f'runner exit {runner_exit} requires ' + ' and '.join(table))
    # MvpSuite assesses the whole required table, not this single selected case.
    require(lines[7] in ('MvpSuite=PASS', 'MvpSuite=FAIL'), 'missing or invalid MvpSuite summary')
    require(not list(evidence.glob(f'*/{name}-recovery-required.txt')), 'recovery-required marker present')
    restored = sorted(evidence.glob(f'*/{name}-final-restored-state.txt'))
    require(len(restored) == 1, f'expected exactly one restoration file, found {len(restored)}')
    restoration = restored[0].read_text(encoding='utf-8-sig').splitlines()
    for field in ('BaselineClean', 'ProcessCreationAuditRestored'):
        values = [line for line in restoration if line.startswith(field + '=')]
        require(values == [field + '=True'], field + ' must be exactly one True restoration line')
    return 'runner, case gates and independent restoration passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runner_exit', type=int)
    parser.add_argument('tag')
    parser.add_argument('case')
    parser.add_argument('mode')
    parser.add_argument('--evidence-root', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'evidence')
    args = parser.parse_args()
    try:
        reason = classify(args.evidence_root, args.runner_exit, args.tag, args.case, args.mode)
    except (OSError, ValueError) as error:
        print('CaseVerdict=FAIL reason=' + ' '.join(str(error).split()))
        return 1
    print('CaseVerdict=PASS reason=' + reason)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
