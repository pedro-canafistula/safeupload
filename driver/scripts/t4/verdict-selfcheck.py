#!/usr/bin/env python3
"""Replay retained T4 evidence through the launcher's actual Python verdict.

Run from any directory: python3 driver/scripts/t4/verdict-selfcheck.py
No VM or native memory purge is invoked. The historical long row retains its
functional failures; this control checks memory verdicts, not qualification.
"""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[3]
launcher = (REPO / 'driver/scripts/Invoke-StageCycles.sh').read_text()
match = re.search(r"^python3 - .* <<'PY'\n(.*?)^PY$", launcher, re.M | re.S)
if not match:
    raise SystemExit('Actual launcher verdict unavailable')
source = match.group(1)


def replay(after, samples, cycles, handback='no', delete_attribution='no'):
    with tempfile.TemporaryDirectory(prefix='t4-verdict-control-') as directory:
        root = Path(directory)
        after_path = root / 'control-after.txt'
        samples_path = root / 'control-samples.jsonl'
        verdict_path = root / 'control-verdict.txt'
        after_path.write_text(after)
        samples_path.write_text(''.join(json.dumps(s) + '\n' for s in samples))
        run = subprocess.run([sys.executable, '-', str(after_path), str(samples_path),
                              str(verdict_path), str(cycles), 'verifier-from-boot', 'yes', '0', handback, delete_attribution],
                             input=source, text=True, capture_output=True)
        if run.returncode not in (0, 1) or not verdict_path.is_file():
            raise AssertionError(run.stderr or run.stdout)
        lines = verdict_path.read_text().splitlines()
        return {line.split()[0]: line for line in lines}, run.returncode


def retained(day, tag):
    prefix = REPO / 'driver/evidence' / day / tag
    after = Path(str(prefix) + '-after.txt').read_text(encoding='utf-8-sig')
    samples = [json.loads(line) for line in Path(str(prefix) + '-samples.jsonl').read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    return after, samples


def require(lines, name, status, fragment=None):
    line = lines.get(name, '')
    assert line.startswith(f'{name} {status} '), line
    assert fragment is None or fragment in line, line


short_after, short_samples = retained('2026-10-12', 'm2t4clean256b1')
short, code = replay(short_after, short_samples, 256)
require(short, 'T4PoolEndpoint', 'PASS')
require(short, 'T4PoolSlope', 'INFO', '461.600 B/cycle')
require(short, 'T4RegistryBounded', 'PASS')
require(short, 'T4ContextsReleased', 'INFO', 'purged sample missing')
assert 'T4PoolFlat' not in short and code == 0
for name in ('T4PoolEndpoint', 'T4PoolSlope', 'T4RegistryBounded'):
    print('m2t4clean256b1: ' + short[name])

long_after, long_samples = retained('2026-10-11', 'm2t4boot10k1011a2')
long, code = replay(long_after, long_samples, 10000)
require(long, 'T4PoolFlat', 'PASS', 'slope 1.501 B/cycle')
require(long, 'T4ContextsReleased', 'FAIL', 'purged sample missing')
require(long, 'T4CyclesCompleted', 'FAIL')
require(long, 'T4VersionsReleased', 'FAIL')
require(long, 'T4StageFilesDeleted', 'FAIL')
assert 'T4PoolEndpoint' not in long and code == 1
for name in ('T4PoolFlat', 'T4ContextsReleased'):
    print('m2t4boot10k1011a2: ' + long[name])

# Boundary and refusal controls use copies, never modify the retained evidence.
result_match = re.search(r'^RESULT=(.*)$', long_after, re.M)
result = json.loads(result_match.group(1))
start_live = long_samples[0]['TagSUfl']['NonPagedAllocs'] - long_samples[0]['TagSUfl']['NonPagedFrees']
purged = copy.deepcopy(result['Idle'])
purged['Label'] = 'purged'
purged['TagSUfl']['NonPagedAllocs'] = purged['TagSUfl']['NonPagedFrees'] + start_live + 2048
result['Purged'] = purged
result['Purge'] = [dict(Operation=operation, **{field: value}, NTSTATUS=0)
                   for operation, field, value in [('RtlAdjustPrivilege', 'Privilege', 13),
                                                  ('RtlAdjustPrivilege', 'Privilege', 5),
                                                  ('NtSetSystemInformation', 'Command', 2),
                                                  ('NtSetSystemInformation', 'Command', 3),
                                                  ('NtSetSystemInformation', 'Command', 4)]]


def changed_result(value):
    return long_after[:result_match.start(1)] + json.dumps(value) + long_after[result_match.end(1):]


lines, _ = replay(changed_result(result), long_samples + [purged], 10000)
require(lines, 'T4ContextsReleased', 'PASS')
purged['TagSUfl']['NonPagedAllocs'] += 1
lines, _ = replay(changed_result(result), long_samples + [purged], 10000)
require(lines, 'T4ContextsReleased', 'FAIL')
purged['TagSUfl']['NonPagedAllocs'] -= 1
for i in range(5):
    refused = copy.deepcopy(result)
    refused['Purge'][i]['NTSTATUS'] = -1073741727  # STATUS_PRIVILEGE_NOT_HELD
    lines, _ = replay(changed_result(refused), long_samples + [purged], 10000)
    require(lines, 'T4ContextsReleased', 'FAIL', 'purge NTSTATUS FAIL')
for label in ('cycle', 'settled', 'idle', 'purged'):
    oversized = copy.deepcopy(long_samples + [purged])
    sample = next(s for s in oversized if s['Label'] == label)
    sample['WriterState']['registryEntries'] = sample['WriterState']['registryCapacity'] + 1
    lines, _ = replay(changed_result(result), oversized, 10000)
    require(lines, 'T4RegistryBounded', 'FAIL')
capacity_failure = copy.deepcopy(result)
capacity_failure['Idle']['WriterState']['registryCapacityFailures'] = 1
lines, _ = replay(changed_result(capacity_failure), long_samples + [purged], 10000)
require(lines, 'T4RegistryBounded', 'FAIL')

# A contexts-only failure includes "purge NTSTATUS PASS" in its explanation.
# That text must never turn the FAIL status into a successful launcher exit.
healthy = json.loads(re.search(r'^RESULT=(.*)$', short_after, re.M).group(1))
healthy.update(Cycles=10000, Completed=10000, Attempted=10000)
healthy['Outcomes'] = {pattern + '-' + decision: {'Ok': count, 'Failed': 0}
                       for pattern in ('resave', 'new', 'replace', 'mapped')
                       for decision, count in [('approve', 1875), ('block', 625)]}
for label in ('Settled', 'AfterActorExit', 'Idle'):
    healthy[label]['Cycle'] = 10000
    for key in ('versionsCreated', 'versionsReleased', 'viewsReleased'):
        healthy[label]['StageWorker'][key] = 10000
healthy['Purge'] = copy.deepcopy(result['Purge'])
healthy['Purged'] = copy.deepcopy(purged)
healthy['Purged']['TagSUfl']['NonPagedAllocs'] += 1
healthy_samples = long_samples + [healthy['Purged']]
lines, code = replay(changed_result(healthy), healthy_samples, 10000)
require(lines, 'T4ContextsReleased', 'FAIL', 'purge NTSTATUS PASS')
assert [name for name, line in lines.items() if line.split()[1] == 'FAIL'] == ['T4ContextsReleased']
assert code == 1, 'Embedded PASS in a FAIL explanation must not make the row pass'
healthy['Purged']['TagSUfl']['NonPagedAllocs'] -= 1
lines, code = replay(changed_result(healthy), healthy_samples, 10000)
require(lines, 'T4ContextsReleased', 'PASS')
assert code == 0, 'The otherwise identical passing row must return success'
print('T4VerdictExitStatusControl=PASS; contexts-only failure returns 1 despite embedded PASS')

# Hand-back attribution diagnostic (non-qualifying): labelled, reports the release, never changes a gate line.
diagnostic = copy.deepcopy(healthy)
deleted_sample = copy.deepcopy(diagnostic['Purged']); deleted_sample['Label'] = 'handbacks-deleted'
deleted_sample['TagSUfl']['NonPagedFrees'] += 1200
repurged_sample = copy.deepcopy(deleted_sample); repurged_sample['Label'] = 'handbacks-deleted-purged'
repurged_sample['TagSUfl']['NonPagedFrees'] += 300
diagnostic['HandbackDiagnostic'] = {
    'Holders': [{'Category': 'Handbacks', 'Files': 1500, 'Holders': [], 'Error': None},
                {'Category': 'Journals', 'Files': 2000, 'Holders': [{'Pid': 4, 'App': 'x', 'Service': '', 'Type': 0}], 'Error': None}],
    'HandbacksDeleted': 1500, 'HandbackDeleteFailures': 0, 'HandbackDeleteErrors': [], 'HandbacksLeft': 0,
    'AfterDelete': deleted_sample, 'AfterDeletePurged': repurged_sample, 'Purge': copy.deepcopy(result['Purge'])}
diagnostic_samples = healthy_samples + [deleted_sample, repurged_sample]
lines, code = replay(changed_result(diagnostic), diagnostic_samples, 2000, 'yes')
require(lines, 'T4Diagnostic', 'INFO', 'non-qualifying')
require(lines, 'T4HandbackAttribution', 'INFO', 'released 1500); released per deleted hand-back 1.000')
require(lines, 'T4FileHolders', 'INFO')
undiagnosed, _ = replay(changed_result(diagnostic), diagnostic_samples, 2000)
assert 'T4Diagnostic' not in undiagnosed and 'T4HandbackAttribution' not in undiagnosed
assert {k: v for k, v in lines.items() if not k.startswith(('T4Diagnostic', 'T4Handback', 'T4FileHolders', 'T4Duration'))} == \
    {k: v for k, v in undiagnosed.items() if k != 'T4Duration'}, 'The diagnostic must not change any gate line'
missing, _ = replay(changed_result(healthy), healthy_samples, 2000, 'yes')
require(missing, 'T4HandbackAttribution', 'INFO', 'diagnostic result missing')
print('T4HandbackDiagnosticControl=PASS; labelled non-qualifying, release reported, gate lines unchanged')
# Delete attribution is INFO even when KD fails; no success/failure token in its text affects a gate.
for attribution in (None, {'CorpusCount': 256, 'Deleted': 255,
                         'DeleteErrors': [{'Path': 'synthetic.txt', 'Error': 'access denied'}],
                         'Errors': ['KD timeout; PASS is only text'],
                         'Snapshots': [{'Label': 'del-after', 'Counts': {'NewBlocks': None},
                                        'Classification': 'Unresolved', 'Errors': ['symbols missing']}]},
                        {'CorpusCount': 256, 'Deleted': 256, 'DeleteErrors': [],
                         'Snapshots': [{'Label': 'del-after',
                                        'Sessions': [{'Label': 'del-after-logical', 'Finished': False,
                                                      'Errors': ['Numeric expression missing; timeout']},
                                                     {'Label': 'del-after-poolfind', 'Finished': True}],
                                        'Counts': {'NewBlocks': 9, 'LogicalOutstanding': None,
                                                   'Anchors': 0, 'ParsedContexts': 7,
                                                   'ObservedVerifierSUflAllocations': 3},
                                        'Classification': 'Unresolved',
                                        'Errors': ['logical session failed; other sessions retained']}]}):
    diagnostic = copy.deepcopy(healthy)
    diagnostic['DeleteAttribution'] = attribution
    for handbacks in ('no', 'yes'):
        for failure in (False, True):
            diagnostic['BlockedBytesPublished'] = failure
            if attribution is not None:
                diagnostic['DeleteAttribution']['Mode'] = 'Handbacks' if handbacks == 'yes' else 'Corpus'
                diagnostic['DeleteAttribution']['ReleasePrecondition'] = {
                    'NearStart': not failure, 'ReleaseProxyObserved': not failure,
                    'IndividualContextReleaseConfirmed': False,
                    'StartSUfl': 300, 'BaselineSUfl': 330 if not failure else 600}
            observed, observed_code = replay(changed_result(diagnostic), healthy_samples, 256,
                                             handback=handbacks, delete_attribution='yes')
            original, original_code = replay(changed_result(diagnostic), healthy_samples, 256, handback=handbacks)
            require(observed, 'T4Diagnostic', 'INFO', 'non-qualifying')
            require(observed, 'T4DeleteAttribution', 'INFO', 'diagnostic result missing' if attribution is None else f"deleted {attribution['Deleted']}")
            if attribution is not None and handbacks == 'yes':
                require(observed, 'T4DeleteAttributionRelease', 'INFO', '"IndividualContextReleaseConfirmed": false')
            ignored = ('T4Diagnostic', 'T4DeleteAttribution')
            assert {k: v for k, v in observed.items() if not k.startswith(ignored)} == \
                {k: v for k, v in original.items() if not k.startswith(ignored)}
            assert observed_code == original_code
            if failure:
                require(observed, 'T4NoBlockedBytesPublished', 'FAIL')
                assert observed_code == 1
print('T4DeleteAttributionControl=PASS; corpus/combined modes non-qualifying, missing/failed/partially successful KD remains INFO, gate lines and exit unchanged')
# Preflight controls stop before artifact hashing, inventory, SSH or run_disk_begin.
# Even the valid option combination has deliberately absent product artifacts.
with tempfile.TemporaryDirectory(prefix='t4-delete-preflight-') as directory:
    root = Path(directory)
    (root / 'debuggers.zip').write_bytes(b'synthetic presence check only')
    (root / 'SafeUpload.pdb').write_bytes(b'synthetic presence check only')
    base = dict(os.environ, T4_MEMORY_TOOLS=directory, T4_DELETE_ATTRIBUTION='yes',
                T4_HANDBACK_DIAGNOSTIC='no', SAFEUPLOAD_DEBUGGEE='win10-debug3')
    cases = [({}, '256', 'verifier-from-boot', 'needs the signed driver'),
             ({'T4_MEMORY_TOOLS': ''}, '256', 'verifier-from-boot', 'Delete attribution requires'),
             ({'T4_HANDBACK_DIAGNOSTIC': 'yes'}, '256', 'verifier-from-boot', 'needs the signed driver'),
             ({}, '10000', 'verifier-from-boot', 'Delete attribution requires'),
             ({}, '256', 'runtime-verifier', 'Memory attribution requires'),
             ({}, '256', 'ordinary', 'Memory attribution requires'),
             ({'SAFEUPLOAD_DEBUGGEE': ''}, '256', 'verifier-from-boot', 'requires explicit'),
             ({'T4_HANDBACK_DIAGNOSTIC': 'yes', 'T4_MEMORY_TOOLS': ''}, '256', 'verifier-from-boot', 'Delete attribution requires'),
             ({'T4_DELETE_ATTRIBUTION': 'maybe'}, '256', 'verifier-from-boot', 'must be yes or no')]
    for overrides, count, mode, message in cases:
        run = subprocess.run(['bash', str(REPO / 'driver/scripts/Invoke-StageCycles.sh'),
                              'win10-debug3', 'offlineDel', str(root / 'absent.sys'), str(root / 'absent.zip'),
                              count, mode, '64'], env=dict(base, **overrides), capture_output=True, text=True, timeout=10)
        assert run.returncode == 2 and message in run.stdout, (overrides, run.stdout, run.stderr)
        assert '== run disk' not in run.stdout
print('T4DeletePreflightControl=PASS; 9 offline option/dependency controls, no VM contact')
print('T4VerdictSelfCheck=PASS; retained replay and context/registry refusal controls; Qualification=False')
