#!/usr/bin/env python3
"""Replay retained T4 evidence through the launcher's actual Python verdict.

Run from any directory: python3 driver/scripts/t4/verdict-selfcheck.py
No VM or native memory purge is invoked. The historical long row retains its
functional failures; this control checks memory verdicts, not qualification.
"""
import copy
import json
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


def replay(after, samples, cycles):
    with tempfile.TemporaryDirectory(prefix='t4-verdict-control-') as directory:
        root = Path(directory)
        after_path = root / 'control-after.txt'
        samples_path = root / 'control-samples.jsonl'
        verdict_path = root / 'control-verdict.txt'
        after_path.write_text(after)
        samples_path.write_text(''.join(json.dumps(s) + '\n' for s in samples))
        run = subprocess.run([sys.executable, '-', str(after_path), str(samples_path),
                              str(verdict_path), str(cycles), 'verifier-from-boot', 'yes', '0'],
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
print('T4VerdictSelfCheck=PASS; retained replay and context/registry refusal controls; Qualification=False')
