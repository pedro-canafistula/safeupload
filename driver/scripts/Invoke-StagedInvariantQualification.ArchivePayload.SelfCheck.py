#!/usr/bin/env python3
"""Offline controls for archive_payload_matches (host validation of archived journal payloads).

Run from any directory: python3 driver/scripts/Invoke-StagedInvariantQualification.ArchivePayload.SelfCheck.py
No VM is contacted. Positive control: a well-formed SUJA v1 frame inside a pack. Negative controls: every field the validator
must bind (offset, magic, version, length, header digest, record digest, retained bytes, bounds) is mutated and must fail.
The retained real pack from m2t4p1 is replayed when present (informational when absent)."""
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('qualification', ROOT / 'driver/scripts/Invoke-StagedInvariantQualification.py')
module = importlib.util.module_from_spec(spec)
sys.modules['qualification'] = module
spec.loader.exec_module(module)
matches = module.archive_payload_matches


def frame(payload, transfer=b'\x11' * 16, magic=0x414A5553, version=1, length=None, digest=None):
    length = len(payload) if length is None else length
    digest = hashlib.sha256(payload).digest() if digest is None else digest
    return struct.pack('<Iii', magic, version, length) + transfer + digest + payload


def container(*frames, pad=4096):
    return bytes(pad) + b''.join(frames)


def record(payload, offset=4096, **override):
    value = {'FrameOffset': offset, 'PhysicalPath': 'C:\\x\\00000001.pack', 'Length': len(payload),
             'Sha256': hashlib.sha256(payload).hexdigest().upper(), 'Bytes': list(payload)}
    value.update(override)
    return value


payload = b'{"State":5}' * 40
good = container(frame(payload))
checks = []


def check(name, condition):
    checks.append((name, bool(condition)))


check('positive', matches(good, record(payload)))
check('positive-second-frame', matches(container(frame(b'abc' * 10), frame(payload)), record(payload, offset=4096 + 60 + 30)))
check('negative-offset-shifted', not matches(good, record(payload, offset=4097)))
check('negative-offset-below-header', not matches(good, record(payload, offset=64)))
check('negative-offset-not-int', not matches(good, record(payload, offset='4096')) and not matches(good, record(payload, offset=True)))
check('negative-offset-past-end', not matches(good, record(payload, offset=len(good))))
check('negative-magic', not matches(container(frame(payload, magic=0x414A5554)), record(payload)))
check('negative-version', not matches(container(frame(payload, version=2)), record(payload)))
check('negative-header-length', not matches(container(frame(payload, length=len(payload) + 1)), record(payload)))
check('negative-record-length', not matches(good, record(payload, Length=len(payload) - 1)))
check('negative-zero-length', not matches(container(frame(b'', length=0)), record(b'', Length=0, Bytes=[])))
check('negative-header-digest', not matches(container(frame(payload, digest=b'\x00' * 32)), record(payload)))
check('negative-record-digest', not matches(good, record(payload, Sha256='0' * 64)))
check('negative-bytes-differ', not matches(good, record(payload, Bytes=list(payload[:-1]) + [payload[-1] ^ 1])))
check('negative-bytes-type', not matches(good, record(payload, Bytes=[300] + list(payload[1:]))))
check('negative-truncated-container', not matches(good[:-1], record(payload)))
check('negative-payload-corrupt', not matches(good[:-1] + bytes([good[-1] ^ 1]), record(payload)))
check('positive-without-retained-bytes', matches(good, {k: v for k, v in record(payload).items() if k != 'Bytes'}))

replay = 'ABSENT'
evidence = ROOT / 'driver/evidence/2026-10-21/boot-start-invariant-C01-approve-absent-ordinary-m2t4p1-artifacts'
export = evidence / 'case.guest-export.txt'
if export.is_file():
    text = export.read_text(encoding='utf-8-sig', errors='replace')
    data = json.loads(text[text.find('{'):text.rfind('}') + 1])
    derived = [r for t in data['Trials'] for s in (t.get('ServiceAfter') or {}, t.get('ServiceBefore') or {})
               for r in (s.get('Journal') or []) if 'FrameOffset' in r]
    ok = bool(derived)
    for r in derived:
        pack = evidence / r['Artifact'].replace('\\', '/').split('-artifacts/')[-1]
        ok = ok and pack.is_file() and matches(pack.read_bytes(), r)
    replay = 'PASS' if ok else 'FAIL'
    check('retained-real-pack-replay', ok)

failed = [name for name, passed in checks if not passed]
for name, passed in checks:
    print(('PASS ' if passed else 'FAIL ') + name)
print(f'ArchivePayloadSelfCheck={"PASS" if not failed else "FAIL"};Checks={len(checks)};RetainedReplay={replay};Qualification=False')
sys.exit(1 if failed else 0)
