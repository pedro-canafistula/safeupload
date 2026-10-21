#!/usr/bin/env python3
"""Replay actual T5 host archive validator against both retained packs; no network."""
import ast
import hashlib
import json
from pathlib import Path
import re
import struct
import uuid
launcher = Path(__file__).resolve().parents[1] / 'Invoke-StageNotepad.sh'
trees = [ast.parse(b) for b in re.findall(r"<<'PY'\n(.*?)\nPY\n", launcher.read_text(), re.S)]
fn = next(n for t in trees for n in t.body if isinstance(n, ast.FunctionDef) and n.name == 'archive_payload_matches')
env = {'hashlib': hashlib, 'json': json}
exec(compile(ast.Module(body=[fn], type_ignores=[]), str(launcher), 'exec'), env)
checks = 0
for path in [launcher.parent / 't5/fixtures/C01-00000001.pack', launcher.parent / 't5/fixtures/m2t5ord4-00000001.pack']:
    data = path.read_bytes()
    offset = 4096
    while offset < len(data):
        length = struct.unpack_from('<i', data, offset+8)[0]
        record = dict(FrameOffset=offset, Length=length, Sha256=data[offset+28:offset+60].hex().upper(), TransferId=uuid.UUID(bytes_le=data[offset+12:offset+28]).hex)
        assert env['archive_payload_matches'](data, record); checks += 1
        for key, bad in [('FrameOffset', 0), ('Length', length+1), ('Sha256', '0'*64), ('TransferId', '0'*32)]:
            assert not env['archive_payload_matches'](data, dict(record, **{key: bad})); checks += 1
        for pos in [0, 4, 8, 16, offset, offset+4, offset+8, offset+12, offset+28, offset+60]:
            bad = bytearray(data); bad[pos] ^= 1
            assert not env['archive_payload_matches'](bad, record); checks += 1
        offset += 60+length
print(f'T5ArchivePayloadSelfCheck=PASS;Assertions={checks};ProductQualified=False')
