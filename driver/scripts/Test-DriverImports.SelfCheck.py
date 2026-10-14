#!/usr/bin/env python3
"""Offline controls for Test-DriverImports.py; no builder, network or VM.

Synthetic controls always run. When the retained driver artifacts are present locally, they are checked too: the k11 driver
that loaded on the target must pass and the t5-fix2 driver that could not load must fail on exactly SeDeleteClientSecurity.
Run: python3 driver/scripts/Test-DriverImports.SelfCheck.py
"""
import importlib.util
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('imports', HERE / 'Test-DriverImports.py')
imports = importlib.util.module_from_spec(spec)
spec.loader.exec_module(imports)

reference = imports.load_reference(imports.DEFAULT_REFERENCE)
assert {'ntoskrnl.exe', 'hal.dll', 'fltmgr.sys', 'cng.sys'} <= set(reference), sorted(reference)
assert 'SeDeleteClientSecurity' not in reference['ntoskrnl.exe']
for module, name in (('ntoskrnl.exe', 'ObfDereferenceObject'), ('ntoskrnl.exe', 'SeCreateClientSecurityFromSubjectContext'),
                     ('fltmgr.sys', 'FltSetCancelCompletion'), ('cng.sys', 'BCryptHashData')):
    assert name in reference[module], (module, name)

ok = [('ntoskrnl.exe', 'ObfDereferenceObject', 0), ('FLTMGR.SYS', 'FltSetCancelCompletion', 0)]
assert imports.missing_imports(ok, reference) == []
assert imports.missing_imports(ok + [('ntoskrnl.exe', 'SeDeleteClientSecurity', 0)], reference) == ['ntoskrnl.exe!SeDeleteClientSecurity']
assert imports.missing_imports([('ntoskrnl.exe', None, 42)], reference) == ['ntoskrnl.exe!#42 (import by ordinal)']
assert imports.missing_imports([('ksecdd.sys', 'Anything', 0)], reference) == ['ksecdd.sys!* (module not in reference)']

with tempfile.TemporaryDirectory() as d:
    bogus = Path(d) / 'not-a-driver.sys'
    bogus.write_bytes(b'MZ not a PE image')
    assert imports.main([str(bogus)]) == 1  # unreadable never passes
    empty = Path(d) / 'empty-reference.txt'
    empty.write_text('MODULE ntoskrnl.exe\n')
    try:
        imports.load_reference(empty)
        raise AssertionError('an empty reference module must be refused')
    except SystemExit:
        pass

retained = {
    Path('/tmp/safeupload-t4-memory-tools/SafeUpload-stage-prototype.sys'): [],
    Path('/mnt/storage/safeupload-archive/pairs/t5-fix2/SafeUpload-stage-prototype.sys'): ['ntoskrnl.exe!SeDeleteClientSecurity'],
}
checked = 0
for path, expected in retained.items():
    if path.is_file():
        assert imports.missing_imports(imports.driver_imports(path), reference) == expected, path
        checked += 1
print(f'DriverImportsSelfCheck=PASS; synthetic controls and {checked} retained driver(s)')
