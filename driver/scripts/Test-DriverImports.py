#!/usr/bin/env python3
"""Fail a driver whose imports are not all exported by the qualified Windows 10 family.

ApiValidator checks API-set compliance, not whether each imported routine exists on the target build. The dormant T5 pair
imported ntoskrnl!SeDeleteClientSecurity (a function in the current WDK for this NTDDI_VERSION, a macro before Windows 11),
which Windows 10 19041/19045 does not export: `fltmc load` failed with 0x8007007F and, as a boot-start driver, every boot
fell into WinRE (m2t5boot1-3, m2t5rv1). Import by ordinal is refused too: nothing here may depend on an export number.

Usage: Test-DriverImports.py [--reference driver/scripts/reference/win10-19045-exports.txt] DRIVER.sys...
Prints one line per driver and DriverImportAvailability=PASS|FAIL; exits 1 on any missing import or unreadable driver.
"""
import argparse
import sys
from pathlib import Path

DEFAULT_REFERENCE = Path(__file__).resolve().parent / 'reference' / 'win10-19045-exports.txt'


def load_reference(path):
    exports, current = {}, None
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if line.startswith('MODULE '):
            current = line.split()[1].lower()
            exports[current] = set()
        elif line.startswith('EXPORT ') and current is not None:
            exports[current].add(line.split(None, 1)[1].strip())
    if not exports or not all(exports.values()):
        raise SystemExit('Reference export list is empty or has an empty module: ' + str(path))
    return exports


def missing_imports(imports, exports):
    """imports: iterable of (module, name-or-None, ordinal). Returns sorted 'module!name' strings that are unavailable."""
    missing = set()
    for module, name, ordinal in imports:
        table = exports.get(module.lower())
        if table is None:
            missing.add(f'{module}!* (module not in reference)')
        elif name is None:
            missing.add(f'{module}!#{ordinal} (import by ordinal)')
        elif name not in table:
            missing.add(f'{module}!{name}')
    return sorted(missing)


def driver_imports(path):
    import pefile
    pe = pefile.PE(str(path), fast_load=False)
    result = []
    for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
        module = entry.dll.decode('ascii')
        for item in entry.imports:
            result.append((module, item.name.decode('ascii') if item.name else None, item.ordinal))
    for entry in getattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT', []):
        module = entry.dll.decode('ascii')
        for item in entry.imports:
            result.append((module, item.name.decode('ascii') if item.name else None, item.ordinal))
    if not result:
        raise ValueError('no imports found')
    return result


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--reference', default=str(DEFAULT_REFERENCE))
    parser.add_argument('drivers', nargs='+')
    args = parser.parse_args(argv)
    exports = load_reference(args.reference)
    failed = False
    for driver in args.drivers:
        try:
            imports = driver_imports(driver)
        except Exception as error:  # an unreadable or missing artifact never passes
            print(f'DriverImports {Path(driver).name} FAIL unreadable: {error}')
            failed = True
            continue
        missing = missing_imports(imports, exports)
        if missing:
            failed = True
            print(f'DriverImports {Path(driver).name} FAIL {len(imports)} imports; missing on Windows 10 19045: {", ".join(missing)}')
        else:
            print(f'DriverImports {Path(driver).name} PASS {len(imports)} imports all exported by the reference')
    print('DriverImportAvailability=' + ('FAIL' if failed else 'PASS'))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
