#!/usr/bin/env python3
"""Exercise the kernel fetch/summary/import gate with inert transports; no builder."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('Invoke-ExactSourceBuild.sh')
BUILDS = ('driver:owned-feature', 'driver:owned-feature-release',
          'inspector-feature-release', 'writer-fixture')
DRIVERS = ('SafeUpload-stage-prototype.sys', 'owned-feature.sys', 'owned-feature-release.sys')
FETCH = {'summary.txt', 'owned-feature-wdk.txt', 'owned-feature-release-wdk.txt', 'sign.txt',
         *DRIVERS, 'inspector-feature-release.exe', 'inspector-feature-release.txt',
         'writer-fixture.exe', 'writer-fixture.txt', 'signature-verification.json'}


def fixtures():
    rows = ['Builder=builder1', 'BuilderHost=192.168.122.210', 'BuilderComputerName=DESKTOP-O1LP5DG',
            'KernelBuildProfiles=owned-feature,owned-feature-release']
    for name in BUILDS:
        tokens = ' exit=0 succeeded=True warnings=0 errors=0 artifact_sha256=' + 'A' * 64
        if name.startswith('driver:'):
            tokens += (' apivalidator=True prefast=True feature=true configuration='
                       + ('Release' if name.endswith('-release') else 'Debug'))
        if name != 'writer-fixture':
            tokens += ' owner_fsp=false'
        rows.append(name + ' :' + tokens)
    rows.append('sign : exit=0 signature_valid=True unsigned_unchanged=True signer=' + 'B' * 40
                + ' store=CurrentUser signed_sha256=' + 'C' * 64)
    imports = ['DriverImports ' + name + ' PASS 12 imports all exported by the reference' for name in DRIVERS]
    imports.append('DriverImportAvailability=PASS')
    return rows, imports


def run_gate(source, rows, imports, import_exit=0, build_exit=0):
    # Execute the actual shell tail, including the Python heredoc. All transport
    # and import-tool calls are intercepted; the summary gate is unmodified.
    tail = source[source.index('for f in summary.txt'):]
    with tempfile.TemporaryDirectory(prefix='kernel-delivery-control-') as temporary:
        root = Path(temporary)
        work, evidence = root / 'work', root / 'evidence'
        work.mkdir(); evidence.mkdir()
        for name in FETCH:
            (work / name).write_text('inert fixture')
        (work / 'summary.txt').write_text('\n'.join(rows) + '\n')
        import_file = root / 'imports.txt'
        import_file.write_text('\n'.join(imports) + '\n')
        trace = root / 'trace.txt'
        values = {'work': str(work), 'ev': str(evidence), 'label': 'fixture', 'd': 'inert',
                  'thumb': 'B' * 40, 'store': 'CurrentUser', 'owner_fsp': 'false',
                  'builder_name': 'builder1', 'host': '192.168.122.210', 'builder_computer': 'DESKTOP-O1LP5DG',
                  'build_exit': str(build_exit), 'fixture_import_exit': str(import_exit),
                  'fixture_import_file': str(import_file), 'fixture_trace': str(trace)}
        prefix = 'set -uo pipefail\nscp_opts=()\n'
        prefix += '\n'.join(k + '=' + shlex.quote(v) for k, v in values.items()) + '\n'
        prefix += '''
scp() { printf 'FETCH=%s\n' "${1##*/}" >> "$fixture_trace"; }
python3() {
    if [[ "$1" == driver/scripts/Test-DriverImports.py ]]; then
        shift
        for artifact in "$@"; do printf 'IMPORT=%s\n' "${artifact##*/}" >> "$fixture_trace"; done
        cat "$fixture_import_file"
        return "$fixture_import_exit"
    fi
    command python3 "$@"
}
'''
        result = subprocess.run(['bash'], input=prefix + tail, text=True, capture_output=True)
        return result, trace.read_text().splitlines()


class KernelDeliveryControls(unittest.TestCase):
    def contract(self, source):
        rows, imports = fixtures()
        result, trace = run_gate(source, rows, imports)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('ExactSourceBuildSummaryGate=PASS', result.stdout)
        self.assertEqual(FETCH, {line.removeprefix('FETCH=') for line in trace if line.startswith('FETCH=')})
        self.assertEqual(['IMPORT=' + name for name in DRIVERS], [line for line in trace if line.startswith('IMPORT=')])
        failures = []
        for index, row in enumerate(rows):
            failures += [rows[:index] + rows[index + 1:], rows + [row]]
            if ' :' in row:
                for token in row.split()[2:]:
                    if token.startswith(('artifact_sha256=', 'signed_sha256=')):
                        continue
                    failures.append(rows[:index] + [row.replace(token, token + '_invalid')] + rows[index + 1:])
        # Normal build results cannot substitute for either required feature row.
        failures.append([row.replace('driver:owned-feature', 'driver:normal') for row in rows])
        for changed in failures:
            result, _ = run_gate(source, changed, imports)
            self.assertNotEqual(0, result.returncode, changed)
            self.assertNotIn('ExactSourceBuildSummaryGate=PASS', result.stdout)
        for index, row in enumerate(imports):
            for changed in (imports[:index] + imports[index + 1:], imports + [row],
                            imports[:index] + [row.replace('PASS', 'FAIL')] + imports[index + 1:]):
                result, _ = run_gate(source, rows, changed)
                self.assertNotEqual(0, result.returncode, changed)
                self.assertNotIn('ExactSourceBuildSummaryGate=PASS', result.stdout)
        for import_exit, build_exit in ((1, 0), (0, 1)):
            result, _ = run_gate(source, rows, imports, import_exit, build_exit)
            self.assertNotEqual(0, result.returncode)

    def test_feature_delivery_and_each_missing_or_failed_guard(self):
        self.contract(SCRIPT.read_text())

    def test_guard_mutations_are_caught(self):
        source = SCRIPT.read_text()
        mutations = [
            ("'driver:owned-feature', 'driver:owned-feature-release',", "'driver:owned-feature',"),
            ("'driver:owned-feature', 'driver:owned-feature-release',", "'driver:owned-feature-release',"),
            ("'warnings=0', ", ''), (", 'errors=0'", ''),
            ("'apivalidator=True', ", ''), ("'prefast=True', ", ''),
            ('if len(rows) != 1 or rows[0].split()[2] != \'PASS\':', 'if False:'),
            ("if imports.count('DriverImportAvailability=PASS') != 1 or any(", 'if False and any('),
            ('"$work/owned-feature-release.sys" | tee', '| tee'),
            ('"$work/owned-feature.sys" \\\n', '\\\n'),
            ('if ! python3 driver/scripts/Test-DriverImports.py', 'if python3 driver/scripts/Test-DriverImports.py'),
            ("if lines.count('KernelBuildProfiles=owned-feature,owned-feature-release') != 1:", 'if False:'),
        ]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                with self.assertRaises(AssertionError):
                    self.contract(source.replace(old, new))


if __name__ == '__main__':
    unittest.main(verbosity=2)
