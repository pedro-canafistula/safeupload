#!/usr/bin/env python3
"""Offline controls for local compile/preflight defaults; native builds are mocked."""
import contextlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parent


def load_preflight(source=None):
    path = SCRIPTS / 'agent-test-preflight.py'
    module = types.ModuleType('preflight_control')
    module.__file__ = str(path)
    exec(compile(source or path.read_text(), str(path), 'exec'), module.__dict__)
    return module


class FeatureAgentDefaults(unittest.TestCase):
    def compile_contract(self, source):
        with tempfile.TemporaryDirectory(prefix='compile-defaults-') as temporary:
            root = Path(temporary)
            tools = root / 'tools'
            (tools / 'dotnet').mkdir(parents=True)
            (tools / 'nuget-cache').mkdir()
            (root / 'agente').mkdir()
            dotnet = tools / 'dotnet/dotnet'
            dotnet.write_text('#!/bin/bash\nif [[ "$1" == --version ]]; then echo fixture; exit; fi\nprintf "%s\\n" "$*" >> "$COMPILE_TRACE"\nexit "${COMPILE_EXIT:-0}"\n')
            dotnet.chmod(0o755)
            trace = root / 'trace.txt'
            script = root / 'compile.sh'
            script.write_text(source)
            env = {**os.environ, 'SAFEUPLOAD_TOOLS': str(tools), 'COMPILE_TRACE': str(trace), 'TMPDIR': temporary}
            for profiles, expected, feature in (([], ['feature-debug', 'feature-release'], 'true'),
                                                 (['normal-debug', 'normal-release'], ['normal-debug', 'normal-release'], 'false')):
                trace.write_text('')
                result = subprocess.run(['bash', str(script), '--root', str(root), *profiles], env=env, text=True, capture_output=True)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                calls = trace.read_text().splitlines()
                self.assertEqual(6, len(calls))
                for profile in expected:
                    self.assertEqual(3, sum('/' + profile + '/' in call for call in calls))
                for call in calls:
                    self.assertIn('-warnaserror', call)
                    self.assertIn('-p:SafeUploadAdmissionEvidence=' + feature, call)
                self.assertIn('profiles=' + ' '.join(expected), result.stdout)
            failed = subprocess.run(['bash', str(script), '--root', str(root)], env={**env, 'COMPILE_EXIT': '1'}, text=True, capture_output=True)
            self.assertNotEqual(0, failed.returncode)
            self.assertIn('LocalAgentCompile=FAIL', failed.stdout)

    def test_local_compile_defaults_explicit_normals_and_mutations(self):
        source = (SCRIPTS / 'Invoke-LocalAgentCompile.sh').read_text()
        self.compile_contract(source)
        for old, new in [
            ('|| profiles=(feature-debug feature-release)', '|| profiles=(normal-debug normal-release)'),
            ('|| profiles=(feature-debug feature-release)', '|| profiles=(feature-debug)'),
            (' -warnaserror ', ' '),
            ('feature=true', 'feature=false'),
        ]:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                with self.assertRaises(AssertionError):
                    self.compile_contract(source.replace(old, new))

    def preflight_contract(self, module):
        # Build source fixtures from an independent copy of the real required
        # inventory, so a preflight mutation cannot silently shrink its fixture.
        required, cases = load_preflight().runner_requirements()
        with tempfile.TemporaryDirectory(prefix='preflight-defaults-') as temporary:
            root = Path(temporary)
            tests = root / 'agente/SafeUpload.Agent.Tests'
            tests.mkdir(parents=True)
            grouped = {}
            for cls, method in required:
                grouped.setdefault(cls, []).append(method)
            grouped['Synthetic.Tests.Keep'] = ['DebugOnly', 'ReleaseOnly', 'NormalOnly']
            for cls, methods in grouped.items():
                namespace, name = cls.rsplit('.', 1)
                text = 'namespace ' + namespace + ';\nclass ' + name + ' {\n'
                for method in methods:
                    text += '[Fact]\n'
                    for case in cases.get(cls + '.' + method, ()):
                        if case:
                            text += '[InlineData(' + re.search(r'"[^"]*"', case)[0] + ')]\n'
                    text += 'public void ' + method + '() {}\n'
                (tests / (name + '.cs')).write_text(text + '}\n')
            evidence = root / 'evidence/day'
            evidence.mkdir(parents=True)
            paths = {}
            for profile, method in [('feature-debug', 'DebugOnly'), ('feature-release', 'ReleaseOnly'), ('normal-debug', 'NormalOnly')]:
                path = evidence / ('exact-agent-matrix-fixture-' + profile + '-results-agent-tests-discovered-fq.txt')
                path.write_text('Synthetic.Tests.Keep.' + method + '\n')
                paths[profile] = path

            def run(*extra):
                output = io.StringIO()
                argv = ['preflight', '--root', str(root), '--evidence', str(evidence.parent), '--baseline', 'fixture', *extra]
                with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(output):
                    try:
                        code = module.main()
                    except SystemExit as exc:
                        code = exc.code
                return code, output.getvalue()

            code, output = run()
            self.assertEqual(0, code, output)
            self.assertIn('profiles=feature-debug,feature-release', output)
            self.assertEqual(len(required), len(module.runner_requirements()[0]))
            self.assertNotIn('BaselineProfile=normal', output)
            for profile in ('feature-debug', 'feature-release'):
                data = paths[profile].read_text()
                paths[profile].unlink()
                self.assertNotEqual(0, run()[0])
                paths[profile].write_text(data)
            keep = tests / 'Keep.cs'
            text = keep.read_text()
            keep.write_text(text.replace('ReleaseOnly', 'Renamed'))
            self.assertNotEqual(0, run()[0])
            keep.write_text(text)
            endpoint = tests / 'AdmissionEvidenceEndpointTests.cs'
            text = endpoint.read_text()
            endpoint.write_text(text.replace('EvidenceTypesExistOnlyInFeatureBuilds', 'Renamed'))
            self.assertNotEqual(0, run()[0])
            endpoint.write_text(text)
            # Explicit normal diagnostics do not require either feature baseline.
            for profile in ('feature-debug', 'feature-release'):
                paths[profile].unlink()
            code, output = run('--profile', 'normal-debug')
            self.assertEqual(0, code, output)
            self.assertIn('profiles=normal-debug', output)

    def test_preflight_feature_defaults_explicit_normal_and_mutations(self):
        self.preflight_contract(load_preflight())
        source = (SCRIPTS / 'agent-test-preflight.py').read_text()
        mutations = [
            ("args.profile or ['feature-debug', 'feature-release']", "args.profile or ['feature-debug']"),
            ("args.profile or ['feature-debug', 'feature-release']", "args.profile or ['normal-debug']"),
            ('module.required_feature_tests()', 'module.STAGED_V20_REQUIRED_TESTS'),
            ('baseline |= names', 'baseline = names if not baseline else baseline'),
        ]
        for old, new in mutations:
            with self.subTest(mutation=old):
                self.assertIn(old, source)
                with self.assertRaises(AssertionError):
                    self.preflight_contract(load_preflight(source.replace(old, new)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
