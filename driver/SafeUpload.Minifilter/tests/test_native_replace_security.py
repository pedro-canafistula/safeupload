#!/usr/bin/env python3
"""Execute production authorization bodies against injectable OS boundaries."""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('directory', HERE / 'test_directory_ux.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

class NativeReplaceSecurity(unittest.TestCase):
    def test_exact_object_and_original_subject_authority(self):
        source = (HERE.parent / 'StageSecurity.c').read_text()
        bodies = ''.join(d.function(source, name) for name in (
            'StageQueryBoundSecurity', 'SafeUploadStageCheckNativeReplace'))
        fixture = (HERE / 'native_replace_security_fixture.c').read_text().replace('/* PRODUCTION */', bodies)
        scratch = Path(os.environ.get('TMPDIR', d.ROOT / '.scratch'))
        scratch.mkdir(parents=True, exist_ok=True)
        for compiler in ('cc', 'clang'):
            with self.subTest(compiler=compiler):
                root = Path(tempfile.mkdtemp(prefix='native-replace-', dir=scratch))
                (root / 'fixture.c').write_text(fixture)
                build = subprocess.run([compiler, '-std=c11', '-fshort-wchar', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=undefined', '-fno-sanitize-recover=all', str(root / 'fixture.c'), '-o', str(root / 'fixture')],
                    capture_output=True, text=True)
                (root / 'build.txt').write_text(build.stdout + build.stderr)
                self.assertEqual(build.returncode, 0, str(root) + ': ' + build.stderr)
                run = subprocess.run([str(root / 'fixture')], capture_output=True, text=True, timeout=30)
                (root / 'run.txt').write_text(run.stdout + run.stderr)
                self.assertEqual(run.returncode, 0, str(root) + ': ' + run.stderr)
                print(run.stdout.strip())
                shutil.rmtree(root)

if __name__ == '__main__':
    unittest.main()
