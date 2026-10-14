"""Synthetic exact-source controls for the Phase 4 runner (commit archives and legacy manifests); not Windows qualification."""
import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('qualification', Path(__file__).with_name('Invoke-StagedInvariantQualification.py'))
Q = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(Q)
SUBTREE = 'driver/SafeUpload.Inspector'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


class ExactSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.work = Path(self.temp.name)
        self.commit = Q.git('rev-parse', 'HEAD').decode().strip()
        self.paths = Q.git('ls-tree', '-r', '--name-only', self.commit, '--', SUBTREE).decode().splitlines()
        subprocess.run(['git', 'archive', '--format=zip', '-o', str(self.work / 'src.zip'), self.commit, SUBTREE], cwd=Q.ROOT, check=True)

    def tearDown(self):
        self.temp.cleanup()

    def summary(self, commit=None, source=None):
        return 'SOURCE_COMMIT=%s\nARCHIVE_SHA256=%s\n' % (commit or self.commit, digest(source or self.work / 'src.zip'))

    def rezip(self, name, comment, change=None):
        target = self.work / name
        with zipfile.ZipFile(self.work / 'src.zip') as source, zipfile.ZipFile(target, 'w') as out:
            for item in source.infolist():
                data = source.read(item.filename)
                out.writestr(item.filename, change(item.filename, data) if change else data)
            out.comment = comment
        return target

    def check(self, summary, source=None):
        Q.exact_sources(self.work, summary, self.commit, [SUBTREE], source)

    def test_commit_archive_passes(self):
        self.check(self.summary())
        self.check('ArtifactView=x\nSourceCommit=%s\nARCHIVE_SHA256=%s\n' % (self.commit, digest(self.work / 'src.zip')))

    def test_commit_archive_from_another_location_passes(self):
        other = self.rezip('matrix-src.zip', self.commit.encode())
        self.check(self.summary(source=other), other)

    def test_summary_must_name_exactly_the_commit(self):
        for bad in (self.summary(commit='0' * 40), self.summary() + 'SourceCommit=%s\n' % self.commit,
                    'ARCHIVE_SHA256=%s\n' % digest(self.work / 'src.zip')):
            with self.assertRaises(RuntimeError):
                self.check(bad)

    def test_archive_hash_and_comment_are_required(self):
        with self.assertRaises(RuntimeError):
            self.check('SOURCE_COMMIT=%s\nARCHIVE_SHA256=%s\n' % (self.commit, 'A' * 64))
        uncommented = self.rezip('plain.zip', b'')
        with self.assertRaises(RuntimeError):
            self.check(self.summary(source=uncommented), uncommented)

    def test_changed_extra_or_missing_files_fail(self):
        changed = self.rezip('changed.zip', self.commit.encode(), lambda name, data: data + b' ' if name == self.paths[0] else data)
        with self.assertRaises(RuntimeError):
            self.check(self.summary(source=changed), changed)
        extra = self.rezip('extra.zip', self.commit.encode())
        with zipfile.ZipFile(extra, 'a') as out:
            out.writestr(SUBTREE + '/planted.c', b'int x;')
        with self.assertRaises(RuntimeError):
            self.check(self.summary(source=extra), extra)
        missing = self.work / 'missing.zip'
        with zipfile.ZipFile(self.work / 'src.zip') as source, zipfile.ZipFile(missing, 'w') as out:
            for item in source.infolist()[:-1]:
                out.writestr(item.filename, source.read(item.filename))
            out.comment = self.commit.encode()
        with self.assertRaises(RuntimeError):
            self.check(self.summary(source=missing), missing)

    def test_legacy_manifest_is_still_checked(self):
        rows = ['%s  %s' % (hashlib.sha256(Q.git('show', self.commit + ':' + path)).hexdigest().upper(), path) for path in self.paths]
        (self.work / 'src.manifest').write_text('\n'.join(rows) + '\n')
        legacy = 'ARCHIVE_SHA256=%s\nMANIFEST_SHA256=%s\n' % (digest(self.work / 'src.zip'), digest(self.work / 'src.manifest'))
        self.check(legacy)
        with self.assertRaises(RuntimeError):
            self.check('ARCHIVE_SHA256=%s\nMANIFEST_SHA256=%s\n' % (digest(self.work / 'src.zip'), 'A' * 64))
        for bad in (rows[:-1], ['%s  %s' % ('0' * 64, self.paths[0])] + rows[1:]):
            (self.work / 'src.manifest').write_text('\n'.join(bad) + '\n')
            with self.assertRaises(RuntimeError):
                self.check('ARCHIVE_SHA256=%s\nMANIFEST_SHA256=%s\n' % (digest(self.work / 'src.zip'), digest(self.work / 'src.manifest')))


if __name__ == '__main__':
    unittest.main()
