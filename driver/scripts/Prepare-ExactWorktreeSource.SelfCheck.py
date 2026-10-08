#!/usr/bin/env python3
"""Exercise source-provenance failures in disposable Git repos; no remote calls."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location(
    'snapshot', Path(__file__).with_name('Prepare-ExactWorktreeSource.py'))
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)


class CaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / 'repo'
        self.root.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        for name in [snapshot.ROOTS[0] + '/input.c',
                     snapshot.ROOTS[1] + '/main.c', *snapshot.TOOLS]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('old\n')
        self.run_git('add', '.')
        self.run_git('-c', 'user.name=fixture', '-c', 'user.email=fixture@local',
                     'commit', '-qm', 'fixture')
        self.name = snapshot.ROOTS[0] + '/input.c'
        self.output = Path(temp.name) / 'out'

    def run_git(self, *args):
        return snapshot.git(self.root, *args)

    def test_dirty_bytes_without_git_mutation(self):
        index = self.run_git('ls-files', '--stage', '-z')
        head = self.run_git('rev-parse', 'HEAD')
        (self.root / self.name).write_bytes(b'new\r\n')
        provenance = snapshot.capture(self.root, self.output)
        with zipfile.ZipFile(self.output / 'src.zip') as archive:
            self.assertEqual(archive.read(self.name), b'new\r\n')
        self.assertEqual(provenance['ChangedFromBaseCommit'], [self.name])
        self.assertEqual(index, self.run_git('ls-files', '--stage', '-z'))
        self.assertEqual(head, self.run_git('rev-parse', 'HEAD'))
        other = snapshot.capture(self.root, self.output.with_name('out2'))
        self.assertEqual(provenance['ArchiveSHA256'], other['ArchiveSHA256'])

    def test_reuse_refused(self):
        snapshot.capture(self.root, self.output)
        with self.assertRaises(FileExistsError):
            snapshot.capture(self.root, self.output)

    def test_untracked_input_refused(self):
        (self.root / snapshot.ROOTS[0] / 'new.c').write_text('new')
        with self.assertRaisesRegex(ValueError, 'Untracked'):
            snapshot.capture(self.root, self.output)
        self.assertFalse((self.output / 'source-provenance.json').exists())

    def test_exact_reviewed_new_input_without_index_mutation(self):
        name = snapshot.ROOTS[0] + '/reviewed.c'
        data = b'reviewed new source\n'
        (self.root / name).write_bytes(data)
        index = self.run_git('ls-files', '--stage', '-z')
        approved = {name: snapshot.digest(data)}
        provenance = snapshot.capture(self.root, self.output, reviewed_untracked=approved)
        self.assertEqual(provenance['ReviewedUntrackedSHA256'], approved)
        self.assertEqual(index, self.run_git('ls-files', '--stage', '-z'))
        with zipfile.ZipFile(self.output / 'src.zip') as archive:
            self.assertEqual(archive.read(name), data)

    def test_unknown_extra_not_hidden_by_reviewed_input(self):
        name = snapshot.ROOTS[0] + '/reviewed.c'
        (self.root / name).write_bytes(b'reviewed')
        (self.root / snapshot.ROOTS[0] / 'unexpected.c').write_bytes(b'unreviewed')
        with self.assertRaisesRegex(ValueError, 'Untracked'):
            snapshot.capture(self.root, self.output,
                             reviewed_untracked={name: snapshot.digest(b'reviewed')})
        self.assertFalse((self.output / 'source-provenance.json').exists())

    def test_reviewed_input_hash_drift_refused(self):
        name = snapshot.ROOTS[0] + '/reviewed.c'
        (self.root / name).write_bytes(b'changed after review')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            snapshot.capture(self.root, self.output,
                             reviewed_untracked={name: snapshot.digest(b'reviewed')})

    def test_reviewed_case_collision_refused(self):
        name = snapshot.ROOTS[0] + '/INPUT.C'
        (self.root / name).write_bytes(b'reviewed')
        with self.assertRaisesRegex(ValueError, 'collision'):
            snapshot.capture(self.root, self.output,
                             reviewed_untracked={name: snapshot.digest(b'reviewed')})

    def test_reviewed_input_outside_roots_refused(self):
        with self.assertRaisesRegex(ValueError, 'Untracked'):
            snapshot.capture(self.root, self.output,
                             reviewed_untracked={'../private.cs': '0' * 64})

    def test_indexed_new_input_does_not_bypass_review(self):
        name = snapshot.ROOTS[0] + '/new.c'
        (self.root / name).write_bytes(b'new')
        self.run_git('add', name)
        with self.assertRaisesRegex(ValueError, 'indexed new'):
            snapshot.capture(self.root, self.output)
        self.assertFalse((self.output / 'source-provenance.json').exists())

    def test_intent_to_add_new_input_does_not_bypass_review(self):
        name = snapshot.ROOTS[0] + '/new.c'
        (self.root / name).write_bytes(b'new')
        self.run_git('add', '-N', name)
        with self.assertRaisesRegex(ValueError, 'indexed new'):
            snapshot.capture(self.root, self.output)

    def test_reviewed_indexed_new_input_is_pinned(self):
        name = snapshot.ROOTS[0] + '/new.c'
        (self.root / name).write_bytes(b'new')
        self.run_git('add', name)
        provenance = snapshot.capture(self.root, self.output,
                                     reviewed_untracked={name: snapshot.digest(b'new')})
        self.assertEqual(provenance['ReviewedUntrackedSHA256'], {name: snapshot.digest(b'new')})

    def test_reviewed_input_symlink_refused(self):
        name = snapshot.ROOTS[0] + '/reviewed.c'
        (self.root / name).symlink_to(self.root / self.name)
        with self.assertRaises(OSError):
            snapshot.capture(self.root, self.output,
                             reviewed_untracked={name: snapshot.digest(b'old\n')})

    def test_alternate_profile_tools_are_delivery_pinned(self):
        tools = (snapshot.TOOLS[1],)
        provenance = snapshot.capture(self.root, self.output, roots=(snapshot.ROOTS[0],), tools=tools)
        snapshot.verify(self.output, provenance, tools=tools)
        (self.output / 'tools' / Path(tools[0]).name).write_bytes(b'replaced')
        with self.assertRaisesRegex(ValueError, 'tool changed'):
            snapshot.verify(self.output, provenance, tools=tools)

    def test_symlink_refused(self):
        path = self.root / self.name
        path.unlink()
        path.symlink_to(self.root / snapshot.ROOTS[1] / 'main.c')
        with self.assertRaises(OSError):
            snapshot.capture(self.root, self.output)

    def test_mid_capture_mutation_refused(self):
        original = snapshot.read_regular
        reads = 0

        def changing_read(repo, name):
            nonlocal reads
            result = original(repo, name)
            if name == self.name:
                reads += 1
                if reads == 1:
                    (repo / name).write_text('mutated')
            return result

        with patch.object(snapshot, 'read_regular', side_effect=changing_read):
            with self.assertRaisesRegex(ValueError, 'changed during capture'):
                snapshot.capture(self.root, self.output)
        self.assertFalse((self.output / 'source-provenance.json').exists())

    def test_case_collision_refused(self):
        (self.root / snapshot.ROOTS[0] / 'INPUT.C').write_text('old')
        self.run_git('add', '.')
        with self.assertRaisesRegex(ValueError, 'collision'):
            snapshot.capture(self.root, self.output)

    def test_deleted_input_refused(self):
        (self.root / self.name).unlink()
        with self.assertRaises(FileNotFoundError):
            snapshot.capture(self.root, self.output)

    def test_ignored_input_refused(self):
        (self.root / '.gitignore').write_text('ignored.c\n')
        (self.root / snapshot.ROOTS[0] / 'ignored.c').write_text('ignored')
        with self.assertRaisesRegex(ValueError, 'Untracked'):
            snapshot.capture(self.root, self.output)

    def test_reserved_windows_name_refused(self):
        (self.root / snapshot.ROOTS[0] / 'NUL.c').write_text('invalid')
        self.run_git('add', '.')
        with self.assertRaisesRegex(ValueError, 'Unsafe Windows'):
            snapshot.capture(self.root, self.output)

    def test_directory_component_case_collision_refused(self):
        for leaf in ('Shared/one.c', 'shared/two.c'):
            path = self.root / snapshot.ROOTS[0] / leaf
            path.parent.mkdir(parents=True)
            path.write_text('invalid')
        self.run_git('add', '.')
        with self.assertRaisesRegex(ValueError, 'collision'):
            snapshot.capture(self.root, self.output)

    def test_parent_symlink_swap_cannot_read_outside(self):
        outside = self.root.parent / 'outside'
        target = outside / 'SafeUpload.Minifilter' / 'input.c'
        target.parent.mkdir(parents=True)
        target.write_text('outside-private-bytes')
        original_open = os.open
        swapped = False

        def swapping_open(path, flags, *args, **kwargs):
            nonlocal swapped
            fd = original_open(path, flags, *args, **kwargs)
            if path == 'driver' and not swapped:
                swapped = True
                (self.root / 'driver').rename(self.root / 'original-driver')
                (self.root / 'driver').symlink_to(outside, target_is_directory=True)
            return fd

        with patch.object(snapshot.os, 'open', side_effect=swapping_open):
            data, _ = snapshot.read_regular(self.root, self.name)
        self.assertTrue(swapped)
        self.assertEqual(data, b'old\n')
        with self.assertRaises(OSError):
            snapshot.read_regular(self.root, self.name)

    def test_post_capture_inputs_remain_bound(self):
        provenance = snapshot.capture(self.root, self.output)
        snapshot.verify(self.output, provenance)
        (self.output / 'src.zip').write_bytes(b'replacement archive')
        (self.output / 'src.manifest').write_text('replacement manifest')
        with self.assertRaisesRegex(ValueError, 'input changed'):
            snapshot.verify(self.output, provenance)

    def test_post_capture_provenance_replacement_refused(self):
        provenance = snapshot.capture(self.root, self.output)
        changed = dict(provenance, ArchiveSHA256='0' * 64)
        (self.output / 'source-provenance.json').write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, 'provenance changed'):
            snapshot.verify(self.output, provenance)

    def test_post_capture_tool_replacement_refused(self):
        provenance = snapshot.capture(self.root, self.output)
        (self.output / 'tools' / 'Build-ExactSource.ps1').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'tool changed'):
            snapshot.verify(self.output, provenance)

    def test_hardlinked_input_refused(self):
        os.link(self.root / self.name, self.root.parent / 'second-link')
        with self.assertRaisesRegex(ValueError, 'Hardlinked'):
            snapshot.capture(self.root, self.output)


if __name__ == '__main__':
    unittest.main()
