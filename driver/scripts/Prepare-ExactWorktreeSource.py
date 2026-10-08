#!/usr/bin/env python3
"""Capture current tracked driver sources locally; never commit, upload or run a VM.

The archive is the build identity, not BaseCommit. Two reads reject changes during
capture; this is a stable capture check, not an atomic filesystem snapshot.
Untracked project inputs are refused by default. Other profiles may supply an
exact separately reviewed name-to-hash allowlist; unknown inputs remain refused.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

ROOTS = ('driver/SafeUpload.Minifilter', 'driver/SafeUpload.Inspector',
         'driver/SafeUpload.WriterFixture')
TOOLS = ('driver/scripts/Build-ExactSource.ps1', 'driver/scripts/remote_ps.py',
         'driver/scripts/Invoke-ExactSourceBuild.sh',
         'driver/scripts/Prepare-ExactWorktreeSource.py')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def reviewed_inputs(path, expected_sha256):
    """Load an exact caller-pinned allowlist without changing the Git index."""
    if not re.fullmatch('[0-9A-Fa-f]{64}', expected_sha256):
        raise ValueError('Invalid reviewed-inputs SHA-256')
    data = read_regular(path.parent.resolve(), path.name)[0]
    if digest(data) != expected_sha256.lower():
        raise ValueError('Reviewed-inputs document hash mismatch')

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate reviewed-input path: ' + key)
            result[key] = value
        return result

    result = json.loads(data, object_pairs_hook=unique_object)
    if not isinstance(result, dict) or not all(
            isinstance(name, str) and isinstance(sha, str)
            and re.fullmatch('[0-9a-f]{64}', sha)
            for name, sha in result.items()):
        raise ValueError('Reviewed-inputs document must map paths to lowercase SHA-256 hashes')
    return result


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def inventory(repo, roots=ROOTS, reviewed_untracked=None):
    reviewed_untracked = reviewed_untracked or {}
    entries = git(repo, 'ls-files', '--stage', '-z', '--', *roots)
    extra = git(repo, 'ls-files', '--others', '-z', '--', *roots)
    extra_names = {raw.decode('utf-8') for raw in extra.split(b'\0') if raw}
    if not extra_names.issubset(set(reviewed_untracked)):
        raise ValueError('Untracked project inputs differ from reviewed allowlist: '
                         + repr(sorted(extra_names - set(reviewed_untracked))))
    for name, sha in reviewed_untracked.items():
        if not re.fullmatch('[0-9a-f]{64}', sha):
            raise ValueError('Invalid reviewed input hash: ' + name)
    # Synthetic entries undergo the same path/collision checks as tracked files;
    # they never enter the repository's Git index.
    validation_entries = entries + b''.join(
        b'100644 ' + b'0' * 40 + b' 0\t' + n.encode('utf-8') + b'\0'
        for n in sorted(extra_names))
    names = []
    folded = set()
    component_spellings = {}
    for entry in validation_entries.split(b'\0'):
        if not entry:
            continue
        meta, raw = entry.split(b'\t', 1)
        mode, _, stage = meta.split()
        name = raw.decode('utf-8')
        if mode not in (b'100644', b'100755') or stage != b'0':
            raise ValueError('Non-regular or unmerged index entry: ' + name)
        # These paths are consumed by Windows and the line-oriented manifest.
        parts = name.split('/')
        for i, part in enumerate(parts):
            if (part in ('', '.', '..') or part.endswith((' ', '.'))
                    or any(ord(c) < 32 or c in '\\:*?<>|"' for c in part)
                    or re.fullmatch(r'(?i)(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])',
                                    part.split('.')[0])):
                raise ValueError('Unsafe Windows archive path: ' + name)
            prefix = '/'.join(parts[:i + 1])
            old = component_spellings.setdefault(prefix.casefold(), prefix)
            if old != prefix:
                raise ValueError('Case-insensitive path collision: ' + name)
        if name.casefold() in folded:
            raise ValueError('Case-insensitive path collision: ' + name)
        folded.add(name.casefold())
        names.append(name)
    if not all(any(n.startswith(r + '/') for n in names) for r in roots[:2]):
        raise ValueError('Missing required project sources')
    committed_names = {raw.decode('utf-8') for raw in
                       git(repo, 'ls-tree', '-r', '--name-only', '-z', 'HEAD', '--', *roots).split(b'\0')
                       if raw}
    new_names = set(names) - committed_names
    if new_names != set(reviewed_untracked):
        raise ValueError('Untracked or indexed new project inputs differ from reviewed allowlist: '
                         + repr(sorted(new_names ^ set(reviewed_untracked))))
    for name, sha in reviewed_untracked.items():
        if digest(read_regular(repo, name)[0]) != sha:
            raise ValueError('Reviewed input hash mismatch: ' + name)
    # Include ignored files: the fresh builder cannot silently pick up any local
    # generated or ignored input. Move such files out of these source roots first.
    return entries, sorted(names)


def read_regular(repo, name):
    # Directory-FD traversal prevents a concurrent parent symlink replacement
    # from redirecting an allowlisted archive name outside the repository.
    parts = name.split('/')
    directory = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('Not a regular file: ' + name)
        if before.st_nlink != 1:
            raise ValueError('Hardlinked input refused: ' + name)
        data = handle.read()
        after = os.fstat(handle.fileno())
    key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size,
                     s.st_mtime_ns, s.st_ctime_ns)
    if key(before) != key(after):
        raise ValueError('File changed while reading: ' + name)
    return data, key(after)


def capture(repo, output, roots=ROOTS, tools=TOOLS, reviewed_untracked=None):
    repo = repo.resolve()
    output = output.absolute()
    # No reuse: a failed capture is kept for inspection, never a valid build input.
    output.mkdir(parents=True, exist_ok=False)
    head = git(repo, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
    reviewed_untracked = dict(reviewed_untracked or {})
    entries, names = inventory(repo, roots, reviewed_untracked)
    captured = {n: read_regular(repo, n) for n in names + list(tools)}
    manifest = ''.join(digest(captured[n][0]) + '  ' + n + '\n' for n in names)
    archive = output / 'src.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as z:
        for name in names:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            z.writestr(info, captured[name][0])
    (output / 'src.manifest').write_bytes(manifest.encode('utf-8'))
    (output / 'tools').mkdir()
    for name in tools:
        (output / 'tools' / Path(name).name).write_bytes(captured[name][0])
    changed = []
    for name in names:
        baseline = subprocess.run(['git', '-C', str(repo), 'show', head + ':' + name],
                                  capture_output=True)
        if baseline.returncode or baseline.stdout != captured[name][0]:
            changed.append(name)
    if git(repo, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip() != head:
        raise ValueError('HEAD changed during capture')
    if inventory(repo, roots, reviewed_untracked) != (entries, names):
        raise ValueError('Project index/inventory changed during capture')
    for name, original in captured.items():
        if read_regular(repo, name) != original:
            raise ValueError('Source/tool changed during capture: ' + name)
    provenance = {
        'SourceKind': 'worktree', 'BaseCommit': head,
        'CapturedUTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'ArchiveSHA256': digest(archive.read_bytes()),
        'ManifestSHA256': digest(manifest.encode('utf-8')),
        'ProjectIndexSHA256': digest(entries), 'Files': len(names),
        'ChangedFromBaseCommit': changed,
        'BuildToolsSHA256': {n: digest(captured[n][0]) for n in tools},
        'ReviewedUntrackedSHA256': reviewed_untracked,
        'CaptureCheck': 'two reads; byte and file metadata equality',
        'NetworkOperationsDuringPreparation': 0,
    }
    # Published last; its absence means preparation failed.
    (output / 'source-provenance.json').write_text(
        json.dumps(provenance, indent=2) + '\n', encoding='utf-8')
    return provenance


def verify(output, expected, tools=TOOLS):
    """Bind delivery inputs to the provenance held by the caller at capture time."""
    actual = json.loads(read_regular(output, 'source-provenance.json')[0])
    if actual != expected:
        raise ValueError('Capture provenance changed before delivery')
    for name, key in (('src.zip', 'ArchiveSHA256'), ('src.manifest', 'ManifestSHA256')):
        if digest(read_regular(output, name)[0]) != expected[key]:
            raise ValueError('Captured input changed before delivery: ' + name)
    for name in tools:
        if digest(read_regular(output, 'tools/' + Path(name).name)[0]) != expected['BuildToolsSHA256'][name]:
            raise ValueError('Frozen build tool changed before delivery: ' + name)
    return expected['ArchiveSHA256'] + ' ' + expected['ManifestSHA256']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--repo', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--provenance-json')
    parser.add_argument('--reviewed-inputs-json', type=Path)
    parser.add_argument('--reviewed-inputs-sha256')
    args = parser.parse_args()
    if bool(args.reviewed_inputs_json) != bool(args.reviewed_inputs_sha256):
        parser.error('--reviewed-inputs-json and --reviewed-inputs-sha256 are required together')
    if args.verify:
        if args.reviewed_inputs_json:
            parser.error('Reviewed inputs are only valid when capturing; verification uses caller-held provenance')
        if not args.provenance_json:
            parser.error('--verify requires the caller-held --provenance-json')
        print(verify(args.output, json.loads(args.provenance_json)))
    else:
        if args.provenance_json:
            parser.error('--provenance-json is only valid with --verify')
        allowlist = reviewed_inputs(args.reviewed_inputs_json, args.reviewed_inputs_sha256) if args.reviewed_inputs_json else None
        print(json.dumps(capture(args.repo, args.output, reviewed_untracked=allowlist), indent=2))
