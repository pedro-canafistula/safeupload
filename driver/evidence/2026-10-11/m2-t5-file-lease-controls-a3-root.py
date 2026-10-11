import datetime, errno, fcntl, hashlib, json, mmap, os, pathlib, signal, subprocess, sys, tempfile

repo = pathlib.Path('/home/victor/Work/safeupload-staging')
results = []
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGIO})

def reject_existing_writer(reader, case):
    try:
        fcntl.fcntl(reader, fcntl.F_SETLEASE, fcntl.F_RDLCK)
    except OSError as error:
        assert error.errno == errno.EAGAIN, (case, error)
        results.append({'Case': case, 'LeaseAcquisitionErrno': error.errno, 'Result': 'PASS'})
    else:
        fcntl.fcntl(reader, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        raise AssertionError(case + ': lease was granted with an existing writable file object')

with tempfile.TemporaryDirectory(prefix='m2-t5-lease-controls-', dir='/mnt/storage') as directory:
    target = pathlib.Path(directory) / 'disposable.bin'
    target.write_bytes(b'B' * 4096)
    reader = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    try:
        writer = os.open(target, os.O_RDWR | os.O_CLOEXEC)
        try:
            reject_existing_writer(reader, 'ExistingWritableDescriptor')
        finally:
            os.close(writer)

        writer = os.open(target, os.O_RDWR | os.O_CLOEXEC)
        view = mmap.mmap(writer, 4096, flags=mmap.MAP_SHARED,
                         prot=mmap.PROT_READ | mmap.PROT_WRITE, trackfd=False)
        os.close(writer)
        try:
            reject_existing_writer(reader, 'SharedWritableMappingAfterDescriptorClose')
        finally:
            view.close()

        fcntl.fcntl(reader, fcntl.F_SETOWN, os.getpid())
        fcntl.fcntl(reader, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        try:
            assert fcntl.fcntl(reader, fcntl.F_GETLEASE) == fcntl.F_RDLCK
            code = '''import errno,json,os,sys
try:
 fd=os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC)
except OSError as error:
 print(json.dumps({'Blocked':True,'Errno':error.errno}))
 sys.exit(0 if error.errno in (errno.EAGAIN,errno.EWOULDBLOCK) else 2)
else:
 os.close(fd)
 print(json.dumps({'Blocked':False}))
 sys.exit(1)
'''
            done = subprocess.run([sys.executable, '-B', '-c', code, str(target)],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=5, check=True)
            outcome = json.loads(done.stdout)
            assert outcome['Blocked'] is True
            assert target.read_bytes() == b'B' * 4096
            results.append({'Case': 'NewNonblockingWriterOpenWhileReadLeaseHeld',
                            'Result': 'PASS', 'WriterResult': outcome,
                            'GetLeaseAfterBreakRequest': fcntl.fcntl(reader, fcntl.F_GETLEASE),
                            'GetLeaseAfterBreakIsNotTerminalProof': True,
                            'RawStdoutUTF8': done.stdout.decode('utf-8'),
                            'RawStderrUTF8': done.stderr.decode('utf-8'),
                            'RawStdoutSHA256': hashlib.sha256(done.stdout).hexdigest(),
                            'RawStderrSHA256': hashlib.sha256(done.stderr).hexdigest()})
        finally:
            fcntl.fcntl(reader, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        writer = os.open(target, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        os.close(writer)
        results.append({'Case': 'NewWriterOpenAfterExplicitLeaseRelease', 'Result': 'PASS'})
    finally:
        os.close(reader)

mount = subprocess.run(['/usr/bin/findmnt', '--json', '--target', '/mnt/storage',
                        '--output', 'FSTYPE,TARGET,SOURCE'], stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=5)
assert all(row['fstype'] == 'ext4' for row in json.loads(mount.stdout)['filesystems'])
receipt = {
    'CapturedUTC': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'QueryUID': os.getuid(), 'KernelRelease': os.uname().release,
    'TemporaryFileFilesystem': json.loads(mount.stdout), 'Controls': results,
    'ControlCount': len(results), 'Result': 'PASS_TEMPORARY_FILE_MECHANISM_CONTROLS',
    'ControlScriptSHA256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    'LeasesEnableObserved': pathlib.Path('/proc/sys/fs/leases-enable').read_text().strip(),
    'LeaseBreakSecondsObserved': pathlib.Path('/proc/sys/fs/lease-break-time').read_text().strip(),
    'TemporaryKernelFileLeasesUsed': True, 'OriginalVMFilesOpened': False,
    'HostPolicyMutated': False, 'SysctlChanged': False, 'ImmutableFlagsChanged': False,
    'ProductVMStarted': False, 'Ext4MechanismTested': True, 'RuntimeGuardQualified': False,
    'PriorReceiptErratum': 'a1 ran on /tmp tmpfs, as its actual findmnt field records; its prose Limit incorrectly said Btrfs. This a3 actually runs in a private disposable Ext4 directory on /mnt/storage.',
    'Limit': 'Disposable Ext4 files only. No forced timeout, non-expiring lease, crash survival, writeback drain, VM baseline protection or restoration is qualified.',
}
raw = (json.dumps(receipt, indent=2, sort_keys=True) + '\n').encode()
destination = repo / 'driver/evidence/2026-10-11/m2-t5-file-lease-controls-a3-root.json'
with destination.open('xb') as stream:
    stream.write(raw)
print(json.dumps({'Receipt': str(destination.relative_to(repo)),
                  'SHA256': hashlib.sha256(raw).hexdigest(), 'Controls': len(results)}))
