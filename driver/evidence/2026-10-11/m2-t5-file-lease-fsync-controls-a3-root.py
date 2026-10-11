#!/usr/bin/python3.14
"""Disposable Ext4 check: acquire an O_RDONLY lease, fsync it, then read."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time


FIXTURE_ROOT = "/mnt/storage"
SIZE = 16 * 1024 * 1024
CHUNK = bytes(range(256)) * 4096


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_exact(fd: int, size: int) -> bytes:
    parts: list[bytes] = []
    offset = 0
    while offset < size:
        part = os.pread(fd, min(1024 * 1024, size - offset), offset)
        if not part:
            raise RuntimeError("short read from disposable fixture")
        parts.append(part)
        offset += len(part)
    return b"".join(parts)


def main() -> int:
    fstype = subprocess.run(
        ["/usr/bin/findmnt", "-n", "-o", "FSTYPE", "--target", FIXTURE_ROOT],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=5,
    ).stdout.strip()
    if fstype != "ext4":
        raise RuntimeError("workspace is not on Ext4; refusing to run this control")
    kernel = os.uname().release
    prior_break_time = Path("/proc/sys/fs/lease-break-time").read_text().strip()
    prior_leases_enable = Path("/proc/sys/fs/leases-enable").read_text().strip()
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGIO})
    temp_dir = tempfile.mkdtemp(prefix="m2-t5-lease-fsync-a3-", dir=FIXTURE_ROOT)
    path = os.path.join(temp_dir, "buffered-closed-writer.bin")
    expected_hash = hashlib.sha256()
    writer_fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    try:
        left = SIZE
        while left:
            raw = CHUNK[: min(len(CHUNK), left)]
            view = memoryview(raw)
            while view:
                n = os.write(writer_fd, view)
                if n <= 0:
                    raise RuntimeError("short buffered fixture write")
                expected_hash.update(view[:n])
                view = view[n:]
            left -= len(raw)
    finally:
        os.close(writer_fd)

    read_fd = -1
    lease_acquired = False
    try:
        read_fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOATIME)
        before = os.fstat(read_fd)
        if not os.path.isfile(path) or before.st_size != SIZE:
            raise RuntimeError("disposable fixture metadata differs before lease")
        fcntl.fcntl(read_fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        lease_acquired = True
        after_lease = os.fstat(read_fd)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after_lease.st_dev, after_lease.st_ino, after_lease.st_size
        ):
            raise RuntimeError("fixture identity changed at lease acquisition")
        os.fsync(read_fd)
        fsync_errno = 0
        data = read_exact(read_fd, SIZE)
        after_read = os.fstat(read_fd)
        if sha(data) != expected_hash.hexdigest():
            raise RuntimeError("read-only leased descriptor content hash differs")
        if (after_lease.st_dev, after_lease.st_ino, after_lease.st_size) != (
            after_read.st_dev, after_read.st_ino, after_read.st_size
        ):
            raise RuntimeError("fixture identity changed before lease release")
        result = {
            "Schema": "T5DisposableExt4ReadonlyLeaseFsyncControlV1",
            "Status": "PASS_DISPOSABLE_FIXTURE_ONLY",
            "Kernel": kernel,
            "Filesystem": fstype,
            "FixturePathWasUnderDedicatedExt4FixtureDirectory": True,
            "FixtureDirectory": os.path.basename(temp_dir),
            "FixtureBytes": SIZE,
            "FixtureSHA256": expected_hash.hexdigest(),
            "WriterClosedBeforeLease": True,
            "LeaseFDFlags": "O_RDONLY|O_CLOEXEC|O_NOATIME",
            "LeaseType": "F_RDLCK",
            "LeaseAcquired": True,
            "FsyncOnReadOnlyLeasedFD": "SUCCESS",
            "FsyncErrno": fsync_errno,
            "ReadHashWhileLeaseHeld": sha(data),
            "LeaseHeldThroughFsyncAndRead": True,
            "LeaseExplicitlyReleasedInFinally": True,
            "LeaseBreakTimeBefore": prior_break_time,
            "LeaseBreakTimeAfter": Path("/proc/sys/fs/lease-break-time").read_text().strip(),
            "LeasesEnableBefore": prior_leases_enable,
            "LeasesEnableAfter": Path("/proc/sys/fs/leases-enable").read_text().strip(),
            "NoSysctlOrFileFlagsChanged": True,
            "NoOriginalStateOrLibvirtPathOpened": True,
            "Scope": ("demonstrates O_RDONLY F_RDLCK acquisition and successful fsync/read "
                      "on this disposable Ext4 fixture only; does not prove the page was "
                      "still dirty at acquisition, ext4 behavior, systemd FD retention, "
                      "or full-run protection"),
        }
        assert result["LeaseBreakTimeBefore"] == result["LeaseBreakTimeAfter"]
        assert result["LeasesEnableBefore"] == result["LeasesEnableAfter"]
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        if lease_acquired:
            fcntl.fcntl(read_fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        if read_fd >= 0:
            os.close(read_fd)
        os.unlink(path)
        os.rmdir(temp_dir)


if __name__ == "__main__":
    raise SystemExit(main())
