#!/bin/bash
# Roll win10-debug back to the clean state taken before the failed C01 run c01j (2026-10-06).
# Why: C01 c01j restoration ran concurrently with the observation (wall-clock deadline expired after the guest clock jump).
# a queue.jsonl ACL mismatch, so product files may be partly restored.
# The c01i recovery was verified BaselineClean=True after a clean restart. The failed overlay is kept.
# Run as the user who normally runs virsh for this VM.
set -euo pipefail
V="virsh -c qemu:///system"
IMG=/var/lib/libvirt/images
FAILED=$IMG/win10-debug.safeupload-pre-boot-start-invariant-C01-approve-absent-runtime-verifier-c01j-20261006
CLEAN=win10-debug.safeupload-recovery-c01i-20261006.qcow2
NEW=win10-debug.safeupload-recovery-c01j-20261006.qcow2

# Safety: the domain must currently run on the failed overlay, and that overlay must sit directly on CLEAN.
# Output is captured first: with pipefail, `virsh ... | grep -q` fails when grep exits early and virsh gets SIGPIPE.
SOURCES=$($V dumpxml win10-debug | grep -o "source file='[^']*'" | cut -d"'" -f2)
TOP=$(sed -n 1p <<<"$SOURCES"); PARENT=$(sed -n 2p <<<"$SOURCES")
[ "$TOP" = "$FAILED" ] || { echo "vda is not the failed overlay ($TOP); stop"; exit 1; }
[ "$PARENT" = "$IMG/$CLEAN" ] || { echo "the failed overlay's parent is not the clean checkpoint ($PARENT); stop"; exit 1; }

$V pool-refresh default
CAP=$($V vol-info --bytes --pool default "$CLEAN" | awk '/Capacity/{print $2}')
$V destroy win10-debug || true
$V vol-create-as default "$NEW" "$CAP" --format qcow2 --backing-vol "$IMG/$CLEAN" --backing-vol-format qcow2
$V dumpxml --inactive win10-debug > /tmp/claude-1000/win10-debug-recovery-c01j.xml
python3 - "$FAILED" "$IMG/$NEW" <<'PY'
import sys, xml.etree.ElementTree as ET
p = '/tmp/claude-1000/win10-debug-recovery-c01j.xml'; t = ET.parse(p); n = 0
for disk in t.getroot().iter('disk'):
    s = disk.find('source')
    if disk.get('device') == 'disk' and s is not None and s.get('file') == sys.argv[1]:
        s.set('file', sys.argv[2]); bs = disk.find('backingStore')
        if bs is not None: disk.remove(bs)
        n += 1
if n != 1: raise SystemExit('expected exactly one disk to repoint, found %d' % n)
t.write(p)
PY
$V define /tmp/claude-1000/win10-debug-recovery-c01j.xml
$V start win10-debug
$V domblklist win10-debug
echo "Started on $NEW. Then: driver/scripts/Get-StagedBaseline.ps1 via remote_ps should report BaselineClean=True."
