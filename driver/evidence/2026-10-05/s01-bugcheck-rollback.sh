#!/bin/bash
# Roll win10-debug back to the clean state taken before the failed S01 boot-start run (notify8b).
# Why: the increments 3-5 driver (mvp3-b4) bugchecks 0xEF (wininit.exe died, exit 14001 SxS) on every boot under S01's boot
# policy, so the guest cannot recover by itself. The active overlay holds only the failed run; its backing file is the state the
# wrapper verified clean (BaselineClean=True) right after S00. Nothing is deleted: the failed overlay is kept as evidence.
# Run as the user who normally runs virsh for this VM.
set -euo pipefail
V="virsh -c qemu:///system"
IMG=/var/lib/libvirt/images
FAILED=$IMG/win10-debug.safeupload-pre-boot-start-invariant-S01-denied-write-after-boot-ordinary-notify8b-20261004
CLEAN=win10-debug.safeupload-pre-boot-start-invariant-S00-observer-control-ordinary-notify8b-20261004
NEW=win10-debug.safeupload-recovery-s01-bugcheck-20261005

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
$V dumpxml --inactive win10-debug > /tmp/win10-debug-recovery.xml
python3 - "$FAILED" "$IMG/$NEW" <<'PY'
import sys, xml.etree.ElementTree as ET
p = '/tmp/win10-debug-recovery.xml'; t = ET.parse(p); n = 0
for disk in t.getroot().iter('disk'):
    s = disk.find('source')
    if disk.get('device') == 'disk' and s is not None and s.get('file') == sys.argv[1]:
        s.set('file', sys.argv[2]); bs = disk.find('backingStore')
        if bs is not None: disk.remove(bs)
        n += 1
if n != 1: raise SystemExit('expected exactly one disk to repoint, found %d' % n)
t.write(p)
PY
$V define /tmp/win10-debug-recovery.xml
$V start win10-debug
$V domblklist win10-debug
echo "Started on $NEW. Then: driver/scripts/Get-StagedBaseline.ps1 via remote_ps should report BaselineClean=True."
