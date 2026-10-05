#!/bin/bash
# Roll win10-debug back to the clean checkpoint parent of S01 b22s01a (boot Verifier).
# The guest display confirms IRQL_NOT_LESS_OR_EQUAL; dump diagnosis is pending.
# The parent recovery overlay passed BaselineClean=True after the owner-approved orphan profile cleanup.
# The failed overlay and original ELF memory dump are retained. Run only after the test wrapper stops.
# Run as the user who normally runs virsh for this VM.
set -euo pipefail
V="virsh -c qemu:///system"
IMG=/var/lib/libvirt/images
FAILED=$IMG/win10-debug.safeupload-pre-boot-start-invariant-S01-denied-write-after-boot-boot-verifier-b22s01a-20261005
CLEAN=win10-debug.safeupload-recovery-s01-bugcheck-20261005
NEW=win10-debug.safeupload-recovery-b22s01a-20261005

# Safety: the domain must currently run on the failed overlay, and that overlay must sit directly on CLEAN.
# Output is captured first: with pipefail, `virsh ... | grep -q` fails when grep exits early and virsh gets SIGPIPE.
SOURCES=$($V dumpxml win10-debug | grep -o "source file='[^']*'" | cut -d"'" -f2)
TOP=$(sed -n 1p <<<"$SOURCES"); PARENT=$(sed -n 2p <<<"$SOURCES")
[ "$TOP" = "$FAILED" ] || { echo "vda is not the failed overlay ($TOP); stop"; exit 1; }
[ "$PARENT" = "$IMG/$CLEAN" ] || { echo "the failed overlay's parent is not the clean checkpoint ($PARENT); stop"; exit 1; }

[ ! -e "$IMG/$NEW" ] || { echo "recovery overlay already exists; stop"; exit 1; }
$V pool-refresh default
CAP=$($V vol-info --bytes --pool default "$CLEAN" | awk '/Capacity/{print $2}')
$V destroy win10-debug || true
STATE=$($V domstate win10-debug)
[ "$STATE" = "shut off" ] || { echo "domain did not stop ($STATE); stop"; exit 1; }
$V vol-create-as default "$NEW" "$CAP" --format qcow2 --backing-vol "$IMG/$CLEAN" --backing-vol-format qcow2
$V dumpxml --inactive win10-debug > /tmp/win10-debug-b22s01a-recovery.xml
python3 - "$FAILED" "$IMG/$NEW" <<'PY'
import sys, xml.etree.ElementTree as ET
p = '/tmp/win10-debug-b22s01a-recovery.xml'; t = ET.parse(p); n = 0
for disk in t.getroot().iter('disk'):
    s = disk.find('source')
    if disk.get('device') == 'disk' and s is not None and s.get('file') == sys.argv[1]:
        s.set('file', sys.argv[2]); bs = disk.find('backingStore')
        if bs is not None: disk.remove(bs)
        n += 1
if n != 1: raise SystemExit('expected exactly one disk to repoint, found %d' % n)
t.write(p)
PY
$V define /tmp/win10-debug-b22s01a-recovery.xml
$V start win10-debug
$V domblklist win10-debug
echo "Started on $NEW. Then: driver/scripts/Get-StagedBaseline.ps1 via remote_ps should report BaselineClean=True."
