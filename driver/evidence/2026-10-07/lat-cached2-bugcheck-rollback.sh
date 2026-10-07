#!/bin/bash
# Roll win10-debug back to the clean state taken before the failed dedicated-latency run sol-lat-cached2 (2026-10-07).
# Why: the guest bugchecked 0xD1 at 07:30:42Z during the run (StageRegistryCopyUnknownSopChunk wrote a PAGED
# snapshot buffer under SectionLock); the wrapper's offline rollback could not read the libvirt-owned overlay.
# Memory image: /var/tmp/lat-cached2-hang-20261007.elf (readable copy lat-cached2-hang-readable.elf).
# The failed overlay is kept. Run as the user who normally runs virsh for this VM.
set -euo pipefail
V="virsh -c qemu:///system"
IMG=/var/lib/libvirt/images
FAILED=$IMG/win10-debug.safeupload-pre-boot-start-invariant-C01-approve-absent-runtime-verifier-sol-lat-cached2-20261007
CLEAN=win10-debug.safeupload-pre-boot-start-invariant-A04-runtime-verifier-sol-a04r1-20261007
NEW=win10-debug.safeupload-recovery-lat-cached2-20261007.qcow2
XML=/tmp/claude-1000/win10-debug-recovery-lat-cached2.xml

# Safety: the domain must currently run on the failed overlay, and that overlay must sit directly on CLEAN.
SOURCES=$($V dumpxml win10-debug | grep -o "source file='[^']*'" | cut -d"'" -f2)
TOP=$(sed -n 1p <<<"$SOURCES"); PARENT=$(sed -n 2p <<<"$SOURCES")
[ "$TOP" = "$FAILED" ] || { echo "vda is not the failed overlay ($TOP); stop"; exit 1; }
[ "$PARENT" = "$IMG/$CLEAN" ] || { echo "the failed overlay's parent is not the clean checkpoint ($PARENT); stop"; exit 1; }
[ -e /var/tmp/lat-cached2-hang-20261007.elf ] || { echo "memory image missing; capture it before destroying the guest"; exit 1; }

$V pool-refresh default
CAP=$($V vol-info --bytes --pool default "$CLEAN" | awk '/Capacity/{print $2}')
$V destroy win10-debug || true
$V vol-create-as default "$NEW" "$CAP" --format qcow2 --backing-vol "$IMG/$CLEAN" --backing-vol-format qcow2
$V dumpxml --inactive win10-debug > "$XML"
python3 - "$FAILED" "$IMG/$NEW" "$XML" <<'PY'
import sys, xml.etree.ElementTree as ET
p = sys.argv[3]; t = ET.parse(p); n = 0
for disk in t.getroot().iter('disk'):
    s = disk.find('source')
    if disk.get('device') == 'disk' and s is not None and s.get('file') == sys.argv[1]:
        s.set('file', sys.argv[2]); bs = disk.find('backingStore')
        if bs is not None: disk.remove(bs)
        n += 1
if n != 1: raise SystemExit('expected exactly one disk to repoint, found %d' % n)
t.write(p)
PY
$V define "$XML"
$V start win10-debug
$V domblklist win10-debug
echo "Started on $NEW. Then: driver/scripts/Get-StagedBaseline.ps1 should report BaselineClean=True."
