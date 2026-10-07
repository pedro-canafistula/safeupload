#!/usr/bin/env bash
# Owner request 2026-10-07: run suite batches on several identical debuggees at once.
# Usage: driver/scripts/New-ParallelDebuggees.sh <count 2-4> <memory MiB>
# Requires win10-debug cleanly shut down from a BaselineClean=True state. Its current top overlay
# becomes the read-only common base; win10-debug and each clone win10-debug2..<count> get their own
# new qcow2 overlay on it (nothing is copied or deleted), the same memory size, and their own MAC
# and UEFI variable store (seeded from the firmware's default variables). Clones keep the guest's static
# address .51 until reconfigured one at a time (see driver/MVP-PLAN.md); never start two before that.
set -euo pipefail
count="${1:?count}"; mib="${2:?memory MiB}"
[[ "$count" =~ ^[2-4]$ && "$mib" =~ ^[0-9]{4,5}$ ]] || { echo 'count 2-4, memory MiB'; exit 2; }
V="virsh -c qemu:///system"; IMG=/var/lib/libvirt/images; stamp=$(date +%Y%m%d%H%M)
[ "$($V domstate win10-debug)" = "shut off" ] || { echo 'win10-debug must be shut off cleanly first'; exit 1; }
for n in $(seq 2 "$count"); do
    ! $V dominfo "win10-debug$n" >/dev/null 2>&1 || { echo "win10-debug$n already exists"; exit 1; }
done
source_xml=$(mktemp); $V dumpxml --inactive win10-debug > "$source_xml"
top=$(python3 -c 'import sys,xml.etree.ElementTree as E
d=[x for x in E.parse(sys.argv[1]).getroot().iter("disk") if x.get("device")=="disk"]
assert len(d)==1; print(d[0].find("source").get("file"))' "$source_xml")
nvram=$(python3 -c 'import sys,xml.etree.ElementTree as E; print(E.parse(sys.argv[1]).getroot().find("os/nvram").text)' "$source_xml")
$V pool-refresh default >/dev/null
cap=$($V vol-info --bytes --pool default "$(basename "$top")" | awk '/Capacity/{print $2}')
echo "CommonBase=$top"; echo "Capacity=$cap"; echo "MemoryMiB=$mib"; echo "SourceNvram=$nvram"
for n in $(seq 1 "$count"); do
    dom=win10-debug; [ "$n" -gt 1 ] && dom="win10-debug$n"
    vol="$dom.parallel-base-$stamp.qcow2"
    $V vol-create-as default "$vol" "$cap" --format qcow2 --backing-vol "$top" --backing-vol-format qcow2 >/dev/null
    xml=$(mktemp)
    python3 - "$source_xml" "$xml" "$dom" "$n" "$IMG/$vol" "$mib" "$nvram" <<'PY'
import sys, xml.etree.ElementTree as E
src, out, dom, n, disk, mib, nvram = sys.argv[1:]
t = E.parse(src); r = t.getroot(); n = int(n)
for tag in ('memory', 'currentMemory'):
    r.find(tag).set('unit', 'KiB'); r.find(tag).text = str(int(mib) * 1024)
d = [x for x in r.iter('disk') if x.get('device') == 'disk']; assert len(d) == 1
d[0].find('source').set('file', disk)
bs = d[0].find('backingStore')
if bs is not None: d[0].remove(bs)
if n > 1:
    r.find('name').text = dom; r.remove(r.find('uuid'))
    macs = r.findall('devices/interface/mac'); assert len(macs) == 1
    macs[0].set('address', '52:54:00:aa:dd:%02x' % (0x10 + n))
    # libvirt's EFI auto-selection rejects a custom template; the clone's store is seeded from the
    # firmware's default vars and Windows boots through the ESP fallback loader.
    v = r.find('os/nvram')
    for a in ('template', 'templateFormat'): v.attrib.pop(a, None)
    v.text = '/var/lib/libvirt/qemu/nvram/%s_VARS.fd' % dom
t.write(out)
PY
    $V define "$xml" >/dev/null
    echo "Defined $dom disk=$IMG/$vol"
done
