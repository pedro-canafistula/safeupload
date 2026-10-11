#!/usr/bin/env bash
# Independently boot a fresh disposable disk and run the original baseline check.
# Use after the product run's disk has been deleted; never boot the base writable.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
dom=${1:?domain}; tag=${2:?fresh verification tag}
[[ "$tag" =~ ^[A-Za-z0-9]{3,40}$ ]] || exit 2
host=$(awk -v d="$dom" '$1==d{print $2}' driver/scripts/debuggees.txt)
case "$dom" in
    win10-debug3) expected_uuid=FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3 ;;
    *) echo 'Select the owner-approved test VM win10-debug3'; exit 2 ;;
esac
V='virsh -c qemu:///system'
ev="driver/evidence/$(date +%F)"; mkdir -p "$ev"
source driver/scripts/image-store.sh
source driver/scripts/run-disk.sh
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR -o StrictHostKeyChecking=yes)
finish() {
    local rc=$?
    trap - EXIT
    if [ -f "$RUN_DISK_STATE/$dom" ]; then
        if ! run_disk_end "$dom" "$tag" > "$ev/$tag-restoration.txt" 2>&1; then
            cat "$ev/$tag-restoration.txt"; exit 22
        fi
        cat "$ev/$tag-restoration.txt"
    fi
    [ "$rc" -ne 0 ] || echo 'IndependentRestoration=PASS'
    exit "$rc"
}
trap finish EXIT
run_disk_begin "$dom" "$tag" > "$ev/$tag-start.txt" 2>&1 || { cat "$ev/$tag-start.txt"; exit 12; }
for i in $(seq 1 90); do
    if ssh "${opts[@]}" "vika@$host" 'echo up' >/dev/null 2>&1; then break; fi
    [ "$i" -lt 90 ] || { echo 'BaselineStopReason=SSH timeout'; exit 3; }
    sleep 10
done
scp "${opts[@]}" driver/scripts/Get-StagedBaseline.ps1 "vika@$host:C:/Users/vika/Documents/Get-StagedBaseline.ps1" || exit 4
python3 driver/scripts/remote_ps.py "$host" <<'PS' > "$ev/$tag-baseline-raw.txt" 2>&1
& 'C:\Users\vika\Documents\Get-StagedBaseline.ps1'
PS
rc=$?
tr -d '\r' < "$ev/$tag-baseline-raw.txt" > "$ev/$tag-baseline.txt"
cat "$ev/$tag-baseline.txt"
[ "$rc" = 0 ] && grep -qx 'BaselineClean=True' "$ev/$tag-baseline.txt" &&
    grep -qx "UUID=$expected_uuid" "$ev/$tag-baseline.txt" || exit 10
