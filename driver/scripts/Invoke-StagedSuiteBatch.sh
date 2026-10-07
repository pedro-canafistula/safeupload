#!/usr/bin/env bash
# Run Phase 4 cases serially on the debuggee, one runner invocation per case, with automatic recovery.
# Optional EXTRA_RUNNER_ARGS (e.g. --dedicated-unheld-latency) is passed to every runner call.
# Usage: driver/scripts/Invoke-StagedSuiteBatch.sh <driver_label> <driver_commit> <agent_label> <agent_commit> <mode> <tagprefix> CASE...
# For each case: verify the baseline, run it, summarize the gate fields, and if the run left a
# recovery-required marker, roll the guest back to the run's pre-run checkpoint (the failed overlay's
# direct parent, checked against the run name), clean-restart it and re-verify the baseline.
# Stops the batch when the guest cannot be brought back to BaselineClean=True.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
driver_label=$1; driver_commit=$2; agent_label=$3; agent_commit=$4; mode=$5; prefix=$6; shift 6
policy=29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731
host=192.168.122.51; V="virsh -c qemu:///system"; IMG=/var/lib/libvirt/images
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
remote() { python3 driver/scripts/remote_ps.py "$host"; }
wait_up() { for _ in $(seq 1 60); do remote <<<'"up"' >/dev/null 2>&1 && return 0; sleep 5; done; return 1; }
baseline() {  # $1 evidence path
    echo "& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1'" | remote > "$1" 2>&1
    grep -q 'BaselineClean=True' "$1"
}
clean_restart() { wait_up && { remote <<<'Restart-Computer -Force' >/dev/null 2>&1; sleep 45; wait_up; }; }
rollback() {  # $1 run name; the failed overlay must be the run's checkpoint overlay
    local sources top parent new xml
    sources=$($V dumpxml win10-debug | grep -o "source file='[^']*'" | cut -d"'" -f2)
    top=$(sed -n 1p <<<"$sources"); parent=$(sed -n 2p <<<"$sources")
    [[ "$top" == *"$1"* ]] || { log "rollback refused: top overlay $top is not run $1"; return 1; }
    new="win10-debug.safeupload-recovery-$1.qcow2"; xml=/tmp/claude-1000/win10-debug-recovery-$1.xml
    $V pool-refresh default >/dev/null
    local cap; cap=$($V vol-info --bytes --pool default "$(basename "$parent")" | awk '/Capacity/{print $2}')
    $V destroy win10-debug >/dev/null 2>&1 || true
    $V vol-create-as default "$new" "$cap" --format qcow2 --backing-vol "$parent" --backing-vol-format qcow2 >/dev/null || return 1
    $V dumpxml --inactive win10-debug > "$xml"
    python3 - "$top" "$IMG/$new" "$xml" <<'PY' || return 1
import sys, xml.etree.ElementTree as ET
t = ET.parse(sys.argv[3]); n = 0
for disk in t.getroot().iter('disk'):
    s = disk.find('source')
    if disk.get('device') == 'disk' and s is not None and s.get('file') == sys.argv[1]:
        s.set('file', sys.argv[2]); bs = disk.find('backingStore')
        if bs is not None: disk.remove(bs)
        n += 1
if n != 1: raise SystemExit('expected exactly one disk to repoint, found %d' % n)
t.write(sys.argv[3])
PY
    $V define "$xml" >/dev/null && $V start win10-debug >/dev/null || return 1
    log "rolled back $1: $top -> $IMG/$new (parent $parent kept)"
}
day=$(date +%F); ev=driver/evidence/$day; mkdir -p "$ev"
i=0
for case in "$@"; do
    i=$((i+1)); tag="${prefix}${i}"
    baseline "$ev/batch-$tag-pre-baseline.txt" || { log "STOP: baseline not clean before $tag"; exit 2; }
    log "run $tag $case $mode"
    python3 driver/scripts/Invoke-StagedInvariantQualification.py "$tag" "$driver_label" "$driver_commit" "$agent_label" "$policy" \
        --cases "$case" --modes "$mode" --agent-source-commit "$agent_commit" ${EXTRA_RUNNER_ARGS:-} > "$ev/batch-$tag-runner.log" 2>&1
    day=$(date +%F); ev=driver/evidence/$day; mkdir -p "$ev"
    index=$(ls -t driver/evidence/*/phase4-suite-"$tag"-index.txt 2>/dev/null | head -1)
    summary=$( [ -n "$index" ] && grep -o '"Verdict": "[A-Z]*"\|"GatePassed": [a-z]*\|"RestorationClean": [a-z]*\|"ForbiddenByteCount": [0-9a-z]*' "$index" | tr '\n' ' ')
    log "result $tag $case: ${summary:-no index}"
    name="boot-start-invariant-$case-$mode-$tag"
    if ls driver/evidence/*/"$name"-recovery-required.txt >/dev/null 2>&1; then
        rollback "$name" || { log "STOP: rollback failed for $tag"; exit 3; }
    fi
    clean_restart || { log "STOP: guest did not come back after $tag"; exit 4; }
    baseline "$ev/batch-$tag-post-baseline.txt" || { log "STOP: baseline not clean after $tag"; exit 5; }
done
log "batch complete"
