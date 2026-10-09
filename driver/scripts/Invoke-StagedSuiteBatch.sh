#!/usr/bin/env bash
# Run Phase 4 cases serially on the debuggee, one runner invocation per case, each on its own disposable run disk.
# Optional EXTRA_RUNNER_ARGS (e.g. --dedicated-unheld-latency) is passed to every runner call.
# Usage: driver/scripts/Invoke-StagedSuiteBatch.sh <driver_label> <driver_commit> <agent_label> <agent_commit> <mode> <tagprefix> CASE...
# SAFEUPLOAD_DEBUGGEE selects the VM (driver/scripts/debuggees.txt); batches on different VMs may run
# concurrently from one checkout with distinct tag prefixes, and the checkout must not change meanwhile.
# Every case runs on a disposable run disk (run-disk.sh): the debuggee idles shut off on its base, each case boots a fresh overlay of
# it, the baseline is verified on that fresh disk, the case runs (the wrapper verifies its own baseline before its checkpoint and runs
# an independent restoration check after the restoration reboot), the gate fields are summarized, and the run's files are deleted
# again, whatever the outcome. A case that left a recovery-required marker or an unclean restoration is reported and the batch goes
# on, because the next case starts from the untouched base anyway. Stops the batch when a fresh run disk does not reach
# BaselineClean=True (the base itself changed) or when a run's files cannot be discarded.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
driver_label=$1; driver_commit=$2; agent_label=$3; agent_commit=$4; mode=$5; prefix=$6; shift 6
policy=29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731
dom="${SAFEUPLOAD_DEBUGGEE:-win10-debug}"; host=$(awk -v d="$dom" '$1==d{print $2}' driver/scripts/debuggees.txt)
[ -n "$host" ] || { echo "Unknown debuggee $dom (driver/scripts/debuggees.txt)"; exit 2; }
export SAFEUPLOAD_DEBUGGEE="$dom"; V="virsh -c qemu:///system"
source "$(dirname "${BASH_SOURCE[0]}")/image-store.sh"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
remote() { python3 driver/scripts/remote_ps.py "$host"; }
wait_up() { for _ in $(seq 1 60); do remote <<<'"up"' >/dev/null 2>&1 && return 0; sleep 5; done; return 1; }
baseline() {  # $1 evidence path
    echo "& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1'" | remote > "$1" 2>&1
    grep -q 'BaselineClean=True' "$1"
}
source "$(dirname "${BASH_SOURCE[0]}")/run-disk.sh"
day=$(date +%F); ev=driver/evidence/$day; mkdir -p "$ev"
for i in $(seq 1 $#); do  # refuse reused suite tags before touching the guest
    tag="${prefix}${i}"
    if compgen -G "driver/evidence/*/phase4-suite-$tag-index.txt" >/dev/null; then
        log "STOP: suite index already exists for $tag; choose a fresh tag prefix"; exit 6
    fi
done
i=0
for case in "$@"; do
    i=$((i+1)); tag="${prefix}${i}"; disk="$ev/batch-$tag-run-disk.txt"
    run_disk_begin "$dom" "$tag" >> "$disk" 2>&1 || { log "STOP: no fresh run disk for $tag ($disk)"; exit 3; }
    wait_up || { log "STOP: guest did not boot on the run disk of $tag"; run_disk_end "$dom" "$tag" >> "$disk" 2>&1; exit 4; }
    baseline "$ev/batch-$tag-pre-baseline.txt" ||
        { log "STOP: baseline not clean on a fresh run disk before $tag: the base changed"; run_disk_end "$dom" "$tag" >> "$disk" 2>&1; exit 2; }
    log "run $tag $case $mode on $dom"
    python3 driver/scripts/Invoke-StagedInvariantQualification.py "$tag" "$driver_label" "$driver_commit" "$agent_label" "$policy" \
        --cases "$case" --modes "$mode" --agent-source-commit "$agent_commit" ${EXTRA_RUNNER_ARGS:-} > "$ev/batch-$tag-runner.log" 2>&1
    index=$(ls -t driver/evidence/*/phase4-suite-"$tag"-index.txt 2>/dev/null | head -1)
    summary=$( [ -n "$index" ] && grep -o '"Verdict": "[A-Z_]*"\|"GatePassed": [a-z]*\|"MvpGatePassed": [a-z]*\|"RestorationClean": [a-z]*\|"ForbiddenByteCount": [0-9a-z]*' "$index" | tr '\n' ' ')
    log "result $tag $case: ${summary:-no index}"
    name="boot-start-invariant-$case-$mode-$tag"
    restored=$(ls driver/evidence/*/"$name"-final-restored-state.txt 2>/dev/null | head -1)
    if ls driver/evidence/*/"$name"-recovery-required.txt >/dev/null 2>&1; then
        log "run $tag left a recovery-required marker; its disk is discarded"
    elif [ -n "$restored" ]; then
        grep -q '^BaselineClean=True' "$restored" && grep -qx 'ProcessCreationAuditRestored=True' "$restored" ||
            log "independent restoration of $tag not clean ($restored); its disk is discarded"
    fi
    run_disk_end "$dom" "$tag" >> "$disk" 2>&1 && grep -qx 'RunDiskBaseUntouched=True' "$disk" ||
        { log "STOP: run files of $tag not discarded cleanly ($disk)"; exit 3; }
    day=$(date +%F); ev=driver/evidence/$day; mkdir -p "$ev"
done
log "batch complete"
