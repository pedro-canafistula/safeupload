#!/usr/bin/env bash
# One VM experiment on the isolated debuggee, always in the same order:
#   1. independent baseline check (Get-StagedBaseline.ps1), abort unless BaselineClean=True
#   1b. guest volume cache written (Write-VolumeCache), so the checkpoint is consistent
#   2. disk-only external checkpoint (documented virsh command; earlier disks are preserved)
#   3. copy the harness script, run the given PowerShell line, tee the full output to evidence
#   4. SEPARATE restoration check (a new remote call, not the harness's own output)
# Usage: [EXTRA_FILES='local=guestname ...'] [PRE_RUN_PS='<PowerShell>'] \
#        Invoke-DebuggeeExperiment.sh <name> <harness.ps1 path> '<PowerShell invocation line>'
# For <name> boot-start, also provide BOOT_START_AFTER_BOOT_PS and
# BOOT_START_FINAL_PS. The harness invocation is Prepare; this wrapper reboots,
# waits for guest SSH, runs AfterBoot, reboots after restoration, then runs
# Finalize. If SSH does not return, the wrapper stops without modifying the
# external checkpoint; use the recorded overlay for offline recovery.
# Suite-specific completion lines may use BOOT_START_{PREPARED,CASE,RESTORED,FINAL}_SENTINEL.
# Defaults preserve the Phase 2 boot-start protocol. These lines are not a case verdict.
# EXTRA_FILES are copied to the guest Documents folder AFTER the checkpoint, so the checkpoint stays a clean
# original; PRE_RUN_PS runs on the guest after the checkpoint and before the copy (for example to preserve
# an existing file under a new name). Both are recorded in the gate file.
# Outputs: driver/evidence/<today>/<name>-{baseline,checkpoint,gate,final-restored-state}.txt
# The harness exit status is NOT the verdict; read the gate and the restoration files.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
name="${1:?experiment name}"; harness="${2:?harness script}"; invocation="${3:?PowerShell invocation line}"
day="$(date +%F)"; stamp="$(date +%Y%m%d)"; ev="driver/evidence/$day"
dom="${SAFEUPLOAD_DEBUGGEE:-win10-debug}"; host=$(awk -v d="$dom" '$1==d{print $2}' driver/scripts/debuggees.txt)
[ -n "$host" ] || { echo "Unknown debuggee $dom (driver/scripts/debuggees.txt)"; exit 2; }
mkdir -p "$ev"
scp_opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new)
guest_docs='C:/Users/vika/Documents'
clean() { perl -pe 's/<Objs.*?<\/Objs>//g' | tr -d '\r' | grep -v -e '^$' -e CLIXML; }   # strip only the progress spans, never the text around them

baseline_check() {  # $1 = output file
    scp "${scp_opts[@]}" driver/scripts/Get-StagedBaseline.ps1 "vika@$host:$guest_docs/Get-StagedBaseline.ps1" || return 2
    python3 driver/scripts/remote_ps.py "$host" <<'PS' 2>&1 | clean | tee "$1"
& 'C:\Users\vika\Documents\Get-StagedBaseline.ps1'
PS
}

echo "== 1. baseline"
baseline_check "$ev/$name-baseline.txt" >/dev/null
grep -q '^BaselineClean=True' "$ev/$name-baseline.txt" || { echo "BASELINE NOT CLEAN; aborting before any change"; cat "$ev/$name-baseline.txt"; exit 10; }
echo "baseline clean"
# Write the guest volume cache before the disk-only checkpoint, so the frozen layer never holds metadata without data.
python3 driver/scripts/remote_ps.py "$host" <<'PS' 2>&1 | clean | tee "$ev/$name-flush.txt" >/dev/null
try { Write-VolumeCache -DriveLetter C; 'VolumeCacheWritten=True' } catch { 'VolumeCacheWritten=False ' + $_.Exception.Message }
PS
grep -qx 'VolumeCacheWritten=True' "$ev/$name-flush.txt" || {
    echo "guest volume cache flush failed; aborting before checkpoint"
    cat "$ev/$name-flush.txt"
    exit 16
}

echo "== 2. checkpoint"
# Each run stacks one external overlay; libvirt refuses chains deeper than 200. Stop early with a clear reason.
depth=$(virsh -c qemu:///system dumpxml "$dom" | grep -c '<backingStore type')
echo "BackingChainDepth=$depth"
[ "$depth" -lt 190 ] || { echo "BACKING CHAIN TOO DEEP ($depth layers); flatten it (virsh blockpull) before more runs"; exit 13; }
source "$(dirname "${BASH_SOURCE[0]}")/image-store.sh"; V="virsh -c qemu:///system"
IMGDIR=$(image_dir_of_domain "$dom"); image_dir_check "$IMGDIR" || exit 13
snap="safeupload-pre-$name-$stamp"; overlay="$IMGDIR/$dom.$snap"
[ -e "$overlay" ] && { echo "overlay already exists: $overlay"; exit 11; }
{
  echo "UTC=$(date -u +%FT%TZ)"
  echo "virsh -c qemu:///system snapshot-create-as --domain $dom --name $snap --description 'Clean original driver and policy before $name' --disk-only --no-metadata --diskspec vda,snapshot=external,file=$overlay --atomic"
  virsh -c qemu:///system snapshot-create-as --domain $dom --name "$snap" \
      --description "Clean original driver and policy before $name" --disk-only --no-metadata \
      --diskspec "vda,snapshot=external,file=$overlay" --atomic 2>&1
  echo "--- active disk after checkpoint"
  virsh -c qemu:///system domblklist "$dom" 2>&1
  virsh -c qemu:///system domstate "$dom" 2>&1
} | tee "$ev/$name-checkpoint.txt"
grep -q "$overlay" <(virsh -c qemu:///system domblklist "$dom") || {
    echo "CHECKPOINT NOT ACTIVE; aborting"
    exit 12
}

write_offline_rollback_step() {
    local backing format quoted_backing output="$ev/$name-offline-rollback.txt"
    backing="$(qemu-img info --output=json "$overlay" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("backing-filename", ""))')"
    if [ -z "$backing" ]; then
        echo "Could not determine the checkpoint overlay backing file: $overlay" | tee "$output"
        return 1
    fi
    case "$backing" in
        /*) ;;
        *) backing="$(realpath -m "$(dirname "$overlay")/$backing")" ;;
    esac
    format="$(qemu-img info --output=json "$backing" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("format", ""))')"
    if [ -z "$format" ]; then
        echo "Could not determine the backing disk format: $backing" | tee "$output"
        return 1
    fi
    printf -v quoted_backing '%q' "$backing"
    {
        echo 'OFFLINE_ROLLBACK_OPERATOR_STEP=True'
        echo 'These commands are recorded for an operator. The wrapper will not repoint VM disks.'
        echo 'Run only after inspecting the guest and deciding to roll it back to the checkpoint parent.'
        echo '1. Stop the VM if it is running:'
        echo "virsh -c qemu:///system destroy $dom"
        echo '2. Confirm the current vda source:'
        echo "virsh -c qemu:///system domblklist $dom --details"
        echo '3. Remove vda from the persistent VM definition:'
        echo "virsh -c qemu:///system detach-disk $dom vda --config"
        echo '4. Attach the checkpoint parent disk as vda:'
        echo "virsh -c qemu:///system attach-disk $dom $quoted_backing vda --driver qemu --subdriver $format --targetbus virtio --config"
        echo '5. Verify the persistent vda source before starting the VM:'
        echo "virsh -c qemu:///system domblklist $dom --details"
        echo "CheckpointOverlay=$overlay"
        echo "CheckpointParent=$backing"
        echo "CheckpointParentFormat=$format"
    } | tee "$output"
}

record_recovery_required() {  # $1 concise reason
    {
        echo "GUEST_RECOVERY_REQUIRED=True"
        echo "Reason=$1"
        echo "Checkpoint=$snap"
        echo "ActiveOverlay=$overlay"
        echo "Domain=$dom"
        virsh -c qemu:///system domblklist "$dom" --details
        qemu-img info --backing-chain "$overlay"
    } | tee "$ev/$name-recovery-required.txt"
    write_offline_rollback_step || true
}

echo "== 3. run"
if [ -n "${PRE_RUN_PS:-}" ]; then
    echo "PRE_RUN_PS: $PRE_RUN_PS" | tee "$ev/$name-prerun.txt"
    for pre_attempt in 1 2 3; do  # the first guest call right after a disk-only checkpoint can fail transiently
        python3 driver/scripts/remote_ps.py "$host" <<<"$PRE_RUN_PS" 2>&1 | clean | tee "$ev/$name-prerun-result.txt" | tee -a "$ev/$name-prerun.txt"
        pre_run_status=${PIPESTATUS[0]}
        [ "$pre_run_status" -eq 0 ] && grep -qx 'PRE_RUN_OK=True' "$ev/$name-prerun-result.txt" && break
        echo "PRE_RUN attempt $pre_attempt failed (status $pre_run_status); retrying" | tee -a "$ev/$name-prerun.txt"
        sleep 10
    done
    if [ "$pre_run_status" -ne 0 ] || ! grep -qx 'PRE_RUN_OK=True' "$ev/$name-prerun-result.txt"; then
        echo "PRE_RUN failed or omitted PRE_RUN_OK=True; refusing extra-file staging"
        record_recovery_required 'PRE_RUN failed after the checkpoint became active.'
        exit 15
    fi
fi
for pair in ${EXTRA_FILES:-}; do
    src="${pair%%=*}"; dst="${pair#*=}"
    scp "${scp_opts[@]}" "$src" "vika@$host:$guest_docs/$dst" || {
        echo "copy failed: $src"
        record_recovery_required "Could not stage extra file $dst after checkpoint."
        exit 14
    }
    echo "copied $src -> $dst sha256=$(sha256sum "$src" | cut -d' ' -f1)" | tee -a "$ev/$name-prerun.txt"
done
scp "${scp_opts[@]}" "$harness" "vika@$host:$guest_docs/$(basename "$harness")" || {
    echo "harness copy failed"
    record_recovery_required 'Could not stage the harness after the checkpoint became active.'
    exit 13
}

run_remote_phase() {  # $1 evidence label, $2 PowerShell invocation
    local label="$1" command_line="$2"
    python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | clean | tee "$ev/$name-$label.txt"
\$ErrorActionPreference = 'Continue'
try { $command_line; 'HARNESS_RETURNED' } catch { 'HARNESS_THREW: ' + \$_.Exception.Message }
PS
    return "${PIPESTATUS[0]}"
}

w01_afterboot_restoration_gate() {  # phase transport status and $name-after-boot.txt
    local transport_status="$1" file="$2" returned restored diagnostic_true diagnostic_false case_true case_any restored_any diagnostic_any
    [ "$transport_status" -eq 0 ] && [ -f "$file" ] || return 1
    returned="$(grep -Fxc -- 'HARNESS_RETURNED' "$file" || true)"
    restored="$(grep -Fxc -- 'W01_RESTORED=True' "$file" || true)"
    restored_any="$(grep -c '^W01_RESTORED=' "$file" || true)"
    diagnostic_true="$(grep -Fxc -- 'W01_DIAGNOSTIC_COMPLETED=True' "$file" || true)"
    diagnostic_false="$(grep -Fxc -- 'W01_DIAGNOSTIC_COMPLETED=False' "$file" || true)"
    diagnostic_any="$(grep -c '^W01_DIAGNOSTIC_COMPLETED=' "$file" || true)"
    case_true="$(grep -Fxc -- 'W01_CASE_COMPLETED=True' "$file" || true)"
    case_any="$(grep -c '^W01_CASE_COMPLETED=' "$file" || true)"
    [ "$returned" -eq 1 ] && [ "$restored" -eq 1 ] && [ "$restored_any" -eq 1 ] || return 1
    [ "$diagnostic_any" -eq 1 ] && [ $((diagnostic_true + diagnostic_false)) -eq 1 ] || return 1
    ! grep -q '^HARNESS_THREW' "$file" || return 1
    if [ "$diagnostic_true" -eq 1 ]; then
        [ "$case_true" -eq 1 ] && [ "$case_any" -eq 1 ] || return 1
    else
        [ "$case_any" -eq 0 ] || return 1
    fi
}

request_guest_reboot() {  # $1 evidence label
    local label="$1"
    python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | clean | tee "$ev/$name-$label.txt"
try { & shutdown.exe /r /t 5 /c 'SafeUpload checkpointed boot-start experiment'; 'REBOOT_REQUESTED=True' }
catch { 'REBOOT_REQUEST_FAILED=' + \$_.Exception.Message }
PS
    local remote_status=${PIPESTATUS[0]}
    [ "$remote_status" -eq 0 ] && grep -qx 'REBOOT_REQUESTED=True' "$ev/$name-$label.txt"
}

wait_for_guest_ssh() {  # allow up to 15 minutes; boot Verifier can delay logon
    local attempt
    for attempt in $(seq 1 90); do
        if ssh "${scp_opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo safeupload-ssh-ready' >/dev/null 2>&1; then
            echo "guest SSH returned after reboot (attempt $attempt)"
            return 0
        fi
        sleep 5
    done
    return 1
}

guest_boot_time() {  # $1 evidence label; prints the guest's current LastBootUpTime
    local label output
    label="$1"
    output="$ev/$name-$label.txt"
    python3 driver/scripts/remote_ps.py "$host" <<'PS' 2>&1 | clean | tee "$output" >/dev/null
try {
    $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
    'GuestLastBootUpTime=' + $boot
} catch { 'GuestLastBootUpTimeError=' + $_.Exception.Message; exit 1 }
PS
    local remote_status=${PIPESTATUS[0]}
    [ "$remote_status" -eq 0 ] || return 1
    grep '^GuestLastBootUpTime=' "$output" | tail -n 1 | cut -d= -f2-
}

wait_for_changed_boot_time() {  # $1 previous LastBootUpTime, $2 evidence label
    local before="$1" label="$2" current attempt
    for attempt in $(seq 1 24); do
        current="$(guest_boot_time "$label-attempt-$attempt")" || current=''
        if [ -n "$current" ] && [ "$current" != "$before" ]; then
            echo "BootIdentityChanged=True;Before=$before;After=$current" | tee "$ev/$name-$label-changed.txt"
            return 0
        fi
        sleep 5
    done
    echo "BootIdentityChanged=False;Before=$before;LastObserved=$current" | tee "$ev/$name-$label-changed.txt"
    return 1
}

case "$name" in boot-start*) boot_start_run=1 ;; *) boot_start_run=0 ;; esac
if [ "$boot_start_run" = 1 ]; then
    : "${BOOT_START_AFTER_BOOT_PS:?set the AfterBoot PowerShell invocation}"
    : "${BOOT_START_FINAL_PS:?set the Finalize PowerShell invocation}"
    run_remote_phase prepare "$invocation"
    grep -Fqx -- "${BOOT_START_PREPARED_SENTINEL:-BOOT_PREPARED=True}" "$ev/$name-prepare.txt" &&
        grep -qx 'HARNESS_RETURNED' "$ev/$name-prepare.txt" || {
        echo "BOOT PREPARE FAILED; inspect the retained checkpoint and prepare rollback evidence"
        record_recovery_required 'Prepare failed after the checkpoint became active.'
        exit 20
    }
    boot_before_1="$(guest_boot_time reboot-1-before)" || {
        echo "Could not read LastBootUpTime before the first reboot"
        record_recovery_required 'Could not read LastBootUpTime before requesting the first reboot.'
        exit 23
    }
    request_guest_reboot reboot-1-requested || {
        echo "Guest reboot request failed; aborting without claiming a reboot"
        cat "$ev/$name-reboot-1-requested.txt"
        record_recovery_required 'Guest rejected the first reboot request.'
        exit 24
    }
    if ! wait_for_guest_ssh; then
        record_recovery_required 'Guest did not return after the boot-Verifier reboot.'
        exit 50
    fi
    if ! wait_for_changed_boot_time "$boot_before_1" reboot-1; then
        record_recovery_required 'LastBootUpTime did not change after the first reboot request.'
        exit 52
    fi
    run_remote_phase after-boot "$BOOT_START_AFTER_BOOT_PS"
    after_boot_transport_status=$?
    if [[ "$name" == boot-start-w01-* ]]; then
        if ! w01_afterboot_restoration_gate "$after_boot_transport_status" "$ev/$name-after-boot.txt"; then
            echo "AFTER-BOOT RESTORATION FAILED; preserve checkpoint and inspect guest state"
            record_recovery_required 'W01 AfterBoot phase transport failed/pended or safe restoration evidence was incomplete.'
            exit 21
        fi
    else
        grep -Fqx -- "${BOOT_START_CASE_SENTINEL:-BootStartX4AndE1=True}" "$ev/$name-after-boot.txt" &&
            grep -Fqx -- "${BOOT_START_RESTORED_SENTINEL:-BOOT_RESTORED=True}" "$ev/$name-after-boot.txt" &&
            grep -qx 'HARNESS_RETURNED' "$ev/$name-after-boot.txt" || {
            echo "AFTER-BOOT RESTORATION FAILED; preserve checkpoint and inspect guest state"
            record_recovery_required 'AfterBoot harness failed or restoration was incomplete.'
            exit 21
        }
    fi
    boot_before_2="$(guest_boot_time reboot-restore-before)" || {
        record_recovery_required 'Could not read LastBootUpTime before the restoration reboot.'
        exit 25
    }
    request_guest_reboot reboot-restore-requested || {
        record_recovery_required 'Guest restoration reboot request failed.'
        exit 26
    }
    if ! wait_for_guest_ssh; then
        record_recovery_required 'Guest did not return after the restored-driver reboot.'
        exit 51
    fi
    if ! wait_for_changed_boot_time "$boot_before_2" reboot-restore; then
        record_recovery_required 'LastBootUpTime did not change after the restoration reboot request.'
        exit 53
    fi
    run_remote_phase finalize "$BOOT_START_FINAL_PS"
    grep -Fqx -- "${BOOT_START_FINAL_SENTINEL:-BOOT_FINAL_STATE=True}" "$ev/$name-finalize.txt" &&
        grep -qx 'HARNESS_RETURNED' "$ev/$name-finalize.txt" || {
        echo "FINAL RESTORATION ASSERTIONS FAILED"
        record_recovery_required 'Final restoration assertions failed after the restoration reboot.'
        exit 22
    }
else
    # A guest command that never returns (registry-txf run 2: fltmc unload parked in FltUnregisterFilter) must not stall the run.
    timeout "${HARNESS_TIMEOUT_SECONDS:-5400}" python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | clean | tee "$ev/$name-gate.txt"
\$ErrorActionPreference = 'Continue'
try { $invocation; 'HARNESS_RETURNED' } catch { 'HARNESS_THREW: ' + \$_.Exception.Message }
PS
    if [ "${PIPESTATUS[0]}" -eq 124 ]; then
        echo "HARNESS_TIMEOUT=True;Seconds=${HARNESS_TIMEOUT_SECONDS:-5400}" | tee -a "$ev/$name-gate.txt"
        record_recovery_required "The guest harness did not return within ${HARNESS_TIMEOUT_SECONDS:-5400} s; a guest command is hung."
    fi
fi

echo "== 4. independent restoration check"
baseline_check "$ev/$name-final-restored-state.txt" >/dev/null
for audit_field in ProcessCreationAuditFlags ProcessCreationAuditPerUserCount; do
    before_audit=$(grep -E "^$audit_field=[0-9]+$" "$ev/$name-baseline.txt")
    after_audit=$(grep -E "^$audit_field=[0-9]+$" "$ev/$name-final-restored-state.txt")
    if [ -z "$before_audit" ] || [ "$before_audit" != "$after_audit" ] || [ "$(printf '%s\n' "$before_audit" | wc -l)" -ne 1 ]; then
        echo "ProcessCreationAuditRestored=False;Field=$audit_field" | tee -a "$ev/$name-final-restored-state.txt"
        record_recovery_required 'Process-creation audit policy differs from independent pre-case baseline'
        exit 19
    fi
done
echo 'ProcessCreationAuditRestored=True' | tee -a "$ev/$name-final-restored-state.txt"
grep -E '^(BaselineClean|OriginalDriverHash|FilterUnloaded|VerifierOff|OriginalPolicyHash|ZeroAgentProcesses|ZeroTestTasks|NoGuidFixtureDirectories)=' "$ev/$name-final-restored-state.txt"
