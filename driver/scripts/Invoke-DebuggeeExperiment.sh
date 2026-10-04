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
# EXTRA_FILES are copied to the guest Documents folder AFTER the checkpoint, so the checkpoint stays a clean
# original; PRE_RUN_PS runs on the guest after the checkpoint and before the copy (for example to preserve
# an existing file under a new name). Both are recorded in the gate file.
# Outputs: driver/evidence/<today>/<name>-{baseline,checkpoint,gate,final-restored-state}.txt
# The harness exit status is NOT the verdict; read the gate and the restoration files.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
name="${1:?experiment name}"; harness="${2:?harness script}"; invocation="${3:?PowerShell invocation line}"
day="$(date +%F)"; stamp="$(date +%Y%m%d)"; ev="driver/evidence/$day"; host=192.168.122.51
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
grep -q 'VolumeCacheWritten=True' "$ev/$name-flush.txt" || echo "warning: guest volume cache flush did not report success"

echo "== 2. checkpoint"
# Each run stacks one external overlay; libvirt refuses chains deeper than 200. Stop early with a clear reason.
depth=$(virsh -c qemu:///system dumpxml win10-debug | grep -c '<backingStore type')
echo "BackingChainDepth=$depth"
[ "$depth" -lt 190 ] || { echo "BACKING CHAIN TOO DEEP ($depth layers); flatten it (virsh blockpull) before more runs"; exit 13; }
snap="safeupload-pre-$name-$stamp"; overlay="/var/lib/libvirt/images/win10-debug.$snap"
[ -e "$overlay" ] && { echo "overlay already exists: $overlay"; exit 11; }
{
  echo "UTC=$(date -u +%FT%TZ)"
  echo "virsh -c qemu:///system snapshot-create-as --domain win10-debug --name $snap --description 'Clean original driver and policy before $name' --disk-only --no-metadata --diskspec vda,snapshot=external,file=$overlay --atomic"
  virsh -c qemu:///system snapshot-create-as --domain win10-debug --name "$snap" \
      --description "Clean original driver and policy before $name" --disk-only --no-metadata \
      --diskspec "vda,snapshot=external,file=$overlay" --atomic 2>&1
  echo "--- active disk after checkpoint"
  virsh -c qemu:///system domblklist win10-debug 2>&1
  virsh -c qemu:///system domstate win10-debug 2>&1
} | tee "$ev/$name-checkpoint.txt"
grep -q "$overlay" <(virsh -c qemu:///system domblklist win10-debug) || { echo "CHECKPOINT NOT ACTIVE; aborting"; exit 12; }

echo "== 3. run"
if [ -n "${PRE_RUN_PS:-}" ]; then
    echo "PRE_RUN_PS: $PRE_RUN_PS" | tee "$ev/$name-prerun.txt"
    python3 driver/scripts/remote_ps.py "$host" <<<"$PRE_RUN_PS" 2>&1 | clean | tee "$ev/$name-prerun-result.txt" | tee -a "$ev/$name-prerun.txt"
    pre_run_status=${PIPESTATUS[0]}
    if [ "$pre_run_status" -ne 0 ] || ! grep -qx 'PRE_RUN_OK=True' "$ev/$name-prerun-result.txt"; then
        echo "PRE_RUN failed or omitted PRE_RUN_OK=True; refusing extra-file staging"
        exit 15
    fi
fi
for pair in ${EXTRA_FILES:-}; do
    src="${pair%%=*}"; dst="${pair#*=}"
    scp "${scp_opts[@]}" "$src" "vika@$host:$guest_docs/$dst" || { echo "copy failed: $src"; exit 14; }
    echo "copied $src -> $dst sha256=$(sha256sum "$src" | cut -d' ' -f1)" | tee -a "$ev/$name-prerun.txt"
done
scp "${scp_opts[@]}" "$harness" "vika@$host:$guest_docs/$(basename "$harness")" || { echo "harness copy failed"; exit 13; }

run_remote_phase() {  # $1 evidence label, $2 PowerShell invocation
    local label="$1" command_line="$2"
    python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | clean | tee "$ev/$name-$label.txt"
\$ErrorActionPreference = 'Continue'
try { $command_line; 'HARNESS_RETURNED' } catch { 'HARNESS_THREW: ' + \$_.Exception.Message }
PS
    return "${PIPESTATUS[0]}"
}

request_guest_reboot() {  # $1 evidence label
    local label="$1"
    python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | clean | tee "$ev/$name-$label.txt"
try { & shutdown.exe /r /t 5 /c 'SafeUpload checkpointed boot-start experiment'; 'REBOOT_REQUESTED=True' }
catch { 'REBOOT_REQUEST_FAILED=' + \$_.Exception.Message }
PS
    return "${PIPESTATUS[0]}"
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

if [ "$name" = boot-start ]; then
    : "${BOOT_START_AFTER_BOOT_PS:?set the AfterBoot PowerShell invocation}"
    : "${BOOT_START_FINAL_PS:?set the Finalize PowerShell invocation}"
    run_remote_phase prepare "$invocation"
    grep -qx 'BOOT_PREPARED=True' "$ev/$name-prepare.txt" &&
        grep -qx 'HARNESS_RETURNED' "$ev/$name-prepare.txt" || {
        echo "BOOT PREPARE FAILED; inspect the retained checkpoint and prepare rollback evidence"
        exit 20
    }
    request_guest_reboot reboot-1-requested || true
    if ! wait_for_guest_ssh; then
        {
            echo "GUEST_RECOVERY_REQUIRED=True"
            echo "Checkpoint=$snap"
            echo "ActiveOverlay=$overlay"
            echo "Domain=win10-debug"
            echo "Guest did not return after the boot-Verifier reboot; stop the VM and restore its vda source to the overlay's backing file before retrying."
            virsh -c qemu:///system domblklist win10-debug
            qemu-img info --backing-chain "$overlay"
        } | tee "$ev/$name-recovery-required.txt"
        exit 50
    fi
    run_remote_phase after-boot "$BOOT_START_AFTER_BOOT_PS"
    grep -qx 'BootStartX4AndE1=True' "$ev/$name-after-boot.txt" &&
        grep -qx 'BOOT_RESTORED=True' "$ev/$name-after-boot.txt" &&
        grep -qx 'HARNESS_RETURNED' "$ev/$name-after-boot.txt" || {
        echo "AFTER-BOOT RESTORATION FAILED; preserve checkpoint and inspect guest state"
        exit 21
    }
    request_guest_reboot reboot-restore-requested || true
    if ! wait_for_guest_ssh; then
        {
            echo "GUEST_RECOVERY_REQUIRED=True"
            echo "Checkpoint=$snap"
            echo "ActiveOverlay=$overlay"
            echo "Domain=win10-debug"
            echo "Guest did not return after the restored-driver reboot; retain the external checkpoint for offline repair."
            virsh -c qemu:///system domblklist win10-debug
            qemu-img info --backing-chain "$overlay"
        } | tee "$ev/$name-recovery-required.txt"
        exit 51
    fi
    run_remote_phase finalize "$BOOT_START_FINAL_PS"
    grep -qx 'BOOT_FINAL_STATE=True' "$ev/$name-finalize.txt" &&
        grep -qx 'HARNESS_RETURNED' "$ev/$name-finalize.txt" || {
        echo "FINAL RESTORATION ASSERTIONS FAILED"
        exit 22
    }
else
    python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | clean | tee "$ev/$name-gate.txt"
\$ErrorActionPreference = 'Continue'
try { $invocation; 'HARNESS_RETURNED' } catch { 'HARNESS_THREW: ' + \$_.Exception.Message }
PS
fi

echo "== 4. independent restoration check"
baseline_check "$ev/$name-final-restored-state.txt" >/dev/null
grep -E '^(BaselineClean|OriginalDriverHash|FilterUnloaded|VerifierOff|OriginalPolicyHash|ZeroAgentProcesses|ZeroTestTasks|NoGuidFixtureDirectories)=' "$ev/$name-final-restored-state.txt"
