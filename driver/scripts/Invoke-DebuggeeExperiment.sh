#!/usr/bin/env bash
# One VM experiment on the isolated debuggee, always in the same order:
#   1. independent baseline check (Get-StagedBaseline.ps1), abort unless BaselineClean=True
#   2. disk-only external checkpoint (documented virsh command; earlier disks are preserved)
#   3. copy the harness script, run the given PowerShell line, tee the full output to evidence
#   4. SEPARATE restoration check (a new remote call, not the harness's own output)
# Usage: Invoke-DebuggeeExperiment.sh <name> <harness.ps1 path> '<PowerShell invocation line>'
# Outputs: driver/evidence/<today>/<name>-{baseline,checkpoint,gate,final-restored-state}.txt
# The harness exit status is NOT the verdict; read the gate and the restoration files.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
name="${1:?experiment name}"; harness="${2:?harness script}"; invocation="${3:?PowerShell invocation line}"
day="$(date +%F)"; stamp="$(date +%Y%m%d)"; ev="driver/evidence/$day"; host=192.168.122.51
scp_opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new)
guest_docs='C:/Users/vika/Documents'
clean() { sed 's/<Objs.*//' | tr -d '\r' | grep -v -e '^$' -e CLIXML; }

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

echo "== 2. checkpoint"
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
scp "${scp_opts[@]}" "$harness" "vika@$host:$guest_docs/$(basename "$harness")" || { echo "harness copy failed"; exit 13; }
python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | clean | tee "$ev/$name-gate.txt"
\$ErrorActionPreference = 'Continue'
try { $invocation; 'HARNESS_RETURNED' } catch { 'HARNESS_THREW: ' + \$_.Exception.Message }
PS

echo "== 4. independent restoration check"
baseline_check "$ev/$name-final-restored-state.txt" >/dev/null
grep -E '^(BaselineClean|OriginalDriverHash|FilterUnloaded|VerifierOff|OriginalPolicyHash|ZeroAgentProcesses|ZeroTestTasks|NoGuidFixtureDirectories)=' "$ev/$name-final-restored-state.txt"
