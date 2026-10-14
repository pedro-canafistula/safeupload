#!/usr/bin/env bash
# T4: N save cycles in one boot (approve and block mixed, four save patterns) on a debuggee in a disposable run disk (run-disk.sh,
# always deleted afterwards; the base disk is never written). Proves that staged versions are released (no 128-per-boot ceiling),
# that the driver's pool stays flat and that the event-driven stage worker goes idle.
#
# Usage: driver/scripts/Invoke-StageCycles.sh <debuggee domain> <tag> <driver.sys> <agent zip> [cycles=10000] [ordinary|runtime-verifier|verifier-from-boot] [sample_every=500]
#   Installs the pair like the manual install and reboots. Runtime mode holds both services at demand start across that reboot,
#   arms volatile Verifier while the filter is still unloaded (flags 0x13B: special pool, IRQL, pool tracking, I/O, deadlock,
#   security checks), loads it once, starts the agent, restores product start modes, and waits for Ready. Creates a standard
#   user and runs t4/cycles-coordinator.ps1 as SYSTEM with
#   t4/cycles-actor.ps1 as the standard user.
#
# Evidence: driver/evidence/<day>/<tag>-*.txt|jsonl; the verdict is <tag>-verdict.txt; the exit status is 0 only when every required
# line passes.
# T4_MEMORY_TOOLS may name a local directory containing debuggers.zip and the exact SafeUpload.pdb.
# This adds read-only local-KD attribution and fixed-identity controls on the throwaway disk. It is diagnostic,
# not milestone qualification; all original verdicts remain unchanged. No host debugger/configuration is installed.
# T4_HANDBACK_DIAGNOSTIC=yes runs the owner-authorized (2026-10-13) hand-back attribution row: blocks three cycles in four, and after
# the purged sample records which processes hold the kept files, deletes only the hand-backs and samples again before and after a
# second purge. It requires boot Verifier and fewer than 10,000 cycles; its verdict is labelled non-qualifying and passes no T4 gate.
# T4_DELETE_ATTRIBUTION=yes adds a 256-file identity-resolved deletion diagnostic after purged. Requires T4_MEMORY_TOOLS,
# boot Verifier and cycles < 10000. With T4_HANDBACK_DIAGNOSTIC=yes, inventory/delete the block-heavy hand-backs instead,
# after recording the fresh-purge release proxy. Both paths are non-qualifying; original gates unchanged.
# T4_VOLUME_DISCRIMINATOR=yes adds a non-qualifying 512-file NTFS VHD open/delete/teardown diagnostic after the existing samples.
# Requires boot Verifier, cycles < 10000 and explicit win10-debug3; no memory tools needed. Cannot combine with delete attribution;
# classification is INFO only, and diskpart/fltmc receipts travel with the existing failure-evidence export.
# T4_PURGE_ATTRIBUTION=yes records per-window Kernel-File ETW and SUfl/SUwH timelines, then repeat/agent-stop purge controls.
# Non-qualifying; cycles < 10000; cannot combine with hand-back, delete or volume diagnostics.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
dom="${1:?debuggee domain}"; tag="${2:?tag}"; sys="${3:?driver.sys}"; zip="${4:?agent zip}"; cycles="${5:-10000}"; mode="${6:-runtime-verifier}"; sample_every="${7:-500}"
[[ "$tag" =~ ^[A-Za-z0-9]{3,30}$ ]] || { echo 'Invalid tag'; exit 2; }
[[ "$cycles" =~ ^[0-9]{1,6}$ ]] || { echo 'Invalid cycle count'; exit 2; }
[[ "$sample_every" =~ ^[1-9][0-9]{0,5}$ ]] || { echo 'Invalid sample interval'; exit 2; }
case "$mode" in ordinary|runtime-verifier|verifier-from-boot) ;; *) echo 'Unknown mode'; exit 2;; esac
purge_attribution=${T4_PURGE_ATTRIBUTION-no}
case "$purge_attribution" in
    no) ;;
    yes) [ "$cycles" -lt 10000 ] || {
            echo 'Purge attribution requires fewer than 10,000 cycles'; exit 2; }
         for forbidden in T4_HANDBACK_DIAGNOSTIC T4_DELETE_ATTRIBUTION T4_VOLUME_DISCRIMINATOR; do
             [ "${!forbidden:-no}" != yes ] || {
                 echo "Purge attribution cannot be combined with $forbidden"; exit 2; }
         done ;;
    *) echo 'T4_PURGE_ATTRIBUTION must be yes or no'; exit 2 ;;
esac
memory_tools=${T4_MEMORY_TOOLS:-}
memory_enabled=no
if [ -n "$memory_tools" ]; then
    [ "$mode" = verifier-from-boot ] && [ -s "$memory_tools/debuggers.zip" ] && [ -s "$memory_tools/SafeUpload.pdb" ] || {
        echo 'Memory attribution requires boot Verifier, debugger archive and exact PDB'; exit 2;
    }
    memory_enabled=yes
fi
handback_diagnostic=${T4_HANDBACK_DIAGNOSTIC:-no}
case "$handback_diagnostic" in
    no) ;;
    yes) [ "$mode" = verifier-from-boot ] && [ "$cycles" -lt 10000 ] || {
            echo 'The hand-back diagnostic requires boot Verifier and fewer than 10,000 cycles'; exit 2; } ;;
    *) echo 'T4_HANDBACK_DIAGNOSTIC must be yes or no'; exit 2 ;;
esac
delete_attribution=${T4_DELETE_ATTRIBUTION:-no}
case "$delete_attribution" in
    no) ;;
    yes) [ "$memory_enabled" = yes ] && [ "$mode" = verifier-from-boot ] && [ "$cycles" -lt 10000 ] || {
            echo 'Delete attribution requires T4_MEMORY_TOOLS, boot Verifier, fewer than 10,000 cycles'; exit 2; }
         [ "$dom" = win10-debug3 ] && [ "${SAFEUPLOAD_DEBUGGEE:-}" = win10-debug3 ] || {
            echo 'Delete attribution requires explicit SAFEUPLOAD_DEBUGGEE=win10-debug3 and target win10-debug3'; exit 2; } ;;
    *) echo 'T4_DELETE_ATTRIBUTION must be yes or no'; exit 2 ;;
esac
volume_discriminator=${T4_VOLUME_DISCRIMINATOR:-no}
case "$volume_discriminator" in
    no) ;;
    yes) [ "$mode" = verifier-from-boot ] && [ "$cycles" -lt 10000 ] || {
            echo 'Volume discriminator requires boot Verifier and fewer than 10,000 cycles'; exit 2; }
         [ "$dom" = win10-debug3 ] && [ "${SAFEUPLOAD_DEBUGGEE:-}" = win10-debug3 ] || {
            echo 'Volume discriminator requires explicit SAFEUPLOAD_DEBUGGEE=win10-debug3 and target win10-debug3'; exit 2; }
         [ "$delete_attribution" = no ] || {
            echo 'Volume discriminator cannot be combined with T4_DELETE_ATTRIBUTION'; exit 2; } ;;
    *) echo 'T4_VOLUME_DISCRIMINATOR must be yes or no'; exit 2 ;;
esac
# verifier-from-boot: the same Verifier flags (0x13B) configured persistently before the install reboot, so pool tracking covers the
# driver from its first allocation and the agent reaches Ready through the normal boot path (runtime-verifier's fltmc load after
# boot is a late attach, which never reports Ready).
[ -f "$sys" ] && [ -f "$zip" ] || { echo 'needs the signed driver and the agent zip'; exit 2; }
driver_sha=$(sha256sum "$sys" | cut -d' ' -f1) || exit 2
host=$(awk -v d="$dom" '$1==d{print $2}' driver/scripts/debuggees.txt); [ -n "$host" ] || { echo "Unknown debuggee $dom"; exit 2; }
export SAFEUPLOAD_MIN_FREE_GB=${T4_MIN_FREE_GB:-15}
V="virsh -c qemu:///system"; ev="driver/evidence/$(date +%F)"; mkdir -p "$ev"
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new)
guest='C:/Users/vika/Documents'
clean() { python3 -c '
import re, sys, html
text = sys.stdin.read()
errors = ["ERROR: " + html.unescape(m).replace("_x000D__x000A_", "\n") for m in re.findall(r"<S S=\"Error\">(.*?)</S>", text, flags=re.S)]
text = re.sub(r"<Objs.*?</Objs>", "", text, flags=re.S).replace("#< CLIXML", "").replace("\r", "")
print("\n".join(line for line in (text.split("\n") + errors) if line.strip()))
'; }
remote() { python3 driver/scripts/remote_ps.py "$host" 2>&1 | clean; }
wait_ssh() { for _ in $(seq 1 90); do ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }
started=$(date +%s)
stop_reason='setup-or-test-exit'
phase=run-disk
state=NOT_STARTED
waited=0
failure_evidence_exported=no
purge_evidence_exported=no
capture_purge_evidence() {
    [ "$purge_attribution" = yes ] && [ "$purge_evidence_exported" = no ] || return 0
    mkdir -p "$ev/$tag-purge-attribution"
    # scp supports binary ETLs; retain the entire folder before the disposable disk goes away.
    if timeout 90 scp -r "${opts[@]}" "vika@$host:C:/T4/purge-attribution" "$ev/$tag-purge-attribution/" > "$ev/$tag-purge-attribution-copy.txt" 2>&1; then
        echo 'T4PurgeAttributionExport=CAPTURED' > "$ev/$tag-purge-attribution-export.txt"
        purge_evidence_exported=yes
    else
        echo 'T4PurgeAttributionExport=ABSENT_OR_FAILED' > "$ev/$tag-purge-attribution-export.txt"
    fi
}
capture_failure_evidence() {
    capture_purge_evidence
    [ "$failure_evidence_exported" = yes ] && return 0
    mkdir -p "$ev/$tag-failure-evidence"
    # The trap calls this too, so interruption cannot silently lose snapshots
    # already captured by the coordinator before its run disk is discarded.
    if timeout 90 scp -r "${opts[@]}" "vika@$host:C:/T4/failure-evidence" "$ev/$tag-failure-evidence/" > "$ev/$tag-failure-evidence-copy.txt" 2>&1; then
        echo 'T4FailureEvidenceExport=CAPTURED' > "$ev/$tag-failure-evidence-export.txt"
        failure_evidence_exported=yes
    else
        echo 'T4FailureEvidenceExport=ABSENT_OR_FAILED' > "$ev/$tag-failure-evidence-export.txt"
    fi
}

echo "== run disk"
source "$(dirname "${BASH_SOURCE[0]}")/image-store.sh"; source "$(dirname "${BASH_SOURCE[0]}")/run-disk.sh"
run_disk_begin "$dom" "$tag" > "$ev/$tag-checkpoint.txt" 2>&1 || { cat "$ev/$tag-checkpoint.txt"; exit 12; }
# An unreachable debuggee is usually a bugcheck spinning in kdcom (it looks like a hang). Before the trap discards the run
# disk, keep a screenshot, two vCPU time samples 10 s apart (spinning versus idle) and, unless T4_CAPTURE_DUMP=no, a full
# guest memory dump in /var/tmp (libvirt-qemu 0400; read it through a transient libvirt pool, convert with elf2dmp, then
# delete it as soon as it is analysed). Diagnostic only: it never changes a verdict or exit status.
unreachable_captured=no
capture_unreachable() {  # $1 label; at most once per run
    local label=$1 elf free
    [ "$unreachable_captured" = no ] || return 0
    unreachable_captured=yes
    $V screenshot "$dom" "$ev/$tag-$label.png" >/dev/null 2>&1 && echo "UnreachableScreenshot=$tag-$label.png"
    { date -u +%FT%TZ; $V domstats "$dom" --vcpu --cpu-total; sleep 10; date -u +%FT%TZ; $V domstats "$dom" --vcpu --cpu-total; } \
        > "$ev/$tag-$label-vcpu.txt" 2>&1
    [ "${T4_CAPTURE_DUMP:-yes}" = yes ] || { echo 'UnreachableDump=DISABLED'; return 0; }
    free=$(df --output=avail -BG /var/tmp | tail -1 | tr -dc '0-9')
    [ "${free:-0}" -ge 30 ] || { echo "UnreachableDump=SKIPPED_LOW_SPACE free=${free}G"; return 0; }
    elf="/var/tmp/safeupload-$tag-$label.elf"
    if timeout 1200 $V qemu-monitor-command "$dom" --hmp "dump-guest-memory $elf" > "$ev/$tag-$label-dump.txt" 2>&1 && [ -e "$elf" ]; then
        echo "UnreachableDump=$elf"
    else
        echo 'UnreachableDump=FAILED'
    fi
}
finish() {
    local test_status=$?
    trap - EXIT TERM INT HUP
    printf 'T4StopReason=%s;ExitCode=%s;Phase=%s;Progress=%s;ElapsedSeconds=%s\n' \
        "$stop_reason" "$test_status" "$phase" "$state" "$waited" | tee "$ev/$tag-stop.txt"
    if [ "$memory_enabled" = yes ]; then
        mkdir -p "$ev/$tag-memory"
        if timeout 60 scp -r "${opts[@]}" "vika@$host:C:/T4Memory/output" "$ev/$tag-memory/" \
            > "$ev/$tag-memory-export.txt" 2>&1; then
            echo 'T4MemoryEvidenceExport=PASS' >> "$ev/$tag-memory-export.txt"
        else
            echo 'T4MemoryEvidenceExport=FAILED' >> "$ev/$tag-memory-export.txt"
            test_status=25
        fi
    fi
    # A failed run whose guest no longer answers (for example a bugcheck after boot) is captured before the disk is discarded.
    if [ "$test_status" != 0 ] && [ "$phase" != run-disk ] &&
        ! ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1; then
        capture_unreachable "exit-$test_status" >> "$ev/$tag-stop.txt"  # no pipe: the flag stays in this shell
        grep '^Unreachable' "$ev/$tag-stop.txt"
    fi
    if [ "$phase" = cycles ]; then
        # Preserve partial progress even when the launcher receives a signal.
        timeout 90 scp "${opts[@]}" "vika@$host:C:/T4/cycles.jsonl" "$ev/$tag-cycles-at-stop.jsonl" >/dev/null 2>&1 || true
        timeout 90 scp "${opts[@]}" "vika@$host:C:/T4/samples.jsonl" "$ev/$tag-samples-at-stop.jsonl" >/dev/null 2>&1 || true
        capture_failure_evidence
    fi
    echo "== discard the run disk"
    if ! run_disk_end "$dom" "$tag" > "$ev/$tag-final-restored-state.txt" 2>&1 ||
        ! grep -qx 'RunDiskBaseUntouched=True' "$ev/$tag-final-restored-state.txt"; then
        cat "$ev/$tag-final-restored-state.txt"
        echo 'T4Restoration=FAIL'
        exit 22
    fi
    cat "$ev/$tag-final-restored-state.txt"
    # Separate baseline boot/check after the tested run has ended and its disk is gone.
    if ! bash driver/scripts/Verify-RunDiskRestoration.sh "$dom" "${tag}restore" > "$ev/$tag-independent-restoration.txt" 2>&1; then
        cat "$ev/$tag-independent-restoration.txt"
        echo 'T4Restoration=FAIL'; exit 22
    fi
    echo 'T4IndependentRestoration=PASS'
    exit "$test_status"
}
trap finish EXIT
trap 'stop_reason=signal-TERM; exit 143' TERM
trap 'stop_reason=signal-INT; exit 130' INT
trap 'stop_reason=signal-HUP; exit 129' HUP
wait_ssh || { echo 'guest did not boot on the run disk'; exit 3; }

phase=baseline
echo "== baseline"
scp "${opts[@]}" driver/scripts/Get-StagedBaseline.ps1 "vika@$host:$guest/Get-StagedBaseline.ps1" || exit 3
echo "& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1'" | remote | tee "$ev/$tag-baseline.txt" >/dev/null
grep -q '^BaselineClean=True' "$ev/$tag-baseline.txt" || { echo 'BASELINE NOT CLEAN on a fresh run disk: the base changed'; exit 10; }
case "$dom" in
    win10-debug3) expected_uuid=FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3 ;;
    *) echo 'T4 now uses the owner-selected VM win10-debug3 only'; exit 10 ;;
esac
grep -qx "UUID=$expected_uuid" "$ev/$tag-baseline.txt" || { echo 'Wrong VM identity'; exit 10; }


# As in the invariant batch, settle the guest's cold-boot clock before the install reboot. Deadlines remain monotonic.
clock_now=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
remote <<PS > "$ev/$tag-clock.txt"
\$target = [DateTime]::Parse('$clock_now', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
'GuestSkewSecondsBefore=' + [math]::Round(([DateTime]::UtcNow - \$target).TotalSeconds, 1)
Start-Service w32time -ErrorAction SilentlyContinue
\$ok = \$false
for (\$i = 0; \$i -lt 15 -and -not \$ok; \$i++) { \$r = (& w32tm.exe /resync /force 2>&1 | Out-String); if (\$LASTEXITCODE -eq 0 -and \$r -notmatch 'did not resync') { \$ok = \$true } else { Start-Sleep -Seconds 2 } }
'GuestTimeServiceResync=' + \$ok
if (-not \$ok) { Set-Date -Date \$target.ToLocalTime() | Out-Null; 'GuestClockSetFromHost=True' }
PS
clock_now=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
remote <<PS >> "$ev/$tag-clock.txt"
\$target = [DateTime]::Parse('$clock_now', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
\$skew = ([DateTime]::UtcNow - \$target).TotalSeconds
'GuestSkewSecondsAfter=' + [math]::Round(\$skew, 1)
'GuestClockSynced=' + ([math]::Abs(\$skew) -le 10)
PS
grep -qx 'GuestClockSynced=True' "$ev/$tag-clock.txt" || { echo 'guest clock not synchronized'; exit 11; }

phase=install
echo "== stage files and install"
sleep 5
scp "${opts[@]}" "$sys" "vika@$host:$guest/SafeUpload-t4.sys" && scp "${opts[@]}" "$zip" "vika@$host:$guest/stage-service-publish.zip" \
  && scp "${opts[@]}" agente/scripts/Install-SafeUploadAgent.ps1 "vika@$host:$guest/Install-SafeUploadAgent.ps1" \
  && scp "${opts[@]}" agente/scripts/Protect-SafeUploadPolicy.ps1 "vika@$host:$guest/Protect-SafeUploadPolicy.ps1" \
  && scp "${opts[@]}" agente/scripts/Get-SafeUploadDiagnostics.ps1 "vika@$host:$guest/Get-SafeUploadDiagnostics.ps1" \
  && scp "${opts[@]}" driver/scripts/t4/cycles-actor.ps1 "vika@$host:$guest/t4-cycles-actor.ps1" \
  && scp "${opts[@]}" driver/scripts/t4/cycles-coordinator.ps1 "vika@$host:$guest/t4-cycles-coordinator.ps1" \
  && scp "${opts[@]}" driver/scripts/t4/failure-evidence.ps1 "vika@$host:$guest/failure-evidence.ps1" \
  && scp "${opts[@]}" driver/scripts/t4/purge-attribution.ps1 "vika@$host:$guest/purge-attribution.ps1" \
  && scp "${opts[@]}" driver/scripts/t4/cycles-progress.ps1 "vika@$host:$guest/t4-cycles-progress.ps1" \
  && scp "${opts[@]}" driver/scripts/t4/agent-readiness.ps1 "vika@$host:$guest/t4-agent-readiness.ps1" \
  && scp "${opts[@]}" driver/scripts/t4/runtime-verifier.ps1 "vika@$host:$guest/t4-runtime-verifier.ps1" || { echo 'copy failed'; exit 14; }
remote <<'PS' | tee "$ev/$tag-install.txt"
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
$agentDir = 'C:\Program Files\SafeUpload\Agent'
New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
Expand-Archive -LiteralPath "$d\stage-service-publish.zip" -DestinationPath $agentDir -Force
Copy-Item -LiteralPath "$d\SafeUpload-t4.sys" -Destination 'C:\Windows\System32\drivers\SafeUpload.sys' -Force
New-Item -ItemType Directory -Force -Path 'C:\Protected' | Out-Null
& icacls.exe 'C:\Protected' /grant 'BUILTIN\Users:(OI)(CI)M' | Out-Null
# The cycles' folder must exist before the driver loads: staging never creates a directory inside a protected folder.
New-Item -ItemType Directory -Force -Path 'C:\Protected\t4' | Out-Null
$data = 'C:\ProgramData\SafeUpload'
New-Item -ItemType Directory -Force -Path $data | Out-Null
$policy = @{ version = 1; activeCategories = @('Cpf'); monitoredScopes = @{ extensions = @('.txt'); destinationPaths = @('C:\Protected'); removableDrives = $false; networkPaths = $false }; failOpen = $false; auditOnly = $false; overrideEnabled = $false } | ConvertTo-Json -Depth 5
Set-Content -LiteralPath "$data\policy.json" -Value $policy -Encoding UTF8
& "$d\Protect-SafeUploadPolicy.ps1"
& "$d\Install-SafeUploadAgent.ps1" -ServiceExecutablePath "$agentDir\SafeUpload.Agent.Service.exe"
'DriverStart=' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload').Start
'INSTALL_DONE=True'
PS
grep -qx 'INSTALL_DONE=True' "$ev/$tag-install.txt" || { echo 'install failed'; exit 15; }
if [ "$memory_enabled" = yes ]; then
    scp "${opts[@]}" "$memory_tools/debuggers.zip" "$memory_tools/SafeUpload.pdb" \
        driver/scripts/t4/memory-debugger.ps1 "vika@$host:$guest/" || exit 14
    remote <<'PS' | tee "$ev/$tag-memory-setup.txt"
$ErrorActionPreference='Stop'
$d='C:\Users\vika\Documents'
New-Item -ItemType Directory -Path C:\T4Memory\symbols -Force | Out-Null
Expand-Archive -LiteralPath "$d\debuggers.zip" -DestinationPath C:\T4Memory
Copy-Item -LiteralPath "$d\SafeUpload.pdb" -Destination C:\T4Memory\symbols\SafeUpload.pdb
Copy-Item -LiteralPath "$d\memory-debugger.ps1" -Destination "$d\t4-memory-debugger.ps1"
& bcdedit.exe /debug on
if($LASTEXITCODE -ne 0){throw 'Could not enable local debugging on the run disk.'}
# This VM already has a debugger transport. KD -kl can use it as configured;
# changing NET to LOCAL replaces its Windows network adapter and loses the test IP.
'T4MemorySetup=True'
PS
    grep -qx 'T4MemorySetup=True' "$ev/$tag-memory-setup.txt" || exit 16
fi
if [ "$mode" = runtime-verifier ]; then
    remote <<'PS' | tee "$ev/$tag-demand-held.txt"
$ErrorActionPreference = 'Stop'
. 'C:\Users\vika\Documents\t4-runtime-verifier.ps1'
Set-T4RuntimeDemandBeforeReboot
PS
    grep -qx 'RUNTIME_DEMAND_HELD=True' "$ev/$tag-demand-held.txt" || { echo 'runtime demand-start hold failed'; exit 16; }
fi
if [ "$mode" = verifier-from-boot ]; then
    remote <<'PS' | tee "$ev/$tag-verifier-from-boot.txt"
$ErrorActionPreference = 'Stop'
. 'C:\Users\vika\Documents\t4-runtime-verifier.ps1'
Set-T4VerifierFromBoot
PS
    grep -qx 'VERIFIER_FROM_BOOT_CONFIGURED=True' "$ev/$tag-verifier-from-boot.txt" || { echo 'persistent Verifier configuration failed'; exit 16; }
fi
# Keep a bugcheck on screen instead of rebooting into WinRE (m2t5boot2): on this disposable run disk only, the stop code then
# shows in the screenshot and the memory dump holds the crashed system, not the recovery environment.
remote <<<"Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name AutoReboot -Value 0 -Type DWord; 'CRASH_AUTOREBOOT=' + (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl').AutoReboot" \
    >> "$ev/$tag-install.txt"
grep -qx 'CRASH_AUTOREBOOT=0' "$ev/$tag-install.txt" || { echo 'could not keep bugchecks on screen'; exit 27; }
echo "== reboot"
remote <<<'& shutdown.exe /r /t 5 /c "T4 install"' >/dev/null; sleep 60
wait_ssh || {
    echo 'guest did not return'
    capture_unreachable install-unreachable >> "$ev/$tag-install.txt"  # no pipe: the flag must reach the trap
    grep '^Unreachable' "$ev/$tag-install.txt"; exit 17; }
if [ "$mode" = runtime-verifier ]; then
    remote <<PS | tee "$ev/$tag-preload-verifier.txt"
\$ErrorActionPreference = 'Stop'
. 'C:\Users\vika\Documents\t4-runtime-verifier.ps1'
Start-T4RuntimePairBeforeFirstLoad '$driver_sha' 'C:\Users\vika\Documents\t4-verifier'
PS
    for phase in before-load after-load after-agent; do
        scp "${opts[@]}" "vika@$host:$guest/t4-verifier-$phase.txt" "$ev/$tag-verifier-$phase.txt" >/dev/null 2>&1 || true
    done
    grep -qx 'VERIFIER_BEFORE_FIRST_LOAD=True' "$ev/$tag-preload-verifier.txt" && \
        grep -qx 'RUNTIME_PAIR_STARTED=True' "$ev/$tag-preload-verifier.txt" || { echo 'runtime Verifier first-load setup failed'; exit 18; }
    for phase in before-load after-load after-agent; do
        [ -s "$ev/$tag-verifier-$phase.txt" ] || { echo "missing runtime Verifier $phase query"; exit 18; }
    done
fi
if [ "$mode" = verifier-from-boot ]; then
    remote <<PS | tee "$ev/$tag-first-load-verifier.txt"
\$ErrorActionPreference = 'Stop'
. 'C:\Users\vika\Documents\t4-runtime-verifier.ps1'
Assert-T4VerifierFromFirstLoad '$driver_sha' 'C:\Users\vika\Documents\t4-verifier'
PS
    scp "${opts[@]}" "vika@$host:$guest/t4-verifier-after-boot.txt" "$ev/$tag-verifier-after-boot.txt" >/dev/null 2>&1 || true
    grep -qx 'VERIFIER_FROM_FIRST_LOAD=True' "$ev/$tag-first-load-verifier.txt" || { echo 'Verifier not active from the first load'; exit 18; }
fi
phase=readiness
remote <<'PS' | tee "$ev/$tag-ready.txt"
& 'C:\Users\vika\Documents\t4-agent-readiness.ps1'
PS
if ! grep -qx 'READY=True' "$ev/$tag-ready.txt"; then
    stop_reason=admission-not-ready; echo 'agent never Ready'
    # Diagnostic only (m2t5boot4: the status pipe never accepted a connection): service state, process and the agent's,
    # crash and SCM events since boot, before the trap discards the disk. m2t5boot10 (coverage stuck at WriterStateUnknown):
    # also the driver's writer-state counters and deny ring, as after the cycles.
    remote > "$ev/$tag-readiness-diagnostics.txt" 2>&1 <<'PS'
sc.exe queryex SafeUploadAgent
Get-Process -Name 'SafeUpload.Agent.Service' -ErrorAction SilentlyContinue | Format-List Id,StartTime,CPU,WorkingSet64,Responding
$since = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
'BootTime=' + $since.ToString('o')
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$since} -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -in 'SafeUpload.Agent.Service','Application Error','.NET Runtime','Windows Error Reporting' } |
    Select-Object -First 300 | ForEach-Object { '{0:o} {1} {2} L{3} {4}' -f $_.TimeCreated, $_.ProviderName, $_.Id, $_.Level, ($_.Message -replace '\s+',' ') }
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since; ProviderName='Service Control Manager'} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like '*SafeUpload*' } | ForEach-Object { '{0:o} SCM {1} {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+',' ') }
fltmc.exe filters
fltmc.exe instances -f SafeUpload
# Volume arrivals/removals and other system events since boot, to place a topology change next to the coverage events.
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since} -ErrorAction SilentlyContinue |
    Select-Object -First 400 | ForEach-Object { '{0:o} SYS {1} {2} L{3} {4}' -f $_.TimeCreated, $_.ProviderName, $_.Id, $_.Level, (($_.Message -replace '\s+',' ') -replace '^(.{0,240}).*$','$1') }
try { $c = & 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query counters; 'COUNTERS=' + ($c | ConvertTo-Json -Depth 6 -Compress) } catch { 'COUNTERS_ERROR=' + $_.Exception.Message }
try { $ring = @(& 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query deny-ring); 'RING_TOTAL=' + $ring.Count; foreach ($e in $ring | Select-Object -Last 40) { 'RING=' + ($e | ConvertTo-Json -Compress) } } catch { 'RING_ERROR=' + $_.Exception.Message }
'READINESS_DIAGNOSTICS_DONE=True'
PS
    exit 19
fi
if [ "$memory_enabled" = yes ]; then
    phase=memory-controls
    remote <<'PS' | tee "$ev/$tag-memory-controls.txt"
$ErrorActionPreference='Stop'
. 'C:\Users\vika\Documents\t4-memory-debugger.ps1'
Invoke-T4MemoryControls
PS
    grep -qx 'T4MemoryControls=PASS' "$ev/$tag-memory-controls.txt" || {
        stop_reason=memory-controls-failed; exit 23;
    }
fi

phase=coordinator-start
echo "== actor, Verifier ($mode) and the coordinator"
setup_ps=$(cat <<'PS'
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
New-Item -ItemType Directory -Force -Path C:\T4\control | Out-Null
[string](Get-WinEvent -LogName Application -MaxEvents 1).RecordId | Set-Content -LiteralPath 'C:\T4\event-baseline.txt'
& icacls.exe 'C:\T4\control' /grant 'BUILTIN\Users:(OI)(CI)M' | Out-Null
$name = 't4actor'; $password = 'T4!' + [guid]::NewGuid().ToString('N').Substring(0, 20)
if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires | Out-Null
} else { Set-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) }
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name -ErrorAction SilentlyContinue
$sid = (Get-LocalUser -Name $name).SID.Value
# A new standard user lacks "log on as a batch job", so its password-logon task never starts (as in the suite: S00 attempt 4), and the
# hand-back goes to its profile, which a batch logon of a brand-new account may not create in time: grant the right, create the profile.
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Security.Principal; using System.Text;
public static class T4Lsa {
  [StructLayout(LayoutKind.Sequential)] struct US { public ushort Length, MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct OA { public int Length; public IntPtr a, b; public uint c; public IntPtr d, e; }
  [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr s, ref OA o, uint access, out IntPtr h);
  [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr h, byte[] sid, US[] rights, uint n);
  [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr h);
  [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint s);
  [DllImport("userenv.dll", CharSet = CharSet.Unicode)] public static extern int CreateProfile(string sid, string user, StringBuilder path, uint cch);
  public static uint Grant(string sidText, string right) {
    var sid = new SecurityIdentifier(sidText); byte[] b = new byte[sid.BinaryLength]; sid.GetBinaryForm(b, 0);
    OA o = new OA(); o.Length = Marshal.SizeOf(typeof(OA)); IntPtr h;
    uint s = LsaOpenPolicy(IntPtr.Zero, ref o, 0x811, out h); if (s != 0) return LsaNtStatusToWinError(s);
    US u = new US(); u.Buffer = Marshal.StringToHGlobalUni(right); u.Length = (ushort)(right.Length * 2); u.MaximumLength = (ushort)(u.Length + 2);
    try { s = LsaAddAccountRights(h, b, new[]{u}, 1); } finally { Marshal.FreeHGlobal(u.Buffer); LsaClose(h); }
    return s == 0 ? 0 : LsaNtStatusToWinError(s);
  }
}
"@
$code = [T4Lsa]::Grant($sid, 'SeBatchLogonRight'); if ($code -ne 0) { throw "SeBatchLogonRight grant failed: $code" }
$profilePath = New-Object Text.StringBuilder 260
$hr = [T4Lsa]::CreateProfile($sid, $name, $profilePath, 260)
'ACTOR_PROFILE=' + $profilePath.ToString() + ' hr=0x' + $hr.ToString('X8')
# The actor cannot read the admin's Documents: run it from C:\T4 (readable by Users).
Copy-Item -LiteralPath "$d\t4-cycles-actor.ps1" -Destination 'C:\T4\cycles-actor.ps1' -Force
$actor = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\T4\cycles-actor.ps1"'
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 12) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 't4-actor' -Action $actor -User ($env:COMPUTERNAME + '\' + $name) -Password $password -RunLevel Limited -Settings $settings -Force | Out-Null
if ('__MODE__' -in 'runtime-verifier', 'verifier-from-boot') {
    . "$d\t4-runtime-verifier.ps1"
    Assert-T4RuntimeVerifierState (Invoke-T4RuntimeNative 'verifier.exe' @('/query')) $true
    'VERIFIER_ARMED=True'
}
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$coordinatorArgs = '-NoProfile -ExecutionPolicy Bypass -File "' + $d + '\t4-cycles-coordinator.ps1" -Cycles __CYCLES__ -SampleEvery __SAMPLE_EVERY__'
if ('__MODE__' -in 'runtime-verifier', 'verifier-from-boot') { $coordinatorArgs += ' -RequireVerifierPool' }
if ('__MEMORY__' -eq 'yes') { $coordinatorArgs += ' -MemoryDiagnostic' }
if ('__HANDBACK__' -eq 'yes') { $coordinatorArgs += ' -BlockHeavy -HandbackDiagnostic' }
if ('__DELETE__' -eq 'yes') { $coordinatorArgs += ' -DeleteAttribution' }
if ('__VOLUME__' -eq 'yes') { $coordinatorArgs += ' -VolumeDiscriminator' }
if ('__PURGEATTR__' -eq 'yes') { $coordinatorArgs += ' -PurgeAttribution' }
$coordinator = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $coordinatorArgs
Register-ScheduledTask -TaskName 't4-coordinator' -Principal $principal -Action $coordinator -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 't4-coordinator'
'COORDINATOR_STARTED=True'
PS
)
setup_ps=${setup_ps//__MODE__/$mode}; setup_ps=${setup_ps//__CYCLES__/$cycles}; setup_ps=${setup_ps//__SAMPLE_EVERY__/$sample_every}; setup_ps=${setup_ps//__MEMORY__/$memory_enabled}; setup_ps=${setup_ps//__HANDBACK__/$handback_diagnostic}; setup_ps=${setup_ps//__DELETE__/$delete_attribution}; setup_ps=${setup_ps//__VOLUME__/$volume_discriminator}; setup_ps=${setup_ps//__PURGEATTR__/$purge_attribution}
printf '%s\n' "$setup_ps" | remote | tee "$ev/$tag-setup.txt"
grep -qx 'COORDINATOR_STARTED=True' "$ev/$tag-setup.txt" || { echo 'coordinator did not start'; exit 20; }
if [ "$mode" != ordinary ]; then grep -qx 'VERIFIER_ARMED=True' "$ev/$tag-setup.txt" || { echo 'runtime Verifier not armed'; exit 21; }; fi

# The earlier run's median was 2.2 s per cycle. Allow 4 s each on the fast run disk, plus settle and idle samples, at least an hour.
# Eighteen extra KD sessions at 180 s + up to 10 s termination each, and three 30 s waits.
extra_diagnostic_seconds=0
[ "$delete_attribution" = yes ] && extra_diagnostic_seconds=3510
# Five settles and bounded diskpart/fltmc commands, including failure cleanup.
[ "$volume_discriminator" = yes ] && extra_diagnostic_seconds=$(( extra_diagnostic_seconds + 1800 ))
# Two extra 30 s waits, SCM stop/start deadlines, existing 600 s readiness helper and ETL parse/export allowance.
[ "$purge_attribution" = yes ] && extra_diagnostic_seconds=$(( extra_diagnostic_seconds + 1800 ))
limit=${T4_DEADLINE_SECONDS:-$(( cycles * 4 + 600 + extra_diagnostic_seconds ))}
[[ "$limit" =~ ^[0-9]+$ ]] || { echo 'Invalid T4 deadline'; exit 2; }
[ "$limit" -ge 3600 ] || limit=3600
if [ "$cycles" -ge 10000 ] && [ "$limit" -lt 21600 ]; then
    echo '10,000-cycle runs require at least a six-hour deadline'; exit 2
fi
printf 'T4DeadlineSeconds=%s\n' "$limit" | tee "$ev/$tag-deadline.txt"
loop_started=$(python3 -c 'import time; print(time.monotonic())')
phase=cycles; waited=0; state=RUNNING; alive=yes
stop_reason=deadline
while [ "$waited" -lt "$limit" ]; do
    sleep 60
    waited=$(python3 - "$loop_started" <<'MONOTONIC'
import sys,time
print(int(time.monotonic()-float(sys.argv[1])))
MONOTONIC
)
    if ! state=$(remote <<<"& 'C:\Users\vika\Documents\t4-cycles-progress.ps1'" | tail -1); then state=UNREACHABLE; fi
    case "$state" in DONE*) stop_reason=coordinator-finished; break;; RUNNING*) alive=yes;; *) # a bugcheck looks like a hang: the guest stops answering
        if ! ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1; then alive=no; stop_reason=guest-unreachable; echo "guest unreachable after ${waited}s"; break; fi;;
    esac
    echo "progress after ${waited}s: $state"
done
echo "wait ended after ${waited}s: $state alive=$alive reason=$stop_reason"
phase=collect-results

if [ "$alive" = yes ]; then
    remote <<'PS' > "$ev/$tag-after.txt"
$ErrorActionPreference = 'Continue'
'RESULT=' + $(if (Test-Path C:\T4\result.json) { (Get-Content C:\T4\result.json -Raw) -replace '\s+', ' ' } else { 'missing' })
if (Test-Path C:\T4\result.json) { 'COORDINATOR_STOP_REASON=' + (Get-Content C:\T4\result.json -Raw | ConvertFrom-Json).StopReason }
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
'VERIFIER=' + ((& verifier.exe /query | Out-String) -replace '\s+', ' ')
try { $c = & 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query counters; 'COUNTERS=' + ($c | ConvertTo-Json -Depth 6 -Compress) } catch { 'COUNTERS_ERROR=' + $_.Exception.Message }
try { $ring = @(& 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query deny-ring); 'RING_TOTAL=' + $ring.Count; foreach ($e in $ring | Select-Object -Last 40) { 'RING=' + ($e | ConvertTo-Json -Compress) } } catch { 'RING_ERROR=' + $_.Exception.Message }
'AFTER_DONE=True'
PS
    coordinator_reason=$(sed -n 's/^COORDINATOR_STOP_REASON=//p' "$ev/$tag-after.txt" | head -1)
    case "$coordinator_reason" in
        completed|completed-with-failures|repeated-identical-failure|blocked-bytes-published|actor-command-timeout|coordinator-error)
            stop_reason="$coordinator_reason";;
    esac
    # Capture diagnostic journal copies while the run disk still exists.
    # A failed/missing export is recorded and can never make the row pass.
    capture_failure_evidence
    scp "${opts[@]}" "vika@$host:C:/T4/samples.jsonl" "$ev/$tag-samples.jsonl" >/dev/null 2>&1 || true
    scp "${opts[@]}" "vika@$host:C:/T4/cycles.jsonl" "$ev/$tag-cycles.jsonl" >/dev/null 2>&1 || true
    mkdir -p "$ev/$tag-verifier"
    scp "${opts[@]}" "vika@$host:C:/T4/verifier-*.txt" "$ev/$tag-verifier/" >/dev/null 2>&1 || true
    scp "${opts[@]}" "vika@$host:C:/T4/control/actor-error.txt" "$ev/$tag-actor-error.txt" >/dev/null 2>&1 || true
    remote <<'PS' > "$ev/$tag-service-events.txt"
$base = [long](Get-Content -LiteralPath 'C:\T4\event-baseline.txt')
# Record IDs survive the clock step: a timestamp filter would miss the earlier failure.
$xpath = "*[System[Provider[@Name='SafeUpload.Agent.Service'] and EventRecordID > $base and (Level=1 or Level=2 or Level=3)]]"
Get-WinEvent -LogName Application -FilterXPath $xpath -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ RecordId = $_.RecordId; TimeCreated = $_.TimeCreated.ToString('o'); Level = $_.Level; Message = $_.Message } | ConvertTo-Json -Compress
}
PS
else
    $V screenshot "$dom" "$ev/$tag-unreachable.ppm" >/dev/null 2>&1 || true
    : > "$ev/$tag-after.txt"
fi

python3 - "$ev/$tag-after.txt" "$ev/$tag-samples.jsonl" "$ev/$tag-verdict.txt" "$cycles" "$mode" "$alive" "$(( $(date +%s) - started ))" "$handback_diagnostic" "$delete_attribution" "$volume_discriminator" "$purge_attribution" <<'PY'
import json, re, sys
after_path, samples_path, verdict_path, cycles, mode, alive, elapsed = sys.argv[1:8]
handback_diagnostic = len(sys.argv) > 8 and sys.argv[8] == 'yes'
delete_attribution = len(sys.argv) > 9 and sys.argv[9] == 'yes'
volume_discriminator = len(sys.argv) > 10 and sys.argv[10] == 'yes'
purge_attribution = len(sys.argv) > 11 and sys.argv[11] == 'yes'
cycles = int(cycles)
after = open(after_path, encoding='utf-8', errors='replace').read()
out = []
if handback_diagnostic:
    out.append('T4Diagnostic INFO hand-back attribution row (owner-authorized 2026-10-13, block-heavy mix); non-qualifying: '
               'no line in this file passes or fails a T4 gate')
if delete_attribution:
    out.append('T4Diagnostic INFO KD delete attribution (owner-authorized 2026-10-13); non-qualifying: '
               'no line in this file passes or fails a T4 gate')
if volume_discriminator:
    out.append('T4VolumeDiscriminatorMode INFO volume teardown diagnostic; non-qualifying; classification is informational')
if purge_attribution:
    out.append('T4PurgeAttributionMode INFO purge attribution diagnostic; non-qualifying')
def verdict(name, ok, reason):
    out.append(f"{name} {'PASS' if ok else 'FAIL'} {reason}")
m = re.search(r'^RESULT=(.*)$', after, re.M)
result = None
if m and m.group(1).strip() != 'missing':
    try: result = json.loads(m.group(1))
    except Exception: result = None
samples = []
try:
    for line in open(samples_path, encoding='utf-8-sig', errors='replace'):
        line = line.strip()
        if line:
            try:
                sample = json.loads(line)
                # These new control labels are diagnostic evidence, outside the original workload gates.
                # In particular the stopped-agent control cannot query the service's writer counters.
                if sample.get('Label') not in ('purged-repeat', 'purged-agent-stopped'):
                    samples.append(sample)
            except Exception: pass
except FileNotFoundError: pass
verdict('T4GuestAlive', alive == 'yes', 'the guest answered through the run (a Verifier stop is a bugcheck, which looks like a hang)')
verdict('T4DriverLoaded', 'DRIVER_LOADED=True' in after, 'the filter is still loaded after the cycles')
if mode in ('runtime-verifier', 'verifier-from-boot'):
    v = re.search(r'^VERIFIER=(.*)$', after, re.M)
    vt = v.group(1) if v else ''
    verdict('T4VerifierActive', 'SafeUpload.sys' in vt and re.search(r'Verifier Flags:\s*0x0*13b', vt, re.I) is not None, 'runtime Verifier 0x13B still verifies SafeUpload.sys')
completed = result.get('Completed') if result else None
verdict('T4CyclesCompleted', result is not None and completed == cycles and not result.get('Error'),
        f"{completed} of {cycles} cycles reached their outcome; outcomes {json.dumps(result.get('Outcomes')) if result else 'none'}; " +
        (f"error {result.get('Error')}; " if result and result.get('Error') else '') +
        (f"first failures {result.get('Failures')[:5]}" if result and result.get('Failures') else 'no failures'))
verdict('T4ActorStopped', result is not None and result.get('ActorStopped') is True, 'the actor acknowledged stop')
out.append('T4StopReason INFO ' + str(result.get('StopReason') if result else 'missing') +
           f"; attempted {result.get('Attempted') if result else 'missing'}; failures {result.get('FailureCount') if result else 'missing'}")
leak = [f for f in (result.get('Failures') or []) if 'BLOCKED BYTES PUBLISHED' in f] if result else []
verdict('T4NoBlockedBytesPublished', result is not None and not result.get('BlockedBytesPublished') and not leak, 'no blocked version reached its public name' if not leak else '; '.join(leak[:5]))
cyc = [s for s in samples if s.get('Label') == 'cycle' and isinstance(s.get('Verifier'), dict) and s['Verifier'].get('NonPagedBytes') is not None]
if mode in ('runtime-verifier', 'verifier-from-boot') and len(cyc) >= 4:
    warm = [s for s in cyc if s['Cycle'] >= min(1000, cycles // 4)]
    xs = [s['Cycle'] for s in warm]; ys = [s['Verifier']['NonPagedBytes'] for s in warm]
    n = len(xs); mx = sum(xs) / n; my = sum(ys) / n
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / max(1, sum((x - mx) ** 2 for x in xs))
    settled = (result or {}).get('Idle') or {}
    final = (settled.get('Verifier') or {}).get('NonPagedBytes')
    first = ys[0]
    # Before T4 every staged save kept about 4.5 KB of nonpaged pool (version plus view); flat means well under 1/1000 of that.
    ok = slope < 4.0 and final is not None and final <= first + 65536
    if cycles >= 10000:
        verdict('T4PoolFlat', ok, f"driver nonpaged bytes (Verifier pool tracking) from cycle {xs[0]}: {first} -> {ys[-1]} at cycle {xs[-1]}, "
                f"after idle {final}; slope {slope:.3f} B/cycle (limit 4); peak {(settled.get('Verifier') or {}).get('PeakNonPagedBytes')}")
    else:
        verdict('T4PoolEndpoint', final is not None and final <= first + 65536,
                f"driver nonpaged bytes (Verifier pool tracking) from cycle {xs[0]}: {first}; after idle {final}; limit {first + 65536}")
        out.append(f"T4PoolSlope INFO {slope:.3f} B/cycle (smoke row; judged only on the 10,000-cycle row)")
elif mode in ('runtime-verifier', 'verifier-from-boot'):
    verdict('T4PoolFlat' if cycles >= 10000 else 'T4PoolEndpoint', False, f"only {len(cyc)} Verifier pool samples")
    if cycles < 10000:
        out.append('T4PoolSlope INFO unavailable B/cycle (smoke row; judged only on the 10,000-cycle row)')
def stage(s, k):
    return ((s or {}).get('StageWorker') or {}).get(k)
settled = (result or {}).get('Settled'); exited = (result or {}).get('AfterActorExit'); idle = (result or {}).get('Idle')
registry_bad = []
for sample in samples:
    writer = sample.get('WriterState') or {}
    entries = writer.get('registryEntries'); capacity = writer.get('registryCapacity')
    if not isinstance(entries, int) or not isinstance(capacity, int) or entries > capacity:
        registry_bad.append(f"{sample.get('Label')}@{sample.get('Cycle')}: {entries}/{capacity}")
capacity_failures = ((idle or {}).get('WriterState') or {}).get('registryCapacityFailures')
verdict('T4RegistryBounded', bool(samples) and not registry_bad and capacity_failures == 0,
        f"{len(samples)} samples within registry capacity; idle capacity failures {capacity_failures}; invalid samples {registry_bad}")
def sufl_live(sample):
    tag = (sample or {}).get('TagSUfl') or {}
    allocs = tag.get('NonPagedAllocs'); frees = tag.get('NonPagedFrees')
    return allocs - frees if isinstance(allocs, int) and isinstance(frees, int) else None
start = next((s for s in samples if s.get('Label') == 'start'), None)
last_cycle = next((s for s in reversed(samples) if s.get('Label') == 'cycle'), None)
purged = (result or {}).get('Purged')
for label, sample in [('start', start), ('last-cycle', last_cycle), ('idle', idle), ('purged', purged)]:
    out.append(f"T4Memory INFO {label}: SUfl live {sufl_live(sample)}, bytes {((sample or {}).get('TagSUfl') or {}).get('NonPagedUsed')}; "
               f"SwUr bytes {((sample or {}).get('TagSwUr') or {}).get('NonPagedUsed')}; "
               f"module bytes {((sample or {}).get('Verifier') or {}).get('NonPagedBytes')}")
purge = (result or {}).get('Purge') or []
expected_purge = [('RtlAdjustPrivilege', 13), ('RtlAdjustPrivilege', 5),
                  ('NtSetSystemInformation', 2), ('NtSetSystemInformation', 3), ('NtSetSystemInformation', 4)]
purge_ok = isinstance(purge, list) and len(purge) == len(expected_purge) and all(
    isinstance(record, dict) and (record.get('Operation'), record.get('Privilege', record.get('Command'))) == expected
    and isinstance(record.get('NTSTATUS'), int) and 0 <= record['NTSTATUS'] < 0x80000000
    for record, expected in zip(purge, expected_purge))
start_live = sufl_live(start); purged_live = sufl_live(purged)
idle_live = sufl_live(idle)
growth = idle_live - start_live if idle_live is not None and start_live is not None else None
released = idle_live - purged_live if idle_live is not None and purged_live is not None else None
contexts_ok = purge_ok and (purged or {}).get('Label') == 'purged' and start_live is not None and purged_live is not None and purged_live <= start_live + 2048
contexts_reason = (f"SUfl live start {start_live}, purged {purged_live}; limit start + 2048; "
                   f"released {released} of idle growth since start {growth}; "
                   f"purge NTSTATUS {'PASS' if purge_ok else 'FAIL'} {json.dumps(purge)}; "
                   f"purged sample {'present' if purged else 'missing'}")
if cycles >= 10000:
    verdict('T4ContextsReleased', contexts_ok, contexts_reason)
else:
    out.append(f"T4ContextsReleased INFO check {'PASS' if contexts_ok else 'FAIL'}; {contexts_reason}")
if handback_diagnostic:
    diag = (result or {}).get('HandbackDiagnostic')
    if not isinstance(diag, dict):
        out.append('T4HandbackAttribution INFO diagnostic result missing')
    else:
        deleted_live = sufl_live(diag.get('AfterDelete')); repurged_live = sufl_live(diag.get('AfterDeletePurged'))
        deleted = diag.get('HandbacksDeleted')
        def delta(a, b):
            return a - b if isinstance(a, int) and isinstance(b, int) else None
        released = delta(purged_live, repurged_live)
        per = f"{released / deleted:.3f}" if isinstance(released, int) and isinstance(deleted, int) and deleted else 'n/a'
        out.append(f"T4HandbackAttribution INFO SUfl live start {start_live}, purged {purged_live} (above start {delta(purged_live, start_live)}); "
                   f"hand-backs deleted {deleted}, delete failures {diag.get('HandbackDeleteFailures')}, left {diag.get('HandbacksLeft')}; "
                   f"after delete {deleted_live} (released {delta(purged_live, deleted_live)}); after second purge {repurged_live} "
                   f"(released {released}); released per deleted hand-back {per}; delete errors {json.dumps(diag.get('HandbackDeleteErrors'))}")
        second = diag.get('Purge') or []
        out.append('T4HandbackPurge INFO second purge statuses ' + json.dumps([(r.get('Operation'), r.get('StatusHex')) for r in second if isinstance(r, dict)]))
        for holder in diag.get('Holders') or []:
            if isinstance(holder, dict):
                out.append(f"T4FileHolders INFO {holder.get('Category')}: files {holder.get('Files')}, error {holder.get('Error')}, "
                           f"holders {json.dumps(holder.get('Holders'))}")
if delete_attribution:
    diag = (result or {}).get('DeleteAttribution')
    if not isinstance(diag, dict):
        out.append('T4DeleteAttribution INFO diagnostic result missing')
    else:
        out.append(f"T4DeleteAttribution INFO mode {diag.get('Mode', 'Corpus')}; corpus {diag.get('CorpusCount')}; deleted {diag.get('Deleted')}; "
                   f"delete errors {json.dumps(diag.get('DeleteErrors'))}; errors {json.dumps(diag.get('Errors'))}; "
                   f"identities {diag.get('CorpusIdentities')}")
        if diag.get('Mode') == 'Handbacks':
            out.append('T4DeleteAttributionRelease INFO ' + json.dumps(diag.get('ReleasePrecondition')))
        for sample in diag.get('Samples') or []:
            if isinstance(sample, dict):
                out.append(f"T4DeleteAttributionSample INFO {sample.get('Label')}: SUfl live {sufl_live(sample)}")
        for snapshot in diag.get('Snapshots') or []:
            if isinstance(snapshot, dict):
                out.append(f"T4DeleteAttributionSnapshot INFO {snapshot.get('Label')}: counts {json.dumps(snapshot.get('Counts'))}; "
                           f"classification {snapshot.get('Classification')}; errors {json.dumps(snapshot.get('Errors'))}; "
                           f"summary {snapshot.get('SummaryFile')}")
        out.append('T4DeleteAttributionPurge INFO ' + json.dumps(diag.get('Purges')))
if volume_discriminator:
    diag = (result or {}).get('VolumeDiscriminator')
    if not isinstance(diag, dict):
        out.append('T4VolumeDiscriminator INFO diagnostic result missing')
    else:
        out.append(f"T4VolumeDiscriminator INFO classification {diag.get('Classification')}; letter {diag.get('Letter')}; N {diag.get('N')}; "
                   f"filter attached {json.dumps(diag.get('FilterAttached'))}; SUfl live {json.dumps(diag.get('LiveSUfl'))}; "
                   f"growth {diag.get('Growth')}; delete release {diag.get('DeleteRelease')}; teardown release {diag.get('TeardownRelease')}; "
                   f"residual {diag.get('Residual')}; errors {json.dumps(diag.get('Errors'))}")
if purge_attribution:
    diag = (result or {}).get('PurgeAttribution')
    if not isinstance(diag, dict):
        out.append('T4PurgeAttribution INFO diagnostic result missing')
    else:
        windows = []
        for window in diag.get('Windows', []) or []:
            summary = window.get('Summary') or {}
            top = ', '.join(f"{p.get('Name')}[{p.get('ProcessId')}]={p.get('CreateCount')}"
                            for p in (summary.get('TopProcesses') or [])[:3])
            windows.append(f"{window.get('Label')} creates {summary.get('TotalCreates')}, top {top or 'unavailable'}")
        controls = diag.get('Controls') or {}
        text = (f"T4PurgeAttribution INFO {'; '.join(windows)}; SUfl live purged {purged_live}, "
                f"purged-repeat {sufl_live(controls.get('PurgedRepeat'))}, "
                f"purged-agent-stopped {sufl_live(controls.get('PurgedAgentStopped'))}; "
                f"agent stopped {(controls.get('AgentStop') or {}).get('Reached')}, "
                f"restart {(controls.get('AgentRestart') or {}).get('Reached')}, readiness {controls.get('AgentReady')}")
        # Process names are external input; even a process literally named PASS/FAIL must remain token-free.
        out.append(re.sub(r'\b(PASS|FAIL)\b', lambda m: m.group(1).lower(), text).replace('\n', ' ').replace('\r', ' '))
verdict('T4VersionsReleased', stage(settled, 'liveVersions') == 0 and stage(settled, 'liveViews') == 0,
        f"after settle: live versions {stage(settled, 'liveVersions')}, views {stage(settled, 'liveViews')}, created {stage(settled, 'versionsCreated')}, "
        f"released {stage(settled, 'versionsReleased')}, views released {stage(settled, 'viewsReleased')}")
verdict('T4TombstonesReleased', stage(exited, 'tombstones') == 0, f"after the actor exited: tombstones {stage(exited, 'tombstones')}")
verdict('T4NoCapRefusal', stage(idle, 'capRefusals') == 0 and stage(idle, 'tombstoneRefusals') == 0,
        f"cap refusals {stage(idle, 'capRefusals')}, tombstone refusals {stage(idle, 'tombstoneRefusals')}")
verdict('T4StageFilesDeleted', (idle or {}).get('StageFiles') == 0 and stage(idle, 'stageDeleteFailures') == 0,
        f"stage files after idle {(idle or {}).get('StageFiles')} (journal manifests {(idle or {}).get('JournalFiles')}, hand-backs {(idle or {}).get('Handbacks')}); "
        f"driver deletes {stage(idle, 'stageDeletes')}, failures {stage(idle, 'stageDeleteFailures')}")
if exited and idle:
    passes = (stage(idle, 'passes') or 0) - (stage(exited, 'passes') or 0)
    timer = (stage(idle, 'wakeTimer') or 0) - (stage(exited, 'wakeTimer') or 0)
    verdict('T4StageWorkerIdle', stage(idle, 'passes') is not None and passes == 0,
            f"stage worker passes over 60 s with nothing waiting: {passes} (timer fires {timer}; waiting versions {stage(idle, 'waitingVersions')})")
wakes = {k: stage(idle, k) for k in ('wakeCleanup', 'wakeClose', 'wakeDispose', 'wakeConnect', 'wakeExit', 'wakeTimer', 'wakeInline', 'timerArms',
                                     'disposeHeld', 'disposeNotHeld', 'disposeStale', 'disposeDeferred', 'passes')}
out.append('T4WorkerWakes INFO ' + json.dumps(wakes))
times = []
try:
    for line in open(samples_path.replace('-samples.jsonl', '-cycles.jsonl'), encoding='utf-8-sig', errors='replace'):
        try: c = json.loads(line); times.append(c.get('AckMs', 0) + c.get('OutcomeMs', 0))
        except Exception: pass
except FileNotFoundError: pass
if times:
    times.sort()
    out.append(f"T4CycleTime INFO median {times[len(times)//2]:.0f} ms, p95 {times[int(len(times)*0.95)-1]:.0f} ms, max {times[-1]:.0f} ms over {len(times)} cycles")
out.append(f"T4Duration INFO {elapsed} s ({mode}, {cycles} cycles)")
open(verdict_path, 'w').write('\n'.join(out) + '\n')
print('\n'.join(out))
sys.exit(0 if all(l.split(' ', 2)[1] in ('PASS', 'INFO') for l in out) else 1)
PY
verdict_status=$?
if [ "$verdict_status" -eq 0 ] && [ "$alive" = yes ]; then
    # Check status recovery after the original idle/memory observations. Reuse
    # the bounded readiness reader; do not hide transient query warnings or
    # accept an earlier Ready receipt as proof of current coverage.
    phase=final-readiness
    remote <<'PS' | tee "$ev/$tag-post-idle-ready.txt"
& 'C:\Users\vika\Documents\t4-agent-readiness.ps1'
PS
    if ! grep -qx 'READY=True' "$ev/$tag-post-idle-ready.txt"; then
        stop_reason=admission-not-ready-after-idle
        echo 'T4AdmissionRecovered FAIL current coverage did not return to Ready after idle' | tee -a "$ev/$tag-verdict.txt"
        exit 26
    fi
    echo 'T4AdmissionRecovered PASS current coverage returned to Ready after idle' | tee -a "$ev/$tag-verdict.txt"
fi
if [ "$memory_enabled" = yes ] && [ "$alive" = yes ]; then
    phase=memory-teardown
    remote <<'PS' | tee "$ev/$tag-memory-teardown.txt"
$ErrorActionPreference='Stop'
. 'C:\Users\vika\Documents\t4-memory-debugger.ps1'
Invoke-T4MemoryTeardown
PS
    grep -qx 'T4MemoryTeardown=PASS' "$ev/$tag-memory-teardown.txt" || {
        stop_reason=memory-teardown-failed; exit 24;
    }
fi
exit "$verdict_status"
