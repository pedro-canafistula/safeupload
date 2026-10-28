#!/usr/bin/env bash
# Running requires the owner's explicit authorization of this component-host
# setup (design 8.7.4 "separately authorized native component host").
# It is not the protected first boot and does not qualify anything.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../../.."
usage() {
    echo 'Usage: SAFEUPLOAD_DEBUGGEE=win10-debug3 Invoke-Nu501ComponentHost.sh [--dry-run] [--owner-authorized-component-host] <label> <commit> <driver.sys> <driver-sha256> <agent.zip> <zip-sha256> <service-exe-sha256>' >&2
    exit 2
}
stop() { echo "STOP: $*" >&2; exit 1; }
dry=false; authorized=false; args=()
for arg in "$@"; do
    case "$arg" in --dry-run) dry=true;; --owner-authorized-component-host) authorized=true;; *) args+=("$arg");; esac
done
[ "${#args[@]}" -eq 7 ] || usage
label=${args[0]}; requested_commit=${args[1]}; driver=$(realpath "${args[2]}"); driver_sha=${args[3],,}
agent=$(realpath "${args[4]}"); agent_sha=${args[5],,}; service_sha=${args[6],,}
[[ "$label" =~ ^[A-Za-z0-9]{3,25}$ ]] || usage
for sha in "$driver_sha" "$agent_sha" "$service_sha"; do [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || usage; done
[ "${SAFEUPLOAD_DEBUGGEE:-}" = win10-debug3 ] || stop 'set SAFEUPLOAD_DEBUGGEE=win10-debug3 explicitly'
export SAFEUPLOAD_DEBUGGEE=win10-debug3
[ -f "$driver" ] && [ -f "$agent" ] || stop 'missing pinned artifacts'
[ "$(sha256sum "$driver" | cut -d' ' -f1)" = "$driver_sha" ] || stop 'driver hash differs'
[ "$(sha256sum "$agent" | cut -d' ' -f1)" = "$agent_sha" ] || stop 'agent ZIP hash differs'
commit=$(git rev-parse --verify --end-of-options "$requested_commit^{commit}")
ev="driver/evidence/$(date +%F)/t9-nu501-$label"
[ ! -e "$ev" ] && [ ! -L "$ev" ] || stop 'label/evidence already exists'
if $dry; then
    printf 'DryRun=True\nSourceCommit=%s\nDriverSHA256=%s\nAgentZipSHA256=%s\nServiceSHA256=%s\nEvidence=%s\n' "$commit" "$driver_sha" "$agent_sha" "$service_sha" "$ev"
    cat <<'PLAN'
No network, VM, builder, lock or evidence-directory operation in dry-run.
Real run requires separately recorded owner authorization and committed scripts.
Hold both builder locks nonblocking, including cleanup/restoration. Refuse debug2
or debug3 running, prior run state, changed baseline or repeated-label retry.
Fresh win10-debug3 overlay, original XML/base retained, EFI reset, no TPM.
Independent baseline and pinned UUID/19045.2965/testsigning/SecureBoot checks.
Install pinned reviewed driver/feature agent; inert validated zero-destination
policy, no actor. Original SYSTEM/service-SID connection; product workers closed.
Require actual component evidence binding; this does not assert legacy/product Ready.
Runtime Verifier /volatile /flags 0x13B /adddriver SafeUpload.sys with /query.
Execute committed PS5.1 client once. Independently validate complete JSON receipt.
Collect raw command streams, hashes, verifier/event/minidump state; stop at first
assertion, Verifier report, hang, reboot or collection failure. Never retry.
Discard overlay, independently boot a restoration overlay/check baseline,
discard restoration overlay. Both builders remain locked through restoration.
PLAN
    exit 0
fi
$authorized || stop 'owner must explicitly authorize this component-host setup; record that authorization before supplying the flag'
# Use committed runner helpers/scripts, not a mutable checkout as guest source.
scripts=driver/scripts
nu="$scripts/t9/nu501"
inputs=("$nu/Invoke-Nu501Client.ps1" "$nu/Prepare-Nu501Component.ps1" "$nu/validate_receipt.py" "$scripts/Get-StagedBaseline.ps1"
        agente/scripts/Install-SafeUploadAgent.ps1 agente/scripts/Protect-SafeUploadPolicy.ps1)
for file in "${inputs[@]}"; do git cat-file -e "$commit:$file" || stop "not committed: $file"; done
for file in "$scripts/run-disk.sh" "$scripts/image-store.sh" "$scripts/remote_ps.py" "$scripts/debuggees.txt" "$nu/Invoke-Nu501ComponentHost.sh"; do
    cmp -s "$file" <(git show "$commit:$file") || stop "host helper differs from pinned commit: $file"
done
locks=/home/victor/Work/safeupload-tools/builder-locks
exec {builder1_fd}<"$locks/builder1.lock" || stop 'builder1 lock missing'
flock -n -x "$builder1_fd" || stop 'builder1 busy'
exec {builder2_fd}<"$locks/builder2.lock" || stop 'builder2 lock missing'
flock -n -x "$builder2_fd" || stop 'builder2 busy'
V='virsh -c qemu:///system'; dom=win10-debug3
source "$scripts/image-store.sh"
source "$scripts/run-disk.sh"
[ ! -e "$RUN_DISK_STATE/$dom" ] || stop 'prior run state remains; inspect before running'
for peer in win10-debug2 "$dom"; do [ "$($V domstate "$peer")" = 'shut off' ] || stop "$peer must be off"; done
host=$(awk -v d="$dom" '$1==d{print $2}' "$scripts/debuggees.txt")
[ "$host" = 192.168.122.52 ] || stop 'target inventory changed'
mkdir -p "$(dirname "$ev")"; mkdir "$ev"
for file in "${inputs[@]}"; do git show "$commit:$file" > "$ev/$(basename "$file")"; done
printf 'SourceCommit=%s\nDriverSHA256=%s\nAgentZipSHA256=%s\nServiceSHA256=%s\n' "$commit" "$driver_sha" "$agent_sha" "$service_sha" > "$ev/inputs.txt"
sha256sum "$ev/"*.ps1 "$ev/validate_receipt.py" "${BASH_SOURCE[0]}" "$scripts/"{run-disk.sh,image-store.sh,remote_ps.py} >> "$ev/inputs.txt"
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR -o StrictHostKeyChecking=yes)
remote() { timeout 180 python3 "$scripts/remote_ps.py" "$host"; }
monotonic() { python3 -c 'import time; print(int(time.monotonic()))'; }
wait_up() {
    local end=$(( $(monotonic) + 300 ))
    while (( $(monotonic) < end )); do
        timeout 10 ssh "${opts[@]}" "vika@$host" 'echo up' >/dev/null 2>&1 && return 0
        sleep 5
    done
    return 1
}
call() {
    local stem=$1 rc=0
    remote > "$stem.raw" 2>&1 || rc=$?
    python3 - "$stem.raw" "$stem.txt" <<'PY'
import html,pathlib,re,sys
s=pathlib.Path(sys.argv[1]).read_text(errors='replace')
errors=['ERROR: '+html.unescape(e) for e in re.findall(r'<S S="Error">(.*?)</S>',s,re.S)]
s=re.sub(r'<Objs.*?</Objs>','',s,flags=re.S).replace('#< CLIXML','').replace('\r','')
pathlib.Path(sys.argv[2]).write_text('\n'.join([l for l in s.splitlines() if l.strip()]+errors)+'\n')
PY
    printf '%s\n' "$rc" > "$stem.transport-exit.txt"
    [ "$rc" -eq 0 ]
}
copy() { timeout 120 scp "${opts[@]}" "$1" "vika@$host:$2"; }
baseline() {
    copy "$ev/Get-StagedBaseline.ps1" 'C:/Users/vika/Documents/nu501-baseline.ps1' > "$1-copy.txt" 2>&1 || return 1
    call "$1" <<'PS' || return 1
& 'C:\Users\vika\Documents\nu501-baseline.ps1'
PS
    python3 - "$1.txt" <<'PY'
import pathlib,sys
s=pathlib.Path(sys.argv[1]).read_text().splitlines()
assert [l for l in s if l.startswith('BaselineClean=')]==['BaselineClean=True']
assert 'UUID=FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3' in s
PY
}
active=''; restore_needed=false
collect() {
    timeout 60 scp "${opts[@]}" -r "vika@$host:C:/Nu501-$label" "$ev/collected" > "$ev/collect.txt" 2>&1 || return 1
}
finish() {
    local rc=$?; trap - EXIT
    # Best effort crash artifacts even on first failure; never convert failure
    # to PASS because transport succeeded. Do not restart a crashed guest.
    # Kernel refusals are typed without a reason on the wire; the driver prints
    # one ERROR-level DbgPrint line per refusal. On a failure after the component
    # was prepared, take a live memory dump of the still-running guest before the
    # overlay is discarded (read later with cdb !dbgprint on a builder).
    if [ "$rc" -ne 0 ] && [ -n "$active" ] && [ "$active" = "$label" ] &&
        tr -d '\r' < "$ev/prepare.txt" 2>/dev/null | grep -qx 'Nu501ComponentPrepared=True' &&
        [ "$($V domstate "$dom" 2>/dev/null)" = running ]; then
        elf="/var/tmp/nu501-$label.elf"
        if timeout 900 $V qemu-monitor-command "$dom" --hmp "dump-guest-memory $elf" > "$ev/live-dump.txt" 2>&1 && [ -s "$elf" ]; then
            timeout 900 /var/tmp/safeupload-qemu-tools/build/contrib/elf2dmp/elf2dmp "$elf" "$ev/guest-live.dmp" >> "$ev/live-dump.txt" 2>&1 || true
            rm -f "$elf" 2>/dev/null || true
        fi
        ls -la "$ev/guest-live.dmp" >> "$ev/live-dump.txt" 2>&1 || true
    fi
    if [ -n "$active" ]; then
        $V domstate "$dom" --reason > "$ev/final-domstate.txt" 2>&1 || true
        $V screenshot "$dom" "$ev/final-screen.png" >/dev/null 2>&1 || true
        timeout 30 scp "${opts[@]}" -r "vika@$host:C:/Windows/Minidump" "$ev/minidumps" > "$ev/minidump-copy.txt" 2>&1 || true
        if [ ! -d "$ev/collected" ]; then collect || true; fi
        if [ -e "$RUN_DISK_STATE/$dom" ]; then
            if ! run_disk_end "$dom" "$active" > "$ev/discard.txt" 2>&1; then
                rc=22; restore_needed=false
                echo 'Nu501RestorationBaseline=BLOCKED discard failed; preserve run state' > "$ev/restoration.txt"
            fi
        fi
        active=''
    fi
    if $restore_needed; then
        active="${label}restore"
        if run_disk_begin "$dom" "$active" > "$ev/restore-begin.txt" 2>&1 && wait_up && baseline "$ev/restore-baseline"; then
            echo 'Nu501RestorationBaseline=PASS' > "$ev/restoration.txt"
        else echo 'Nu501RestorationBaseline=FAIL' > "$ev/restoration.txt"; rc=23; fi
        if [ -e "$RUN_DISK_STATE/$dom" ]; then
            run_disk_end "$dom" "$active" > "$ev/restore-discard.txt" 2>&1 || rc=24
        fi
    fi
    exit "$rc"
}
trap finish EXIT
restore_needed=true; active="$label"
run_disk_begin "$dom" "$active" > "$ev/run-begin.txt" 2>&1 || stop 'overlay/EFI/no-TPM setup failed'
wait_up || stop 'guest did not boot; STOP'
baseline "$ev/baseline" || stop 'baseline differs; STOP'
guest="C:/Nu501-$label"
call "$ev/stage" <<PS || stop 'guest staging failed'
\$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '$guest') { throw 'Evidence path exists' }
New-Item -ItemType Directory -Path '$guest' | Out-Null
'Staged=True'
PS
grep -qx 'Staged=True' "$ev/stage.txt" || stop 'no guest staging receipt'
for file in "$ev/"*.ps1; do copy "$file" "$guest/$(basename "$file")" >> "$ev/upload.txt" 2>&1 || stop 'script copy failed'; done
copy "$driver" "$guest/SafeUpload.sys" >> "$ev/upload.txt" 2>&1 || stop 'driver copy failed'
copy "$agent" "$guest/agent.zip" >> "$ev/upload.txt" 2>&1 || stop 'agent copy failed'
# Compare staged scripts with commit-extracted source and parse in actual PS5.1.
for file in "$ev/"*.ps1; do
    name=$(basename "$file"); sha=$(sha256sum "$file" | cut -d' ' -f1)
    call "$ev/parse-$name" <<PS || stop 'script hash/PS5.1 parser gate failed'
\$ErrorActionPreference='Stop'
if (\$PSVersionTable.PSVersion.ToString() -notlike '5.1.*') { throw 'Requires PS5.1' }
if ((Get-FileHash -LiteralPath '$guest/$name' -Algorithm SHA256).Hash -ine '$sha') { throw 'Committed script hash mismatch' }
\$tokens=\$null; \$errors=\$null
[void][Management.Automation.Language.Parser]::ParseFile('$guest/$name',[ref]\$tokens,[ref]\$errors)
if (\$errors.Count) { throw (\$errors | Out-String) }
'HashAndParse=True'
PS
    grep -qx 'HashAndParse=True' "$ev/parse-$name.txt" || stop 'no hash/parser receipt'
done
call "$ev/prepare" <<PS || stop 'component preparation transport failed'
& '$guest/Prepare-Nu501Component.ps1' -InputDirectory '$guest' -DriverSHA256 '$driver_sha' -AgentZipSHA256 '$agent_sha' -ServiceSHA256 '$service_sha'
PS
grep -qx 'Nu501ComponentPrepared=True' "$ev/prepare.txt" || stop 'component setup/readiness/Verifier failed'
call "$ev/client" <<PS || stop 'client timeout/transport failure; STOP'
& powershell.exe -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -File '$guest/Invoke-Nu501Client.ps1' -OutputDirectory '$guest/result'
'ClientExit=' + \$LASTEXITCODE
PS
# Preserve the first response before any assertion can stop the row.
collect || stop 'receipt collection failed'
call "$ev/after" <<PS || stop 'post-control check transport failed'
\$ErrorActionPreference='Stop'
\$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
\$client=Get-Content -Raw -LiteralPath '$guest/result/client.json' | ConvertFrom-Json
if (\$client.Boot -cne \$boot) { throw 'Reboot during control' }
\$query=& verifier.exe /query 2>&1 | Out-String
\$query
if (\$LASTEXITCODE -ne 0 -or \$query -notmatch 'SafeUpload\.sys' -or \$query -notmatch '(?i)0x0*13b\b') { throw 'Verifier active state changed' }
\$errors=@()
try {
    \$errors=@(Get-WinEvent -FilterHashtable @{LogName='System'; Id=41,1001,6008,7031,7034,7023; StartTime=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime} -ErrorAction Stop)
} catch {
    if (\$_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
}
\$errors | Format-List TimeCreated,Id,Message
if (\$errors.Count -ne 0) { throw 'System crash/service/Verifier report; STOP' }
\$dumps=@()
if (Test-Path -LiteralPath C:\Windows\Minidump -ErrorAction Stop) { \$dumps=@(Get-ChildItem -LiteralPath C:\Windows\Minidump -ErrorAction Stop) }
if (\$dumps.Count -gt 0 -or (Test-Path -LiteralPath C:\Windows\MEMORY.DMP -ErrorAction Stop)) { throw 'Crash dump present; STOP' }
'PostControl=True'
PS
grep -qx 'PostControl=True' "$ev/after.txt" || stop 'post-control assertion/Verifier failure'
grep -qx 'ClientExit=0' "$ev/client.txt" || stop 'client failed assertion'
python3 "$ev/validate_receipt.py" "$ev/collected/result" > "$ev/verdict.txt" || stop 'structured receipt failed'
cat "$ev/verdict.txt"
