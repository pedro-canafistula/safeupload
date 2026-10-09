#!/usr/bin/env bash
# T3: a large installer or an update with the staged-writes driver loaded (or without it, as the control), on a debuggee in a
# checkpoint that is ALWAYS rolled back afterwards.
#
# Usage: driver/scripts/Invoke-InstallerWorkload.sh <debuggee domain> <tag> <workload> <driver|control> [<driver.sys> <agent zip>]
#   workload: msi | m365 | cu | defender
#   driver:   installs the pair like the manual install (Install-SafeUploadAgent.ps1), reboots, waits for Ready, then runs the
#             workload as SYSTEM in a scheduled task while a second task samples the driver counters and the deny ring.
#   control:  the same workload on the untouched baseline (no driver loaded) for the duration comparison.
#
# Evidence: driver/evidence/<day>/<tag>-*.txt; the verdict is <tag>-verdict.txt (PASS/FAIL/INCONCLUSIVE per line); the exit status is 0
# only when every required line passes. Required with the driver: the workload succeeds; no refusal outside the protected folder;
# coverage is Ready afterwards; the writer registry never overflowed and holds no Unknown reason. Reported: duration, the registry
# high-water mark, the reclaim pass count.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
dom="${1:?debuggee domain}"; tag="${2:?tag}"; workload="${3:?msi|m365|cu|defender}"; mode="${4:?driver|control}"
sys="${5:-}"; zip="${6:-}"
[[ "$tag" =~ ^[A-Za-z0-9]{3,30}$ ]] || { echo 'Invalid tag'; exit 2; }
case "$workload" in msi|m365|cu|defender) ;; *) echo 'Unknown workload'; exit 2;; esac
case "$mode" in driver) [ -f "$sys" ] && [ -f "$zip" ] || { echo 'driver mode needs the signed driver and the agent zip'; exit 2; };; control) ;; *) echo 'Unknown mode'; exit 2;; esac
host=$(awk -v d="$dom" '$1==d{print $2}' driver/scripts/debuggees.txt); [ -n "$host" ] || { echo "Unknown debuggee $dom"; exit 2; }
# The guest's overlay grows by the size of what the workload writes (Microsoft 365 about 10 GB): never start on a nearly full host.
free_gb=$(df --output=avail -BG / | tail -1 | tr -dc '0-9')
min_gb=$([ "$workload" = m365 ] && echo 30 || echo 15)
[ "${free_gb:-0}" -ge "$min_gb" ] || { echo "host disk too low for $workload: ${free_gb} GB free, need $min_gb"; exit 30; }
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

echo "== baseline"
scp "${opts[@]}" driver/scripts/Get-StagedBaseline.ps1 "vika@$host:$guest/Get-StagedBaseline.ps1" || exit 3
echo "& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1'" | remote | tee "$ev/$tag-baseline.txt" >/dev/null
grep -q '^BaselineClean=True' "$ev/$tag-baseline.txt" || { echo 'BASELINE NOT CLEAN'; exit 10; }
remote <<<'Write-VolumeCache -DriveLetter C; "VolumeCacheWritten=True"' | grep -qx 'VolumeCacheWritten=True' || exit 16

echo "== checkpoint"
overlay="/var/lib/libvirt/images/$dom.safeupload-pre-$tag-$(date +%Y%m%d)"
[ -e "$overlay" ] && { echo "overlay exists: $overlay"; exit 11; }
$V snapshot-create-as --domain "$dom" --name "safeupload-pre-$tag" --description "before $tag" --disk-only --no-metadata \
    --diskspec "vda,snapshot=external,file=$overlay" --atomic > "$ev/$tag-checkpoint.txt" 2>&1 || { cat "$ev/$tag-checkpoint.txt"; exit 12; }
grep -q "$overlay" <($V domblklist "$dom") || { echo 'checkpoint not active'; exit 12; }

finish() {
    echo "== rollback"
    /home/victor/Work/safeupload-tools/rollback-vm.sh "$dom" "$tag" 2>&1 | tail -2
    sleep 25
    local up=0
    for _ in $(seq 1 18); do ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1 && { up=1; break; }; sleep 10; done
    if [ "$up" -eq 0 ]; then
        echo "guest did not boot after rollback; power-cycling once"
        $V destroy "$dom" >/dev/null 2>&1; sleep 3; $V start "$dom" >/dev/null 2>&1
        for _ in $(seq 1 30); do ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1 && break; sleep 10; done
    fi
    for _ in $(seq 1 40); do
        echo "& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1'" | remote > "$ev/$tag-final-restored-state.txt" 2>&1
        grep -q '^BaselineClean=True' "$ev/$tag-final-restored-state.txt" && break; sleep 6
    done
    grep -E 'BaselineClean|OriginalDriverHash' "$ev/$tag-final-restored-state.txt"
}
trap finish EXIT

if [ "$mode" = driver ]; then
    echo "== stage files and install"
    sleep 5
    scp "${opts[@]}" "$sys" "vika@$host:$guest/SafeUpload-t3.sys" && scp "${opts[@]}" "$zip" "vika@$host:$guest/stage-service-publish.zip" \
      && scp "${opts[@]}" agente/scripts/Install-SafeUploadAgent.ps1 "vika@$host:$guest/Install-SafeUploadAgent.ps1" \
      && scp "${opts[@]}" agente/scripts/Protect-SafeUploadPolicy.ps1 "vika@$host:$guest/Protect-SafeUploadPolicy.ps1" \
      && scp "${opts[@]}" agente/scripts/Get-SafeUploadDiagnostics.ps1 "vika@$host:$guest/Get-SafeUploadDiagnostics.ps1" || { echo 'copy failed'; exit 14; }
    remote <<'PS' | tee "$ev/$tag-install.txt"
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
$agentDir = 'C:\Program Files\SafeUpload\Agent'
New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
Expand-Archive -LiteralPath "$d\stage-service-publish.zip" -DestinationPath $agentDir -Force
Copy-Item -LiteralPath "$d\SafeUpload-t3.sys" -Destination 'C:\Windows\System32\drivers\SafeUpload.sys' -Force
New-Item -ItemType Directory -Force -Path 'C:\Protected' | Out-Null
& icacls.exe 'C:\Protected' /grant 'BUILTIN\Users:(OI)(CI)M' | Out-Null
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
    echo "== reboot"
    remote <<<'& shutdown.exe /r /t 5 /c "T3 install"' >/dev/null; sleep 60; wait_ssh || { echo 'guest did not return'; exit 17; }
    remote <<'PS' | tee "$ev/$tag-ready.txt"
$ErrorActionPreference = 'Continue'
function Read-AgentFrame {
    $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'SafeUpload.Agent', [System.IO.Pipes.PipeDirection]::In)
    try { $c.Connect(5000); $r = New-Object System.IO.StreamReader($c); $r.ReadLine() } finally { $c.Dispose() }
}
$ready = $false; $last = ''
for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
    try { $last = Read-AgentFrame; if ($last -match '"admissionCoverage"\s*:\s*"Ready"') { $ready = $true } } catch { $last = 'ERR ' + $_.Exception.Message }
    if (-not $ready) { Start-Sleep -Seconds 5 }
}
'READY=' + $ready
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
PS
    grep -qx 'READY=True' "$ev/$tag-ready.txt" || { echo 'agent never Ready'; exit 19; }
fi

# --- the workload, as SYSTEM in scheduled tasks so a long run does not hang on an ssh session ---------------------------------
echo "== workload $workload ($mode)"
for f in run.ps1 sampler.ps1 "$workload.ps1"; do
    scp "${opts[@]}" "driver/scripts/t3/$f" "vika@$host:$guest/t3-$f" || { echo "copy of $f failed"; exit 14; }
done
setup_ps=$(cat <<'PS'
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path C:\T3 | Out-Null
Remove-Item C:\T3\result.json, C:\T3\samples.jsonl -ErrorAction SilentlyContinue
$d = 'C:\Users\vika\Documents'
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$workloadAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $d + '\t3-run.ps1" -Body "' + $d + '\t3-__WORKLOAD__.ps1"')
Register-ScheduledTask -TaskName 't3-workload' -Principal $principal -Force -Action $workloadAction | Out-Null
if ('__MODE__' -eq 'driver') {
    $samplerAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $d + '\t3-sampler.ps1"')
    Register-ScheduledTask -TaskName 't3-sampler' -Principal $principal -Force -Action $samplerAction | Out-Null
    Start-ScheduledTask -TaskName 't3-sampler'
    Start-Sleep -Seconds 4
}
if ('__MODE__' -eq 'driver') {
    try { $c = & "$d\Get-SafeUploadDiagnostics.ps1" -Query counters; 'RING_NEXT_BEFORE=' + $c.refusals.nextSequence } catch { 'RING_NEXT_BEFORE_ERROR=' + $_.Exception.Message }
}
Start-ScheduledTask -TaskName 't3-workload'
'WORKLOAD_STARTED=True'
PS
)
setup_ps=${setup_ps//__WORKLOAD__/$workload}; setup_ps=${setup_ps//__MODE__/$mode}
printf '%s\n' "$setup_ps" | remote | tee "$ev/$tag-workload-setup.txt"
grep -qx 'WORKLOAD_STARTED=True' "$ev/$tag-workload-setup.txt" || { echo 'workload did not start'; exit 20; }

limit=3600; [ "$workload" = m365 ] && limit=5400
waited=0; state=RUNNING
while [ "$waited" -lt "$limit" ]; do
    sleep 30; waited=$((waited + 30))
    state=$(remote <<<'if (Test-Path C:\T3\result.json) { "DONE" } else { "RUNNING " + (Get-ScheduledTask -TaskName t3-workload).State }' | tail -1)
    [[ "$state" == DONE* ]] && break
done
echo "workload wait ended after ${waited}s: $state"

if [ "$workload" = cu ]; then
    # A cumulative update finishes at the reboot: let the servicing reboot happen, then check the driver survived it.
    remote <<<'& shutdown.exe /r /t 5 /c "T3 cumulative update"' >/dev/null; sleep 90; wait_ssh || echo 'guest did not return after the update reboot'
    sleep 120
fi

remote <<'PS' | tee "$ev/$tag-after.txt"
$ErrorActionPreference = 'Continue'
$d = 'C:\Users\vika\Documents'
'WORKLOAD_RESULT=' + $(if (Test-Path C:\T3\result.json) { (Get-Content C:\T3\result.json -Raw) -replace '\s+', ' ' } else { 'missing' })
'BUILD=' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild + '.' + (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
function Read-AgentFrame {
    $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'SafeUpload.Agent', [System.IO.Pipes.PipeDirection]::In)
    try { $c.Connect(5000); $r = New-Object System.IO.StreamReader($c); $r.ReadLine() } finally { $c.Dispose() }
}
try { $f = Read-AgentFrame; 'AGENT_FRAME=' + $f } catch { 'AGENT_FRAME_ERROR=' + $_.Exception.Message }
try { $c = & "$d\Get-SafeUploadDiagnostics.ps1" -Query counters; 'COUNTERS_AFTER=' + ($c | ConvertTo-Json -Depth 6 -Compress) } catch { 'COUNTERS_AFTER_ERROR=' + $_.Exception.Message }
try { $ring = @(& "$d\Get-SafeUploadDiagnostics.ps1" -Query deny-ring); 'RING_TOTAL=' + $ring.Count; foreach ($e in $ring) { 'RING=' + ($e | ConvertTo-Json -Compress) } } catch { 'RING_ERROR=' + $_.Exception.Message }
$samples = if (Test-Path C:\T3\samples.jsonl) { @(Get-Content C:\T3\samples.jsonl) } else { @() }
'SAMPLES=' + $samples.Count
$max = 0; $maxPasses = 0; $overflow = 0; $unk = 0
foreach ($s in $samples) { try { $j = $s | ConvertFrom-Json; if ($j.writerState.registryEntries -gt $max) { $max = $j.writerState.registryEntries }; if ($j.writerState.registryOverflow -gt $overflow) { $overflow = $j.writerState.registryOverflow }; if ($j.writerState.registryUnknownReasons -ne 0) { $unk = $j.writerState.registryUnknownReasons } } catch {} }
'REGISTRY_ENTRIES_MAX=' + $max
'REGISTRY_OVERFLOW_MAX=' + $overflow
'REGISTRY_UNKNOWN_SEEN=' + $unk
'AFTER_DONE=True'
PS

# Evidence kept before the rollback: the sampler's counter timeline.
scp "${opts[@]}" "vika@$host:C:/T3/samples.jsonl" "$ev/$tag-samples.jsonl" >/dev/null 2>&1 || true

# Verdict.
python3 - "$ev/$tag-after.txt" "$ev/$tag-verdict.txt" "$mode" "$workload" "$(( $(date +%s) - started ))" "$ev/$tag-workload-setup.txt" <<'PY'
import json, re, sys
after = open(sys.argv[1], encoding='utf-8', errors='replace').read()
mode, workload = sys.argv[3], sys.argv[4]
out = []
def verdict(name, ok, reason, required=True):
    out.append(f"{name} {'PASS' if ok else ('FAIL' if required else 'INCONCLUSIVE')} {reason}")
m = re.search(r'^WORKLOAD_RESULT=(.*)$', after, re.M)
result = None
if m and m.group(1).strip() != 'missing':
    try: result = json.loads(m.group(1))
    except Exception: result = None
ok = bool(result and result.get('ok'))
verdict('T3Workload', ok, f"{workload}: " + (json.dumps({k: v for k, v in result.items() if k != 'candidates'})[:400] if result else 'no result'))
if result and 'duration' in result:
    out.append(f"T3Duration INFO {mode} {workload} {result['duration']} s")
if mode == 'driver':
    verdict('T3DriverLoaded', 'DRIVER_LOADED=True' in after, 'the filter is loaded after the workload')
    frame = re.search(r'^AGENT_FRAME=(.*)$', after, re.M)
    verdict('T3CoverageReady', bool(frame) and '"admissionCoverage":"Ready"' in frame.group(1).replace(' ', ''), (frame.group(1)[:160] if frame else 'no agent frame'))
    ring = []
    for line in re.findall(r'^RING=(\{.*\})$', after, re.M):
        try: ring.append(json.loads(line))
        except Exception: pass
    total = re.search(r'^RING_TOTAL=(\d+)', after, re.M)
    verdict('T3RingRead', total is not None and int(total.group(1)) == len(ring), f"records read {len(ring)} of {total.group(1) if total else 'unknown'}")
    def inside(r): return '\\protected\\' in ((r.get('name') or '').lower() + '\\')
    def own_namespace(r): return r.get('reason') == 'privateNamespace' or '\\safeupload\\staging\\' in (r.get('name') or '').lower()
    setup = open(sys.argv[6], encoding='utf-8', errors='replace').read() if len(sys.argv) > 6 else ''
    cursor = re.search(r'^RING_NEXT_BEFORE=(\d+)', setup, re.M)
    start_seq = int(cursor.group(1)) if cursor else 0
    candidates = [r for r in ring if r.get('major') != 'QUERY_INFORMATION' and not inside(r) and not own_namespace(r)]
    during = [r for r in candidates if r['sequence'] >= start_seq]
    boot = [r for r in candidates if r['sequence'] < start_seq]
    describe = lambda rs: '; '.join(f"#{r['sequence']} {r.get('statusName')} {r.get('major')} {r.get('reason') or 'noReason'} {r.get('name')}" for r in rs[:8])
    verdict('T3NoRefusalOutsideScope', cursor is not None and not during,
            ('no refusal outside the protected folder during the workload' if not during else f"{len(during)} refusals during the workload; first: " + describe(during)) +
            ('' if cursor else '; the ring cursor at the workload start is missing'))
    out.append('T3BootTimeRefusals ' + ('INFO none before the workload' if not boot else 'INFO ' + str(len(boot)) + ' before the workload started (boot, T2c): ' + describe(boot)))
    ov = re.search(r'^REGISTRY_OVERFLOW_MAX=(\d+)', after, re.M)
    verdict('T3RegistryNeverOverflowed', ov is not None and int(ov.group(1)) == 0, f"overflow max {ov.group(1) if ov else 'unknown'}")
    mx = re.search(r'^REGISTRY_ENTRIES_MAX=(\d+)', after, re.M)
    out.append(f"T3RegistryHighWater INFO {mx.group(1) if mx else 'unknown'} of 4096")
    unk = re.search(r'^REGISTRY_UNKNOWN_SEEN=(\d+)', after, re.M)
    verdict('T3NoUnknownReason', unk is not None and int(unk.group(1)) == 0, f"unknown reasons seen {unk.group(1) if unk else 'unknown'}")
    cnt = re.search(r'^COUNTERS_AFTER=(.*)$', after, re.M)
    if cnt:
        try:
            c = json.loads(cnt.group(1)); out.append(f"T3ReclaimPasses INFO {c['reclaimWorker']['passes']} parked {c['reclaimWorker']['parkedPasses']}")
        except Exception: pass
open(sys.argv[2], 'w').write('\n'.join(out) + '\n')
print('\n'.join(out))
sys.exit(0 if all(' FAIL ' not in l for l in out) else 1)
PY
rc=$?
echo "T3 verdict file: $ev/$tag-verdict.txt (rc=$rc)"
exit $rc
