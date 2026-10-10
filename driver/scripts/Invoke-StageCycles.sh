#!/usr/bin/env bash
# T4: N save cycles in one boot (approve and block mixed, four save patterns) on a debuggee in a disposable run disk (run-disk.sh,
# always deleted afterwards; the base disk is never written). Proves that staged versions are released (no 128-per-boot ceiling),
# that the driver's pool stays flat and that the event-driven stage worker goes idle.
#
# Usage: driver/scripts/Invoke-StageCycles.sh <debuggee domain> <tag> <driver.sys> <agent zip> [cycles=10000] [ordinary|runtime-verifier]
#   Installs the pair like the manual install, reboots, waits for Ready, creates a standard user, arms runtime Verifier (flags 0x13B:
#   special pool, IRQL checking, pool tracking, I/O, deadlock, DDI) unless ordinary, and runs t4/cycles-coordinator.ps1 as SYSTEM with
#   t4/cycles-actor.ps1 as the standard user.
#
# Evidence: driver/evidence/<day>/<tag>-*.txt|jsonl; the verdict is <tag>-verdict.txt; the exit status is 0 only when every required
# line passes.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
dom="${1:?debuggee domain}"; tag="${2:?tag}"; sys="${3:?driver.sys}"; zip="${4:?agent zip}"; cycles="${5:-10000}"; mode="${6:-runtime-verifier}"
[[ "$tag" =~ ^[A-Za-z0-9]{3,30}$ ]] || { echo 'Invalid tag'; exit 2; }
[[ "$cycles" =~ ^[0-9]{1,6}$ ]] || { echo 'Invalid cycle count'; exit 2; }
case "$mode" in ordinary|runtime-verifier) ;; *) echo 'Unknown mode'; exit 2;; esac
[ -f "$sys" ] && [ -f "$zip" ] || { echo 'needs the signed driver and the agent zip'; exit 2; }
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

echo "== run disk"
source "$(dirname "${BASH_SOURCE[0]}")/image-store.sh"; source "$(dirname "${BASH_SOURCE[0]}")/run-disk.sh"
run_disk_begin "$dom" "$tag" > "$ev/$tag-checkpoint.txt" 2>&1 || { cat "$ev/$tag-checkpoint.txt"; exit 12; }
finish() {
    local test_status=$?
    trap - EXIT
    echo "== discard the run disk"
    if ! run_disk_end "$dom" "$tag" > "$ev/$tag-final-restored-state.txt" 2>&1 ||
        ! grep -qx 'RunDiskBaseUntouched=True' "$ev/$tag-final-restored-state.txt"; then
        cat "$ev/$tag-final-restored-state.txt"
        echo 'T4Restoration=FAIL'
        exit 22
    fi
    grep -E 'RunDiskBaseUntouched|deleted|nothing deleted' "$ev/$tag-final-restored-state.txt"
    exit "$test_status"
}
trap finish EXIT
wait_ssh || { echo 'guest did not boot on the run disk'; exit 3; }

echo "== baseline"
scp "${opts[@]}" driver/scripts/Get-StagedBaseline.ps1 "vika@$host:$guest/Get-StagedBaseline.ps1" || exit 3
echo "& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1'" | remote | tee "$ev/$tag-baseline.txt" >/dev/null
grep -q '^BaselineClean=True' "$ev/$tag-baseline.txt" || { echo 'BASELINE NOT CLEAN on a fresh run disk: the base changed'; exit 10; }

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

echo "== stage files and install"
sleep 5
scp "${opts[@]}" "$sys" "vika@$host:$guest/SafeUpload-t4.sys" && scp "${opts[@]}" "$zip" "vika@$host:$guest/stage-service-publish.zip" \
  && scp "${opts[@]}" agente/scripts/Install-SafeUploadAgent.ps1 "vika@$host:$guest/Install-SafeUploadAgent.ps1" \
  && scp "${opts[@]}" agente/scripts/Protect-SafeUploadPolicy.ps1 "vika@$host:$guest/Protect-SafeUploadPolicy.ps1" \
  && scp "${opts[@]}" agente/scripts/Get-SafeUploadDiagnostics.ps1 "vika@$host:$guest/Get-SafeUploadDiagnostics.ps1" \
  && scp "${opts[@]}" driver/scripts/t4/cycles-actor.ps1 "vika@$host:$guest/t4-cycles-actor.ps1" \
  && scp "${opts[@]}" driver/scripts/t4/cycles-coordinator.ps1 "vika@$host:$guest/t4-cycles-coordinator.ps1" || { echo 'copy failed'; exit 14; }
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
echo "== reboot"
remote <<<'& shutdown.exe /r /t 5 /c "T4 install"' >/dev/null; sleep 60; wait_ssh || { echo 'guest did not return'; exit 17; }
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
if ('__MODE__' -eq 'runtime-verifier') {
    & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Null
    $q = (& verifier.exe /query | Out-String)
    'VERIFIER_ARMED=' + ($q -match 'SafeUpload\.sys' -and $q -match '(?im)^\s*Verifier Flags:\s*0x0*13b')
}
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$coordinator = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $d + '\t4-cycles-coordinator.ps1" -Cycles __CYCLES__')
Register-ScheduledTask -TaskName 't4-coordinator' -Principal $principal -Action $coordinator -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 't4-coordinator'
'COORDINATOR_STARTED=True'
PS
)
setup_ps=${setup_ps//__MODE__/$mode}; setup_ps=${setup_ps//__CYCLES__/$cycles}
printf '%s\n' "$setup_ps" | remote | tee "$ev/$tag-setup.txt"
grep -qx 'COORDINATOR_STARTED=True' "$ev/$tag-setup.txt" || { echo 'coordinator did not start'; exit 20; }
if [ "$mode" = runtime-verifier ]; then grep -qx 'VERIFIER_ARMED=True' "$ev/$tag-setup.txt" || { echo 'runtime Verifier not armed'; exit 21; }; fi

# The earlier run's median was 2.2 s per cycle. Allow 4 s each on the fast run disk, plus settle and idle samples, at least an hour.
limit=$(( cycles * 4 + 600 )); [ "$limit" -lt 3600 ] && limit=3600
waited=0; state=RUNNING; alive=yes
while [ "$waited" -lt "$limit" ]; do
    sleep 60; waited=$((waited + 60))
    if ! state=$(remote <<<'if (Test-Path C:\T4\result.json) { "DONE" } else { "RUNNING " + @(Get-Content C:\T4\cycles.jsonl -ErrorAction SilentlyContinue).Count }' | tail -1); then state=UNREACHABLE; fi
    case "$state" in DONE*) break;; RUNNING*) alive=yes;; *) # a bugcheck looks like a hang: the guest stops answering
        if ! ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1; then alive=no; echo "guest unreachable after ${waited}s"; break; fi;;
    esac
    [ $((waited % 600)) -eq 0 ] && echo "progress after ${waited}s: $state"
done
echo "wait ended after ${waited}s: $state alive=$alive"

if [ "$alive" = yes ]; then
    remote <<'PS' > "$ev/$tag-after.txt"
$ErrorActionPreference = 'Continue'
'RESULT=' + $(if (Test-Path C:\T4\result.json) { (Get-Content C:\T4\result.json -Raw) -replace '\s+', ' ' } else { 'missing' })
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
'VERIFIER=' + ((& verifier.exe /query | Out-String) -replace '\s+', ' ')
try { $c = & 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query counters; 'COUNTERS=' + ($c | ConvertTo-Json -Depth 6 -Compress) } catch { 'COUNTERS_ERROR=' + $_.Exception.Message }
try { $ring = @(& 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query deny-ring); 'RING_TOTAL=' + $ring.Count; foreach ($e in $ring | Select-Object -Last 40) { 'RING=' + ($e | ConvertTo-Json -Compress) } } catch { 'RING_ERROR=' + $_.Exception.Message }
'AFTER_DONE=True'
PS
    scp "${opts[@]}" "vika@$host:C:/T4/samples.jsonl" "$ev/$tag-samples.jsonl" >/dev/null 2>&1 || true
    scp "${opts[@]}" "vika@$host:C:/T4/cycles.jsonl" "$ev/$tag-cycles.jsonl" >/dev/null 2>&1 || true
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

python3 - "$ev/$tag-after.txt" "$ev/$tag-samples.jsonl" "$ev/$tag-verdict.txt" "$cycles" "$mode" "$alive" "$(( $(date +%s) - started ))" <<'PY'
import json, re, sys
after_path, samples_path, verdict_path, cycles, mode, alive, elapsed = sys.argv[1:8]
cycles = int(cycles)
after = open(after_path, encoding='utf-8', errors='replace').read()
out = []
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
            try: samples.append(json.loads(line))
            except Exception: pass
except FileNotFoundError: pass
verdict('T4GuestAlive', alive == 'yes', 'the guest answered through the run (a Verifier stop is a bugcheck, which looks like a hang)')
verdict('T4DriverLoaded', 'DRIVER_LOADED=True' in after, 'the filter is still loaded after the cycles')
if mode == 'runtime-verifier':
    v = re.search(r'^VERIFIER=(.*)$', after, re.M)
    vt = v.group(1) if v else ''
    verdict('T4VerifierActive', 'SafeUpload.sys' in vt and re.search(r'Verifier Flags:\s*0x0*13b', vt, re.I) is not None, 'runtime Verifier 0x13B still verifies SafeUpload.sys')
completed = result.get('Completed') if result else None
verdict('T4CyclesCompleted', result is not None and completed == cycles and not result.get('Error'),
        f"{completed} of {cycles} cycles reached their outcome; outcomes {json.dumps(result.get('Outcomes')) if result else 'none'}; " +
        (f"error {result.get('Error')}; " if result and result.get('Error') else '') +
        (f"first failures {result.get('Failures')[:5]}" if result and result.get('Failures') else 'no failures'))
leak = [f for f in (result.get('Failures') or []) if 'BLOCKED BYTES PUBLISHED' in f] if result else []
verdict('T4NoBlockedBytesPublished', result is not None and not leak, 'no blocked version reached its public name' if not leak else '; '.join(leak[:5]))
cyc = [s for s in samples if s.get('Label') == 'cycle' and isinstance(s.get('Verifier'), dict) and s['Verifier'].get('NonPagedBytes') is not None]
if mode == 'runtime-verifier' and len(cyc) >= 4:
    warm = [s for s in cyc if s['Cycle'] >= min(1000, cycles // 4)]
    xs = [s['Cycle'] for s in warm]; ys = [s['Verifier']['NonPagedBytes'] for s in warm]
    n = len(xs); mx = sum(xs) / n; my = sum(ys) / n
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / max(1, sum((x - mx) ** 2 for x in xs))
    settled = (result or {}).get('Idle') or {}
    final = (settled.get('Verifier') or {}).get('NonPagedBytes')
    first = ys[0]
    # Before T4 every staged save kept about 4.5 KB of nonpaged pool (version plus view); flat means well under 1/1000 of that.
    ok = slope < 4.0 and final is not None and final <= first + 65536
    verdict('T4PoolFlat', ok, f"driver nonpaged bytes (Verifier pool tracking) from cycle {xs[0]}: {first} -> {ys[-1]} at cycle {xs[-1]}, "
            f"after idle {final}; slope {slope:.3f} B/cycle (limit 4); peak {(settled.get('Verifier') or {}).get('PeakNonPagedBytes')}")
elif mode == 'runtime-verifier':
    verdict('T4PoolFlat', False, f"only {len(cyc)} Verifier pool samples")
def stage(s, k):
    return ((s or {}).get('StageWorker') or {}).get(k)
settled = (result or {}).get('Settled'); exited = (result or {}).get('AfterActorExit'); idle = (result or {}).get('Idle')
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
sys.exit(0 if all(' PASS ' in l or ' INFO ' in l for l in out) else 1)
PY
