#!/usr/bin/env bash
# T5: Notepad Save As into a protected folder. On a debuggee in a disposable run disk (run-disk.sh, always deleted afterwards; the
# base disk is never written), a standard user signs in interactively (one-boot autologon, set before the install reboot) and a
# task with its interactive token runs t5/notepad-actor.ps1 in that session: the common file dialog's test create replayed natively
# (with an explicit delete and with delete-on-close), then real Notepad Save As driven by UI Automation, clean and CPF. A SYSTEM
# coordinator records what reached each public name, the journal entries for it and the driver's deny ring.
#
# Usage: driver/scripts/Invoke-StageNotepad.sh <debuggee domain> <tag> <driver.sys> <agent zip> [ordinary|runtime-verifier|boot-verifier]
#
# Evidence: driver/evidence/<day>/<tag>-*; the verdict is <tag>-verdict.txt; the exit status is 0 only when every required line passes.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
dom="${1:?debuggee domain}"; tag="${2:?tag}"; sys="${3:?driver.sys}"; zip="${4:?agent zip}"; mode="${5:-runtime-verifier}"
[[ "$tag" =~ ^[A-Za-z0-9]{3,30}$ ]] || { echo 'Invalid tag'; exit 2; }
case "$mode" in ordinary|runtime-verifier|boot-verifier) ;; *) echo 'Unknown mode'; exit 2;; esac
[ -f "$sys" ] && [ -f "$zip" ] || { echo 'needs the signed driver and the agent zip'; exit 2; }
driver_sha=$(sha256sum "$sys" | cut -d' ' -f1) || exit 2
host=$(awk -v d="$dom" '$1==d{print $2}' driver/scripts/debuggees.txt); [ -n "$host" ] || { echo "Unknown debuggee $dom"; exit 2; }
export SAFEUPLOAD_MIN_FREE_GB=${T5_MIN_FREE_GB:-15}
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
        echo 'T5Restoration=FAIL'
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

echo "== stage files and install"
scp "${opts[@]}" "$sys" "vika@$host:$guest/SafeUpload-t5.sys" && scp "${opts[@]}" "$zip" "vika@$host:$guest/stage-service-publish.zip" \
  && scp "${opts[@]}" agente/scripts/Install-SafeUploadAgent.ps1 "vika@$host:$guest/Install-SafeUploadAgent.ps1" \
  && scp "${opts[@]}" agente/scripts/Protect-SafeUploadPolicy.ps1 "vika@$host:$guest/Protect-SafeUploadPolicy.ps1" \
  && scp "${opts[@]}" agente/scripts/Get-SafeUploadDiagnostics.ps1 "vika@$host:$guest/Get-SafeUploadDiagnostics.ps1" \
  && scp "${opts[@]}" driver/scripts/t5/notepad-actor.ps1 "vika@$host:$guest/t5-notepad-actor.ps1" \
  && scp "${opts[@]}" driver/scripts/t5/notepad-coordinator.ps1 "vika@$host:$guest/t5-notepad-coordinator.ps1" || { echo 'copy failed'; exit 14; }
remote <<'PS' | tee "$ev/$tag-install.txt"
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
$agentDir = 'C:\Program Files\SafeUpload\Agent'
New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
Expand-Archive -LiteralPath "$d\stage-service-publish.zip" -DestinationPath $agentDir -Force
Copy-Item -LiteralPath "$d\SafeUpload-t5.sys" -Destination 'C:\Windows\System32\drivers\SafeUpload.sys' -Force
New-Item -ItemType Directory -Force -Path 'C:\Protected' | Out-Null
& icacls.exe 'C:\Protected' /grant 'BUILTIN\Users:(OI)(CI)M' | Out-Null
# The destination folder must exist before the driver loads: staging never creates a directory inside a protected folder.
New-Item -ItemType Directory -Force -Path 'C:\Protected\t5' | Out-Null
# The actor signs in interactively at the next boot (one-boot autologon on the disposable run disk).
$name = 't5actor'; $password = 'T5!' + [guid]::NewGuid().ToString('N').Substring(0, 20)
New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires -PasswordNeverExpires | Out-Null
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name -ErrorAction SilentlyContinue
$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($v in @{ AutoAdminLogon = '1'; DefaultUserName = $name; DefaultDomainName = $env:COMPUTERNAME; DefaultPassword = $password }.GetEnumerator()) {
    New-ItemProperty -LiteralPath $key -Name $v.Key -Value $v.Value -PropertyType String -Force | Out-Null }
New-ItemProperty -LiteralPath $key -Name AutoLogonCount -Value 1 -PropertyType DWord -Force | Out-Null
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
case "$mode" in
boot-verifier)
    remote <<'PS' | tee "$ev/$tag-boot-verifier.txt"
$ErrorActionPreference = 'Continue'
& verifier.exe /standard /driver SafeUpload.sys | Out-Null; $a = $LASTEXITCODE
& verifier.exe /bootmode oneboot | Out-Null; $b = $LASTEXITCODE
$settings = (& verifier.exe /querysettings 2>&1 | Out-String)
'BOOT_VERIFIER_CONFIGURED=' + ($a -in 0,2 -and $b -in 0,2 -and $settings -match 'SafeUpload\.sys' -and $settings -match 'Verifier Flags:\s+0x(?!0+\b)[0-9a-fA-F]+')
PS
    grep -qx 'BOOT_VERIFIER_CONFIGURED=True' "$ev/$tag-boot-verifier.txt" || { echo 'boot Verifier configuration failed'; exit 16; };;
esac
echo "== reboot"
remote <<<'& shutdown.exe /r /t 5 /c "T5 install"' >/dev/null; sleep 60; wait_ssh || { echo 'guest did not return'; exit 17; }
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
'VERIFIER=' + ((& verifier.exe /query | Out-String) -replace '\s+', ' ')
PS
grep -qx 'READY=True' "$ev/$tag-ready.txt" || { echo 'agent never Ready'; exit 19; }
if [ "$mode" = runtime-verifier ]; then
    # As the suite does: volatile Verifier on the boot-loaded driver once it is Ready (an fltmc load after boot is a late attach,
    # which never reports Ready).
    remote <<'PS' | tee "$ev/$tag-runtime-verifier.txt"
$ErrorActionPreference = 'Continue'
& verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Null
$q = (& verifier.exe /query 2>&1 | Out-String)
'RUNTIME_VERIFIER_ARMED=' + ($q -match 'SafeUpload\.sys' -and $q -match '(?im)^\s*Verifier Flags:\s*0x0*13b\s*$')
PS
    grep -qx 'RUNTIME_VERIFIER_ARMED=True' "$ev/$tag-runtime-verifier.txt" || { echo 'runtime Verifier not armed'; exit 18; }
fi

echo "== the actor's interactive session"
remote <<'PS' | tee "$ev/$tag-session.txt"
$deadline = [Diagnostics.Stopwatch]::GetTimestamp() + 180 * [Diagnostics.Stopwatch]::Frequency
do {
    $e = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User -eq 't5actor' })
    if ($e.Count) { 'ACTOR_SESSION=' + $e[0].SessionId; break }
    Start-Sleep -Seconds 2
} while ([Diagnostics.Stopwatch]::GetTimestamp() -lt $deadline)
PS
grep -q '^ACTOR_SESSION=[1-9]' "$ev/$tag-session.txt" || { echo 'the actor never signed in interactively'; exit 20; }

echo "== actor and coordinator ($mode)"
setup_ps=$(cat <<'PS'
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
New-Item -ItemType Directory -Force -Path C:\T5\control | Out-Null
& icacls.exe 'C:\T5\control' /grant 'BUILTIN\Users:(OI)(CI)M' | Out-Null
Copy-Item -LiteralPath "$d\t5-notepad-actor.ps1" -Destination 'C:\T5\notepad-actor.ps1' -Force
& icacls.exe 'C:\T5\notepad-actor.ps1' /grant 'BUILTIN\Users:(R)' | Out-Null
$name = 't5actor'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -STA -ExecutionPolicy Bypass -File "C:\T5\notepad-actor.ps1"'
$principal = New-ScheduledTaskPrincipal -UserId ($env:COMPUTERNAME + '\' + $name) -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 't5-actor' -Action $action -Principal $principal -Settings $settings -Force | Out-Null
$system = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$coordinator = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $d + '\t5-notepad-coordinator.ps1"')
Register-ScheduledTask -TaskName 't5-coordinator' -Principal $system -Action $coordinator -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 't5-coordinator'
'COORDINATOR_STARTED=True'
PS
)
printf '%s\n' "$setup_ps" | remote | tee "$ev/$tag-setup.txt"
grep -qx 'COORDINATOR_STARTED=True' "$ev/$tag-setup.txt" || { echo 'coordinator did not start'; exit 20; }

limit=1800; waited=0; state=RUNNING; alive=yes
while [ "$waited" -lt "$limit" ]; do
    sleep 30; waited=$((waited + 30))
    if ! state=$(remote <<<"if (Test-Path C:\\T5\\result.json) { 'DONE' } else { 'RUNNING' }" | tail -1); then state=UNREACHABLE; fi
    case "$state" in DONE*) break;; RUNNING*) alive=yes;; *) # a bugcheck looks like a hang: the guest stops answering
        if ! ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1; then alive=no; echo "guest unreachable after ${waited}s"; break; fi;;
    esac
done
echo "wait ended after ${waited}s: $state alive=$alive"

if [ "$alive" = yes ]; then
    remote <<'PS' > "$ev/$tag-after.txt"
$ErrorActionPreference = 'Continue'
'RESULT=' + $(if (Test-Path C:\T5\result.json) { (Get-Content C:\T5\result.json -Raw) -replace '\s+', ' ' } else { 'missing' })
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
'VERIFIER=' + ((& verifier.exe /query | Out-String) -replace '\s+', ' ')
try { $ring = @(& 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query deny-ring); 'RING_TOTAL=' + $ring.Count; foreach ($e in $ring | Select-Object -Last 60) { 'RING=' + ($e | ConvertTo-Json -Compress) } } catch { 'RING_ERROR=' + $_.Exception.Message }
'AFTER_DONE=True'
PS
    scp "${opts[@]}" "vika@$host:C:/T5/control/actor-error.txt" "$ev/$tag-actor-error.txt" >/dev/null 2>&1 || true
else
    $V screenshot "$dom" "$ev/$tag-unreachable.ppm" >/dev/null 2>&1 || true
    : > "$ev/$tag-after.txt"
fi

python3 - "$ev/$tag-after.txt" "$ev/$tag-verdict.txt" "$mode" "$alive" "$(( $(date +%s) - started ))" <<'PY'
import json, re, sys
after_path, verdict_path, mode, alive, elapsed = sys.argv[1:6]
after = open(after_path, encoding='utf-8', errors='replace').read()
out = []
def verdict(name, ok, reason):
    out.append(f"{name} {'PASS' if ok else 'FAIL'} {reason}")
m = re.search(r'^RESULT=(.*)$', after, re.M)
result = None
if m and m.group(1).strip() != 'missing':
    try: result = json.loads(m.group(1))
    except Exception: result = None
verdict('T5GuestAlive', alive == 'yes', 'the guest answered through the run')
verdict('T5DriverLoaded', 'DRIVER_LOADED=True' in after, 'the filter is still loaded after the run')
cases = (result or {}).get('Cases') or []
verdict('T5CasesCompleted', result is not None and not result.get('Error') and len(cases) == 4, f"{len(cases)} of 4 cases; error {(result or {}).get('Error')}")
for c in cases:
    name = 'T5' + ''.join(w.capitalize() for w in c['Op'].split('-')) + ('Block' if c.get('Sensitive') else 'Approve')
    ui = ((c.get('Ack') or {}).get('Ui') or {})
    windows = ui.get('WindowsAfterSave') or []
    detail = f"ack {json.dumps(c.get('Ack'))[:400]}; final length {c.get('FinalLength')} owner {c.get('Owner')}"
    if c.get('Sensitive'):
        ok = c.get('HandedBack') and not c.get('Leaked')
    else:
        ok = c.get('Published') and c.get('FinalSha256') == c.get('ExpectedSha256')
    if c['Op'] == 'notepad':
        ok = ok and len(windows) <= 1   # only the main window: no error box
    verdict(name, bool(ok), detail)
    for j in (c.get('Journal') or [])[:6]:
        out.append(f"{name}Journal INFO {j[:600]}")
for r in ((result or {}).get('Ring') or [])[-25:]:
    out.append(f"T5DenyRing INFO {r[:400]}")
out.append(f"T5Duration INFO {elapsed} s ({mode})")
open(verdict_path, 'w').write('\n'.join(out) + '\n')
print('\n'.join(out))
sys.exit(0 if all(' FAIL ' not in line for line in out) else 1)
PY
