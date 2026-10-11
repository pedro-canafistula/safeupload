#!/usr/bin/env bash
# T5: Notepad Save As into a protected folder. On a debuggee in a disposable run disk (run-disk.sh; deleted afterwards,
# with the base verified untouched, XML unchanged and EFI reset at every start), a standard user signs in
# interactively (one-boot autologon, set before the install reboot) and a
# task with its interactive token runs t5/notepad-actor.ps1 in that session: native control replays of the common file-dialog test
# create (with explicit delete and delete-on-close) include a labeled observer pause; separate real Notepad Save As cases use UI
# Automation, clean and CPF. A SYSTEM
# coordinator records raw NTFS destination images beside buffered public reads, the raw parent index, journal entries and the driver's
# deny ring. The independent raw artifacts and result are copied off before the run disk is discarded.
#
# Usage: driver/scripts/Invoke-StageNotepad.sh <debuggee domain> <tag> <driver.sys> <agent zip> [ordinary|runtime-verifier|boot-verifier]
#
# Evidence: driver/evidence/<day>/<tag>-*; the verdict is <tag>-verdict.txt; the exit status is 0 only when every required line passes.
set -uo pipefail
workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
code_root=$workspace_root
code_scripts="$code_root/driver/scripts"
cd "$workspace_root"
dom="${1:?debuggee domain}"; tag="${2:?tag}"; sys="${3:?driver.sys}"; zip="${4:?agent zip}"; mode="${5:-runtime-verifier}"
[[ "$tag" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{2,29}$ ]] || { echo 'Invalid tag'; exit 2; }
case "$mode" in ordinary|runtime-verifier|boot-verifier) ;; *) echo 'Unknown mode'; exit 2;; esac
[ -f "$sys" ] && [ -f "$zip" ] || { echo 'needs the signed driver and the agent zip'; exit 2; }
case "$dom" in
    win10-debug) expected_guest_uuid='9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D' ;;
    win10-debug2) expected_guest_uuid='9D6E3F02-B40A-49F0-A77F-439714F8F308' ;;
    win10-debug3) expected_guest_uuid='FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3' ;;
    *) echo "No pinned guest UUID for requested debuggee $dom"; exit 2 ;;
esac
driver_sha=$(sha256sum "$sys" | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]') || exit 2
agent_zip_sha=$(sha256sum "$zip" | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]') || exit 2
agent_service_sha=$(python3 - "$zip" <<'PY'
import hashlib, os, sys, zipfile
try:
    with zipfile.ZipFile(sys.argv[1]) as archive:
        matches = [item for item in archive.infolist()
                   if not item.is_dir() and os.path.basename(item.filename).lower() == 'safeupload.agent.service.exe']
        if len(matches) != 1 or matches[0].filename.replace('\\', '/') != 'SafeUpload.Agent.Service.exe':
            raise ValueError('package must contain exactly one root SafeUpload.Agent.Service.exe')
        print(hashlib.sha256(archive.read(matches[0])).hexdigest().upper())
except Exception as exc:
    print('T5 input package validation failed: ' + str(exc), file=sys.stderr)
    sys.exit(1)
PY
) || exit 2
[[ "$driver_sha" =~ ^[A-F0-9]{64}$ && "$agent_zip_sha" =~ ^[A-F0-9]{64}$ && "$agent_service_sha" =~ ^[A-F0-9]{64}$ ]] || { echo 'Could not pin T5 input hashes'; exit 2; }
host=$(awk -v d="$dom" '$1==d{print $2}' "$code_scripts/debuggees.txt"); [ -n "$host" ] || { echo "Unknown debuggee $dom"; exit 2; }
export SAFEUPLOAD_MIN_FREE_GB=${T5_MIN_FREE_GB:-15}
V="virsh -c qemu:///system"; ev="driver/evidence/$(date +%F)"; mkdir -p "$ev"
if find "$ev" -maxdepth 1 \( -type f -o -type d \) -name "$tag-*" -print -quit | grep -q .; then
    echo "Evidence tag already exists for today: $tag"
    exit 2
fi
{
    printf 'RunTag=%s\nMode=%s\nRequestedDomain=%s\nExpectedGuestUUID=%s\n' "$tag" "$mode" "$dom" "$expected_guest_uuid"
    printf 'LocalDriverSys=%s\nLocalDriverSysSHA256=%s\n' "$sys" "$driver_sha"
    printf 'LocalAgentZip=%s\nLocalAgentZipSHA256=%s\n' "$zip" "$agent_zip_sha"
    printf 'LocalAgentServiceEntry=SafeUpload.Agent.Service.exe\nExpectedExtractedServiceSHA256=%s\n' "$agent_service_sha"
} > "$ev/$tag-input-hashes.txt"
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new)
guest='C:/Users/vika/Documents'
clean() { python3 -c '
import re, sys, html
text = sys.stdin.read()
errors = ["ERROR: " + html.unescape(m).replace("_x000D__x000A_", "\n") for m in re.findall(r"<S S=\"Error\">(.*?)</S>", text, flags=re.S)]
text = re.sub(r"<Objs.*?</Objs>", "", text, flags=re.S).replace("#< CLIXML", "").replace("\r", "")
print("\n".join(line for line in (text.split("\n") + errors) if line.strip()))
'; }
remote() { python3 "$code_scripts/remote_ps.py" "$host" 2>&1 | clean; }
wait_ssh() { for _ in $(seq 1 90); do ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }
started=$(date +%s)

echo "== run disk"
source "$(dirname "${BASH_SOURCE[0]}")/image-store.sh"; source "$(dirname "${BASH_SOURCE[0]}")/run-disk.sh"
alive=no; result_saved=no; raw_saved=no
finish() {
    local test_status=$?
    trap - EXIT
    echo "== discard the run disk"
    if ! run_disk_end "$dom" "$tag" > "$ev/$tag-final-restored-state.txt" 2>&1; then
        cat "$ev/$tag-final-restored-state.txt"
        echo 'T5Restoration=FAIL'
        exit 22
    fi
    cat "$ev/$tag-final-restored-state.txt"
    exit "$test_status"
}
run_disk_begin "$dom" "$tag" > "$ev/$tag-checkpoint.txt" 2>&1 || { cat "$ev/$tag-checkpoint.txt"; exit 12; }
trap finish EXIT
wait_ssh || { echo 'guest did not boot on the run disk'; exit 3; }

echo "== baseline"
scp "${opts[@]}" "$code_scripts/Get-StagedBaseline.ps1" "vika@$host:$guest/Get-StagedBaseline.ps1" || exit 3
echo "& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1'" | remote | tee "$ev/$tag-baseline.txt" >/dev/null
grep -q '^BaselineClean=True' "$ev/$tag-baseline.txt" || { echo 'BASELINE NOT CLEAN on a fresh run disk: the base changed'; exit 10; }
baseline_uuid_count=$(grep -c '^UUID=' "$ev/$tag-baseline.txt" || true)
baseline_uuid=$(sed -n 's/^UUID=//p' "$ev/$tag-baseline.txt" | tr '[:lower:]' '[:upper:]')
if [ "$baseline_uuid_count" -ne 1 ] || [ "$baseline_uuid" != "$expected_guest_uuid" ]; then
    printf 'T5GuestIdentity=FAIL requested=%s expected=%s observed=%s count=%s\n' "$dom" "$expected_guest_uuid" "${baseline_uuid:-MISSING}" "$baseline_uuid_count" | tee "$ev/$tag-guest-identity.txt"
    echo 'Guest baseline UUID does not match the requested domain pinned identity'; exit 11
fi
printf 'T5GuestIdentity=PASS requested=%s expected=%s observed=%s\n' "$dom" "$expected_guest_uuid" "$baseline_uuid" | tee "$ev/$tag-guest-identity.txt"

echo "== stage files and install"
scp "${opts[@]}" "$sys" "vika@$host:$guest/SafeUpload-t5.sys" && scp "${opts[@]}" "$zip" "vika@$host:$guest/stage-service-publish.zip" \
  && scp "${opts[@]}" "$code_root/agente/scripts/Install-SafeUploadAgent.ps1" "vika@$host:$guest/Install-SafeUploadAgent.ps1" \
  && scp "${opts[@]}" "$code_root/agente/scripts/Protect-SafeUploadPolicy.ps1" "vika@$host:$guest/Protect-SafeUploadPolicy.ps1" \
  && scp "${opts[@]}" "$code_root/agente/scripts/Get-SafeUploadDiagnostics.ps1" "vika@$host:$guest/Get-SafeUploadDiagnostics.ps1" \
  && scp "${opts[@]}" "$code_scripts/StagedInvariantObserver.psm1" "vika@$host:$guest/StagedInvariantObserver.psm1" \
  && scp "${opts[@]}" "$code_scripts/t5/notepad-actor.ps1" "vika@$host:$guest/t5-notepad-actor.ps1" \
  && scp "${opts[@]}" "$code_scripts/t5/notepad-coordinator.ps1" "vika@$host:$guest/t5-notepad-coordinator.ps1" || { echo 'copy failed'; exit 14; }
install_ps=$(cat <<'PS'
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
$agentDir = 'C:\Program Files\SafeUpload\Agent'
$expectedDriverSha = '__T5_EXPECTED_DRIVER_SHA__'
$expectedAgentZipSha = '__T5_EXPECTED_AGENT_ZIP_SHA__'
$expectedServiceSha = '__T5_EXPECTED_SERVICE_SHA__'
$uploadedDriverSha = (Get-FileHash -LiteralPath "$d\SafeUpload-t5.sys" -Algorithm SHA256).Hash.ToUpperInvariant()
$uploadedAgentZipSha = (Get-FileHash -LiteralPath "$d\stage-service-publish.zip" -Algorithm SHA256).Hash.ToUpperInvariant()
'UPLOAD_DRIVER_SHA256=' + $uploadedDriverSha
'UPLOAD_AGENT_ZIP_SHA256=' + $uploadedAgentZipSha
if ($uploadedDriverSha -cne $expectedDriverSha -or $uploadedAgentZipSha -cne $expectedAgentZipSha) { throw 'Uploaded T5 driver/package bytes do not match the pinned local inputs.' }
New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
Expand-Archive -LiteralPath "$d\stage-service-publish.zip" -DestinationPath $agentDir -Force
Copy-Item -LiteralPath "$d\SafeUpload-t5.sys" -Destination 'C:\Windows\System32\drivers\SafeUpload.sys' -Force
$installedDriverSha = (Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\SafeUpload.sys' -Algorithm SHA256).Hash.ToUpperInvariant()
$serviceExe = Join-Path $agentDir 'SafeUpload.Agent.Service.exe'
if (-not (Test-Path -LiteralPath $serviceExe -PathType Leaf)) { throw 'The extracted service executable is missing from the package root.' }
$extractedServiceSha = (Get-FileHash -LiteralPath $serviceExe -Algorithm SHA256).Hash.ToUpperInvariant()
'INSTALLED_DRIVER_SHA256=' + $installedDriverSha
'EXTRACTED_SERVICE_EXE_SHA256=' + $extractedServiceSha
if ($installedDriverSha -cne $expectedDriverSha -or $extractedServiceSha -cne $expectedServiceSha) { throw 'Installed driver or extracted service executable differs from the pinned local input.' }
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
# A brand-new account's first sign-in otherwise stops at the privacy-settings pages and the first-logon animation, with no desktop.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE' -Name DisablePrivacyExperience -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableFirstLogonAnimation -Value 0 -PropertyType DWord -Force | Out-Null
$data = 'C:\ProgramData\SafeUpload'
New-Item -ItemType Directory -Force -Path $data | Out-Null
$policy = @{ version = 1; activeCategories = @('Cpf'); monitoredScopes = @{ extensions = @('.txt'); destinationPaths = @('C:\Protected'); removableDrives = $false; networkPaths = $false }; failOpen = $false; auditOnly = $false; overrideEnabled = $false } | ConvertTo-Json -Depth 5
Set-Content -LiteralPath "$data\policy.json" -Value $policy -Encoding UTF8
& "$d\Protect-SafeUploadPolicy.ps1"
& "$d\Install-SafeUploadAgent.ps1" -ServiceExecutablePath "$agentDir\SafeUpload.Agent.Service.exe"
'DriverStart=' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload').Start
'INSTALL_DONE=True'
PS
)
install_ps=${install_ps//__T5_EXPECTED_DRIVER_SHA__/$driver_sha}
install_ps=${install_ps//__T5_EXPECTED_AGENT_ZIP_SHA__/$agent_zip_sha}
install_ps=${install_ps//__T5_EXPECTED_SERVICE_SHA__/$agent_service_sha}
printf '%s\n' "$install_ps" | remote | tee "$ev/$tag-install.txt"
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
[string](Get-WinEvent -LogName Application -MaxEvents 1).RecordId | Set-Content -LiteralPath 'C:\T5\event-baseline.txt'
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
'RESULT_PRESENT=' + [bool](Test-Path C:\T5\result.json)
'RAW_MANIFEST_PRESENT=' + [bool](Test-Path C:\T5\raw\manifest.ndjson)
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
'VERIFIER=' + ((& verifier.exe /query | Out-String) -replace '\s+', ' ')
try { $ring = @(& 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query deny-ring); 'RING_TOTAL=' + $ring.Count; foreach ($e in $ring | Select-Object -Last 60) { 'RING=' + ($e | ConvertTo-Json -Compress) } } catch { 'RING_ERROR=' + $_.Exception.Message }
'AFTER_DONE=True'
PS
    result_saved=no; raw_saved=no
    if scp "${opts[@]}" "vika@$host:C:/T5/result.json" "$ev/$tag-result.json" >/dev/null 2>&1; then result_saved=yes; fi
    if scp -r "${opts[@]}" "vika@$host:C:/T5/raw" "$ev/$tag-raw" >/dev/null 2>&1 && \
        find "$ev/$tag-raw" -type f -name manifest.ndjson -size +0c -print -quit | grep -q .; then raw_saved=yes; fi
    scp "${opts[@]}" "vika@$host:C:/T5/control/actor-error.txt" "$ev/$tag-actor-error.txt" >/dev/null 2>&1 || true
    # The agent's own warnings and errors explain slow or refused publications (record IDs survive the guest clock step).
    remote <<'PS' > "$ev/$tag-service-events.txt"
$base = [long](Get-Content -LiteralPath 'C:\T5\event-baseline.txt')
$xpath = "*[System[Provider[@Name='SafeUpload.Agent.Service'] and EventRecordID > $base and (Level=1 or Level=2 or Level=3 or Level=4)]]"
Get-WinEvent -LogName Application -FilterXPath $xpath -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ RecordId = $_.RecordId; TimeCreated = $_.TimeCreated.ToString('o'); Level = $_.Level; Message = $_.Message } | ConvertTo-Json -Compress
}
PS
else
    $V screenshot "$dom" "$ev/$tag-unreachable.ppm" >/dev/null 2>&1 || true
    : > "$ev/$tag-after.txt"
fi

python3 - "$ev/$tag-after.txt" "$ev/$tag-verdict.txt" "$ev/$tag-result.json" "$ev/$tag-raw" "$mode" "$alive" "$(( $(date +%s) - started ))" "${result_saved:-no}" "${raw_saved:-no}" <<'PY'
import hashlib, json, os, re, sys
after_path, verdict_path, result_path, raw_dir, mode, alive, elapsed, result_saved, raw_saved = sys.argv[1:10]
after = open(after_path, encoding='utf-8', errors='replace').read()
out = []
def verdict(name, outcome, reason):
    if outcome not in ('PASS', 'FAIL', 'INCONCLUSIVE'):
        outcome = 'FAIL'
    out.append(f"{name} {outcome} {reason}")
result = None
if result_saved == 'yes':
    try: result = json.load(open(result_path, encoding='utf-8'))
    except Exception: result = None
verdict('T5GuestAlive', 'PASS' if alive == 'yes' else 'FAIL', 'the guest answered through the run')
verdict('T5DriverLoaded', 'PASS' if 'DRIVER_LOADED=True' in after else 'FAIL', 'the filter is still loaded after the run')
verdict('T5ResultEvidence', 'PASS' if result is not None and result_saved == 'yes' else 'FAIL',
        f"copied={result_saved}; guest-present={re.search(r'^RESULT_PRESENT=True$', after, re.M) is not None}")
verdict('T5ActorTaskStart', 'PASS' if result is not None and result.get('ActorTaskStartIssued') is True else 'FAIL',
        'the SYSTEM coordinator explicitly started the interactive actor after capturing the raw destination baseline')
ro = (result or {}).get('RawObserver') or {}
baseline = ro.get('Baseline') or {}
disposal = ro.get('Disposal') or {}
raw_samples = ro.get('Samples') or []
expected_leaves = {'probe-delete.txt', 'probe-after-publication.txt', 'probe-before-cpf.txt', 'probe-after-cpf.txt',
                   'probe-doc.txt', 'probe-onclose.txt', 'ok.txt', 'cpf.txt'}
scope_path = str(ro.get('ScopePath') or '').replace('/', '\\').rstrip('\\')
expected_paths = {scope_path + '\\' + leaf for leaf in expected_leaves}
baseline_images = baseline.get('Images') or []
baseline_current = [i for i in baseline_images if isinstance(i, dict) and i.get('Role') == 'Current']
baseline_parent = [i for i in baseline_images if isinstance(i, dict) and i.get('Role') == 'Parent']
baseline_raw_ok = (len(baseline_images) == len(expected_leaves) + 1 and len(baseline_current) == len(expected_leaves) and len(baseline_parent) == 1 and
                   {str(i.get('Path') or '').replace('/', '\\').lower() for i in baseline_current} == {p.lower() for p in expected_paths} and
                   all(i.get('Absent') is True and i.get('LogicalArtifact') is None and i.get('FileId') is None for i in baseline_current) and
                   baseline_parent[0].get('Path', '').lower() == r'c:\protected\t5' and
                   isinstance(baseline_parent[0].get('FileId'), str) and bool(baseline_parent[0].get('FileId')) and
                   isinstance(baseline_parent[0].get('Reference'), str) and bool(baseline_parent[0].get('Reference')) and
                   isinstance(baseline_parent[0].get('DirectoryEntries'), list) and len(baseline_parent[0]['DirectoryEntries']) == 0)
def valid_raw_sample(s):
    if not isinstance(s, dict) or s.get('Status') != 'OK' or s.get('RawComplete') is not True or \
       s.get('IndependentReadersAgree') is not True or s.get('NativeReaderCoverageComplete') is not True or \
       s.get('DirectoryComplete') is not True or not s.get('Phase') or not isinstance(s.get('Sequence'), int) or s['Sequence'] <= 0 or \
       not isinstance(s.get('ModuleSequence'), int) or s['ModuleSequence'] <= 0 or not isinstance(s.get('DirectoryEntries'), list) or \
       not isinstance(s.get('TargetAbsent'), bool) or s.get('ForbiddenBytesObserved') is not False:
        return False
    start, end = s.get('Start'), s.get('End')
    if not isinstance(start, dict) or not isinstance(end, dict) or start.get('BootId') != end.get('BootId') or start.get('BootId') != ro.get('BootId') or \
       not isinstance(start.get('Qpc'), int) or not isinstance(end.get('Qpc'), int) or end['Qpc'] < start['Qpc'] or \
       not isinstance(start.get('QpcFrequency'), int) or start['QpcFrequency'] <= 0 or end.get('QpcFrequency') != start['QpcFrequency']:
        return False
    images = s.get('CurrentImages')
    public = s.get('PublicReaders')
    native = s.get('ObserverReaders')
    if not isinstance(images, list) or not isinstance(public, list) or not isinstance(native, list) or len(images) != len(expected_leaves) or len(public) != len(expected_leaves) or \
       len(baseline_parent) != 1 or not isinstance(s.get('ParentFileId'), str) or not s.get('ParentFileId') or \
       not isinstance(s.get('ParentReference'), str) or not s.get('ParentReference') or \
       s.get('ParentFileId') != baseline_parent[0].get('FileId') or s.get('ParentReference') != baseline_parent[0].get('Reference'):
        return False
    image_by_leaf = {}
    for image in images:
        if not isinstance(image, dict) or not image.get('Path'):
            return False
        leaf = image['Path'].replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if leaf in image_by_leaf or image['Path'].replace('/', '\\').lower() != (scope_path + '\\' + leaf).lower():
            return False
        image_by_leaf[leaf] = image
        if image.get('Absent') is True:
            if image.get('FileId') is not None or image.get('LogicalArtifact') is not None or image.get('FileNames') != []:
                return False
        elif image.get('Absent') is False:
            artifact = image.get('LogicalArtifact')
            if not isinstance(artifact, dict) or not artifact.get('Path') or not isinstance(image.get('Length'), int) or image['Length'] < 0 or \
               artifact.get('Length') != image['Length'] or not re.fullmatch(r'[A-Fa-f0-9]{64}', str(image.get('Sha256', ''))) or \
               artifact.get('Sha256') != image.get('Sha256') or not image.get('FileId') or not image.get('Reference') or not isinstance(image.get('FileNames'), list):
                return False
        else:
            return False
    if set(image_by_leaf) != {x.lower() for x in expected_leaves}:
        return False
    public_by_leaf = {}
    for reader in public:
        if not isinstance(reader, dict) or not reader.get('Path'):
            return False
        leaf = reader['Path'].replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if leaf in public_by_leaf or reader['Path'].replace('/', '\\').lower() != (scope_path + '\\' + leaf).lower():
            return False
        public_by_leaf[leaf] = reader
    if set(public_by_leaf) != set(image_by_leaf):
        return False
    def directory_key(item):
        return (str(item.get('Name', '')).lower(), str(item.get('Namespace')), str(item.get('Reference')))
    expected_entries = []
    for leaf, image in image_by_leaf.items():
        if image.get('Absent') is True:
            continue
        named_in_parent = [f for f in image.get('FileNames') or [] if isinstance(f, dict) and str(f.get('Parent')) == str(s.get('ParentReference'))]
        if not any(str(f.get('Name', '')).lower() == leaf and str(f.get('Namespace')) != '2' for f in named_in_parent):
            return False
        expected_entries.extend(directory_key(f) for f in named_in_parent)
    actual_entries = [directory_key(d) for d in s.get('DirectoryEntries')]
    if len(actual_entries) != len(set(actual_entries)) or set(actual_entries) != set(expected_entries) or len(actual_entries) != len(expected_entries):
        return False
    for leaf, image in image_by_leaf.items():
        reader = public_by_leaf[leaf]
        if image.get('Absent') is True:
            if reader.get('Status') != 'ABSENT':
                return False
            if any(r.get('Path', '').replace('/', '\\').rsplit('\\', 1)[-1].lower() == leaf for r in native if isinstance(r, dict)):
                return False
        else:
            if reader.get('Status') != 'OK' or reader.get('Length') != image.get('Length') or reader.get('Sha256') != image.get('Sha256'):
                return False
            matches = [r for r in native if isinstance(r, dict) and r.get('Path', '').replace('/', '\\').rsplit('\\', 1)[-1].lower() == leaf]
            if len(matches) != 2 or sum(r.get('Unbuffered') is True for r in matches) != 1:
                return False
            for r in matches:
                if r.get('Status') != 'OK' or r.get('Length') != image.get('Length') or r.get('Sha256') != image.get('Sha256') or \
                   r.get('BeforeFileId') != image.get('FileId') or r.get('AfterFileId') != image.get('FileId'):
                    return False
    return True
def validate_raw_artifacts(directory, observer):
    manifests = []
    for base, _, names in os.walk(directory):
        manifests.extend(os.path.join(base, n) for n in names if n.lower() == 'manifest.ndjson')
    if len(manifests) != 1:
        return False, f'found {len(manifests)} raw manifests'
    manifest_dir = os.path.dirname(manifests[0])
    artifacts = {}
    try:
        with open(manifests[0], encoding='utf-8') as stream:
            lines = [line for line in stream if line.strip()]
        if not lines:
            return False, 'raw manifest is empty'
        for line in lines:
            record = json.loads(line)
            path = record.get('Path')
            if not path:
                return False, 'manifest artifact path missing'
            name = os.path.basename(path.replace('\\', '/'))
            if not name or name in artifacts or not re.fullmatch(r'[A-Za-z0-9_-]+\.bin', name):
                return False, 'manifest artifact name missing, duplicate, or malformed'
            local = os.path.join(manifest_dir, name)
            if not os.path.isfile(local) or os.path.getsize(local) != record.get('Length'):
                return False, f'missing/short artifact {name}'
            digest = hashlib.sha256()
            with open(local, 'rb') as data:
                for chunk in iter(lambda: data.read(1024 * 1024), b''):
                    digest.update(chunk)
            if digest.hexdigest().upper() != str(record.get('Sha256', '')).upper():
                return False, f'artifact digest mismatch {name}'
            artifacts[name] = record
        required = set()
        for image in (observer.get('Baseline') or {}).get('Images') or []:
            artifact = image.get('LogicalArtifact')
            if artifact and artifact.get('Path'):
                required.add(os.path.basename(artifact['Path'].replace('\\', '/')))
        for sample in observer.get('Samples') or []:
            for image in sample.get('CurrentImages') or []:
                artifact = image.get('LogicalArtifact')
                if artifact and artifact.get('Path'):
                    required.add(os.path.basename(artifact['Path'].replace('\\', '/')))
        if not required or not required.issubset(artifacts):
            return False, 'one or more raw logical artifacts are not retained in the manifest'
        return True, f'{len(artifacts)} artifacts verified; {len(required)} logical images referenced'
    except Exception as exc:
        return False, f'raw artifact validation error: {exc}'
def native_steps_match(case):
    expected = {
        'probe-delete-before-seal': {'test-create': 0, 'test-close': 0, 'test-delete': 0, 'save-create': 0, 'save-write': 0, 'save-close': 0},
        'probe-delete-after-publication': {'test-create': 0, 'test-close': 0, 'test-delete': 0, 'save-create': 0, 'save-write': 0, 'save-close': 0},
        'probe-doc': {'test-create': 0, 'open-after-doc-flag': 303, 'test-close': 0, 'save-create': 0, 'save-write': 0, 'save-close': 0},
        'probe-onclose': {'first-create': 0, 'second-open': 0, 'first-on-close-delete': 0, 'open-after-first-flag': 303,
                          'second-on-close-delete': 0, 'first-on-close-clear': 0, 'open-after-first-clear': 303,
                          'second-on-close-clear': 0, 'open-after-both-clear': 0, 'save-write': 0, 'save-close': 0,
                          'first-close': 0, 'second-close': 0},
    }.get(case.get('Op'))
    if expected is None:
        return case.get('NativeStepsOk') is True
    if case.get('NativeStepsChecked') is not True or case.get('NativeStepsOk') is not True:
        return False
    steps = str((case.get('Ack') or {}).get('Steps') or '')
    for name, code in expected.items():
        found = re.findall(r'(?:^|\s)' + re.escape(name) + r'=(-?[0-9]+)', steps)
        if len(found) != 1 or int(found[0]) != code:
            return False
    return not (case.get('Ack') or {}).get('Error')
def forced_order_matches(case, samples):
    op = case.get('Op')
    if op not in ('probe-delete-before-seal', 'probe-delete-after-publication', 'probe-doc'):
        return True
    proof = case.get('ForcedOrderProof')
    if not isinstance(proof, dict) or proof.get('Verified') is not True or proof.get('Op') != op:
        return False
    ready, ack = proof.get('ActorReady'), case.get('Ack')
    sequences, journal = proof.get('RawSequences'), proof.get('Journal')
    if not isinstance(ready, dict) or not isinstance(ack, dict) or ready.get('N') != ack.get('N') or ready.get('Op') != op or \
       ready.get('ProbeCreated') is not True or not isinstance(sequences, list) or not sequences or \
       len(set(sequences)) != len(sequences) or not isinstance(journal, list):
        return False
    by_sequence = {s.get('Sequence'): s for s in samples if isinstance(s, dict)}
    if any(sequence not in by_sequence for sequence in sequences) or proof.get('FinalRawSequence') != sequences[-1]:
        return False
    observations = [by_sequence[sequence] for sequence in sequences]
    before_go = proof.get('CapturedBeforeGoQpc')
    if not isinstance(before_go, int) or before_go <= 0 or any(not valid_raw_sample(s) or
        s.get('Phase') != 'ControlProbeAfterTestCreateCloseBeforeDeleteOrSave' or s['End']['Qpc'] > before_go for s in observations):
        return False
    path = str(case.get('Path') or '').replace('/', '\\').lower()
    target = [i for i in observations[-1].get('CurrentImages', []) if str(i.get('Path') or '').replace('/', '\\').lower() == path]
    if len(target) != 1 or proof.get('Target') != target[0]:
        return False
    steps = str(ack.get('Steps') or '')
    if op == 'probe-doc':
        return len(observations) >= 2 and all(s.get('TargetAbsent') is True for s in observations)
    if len(journal) != 1 or journal[0].get('IsV20') is not True or str(journal[0].get('DestinationPath') or '').replace('/', '\\').lower() != path:
        return False
    entry = journal[0]
    identity = entry.get('StageIdentity')
    if not isinstance(identity, dict) or any(type(identity.get(k)) is not int or not 0 <= identity[k] < 2**64
        for k in ('VolumeSerialNumber', 'FileIdHigh', 'FileIdLow')) or not entry.get('DriverInstanceId') or not entry.get('TransferId'):
        return False
    if op == 'probe-delete-before-seal':
        return (ready.get('WritableProbeHandleHeld') is True and ready.get('ForcedOrder') == 'DeleteBeforeSeal' and
                ack.get('ForcedOrder') == 'DeleteBeforeSeal' and len(observations) >= 2 and
                all(s.get('TargetAbsent') is True for s in observations) and entry.get('State') in ('0', '8') and
                entry.get('SealedOnce') is False and entry.get('SealedLength') is None and entry.get('Sha256Hex') is None and
                0 <= steps.find('test-delete=') < steps.find('test-close='))
    empty_sha = 'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855'
    return (ready.get('WritableProbeHandleHeld') is False and ready.get('RequiredObservation') == 'PublicEmptyFile' and
            ready.get('ForcedOrder') == 'DeleteAfterObservedPublication' and ack.get('ForcedOrder') == 'DeleteAfterObservedPublication' and
            target[0].get('Absent') is False and target[0].get('Length') == 0 and target[0].get('Sha256') == empty_sha and
            bool(target[0].get('FileId')) and entry.get('State') == '5' and entry.get('SealedOnce') is True and
            entry.get('SealedLength') == 0 and entry.get('Sha256Hex') == empty_sha and
            0 <= steps.find('test-close=') < steps.find('test-delete='))
def raw_case_final_matches(case, samples):
    if not isinstance(samples, list) or not samples:
        return False
    leaf = str(case.get('Leaf') or '').lower()
    if leaf not in expected_leaves:
        return False
    target_path = (scope_path + '\\' + leaf).lower()
    images = [i for i in (samples[-1].get('CurrentImages') or []) if isinstance(i, dict) and
              str(i.get('Path') or '').replace('/', '\\').lower() == target_path]
    if len(images) != 1:
        return False
    image = images[0]
    if case.get('Sensitive') is True:
        return image.get('Absent') is True and image.get('FileId') is None and image.get('LogicalArtifact') is None
    expected_length = case.get('ExpectedLength')
    expected_sha = case.get('ExpectedSha256')
    return (case.get('Sensitive') is False and isinstance(expected_length, int) and expected_length > 0 and
            re.fullmatch(r'[A-Fa-f0-9]{64}', str(expected_sha or '')) is not None and image.get('Absent') is False and
            image.get('Length') == expected_length and image.get('Sha256') == expected_sha)
raw_schema_ok = (isinstance(raw_samples, list) and len(raw_samples) > 0 and all(valid_raw_sample(s) for s in raw_samples) and
                 len({s.get('Sequence') for s in raw_samples if isinstance(s, dict)}) == len(raw_samples))
cases = (result or {}).get('Cases') or []
case_raw_samples = [s for c in cases for s in (c.get('RawSamples') or [])]
case_sequence_keys = {(s.get('Sequence'), s.get('Phase')) for s in case_raw_samples if isinstance(s, dict)}
global_sequence_keys = {(s.get('Sequence'), s.get('Phase')) for s in raw_samples if isinstance(s, dict)}
case_samples_by_key = {(s.get('Sequence'), s.get('Phase')): s for s in case_raw_samples if isinstance(s, dict)}
global_samples_by_key = {(s.get('Sequence'), s.get('Phase')): s for s in raw_samples if isinstance(s, dict)}
raw_schema_ok = raw_schema_ok and len(case_raw_samples) == len(raw_samples) and case_sequence_keys == global_sequence_keys and \
                case_samples_by_key == global_samples_by_key
ordered_sequences = [s.get('Sequence') for s in raw_samples if isinstance(s, dict)]
raw_schema_ok = raw_schema_ok and ordered_sequences == list(range(1, len(raw_samples) + 1)) and \
                [s.get('ModuleSequence') for s in raw_samples if isinstance(s, dict)] == ordered_sequences
raw_artifacts_ok, raw_artifact_reason = validate_raw_artifacts(raw_dir, ro) if raw_saved == 'yes' and result is not None else (False, 'raw directory or result copy missing')
raw_ok = (ro.get('Status') == 'OK' and ro.get('CaseId') == 'T5' and ro.get('ObserverPid') and
          ro.get('ObserverSid') == 'S-1-5-18' and baseline.get('Status') == 'OK' and
          baseline.get('ObserverPid') == ro.get('ObserverPid') and baseline.get('ObserverSid') == 'S-1-5-18' and
          ro.get('Build') == '19045.2965' and ro.get('BootId') and ro.get('VolumeGuid') and
          str(ro.get('ScopePath') or '').lower() == r'c:\protected\t5' and re.fullmatch(r'[A-Fa-f0-9]{64}', str(ro.get('ModuleSha256', ''))) and
          isinstance(baseline.get('Names'), list) and len(baseline.get('Names')) == len(expected_leaves) and
          {str(x).lower() for x in baseline.get('Names')} == expected_leaves and
          isinstance(baseline.get('Images'), list) and baseline_raw_ok and
          isinstance(baseline.get('Time'), dict) and baseline['Time'].get('BootId') == ro.get('BootId') and
          isinstance(baseline['Time'].get('QpcFrequency'), int) and baseline['Time']['QpcFrequency'] > 0 and
          isinstance(disposal.get('Errors'), list) and len(disposal.get('Errors')) == 0 and
          isinstance(disposal.get('Time'), dict) and disposal['Time'].get('BootId') == ro.get('BootId') and
          disposal.get('Status') == 'OK' and raw_schema_ok and raw_artifacts_ok)
verdict('T5RawObserver', 'PASS' if raw_ok else 'FAIL',
        f"status={ro.get('Status')}; baseline={baseline.get('Status')}; samples={len(raw_samples)}; disposal={disposal.get('Status')}; schema={raw_schema_ok}; artifacts={raw_artifact_reason}")
verdict('T5RawEvidenceRetained', 'PASS' if raw_artifacts_ok else 'FAIL',
        f"copied={raw_saved}; guest-manifest={re.search(r'^RAW_MANIFEST_PRESENT=True$', after, re.M) is not None}; {raw_artifact_reason}")
expected_case_specs = {
    'ProbeDelete': ('probe-delete-before-seal', 'probe-delete.txt', False),
    'ProbeDeleteAfterPublication': ('probe-delete-after-publication', 'probe-after-publication.txt', False),
    'ProbeDeleteBeforeSealCpf': ('probe-delete-before-seal', 'probe-before-cpf.txt', True),
    'ProbeDeleteAfterPublicationCpf': ('probe-delete-after-publication', 'probe-after-cpf.txt', True),
    'ProbeDeleteOnClose': ('probe-doc', 'probe-doc.txt', False),
    'OnCloseCancellation': ('probe-onclose', 'probe-onclose.txt', False),
    'NotepadApprove': ('notepad', 'ok.txt', False),
    'NotepadHandBack': ('notepad', 'cpf.txt', True),
}
expected_kinds = set(expected_case_specs)
cases_by_kind = {c.get('Kind'): c for c in cases}
case_matrix_ok = (len(cases) == len(expected_kinds) and set(cases_by_kind) == expected_kinds and all(
    (cases_by_kind[k].get('Op'), cases_by_kind[k].get('Leaf'), cases_by_kind[k].get('Sensitive')) == expected_case_specs[k]
    for k in expected_kinds))
verdict('T5CasesCompleted', 'PASS' if result is not None and not result.get('Error') and case_matrix_ok else 'FAIL',
        f"{len(cases)} of {len(expected_kinds)} required distinct cases; error {(result or {}).get('Error')}")
for c in cases:
    name = 'T5' + c.get('Kind', c.get('Op', 'Unknown'))
    ui = ((c.get('Ack') or {}).get('Ui') or {})
    windows = ui.get('WindowsAfterSave') or []
    raw_case_samples = c.get('RawSamples') or []
    raw_case_ok = (c.get('RawCoverageComplete') is True and c.get('IndependentReadersAgree') is True and
                   len(raw_case_samples) > 0 and all(valid_raw_sample(s) for s in raw_case_samples) and
                   c.get('FinalRawMatches') is True and raw_case_final_matches(c, raw_case_samples))
    steps_ok = native_steps_match(c)
    detail = f"native={c.get('NativeStepsReason')}; raw={raw_case_ok}; final length={c.get('FinalLength')} sha={c.get('FinalSha256')} owner={c.get('Owner')}"
    target_path = (scope_path + '\\' + str(c.get('Leaf') or '')).lower()
    empty_raw_samples = []
    for sample in raw_case_samples:
        for image in sample.get('CurrentImages') or []:
            if isinstance(image, dict) and str(image.get('Path') or '').replace('/', '\\').lower() == target_path and \
               image.get('Absent') is False and image.get('Length') == 0:
                empty_raw_samples.append({'Sequence': sample.get('Sequence'), 'Phase': sample.get('Phase'), 'Path': image.get('Path')})
    no_empty_leftover = (c.get('NoEmptyLeftover') is True and
                isinstance(c.get('JournalParseErrors'), list) and len(c.get('JournalParseErrors')) == 0 and
                isinstance(c.get('JournalSchemaErrors'), list) and len(c.get('JournalSchemaErrors')) == 0 and
                raw_case_final_matches(c, raw_case_samples))
    journal_outcome = c.get('FinalJournalOutcomeVerified') is True and c.get('SettlementStatus') == 'PASS'
    verdict(name + 'NoEmptyLeftover', 'PASS' if no_empty_leftover else 'FAIL',
            f"settlement={c.get('SettlementStatus')}; empty-records={len(c.get('EmptyVersionPublicationRecords') or [])}; raw-empty-samples={len(empty_raw_samples)}; journal-parse-errors={len(c.get('JournalParseErrors') or [])}; journal-schema-errors={len(c.get('JournalSchemaErrors') or [])}")
    if c.get('Sensitive'):
        ok = raw_case_ok and steps_ok and c.get('HandedBack') is True and c.get('Leaked') is False and c.get('FinalRawMatches') is True and no_empty_leftover and journal_outcome
        detail += f"; handback={((c.get('Handback') or {}).get('Status'))}; leaked={c.get('Leaked')}"
    else:
        ok = raw_case_ok and steps_ok and c.get('Published') is True and c.get('FinalSha256') == c.get('ExpectedSha256') and no_empty_leftover and journal_outcome
    if c.get('Op') in ('probe-delete-before-seal', 'probe-doc'):
        ok = ok and c.get('ProbeControlSamples', 0) >= 2 and c.get('ProbeControlTargetAbsentThroughout') is True and \
             c.get('ProbeDiscarded') is True and c.get('ProbeEmptyPrivateBlocked') is False
        detail += f"; control-window-samples={c.get('ProbeControlSamples')}; control-target-absent={c.get('ProbeControlTargetAbsentThroughout')}; discarded={c.get('ProbeDiscarded')}"
    if c.get('Op') in ('probe-delete-before-seal', 'probe-delete-after-publication', 'probe-doc'):
        order_ok = forced_order_matches(c, raw_case_samples)
        ok = ok and order_ok
        verdict(name + 'ForcedOrder', 'PASS' if order_ok else 'FAIL', 'native steps and independent raw/journal evidence precede the actor release')
    if c.get('Op') == 'notepad':
        ok = ok and c.get('NoUiErrorWindow') is True and len(windows) <= 1
    verdict(name, 'PASS' if bool(ok) else 'FAIL', detail)
    for j in (c.get('Journal') or [])[:6]:
        out.append(f"{name}Journal INFO {json.dumps(j)[:600]}")
raw_verdict = ro.get('NoUnapprovedByteVerdict')
verdict('T5CanonicalNoUnapprovedByte', 'PASS' if raw_verdict == 'PASS' else ('INCONCLUSIVE' if raw_verdict == 'INCONCLUSIVE' else 'FAIL'),
        ro.get('NoUnapprovedByteReason') or 'Canonical lower-mutation proof field missing.')
for r in ((result or {}).get('Ring') or [])[-25:]:
    out.append(f"T5DenyRing INFO {r[:400]}")
out.append(f"T5Duration INFO {elapsed} s ({mode})")
open(verdict_path, 'w').write('\n'.join(out) + '\n')
print('\n'.join(out))
sys.exit(0 if raw_verdict == 'PASS' and all((' PASS ' in line or ' INFO ' in line) for line in out if not line.startswith('T5Duration INFO')) else 1)
PY
