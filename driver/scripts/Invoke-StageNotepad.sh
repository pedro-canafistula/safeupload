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
# Office tasks B (Excel) and W (Word), on the sealed Office base (ordinary or runtime-verifier):
#   T5_OFFICE_BASE=1 SAFEUPLOAD_DEBUGGEE=win10-debug3 driver/scripts/Invoke-StageNotepad.sh win10-debug3 <fresh-tag> <driver.sys> <agent.zip> ordinary
#   T5_OFFICE_BASE=1 SAFEUPLOAD_DEBUGGEE=win10-debug3 driver/scripts/Invoke-StageNotepad.sh win10-debug3 <fresh-tag> <driver.sys> <agent.zip> runtime-verifier
# Password: ~/Work/safeupload-tools/secrets/office-base-20261029-t5actor.txt (0600), read only at runtime into the remote channel.
# Existing t5actor/profile/password are preserved. One-boot autologon exists only on the disposable overlay.
# Office mode refuses a running domain, nonstandard vda, or any debug2/debug3 run/parked state; it restores base-20261014
# after run_disk_end on success/failure/HUP/INT/TERM. Unresolved run files/state are retained if cleanup fails; neither base is booted writable.
# T5_STAGE_SPACE=off sets only Interception:StageSpace:Enabled=false; FloorOnly is preserved. The default "on" leaves the
# package settings unchanged (the MVP package defaults to Enabled=false, FloorOnly=true). Configuration is recorded below.
#
# Evidence: driver/evidence/<day>/<tag>-*; the verdict is <tag>-verdict.txt; the exit status is 0 only when every required line passes.
# After separate restoration, <tag>-mvp-verdict.txt derives A/C/D or Office B/W task outcomes; it never turns a failed full row green.
set -uo pipefail
workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
code_root=$workspace_root
code_scripts="$code_root/driver/scripts"
cd "$workspace_root"
dom="${1:?debuggee domain}"; tag="${2:?tag}"; sys="${3:?driver.sys}"; zip="${4:?agent zip}"; mode="${5:-runtime-verifier}"
[[ "$tag" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{2,29}$ ]] || { echo 'Invalid tag'; exit 2; }
case "$mode" in ordinary|runtime-verifier|boot-verifier) ;; *) echo 'Unknown mode'; exit 2;; esac
office_base=${T5_OFFICE_BASE:-0}
case "$office_base" in 0|1) ;; *) echo 'T5_OFFICE_BASE must be 0 or 1'; exit 2;; esac
if [ "$office_base" = 1 ]; then
    [ "$dom" = win10-debug3 ] && [ "$mode" != boot-verifier ] || { echo 'Office mode requires win10-debug3 and ordinary/runtime-verifier'; exit 2; }
fi
stage_space=${T5_STAGE_SPACE-on}
case "$stage_space" in on|off) ;; *) echo 'T5_STAGE_SPACE must be on or off'; exit 2;; esac
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
    printf 'SourceCommit=%s\n' "$(git rev-parse HEAD)"
    printf 'StageSpace=%s\n' "$stage_space"
    printf 'OfficeBase=%s\n' "$office_base"
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
# Office-base lifecycle: functions are exercised with local stubs by the self-check.
t5_original_base=/var/lib/libvirt/images/win10-debug3.base-20261014.qcow2
t5_office_base=/var/lib/libvirt/images/win10-debug3.office-base-20261029.qcow2
t5_office_repoint=0
t5_office_preflight() {
    [ "$($V domstate "$dom")" = 'shut off' ] && [ "$($V domstate win10-debug2)" = 'shut off' ] || { echo 'Office mode requires both clones shut off'; return 1; }
    [ "$(_rd_vda "$dom" --inactive)" = "$t5_original_base" ] || { echo 'Office mode requires exact base-20261014 vda'; return 1; }
    local conflict
    # An active run on either clone conflicts. A parked disk (run-disk.sh park) and the lifecycle lock do not: the
    # Office repoint never touches base-20261014, which a parked overlay keeps as its base, and restores the vda.
    for conflict in "$RUN_DISK_STATE"/win10-debug2 "$RUN_DISK_STATE"/win10-debug3; do
        [ ! -e "$conflict" ] || { echo 'Office mode refuses conflicting run/parked state'; return 1; }
    done
    for conflict in "$RUN_DISK_STATE"/win10-debug[23].parked-*; do
        case "$conflict" in *.overlay|*.xml) continue ;; esac
        [ ! -e "$conflict" ] || grep -qxF "base=$t5_original_base" "$conflict" ||
            { echo 'Office mode refuses conflicting run/parked state'; return 1; }
    done
    [ -f "$t5_original_base" ] && [ -f "$t5_office_base" ] || return 1
    [ "$(_rd_vol "$t5_office_base" format)" = qcow2 ] && [ "$(_rd_vol "$t5_office_base" backing)" = "$t5_original_base" ] || { echo 'Unexpected Office backing chain'; return 1; }
    _rd_named_elsewhere "$dom" "$t5_office_base" && { echo 'Another domain names the Office base'; return 1; }
    t5_original_stat=$(stat -c '%d:%i:%s:%Y:%Z' "$t5_original_base") || return 1
    t5_office_stat=$(stat -c '%d:%i:%s:%Y:%Z' "$t5_office_base") || return 1
    $V dumpxml --inactive "$dom" > "$ev/$tag-pre-office.xml" || return 1
}
t5_office_return() {
    [ "$t5_office_repoint" = 1 ] || return 0
    # run_disk_end normally leaves the guest off on the Office base. If it
    # failed, preserve the unresolved state/files but still restore the domain.
    if [ "$($V domstate "$dom")" != 'shut off' ]; then
        local current
        current=$(_rd_vda "$dom" --inactive) || return 1
        if [ "$current" = "$t5_office_base" ] || [ "$current" = "$t5_original_base" ]; then
            _rd_shutdown "$dom" || return 1
        else
            $V destroy "$dom" >/dev/null || return 1
        fi
    fi
    [ "$($V domstate "$dom")" = 'shut off' ] || return 1
    _rd_repoint "$dom" "$t5_original_base" || return 1
    [ "$(_rd_vda "$dom" --inactive)" = "$t5_original_base" ] &&
        cmp -s "$ev/$tag-pre-office.xml" <($V dumpxml --inactive "$dom") &&
        [ "$(stat -c '%d:%i:%s:%Y:%Z' "$t5_original_base")" = "$t5_original_stat" ] &&
        [ "$(stat -c '%d:%i:%s:%Y:%Z' "$t5_office_base")" = "$t5_office_stat" ] || return 1
    echo 'T5OfficeOriginalVdaAndXmlRestored=True'
    echo 'T5OfficeBothBasesUntouched=True'
}
finish() {
    local test_status=$?
    local restoration=PASS
    trap - EXIT
    trap '' HUP INT TERM
    echo "== discard the run disk"
    if ! run_disk_end "$dom" "$tag" > "$ev/$tag-final-restored-state.txt" 2>&1; then
        echo 'T5Restoration=FAIL'
        restoration=FAIL
        test_status=22
    fi
    cat "$ev/$tag-final-restored-state.txt"
    if [ "${office_base:-0}" = 1 ]; then
        local office_restored=PASS
        if ! t5_office_return > "$ev/$tag-office-restored-state.txt" 2>&1; then
            office_restored=FAIL; restoration=FAIL; test_status=22
        fi
        cat "$ev/$tag-office-restored-state.txt"
        printf 'T5OfficeBase %s original/Office chain pinned; both base stats and original XML/vda restored; receipt=%s\n' "$office_restored" "$ev/$tag-office-restored-state.txt" >> "$ev/$tag-verdict.txt"
    fi
    printf 'T5Restoration %s separate run_disk_end; receipt=%s\n' "$restoration" "$ev/$tag-final-restored-state.txt" >> "$ev/$tag-verdict.txt"
    python3 "$code_scripts/t5/mvp-task-verdict.py" "$ev/$tag-verdict.txt" > "$ev/$tag-mvp-verdict.txt"
    local mvp_status=$?
    cat "$ev/$tag-mvp-verdict.txt"
    if [ "$test_status" -eq 0 ] && [ "$mvp_status" -ne 0 ]; then test_status=$mvp_status; fi
    exit "$test_status"
}
if [ "$office_base" = 1 ]; then t5_office_preflight > "$ev/$tag-office-preflight.txt" 2>&1 || { cat "$ev/$tag-office-preflight.txt"; exit 12; }; fi
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$office_base" = 1 ]; then
    t5_office_repoint=1
    _rd_repoint "$dom" "$t5_office_base" || exit 12
fi
run_disk_begin "$dom" "$tag" > "$ev/$tag-checkpoint.txt" 2>&1 || { cat "$ev/$tag-checkpoint.txt"; exit 12; }
wait_ssh || { echo 'guest did not boot on the run disk'; exit 3; }

echo "== baseline"
scp "${opts[@]}" "$code_scripts/Get-StagedBaseline.ps1" "vika@$host:$guest/Get-StagedBaseline.ps1" || exit 3
baseline_arg=''; [ "$office_base" = 0 ] || baseline_arg='-OfficeBase'
echo "& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1' $baseline_arg" | remote | tee "$ev/$tag-baseline.txt" >/dev/null
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
  && scp "${opts[@]}" "$code_scripts/t5/notepad-cases.json" "vika@$host:$guest/t5-notepad-cases.json" \
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
# Office's existing account owns DPAPI-bound M365 credentials. Never mutate it.
$officeBase = '__T5_OFFICE_BASE__' -ceq '1'
$name = 't5actor'
if ($officeBase) {
    $officeActor = Get-LocalUser -Name $name -ErrorAction Stop
    if (-not $officeActor.Enabled) { throw 'Office actor is disabled' }
    'OFFICE_ACTOR_SID=' + $officeActor.SID.Value
    'OFFICE_ACTOR_PASSWORD_LAST_SET=' + $officeActor.PasswordLastSet.ToUniversalTime().ToString('o')
} else {
$password = 'T5!' + [guid]::NewGuid().ToString('N').Substring(0, 20)
New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires -PasswordNeverExpires | Out-Null
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name -ErrorAction SilentlyContinue
$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($v in @{ AutoAdminLogon = '1'; DefaultUserName = $name; DefaultDomainName = $env:COMPUTERNAME; DefaultPassword = $password }.GetEnumerator()) {
    New-ItemProperty -LiteralPath $key -Name $v.Key -Value $v.Value -PropertyType String -Force | Out-Null }
New-ItemProperty -LiteralPath $key -Name AutoLogonCount -Value 1 -PropertyType DWord -Force | Out-Null
}
# A brand-new account's first sign-in otherwise stops at the privacy-settings pages and the first-logon animation, with no desktop.
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE' -Name DisablePrivacyExperience -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableFirstLogonAnimation -Value 0 -PropertyType DWord -Force | Out-Null
$data = 'C:\ProgramData\SafeUpload'
New-Item -ItemType Directory -Force -Path $data | Out-Null
$policy = @{ version = 1; activeCategories = @('Cpf'); monitoredScopes = @{ extensions = @('.txt'); destinationPaths = @('C:\Protected'); removableDrives = $false; networkPaths = $false }; failOpen = $false; auditOnly = $false; overrideEnabled = $false } | ConvertTo-Json -Depth 5
if ($officeBase) { $p = $policy | ConvertFrom-Json; $p.monitoredScopes.extensions = @('.xlsx','.docx'); $policy = $p | ConvertTo-Json -Depth 5 }
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
install_ps=${install_ps//__T5_OFFICE_BASE__/$office_base}
printf '%s\n' "$install_ps" | remote | tee "$ev/$tag-install.txt"
grep -qx 'INSTALL_DONE=True' "$ev/$tag-install.txt" || { echo 'install failed'; exit 15; }
if [ "$office_base" = 1 ]; then
    # No shell variable, evidence file or log ever contains the password. This
    # short script stays on remote_ps's encoded-command channel; silence even
    # PowerShell error-source excerpts, which could otherwise expose the value.
    if ! python3 - "$HOME/Work/safeupload-tools/secrets/office-base-20261029-t5actor.txt" <<'PY' | remote >/dev/null 2>&1
import base64, os, stat, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'r', encoding='utf-8') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
            raise ValueError()
        password = source.read(1024).rstrip('\r\n')
    if not 1 <= len(password) <= 256 or any(c in password for c in '\r\n\x00'):
        raise ValueError()
    encoded = base64.b64encode(password.encode('utf-8')).decode('ascii')
except Exception:
    raise SystemExit('Office password file missing or invalid (owner-only regular UTF-8 file required)')
print("""$ErrorActionPreference='Stop'
try {
 $u=Get-LocalUser -Name 't5actor' -ErrorAction Stop
 if(-not $u.Enabled){exit 1}
 $password=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('""" + encoded + """'))
 $key='HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
 foreach($v in @{AutoAdminLogon='1';DefaultUserName='t5actor';DefaultDomainName=$env:COMPUTERNAME;DefaultPassword=$password}.GetEnumerator()){
  New-ItemProperty -LiteralPath $key -Name $v.Key -Value $v.Value -PropertyType String -Force | Out-Null
 }
 New-ItemProperty -LiteralPath $key -Name AutoLogonCount -Value 1 -PropertyType DWord -Force | Out-Null
 $password=$null
 exit 0
}catch{exit 1}
""")
PY
    then echo 'Office one-boot autologon setup failed (secret-channel output suppressed)'; exit 15; fi
fi
if [ "$stage_space" = off ]; then
    remote <<'PS' | tee "$ev/$tag-stage-space.txt"
$ErrorActionPreference = 'Stop'
$path = 'C:\Program Files\SafeUpload\Agent\appsettings.json'
$json = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
$floorOnly = $json.Interception.StageSpace.FloorOnly
$json.Interception.StageSpace.Enabled = $false
$text = $json | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
'STAGE_SPACE_ENABLED=' + (Get-Content -Raw -LiteralPath $path | ConvertFrom-Json).Interception.StageSpace.Enabled
$readback = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
'STAGE_SPACE_FLOOR_ONLY=' + $readback.Interception.StageSpace.FloorOnly
if ($readback.Interception.StageSpace.FloorOnly -ne $floorOnly) { throw 'T5 override changed FloorOnly' }
PS
    grep -qx 'STAGE_SPACE_ENABLED=False' "$ev/$tag-stage-space.txt" || { echo 'could not disable StageSpace for the isolation row'; exit 23; }
fi
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
if ('__T5_OFFICE_BASE__' -ceq '1') { $coordinator = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $d + '\t5-notepad-coordinator.ps1" -OfficeBase') }
Register-ScheduledTask -TaskName 't5-coordinator' -Principal $system -Action $coordinator -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 't5-coordinator'
'COORDINATOR_STARTED=True'
PS
)
setup_ps=${setup_ps//__T5_OFFICE_BASE__/$office_base}
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
try { 'LIVE_DRIVER_SHA256=' + (Get-FileHash -LiteralPath 'C:\Windows\System32\drivers\SafeUpload.sys' -Algorithm SHA256).Hash.ToUpperInvariant() } catch { 'LIVE_DRIVER_SHA256=ERROR' }
try { 'LIVE_SERVICE_EXE_SHA256=' + (Get-FileHash -LiteralPath 'C:\Program Files\SafeUpload\Agent\SafeUpload.Agent.Service.exe' -Algorithm SHA256).Hash.ToUpperInvariant() } catch { 'LIVE_SERVICE_EXE_SHA256=ERROR' }
try { $u=Get-LocalUser -Name 't5actor' -ErrorAction Stop; 'OFFICE_ACTOR_SID='+$u.SID.Value; 'OFFICE_ACTOR_PASSWORD_LAST_SET='+$u.PasswordLastSet.ToUniversalTime().ToString('o') } catch { 'OFFICE_ACTOR_SID=ERROR' }
try { $ring = @(& 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query deny-ring); 'RING_TOTAL=' + $ring.Count; foreach ($e in $ring | Select-Object -Last 60) { 'RING=' + ($e | ConvertTo-Json -Compress) } } catch { 'RING_ERROR=' + $_.Exception.Message }
try { $counters = & 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query counters; 'WRITER_STATE=' + ($counters.writerState | ConvertTo-Json -Depth 6 -Compress); 'COUNTERS_AFTER=' + ($counters | ConvertTo-Json -Depth 6 -Compress) } catch { 'WRITER_STATE_ERROR=' + $_.Exception.Message }
'AFTER_DONE=True'
PS
    result_saved=no; raw_saved=no
    if scp "${opts[@]}" "vika@$host:C:/T5/result.json" "$ev/$tag-result.json" >/dev/null 2>&1; then result_saved=yes; fi
    if scp -r "${opts[@]}" "vika@$host:C:/T5/raw" "$ev/$tag-raw" >/dev/null 2>&1 && \
        find "$ev/$tag-raw" -type f -name manifest.ndjson -size +0c -print -quit | grep -q .; then raw_saved=yes; fi
    scp "${opts[@]}" "vika@$host:C:/T5/control/actor-error.txt" "$ev/$tag-actor-error.txt" >/dev/null 2>&1 || true
    # Independent interactive monitor logs survive even if Word blocks inside COM on an alert.
    scp -r "${opts[@]}" "vika@$host:C:/T5/control/word-alerts" "$ev/$tag-word-alerts" >/dev/null 2>&1 || true
    # The agent's own warnings and errors explain slow or refused publications (record IDs survive the guest clock step).
    remote <<'PS' > "$ev/$tag-service-events.txt"
$base = [long](Get-Content -LiteralPath 'C:\T5\event-baseline.txt')
$xpath = "*[System[Provider[@Name='SafeUpload.Agent.Service'] and EventRecordID > $base and (Level=1 or Level=2 or Level=3 or Level=4)]]"
Get-WinEvent -LogName Application -FilterXPath $xpath -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ RecordId = $_.RecordId; TimeCreated = $_.TimeCreated.ToString('o'); Level = $_.Level; Message = $_.Message } | ConvertTo-Json -Compress
}
PS
    # Diagnostic copies (best effort): the agent's journal and private staging root explain refused or stuck allocations.
    remote <<'PS' > "$ev/$tag-agent-state-list.txt"
foreach ($dir in 'C:\ProgramData\SafeUpload\staging-journal', 'C:\ProgramData\SafeUpload\staging') {
    'DIR=' + $dir
    Get-ChildItem -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { '{0}|{1}|{2}' -f $_.FullName, $_.Length, $_.LastWriteTimeUtc.ToString('o') }
}
PS
    scp -r "${opts[@]}" "vika@$host:C:/ProgramData/SafeUpload/staging-journal" "$ev/$tag-agent-journal" >/dev/null 2>&1 || true
    scp -r "${opts[@]}" "vika@$host:C:/ProgramData/SafeUpload/staging" "$ev/$tag-agent-staging" >/dev/null 2>&1 || true
    scp -r "${opts[@]}" "vika@$host:C:/T5/handback-evidence" "$ev/$tag-handback-evidence" >/dev/null 2>&1 || true
    scp -r "${opts[@]}" "vika@$host:C:/T5/journal-evidence" "$ev/$tag-journal-evidence" >/dev/null 2>&1 || true
else
    $V screenshot "$dom" "$ev/$tag-unreachable.ppm" >/dev/null 2>&1 || true
    : > "$ev/$tag-after.txt"
fi

T5_OFFICE_BASE_EFFECTIVE="$office_base" T5_STAGE_SPACE_EFFECTIVE="$stage_space" python3 - "$ev/$tag-after.txt" "$ev/$tag-verdict.txt" "$ev/$tag-result.json" "$ev/$tag-raw" "$mode" "$alive" "$(( $(date +%s) - started ))" "${result_saved:-no}" "${raw_saved:-no}" "$code_scripts/t5/notepad-cases.json" "$ev/$tag-agent-state-list.txt" <<'PY'
import hashlib, json, os, re, sys
after_path, verdict_path, result_path, raw_dir, mode, alive, elapsed, result_saved, raw_saved = sys.argv[1:10]
after = open(after_path, encoding='utf-8', errors='replace').read()
out = []
def verdict(name, outcome, reason):
    if outcome not in ('PASS', 'FAIL', 'INCONCLUSIVE'):
        outcome = 'FAIL'
    out.append(f"{name} {outcome} {reason}")
def receipt_fields(text, key):
    return re.findall(r'^' + re.escape(key) + r'=(.*)$', text, re.M)

def artifact_hashes_match(inputs, installed, after_text):
    bindings = {
        'LocalDriverSysSHA256': [(installed, 'UPLOAD_DRIVER_SHA256'), (installed, 'INSTALLED_DRIVER_SHA256'), (after_text, 'LIVE_DRIVER_SHA256')],
        'LocalAgentZipSHA256': [(installed, 'UPLOAD_AGENT_ZIP_SHA256')],
        'ExpectedExtractedServiceSHA256': [(installed, 'EXTRACTED_SERVICE_EXE_SHA256'), (after_text, 'LIVE_SERVICE_EXE_SHA256')],
    }
    for key, observations in bindings.items():
        expected = receipt_fields(inputs, key)
        if len(expected) != 1 or not re.fullmatch(r'[A-F0-9]{64}', expected[0]):
            return False
        if any(receipt_fields(text, field) != expected for text, field in observations):
            return False
    return True

def mode_readback_matches(run_mode, ready_text, after_text, arming_text):
    def query(text):
        fields = receipt_fields(text, 'VERIFIER')
        return fields[0] if len(fields) == 1 else ''
    final = query(after_text)
    if run_mode == 'ordinary':
        return all('No drivers are currently verified' in q and not re.search(r'SafeUpload\.sys', q, re.I)
                   for q in (query(ready_text), final))
    if run_mode == 'runtime-verifier':
        return (receipt_fields(arming_text, 'RUNTIME_VERIFIER_ARMED') == ['True'] and
                re.search(r'SafeUpload\.sys', final, re.I) is not None and
                re.search(r'Verifier Flags:\s*0x0*13b\b', final, re.I) is not None)
    if run_mode == 'boot-verifier':
        return (receipt_fields(arming_text, 'BOOT_VERIFIER_CONFIGURED') == ['True'] and
                all(re.search(r'SafeUpload\.sys', q, re.I) and re.search(r'Verifier Flags:\s*0x(?!0+\b)[0-9a-f]+', q, re.I)
                    for q in (query(ready_text), final)))
    return False

def read_run_receipt(suffix):
    try:
        return open(verdict_path.removesuffix('-verdict.txt') + suffix, encoding='utf-8', errors='replace').read()
    except OSError:
        return ''

office_run = os.environ.get('T5_OFFICE_BASE_EFFECTIVE') == '1'
out.append('T5RunProfile INFO ' + ('OfficeApps' if office_run else 'BasicTasks'))
if office_run:
    baseline_receipt = read_run_receipt('-baseline.txt')
    installed_receipt = read_run_receipt('-install.txt')
    account_ok = (receipt_fields(baseline_receipt, 'BaselineClean') == ['True'] and
                  receipt_fields(baseline_receipt, 'OfficeActorAccount') == ['True'] and
                  receipt_fields(baseline_receipt, 'OfficeInstallation') == ['True'])
    for baseline_field, field in (('OfficeActorSID', 'OFFICE_ACTOR_SID'), ('OfficeActorPasswordLastSet', 'OFFICE_ACTOR_PASSWORD_LAST_SET')):
        expected = receipt_fields(baseline_receipt, baseline_field)
        account_ok = account_ok and len(expected) == 1 and bool(expected[0]) and all(
            receipt_fields(text, field) == expected for text in (installed_receipt, after))
    verdict('T5OfficeAccount', 'PASS' if account_ok else 'FAIL', 'explicit Office baseline; existing actor SID and password-last-set unchanged through install and run')
inputs = read_run_receipt('-input-hashes.txt')
verdict('T5PairHashes', 'PASS' if artifact_hashes_match(inputs, read_run_receipt('-install.txt'), after) else 'FAIL',
        'local driver/package/service hashes equal upload, installed/extracted and post-run driver/service readback; ' +
        '; '.join(key + '=' + ','.join(receipt_fields(inputs, key)) for key in
                  ('LocalDriverSysSHA256', 'LocalAgentZipSHA256', 'ExpectedExtractedServiceSHA256')))
verdict('T5ModeReadback', 'PASS' if mode_readback_matches(mode, read_run_receipt('-ready.txt'), after,
        read_run_receipt('-runtime-verifier.txt' if mode == 'runtime-verifier' else '-boot-verifier.txt')) else 'FAIL',
        'requested mode=' + mode + '; ordinary requires no verified drivers; runtime requires SafeUpload.sys flags 0x13B before tasks and after run')
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
with open(sys.argv[10], encoding='utf-8') as case_stream:
    required_cases = [c for c in json.load(case_stream) if bool(c.get('Office')) == (os.environ.get('T5_OFFICE_BASE_EFFECTIVE') == '1')]
expected_leaves = {leaf.lower() for c in required_cases for leaf in [c['Leaf'], *c.get('AuxiliaryLeaves', [])]}
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
                   # Windows PowerShell 5.1 serializes the empty entry collection of the parent image as {} (m2t5ord15): an empty
                   # object is an empty list there, nothing else is.
                   (baseline_parent[0].get('DirectoryEntries') == {} or
                    (isinstance(baseline_parent[0].get('DirectoryEntries'), list) and len(baseline_parent[0]['DirectoryEntries']) == 0)))
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
    # Owner 2026-10-21: a sample taken while the actor runs carries public reads from before the raw capture too; the raw image must
    # match one of the two reads, and a change between them must be approved bytes. Every other phase stays strict.
    before = s.get('PublicReadersBefore')
    before_by_leaf = {}
    if s.get('Phase') == 'ActorRunning' and before is not None:
        if not isinstance(before, list) or len(before) != len(expected_leaves):
            return False
        for reader in before:
            if not isinstance(reader, dict) or not reader.get('Path'):
                return False
            before_by_leaf[reader['Path'].replace('/', '\\').rsplit('\\', 1)[-1].lower()] = reader
        if set(before_by_leaf) != set(image_by_leaf):
            return False
    elif before is not None:
        return False
    def approved_read(leaf, reader):
        if reader.get('Status') in ('ABSENT', 'DELETE_PENDING'):
            return True
        return reader.get('Status') == 'OK' and (reader.get('Length') == 0 or reader.get('Sha256') in approved_public_hashes.get(leaf, set()))
    for leaf, image in image_by_leaf.items():
        reader = public_by_leaf[leaf]
        earlier = before_by_leaf.get(leaf)
        readers = [reader] + ([earlier] if earlier is not None else [])
        if earlier is not None:
            if earlier.get('Status') == 'ERROR':
                return False
            if (earlier.get('Status'), earlier.get('Sha256')) != (reader.get('Status'), reader.get('Sha256')) and \
               not (approved_read(leaf, earlier) and approved_read(leaf, reader)):
                return False
        if image.get('Absent') is True:
            # A raw-absent name the filter reports delete-pending (probe gates) must read delete-pending too.
            expected_status = 'DELETE_PENDING' if image.get('NamedLookup') == 'DELETE_PENDING' else 'ABSENT'
            if image.get('NamedLookup') not in (None, 'DELETE_PENDING') or not any(r.get('Status') == expected_status for r in readers):
                return False
            if any(r.get('Path', '').replace('/', '\\').rsplit('\\', 1)[-1].lower() == leaf for r in native if isinstance(r, dict)):
                return False
        else:
            if not any(r.get('Status') == 'OK' and r.get('Length') == image.get('Length') and r.get('Sha256') == image.get('Sha256') for r in readers):
                return False
            matches = [r for r in native if isinstance(r, dict) and r.get('Path', '').replace('/', '\\').rsplit('\\', 1)[-1].lower() == leaf]
            if len(matches) != 2 or sum(r.get('Unbuffered') is True for r in matches) != 1:
                return False
            for r in matches:
                if r.get('Status') != 'OK' or r.get('Length') != image.get('Length') or r.get('Sha256') != image.get('Sha256') or \
                   r.get('BeforeFileId') != image.get('FileId') or r.get('AfterFileId') != image.get('FileId'):
                    return False
    return True
T5_TRANSIENT_PHASES = ('ActorRunning', 'WorkflowSettlement', 'AfterActorAcknowledgementSettlement')
# Owner 2026-10-22 (third rule, deny-list): in these phases any capture failure is a race unless it is one of the verdict-class errors.
T5_FATAL_OBSERVATION_ERRORS = ('CPF or unexpected nonempty fixture bytes',
                               'Office observation journal is invalid',
                               'differs from the independently captured baseline parent',
                               'Raw parent directory identity is incomplete',
                               'One or more raw target images or artifacts are missing/incomplete',
                               'Raw parent index has unexpected/missing file references',
                               '"Verdict":"FAIL"', '"Verdict":"VIOLATION"')
def transient_observation_error(s):
    # A sample taken while the actor or the agent is mid-operation may fail because a name appeared or vanished or the raw metadata lags.
    if not isinstance(s, dict) or s.get('Status') == 'OK' or s.get('ForbiddenBytesObserved') is not False or s.get('Phase') not in T5_TRANSIENT_PHASES:
        return False
    text = str(s.get('Error') or '').replace('\\"', '"')
    return bool(text.strip()) and not any(fatal in text for fatal in T5_FATAL_OBSERVATION_ERRORS)
def raw_samples_accepted(samples):
    # (accepted, superseded): every sample of one case is valid, or a transient observation error whose very next sample of the same
    # case (any phase; owner 2026-10-22) is valid. The superseded errors stay in the result and are counted in the verdict.
    superseded = 0
    if not isinstance(samples, list) or not samples:
        return False, 0
    for index, sample in enumerate(samples):
        if valid_raw_sample(sample) and workflow_observed_bytes_match(sample):
            continue
        following = samples[index + 1] if index + 1 < len(samples) else None
        if transient_observation_error(sample) and isinstance(following, dict) and isinstance(sample.get('Sequence'), int) and \
           following.get('Sequence') == sample['Sequence'] + 1 and \
           valid_raw_sample(following) and workflow_observed_bytes_match(following):
            superseded += 1
            continue
        return False, superseded
    return True, superseded
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
def archive_payload_matches(container, record):
    import struct
    import uuid
    try:
        if len(container) < 4096 or len(container) > 4194304:
            return False
        magic, version, frontier = struct.unpack_from('<Iiq', container)
        if magic != 0x43415553 or version != 1 or frontier != len(container) or hashlib.sha256(container[:16]).digest() != container[16:48]:
            return False
        offset = record.get('FrameOffset')
        if type(offset) is not int or offset < 4096 or offset + 60 > frontier:
            return False
        magic, version, length = struct.unpack_from('<Iii', container, offset)
        if magic != 0x414A5553 or version != 1 or not 0 < length <= 131072 or offset + 60 + length > frontier:
            return False
        payload = container[offset + 60:offset + 60 + length]
        digest = hashlib.sha256(payload).digest()
        transfer = uuid.UUID(bytes_le=bytes(container[offset + 12:offset + 28])).hex
        return (length == record.get('Length') and digest == container[offset + 28:offset + 60] and
                digest.hex().upper() == record.get('Sha256') and transfer == str(record.get('TransferId', '')).replace('-', '').lower() and
                str(json.loads(payload)['Transfer']['TransferId']).replace('-', '').lower() == transfer)
    except (ValueError, KeyError, TypeError, struct.error):
        return False

def validate_t5_archives(directory, cases):
    import pathlib
    try:
        records = [j['ArchiveRecord'] for c in cases for j in [*(c.get('Journal') or []), *[r for snap in c.get('WorkflowJournalSnapshots', []) for r in snap]] if 'ArchiveRecord' in j]
        # Include the forced-order snapshots: a probe may archive before the next snapshot.
        records += [j['ArchiveRecord'] for c in cases for j in ((c.get('ForcedOrderProof') or {}).get('Journal') or []) if 'ArchiveRecord' in j]
        for record in records:
            name = str(record.get('Artifact') or '').replace('\\', '/').rsplit('/', 1)[-1]
            if not re.fullmatch(r'[A-F0-9]{64}\.bin', name):
                return False, 'archive container artifact missing'
            data = pathlib.Path(directory, name).read_bytes()
            if hashlib.sha256(data).hexdigest().upper() != name[:-4] or not archive_payload_matches(data, record):
                return False, 'archive container/payload/transfer mismatch'
            if record.get('HotArtifact'):
                hot_name = str(record['HotArtifact']).replace('\\', '/').rsplit('/', 1)[-1]
                if hot_name != record['Sha256'] + '.bin':
                    return False, 'hot/archive artifact digest-name mismatch'
                offset = record['FrameOffset'] + 60
                if pathlib.Path(directory, hot_name).read_bytes() != data[offset:offset + record['Length']]:
                    return False, 'retained hot/archive bytes disagree'
        return True, f'{len(records)} archived payload references verified'
    except Exception as exc:
        return False, str(exc)

def native_steps_match(case):
    expected = {
        'probe-delete-before-seal': {'test-create': 0, 'test-close': 0, 'test-delete': 0, 'save-create': 0, 'save-write': 0, 'save-close': 0},
        'probe-delete-after-publication': {'test-create': 0, 'test-close': 0, 'test-delete': 0, 'save-create': 0, 'save-write': 0, 'save-close': 0},
        # STATUS_DELETE_PENDING (-1073741738 = 0xC0000056) for the private view's refused opens; Win32 reports it as 5.
        'probe-doc': {'test-create': 0, 'open-after-doc-flag': 5, 'open-after-doc-flag-nt': -1073741738, 'test-close': 0, 'save-create': 0, 'save-write': 0, 'save-close': 0},
        'probe-onclose': {'first-create': 0, 'second-open': 0, 'first-on-close-delete': 0, 'open-after-first-flag': 5, 'open-after-first-flag-nt': -1073741738,
                          'second-on-close-delete': 0, 'first-on-close-clear': 0, 'open-after-first-clear': 5, 'open-after-first-clear-nt': -1073741738,
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
def writer_registry_verdict(after_text):
    # D7 rev 5 control (m2t5ord9): the driver's writer registry must stay Known across the row. Missing diagnostics are
    # INCONCLUSIVE, never PASS; the reasons and first-Unknown origins are in the line so a failure is triaged from it.
    found = re.search(r'^WRITER_STATE=(\{.*\})\s*$', after_text, re.M)
    if found is None:
        error = re.search(r'^WRITER_STATE_ERROR=(.*)$', after_text, re.M)
        return 'INCONCLUSIVE', 'driver writer-registry diagnostics were not captured: ' + (error.group(1).strip()[:200] if error else 'no WRITER_STATE line')
    try:
        state = json.loads(found.group(1))
        origins = {k: state[k] for k in ('writerGlobalFirstUnknown', 'writerEntryFirstUnknown', 'writerSopFirstUnknown')}
        mask, instance, sop = state['registryUnknownReasons'], state['registryInstanceUnknown'], state['writerSopUnknownCount']
        reasons = [o['reason'] for o in origins.values()]
        assert all(isinstance(v, int) for v in (mask, instance, sop, *reasons))
    except Exception as exc:
        return 'INCONCLUSIVE', 'driver writer-registry diagnostics were unusable: ' + type(exc).__name__ + ' ' + str(exc)[:120]
    detail = ('unknownReasons=%d instanceUnknown=%d sopUnknownCount=%d globalFirst=%s entryFirst=%s sopFirst=%s cleanupUnmatched=%s untrackedCreates=%s' %
              (mask, instance, sop, json.dumps(origins['writerGlobalFirstUnknown']), json.dumps(origins['writerEntryFirstUnknown']),
               json.dumps(origins['writerSopFirstUnknown']), state.get('cleanupUnmatched'), state.get('untrackedCreates')))
    return ('PASS' if mask == 0 and instance == 0 and sop == 0 and not any(reasons) else 'FAIL'), detail
def staging_empty_verdict(listing_text):
    # The SYSTEM coordinator cannot look inside the private staging namespace (the driver refuses every process but the service),
    # so the launcher's own listing of the staging directory after the run is the independent leftover proof.
    section = None
    files = []
    for line in listing_text.splitlines():
        if line.startswith('DIR='):
            section = line[4:].strip().rstrip('\\').lower()
        elif section is not None and section.endswith('\\programdata\\safeupload\\staging') and '|' in line:
            files.append(line.split('|', 1)[0].strip())
    if not any(l.startswith('DIR=') and l[4:].strip().rstrip('\\').lower().endswith('\\programdata\\safeupload\\staging') for l in listing_text.splitlines()):
        return 'INCONCLUSIVE', 'the post-run staging directory listing was not captured'
    if files:
        return 'FAIL', '%d stage file(s) remain after the run: %s' % (len(files), '; '.join(files[:5]))
    return 'PASS', 'the staging directory is empty after the run (independent listing)'
def journal_settled_verdict(listing_text):
    # D8 (m2t5ord10/11): a Notepad probe stayed Retained for ever, so the hot journal still held its entry after the run. Completed
    # transfers live under completed\\ (archived); a *.json directly under staging-journal is an unfinished obligation.
    inside = False
    seen = False
    hot = []
    for line in listing_text.splitlines():
        if line.startswith('DIR='):
            inside = line[4:].strip().rstrip('\\').lower().endswith('\\programdata\\safeupload\\staging-journal')
            seen = seen or inside
        elif inside and '|' in line:
            path = line.split('|', 1)[0].strip()
            leaf = path.rsplit('\\', 1)[-1]
            parent = path.rsplit('\\', 1)[0].lower()
            if parent.endswith('\\staging-journal') and leaf.lower().endswith('.json'):
                hot.append(leaf)
    if not seen:
        return 'INCONCLUSIVE', 'the post-run journal listing was not captured'
    if hot:
        return 'FAIL', '%d unfinished journal entr%s remain after the run: %s' % (len(hot), 'y' if len(hot) == 1 else 'ies', '; '.join(hot[:5]))
    return 'PASS', 'the hot journal is empty after the run (every transfer completed and archived)'
def office_app(case):
    return 'Word' if (workflow_spec(case) or {}).get('OfficeApp') == 'Word' else 'Excel'

def office_versions(case):
    return case.get(office_app(case) + 'Versions') or []

def office_record_matches(case, record):
    """Bind the workbook digest to retained service bytes, subject and object."""
    import pathlib
    try:
        directory = pathlib.Path(raw_dir.removesuffix('-raw') + '-journal-evidence')
        archive = record.get('ArchiveRecord')
        artifact = (archive or {}).get('Artifact') if archive else record.get('JournalArtifact')
        name = str(artifact or '').replace('\\', '/').rsplit('/', 1)[-1]
        if not re.fullmatch(r'[A-F0-9]{64}\.bin', name):
            return False
        data = (directory / name).read_bytes()
        if hashlib.sha256(data).hexdigest().upper() != name[:-4]:
            return False
        if archive:
            if not archive_payload_matches(data, archive):
                return False
            data = data[archive['FrameOffset'] + 60:archive['FrameOffset'] + 60 + archive['Length']]
        manifest = json.loads(data)
        transfer = manifest['Transfer']
        pairs = ('TransferId', 'DestinationPath', 'ProcessId', 'RequestorSid', 'SessionId', 'ProcessName', 'RequestorProcessCreationTime')
        if any(transfer.get(key) != record.get(key) for key in pairs):
            return False
        if str(manifest['State']) != record.get('State') or str(manifest.get('HandbackState')) != record.get('HandbackState') or any(manifest.get(key) != record.get(key) for key in
                ('Sha256Hex', 'SealedLength', 'SealedOnce', 'StageDeleted', 'StageIdentity', 'DriverInstanceId', 'DestinationGeneration')):
            return False
        identity = record.get('StageIdentity')
        if (not isinstance(identity, dict) or any(type(identity.get(k)) is not int or not 0 <= identity[k] < 2**64 for k in
                ('VolumeSerialNumber', 'FileIdHigh', 'FileIdLow')) or not record.get('DriverInstanceId') or not record.get('TransferId') or
                type(record.get('DestinationGeneration')) is not int or record['DestinationGeneration'] <= 0):
            return False
        app = office_app(case)
        writers = [a.get('Ui') or {} for a in case.get('WorkflowAcks', []) if a.get('Op') != app.lower() + '-read']
        return (record.get('DestinationPath', '').lower() == (scope_path + '\\' + case['Leaf']).lower() and
                record.get('RequestorSid') == (result or {}).get('ActorSid') and record.get('SealedOnce') is True and
                type(record.get('SealedLength')) is int and record['SealedLength'] > 0 and
                re.fullmatch(r'[A-F0-9]{64}', str(record.get('Sha256Hex') or '')) is not None and
                re.fullmatch(r'winword(?:\.exe)?' if app == 'Word' else r'excel(?:\.exe)?', str(record.get('ProcessName') or ''), re.I) is not None and
                any(w.get(app + 'Pid') == record.get('ProcessId') and w.get(app + 'Sid') == record['RequestorSid'] and
                    type(w.get(app + 'CreationTime')) is int and w[app + 'CreationTime'] > 0 and
                    w[app + 'CreationTime'] == record.get('RequestorProcessCreationTime') and
                    w.get('SessionId') == record.get('SessionId') and type(w.get('SessionId')) is int and w['SessionId'] > 0 for w in writers))
    except (OSError, ValueError, KeyError, TypeError):
        return False

def office_releases(case):
    return [j for j in case.get('Journal', []) if j.get('State') == '5' and j.get('StageDeleted') is True and office_record_matches(case, j)]

def word_alerts_match(case, ack):
    import pathlib
    ui = ack.get('Ui') or {}
    monitor = ui.get('AlertMonitor') or {}
    artifact = str(monitor.get('Artifact') or '').replace('/', '\\')
    name = artifact.rsplit('\\', 1)[-1]
    if not re.fullmatch(r'[a-f0-9]{32}\.json', name) or not artifact.lower().startswith('c:\\t5\\control\\word-alerts\\'):
        return False
    try:
        path = pathlib.Path(raw_dir.removesuffix('-raw') + '-word-alerts', name)
        if path.stat().st_size > 131072:
            return False
        persisted = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False
    return (persisted == {k: v for k, v in monitor.items() if k != 'Artifact'} and ui.get('AlertTexts') == [] and
            not ui.get('ErrorText') and not ui.get('MonitorError') and monitor.get('WordPid') == ui.get('WordPid') and
            monitor.get('MonitorSid') == ack.get('ActorSid') and monitor.get('SessionId') == ui.get('SessionId') and
            type(monitor.get('MonitorPid')) is int and monitor['MonitorPid'] > 0 and monitor['MonitorPid'] not in (ack.get('ActorPid'), ui.get('WordPid')) and
            monitor.get('Ready') is True and monitor.get('Stopped') is True and monitor.get('TimedOut') is False and
            monitor.get('SawWordWindow') is True and monitor.get('WordCreationTime') == ui.get('WordCreationTime') and
            type(monitor.get('PollCount')) is int and monitor['PollCount'] > 0 and not monitor.get('Error') and monitor.get('AlertTexts') == [])

def office_steps_match(case):
    spec = workflow_spec(case)
    app = office_app(case)
    prefix = app.lower()
    next_op = 'word-overwrite' if case.get('Kind') == 'WordOverwriteApprove' else prefix + '-edit'
    ops = [spec['Op'], prefix + '-read'] if spec.get('Sensitive') else [spec['Op'], next_op, prefix + '-read']
    acks = case.get('WorkflowAcks') or []
    versions = office_versions(case)
    if (case.get('Error') or case.get('NativeStepsChecked') is not True or case.get('NativeStepsOk') is not True or
            len(acks) != len(ops) or len(versions) != (1 if spec.get('Sensitive') else 2)):
        return False
    numbers = []
    for index, (ack, op) in enumerate(zip(acks, ops)):
        ui = ack.get('Ui') or {}
        path = (case.get('Handback') or {}).get('Path') if spec.get('Sensitive') and op == prefix + '-read' else case['Path']
        if (ack.get('Op') != op or ack.get('Error') or ack.get('ActorSid') != (result or {}).get('ActorSid') or
                ack.get('ActorSid') == 'S-1-5-18' or not ack.get('ActorPid') or type(ack.get('N')) is not int or
                str(ack.get('Path') or '').lower() != str(path or '').lower() or
                ui.get(app + 'Sid') != ack.get('ActorSid') or type(ui.get(app + 'Pid')) is not int or ui[app + 'Pid'] <= 0 or
                type(ui.get(app + 'CreationTime')) is not int or ui[app + 'CreationTime'] <= 0 or
                type(ui.get('SessionId')) is not int or ui['SessionId'] <= 0 or ui.get('Version') != '16.0' or
                (re.fullmatch(r'(?:16\.0\.)?20326(?:\.20232)?', str(ui.get('Build') or '')) is None if app == 'Word' else ui.get('Build') != '20326') or
                any(ui.get(key) is not True for key in ('Saved', 'Ready', 'Closed', 'Quit', app + 'Exited')) or
                ui.get('ReadOnly') is not False or ui.get('ProtectedViewCount') != 0 or ui.get('WindowsAtExit') != [] or
                not isinstance(ui.get('Windows'), list) or len(ui['Windows']) > 1 or ui.get('QuitError') or ui.get('Action') != op):
            return False
        final = index > 0 or spec.get('Sensitive')
        if app == 'Word':
            expected_text = 'T5 Word CPF: 529.982.247-25' if spec.get('Sensitive') else 'T5 ' + case['Kind'] + (' inspected newer save' if final else ' published clean prior')
            if ui.get('Text') != expected_text or not word_alerts_match(case, ack) or (op == 'word-edit' and ui.get('PriorTextVerified') is not True):
                return False
            if op == 'word-overwrite':
                prior = ui.get('OverwritePriorRead') or {}
                if (ui.get('OverwriteRequested') is not True or prior.get('Code') != 0 or prior.get('Steps') != 'read-open=0 read=0 read-close=0' or
                        prior.get('Length') != versions[0].get('SealedLength') or prior.get('Sha256') != versions[0].get('Sha256Hex')):
                    return False
        else:
            expected_a = ('529.982.247-25' if spec.get('Sensitive') else
                          (2 if final else 1) if case['Kind'] == 'ExcelInPlaceApprove' else 'T5 ' + case['Kind'])
            expected_c = 'blocked' if spec.get('Sensitive') else 'edit' if final else 'prior'
            if ui.get('A1') != expected_a or ui.get('B1') != 3 or ui.get('C1') != expected_c or (op == 'excel-edit' and ui.get('PriorCellsVerified') is not True):
                return False
        if op == prefix + '-read':
            read = ack.get('Read') or {}
            if (ack.get('Steps') != prefix + '=0 read-open=0 read=0 read-close=0' or read.get('Code') != 0 or
                    read.get('Length') != versions[-1].get('SealedLength') or read.get('Sha256') != versions[-1].get('Sha256Hex')):
                return False
        elif ack.get('Steps') != prefix + '=0':
            return False
        numbers.append(ack['N'])
    return numbers == sorted(set(numbers))

def office_journal_matches(case):
    spec = workflow_spec(case)
    app = office_app(case)
    versions = office_versions(case)
    records = case.get('Journal') or []
    if (not office_steps_match(case) or case.get('JournalParseErrors') != [] or case.get('JournalSchemaErrors') != [] or
            case.get('FinalJournalOutcomeVerified') is not True or case.get('SettlementStatus') != 'PASS' or
            len({j.get('TransferId') for j in versions}) != len(versions)):
        return False
    if any(not office_record_matches(case, j) or j.get('StageDeleted') is not True or not any(
            j.get('TransferId') == r.get('TransferId') and j.get('Sha256Hex') == r.get('Sha256Hex') and
            j.get('SealedLength') == r.get('SealedLength') and j.get('State') == r.get('State') for r in records) for j in versions):
        return False
    if any(j.get('ProcessId') != case['WorkflowAcks'][i]['Ui'][app + 'Pid'] or
           j.get('RequestorProcessCreationTime') != case['WorkflowAcks'][i]['Ui'][app + 'CreationTime'] for i, j in enumerate(versions)):
        return False
    stages = case.get('StageEvidence')
    if (not isinstance(stages, list) or len(stages) != len(records) or {s.get('TransferId') for s in stages} != {j.get('TransferId') for j in records} or
            any(s.get('Exists') is not False for s in stages)):
        return False
    if spec.get('Sensitive'):
        if any(j.get('State') in ('3', '4', '5') for j in records) or versions[0].get('State') != '6' or versions[0].get('HandbackState') != '2':
            return False
        import pathlib
        handback = case.get('Handback') or {}
        try:
            name = str(handback.get('Artifact') or '').replace('\\', '/').rsplit('/', 1)[-1]
            content = pathlib.Path(raw_dir.removesuffix('-raw') + '-handback-evidence', name).read_bytes()
        except OSError:
            return False
        return (case.get('HandedBack') is True and handback.get('Status') == 'PASS' and
                len(content) == versions[0]['SealedLength'] and hashlib.sha256(content).hexdigest().upper() == versions[0]['Sha256Hex'] and
                case.get('ExpectedHandbackLength') == len(content) and case.get('ExpectedHandbackSha256') == versions[0]['Sha256Hex'] and
                workflow_handback_matches(case, content))
    return (all(j.get('State') == '5' for j in versions) and versions[1]['DestinationGeneration'] > versions[0]['DestinationGeneration'] and
            versions[1]['Sha256Hex'] != versions[0]['Sha256Hex'] and
            case.get('ExpectedLength') == versions[-1]['SealedLength'] and case.get('ExpectedSha256') == versions[-1]['Sha256Hex'])

def office_final_matches(case, samples):
    spec = workflow_spec(case)
    path = (scope_path + '\\' + spec['Leaf']).lower()
    images = [i for i in (samples[-1].get('CurrentImages') or []) if str(i.get('Path') or '').lower() == path] if samples else []
    if len(images) != 1:
        return False
    if spec.get('Sensitive'):
        return (images[0].get('Absent') is True and images[0].get('FileId') is None and images[0].get('LogicalArtifact') is None and
                all(i.get('Absent') is True or i.get('Length') == 0 for s in samples for i in s.get('CurrentImages', []) if str(i.get('Path') or '').lower() == path))
    versions = office_releases(case)
    return (images[0].get('Absent') is False and any(j['Sha256Hex'] == images[0].get('Sha256') == case.get('ExpectedSha256') and
            j['SealedLength'] == images[0].get('Length') == case.get('ExpectedLength') for j in versions))

def approved_public_hash_map():
    approved = {}
    for spec in required_cases:
        payloads = []
        if spec.get('Office'):
            matches = [c for c in ((globals().get('result') or {}).get('Cases') or []) if c.get('Kind') == spec['Kind']]
            approved[spec['Leaf'].lower()] = {j['Sha256Hex'] for c in matches for j in office_releases(c)} if not spec.get('Sensitive') else set()
            continue
        if spec.get('Workflow'):
            if spec['Op'] not in ('explorer-empty', 'empty-copy', 'empty-move', 'shell-copy-in', 'shell-move-in'):
                payloads.append(('T5 ' + spec['Kind'] + ' published clean prior').encode('ascii'))
            if spec['Op'] in ('inflight-before', 'inflight-after', 'notepad-edit', 'shell-copy-in', 'shell-move-in'):
                payloads.append(('T5 ' + spec['Kind'] + ' inspected newer save').encode('ascii'))
        elif not spec.get('Sensitive'):
            payloads.append(('T5 ' + spec['Kind'] + ' clean text').encode('ascii'))
        for leaf in [spec['Leaf'], *spec.get('AuxiliaryLeaves', [])]:
            approved.setdefault(leaf.lower(), set()).update(hashlib.sha256(p).hexdigest().upper() for p in payloads)
    return approved

def workflow_observed_bytes_match(sample):
    allowed = {}
    for spec in required_cases:
        if not spec.get('Workflow'):
            continue
        if spec.get('Office'):
            allowed[spec['Leaf'].lower()] = approved_public_hash_map().get(spec['Leaf'].lower(), set())
            continue
        payloads = []
        if spec['Op'] not in ('explorer-empty', 'empty-copy', 'empty-move', 'shell-copy-in', 'shell-move-in'):
            payloads.append(('T5 ' + spec['Kind'] + ' published clean prior').encode('ascii'))
        if spec['Op'] in ('inflight-before', 'inflight-after', 'notepad-edit', 'shell-copy-in', 'shell-move-in'):
            payloads.append(('T5 ' + spec['Kind'] + ' inspected newer save').encode('ascii'))
        hashes = {hashlib.sha256(payload).hexdigest().upper() for payload in payloads}
        for leaf in [spec['Leaf'], *spec.get('AuxiliaryLeaves', [])]:
            allowed[leaf.lower()] = hashes
    for image in sample.get('CurrentImages') or []:
        leaf = image.get('Path', '').replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if leaf in allowed and image.get('Absent') is False and image.get('Length', 0) > 0 and image.get('Sha256') not in allowed[leaf]:
            return False
    return True

def workflow_spec(case):
    return next((s for s in required_cases if s['Kind'] == case.get('Kind') and s.get('Workflow')), None)

def workflow_expected(case):
    spec = workflow_spec(case)
    prior = ('T5 ' + case['Kind'] + ' published clean prior').encode('ascii')
    newer = ('T5 ' + case['Kind'] + ' inspected newer save').encode('ascii')
    return {'Empty': b'', 'Prior': prior, 'Newer': newer, 'Absent': None}[spec['Expected']]

def workflow_steps_match(case):
    spec = workflow_spec(case)
    if spec and spec.get('Office'):
        return office_steps_match(case)
    if not spec or case.get('Error') or not case.get('NativeStepsChecked') or not case.get('NativeStepsOk'):
        return False
    save = {'open': 0, 'write': 0, 'close': 0}
    sequences = {
        'explorer-empty': [('native-create', save), ('shell-rename-empty', {'shell-rename': 0}), ('second-open-empty', {'second-open': 0})],
        'empty-copy': [('empty-copy', {'copy': 0})],
        'empty-move': [('empty-move', {'move': 0})],
        'native-clear': [('native-create', save), ('native-clear', save)],
        'remove-item': [('native-create', save), ('remove-item', {'remove': 0})],
        'shell-delete': [('native-create', save), ('shell-delete', {'shell-item-hr': 0, 'shell-flags-hr': 0, 'shell-delete-item-hr': 0, 'shell-perform-hr': 0, 'shell-abort-hr': 0, 'shell-aborted': 0})],
        'deny-acl': [('native-create', save), ('native-create', save), ('native-delete', {'delete': 5}), ('native-delete', {'delete': 5})],
        'deny-share': [('native-create', save), ('native-create', save)] +
            [('hold-no-share-delete', {'hold-open': 0}), ('native-delete', {'delete': 32}), ('close-held', {'hold-close': 0})] * 2,
        'inflight-before': [('native-create', save), ('inflight-before', {'hold-open': 0, 'hold-write': 0, 'delete': 32, 'hold-close': 0})],
        'inflight-after': [('native-create', save), ('inflight-after', {'hold-open': 0, 'hold-write': 0, 'hold-close': 0, 'delete': 0})],
        'delete-cpf': [('native-create', save), ('native-delete', {'delete': 0}), ('native-create', save)],
        'native-append': [('native-create', save), ('native-append', {'open': 0, 'seek': 0, 'write': 0, 'close': 0})],
    }
    shell = {'shell-item-hr': 0, 'shell-folder-hr': 0, 'shell-flags-hr': 0, 'shell-transfer-item-hr': 0,
             'shell-perform-hr': 0, 'shell-abort-hr': 0, 'shell-aborted': 0}
    sequences.update({
        'notepad-edit': [('native-create', save), ('notepad-edit', {'notepad-edit': 0})],
        'shell-copy-in': [('shell-copy-in', shell)],
        'shell-move-in': [('shell-move-in', shell)],
        'shell-move-within': [('native-create', save), ('shell-move-within', shell)],
        'native-read': [('native-create', save), ('native-create', save),
                        ('native-read', {'read-open': 0, 'read': 0, 'read-close': 0}), ('native-read', {'read-open': 5})],
    })
    expected = sequences.get(spec['Op'], [])
    acks = case.get('WorkflowAcks') or []
    if len(acks) != len(expected) or not expected:
        return False
    numbers = []
    for ack, (op, codes) in zip(acks, expected):
        if ack.get('Op') != op or ack.get('Error') or type(ack.get('N')) is not int or not ack.get('ActorPid') or ack.get('ActorSid') == 'S-1-5-18':
            return False
        index = len(numbers)
        expected_path = case['Path']
        if spec['Op'] in ('explorer-empty', 'shell-move-within') and index == 0:
            expected_path = scope_path + '\\' + spec['AuxiliaryLeaves'][0]
        if spec['Op'] == 'native-read' and index in (1, 3):
            expected_path = scope_path + '\\' + spec['AuxiliaryLeaves'][0]
        if spec['Op'] in ('deny-acl', 'deny-share'):
            native_indexes = (1, 2) if spec['Op'] == 'deny-acl' else (1, 2, 3, 4)
            if index in native_indexes:
                expected_path = acks[1].get('Path', '')
                if not expected_path.lower().startswith('c:\\t5\\control\\native-'):
                    return False
        if str(ack.get('Path') or '').lower() != expected_path.lower():
            return False
        if ack.get('ActorSid') != (result or {}).get('ActorSid'):
            return False
        numbers.append(ack['N'])
        for name, code in codes.items():
            found = re.findall(r'(?:^|\s)' + re.escape(name) + r'=(-?[0-9]+)', str(ack.get('Steps') or ''))
            if len(found) != 1 or int(found[0]) != code:
                return False
        child = ack.get('Child')
        if op in ('native-delete', 'second-open-empty', 'inflight-before', 'inflight-after'):
            if not isinstance(child, dict) or child.get('Error') or not child.get('Pid') or child['Pid'] == ack['ActorPid'] or child.get('Sid') != ack.get('ActorSid') or str(child.get('Path') or '').lower() != expected_path.lower():
                return False
        if op == 'second-open-empty' and (child.get('Length') != 0 or child.get('FirstByte') != -1 or child.get('ReadWrite') is not True):
            return False
        if op == 'empty-move' and ack.get('SourceGone') is not True:
            return False
        if op == 'empty-copy' and ack.get('SourceLength') != 0:
            return False
        if op in ('shell-rename-empty', 'shell-delete') and not isinstance(ack.get('Ui'), dict):
            return False
        if op == 'notepad-edit':
            ui = ack.get('Ui') or {}
            if (ui.get('DirtyObserved') is not True or ui.get('SaveCompleted') is not True or ui.get('NoPromptClosed') is not True or
                not str(ui.get('OpenedExistingTitle') or '').lower().startswith(spec['Leaf'].lower()) or
                not ui.get('Title') or ui['Title'].startswith('*') or len(ui.get('WindowsAfterSave') or []) != 1 or
                ui.get('WindowsAtExit') != [] or ui.get('MenuPath') not in ('command-save', 'File > Save')):
                return False
        if op in ('shell-copy-in', 'shell-move-in', 'shell-move-within'):
            content = workflow_expected(case)
            read = ack.get('SourceRead') or {}
            if (not isinstance(ack.get('Ui'), dict) or read.get('Code') != 0 or read.get('Length') != len(content) or
                read.get('Sha256') != hashlib.sha256(content).hexdigest().upper() or
                read.get('Steps') != 'read-open=0 read=0 read-close=0'):
                return False
            if op == 'shell-move-within':
                if str(ack.get('Source') or '').lower() != (scope_path + '\\' + spec['AuxiliaryLeaves'][0]).lower():
                    return False
            elif ack.get('SourceInActorTemp') is not True or not ack.get('Source') or str(ack['Source']).lower().startswith(scope_path.lower() + '\\'):
                return False
            if op != 'shell-copy-in' and ack.get('SourceGone') is not True:
                return False
        if op == 'native-read':
            read = ack.get('Read') or {}
            if index == 2:
                content = workflow_expected(case)
                if read.get('Code') != 0 or read.get('Length') != len(content) or read.get('Sha256') != hashlib.sha256(content).hexdigest().upper():
                    return False
            elif read.get('Code') != 5 or read.get('Length') != 0 or read.get('Sha256') is not None or ack.get('Steps') != 'read-open=5':
                return False
    return numbers == sorted(set(numbers))

def workflow_order_matches(case, samples):
    if case.get('Op') == 'shell-move-within':
        spec = workflow_spec(case)
        old = (scope_path + '\\' + spec['AuxiliaryLeaves'][0]).lower()
        images = [i for i in (samples[-1].get('CurrentImages') or []) if i.get('Path', '').lower() == old] if samples else []
        return case.get('OldNameAbsent') is True and case.get('SourceGone') is True and len(images) == 1 and images[0].get('Absent') is True
    if case.get('Op') not in ('inflight-before', 'inflight-after'):
        return True
    proof = case.get('ForcedOrderProof') or {}
    ready = proof.get('ActorReady') or {}
    ack = (case.get('WorkflowAcks') or [{}])[-1]
    before = case['Op'] == 'inflight-before'
    seqs = proof.get('RawSequences') or []
    by_seq = {s.get('Sequence'): s for s in samples}
    if (proof.get('Verified') is not True or proof.get('Op') != case['Op'] or ready.get('Op') != case['Op'] or
        ready.get('N') != ack.get('N') or ready.get('ActorPid') != ack.get('ActorPid') or ready.get('ProbeCreated') is not True or ready.get('WritableProbeHandleHeld') is not before or
        len(seqs) < 2 or len(set(seqs)) != len(seqs) or any(seq not in by_seq for seq in seqs)):
        return False
    expected = ('T5 ' + case['Kind'] + (' published clean prior' if before else ' inspected newer save')).encode('ascii')
    digest = hashlib.sha256(expected).hexdigest().upper()
    for seq in seqs:
        sample = by_seq[seq]
        if (not valid_raw_sample(sample) or not workflow_observed_bytes_match(sample) or sample.get('Phase') != 'ControlProbeAfterTestCreateCloseBeforeDeleteOrSave' or
            type(proof.get('CapturedBeforeGoQpc')) is not int or sample['End']['Qpc'] > proof['CapturedBeforeGoQpc']):
            return False
        images = [i for i in sample['CurrentImages'] if i['Path'].lower() == case['Path'].lower()]
        if len(images) != 1 or images[0].get('Absent') is not False or images[0].get('Length') != len(expected) or images[0].get('Sha256') != digest:
            return False
    last_images = [i for i in by_seq[seqs[-1]]['CurrentImages'] if i['Path'].lower() == case['Path'].lower()]
    if proof.get('Target') != last_images[0]:
        return False
    baseline_ids = {j.get('TransferId') for j in case.get('WorkflowBaseline', [])}
    candidates = [j for j in proof.get('Journal', []) if j.get('IsV20') is True and j.get('ProcessId') == ready.get('ActorPid') and j.get('TransferId') not in baseline_ids and j.get('DestinationPath', '').lower() == case['Path'].lower()]
    for entry in candidates:
        identity = entry.get('StageIdentity')
        if not entry.get('TransferId') or not entry.get('DriverInstanceId') or not isinstance(identity, dict) or any(type(identity.get(k)) is not int or not 0 <= identity[k] < 2**64 for k in ('VolumeSerialNumber', 'FileIdHigh', 'FileIdLow')):
            return False
    if before:
        candidates = [j for j in candidates if j.get('State') in ('0', '8') and j.get('SealedOnce') is False and j.get('SealedLength') is None and j.get('Sha256Hex') is None]
    else:
        candidates = [j for j in candidates if j.get('State') == '5' and j.get('SealedOnce') is True and j.get('Sha256Hex') == digest and j.get('SealedLength') == len(expected)]
    steps = str(ack.get('Steps', ''))
    ordered = (steps.find('delete=') < steps.find('hold-close=')) if before else (steps.find('hold-close=') < steps.find('delete='))
    return len(candidates) == 1 and ordered and proof.get('FinalRawSequence') == seqs[-1]

def workflow_handback_matches(case, content):
    import pathlib
    handback = case.get('Handback') or {}
    digest = hashlib.sha256(content).hexdigest().upper()
    prefix = str((result or {}).get('HandbackDirectory') or '').lower().rstrip('\\') + '\\'
    if not prefix.startswith('c:\\users\\') or not str(handback.get('Path') or '').lower().startswith(prefix):
        return False
    if handback.get('Length') != len(content) or handback.get('Sha256') != digest or handback.get('NewFileCount') != 1:
        return False
    readers = handback.get('Readers') or []
    if len(readers) != 2 or sum(r.get('Unbuffered') is True for r in readers) != 1 or any(r.get('Status') != 'OK' or r.get('Length') != len(content) or r.get('Sha256') != digest for r in readers):
        return False
    name = str(handback.get('Artifact') or '').replace('\\', '/').rsplit('/', 1)[-1]
    try:
        return name == digest + '.bin' and pathlib.Path(raw_dir.removesuffix('-raw') + '-handback-evidence', name).read_bytes() == content
    except OSError:
        return False

def workflow_journal_matches(case):
    spec = workflow_spec(case)
    if spec and spec.get('Office'):
        return office_journal_matches(case)
    records = case.get('Journal')
    if not isinstance(records, list) or (not records and spec['Op'] not in ('explorer-empty', 'shell-move-within')) or case.get('JournalParseErrors') != [] or case.get('JournalSchemaErrors') != []:
        return False
    expected = workflow_expected(case)
    if spec.get('Handback'):
        prior = ('T5 ' + case['Kind'] + ' published clean prior').encode('ascii')
        content = prior + b'\r\nT5 notepad CPF: 529.982.247-25' if spec['Op'] == 'native-append' else b'T5 notepad CPF: 529.982.247-25'
        digest = hashlib.sha256(content).hexdigest().upper()
        if not any(j.get('State') == '6' and j.get('HandbackState') == '2' and j.get('Sha256Hex') == digest and j.get('SealedLength') == len(content) for j in records):
            return False
        if not workflow_handback_matches(case, content):
            return False
        if case.get('ExpectedHandbackLength') != len(content) or case.get('ExpectedHandbackSha256') != digest or case.get('HandedBack') is not True or (case.get('Handback') or {}).get('Status') != 'PASS':
            return False
    if spec['Op'] == 'explorer-empty':
        old = (scope_path + '\\' + spec['AuxiliaryLeaves'][0]).lower()
        seed = [j for snap in case.get('WorkflowJournalSnapshots', []) for j in snap if j.get('DestinationPath', '').lower() == old and j.get('State') == '5' and j.get('StageDeleted') is True and j.get('SealedLength') == 0 and j.get('Sha256Hex') == hashlib.sha256(b'').hexdigest().upper()]
        if not seed:
            return False
    if spec['Op'] in ('shell-move-within', 'native-read'):
        old = (scope_path + '\\' + spec['AuxiliaryLeaves'][0]).lower()
        prior = ('T5 ' + case['Kind'] + ' published clean prior').encode('ascii')
        if not any(j.get('DestinationPath', '').lower() == old and j.get('State') == '5' and j.get('StageDeleted') is True and
                   j.get('SealedLength') == len(prior) and j.get('Sha256Hex') == hashlib.sha256(prior).hexdigest().upper()
                   for snap in case.get('WorkflowJournalSnapshots', []) for j in snap):
            return False
    if spec['Op'] in ('notepad-edit', 'shell-copy-in', 'shell-move-in', 'native-read'):
        baseline_ids = {j.get('TransferId') for j in case.get('WorkflowBaseline', [])}
        if not any(j.get('DestinationPath', '').lower() == case['Path'].lower() and j.get('State') == '5' and
                   j.get('StageDeleted') is True and j.get('TransferId') and
                   (spec['Op'] == 'native-read' or j['TransferId'] not in baseline_ids) and
                   j.get('SealedLength') == len(expected) and j.get('Sha256Hex') == hashlib.sha256(expected).hexdigest().upper()
                   for j in records):
            return False
    if spec['Op'] == 'notepad-edit':
        prior = ('T5 ' + case['Kind'] + ' published clean prior').encode('ascii')
        if not any(j.get('DestinationPath', '').lower() == case['Path'].lower() and j.get('State') == '5' and
                   j.get('StageDeleted') is True and j.get('TransferId') and j.get('SealedLength') == len(prior) and
                   j.get('Sha256Hex') == hashlib.sha256(prior).hexdigest().upper() for j in case.get('WorkflowBaseline', [])):
            return False
    if spec['Op'] == 'native-read':
        fixtures = case.get('Fixtures') or []
        if len(fixtures) != 1 or not all(f.get('Restored') is True and f.get('FileBefore') != f.get('FileDenied') and
                                       f.get('Path', '').lower() == old and f.get('Sid') == (result or {}).get('ActorSid') for f in fixtures):
            return False
    stages = case.get('StageEvidence')
    if not isinstance(stages, list) or len(stages) != len(records) or {s.get('TransferId') for s in stages} != {j.get('TransferId') for j in records}:
        return False
    if any(type(s.get('Exists')) is not bool or (s['Exists'] and (not spec.get('Handback') or type(s.get('Length')) is not int or s['Length'] <= 0)) for s in stages):
        return False
    if expected is not None and spec['Op'] not in ('explorer-empty', 'shell-move-within'):
        if not any(j.get('State') == '5' and j.get('Sha256Hex') == hashlib.sha256(expected).hexdigest().upper() and j.get('SealedLength') == len(expected) for j in records):
            return False
    if spec['Op'] in ('deny-acl', 'deny-share', 'inflight-before'):
        if case.get('NoPrivateCancellation') is not True or any(j.get('UnboundCancellation') is not None or j.get('DiscardRequestedAtUtc') is not None for j in records):
            return False
    if spec['Op'] in ('deny-acl', 'deny-share'):
        code = 5 if spec['Op'] == 'deny-acl' else 32
        if case.get('NativeControlCode') != code or case.get('ProtectedDeleteCode') != code:
            return False
    if spec['Op'] == 'deny-acl':
        fixtures = case.get('Fixtures') or []
        if len(fixtures) != 2 or not all(f.get('Restored') is True and f.get('FileBefore') != f.get('FileDenied') and f.get('ParentBefore') != f.get('ParentDenied') for f in fixtures):
            return False
    return case.get('FinalJournalOutcomeVerified') is True and case.get('SettlementStatus') == 'PASS'

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
    if (workflow_spec(case) or {}).get('Office'):
        return office_final_matches(case, samples)
    if workflow_spec(case):
        expected = workflow_expected(case)
        if expected is None:
            return image.get('Absent') is True and image.get('FileId') is None and image.get('LogicalArtifact') is None
        return (case.get('ExpectedLength') == len(expected) and case.get('ExpectedSha256') == hashlib.sha256(expected).hexdigest().upper() and
                image.get('Absent') is False and image.get('Length') == len(expected) and image.get('Sha256') == case['ExpectedSha256'])
    if case.get('Sensitive') is True:
        return image.get('Absent') is True and image.get('FileId') is None and image.get('LogicalArtifact') is None
    expected_length = case.get('ExpectedLength')
    expected_sha = case.get('ExpectedSha256')
    return (case.get('Sensitive') is False and isinstance(expected_length, int) and expected_length > 0 and
            re.fullmatch(r'[A-Fa-f0-9]{64}', str(expected_sha or '')) is not None and image.get('Absent') is False and
            image.get('Length') == expected_length and image.get('Sha256') == expected_sha)
approved_public_hashes = approved_public_hash_map()
cases = (result or {}).get('Cases') or []
case_acceptance = [raw_samples_accepted(c['RawSamples']) for c in cases if c.get('RawSamples')]  # a case with no samples fails on its own line
superseded_errors = sum(count for _, count in case_acceptance)
raw_schema_ok = (isinstance(raw_samples, list) and len(raw_samples) > 0 and bool(cases) and all(accepted for accepted, _ in case_acceptance) and
                 len({s.get('Sequence') for s in raw_samples if isinstance(s, dict)}) == len(raw_samples))
archive_ok, archive_reason = validate_t5_archives(raw_dir.removesuffix('-raw') + '-journal-evidence', cases)
verdict('T5JournalArchiveEvidence', 'PASS' if archive_ok else 'FAIL', archive_reason)
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
observed_bytes_ok = (raw_ok and all(workflow_observed_bytes_match(s) for s in raw_samples if s.get('Status') == 'OK'))
verdict('T5ObservedNoUnapprovedBytes', 'PASS' if observed_bytes_ok else 'FAIL',
        'all accepted independent raw/public observations contain only exact per-leaf approved payloads; sampled evidence, not a canonical lower-mutation proof')
out.append(f"T5RawErrorsSuperseded INFO {superseded_errors} transient observation error sample(s) superseded by the next valid sample of the same case (owner 2026-10-22); all stay in the result")
verdict('T5RawEvidenceRetained', 'PASS' if raw_artifacts_ok else 'FAIL',
        f"copied={raw_saved}; guest-manifest={re.search(r'^RAW_MANIFEST_PRESENT=True$', after, re.M) is not None}; {raw_artifact_reason}")
expected_case_specs = {c['Kind']: (c['Op'], c['Leaf'], c['Sensitive']) for c in required_cases}
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
                   len(raw_case_samples) > 0 and raw_samples_accepted(raw_case_samples)[0] and
                   c.get('FinalRawMatches') is True and raw_case_final_matches(c, raw_case_samples))
    steps_ok = workflow_steps_match(c) if workflow_spec(c) else native_steps_match(c)
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
    if workflow_spec(c):
        spec = workflow_spec(c)
        order_ok = workflow_order_matches(c, raw_case_samples)
        journal_ok = workflow_journal_matches(c)
        ok = (not c.get('Error') and raw_case_ok and steps_ok and no_empty_leftover and journal_ok and order_ok and
              c.get('WorkflowOutcome') is True and c.get('NoStageLeftover') is True and c.get('Leaked') is False)
        if spec['Op'] in ('explorer-empty', 'shell-move-within'):
            old = (scope_path + '\\' + spec['AuxiliaryLeaves'][0]).lower()
            old_images = [i for i in (raw_case_samples[-1].get('CurrentImages', []) if raw_case_samples else []) if i.get('Path', '').lower() == old]
            ok = ok and c.get('OldNameAbsent') is True and len(old_images) == 1 and old_images[0].get('Absent') is True
        if spec['Op'] == 'delete-cpf':
            ok = ok and c.get('DeleteObservedBeforeBlockedSave') is True
        if spec.get('DeleteBarrier'):
            barrier = c.get('DeleteBarrierVerified') is True and bool(c.get('DeleteBarrierRecords'))
            # The barrier stays a required line of its own (INCONCLUSIVE, so the row cannot pass); the case line reports everything else.
            verdict(name + 'DeleteBarrier', 'PASS' if barrier else 'INCONCLUSIVE', c.get('DeleteBarrierReason') or 'Exact journal delete barrier missing')
        if spec['Op'].startswith('inflight-'):
            verdict(name + 'ForcedOrder', 'PASS' if order_ok else 'FAIL', c.get('OrderingNote') or 'Ordering proof missing')
        verdict(name + 'Journal', 'PASS' if journal_ok else 'FAIL', 'Exact publication/block/denial records and native comparison')
        verdict(name, 'PASS' if ok else 'FAIL', detail + '; error=' + str(c.get('Error')) + '; method=' + str(c.get('Method')))
        continue
    if c.get('Sensitive'):
        ok = not c.get('Error') and raw_case_ok and steps_ok and c.get('HandedBack') is True and c.get('Leaked') is False and c.get('FinalRawMatches') is True and no_empty_leftover and journal_outcome
        detail += f"; handback={((c.get('Handback') or {}).get('Status'))}; leaked={c.get('Leaked')}"
    else:
        ok = not c.get('Error') and raw_case_ok and steps_ok and c.get('Published') is True and c.get('FinalSha256') == c.get('ExpectedSha256') and no_empty_leftover and journal_outcome
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
registry_outcome, registry_detail = writer_registry_verdict(after)
verdict('T5WriterRegistryKnown', registry_outcome, registry_detail)
try: staging_listing = open(sys.argv[11], encoding='utf-8', errors='replace').read()
except Exception: staging_listing = ''
staging_outcome, staging_detail = staging_empty_verdict(staging_listing)
verdict('T5StagingEmptyAfterRun', staging_outcome, staging_detail)
journal_outcome_after, journal_detail_after = journal_settled_verdict(staging_listing)
verdict('T5JournalSettledAfterRun', journal_outcome_after, journal_detail_after)
for r in ((result or {}).get('Ring') or [])[-25:]:
    out.append(f"T5DenyRing INFO {r[:400]}")
if os.environ.get('T5_STAGE_SPACE_EFFECTIVE') == 'off':
    out.append('T5StageSpaceConfig INFO T5_STAGE_SPACE=off sets Enabled=false only, preserving package FloorOnly (MVP defaults Enabled=false, FloorOnly=true)')
out.append(f"T5Duration INFO {elapsed} s ({mode})")
open(verdict_path, 'w').write('\n'.join(out) + '\n')
print('\n'.join(out))
sys.exit(0 if raw_verdict == 'PASS' and all((' PASS ' in line or ' INFO ' in line) for line in out if not line.startswith('T5Duration INFO')) else 1)
PY
