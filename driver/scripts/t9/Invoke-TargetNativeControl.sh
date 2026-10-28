#!/usr/bin/env bash
# Native mechanism evidence only; never installs/loads a driver or qualifies a pair.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
usage() { echo 'Usage: Invoke-TargetNativeControl.sh [--dry-run] <label> <commit> [--dry-run]' >&2; exit 2; }
stop() { echo "STOP: $*" >&2; exit 1; }
dry=false
args=()
for arg in "$@"; do
    case "$arg" in --dry-run) dry=true;; *) args+=("$arg");; esac
done
[ "${#args[@]}" -eq 2 ] || usage
label=${args[0]}; requested_commit=${args[1]}
[[ "$label" =~ ^[A-Za-z0-9]{3,30}$ ]] || usage
dom=${SAFEUPLOAD_DEBUGGEE:-}
[ "$dom" = win10-debug3 ] || stop 'set SAFEUPLOAD_DEBUGGEE=win10-debug3 explicitly (only approved target)'
commit=$(git rev-parse --verify --end-of-options "$requested_commit^{commit}") || stop 'invalid source commit'
ev="driver/evidence/$(date +%F)/t9-target-$label"
[ ! -e "$ev" ] && [ ! -L "$ev" ] || stop "evidence already exists: $ev"
control=driver/scripts/t9/native-store-mechanism-control.ps1
baseline_script=driver/scripts/Get-StagedBaseline.ps1
for file in "$control" "$baseline_script"; do
    git cat-file -e "$commit:$file" || stop "missing committed input: $file"
done
control_sha=$(git show "$commit:$control" | sha256sum | cut -d' ' -f1)
host=$(awk -v d="$dom" '$1==d{print $2}' driver/scripts/debuggees.txt)
[ "$host" = 192.168.122.52 ] || stop 'target inventory differs; inspect before running'
if $dry; then
    printf 'DryRun=True\nCommit=%s\nControlSHA256=%s\nEvidence=%s\n' "$commit" "$control_sha" "$ev"
    cat <<'PLAN'
Require both builder-run.sh locks free; hold both through all cleanup.
Require win10-debug2 and win10-debug3 shut off; refuse an existing run state.
For actor, then admin (stop on the first failure):
  Fresh disposable overlay via run-disk.sh; EFI reset, no TPM.
  Independent Get-StagedBaseline.ps1: BaselineClean=True; pinned UUID.
  Record boot ID, OS 19045.2965, installed driver identity/hash, fltmc/sc query.
  Require the original SafeUpload driver stopped and unloaded; no kernel install.
  Stage committed control; verify SHA256 and parse with Windows PowerShell 5.1.
  Actor: guest-generated secret, Users-only t5actor, one-boot autologon;
  reboot (300 s monotonic bound), re-inventory, unique Explorer (180 s),
  then run a limited interactive scheduled task. Never print/export the secret.
  Admin: native powershell.exe child of the admin remote-shell subject.
  Collect JSONL, stderr, child exit receipt, token/session and boot receipts.
  Host requires PASS, ExpectedOS=19045.2965, 32 replacement/48 allocation,
  7 Held faults/8 retained-charge inventories/1 native release proof.
  Capture failures before discarding the overlay via run_disk_end.
  Independently boot a fresh restoration overlay, check BaselineClean=True,
  then discard it too, verifying base/XML/deletion receipts. Never boot the base.
No retry, builder/VM contact, evidence directory or lock acquisition in dry-run.
PLAN
    exit 0
fi

# Same locks as ~/Work/safeupload-tools/builder-run.sh. Never wait behind work
# and never release the locks between the control and its restoration check.
locks=/home/victor/Work/safeupload-tools/builder-locks
exec {builder1_fd}<"$locks/builder1.lock" || stop 'builder1 lock missing/unreadable'
flock -n -x "$builder1_fd" || stop 'builder1 busy; run only with both builders idle'
exec {builder2_fd}<"$locks/builder2.lock" || stop 'builder2 lock missing/unreadable'
flock -n -x "$builder2_fd" || stop 'builder2 busy; run only with both builders idle'
V='virsh -c qemu:///system'
source driver/scripts/image-store.sh
source driver/scripts/run-disk.sh
[ ! -e "$RUN_DISK_STATE/$dom" ] || stop 'prior run state remains; inspect/park it first'
for peer in win10-debug2 "$dom"; do
    [ "$($V domstate "$peer")" = 'shut off' ] || stop "$peer must be shut off before starting"
done
mkdir -p "$(dirname "$ev")"
mkdir "$ev" || stop 'cannot reserve fresh evidence directory'
git show "$commit:$control" > "$ev/control.ps1"
git show "$commit:$baseline_script" > "$ev/baseline.ps1"
printf 'Commit=%s\nControlSHA256=%s\nDomain=%s\nHost=%s\n' "$commit" "$control_sha" "$dom" "$host" > "$ev/inputs.txt"
sha256sum "$ev/"*.ps1 driver/scripts/{run-disk.sh,image-store.sh,remote_ps.py} "${BASH_SOURCE[0]}" driver/scripts/t9/native_control_verdict.py >> "$ev/inputs.txt"
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=yes)
# The control launches get a longer transport bound (REMOTE_TIMEOUT); everything else keeps 420 s.
remote() { timeout "${REMOTE_TIMEOUT:-420}" python3 driver/scripts/remote_ps.py "$host"; }
monotonic() { python3 -c 'import time; print(int(time.monotonic()))'; }
wait_up() {
    local deadline
    deadline=$(( $(monotonic) + 300 ))
    while (( $(monotonic) < deadline )); do
        timeout 15 python3 driver/scripts/remote_ps.py "$host" <<<'"up"' >/dev/null 2>&1 && return 0
        sleep 5
    done
    return 1
}
# Same text/CLIXML decoding as Invoke-StageMoves.sh; keep raw transport too.
decode() { python3 -c '
import html,re,sys
s=sys.stdin.read()
errors=["ERROR: "+html.unescape(x).replace("_x000D__x000A_", "\n") for x in re.findall(r"<S S=\"Error\">(.*?)</S>",s,re.S)]
s=re.sub(r"<Objs.*?</Objs>","",s,flags=re.S).replace("#< CLIXML", "").replace("\r", "")
print("\n".join(x for x in s.splitlines()+errors if x.strip()))
'; }
call() { # Evidence stem; stdin is PowerShell. Transport failure never means PASS.
    local stem=$1 rc=0
    remote > "$stem.raw" 2>&1 || rc=$?
    decode < "$stem.raw" > "$stem.txt"
    printf '%s\n' "$rc" > "$stem.transport-exit.txt"
    [ "$rc" -eq 0 ]
}
baseline() {
    local stem=$1
    timeout 300 scp "${opts[@]}" "$ev/baseline.ps1" "vika@$host:C:/Users/vika/Documents/t9-baseline.ps1" > "$stem-copy.txt" 2>&1 || return 1
    call "$stem" <<'PS' || return 1
'BootId=' + (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
& 'C:\Users\vika\Documents\t9-baseline.ps1'
PS
    python3 - "$stem.txt" <<'PY'
import pathlib,sys
s=pathlib.Path(sys.argv[1]).read_text().splitlines()
assert [x for x in s if x.startswith('BaselineClean=')]==['BaselineClean=True'], 'Baseline not clean'
assert 'UUID=FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3' in s, 'Unexpected target UUID'
PY
}
inventory() {
    call "$1" <<'PS' || { cat "$1.txt" >&2; return 1; }
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = $os.BuildNumber + '.' + $cv.UBR
'OSBuild=' + $build
'BootId=' + $os.LastBootUpTime.ToUniversalTime().ToString('o')
$driver = Get-Item -LiteralPath 'C:\Windows\System32\drivers\SafeUpload.sys'
$hash = (Get-FileHash -LiteralPath $driver.FullName -Algorithm SHA256).Hash
[pscustomobject]@{Kind='InstalledDriver';Path=$driver.FullName;SHA256=$hash;Version=$driver.VersionInfo.FileVersion;Length=$driver.Length} | ConvertTo-Json -Compress
$service = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'"
$service | Select-Object Name,PathName,State,Started,StartMode | ConvertTo-Json -Compress
$filters = & fltmc.exe filters 2>&1 | Out-String; $fc = $LASTEXITCODE
$query = & sc.exe query SafeUpload 2>&1 | Out-String; $sc = $LASTEXITCODE
$filters; 'FltmcExit=' + $fc; $query; 'ScQueryExit=' + $sc
if ($build -cne '19045.2965') { throw ('STOP: OS must equal 19045.2965; observed ' + $build) }
if ($hash -cne 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE' -or
    $fc -ne 0 -or $sc -ne 0 -or $filters -match '(?im)^SafeUpload\S*\s' -or
    $null -eq $service -or $service.State -ne 'Stopped' -or $service.Started) { throw 'STOP: original driver identity/stopped/unloaded precondition failed' }
'NativePreconditions=True'
PS
    if ! grep -qx 'NativePreconditions=True' "$1.txt"; then
        cat "$1.txt" >&2
        return 1
    fi
}
failure_capture() { # Best effort, adapted from Invoke-StagedSuiteBatch.sh.
    local out="$ev/$active_tag-failure"
    { $V domstate "$dom" --reason; $V dominfo "$dom"; } > "$out-domstate.txt" 2>&1 || true
    $V screenshot "$dom" "$out-screen.png" >/dev/null 2>&1 || true
    if wait_up; then
        call "$out-guest" <<'PS' || true
$ErrorActionPreference = 'Continue'
'BootId=' + (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddHours(-3);Id=41,1001,6008,1074,6005,6006,7031,7034,7023} -ErrorAction SilentlyContinue | Format-List TimeCreated,Id,Message
Get-ChildItem C:\Windows\Minidump -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTimeUtc
Get-Item C:\Windows\MEMORY.DMP -ErrorAction SilentlyContinue | Select-Object Length,LastWriteTimeUtc
PS
        timeout 300 scp "${opts[@]}" -r "vika@$host:C:/T9Native-$label" "$out-artifacts" > "$out-copy.txt" 2>&1 || true
        timeout 300 scp "${opts[@]}" -r "vika@$host:C:/Windows/Minidump" "$out-minidump" >/dev/null 2>&1 || true
    fi
}
active_tag=''; needs_restoration=false; discard_attempted=false
discard() {
    discard_attempted=true
    run_disk_end "$dom" "$active_tag" >> "$ev/$active_tag-disk.txt" 2>&1 || return 1
    for receipt in RunDiskBaseUntouched RunDiskXmlUnchanged RunDiskOverlayDeleted; do
        grep -qx "$receipt=True" "$ev/$active_tag-disk.txt" || return 1
    done
    active_tag=''
}
begin() {
    active_tag=$1
    discard_attempted=false
    # Set before begin so a partial overlay/repoint/start also reaches cleanup.
    run_disk_begin "$dom" "$active_tag" >> "$ev/$active_tag-disk.txt" 2>&1 || return 1
    wait_up
}
restore_check() {
    needs_restoration=false
    begin "${label}restore$subject" || return 1
    baseline "$ev/$active_tag-baseline" || return 1
    python3 - "$ev/$subject-baseline.txt" "$ev/$active_tag-baseline.txt" <<'PY' || return 1
import pathlib,sys
def audit(path):
    lines=pathlib.Path(path).read_text().splitlines()
    return [[x for x in lines if x.startswith(k+'=')] for k in ('ProcessCreationAuditFlags','ProcessCreationAuditPerUserCount')]
a,b=map(audit,sys.argv[1:])
assert all(len(x)==1 for x in a+b) and a==b, 'Independent audit restoration mismatch'
PY
    discard
}
finish() {
    local rc=$?
    trap - EXIT INT TERM
    set +e
    if [ "$rc" -ne 0 ] && [ -n "$active_tag" ]; then failure_capture; fi
    if [ -n "$active_tag" ] && ! $discard_attempted && [ -f "$RUN_DISK_STATE/$dom" ]; then
        discard || { echo 'STOP: run disk cleanup failed; inspect retained run state'; rc=1; }
    fi
    if $needs_restoration && [ -z "$active_tag" ]; then
        restore_check || { echo 'STOP: independent restoration failed'; rc=1; }
        if [ -n "$active_tag" ] && ! $discard_attempted && [ -f "$RUN_DISK_STATE/$dom" ]; then
            failure_capture
            discard || rc=1
        fi
    fi
    [ "$rc" -eq 0 ] || echo "STOP: preserve $ev; no automatic retry"
    printf 'TargetNativeControl=%s\n' "$([ "$rc" -eq 0 ] && echo PASS || echo FAIL)" > "$ev/result.txt"
    exit "$rc"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cat > "$ev/subject.ps1" <<'PS'
param([ValidateSet('actor','admin')][string]$Subject,[string]$ExpectedHash)
$ErrorActionPreference = 'Stop'
$d = $PSScriptRoot
$code = 1
try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8) { throw 'Requires native x64 Windows PowerShell 5.1' }
    if ((Get-FileHash -LiteralPath "$d\control.ps1" -Algorithm SHA256).Hash -ine $ExpectedHash) { throw 'Control hash mismatch' }
    $tokens=$null; $errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile("$d\control.ps1",[ref]$tokens,[ref]$errors)
    if ($errors.Count) { throw ($errors | Out-String) }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $session = (Get-Process -Id $PID).SessionId
    if ($Subject -eq 'actor' -and ($admin -or $session -le 0 -or $identity.Name -ine "$env:COMPUTERNAME\t5actor")) { throw 'Wrong interactive standard actor' }
    if ($Subject -eq 'admin' -and (-not $admin -or $identity.Name -ine "$env:COMPUTERNAME\vika")) { throw 'Wrong admin remote-shell subject' }
    [pscustomobject]@{Subject=$Subject;User=$identity.Name;SID=$identity.User.Value;Admin=$admin;Session=$session;PID=$PID;BootId=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');Parser='5.1 PASS';SHA256=$ExpectedHash} |
        ConvertTo-Json -Compress | Set-Content -LiteralPath "$d\$Subject-subject.json" -Encoding UTF8
    & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -File "$d\control.ps1" -ExpectedOS 19045.2965 -ProgressPath "$d\$Subject-progress.txt" 2> "$d\$Subject-stderr.txt" |
        Set-Content -LiteralPath "$d\$Subject.jsonl" -Encoding UTF8
    $code = $LASTEXITCODE
} catch {
    $_ | Out-String | Set-Content -LiteralPath "$d\$Subject-wrapper-error.txt" -Encoding UTF8
} finally {
    [string]$code | Set-Content -LiteralPath "$d\$Subject-exit.txt" -Encoding ASCII
}
exit $code
PS

verdict() {
    python3 - "$ev" "$subject" "$control_sha" <<'PY'
import json,pathlib,sys
sys.path.insert(0, "driver/scripts/t9")
from native_control_verdict import validate
root,subject,sha=pathlib.Path(sys.argv[1]),sys.argv[2],sys.argv[3].upper()
def read(name): return (root/name).read_text(encoding='utf-8-sig').strip()
def one(rows,kind):
    values=[r for r in rows if r.get('Kind')==kind]
    assert len(values)==1, 'Missing/duplicate '+kind
    return values[0]
assert read(subject+'-exit.txt')=='0', 'Unexpected child exit code'
if (root/(subject+'-wrapper-error.txt')).exists():
    assert not read(subject+'-wrapper-error.txt'), 'Wrapper error'
err=(root/(subject+'-stderr.txt')).read_bytes()
assert not err.decode('utf-16' if err.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig').strip(), 'Control stderr'
lines=read(subject+'.jsonl').splitlines()
assert [l for l in lines if l.startswith('NativeStoreMechanism=')]==['NativeStoreMechanism=PASS'], 'Missing/failed summary'
rows=[json.loads(l) for l in lines if not l.startswith('NativeStoreMechanism=')]
assert all(isinstance(r,dict) for r in rows), 'Malformed JSON receipt'
v=validate(rows,'19045.2965',sha)
assert v['Verdict']=='PASS' and not v['FirstDifference'] and v['LabStop'] is False and v['TargetBaselineMatches'] is True, 'Failed JSON verdict'
assert v['ReplacementRows']==32 and v['AllocationRows']==48, 'Incomplete coverage'
assert sum(r.get('Kind')=='ReplacementResult' for r in rows)==32, 'Missing replacement receipts'
assert sum(r.get('Kind')=='AllocationResult' for r in rows)==48, 'Missing allocation receipts'
assert not any(r.get('Kind') in ('Error','Fatal') or r.get('Comparison')=='DIFFERS' for r in rows), 'Native failure'
s=one(rows,'Script'); t=one(rows,'Token'); e=one(rows,'Environment')
assert s['SHA256']==sha and s['PSVersion'].startswith('5.1.') and s['ProcessBits']==64, 'Script/runtime mismatch'
assert e['OS']=='10.0.19045.2965' and e['TargetBaselineMatches'] is True and e['ExpectBuilderTable'] is True, 'Wrong environment/mode'
p=json.loads(read(subject+'-subject.json'))
assert p['Subject']==subject and p['SHA256'].upper()==sha and p['Parser']=='5.1 PASS', 'Wrong subject receipt'
assert t['SID']==p['SID'] and t['User']==p['User'], 'Child subject mismatch'
if subject=='actor':
    assert read('actor-task-exit.txt')=='0', 'Unexpected scheduled-task exit'
    assert p['Session']>0 and p['Admin'] is False and t['Elevated'] is False and t['IntegrityRID']==8192, 'Not standard interactive actor'
    assert p['Session']==int(read('actor-session.txt').split('ACTOR_SESSION=')[-1]), 'Interactive session differs'
else:
    assert [l for l in read('admin-launch.txt').splitlines() if l.startswith('AdminWrapperExit=')]==['AdminWrapperExit=0'], 'Unexpected admin wrapper exit'
    assert p['Admin'] is True and t['Elevated'] is True and t['IntegrityRID']==12288, 'Not elevated admin'
    actor=json.loads(read('actor-subject.json'))
    assert t['SID']!=actor['SID'], 'Subjects must differ'
def boot(name):
    values=[l[7:] for l in read(name).splitlines() if l.startswith('BootId=')]
    assert len(values)==1, 'Missing/duplicate boot ID'
    return values[0]
assert p['BootId']==boot(subject+'-before.txt')==boot(subject+'-after.txt'), 'Boot changed during control'
if subject=='actor':
    assert p['BootId']==boot('actor-post-reboot.txt') and p['BootId']!=boot('actor-initial.txt'), 'Control must use post-sign-in reboot'
else:
    assert p['BootId']==boot('admin-initial.txt'), 'Unexpected admin reboot'
print('NativeStoreMechanism=PASS;Subject='+subject+';HostValidated=True')
PY
}

for subject in actor admin; do
    needs_restoration=true
    begin "$label$subject" || stop "$subject overlay/boot failed"
    baseline "$ev/$subject-baseline" || stop "$subject fresh baseline is not clean"
    inventory "$ev/$subject-initial" || stop "$subject OS/driver precondition failed (see inventory)"
    if [ "$subject" = actor ]; then
        call "$ev/actor-provision" <<'PS' || stop 'actor provisioning failed'
$ErrorActionPreference = 'Stop'
$name = 't5actor'
if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { throw 'Actor already exists on clean overlay' }
$password = 'T9!' + [guid]::NewGuid().ToString('N')
New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires -PasswordNeverExpires | Out-Null
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name
$actorSid = (Get-LocalUser -Name $name).SID.Value
$groups = @(Get-LocalGroup | Where-Object { @(Get-LocalGroupMember -SID $_.SID | Where-Object { $_.SID.Value -eq $actorSid }).Count -gt 0 })
if ($groups.Count -ne 1 -or $groups[0].SID.Value -ne 'S-1-5-32-545') { throw 'Actor must belong only to Users' }
$key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($v in @{ AutoAdminLogon='1'; DefaultUserName=$name; DefaultDomainName=$env:COMPUTERNAME; DefaultPassword=$password }.GetEnumerator()) {
    New-ItemProperty -LiteralPath $key -Name $v.Key -Value $v.Value -PropertyType String -Force | Out-Null
}
New-ItemProperty -LiteralPath $key -Name AutoLogonCount -Value 1 -PropertyType DWord -Force | Out-Null
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE' -Name DisablePrivacyExperience -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableFirstLogonAnimation -Value 0 -PropertyType DWord -Force | Out-Null
Remove-Variable password
'ActorProvisioned=True'
PS
        grep -qx 'ActorProvisioned=True' "$ev/actor-provision.txt" || stop 'missing actor provisioning receipt'
        old_boot=$(sed -n 's/^BootId=//p' "$ev/actor-initial.txt")
        [ -n "$old_boot" ] || stop 'missing initial boot ID'
        call "$ev/actor-reboot" <<'PS' || stop 'actor reboot request failed'
& shutdown.exe /r /t 5 /c "T9 native control actor sign-in"
if ($LASTEXITCODE -ne 0) { throw 'Reboot refused' }
'RebootRequested=True'
PS
        grep -qx 'RebootRequested=True' "$ev/actor-reboot.txt" || stop 'missing reboot receipt'
        deadline=$(( $(monotonic) + 300 )); attempt=0; rebooted=false
        while (( $(monotonic) < deadline )); do
            attempt=$((attempt + 1))
            # Keep every probe, including transport failures. The guest wall
            # clock is not the deadline; only a changed boot ID admits readiness.
            stem="$ev/actor-reboot-probe-$attempt"
            rc=0
            timeout 15 python3 driver/scripts/remote_ps.py "$host" <<'PS' > "$stem.raw" 2>&1 || rc=$?
'BootId=' + (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
PS
            decode < "$stem.raw" > "$stem.txt"
            printf '%s\n' "$rc" > "$stem.transport-exit.txt"
            new_boot=$(sed -n 's/^BootId=//p' "$stem.txt")
            if [ "$rc" -eq 0 ] && [ -n "$new_boot" ] && [ "$new_boot" != "$old_boot" ]; then rebooted=true; break; fi
            sleep 2
        done
        $rebooted || stop 'actor reboot did not return with a new boot ID within 300 monotonic seconds'
        inventory "$ev/actor-post-reboot" || stop 'post-reboot OS/driver precondition failed'
        call "$ev/actor-ready" <<'PS' || stop 't5actor did not sign in within 180 s'
$ErrorActionPreference = 'Stop'
$sw = [Diagnostics.Stopwatch]::StartNew()
do {
    $desktops = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { (Invoke-CimMethod -InputObject $_ -MethodName GetOwner).User -eq 't5actor' })
    if ($desktops.Count -eq 1 -and $desktops[0].SessionId -gt 0) { 'ActorReady=True'; exit 0 }
    Start-Sleep -Seconds 2
} while ($sw.Elapsed.TotalSeconds -lt 180)
throw 'No unique interactive t5actor desktop; STOP'
PS
        grep -qx 'ActorReady=True' "$ev/actor-ready.txt" || stop 'missing interactive actor readiness receipt'
    fi
    guest="C:/T9Native-$label"
    call "$ev/$subject-stage" <<PS || stop 'guest staging failed'
\$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath '$guest') { throw 'Guest evidence directory exists' }
New-Item -ItemType Directory -Path '$guest' | Out-Null
& icacls.exe '$guest' /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
if (\$LASTEXITCODE -ne 0) { throw 'Actor staging ACL failed' }
PS
    for file in control.ps1 subject.ps1; do
        timeout 300 scp "${opts[@]}" "$ev/$file" "vika@$host:$guest/$file" > "$ev/$subject-$file-copy.txt" 2>&1 || stop 'script upload failed'
    done
    call "$ev/$subject-parse" <<PS || stop 'guest hash/parser gate failed'
\$ErrorActionPreference = 'Stop'
if (\$PSVersionTable.PSVersion.Major -ne 5 -or \$PSVersionTable.PSVersion.Minor -ne 1) { throw 'Parser must be Windows PS 5.1' }
if ((Get-FileHash -LiteralPath '$guest/control.ps1' -Algorithm SHA256).Hash -ine '$control_sha') { throw 'Committed control hash mismatch' }
foreach (\$file in @('$guest/control.ps1','$guest/subject.ps1')) {
    \$tokens=\$null; \$errors=\$null
    [void][Management.Automation.Language.Parser]::ParseFile(\$file,[ref]\$tokens,[ref]\$errors)
    if (\$errors.Count) { throw (\$errors | Out-String) }
}
'GuestHashAndParse=True'
PS
    grep -qx 'GuestHashAndParse=True' "$ev/$subject-parse.txt" || stop 'missing parser/hash receipt'
    inventory "$ev/$subject-before" || stop 'pre-control OS/driver gate failed'
    if [ "$subject" = actor ]; then
        # Liveness bound only (no timing assertion): nu406t1 timed out at 300 s on a first-logon actor
        # profile with no progress trace; the control now streams per-case progress and the bound is 15 min.
        REMOTE_TIMEOUT=1080 call "$ev/actor-launch" <<PS || stop 'interactive task failed/timed out'
\$ErrorActionPreference = 'Stop'
\$explorers = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object { (Invoke-CimMethod -InputObject \$_ -MethodName GetOwner).User -eq 't5actor' })
if (\$explorers.Count -ne 1 -or \$explorers[0].SessionId -le 0) { throw 'Requires exactly one signed-in t5actor desktop; prepare with existing lab tools' }
('ACTOR_SESSION=' + \$explorers[0].SessionId) | Set-Content -LiteralPath '$guest/actor-session.txt' -Encoding ASCII
\$principal = New-ScheduledTaskPrincipal -UserId "\$env:COMPUTERNAME\t5actor" -LogonType Interactive -RunLevel Limited
\$action = New-ScheduledTaskAction -Execute "\$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File $guest/subject.ps1 -Subject actor -ExpectedHash $control_sha'
\$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
Register-ScheduledTask -TaskName 'T9Native-$label' -Principal \$principal -Action \$action -Settings \$settings | Out-Null
Start-ScheduledTask -TaskName 'T9Native-$label'
\$sw = [Diagnostics.Stopwatch]::StartNew()
while (\$sw.Elapsed.TotalSeconds -lt 930 -and (-not (Test-Path -LiteralPath '$guest/actor-exit.txt') -or (Get-ScheduledTask -TaskName 'T9Native-$label').State -eq 'Running')) { Start-Sleep -Seconds 1 }
if (-not (Test-Path -LiteralPath '$guest/actor-exit.txt') -or (Get-ScheduledTask -TaskName 'T9Native-$label').State -eq 'Running') {
    Get-CimInstance Win32_Process | Where-Object { \$_.Name -match '^(powershell|csc|cvtres|MsMpEng|conhost)\.exe\$' } |
        Select-Object Name,ProcessId,ParentProcessId,SessionId,CreationDate,KernelModeTime,UserModeTime,WorkingSetSize,CommandLine |
        Format-List | Out-File -LiteralPath '$guest/actor-timeout-processes.txt' -Encoding UTF8
    throw 'Actor timed out; STOP'
}
([string](Get-ScheduledTaskInfo -TaskName 'T9Native-$label').LastTaskResult) | Set-Content -LiteralPath '$guest/actor-task-exit.txt' -Encoding ASCII
Get-ScheduledTaskInfo -TaskName 'T9Native-$label' | Format-List *
'ActorCompleted=True'
PS
        grep -qx 'ActorCompleted=True' "$ev/actor-launch.txt" || stop 'missing actor completion receipt'
    else
        # A failed child is collected before the host verdict stops the sequence.
        REMOTE_TIMEOUT=1080 call "$ev/admin-launch" <<PS || stop 'admin transport failed'
& powershell.exe -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -File '$guest/subject.ps1' -Subject admin -ExpectedHash '$control_sha'
'AdminWrapperExit=' + \$LASTEXITCODE
PS
    fi
    timeout 300 scp "${opts[@]}" -r "vika@$host:$guest" "$ev/$subject-collected" > "$ev/$subject-collect.txt" 2>&1 || stop 'receipt collection failed'
    cp "$ev/$subject-collected/""$subject"* "$ev/"
    inventory "$ev/$subject-after" || stop 'post-control OS/driver gate failed'
    verdict > "$ev/$subject-verdict.txt" 2>&1 || stop "$subject control failed/missing/DIFFERS (see receipts)"
    discard || stop 'run disk discard failed'
    restore_check || stop 'independent restoration failed'
done
