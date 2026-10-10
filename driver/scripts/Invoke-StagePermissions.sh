#!/usr/bin/env bash
# T10: permission and owner changes reach the real file or folder. On a debuggee in a disposable run disk (run-disk.sh, always deleted
# afterwards; the base disk is never written): phase A, the administrator (the harness account, over ssh) changes permissions and the
# owner of a protected file and of the protected folder with icacls, takeown and Set-Acl while the driver is loaded; phase B, a SYSTEM
# coordinator and a standard user (t10/) check that the private stage keeps its security descriptors while an administrator changes
# the real file's ACL during a version in progress, and that a permission change never lets the standard user publish CPF bytes.
#
# Usage: driver/scripts/Invoke-StagePermissions.sh <debuggee domain> <tag> <driver.sys> <agent zip> [ordinary|runtime-verifier|boot-verifier]
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
export SAFEUPLOAD_MIN_FREE_GB=${T10_MIN_FREE_GB:-15}
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
        echo 'T10Restoration=FAIL'
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
scp "${opts[@]}" "$sys" "vika@$host:$guest/SafeUpload-t10.sys" && scp "${opts[@]}" "$zip" "vika@$host:$guest/stage-service-publish.zip" \
  && scp "${opts[@]}" agente/scripts/Install-SafeUploadAgent.ps1 "vika@$host:$guest/Install-SafeUploadAgent.ps1" \
  && scp "${opts[@]}" agente/scripts/Protect-SafeUploadPolicy.ps1 "vika@$host:$guest/Protect-SafeUploadPolicy.ps1" \
  && scp "${opts[@]}" agente/scripts/Get-SafeUploadDiagnostics.ps1 "vika@$host:$guest/Get-SafeUploadDiagnostics.ps1" \
  && scp "${opts[@]}" driver/scripts/t10/permissions-actor.ps1 "vika@$host:$guest/t10-permissions-actor.ps1" \
  && scp "${opts[@]}" driver/scripts/t10/permissions-coordinator.ps1 "vika@$host:$guest/t10-permissions-coordinator.ps1" || { echo 'copy failed'; exit 14; }
remote <<'PS' | tee "$ev/$tag-install.txt"
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
$agentDir = 'C:\Program Files\SafeUpload\Agent'
New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
Expand-Archive -LiteralPath "$d\stage-service-publish.zip" -DestinationPath $agentDir -Force
Copy-Item -LiteralPath "$d\SafeUpload-t10.sys" -Destination 'C:\Windows\System32\drivers\SafeUpload.sys' -Force
New-Item -ItemType Directory -Force -Path 'C:\Protected' | Out-Null
& icacls.exe 'C:\Protected' /grant 'BUILTIN\Users:(OI)(CI)M' | Out-Null
# The destination folder must exist before the driver loads: staging never creates a directory inside a protected folder.
New-Item -ItemType Directory -Force -Path 'C:\Protected\t10' | Out-Null
# Two files that exist before protection starts: one for the administrator's changes, one for the standard user's.
[IO.File]::WriteAllText('C:\Protected\t10\admin.txt', "T10 admin file clean`r`n")
[IO.File]::WriteAllText('C:\Protected\t10\existing.txt', "T10 existing file clean`r`n")
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
remote <<<'& shutdown.exe /r /t 5 /c "T10 install"' >/dev/null; sleep 60; wait_ssh || { echo 'guest did not return'; exit 17; }
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

echo "== phase A: the administrator changes permissions and owner"
remote <<'PS' | tee "$ev/$tag-admin.txt"
$ErrorActionPreference = 'Continue'
$f = 'C:\Protected\t10\admin.txt'; $dir = 'C:\Protected\t10'
function Step([string]$Name, [scriptblock]$Do, [scriptblock]$Verify) {
    $out = (& $Do 2>&1 | Out-String); $code = $LASTEXITCODE
    $ok = ($code -eq 0 -or $null -eq $code) -and [bool](& $Verify)
    $Name + '=' + $ok + ' exit=' + $code + ' ' + ($out -replace '\s+', ' ')
}
'ADMIN_IDENTITY=' + [Security.Principal.WindowsIdentity]::GetCurrent().Name + ' admin=' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Step 'ADMIN_FILE_GRANT' { icacls.exe $f /grant '*S-1-5-32-545:(R)' } { (Get-Acl -LiteralPath $f).Sddl -match '\(A;[^)]*;FR;;;BU\)' }
Step 'ADMIN_FILE_SETOWNER' { icacls.exe $f /setowner '*S-1-5-32-544' } { (Get-Acl -LiteralPath $f).Owner -match 'Administrators' }
Step 'ADMIN_FILE_TAKEOWN' { takeown.exe /f $f } { (Get-Acl -LiteralPath $f).Owner -eq [Security.Principal.WindowsIdentity]::GetCurrent().Name }
Step 'ADMIN_FILE_SETACL' { $a = Get-Acl -LiteralPath $f; $a.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('Everyone', 'ReadAndExecute', 'Allow'))); Set-Acl -LiteralPath $f -AclObject $a } { (Get-Acl -LiteralPath $f).Sddl -match ';;;WD\)' }
Step 'ADMIN_FOLDER_GRANT_TREE' { icacls.exe $dir /grant '*S-1-5-11:(OI)(CI)(RX)' /T } { (Get-Acl -LiteralPath $dir).Sddl -match ';;;AU\)' }
Step 'ADMIN_FOLDER_RESET_TREE' { icacls.exe $dir /reset /T } { $true }
'ADMIN_FILE_READABLE=' + ((Get-Content -LiteralPath $f -Raw) -eq "T10 admin file clean`r`n")
'ADMIN_DONE=True'
PS
grep -qx 'ADMIN_DONE=True' "$ev/$tag-admin.txt" || { echo 'phase A did not complete'; exit 20; }

echo "== phase B: actor and coordinator ($mode)"
setup_ps=$(cat <<'PS'
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
New-Item -ItemType Directory -Force -Path C:\T10\control | Out-Null
[string](Get-WinEvent -LogName Application -MaxEvents 1).RecordId | Set-Content -LiteralPath 'C:\T10\event-baseline.txt'
& icacls.exe 'C:\T10\control' /grant 'BUILTIN\Users:(OI)(CI)M' | Out-Null
$name = 't10actor'; $password = 'T10!' + [guid]::NewGuid().ToString('N').Substring(0, 20)
if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) -AccountNeverExpires | Out-Null
} else { Set-LocalUser -Name $name -Password (ConvertTo-SecureString $password -AsPlainText -Force) }
Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name -ErrorAction SilentlyContinue
$sid = (Get-LocalUser -Name $name).SID.Value
# A new standard user lacks "log on as a batch job" and its profile (the hand-back target) may not exist in time: grant, create.
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Security.Principal; using System.Text;
public static class T10Lsa {
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
$code = [T10Lsa]::Grant($sid, 'SeBatchLogonRight'); if ($code -ne 0) { throw "SeBatchLogonRight grant failed: $code" }
$profilePath = New-Object Text.StringBuilder 260
$hr = [T10Lsa]::CreateProfile($sid, $name, $profilePath, 260)
'ACTOR_PROFILE=' + $profilePath.ToString() + ' hr=0x' + $hr.ToString('X8')
Copy-Item -LiteralPath "$d\t10-permissions-actor.ps1" -Destination 'C:\T10\permissions-actor.ps1' -Force
$actor = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\T10\permissions-actor.ps1"'
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 't10-actor' -Action $actor -User ($env:COMPUTERNAME + '\' + $name) -Password $password -RunLevel Limited -Settings $settings -Force | Out-Null
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$coordinator = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $d + '\t10-permissions-coordinator.ps1"')
Register-ScheduledTask -TaskName 't10-coordinator' -Principal $principal -Action $coordinator -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 't10-coordinator'
'COORDINATOR_STARTED=True'
PS
)
printf '%s\n' "$setup_ps" | remote | tee "$ev/$tag-setup.txt"
grep -qx 'COORDINATOR_STARTED=True' "$ev/$tag-setup.txt" || { echo 'coordinator did not start'; exit 20; }

limit=1800; waited=0; state=RUNNING; alive=yes
while [ "$waited" -lt "$limit" ]; do
    sleep 30; waited=$((waited + 30))
    if ! state=$(remote <<<"if (Test-Path C:\\T10\\result.json) { 'DONE' } else { 'RUNNING' }" | tail -1); then state=UNREACHABLE; fi
    case "$state" in DONE*) break;; RUNNING*) alive=yes;; *) # a bugcheck looks like a hang: the guest stops answering
        if ! ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1; then alive=no; echo "guest unreachable after ${waited}s"; break; fi;;
    esac
done
echo "wait ended after ${waited}s: $state alive=$alive"

if [ "$alive" = yes ]; then
    remote <<'PS' > "$ev/$tag-after.txt"
$ErrorActionPreference = 'Continue'
'RESULT=' + $(if (Test-Path C:\T10\result.json) { (Get-Content C:\T10\result.json -Raw) -replace '\s+', ' ' } else { 'missing' })
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
'VERIFIER=' + ((& verifier.exe /query | Out-String) -replace '\s+', ' ')
try { $ring = @(& 'C:\Users\vika\Documents\Get-SafeUploadDiagnostics.ps1' -Query deny-ring); 'RING_TOTAL=' + $ring.Count; foreach ($e in $ring | Select-Object -Last 60) { 'RING=' + ($e | ConvertTo-Json -Compress) } } catch { 'RING_ERROR=' + $_.Exception.Message }
'AFTER_DONE=True'
PS
    scp "${opts[@]}" "vika@$host:C:/T10/control/actor-error.txt" "$ev/$tag-actor-error.txt" >/dev/null 2>&1 || true
    remote <<'PS' > "$ev/$tag-service-events.txt"
$base = [long](Get-Content -LiteralPath 'C:\T10\event-baseline.txt')
$xpath = "*[System[Provider[@Name='SafeUpload.Agent.Service'] and EventRecordID > $base and (Level=1 or Level=2 or Level=3)]]"
Get-WinEvent -LogName Application -FilterXPath $xpath -ErrorAction SilentlyContinue | ForEach-Object {
    [ordered]@{ RecordId = $_.RecordId; TimeCreated = $_.TimeCreated.ToString('o'); Level = $_.Level; Message = $_.Message } | ConvertTo-Json -Compress
}
PS
else
    $V screenshot "$dom" "$ev/$tag-unreachable.ppm" >/dev/null 2>&1 || true
    : > "$ev/$tag-after.txt"
fi

python3 - "$ev/$tag-after.txt" "$ev/$tag-admin.txt" "$ev/$tag-verdict.txt" "$mode" "$alive" "$(( $(date +%s) - started ))" <<'PY'
import json, re, sys
after_path, admin_path, verdict_path, mode, alive, elapsed = sys.argv[1:7]
after = open(after_path, encoding='utf-8', errors='replace').read()
admin = open(admin_path, encoding='utf-8', errors='replace').read()
out = []
def verdict(name, ok, reason):
    out.append(f"{name} {'PASS' if ok else 'FAIL'} {reason}")
m = re.search(r'^RESULT=(.*)$', after, re.M)
result = None
if m and m.group(1).strip() != 'missing':
    try: result = json.loads(m.group(1))
    except Exception: result = None
verdict('T10GuestAlive', alive == 'yes', 'the guest answered through the run (a Verifier stop is a bugcheck, which looks like a hang)')
verdict('T10DriverLoaded', 'DRIVER_LOADED=True' in after, 'the filter is still loaded after the run')
if mode != 'ordinary':
    v = re.search(r'^VERIFIER=(.*)$', after, re.M); vt = v.group(1) if v else ''
    want = r'Verifier Flags:\s*0x0*13b' if mode == 'runtime-verifier' else r'Verifier Flags:\s*0x(?!0+\b)[0-9a-f]+'
    verdict('T10VerifierActive', 'SafeUpload.sys' in vt and re.search(want, vt, re.I) is not None, f'{mode} still verifies SafeUpload.sys')
ident = re.search(r'^ADMIN_IDENTITY=(.*)$', admin, re.M)
verdict('T10AdminIsAdministrator', ident is not None and ident.group(1).endswith('admin=True'), ident.group(1) if ident else 'missing')
for step in ('ADMIN_FILE_GRANT', 'ADMIN_FILE_SETOWNER', 'ADMIN_FILE_TAKEOWN', 'ADMIN_FILE_SETACL', 'ADMIN_FOLDER_GRANT_TREE', 'ADMIN_FOLDER_RESET_TREE', 'ADMIN_FILE_READABLE'):
    sm = re.search(r'^' + step + r'=(\S+)(.*)$', admin, re.M)
    verdict('T10' + ''.join(w.capitalize() for w in step.split('_')[1:]), sm is not None and sm.group(1) == 'True', (sm.group(2).strip()[:200] if sm else 'missing'))
checks = (result or {}).get('Checks') or []
verdict('T10PhaseBCompleted', result is not None and not result.get('Error') and len(checks) == 13, f"{len(checks)} of 13 checks; error {(result or {}).get('Error')}")
for c in checks:
    verdict(c.get('Name'), bool(c.get('Ok')), str(c.get('Detail'))[:200])
out.append(f"T10AceAfterPublication INFO admin ACE survived publication: {(result or {}).get('AdminAceSurvivedPublication')}; SDDL {(result or {}).get('AclAfterPublication')}")
out.append(f"T10Duration INFO {elapsed} s ({mode})")
open(verdict_path, 'w').write('\n'.join(out) + '\n')
print('\n'.join(out))
sys.exit(0 if all(' FAIL ' not in line for line in out) else 1)
PY
