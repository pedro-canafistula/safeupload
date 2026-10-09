#!/usr/bin/env bash
# T2 diagnosis: with the staged-writes driver loaded, create a brand-new local user's profile (userenv!CreateProfile, the
# first-sign-in path) and read the driver's deny ring through the service's diagnostics pipe. Reproduces the denied operation
# of "User Profile Service failed the sign-in" (CreateProfile = 0x80070005) and names it.
#
# Usage: driver/scripts/Invoke-NewProfileDiagnosis.sh <debuggee domain> <tag> <driver.sys> <agent stage-service-publish.zip>
# Takes a disk-only checkpoint of the debuggee first, installs the pair like the manual install in MVP-PLAN (through
# Install-SafeUploadAgent.ps1), reboots, waits for Ready, runs the probe, then ALWAYS rolls the guest back to the checkpoint and
# re-verifies the baseline. Evidence: driver/evidence/<day>/<tag>-*.txt. The exit status is not the verdict: read <tag>-probe.txt.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
dom="${1:?debuggee domain}"; tag="${2:?tag}"; sys="${3:?signed driver}"; zip="${4:?agent publish zip}"
[[ "$tag" =~ ^[A-Za-z0-9]{3,30}$ ]] || { echo 'Invalid tag'; exit 2; }
host=$(awk -v d="$dom" '$1==d{print $2}' driver/scripts/debuggees.txt); [ -n "$host" ] || { echo "Unknown debuggee $dom"; exit 2; }
V="virsh -c qemu:///system"; ev="driver/evidence/$(date +%F)"; mkdir -p "$ev"
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new)
guest='C:/Users/vika/Documents'
# Keeps error records (they arrive as CLIXML <S S="Error"> strings) as "ERROR:" lines and drops only progress records.
clean() { python3 -c '
import re, sys, html
text = sys.stdin.read()
errors = ["ERROR: " + html.unescape(m).replace("_x000D__x000A_", "\n") for m in re.findall(r"<S S=\"Error\">(.*?)</S>", text, flags=re.S)]
text = re.sub(r"<Objs.*?</Objs>", "", text, flags=re.S).replace("#< CLIXML", "").replace("\r", "")
print("\n".join(line for line in (text.split("\n") + errors) if line.strip()))
'; }
remote() { python3 driver/scripts/remote_ps.py "$host" 2>&1 | clean; }
wait_ssh() { for _ in $(seq 1 90); do ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }

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
    # A crash-consistent checkpoint can land in Windows Recovery ("Choose your keyboard layout") instead of booting: power-cycle once.
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

echo "== stage files and install"
sleep 5
scp "${opts[@]}" "$sys" "vika@$host:$guest/SafeUpload-t2.sys" && scp "${opts[@]}" "$zip" "vika@$host:$guest/stage-service-publish.zip" \
  && scp "${opts[@]}" agente/scripts/Install-SafeUploadAgent.ps1 "vika@$host:$guest/Install-SafeUploadAgent.ps1" \
  && scp "${opts[@]}" agente/scripts/Protect-SafeUploadPolicy.ps1 "vika@$host:$guest/Protect-SafeUploadPolicy.ps1" \
  && scp "${opts[@]}" agente/scripts/Get-SafeUploadDiagnostics.ps1 "vika@$host:$guest/Get-SafeUploadDiagnostics.ps1" || { echo 'copy failed'; exit 14; }
remote <<'PS' | tee "$ev/$tag-install.txt"
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
$agentDir = 'C:\Program Files\SafeUpload\Agent'
New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
Expand-Archive -LiteralPath "$d\stage-service-publish.zip" -DestinationPath $agentDir -Force
Copy-Item -LiteralPath "$d\SafeUpload-t2.sys" -Destination 'C:\Windows\System32\drivers\SafeUpload.sys' -Force
New-Item -ItemType Directory -Force -Path 'C:\Protected' | Out-Null
& icacls.exe 'C:\Protected' /grant 'BUILTIN\Users:(OI)(CI)M' | Out-Null
$data = 'C:\ProgramData\SafeUpload'
New-Item -ItemType Directory -Force -Path $data | Out-Null
$policy = @{ version = 1; activeCategories = @('Cpf'); monitoredScopes = @{ extensions = @('.txt'); destinationPaths = @('C:\Protected'); removableDrives = $false; networkPaths = $false }; failOpen = $false; auditOnly = $false; overrideAllowed = $false } | ConvertTo-Json -Depth 5
Set-Content -LiteralPath "$data\policy.json" -Value $policy -Encoding UTF8
& "$d\Protect-SafeUploadPolicy.ps1"
& "$d\Install-SafeUploadAgent.ps1" -ServiceExecutablePath "$agentDir\SafeUpload.Agent.Service.exe"
'ImagePath=' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent').ImagePath
'DriverStart=' + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload').Start
'INSTALL_DONE=True'
PS
grep -qx 'INSTALL_DONE=True' "$ev/$tag-install.txt" || { echo 'install failed'; exit 15; }

echo "== reboot"
remote <<<'& shutdown.exe /r /t 5 /c "T2 diagnosis"' >/dev/null; sleep 60; wait_ssh || { echo 'guest did not return'; exit 17; }

echo "== wait Ready and probe"
remote <<'PS' | tee "$ev/$tag-probe.txt"
$ErrorActionPreference = 'Continue'
$d = 'C:\Users\vika\Documents'
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
'LAST_FRAME=' + $last
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
try { $before = & "$d\Get-SafeUploadDiagnostics.ps1" -Query counters; 'COUNTERS_BEFORE=' + ($before | ConvertTo-Json -Depth 6 -Compress) } catch { 'COUNTERS_BEFORE_ERROR=' + $_.Exception.Message }
try { $ringBefore = @(& "$d\Get-SafeUploadDiagnostics.ps1" -Query deny-ring); $after = if ($ringBefore.Count) { [uint64]$ringBefore[-1].sequence } else { [uint64]0 }; 'RING_BEFORE_COUNT=' + $ringBefore.Count } catch { $after = [uint64]0; 'RING_BEFORE_ERROR=' + $_.Exception.Message }

Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
public static class ProfileProbe {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    public static extern int CreateProfile(string sid, string userName, StringBuilder path, uint cch);
}
'@
$name = 't2probe'
& net.exe user $name 'P@ssw0rd!2026' /add | Out-Null
$sid = (New-Object System.Security.Principal.NTAccount($name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
$path = New-Object System.Text.StringBuilder 260
$hr = [ProfileProbe]::CreateProfile($sid, $name, $path, 260)
'CREATEPROFILE_HR=0x{0:X8}' -f $hr
'PROFILE_PATH=' + $path.ToString()
Start-Sleep -Seconds 2
try { $ring = @(& "$d\Get-SafeUploadDiagnostics.ps1" -Query deny-ring -After $after); 'RING_AFTER_COUNT=' + $ring.Count; foreach ($r in $ring) { 'RING=' + ($r | ConvertTo-Json -Compress) } } catch { 'RING_AFTER_ERROR=' + $_.Exception.Message }
try { $c2 = & "$d\Get-SafeUploadDiagnostics.ps1" -Query counters; 'COUNTERS_AFTER=' + ($c2 | ConvertTo-Json -Depth 6 -Compress) } catch { 'COUNTERS_AFTER_ERROR=' + $_.Exception.Message }
# Phase 2: the scope must still be enforced for a standard user, and a deep tree outside it must work (first logon of a new
# account also goes through the Profile Service). The user runs as a scheduled task with its own password.
$u = 't2user'; $pw = 'P@ssw0rd!2026'
& net.exe user $u $pw /add | Out-Null
$userScript = @'
$r = [ordered]@{}
function Step($name, [scriptblock]$body) { try { & $body; $r[$name] = 'OK' } catch { $r[$name] = 'ERR: ' + $_.Exception.Message } }
Step 'mkdir-in-scope' { New-Item -ItemType Directory -Path 'C:\Protected\dirA' -ErrorAction Stop | Out-Null }
Step 'mkdir-deep-in-scope' { New-Item -ItemType Directory -Path 'C:\Protected\a\b\c' -Force -ErrorAction Stop | Out-Null }
Step 'write-file-in-scope' { Set-Content -LiteralPath 'C:\Protected\ok.txt' -Value 'hello' -ErrorAction Stop }
Step 'mkdir-deep-profile' { New-Item -ItemType Directory -Path (Join-Path $env:USERPROFILE 'proj\x\y') -Force -ErrorAction Stop | Out-Null }
Step 'write-file-profile' { Set-Content -LiteralPath (Join-Path $env:USERPROFILE 'proj\x\y\f.txt') -Value 'x' -ErrorAction Stop }
$r['whoami'] = (& whoami.exe)
$r | ConvertTo-Json | Set-Content -LiteralPath 'C:\Users\Public\t2-user-results.json' -Encoding UTF8
'@
Set-Content -LiteralPath 'C:\Users\Public\t2-user.ps1' -Value $userScript -Encoding UTF8
Remove-Item 'C:\Users\Public\t2-user-results.json' -ErrorAction SilentlyContinue
$ringMark = 0
try { $ringAll = @(& "$d\Get-SafeUploadDiagnostics.ps1" -Query deny-ring); if ($ringAll.Count) { $ringMark = [uint64]$ringAll[-1].sequence } } catch { }
$eventMark = Get-Date
try {
    $secure = ConvertTo-SecureString $pw -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential(("$env:COMPUTERNAME\$u"), $secure)
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\t2-user.ps1' `
        -Credential $cred -LoadUserProfile -WorkingDirectory 'C:\Windows\System32' -Wait -PassThru
    'USER_PROCESS_EXIT=' + $proc.ExitCode
} catch { 'USER_PROCESS_ERROR=' + $_.Exception.Message }
try {
    $evts = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $eventMark } -ErrorAction Stop | Where-Object { $_.ProviderName -match 'User Profiles|Userenv|ProfSvc' }
    'PROFSVC_EVENTS=' + @($evts).Count
    foreach ($e in @($evts) | Select-Object -First 6) { 'PROFSVC_EVENT=' + $e.Id + ' ' + ($e.Message -replace '\s+', ' ').Substring(0, [Math]::Min(220, $e.Message.Length)) }
} catch { 'PROFSVC_EVENTS_ERROR=' + $_.Exception.Message }
if (Test-Path 'C:\Users\Public\t2-user-results.json') { 'USER_RESULTS=' + ((Get-Content 'C:\Users\Public\t2-user-results.json' -Raw) -replace '\s+', ' ') } else { 'USER_RESULTS=missing' }
Start-Sleep -Seconds 8
'PROTECTED_LISTING=' + ((Get-ChildItem 'C:\Protected' -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.Name + ':' + $_.Length }) -join ',')
try { $ring2 = @(& "$d\Get-SafeUploadDiagnostics.ps1" -Query deny-ring -After $ringMark); 'RING2_COUNT=' + $ring2.Count; foreach ($r2 in $ring2) { 'RING2=' + ($r2 | ConvertTo-Json -Compress) } } catch { 'RING2_ERROR=' + $_.Exception.Message }
'PROBE_DONE=True'
PS
echo "probe evidence: $ev/$tag-probe.txt"
