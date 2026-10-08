#!/usr/bin/env bash
# Independent verification of a builder run, from the builder's own files (never the build script's exit code):
# per-build logs, signature, four Inspector builds (normal/feature x Debug/Release), normal-build identity
# against the committed HEAD, then fetch the signed SYS and the feature Release Inspector to /tmp/claude-1000/artifacts.
# Usage: driver/scripts/Verify-BuilderBuild.sh <run-label>   (evidence: driver/evidence/<today>/<label>-*.txt)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
label="${1:?run label}"; day="$(date +%F)"; ev="driver/evidence/$day"; host=192.168.122.210
mkdir -p "$ev"
scp_opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
mkdir -p /tmp/claude-1000/artifacts /tmp/claude-1000/headcheck
git archive HEAD driver/SafeUpload.Minifilter -o /tmp/claude-1000/headcheck/head-minifilter.tar
scp "${scp_opts[@]}" /tmp/claude-1000/headcheck/head-minifilter.tar "vika@$host:C:/Users/vika/Documents/head-minifilter.tar" || exit 2
scp "${scp_opts[@]}" driver/scripts/Test-NormalBuildIdentity.ps1 "vika@$host:C:/Users/vika/Documents/Test-NormalBuildIdentity.ps1" || exit 2
for n in normal-wdk owned-feature-wdk normal-release-wdk owned-feature-release-wdk agent-tests service-build; do
  scp "${scp_opts[@]}" "vika@$host:C:/Users/vika/Documents/admission-diagnostic-milestone/$n.txt" "$ev/$label-$n.txt" || echo "scp fail $n"
done
python3 driver/scripts/remote_ps.py "$host" <<'PS' 2>&1 | sed 's/<Objs.*//' | tr -d '\r' | grep -v -e '^$' -e CLIXML | tee "$ev/$label-builder-verification.txt"
$d = 'C:\Users\vika\Documents\admission-diagnostic-milestone'
'UTC=' + [DateTime]::UtcNow.ToString('o')
foreach ($n in 'normal-wdk','owned-feature-wdk','normal-release-wdk','owned-feature-release-wdk') {
  $f = Get-Item (Join-Path $d "$n.txt"); $t = Get-Content $f.FullName -Raw
  $w = ([regex]::Matches($t,'(?m)^\s*(\d+) Warning\(s\)')) | ForEach-Object { $_.Groups[1].Value }
  $e = ([regex]::Matches($t,'(?m)^\s*(\d+) Error\(s\)')) | ForEach-Object { $_.Groups[1].Value }
  "$n : written=$($f.LastWriteTimeUtc.ToString('HH:mm:ss')) warnings=$($w -join ',') errors=$($e -join ',') succeeded=$($t -match 'Build succeeded') apivalidator=$($t -match 'ApiValidator')"
}
$p = Join-Path $d 'SafeUpload-stage-prototype.sys'; $sig = Get-AuthenticodeSignature $p
'SafeUpload-stage-prototype.sys ' + (Get-Item $p).Length + ' sha256=' + (Get-FileHash $p -Algorithm SHA256).Hash + ' signer=' + $sig.SignerCertificate.Thumbprint + ' written=' + (Get-Item $p).LastWriteTimeUtc.ToString('HH:mm:ss')
Set-Location C:\Users\vika\Documents\safeupload-staging-test
$msbuild = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
foreach ($cfg in 'Debug','Release') { foreach ($feat in 'false','true') {
  $label = "inspector-$feat-$cfg"
  $log = & $msbuild driver\SafeUpload.Inspector\SafeUpload.Inspector.vcxproj /t:Rebuild "/p:Configuration=$cfg" /p:Platform=x64 /warnaserror "/p:SafeUploadStagingPrototype=$feat" 2>&1 | Out-String
  $w = ([regex]::Match($log,'(\d+) Warning\(s\)')).Groups[1].Value; $e = ([regex]::Match($log,'(\d+) Error\(s\)')).Groups[1].Value
  $dest = Join-Path $d "$label.exe"; Copy-Item "driver\SafeUpload.Inspector\x64\$cfg\SafeUpload.Inspector.exe" $dest -Force
  $bytes = [IO.File]::ReadAllBytes($dest); $u = [Text.Encoding]::Unicode.GetString($bytes); $a = [Text.Encoding]::ASCII.GetString($bytes)
  $has = ($u.Contains('admission-') -or $a.Contains('admission-') -or $u.Contains('admission_') -or $a.Contains('admission_'))
  "$label : warnings=$w errors=$e size=$($bytes.Length) sha256=$((Get-FileHash $dest -Algorithm SHA256).Hash) containsAdmissionStrings=$has"
} }
try { & 'C:\Users\vika\Documents\Test-NormalBuildIdentity.ps1' -HeadTar 'C:\Users\vika\Documents\head-minifilter.tar' -MilestoneDirectory $d | Select-String 'NormalBuildIdentity|FAIL' } catch { 'IDENTITY_SCRIPT_THREW: ' + $_.Exception.Message }
PS
scp "${scp_opts[@]}" "vika@$host:C:/Users/vika/Documents/admission-diagnostic-milestone/SafeUpload-stage-prototype.sys" /tmp/claude-1000/artifacts/SafeUpload-stage-prototype.sys
scp "${scp_opts[@]}" "vika@$host:C:/Users/vika/Documents/admission-diagnostic-milestone/inspector-true-Release.exe" /tmp/claude-1000/artifacts/SafeUpload.Inspector.exe
sha256sum /tmp/claude-1000/artifacts/* | tee "$ev/$label-artifact-hashes.txt"
