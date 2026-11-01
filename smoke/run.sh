#!/usr/bin/env bash
# End-to-end smoke test of SafeUpload on a throwaway win10-debug3 session (Office image).
#
# Usage: smoke/run.sh <tag> <driver-dir> <agent-pkg-dir> <winfsp.msi> [--keep]
#   driver-dir     SafeUpload.sys + SafeUpload.inf (driver/scripts/build-driver.sh output)
#   agent-pkg-dir  published SafeUpload.Agent.Service with the tray app under App\ (see driver/README.md)
#   --keep         leave the VM running afterwards (end it with driver/scripts/vm-session.sh end <tag>)
# Prints PASS/FAIL lines; output is also saved to out/smoke/<tag>/.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tag="${1:?tag}"; driver="${2:?driver dir}"; pkg="${3:?agent package dir}"; msi="${4:?winfsp msi}"; keep="${5:-}"
host=192.168.122.52
ssh_opts=(-F /dev/null -i "$HOME/.ssh/id_ed25519" -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
out="out/smoke/$tag"; mkdir -p "$out"
remote() { python3 driver/scripts/remote_ps.py "$host" 2>&1 | tr -d '\r' | grep -v '^#< CLIXML'; }

# Runs a PowerShell script as t5actor in its interactive session; the script reports with Out "...".
as_user() {
    local script="$1" limit="$2" name="smk$(date +%s%N | tail -c 7)"
    { echo '$ErrorActionPreference = "Continue"'; echo "\$OutFile = 'C:\\T5\\$name.out'"
      echo 'function Out([string]$t) { Add-Content -LiteralPath $OutFile -Value $t -Encoding UTF8 }'
      echo 'try {'; cat "$script"; echo '} catch { Out ("SCRIPT_ERROR " + $_.Exception.Message) }'; echo 'Out "DONE"'
    } > "$out/$name.ps1"
    scp "${ssh_opts[@]}" "$out/$name.ps1" "vika@$host:C:/T5/$name.ps1" >/dev/null || return 1
    remote <<PS
& icacls.exe C:\T5 /grant 't5actor:(OI)(CI)M' | Out-Null
& schtasks.exe /Create /F /TN $name /RU t5actor /IT /SC ONCE /ST 23:59 /TR "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\T5\\$name.ps1" | Out-Null
& schtasks.exe /Run /TN $name | Out-Null
\$sw = [Diagnostics.Stopwatch]::StartNew()
while (\$sw.Elapsed.TotalSeconds -lt $limit -and -not ((Test-Path C:\T5\\$name.out) -and (Select-String -Path C:\T5\\$name.out -Pattern '^DONE' -Quiet -ErrorAction SilentlyContinue))) { Start-Sleep 1 }
if (Test-Path C:\T5\\$name.out) { Get-Content C:\T5\\$name.out } else { 'FAIL no output after $limit s' }
& schtasks.exe /Delete /F /TN $name | Out-Null
PS
}

usb="su-usb-$tag.img"
cleanup() {
    virsh -c qemu:///system detach-disk win10-debug3 sdc --live >/dev/null 2>&1
    virsh -c qemu:///system vol-delete --pool default "$usb" >/dev/null 2>&1
    [ "$keep" = --keep ] || bash driver/scripts/vm-session.sh end "$tag"
}
bash driver/scripts/vm-session.sh begin "$tag" --office || exit 1
trap cleanup EXIT

echo "== install"
stage="$out/su"; rm -rf "$stage"; mkdir -p "$stage"
( cd "$pkg" && zip -qr "$OLDPWD/$stage/pkg.zip" . )
( cd "$driver" && zip -qr "$OLDPWD/$stage/driver.zip" SafeUpload.sys SafeUpload.inf )
cp "$msi" "$stage/winfsp.msi"; cp -r agente/scripts "$stage/scripts"
scp "${ssh_opts[@]}" -r "$stage" "vika@$host:C:/Users/vika/Documents/" >/dev/null || exit 1
remote < smoke/setup.ps1 | tee "$out/setup.txt"
grep -q '^AgentStarted=True' "$out/setup.txt" || { echo "FAIL installation (see $out/setup.txt)"; exit 1; }
bash driver/scripts/vm-session.sh autologon || exit 1

echo "== administrator checks"
remote < smoke/admin-test.ps1 | tee "$out/admin.txt"
echo "== user checks (t5actor)"
as_user smoke/user-test.ps1 900 | tee "$out/user.txt"
echo "== USB stick (removable virtual disk)"
truncate -s 64M "$out/usb.img" && mkfs.fat -F 32 -n PENDRIVE "$out/usb.img" >/dev/null
virsh -c qemu:///system vol-create-as default "$usb" 64M --format raw >/dev/null &&
    virsh -c qemu:///system vol-upload --pool default "$usb" "$out/usb.img" && rm -f "$out/usb.img"
cat > "$out/usb.xml" <<XML
<disk type='file' device='disk'><driver name='qemu' type='raw'/>
<source file='/var/lib/libvirt/images/$usb'/><target dev='sdc' bus='usb' removable='on'/></disk>
XML
virsh -c qemu:///system attach-device win10-debug3 "$out/usb.xml" --live >/dev/null
as_user smoke/usb-test.ps1 300 | tee "$out/usb.txt"
echo "== SMB share"
as_user smoke/smb-test.ps1 300 | tee "$out/smb.txt"
echo "== agent log"
remote <<'PS' > "$out/agent-log.txt"
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'SafeUpload.Agent.Service' } -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated | ForEach-Object { $_.TimeCreated.ToString('HH:mm:ss') + ' ' + ($_.Message -replace "`r?`n", ' | ') }
PS
grep -c . "$out/agent-log.txt" | sed 's/^/agent log lines: /'
results=("$out/admin.txt" "$out/user.txt" "$out/usb.txt" "$out/smb.txt")
pass=$(cat "${results[@]}" | grep -c '^PASS'); fail=$(cat "${results[@]}" | grep -c '^FAIL')
echo "SMOKE $tag: $pass passed, $fail failed (details in $out)"
[ "$fail" -eq 0 ]
