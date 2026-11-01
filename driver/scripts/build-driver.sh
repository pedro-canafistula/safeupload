#!/usr/bin/env bash
# Build and test-sign the SafeUpload minifilter on a Windows builder VM.
#
# Usage: driver/scripts/build-driver.sh [commit] [Release|Debug]
#   commit   what to build (default HEAD; commit first, uncommitted changes are not sent)
# Output: out/driver/<commit>-<config>/ with SafeUpload.sys (signed), SafeUpload.inf,
#         SafeUploadInspector.exe and build.log
#
# Environment:
#   SAFEUPLOAD_BUILDER               builder address (default 192.168.122.210 = builder1, libvirt "win10";
#                                    192.168.122.211 = builder2, libvirt "su-builder2")
#   SAFEUPLOAD_SIGNING_THUMBPRINT    test-signing certificate in the builder's LocalMachine\My store
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

commit="${1:-HEAD}"; config="${2:-Release}"
[[ "$config" == Release || "$config" == Debug ]] || { echo "config must be Release or Debug"; exit 2; }
host="${SAFEUPLOAD_BUILDER:-192.168.122.210}"; user=vika
thumb="${SAFEUPLOAD_SIGNING_THUMBPRINT:-A6D6CE1AA28835D509160A80ADB7894869AADF38}"
# The current (staging) driver only builds with this property; drop it when the vcxproj no longer uses it.
props="/p:SafeUploadStagingPrototype=true"

sha="$(git rev-parse --short=10 "$commit^{commit}")"
job="su-build-$sha-$config-$(date +%Y%m%d%H%M%S)"
out="out/driver/$sha-$config"; mkdir -p "$out"
ssh_opts=(-F /dev/null -i "$HOME/.ssh/id_ed25519" -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)

# Start the builder VM if it is off, then wait for SSH.
case "$host" in 192.168.122.210) dom=win10 ;; 192.168.122.211) dom=su-builder2 ;; *) dom= ;; esac
if [[ -n "$dom" && "$(virsh -c qemu:///system domstate "$dom" 2>/dev/null)" != running ]]; then
    echo "starting builder VM $dom"; virsh -c qemu:///system start "$dom" >/dev/null
fi
for _ in $(seq 60); do ssh "${ssh_opts[@]}" "$user@$host" exit 2>/dev/null && break; sleep 5; done

git archive --format=zip -o "$out/src.zip" "$commit" driver/SafeUpload.Minifilter driver/SafeUpload.Inspector
scp "${ssh_opts[@]}" "$out/src.zip" "$user@$host:C:/Users/$user/Documents/$job.zip"

python3 driver/scripts/remote_ps.py "$host" <<PS | tee "$out/build.log"
\$ErrorActionPreference = 'Stop'
\$msbuild  = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
\$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe'
\$root = 'C:\Users\\$user\Documents\\$job'
Expand-Archive -LiteralPath "\$root.zip" -DestinationPath \$root
Set-Location \$root
& \$msbuild driver\SafeUpload.Minifilter\SafeUpload.Minifilter.vcxproj /t:Rebuild /p:Configuration=$config /p:Platform=x64 /warnaserror $props /nologo /v:minimal
if (\$LASTEXITCODE -ne 0) { throw 'driver build failed' }
& \$msbuild driver\SafeUpload.Inspector\SafeUpload.Inspector.vcxproj /t:Rebuild /p:Configuration=$config /p:Platform=x64 $props /nologo /v:minimal
if (\$LASTEXITCODE -ne 0) { throw 'inspector build failed' }
\$sys = "driver\SafeUpload.Minifilter\x64\\$config\SafeUpload.sys"
& \$signtool sign /fd sha256 /sha1 $thumb /sm \$sys
if (\$LASTEXITCODE -ne 0) { throw 'signing failed' }
New-Item -ItemType Directory -Path "\$root\out" | Out-Null
Copy-Item \$sys, 'driver\SafeUpload.Minifilter\SafeUpload.inf' "\$root\out\"
Copy-Item (Get-ChildItem -Recurse -Filter *.exe -Path driver\SafeUpload.Inspector\x64 | Select-Object -First 1).FullName "\$root\out\SafeUploadInspector.exe"
Get-ChildItem "\$root\out" | ForEach-Object { 'ARTIFACT ' + \$_.Name + ' ' + (Get-FileHash \$_.FullName -Algorithm SHA256).Hash }
PS

for f in SafeUpload.sys SafeUpload.inf SafeUploadInspector.exe; do
    scp "${ssh_opts[@]}" "$user@$host:C:/Users/$user/Documents/$job/out/$f" "$out/$f"
done
rm -f "$out/src.zip"
( cd "$out" && sha256sum SafeUpload.sys SafeUpload.inf SafeUploadInspector.exe )
echo "built $sha ($config) -> $out"
