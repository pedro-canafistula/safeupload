#!/usr/bin/env bash
# Sync changed driver/Inspector sources to the isolated builder mirror, verify
# their hashes there, run Build-StagedOwnedStreams.ps1 and record the result.
# Usage: driver/scripts/Invoke-BuilderBuild.sh <log-name> [output-dir-leaf] [signing-cert-thumbprint]
# Log: driver/evidence/<today>/<log-name>.txt. The process exit code is NOT the
# verdict; read the BUILD_RESULT / error lines this script prints.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
log_name="${1:?log name}"; leaf="${2:-admission-diagnostic-milestone}"; thumb="${3:-}"
sign_arg=""; [ -n "$thumb" ] && sign_arg="-CertificateThumbprint '$thumb'"
day="$(date +%F)"; log="driver/evidence/$day/$log_name.txt"
mkdir -p "driver/evidence/$day"
host=192.168.122.210
mirror='C:/Users/vika/Documents/safeupload-staging-test'
scp_opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new)

# SYNC_FROM_REF=<git ref> builds the sources of that ref instead of the working tree (same file list: those that
# differ from HEAD), for an A/B comparison against an older driver. Resync the working tree afterwards by building
# again without it, because the mirror is only refreshed for files that differ from HEAD.
mapfile -t files < <( { git diff --name-only HEAD -- driver/SafeUpload.Minifilter driver/SafeUpload.Inspector driver/scripts/Build-StagedOwnedStreams.ps1;
                         git ls-files --others --exclude-standard -- driver/SafeUpload.Minifilter driver/SafeUpload.Inspector; } | sort -u )
[ "${#files[@]}" -gt 0 ] || { echo "no changed sources"; exit 2; }
: > "$log.hashes"
sync_tmp="$(mktemp -d)"
for f in "${files[@]}"; do
    src="$f"
    if [ -n "${SYNC_FROM_REF:-}" ]; then
        mkdir -p "$sync_tmp/$(dirname "$f")"
        git show "$SYNC_FROM_REF:$f" > "$sync_tmp/$f" 2>/dev/null || { echo "$f not in $SYNC_FROM_REF"; exit 5; }
        src="$sync_tmp/$f"
    fi
    scp "${scp_opts[@]}" "$src" "vika@$host:$mirror/$f" || { echo "scp failed: $f"; exit 3; }
    echo "$f $(sha256sum "$src" | cut -c1-12)" >> "$log.hashes"
done
rm -rf "$sync_tmp"
# Verify every copied file by hash on the builder (names passed via a here-string).
list="$(printf "'%s'," "${files[@]//\//\\}")"; list="${list%,}"
remote_hashes="$(python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | sed 's/<Objs.*//' | tr -d '\r' | grep -v -e '^$' -e CLIXML
Set-Location C:\\Users\\vika\\Documents\\safeupload-staging-test
foreach (\$f in @($list)) { \$f.Replace('\\','/') + ' ' + (Get-FileHash \$f -Algorithm SHA256).Hash.Substring(0,12).ToLower() }
PS
)"
if [ "$remote_hashes" != "$(cat "$log.hashes")" ]; then
    echo "HASH MISMATCH between local and builder:"; diff <(echo "$remote_hashes") "$log.hashes"; exit 4
fi
echo "synced and verified ${#files[@]} files"; cat "$log.hashes"

python3 driver/scripts/remote_ps.py "$host" <<PS 2>&1 | sed 's/<Objs.*//' | grep -v '^$' > "$log"
\$ErrorActionPreference = 'Continue'
'BUILD_START_UTC=' + [DateTime]::UtcNow.ToString('o')
Set-Location C:\\Users\\vika\\Documents\\safeupload-staging-test
try {
    & .\\driver\\scripts\\Build-StagedOwnedStreams.ps1 -OutputDirectory 'C:\\Users\\vika\\Documents\\$leaf' $sign_arg 2>&1 | Out-Host
    'BUILD_RESULT=SCRIPT_COMPLETED'
} catch { 'BUILD_RESULT=FAILED: ' + \$_.Exception.Message }
'BUILD_END_UTC=' + [DateTime]::UtcNow.ToString('o')
PS
grep -a -E "BUILD_(START|RESULT|END)|Warning\(s\)|Error\(s\)|error [A-Z]+[0-9]+|warning [A-Z]+[0-9]+|Passed!|Failed!|Hash +:" "$log" | cut -c1-260
