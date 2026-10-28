#!/usr/bin/env bash
# MECHANISM DISCOVERY ONLY. No product qualification or target evidence.
# Takes NO builder locks: the orchestrator MUST invoke under
# ~/Work/safeupload-tools/builder-run.sh (which selects the first free builder
# and exports SAFEUPLOAD_BUILDER). Never run alongside another job there.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../../.."
stop() { echo "STOP: $*" >&2; exit 1; }
dry=false; args=()
for arg in "$@"; do case "$arg" in --dry-run) dry=true;; *) args+=("$arg");; esac; done
[ "${#args[@]}" -eq 2 ] || stop 'Usage: Invoke-BuilderNativeControl.sh <label> <commit> [--dry-run]'
label=${args[0]}; requested_commit=${args[1]}
[[ "$label" =~ ^[A-Za-z0-9]{3,30}$ ]] || stop 'invalid label'
commit=$(git rev-parse --verify --end-of-options "$requested_commit^{commit}") || stop 'invalid commit'
control=driver/scripts/t9/native-store-mechanism-control.ps1
git cat-file -e "$commit:$control" || stop 'control missing from commit'
sha=$(git show "$commit:$control" | sha256sum | cut -d' ' -f1)
ev="driver/evidence/$(date +%F)/t9-builder-native-$label"
[ ! -e "$ev" ] && [ ! -L "$ev" ] || stop 'evidence exists; use a fresh label'
read -r builder host computer user parity < <(python3 driver/scripts/approved_builders.py --role gate --label "$label" --format fields) || stop 'builder selection failed'
if $dry; then
    printf 'DryRun=True\nCommit=%s\nControlSHA256=%s\nBuilder=%s\nEvidence=%s\n' "$commit" "$sha" "$builder" "$ev"
    echo 'ExpectedOS=19045.6466 MechanismDiscovery=True ProductQualification=False TargetEvidence=False'
    echo 'Orchestrator owns builder-run.sh lock; fresh guest directory; SHA256 + PS5.1 parse; one admin control; JSONL host verdict (32/48/7/8/1).'
    exit 0
fi
[ -n "${SAFEUPLOAD_BUILDER:-}" ] || stop 'orchestrator must select/export SAFEUPLOAD_BUILDER under builder-run.sh'
mkdir -p "$(dirname "$ev")"
mkdir "$ev" || stop 'fresh evidence reservation failed'
python3 driver/scripts/approved_builders.py --role gate --label "$label" --format receipt > "$ev/builder.txt"
git show "$commit:$control" > "$ev/control.ps1"
printf '{"SourceCommit":"%s","ControlSHA256":"%s","ExpectedOS":"19045.6466","MechanismDiscovery":true,"ProductQualification":false,"TargetEvidence":false}\n' "$commit" "$sha" > "$ev/provenance.json"
sha256sum "${BASH_SOURCE[0]}" driver/scripts/t9/native_control_verdict.py driver/scripts/{remote_ps.py,approved_builders.py,approved-builders.json} > "$ev/runner-inputs.sha256"
guest="C:/Users/$user/Documents/t9-native-$label"
remote() { timeout 420 python3 driver/scripts/remote_ps.py "$host" --role gate --label "$label"; }
remote > "$ev/preflight.txt" 2>&1 <<PS || stop 'builder preflight failed'
\$ErrorActionPreference='Stop'
if (Test-Path -LiteralPath '$guest') { throw 'Fresh guest directory exists' }
if (\$PSVersionTable.PSVersion.Major -ne 5 -or \$PSVersionTable.PSVersion.Minor -ne 1 -or [IntPtr]::Size -ne 8) { throw 'Requires native x64 PS5.1' }
\$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]\$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Requires elevated admin remote shell' }
New-Item -ItemType Directory -Path '$guest' | Out-Null
'FreshAdminPreflight=True'
PS
grep -qx 'FreshAdminPreflight=True' "$ev/preflight.txt" || stop 'missing builder preflight receipt'
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=yes)
timeout 300 scp "${opts[@]}" "$ev/control.ps1" "$user@$host:$guest/control.ps1" > "$ev/copy.txt" 2>&1 || stop 'control upload failed'
cat > "$ev/run.ps1" <<PS
\$ErrorActionPreference='Stop'
\$d='$guest'
\$code=1
try {
    if ((Get-FileHash -LiteralPath "\$d/control.ps1" -Algorithm SHA256).Hash -ine '$sha') { throw 'Committed control hash mismatch' }
    \$tokens=\$null; \$errors=\$null
    [void][Management.Automation.Language.Parser]::ParseFile("\$d/control.ps1",[ref]\$tokens,[ref]\$errors)
    if (\$errors.Count) { throw (\$errors | Out-String) }
    \$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    [pscustomobject]@{User=\$identity.Name;SID=\$identity.User.Value;Admin=([Security.Principal.WindowsPrincipal]\$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);Parser='5.1 PASS';SHA256='$sha';MechanismDiscovery=\$true;ProductQualification=\$false;TargetEvidence=\$false} | ConvertTo-Json -Compress | Set-Content -LiteralPath "\$d/admin-subject.json" -Encoding UTF8
    & "\$env:SystemRoot/System32/WindowsPowerShell/v1.0/powershell.exe" -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -File "\$d/control.ps1" -ExpectedOS 19045.6466 2> "\$d/admin-stderr.txt" | Set-Content -LiteralPath "\$d/admin.jsonl" -Encoding UTF8
    \$code=\$LASTEXITCODE
} catch {
    \$_ | Out-String | Set-Content -LiteralPath "\$d/admin-wrapper-error.txt" -Encoding UTF8
} finally {
    [string]\$code | Set-Content -LiteralPath "\$d/admin-exit.txt" -Encoding ASCII
}
exit \$code
PS
rc=0
remote < "$ev/run.ps1" > "$ev/run.txt" 2>&1 || rc=$?
printf '%s\n' "$rc" > "$ev/transport.exit"
# Collect even on a failed child/transport. No second execution or expectation
# changes: an absent file, child failure or mismatch fails the host verdict.
timeout 300 scp "${opts[@]}" -r "$user@$host:$guest" "$ev/collected" > "$ev/collect.txt" 2>&1 || true
python3 - "$ev" "$sha" "$computer" "$user" <<'PY' > "$ev/verdict.txt" 2>&1 || { cat "$ev/verdict.txt"; stop 'mechanism discovery failed; preserve first evidence'; }
import json, pathlib, sys
sys.path.insert(0, 'driver/scripts/t9')
from native_control_verdict import one, validate
root, sha, computer, user = pathlib.Path(sys.argv[1]), *sys.argv[2:]
d = root / 'collected'
def read(name): return (d/name).read_text(encoding='utf-8-sig').strip()
assert read('admin-exit.txt') == '0', 'Child failed'
if (d/'admin-wrapper-error.txt').exists():
    assert not read('admin-wrapper-error.txt'), 'Wrapper failed'
err=(d/'admin-stderr.txt').read_bytes()
assert not err.decode('utf-16' if err.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig').strip(), 'Control stderr'
lines=read('admin.jsonl').splitlines()
assert [s for s in lines if s.startswith('NativeStoreMechanism=')] == ['NativeStoreMechanism=PASS'], 'Summary failed/missing'
rows=[json.loads(s) for s in lines if not s.startswith('NativeStoreMechanism=')]
validate(rows, '19045.6466', sha)
p=json.loads(read('admin-subject.json')); t=one(rows,'Token')
assert p['User'].lower()==(computer+'\\'+user).lower() and p['SID']==t['SID'] and p['User']==t['User'], 'Wrong subject'
assert p['SHA256'].upper()==sha.upper() and p['Parser']=='5.1 PASS' and p['Admin'] is True and t['Elevated'] is True and t['IntegrityRID']==12288, 'Not elevated admin'
assert p['MechanismDiscovery'] is True and p['ProductQualification'] is False and p['TargetEvidence'] is False
print('BuilderNativeControl=PASS MechanismDiscovery=True ProductQualification=False TargetEvidence=False')
PY
cat "$ev/verdict.txt"
