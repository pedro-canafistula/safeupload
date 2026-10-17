#!/usr/bin/env bash
# Usage: builder-run.sh gate <label> -- bash driver/scripts/t8/Invoke-MetadataConstructionNativeControl.sh <label> <commit>
# Unprotected builder mechanism evidence only. Does not install/boot a product pair.
set -euo pipefail
label=${1:?fresh label}; commit=${2:?specific committed source}
[[ "$label" =~ ^[A-Za-z0-9._-]{3,60}$ ]] || exit 2
: "${SAFEUPLOAD_BUILDER:?Run through builder-run.sh gate to own one first-free builder slot}"
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
commit=$(git -C "$repo" rev-parse --verify "$commit^{commit}")
selection=$(python3 "$repo/driver/scripts/approved_builders.py" --role gate --label "$label" --format fields)
read -r builder_name host builder_computer builder_user parity <<< "$selection"
[[ "$parity" == False ]] || { echo 'Parity is not this mechanism gate'; exit 2; }
ev="$repo/driver/evidence/$(date +%F)/t8-construction-$label"
[[ ! -e "$ev" ]] || { echo 'Evidence exists; use a fresh label'; exit 2; }
mkdir -p "$ev/source"
printf '%s\n' "$commit" > "$ev/commit.txt"
python3 "$repo/driver/scripts/approved_builders.py" --role gate --label "$label" --format receipt > "$ev/builder.txt"
files=(metadata-construction-native-control.cs metadata-construction-native-control.ps1 Invoke-MetadataConstructionNativeControl.ps1)
for f in "${files[@]}"; do git -C "$repo" show "$commit:driver/scripts/t8/$f" > "$ev/source/$f"; done
(cd "$ev/source" && sha256sum "${files[@]}") > "$ev/source-sha256.txt"
dest="C:/Users/$builder_user/Documents/t8-construction-$label"
remote=(python3 "$repo/driver/scripts/remote_ps.py" "$host" --role gate --label "$label")
"${remote[@]}" > "$ev/prepare.txt" 2>&1 <<PS
if(Test-Path -LiteralPath '$dest'){throw 'Run directory already exists'}
[void](New-Item -ItemType Directory -Path '$dest')
PS
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=yes)
for f in "${files[@]}"; do scp "${opts[@]}" "$ev/source/$f" "$builder_user@$host:$dest/$f"; done
python3 - "$ev/source-sha256.txt" "$dest" "$label" > "$ev/run.ps1" <<'PY'
from pathlib import Path
import sys
hashes, dest, label = sys.argv[1:]
print("$ErrorActionPreference='Stop'")
print("if($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1){throw 'Windows PowerShell 5.1 required'}")
print("'PSVersion='+$PSVersionTable.PSVersion")
for line in Path(hashes).read_text().splitlines():
    digest, name = line.split()
    print(f"if((Get-FileHash -Algorithm SHA256 -LiteralPath '{dest}/{name}').Hash -ine '{digest}'){{throw 'Source hash mismatch: {name}'}}")
    if name.endswith('.ps1'):
        print(f"$t=$null;$e=$null;[void][Management.Automation.Language.Parser]::ParseFile('{dest}/{name}',[ref]$t,[ref]$e);'{name}:ParseErrors='+$e.Count;if($e.Count){{throw ($e|Out-String)}}")
print(f"& '{dest}/Invoke-MetadataConstructionNativeControl.ps1' -Label '{label}'")
PY
set +e
"${remote[@]}" < "$ev/run.ps1" > "$ev/run.txt" 2>&1
code=$?
set -e
printf '%s\n' "$code" > "$ev/transport.exit"
for extension in txt exit pid; do
    scp "${opts[@]}" "$builder_user@$host:$dest/metadata-construction-$label.$extension" "$ev/" >> "$ev/collect.txt" 2>&1 || true
done
scp "${opts[@]}" "$builder_user@$host:$dest/metadata-construction-native-progress.txt" "$ev/" >> "$ev/collect.txt" 2>&1 || true
"${remote[@]}" > "$ev/restoration.txt" 2>&1 <<PS
\$ErrorActionPreference='Stop'
if(Get-ScheduledTask -TaskName 'SafeUpload-T8Construction-$label' -ErrorAction SilentlyContinue){throw 'Task remains'}
\$pidFile='$dest/metadata-construction-$label.pid'
if(Test-Path -LiteralPath \$pidFile){
  \$parts=(Get-Content -LiteralPath \$pidFile -Raw).Trim().Split(';')
  \$worker=Get-Process -Id ([int]\$parts[0]) -ErrorAction SilentlyContinue
  if(\$null -ne \$worker -and \$worker.StartTime.ToUniversalTime().Ticks -eq [long]\$parts[1]){throw 'Worker remains'}
}
\$receipt='$dest/metadata-construction-$label.txt'
if(Test-Path -LiteralPath \$receipt){
  \$text=Get-Content -LiteralPath \$receipt -Raw
  \$match=[regex]::Match(\$text,'Root=(.*?) OS=')
  if(\$match.Success -and (Test-Path -LiteralPath \$match.Groups[1].Value)){throw 'Fixture remains; retain run directory'}
}
'T8IndependentRestoration=PASS TaskAbsent=True WorkerStopped=True FixtureAbsent=True'
Remove-Item -LiteralPath '$dest' -Recurse -Force
PS
cat "$ev/run.txt"
cat "$ev/restoration.txt"
echo "Evidence=$ev"
[[ "$code" == 0 ]]
python3 - "$ev" "$label" <<'PY'
from pathlib import Path
import json, sys
ev, label = Path(sys.argv[1]), sys.argv[2]
receipt = (ev / f'metadata-construction-{label}.txt').read_text(encoding='utf-16')
rows = [json.loads(line) for line in receipt.splitlines() if line.startswith('{')]
assert len(rows) == 24, len(rows)
assert all(row['Passed'] for row in rows)
assert len([row for row in rows if row['Operation'] == 'AfterNativeRename']) == 6
assert 'T8ConstructionFeasibility=PASS TargetQualification=False ProductImplementation=False' in receipt
assert (ev / f'metadata-construction-{label}.exit').read_text().strip() == '0'
assert 'T8IndependentRestoration=PASS' in (ev / 'restoration.txt').read_text()
print('T8StructuredMechanismVerdict=PASS TargetQualification=False ProductImplementation=False')
PY
