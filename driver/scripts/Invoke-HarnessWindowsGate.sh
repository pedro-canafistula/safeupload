#!/usr/bin/env bash
# Gate the Phase 4 harness on the builder's Windows PowerShell 5.1: parse every harness file and run the
# self-checks. Workers author on Linux PS7; PS 5.1 is what the guest runs.
# Usage: driver/scripts/Invoke-HarnessWindowsGate.sh <label> [tree=.]
# Prints HarnessWindowsGate=PASS only when every file parses with 0 errors and every self-check exits 0.
set -uo pipefail
label="${1:?label}"; tree="${2:-.}"
[[ "$label" =~ ^[A-Za-z0-9._-]{3,60}$ ]] || { echo 'Invalid label'; exit 2; }
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
src="$(cd "$tree" && pwd)/driver/scripts"
files=(Test-StagedInvariantSuite.ps1 StagedInvariantObserver.psm1 StagedInvariantCases.psd1 Build-ExactAgent.ps1)
checks=()
for f in "$src"/*.SelfCheck.ps1; do [[ "$(basename "$f")" == StagedInvariant*.SelfCheck.ps1 ]] && checks+=("$(basename "$f")"); done
host=192.168.122.210; dest="C:/Users/vika/Documents/harness-gate-$label"
ev="$repo/driver/evidence/$(date +%F)/harness-windows-gate-$label.txt"; mkdir -p "$(dirname "$ev")"
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=yes)
python3 "$repo/driver/scripts/remote_ps.py" "$host" <<<"if(Test-Path -LiteralPath '$dest'){throw 'gate directory exists'}; [void](New-Item -ItemType Directory -Path '$dest')" || exit 3
for f in "${files[@]}" "${checks[@]}"; do scp "${opts[@]}" "$src/$f" "vika@$host:$dest/$f" || exit 3; done
list="$(printf "'%s'," "${files[@]}" "${checks[@]}")"; checklist="$(printf "'%s'," "${checks[@]}")"
python3 "$repo/driver/scripts/remote_ps.py" "$host" > "$ev" 2>&1 <<PS
\$ok=\$true
foreach(\$f in @(${list%,})){
  \$p=Join-Path '$dest' \$f; \$t=\$null; \$e=\$null
  [void][Management.Automation.Language.Parser]::ParseFile(\$p,[ref]\$t,[ref]\$e)
  \$h=(Get-FileHash -Algorithm SHA256 -LiteralPath \$p).Hash
  "\${f}:ParseErrors=\$(\$e.Count);SHA256=\$h"; if(\$e.Count -ne 0){\$ok=\$false; \$e | ForEach-Object { '  '+\$_.Extent.StartLineNumber+': '+\$_.Message }}
}
foreach(\$c in @(${checklist%,})){
  \$out=& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path '$dest' \$c) 2>&1
  \$code=\$LASTEXITCODE; \$out | Select-Object -Last 3 | ForEach-Object { "  \$c> \$_" }
  "\${c}:Exit=\$code"; if(\$code -ne 0){\$ok=\$false}
}
'PSVersion='+\$PSVersionTable.PSVersion
if(\$ok){'HarnessWindowsGate=PASS'}else{'HarnessWindowsGate=FAIL'}
Remove-Item -LiteralPath '$dest' -Recurse -Force
PS
grep -E 'ParseErrors=|:Exit=|HarnessWindowsGate=' "$ev"; echo "evidence: $ev"
grep -q '^HarnessWindowsGate=PASS' "$ev"
