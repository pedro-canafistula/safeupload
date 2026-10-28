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
files=(Test-StagedInvariantSuite.ps1 StagedInvariantObserver.psm1 StagedInvariantCases.psd1 Build-ExactAgent.ps1 t4/cycles-actor.ps1 t4/cycles-coordinator.ps1 t4/failure-evidence.ps1 t4/cycles-progress.ps1 t4/agent-readiness.ps1 t4/runtime-verifier.ps1 t4/memory-debugger.ps1 t4/purge-attribution.ps1 t6/moves-actor.ps1 t6/moves-coordinator.ps1 t10/permissions-actor.ps1 t10/permissions-coordinator.ps1 t5/notepad-actor.ps1 t5/notepad-coordinator.ps1 t5/writer-permission-native-control.ps1 t5/bound-publication-native-control.ps1 t5/security-roundtrip-native-control.ps1 t5/Invoke-SecurityRoundTripNativeControl.ps1)
checks=(t4/reopen-after-publication.SelfCheck.ps1)
files+=(t4/reopen-after-publication.ps1)
files+=(t5/security-descriptor-native-control.ps1 t5/security-roundtrip-native-control.SelfCheck.ps1)
files+=(t9/native-store-mechanism-control.ps1 t9/native-store-mechanism-control.SelfCheck.ps1)
checks+=(t9/native-store-mechanism-control.SelfCheck.ps1)
files+=(t9/nu501/Invoke-Nu501Client.ps1 t9/nu501/Prepare-Nu501Component.ps1)
for f in "$src"/*.SelfCheck.ps1; do [[ "$(basename "$f")" == StagedInvariant*.SelfCheck.ps1 ]] && checks+=("$(basename "$f")"); done
files+=(t5/notepad-cases.json t5/fixtures/C01-00000001.pack t5/fixtures/m2t5ord4-00000001.pack)
checks+=(t5/notepad-coordinator.SelfCheck.ps1 t5/notepad-journal.SelfCheck.ps1 t5/notepad-native.SelfCheck.ps1 t5/notepad-actor.SelfCheck.ps1 t5/notepad-observer-shape.SelfCheck.ps1)
selection="$(python3 "$repo/driver/scripts/approved_builders.py" --role gate --label "$label" --format fields)" || exit 2
read -r builder_name host builder_computer builder_user parity_check <<< "$selection"
remote_args=("$host" --role gate --label "$label")
dest="C:/Users/$builder_user/Documents/harness-gate-$label"
files+=(Build-ExactAgentMatrix.ps1 Build-ExactSource.ps1 Build-ExactSectionFault.ps1 ApprovedBuilders.ps1 approved-builders.json)
checks+=(Build-ExactAgentMatrix.SelfCheck.ps1 ApprovedBuilders.SelfCheck.ps1 Build-ExactSource.SelfCheck.ps1 Build-ExactAgent.SelfCheck.ps1)
ev="$repo/driver/evidence/$(date +%F)/harness-windows-gate-$label.txt"; mkdir -p "$(dirname "$ev")"
[[ ! -e "$ev" ]] || { echo 'Existing gate evidence; use a fresh label'; exit 2; }
python3 "$repo/driver/scripts/approved_builders.py" --role gate --label "$label" --format receipt > "$ev" || exit 2
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=yes)
python3 "$repo/driver/scripts/remote_ps.py" "${remote_args[@]}" <<<"if(Test-Path -LiteralPath '$dest'){throw 'gate directory exists'}; [void](New-Item -ItemType Directory -Path '$dest/t4'); [void](New-Item -ItemType Directory -Path '$dest/t6'); [void](New-Item -ItemType Directory -Path '$dest/t10'); [void](New-Item -ItemType Directory -Path '$dest/t5'); [void](New-Item -ItemType Directory -Path '$dest/t9'); [void](New-Item -ItemType Directory -Path '$dest/t9/nu501'); [void](New-Item -ItemType Directory -Path '$dest/t5/fixtures')" || exit 3
for f in "${files[@]}" "${checks[@]}"; do scp "${opts[@]}" "$src/$f" "$builder_user@$host:$dest/$f" || exit 3; done
list="$(printf "'%s'," "${files[@]}" "${checks[@]}")"; checklist="$(printf "'%s'," "${checks[@]}")"
python3 "$repo/driver/scripts/remote_ps.py" "${remote_args[@]}" >> "$ev" 2>&1 <<PS
\$ErrorActionPreference='Stop'
if(\$PSVersionTable.PSVersion.Major -ne 5 -or \$PSVersionTable.PSVersion.Minor -ne 1){throw 'Harness requires Windows PowerShell 5.1.'}
\$ok=\$true
foreach(\$f in @(${list%,})){
  \$p=Join-Path '$dest' \$f; \$t=\$null; \$e=\$null
  if(\$f -like '*.json' -or \$f -like '*.pack'){\$e=@()}else{[void][Management.Automation.Language.Parser]::ParseFile(\$p,[ref]\$t,[ref]\$e)}
  \$h=(Get-FileHash -Algorithm SHA256 -LiteralPath \$p).Hash
  "\${f}:ParseErrors=\$(\$e.Count);SHA256=\$h"; if(\$e.Count -ne 0){\$ok=\$false; \$e | ForEach-Object { '  '+\$_.Extent.StartLineNumber+': '+\$_.Message }}
}
foreach(\$c in @(${checklist%,})){
  # Native stderr is evidence, not an exception that can skip the exit receipt.
  \$savedPreference=\$ErrorActionPreference
  try {
    \$ErrorActionPreference='Continue'; \$global:LASTEXITCODE=\$null
    \$out=& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path '$dest' \$c) 2>&1
  } finally { \$ErrorActionPreference=\$savedPreference }
  \$code=\$LASTEXITCODE; \$keep=3; if(\$code -ne 0){\$keep=25}; \$out | Select-Object -Last \$keep | ForEach-Object { "  \$c> \$_" }
  "\${c}:Exit=\$code"; if(\$code -ne 0){\$ok=\$false}
}
'PSVersion='+\$PSVersionTable.PSVersion
if('$parity_check' -eq 'True'){
  'ParityCheck=True'; 'ParityCheck: not a gate'; 'HarnessWindowsGate=False'; "ParityChecksSucceeded=\$ok"
}elseif(\$ok){'HarnessWindowsGate=PASS'}else{'HarnessWindowsGate=FAIL'}
Remove-Item -LiteralPath '$dest' -Recurse -Force
PS
grep -E 'ParseErrors=|:Exit=|HarnessWindowsGate=' "$ev"; echo "evidence: $ev"
if [[ "$parity_check" == True ]]; then
    tr -d '\r' < "$ev" | grep -qx 'ParityChecksSucceeded=True'   # Windows evidence lines end in CRLF
else
    tr -d '\r' < "$ev" | grep -qx 'HarnessWindowsGate=PASS'
fi
