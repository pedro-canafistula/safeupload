#!/usr/bin/env bash
# DIAGNOSTIC ONLY (never a delivery gate): build one committed agent source with warnings as errors in feature Debug on a
# fresh builder directory, then run only the selected tests on the user leg. The required four-leg matrix
# (Invoke-ExactAgentMatrixBuild.py) is unchanged and is still the delivery gate.
# Usage: driver/scripts/Invoke-FocusedAgentDiagnostic.sh <label> <commit> <expected-case-count> <vstest-filter>
#   filter example: 'FullyQualifiedName~StagedMetadataStoreNativeTests'
# Evidence: driver/evidence/<today>/t9-diagnostic-<label>/ (raw, ignored by git; curate what you cite).
# The verdict is the host-side TRX check (executed == expected, failed == 0), not the transport exit code: a filter that
# matches nothing exits 0 in vstest and must not pass.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
label="${1:?label}"; commit="${2:?commit}"; expected="${3:?expected case count}"; filter="${4:?vstest filter}"
[[ "$label" =~ ^[A-Za-z0-9]{3,40}$ ]] || { echo 'Invalid label'; exit 2; }
[[ "$expected" =~ ^[0-9]+$ ]] && [ "$expected" -gt 0 ] || { echo 'expected count must be a positive integer'; exit 2; }
[[ "$filter" =~ ^[A-Za-z0-9_.~=\|\&\(\)\!\ ]+$ ]] || { echo 'filter has unsupported characters'; exit 2; }
ev="$PWD/driver/evidence/$(date -u +%F)/t9-diagnostic-$label"
[ ! -e "$ev" ] || { echo "Evidence directory exists; use a fresh label: $ev"; exit 2; }
mkdir -p "$ev"
read -r builder host computer user parity < <(python3 driver/scripts/approved_builders.py --role gate --label "$label" --format fields) || exit 2
python3 driver/scripts/approved_builders.py --role gate --label "$label" --format receipt > "$ev/builder.txt"
python3 driver/scripts/Invoke-ExactAgentMatrixBuild.py "$label" --commit "$commit" --prepare-only > "$ev/source-prepare.txt" 2>&1 || { cat "$ev/source-prepare.txt"; exit 1; }
archive="$PWD/output/exact-agent-matrix/$label/src.zip"
hash=$(sha256sum "$archive" | cut -d' ' -f1)
full=$(git rev-parse "$commit^{commit}")
printf '{"SourceCommit":"%s","ArchiveSha256":"%s","DiagnosticOnly":true,"ProductQualification":false,"ExpectedCases":%s,"Filter":"%s","Leg":"feature-debug/user"}\n' \
    "$full" "$hash" "$expected" "$filter" > "$ev/provenance.json"
dest_name="focused-$label"
python3 driver/scripts/remote_ps.py "$host" --role gate --label "$label" <<PS > "$ev/preflight.txt" 2>&1
\$ErrorActionPreference='Stop'
\$dest='C:\\Users\\$user\\Documents\\$dest_name'
if(Test-Path -LiteralPath \$dest){throw 'Fresh diagnostic destination exists'}
\$active=@(Get-CimInstance Win32_Process|Where-Object {\$_.Name -match '^(dotnet|testhost|MSBuild|vstest.console)(\\.exe)?\$'})
if(\$active.Count){throw 'Builder has active build/test processes'}
\$drive=Get-PSDrive C
[pscustomobject]@{Computer=\$env:COMPUTERNAME;FreeBytes=\$drive.Free;PSVersion=\$PSVersionTable.PSVersion.ToString();User=[Security.Principal.WindowsIdentity]::GetCurrent().Name}|ConvertTo-Json -Compress
if(\$drive.Free -lt 15GB){throw 'Insufficient build headroom'}
[void](New-Item -ItemType Directory -Path \$dest)
PS
[ $? -eq 0 ] || { cat "$ev/preflight.txt"; echo 'Preflight refused; nothing uploaded'; exit 1; }
scp -F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes \
    "$archive" "$user@$host:C:/Users/$user/Documents/$dest_name/src.zip" > "$ev/copy.txt" 2>&1 || { cat "$ev/copy.txt"; exit 1; }
script=$(cat <<PS
\$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding(\$false)
\$dest='C:\\Users\\$user\\Documents\\$dest_name'
\$zip=Join-Path \$dest 'src.zip'
if((Get-FileHash -LiteralPath \$zip -Algorithm SHA256).Hash -ine '$hash'){throw 'Archive hash mismatch'}
'DiagnosticOnly=True AgentMatrixGate=False ProductQualification=False'
'SourceCommit=$full'
\$src=Join-Path \$dest 'src'
Expand-Archive -LiteralPath \$zip -DestinationPath \$src
\$dotnet='C:\\Program Files\\dotnet\\dotnet.exe'
& \$dotnet --info *> (Join-Path \$dest 'dotnet-info.txt')
\$project=Join-Path \$src 'agente\\SafeUpload.Agent.Tests\\SafeUpload.Agent.Tests.csproj'
\$old=\$ErrorActionPreference
try{\$ErrorActionPreference='Continue'; & \$dotnet build \$project -c Debug -warnaserror -p:SafeUploadAdmissionEvidence=true -m:1 --disable-build-servers -p:UseSharedCompilation=false -nologo *> (Join-Path \$dest 'build.txt');\$buildCode=\$LASTEXITCODE}finally{\$ErrorActionPreference=\$old}
\$buildText=[IO.File]::ReadAllText((Join-Path \$dest 'build.txt'))
if(\$buildCode -ne 0 -or \$buildText -notmatch '0 Warning\\(s\\)' -or \$buildText -notmatch '0 Error\\(s\\)'){Get-Content (Join-Path \$dest 'build.txt');throw 'Diagnostic build failed'}
'DiagnosticBuild=PASS warnings=0 errors=0'
\$dll=Join-Path \$src 'agente\\SafeUpload.Agent.Tests\\bin\\Debug\\net10.0-windows\\SafeUpload.Agent.Tests.dll'
Get-FileHash -LiteralPath \$dll -Algorithm SHA256|Select-Object Hash,Path|ConvertTo-Json -Compress
\$filter='$filter'
try{\$ErrorActionPreference='Continue'; & \$dotnet vstest \$dll ('/TestCaseFilter:'+\$filter) '/Logger:trx;LogFileName=diagnostic.trx' ('/ResultsDirectory:'+\$dest) *> (Join-Path \$dest 'tests.txt');\$testCode=\$LASTEXITCODE}finally{\$ErrorActionPreference=\$old}
Get-Content -LiteralPath (Join-Path \$dest 'tests.txt')
'DiagnosticTestExit='+\$testCode
PS
)
set +e
printf '%s\n' "$script" > "$ev/run.ps1"
python3 driver/scripts/remote_ps.py "$host" --role gate --label "$label" < "$ev/run.ps1" > "$ev/run.txt" 2>&1
printf '%s\n' "$?" > "$ev/transport.exit"
for file in tests.txt diagnostic.trx build.txt dotnet-info.txt; do
    scp -F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes \
        "$user@$host:C:/Users/$user/Documents/$dest_name/$file" "$ev/$file" >> "$ev/collect.txt" 2>&1
done
python3 - "$ev" "$expected" <<'PY'
import re, sys
from pathlib import Path
ev, expected = Path(sys.argv[1]), int(sys.argv[2])
trx = ev / 'diagnostic.trx'
if not trx.exists():
    print('FocusedDiagnostic=FAIL no TRX retrieved; inspect run.txt'); sys.exit(1)
text = trx.read_text(encoding='utf-8-sig')
c = dict(re.findall(r'(\w+)="([^"]*)"', re.search(r'<Counters ([^/]*)/>', text).group(1)))
bad = [k for k in ('failed', 'error', 'timeout', 'aborted', 'inconclusive', 'passedButRunAborted', 'notRunnable',
                   'notExecuted', 'disconnected', 'warning', 'inProgress', 'pending') if c.get(k, '0') != '0']
ok = int(c['executed']) == expected and int(c['passed']) == expected and not bad
print(f"FocusedDiagnostic={'PASS' if ok else 'FAIL'} executed={c['executed']} passed={c['passed']} expected={expected} nonzero={bad}")
for m in re.finditer(r'<UnitTestResult [^>]*testName="([^"]+)"[^>]*outcome="(?!Passed)([^"]+)"', text):
    print('NOT-PASSED', m.group(2), m.group(1))
print('DiagnosticOnly=True AgentMatrixGate=False ProductQualification=False')
sys.exit(0 if ok else 1)
PY
