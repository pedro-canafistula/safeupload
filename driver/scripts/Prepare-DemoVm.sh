#!/usr/bin/env bash
# Demo/manual-test VM (owner request 2026-10-16): install a signed driver + agent pair on a DISPOSABLE run disk of win10-debug3,
# leave the guest RUNNING for interactive use, and replay Notepad-, Word- and Explorer-style file operations against C:\Protected
# so problems surface before the demo. The base disk is never written; discard the run disk afterwards with:
#   driver/scripts/Prepare-DemoVm.sh --discard <tag>
#
# Usage: driver/scripts/Prepare-DemoVm.sh <tag> <driver.sys> <agent zip> <agent source commit>
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
dom=win10-debug3
V="virsh -c qemu:///system"
source driver/scripts/image-store.sh; source driver/scripts/run-disk.sh
if [ "${1:-}" = --discard ]; then
    tag="${2:?tag}"; run_disk_end "$dom" "$tag"; exit $?
fi
tag="${1:?tag}"; sys="${2:?signed driver}"; zip="${3:?agent zip}"; commit="${4:?agent source commit}"
[[ "$tag" =~ ^[A-Za-z0-9]{3,30}$ ]] || { echo 'Invalid tag'; exit 2; }
[ -f "$sys" ] && [ -f "$zip" ] || { echo 'driver or agent zip missing'; exit 2; }
host=$(awk -v d="$dom" '$1==d{print $2}' driver/scripts/debuggees.txt); [ -n "$host" ] || { echo "Unknown debuggee $dom"; exit 2; }
ev="driver/evidence/$(date +%F)"; mkdir -p "$ev"
opts=(-F /dev/null -i /home/victor/.ssh/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new)
guest='C:/Users/vika/Documents'
clean() { python3 -c '
import re, sys, html
text = sys.stdin.read()
errors = ["ERROR: " + html.unescape(m).replace("_x000D__x000A_", "\n") for m in re.findall(r"<S S=\"Error\">(.*?)</S>", text, flags=re.S)]
text = re.sub(r"<Objs.*?</Objs>", "", text, flags=re.S).replace("#< CLIXML", "").replace("\r", "")
print("\n".join(line for line in (text.split("\n") + errors) if line.strip()))
'; }
remote() { python3 driver/scripts/remote_ps.py "$host" 2>&1 | clean; }
wait_ssh() { for _ in $(seq 1 90); do ssh "${opts[@]}" -o ConnectTimeout=5 "vika@$host" 'echo up' >/dev/null 2>&1 && return 0; sleep 10; done; return 1; }

# The agent's own install scripts, from the agent's source commit (not this tree), so script and package match.
scripts=$(mktemp -d); trap 'rm -rf "$scripts"' EXIT
for f in Install-SafeUploadAgent.ps1 Protect-SafeUploadPolicy.ps1 Get-SafeUploadDiagnostics.ps1; do
    git show "$commit:agente/scripts/$f" > "$scripts/$f" || { echo "missing $f at $commit"; exit 2; }
done

echo "== run disk (left running for the demo; discard with --discard $tag)"
run_disk_begin "$dom" "$tag" > "$ev/$tag-checkpoint.txt" 2>&1 || { cat "$ev/$tag-checkpoint.txt"; exit 12; }
wait_ssh || { echo 'guest did not boot on the run disk'; exit 3; }
scp "${opts[@]}" driver/scripts/Get-StagedBaseline.ps1 "vika@$host:$guest/Get-StagedBaseline.ps1" || exit 3
echo "& 'C:\\Users\\vika\\Documents\\Get-StagedBaseline.ps1'" | remote > "$ev/$tag-baseline.txt"
grep -q '^BaselineClean=True' "$ev/$tag-baseline.txt" || { echo 'BASELINE NOT CLEAN on a fresh run disk'; exit 10; }

echo "== install the pair"
scp "${opts[@]}" "$sys" "vika@$host:$guest/SafeUpload-demo.sys" && scp "${opts[@]}" "$zip" "vika@$host:$guest/stage-service-publish.zip" \
  && scp "${opts[@]}" "$scripts/Install-SafeUploadAgent.ps1" "$scripts/Protect-SafeUploadPolicy.ps1" "$scripts/Get-SafeUploadDiagnostics.ps1" "vika@$host:$guest/" \
  || { echo 'copy failed'; exit 14; }
remote <<'PS' | tee "$ev/$tag-install.txt"
$ErrorActionPreference = 'Stop'
$d = 'C:\Users\vika\Documents'
$agentDir = 'C:\Program Files\SafeUpload\Agent'
New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
Expand-Archive -LiteralPath "$d\stage-service-publish.zip" -DestinationPath $agentDir -Force
Copy-Item -LiteralPath "$d\SafeUpload-demo.sys" -Destination 'C:\Windows\System32\drivers\SafeUpload.sys' -Force
New-Item -ItemType Directory -Force -Path 'C:\Protected' | Out-Null
& icacls.exe 'C:\Protected' /grant 'BUILTIN\Users:(OI)(CI)M' | Out-Null
$data = 'C:\ProgramData\SafeUpload'
New-Item -ItemType Directory -Force -Path $data | Out-Null
$policy = @{ version = 1; activeCategories = @('Cpf','Cnpj','PaymentCard'); monitoredScopes = @{ extensions = @('.txt','.docx','.xlsx','.pdf'); destinationPaths = @('C:\Protected'); removableDrives = $false; networkPaths = $false }; failOpen = $false; auditOnly = $false; overrideEnabled = $false } | ConvertTo-Json -Depth 5
Set-Content -LiteralPath "$data\policy.json" -Value $policy -Encoding UTF8
& "$d\Protect-SafeUploadPolicy.ps1"
& "$d\Install-SafeUploadAgent.ps1" -ServiceExecutablePath "$agentDir\SafeUpload.Agent.Service.exe"
'INSTALL_DONE=True'
PS
grep -qx 'INSTALL_DONE=True' "$ev/$tag-install.txt" || { echo 'install failed'; exit 15; }
echo "== reboot"
remote <<<'& shutdown.exe /r /t 5 /c "demo install"' >/dev/null; sleep 60; wait_ssh || { echo 'guest did not return'; exit 17; }
remote <<'PS' | tee "$ev/$tag-ready.txt"
$ErrorActionPreference = 'Continue'
$ready = $false; $last = ''
for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
    try {
        $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'SafeUpload.Agent', [System.IO.Pipes.PipeDirection]::In)
        try { $c.Connect(5000); $last = (New-Object System.IO.StreamReader($c)).ReadLine() } finally { $c.Dispose() }
        if ($last -match '"admissionCoverage"\s*:\s*"Ready"') { $ready = $true }
    } catch { $last = 'ERR ' + $_.Exception.Message }
    if (-not $ready) { Start-Sleep -Seconds 5 }
}
'READY=' + $ready
'DRIVER_LOADED=' + [bool](fltmc.exe filters | Select-String SafeUpload)
PS
grep -qx 'READY=True' "$ev/$tag-ready.txt" || { echo 'agent never Ready (run disk kept for diagnosis)'; exit 19; }

echo "== replay Notepad/Word/Explorer-style operations"
remote <<'PS' | tee "$ev/$tag-smoke.txt"
$ErrorActionPreference = 'Continue'
$p = 'C:\Protected'
function Step([string]$name, [scriptblock]$body) {
    try { & $body; 'STEP ' + $name + ' = ok' } catch { 'STEP ' + $name + ' = ERROR ' + $_.Exception.Message }
}
function New-Docx([string]$path, [string]$text) {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $fs = [IO.File]::Open($path, 'CreateNew', 'ReadWrite', 'None')
    try {
        $zip = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
        $parts = [ordered]@{
            '[Content_Types].xml' = '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
            '_rels/.rels' = '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
            'word/document.xml' = '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>' + $text + '</w:t></w:r></w:p></w:body></w:document>'
        }
        foreach ($k in $parts.Keys) {
            $e = $zip.CreateEntry($k); $w = New-Object IO.StreamWriter($e.Open()); $w.Write($parts[$k]); $w.Dispose()
        }
        $zip.Dispose()
    } finally { $fs.Dispose() }
}
# Notepad-style: create/overwrite a .txt in place.
Step 'notepad-clean' { [IO.File]::WriteAllText("$p\notepad-clean.txt", 'Meeting notes, nothing sensitive.') }
Step 'notepad-cpf' { [IO.File]::WriteAllText("$p\notepad-cpf.txt", 'Cliente CPF: 529.982.247-25') }
Step 'notepad-resave' { [IO.File]::WriteAllText("$p\notepad-clean.txt", 'Meeting notes v2, still clean.') }
# Word-style: owner file, temp write, rename original away, rename temp into place, delete the old copy and the owner file.
$tmp = Join-Path $env:TEMP ('demo-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $tmp | Out-Null
New-Docx "$tmp\v1.docx" 'Relatorio trimestral sem dados pessoais.'
New-Docx "$tmp\v2.docx" 'Relatorio trimestral revisado, ainda limpo.'
New-Docx "$tmp\cpf.docx" 'Funcionario CPF 529.982.247-25'
Step 'word-first-save' { Copy-Item "$tmp\v1.docx" "$p\~WRD0000.tmp"; Rename-Item "$p\~WRD0000.tmp" 'report.docx' }
Step 'word-owner-file' { [IO.File]::WriteAllText("$p\~`$report.docx", 'owner'); (Get-Item "$p\~`$report.docx" -Force).Attributes = 'Hidden' }
Step 'word-save-temp' { Copy-Item "$tmp\v2.docx" "$p\~WRD0001.tmp" }
Step 'word-rename-old' { Rename-Item "$p\report.docx" '~WRL0001.tmp' }
Step 'word-rename-new' { Rename-Item "$p\~WRD0001.tmp" 'report.docx' }
Step 'word-delete-old' { Remove-Item "$p\~WRL0001.tmp" -Force }
Step 'word-close-owner' { Remove-Item "$p\~`$report.docx" -Force }
Step 'word-cpf-save' { Copy-Item "$tmp\cpf.docx" "$p\~WRD0002.tmp"; Rename-Item "$p\~WRD0002.tmp" 'secret.docx' }
# Explorer-style: copy in, rename, New Text Document then rename, new folder, delete.
[IO.File]::WriteAllText("$tmp\from-outside.txt", 'Copied from Documents, clean.')
Step 'explorer-copy-in' { Copy-Item "$tmp\from-outside.txt" "$p\copied.txt" }
Step 'explorer-rename' { Start-Sleep -Seconds 5; Rename-Item "$p\copied.txt" 'renamed.txt' }
Step 'explorer-new-text-document' { [IO.File]::WriteAllText("$p\New Text Document.txt", ''); Rename-Item "$p\New Text Document.txt" 'note.txt' }
Step 'explorer-new-folder' { New-Item -ItemType Directory "$p\New folder" | Out-Null }
Step 'explorer-delete' { Start-Sleep -Seconds 5; Remove-Item "$p\renamed.txt" -Force }
Start-Sleep -Seconds 15
'== final contents of C:\Protected'
Get-ChildItem -LiteralPath $p -Force | ForEach-Object {
    $text = ''
    if (-not $_.PSIsContainer -and $_.Extension -eq '.txt') { try { $text = [IO.File]::ReadAllText($_.FullName) } catch { $text = 'READ ERROR ' + $_.Exception.Message } }
    'ITEM ' + $_.Name + ' | ' + $_.Length + ' B | ' + $_.Attributes + ' | ' + $text
}
Remove-Item -LiteralPath $tmp -Recurse -Force
PS
echo "== handoff"
echo "Demo VM $dom is RUNNING on run disk '$tag' with the pair installed and C:\\Protected monitored (.txt .docx .xlsx .pdf; CPF, CNPJ, card)."
echo "Console: virt-manager -> $dom (user vika). Smoke results: $ev/$tag-smoke.txt. Discard afterwards: $0 --discard $tag"
