#Requires -Version 5.1
[CmdletBinding()]
param([string]$ResultsPath)
$ErrorActionPreference = 'Stop'
$verifier = Join-Path $PSScriptRoot 'Test-PreservedEvidence.ps1'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('safeupload-evidence-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixture | Out-Null
$manifest = Join-Path $fixture 'resumo.json'
$sample = Join-Path $fixture 'sample.bin'
$results = [Collections.Generic.List[object]]::new()
function Reset-Fixture {
    [IO.File]::WriteAllBytes($sample, [byte[]]@(0,1,2,255))
    $entry = [pscustomobject]@{file='sample.bin';bytes=4;sha256=(Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash}
    [pscustomobject]@{files=@($entry)} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding UTF8
}
function Require([bool]$condition) { if (-not $condition) { throw 'Assertion failed.' } }
function Reject([scriptblock]$operation) {
    $rejected = $false
    try { & $operation | Out-Null } catch { $rejected = $true }
    Require $rejected
}
function Case([string]$name, [scriptblock]$operation) {
    Reset-Fixture
    try { & $operation | Out-Null; $results.Add([pscustomobject]@{name=$name;passed=$true}) }
    catch { $results.Add([pscustomobject]@{name=$name;passed=$false;error=$_.Exception.Message}) }
}
Case 'Regular bytes match and qualify nothing' {
    $r = & $verifier -ManifestPath @($manifest) | ConvertFrom-Json
    Require ($r.status -eq 'preserved-evidence-matched' -and $r.qualificationGranted -eq $false -and $r.manifests[0].matched -eq 1)
}
Case 'Same-length tampering fails and retains mismatch receipt' {
    [IO.File]::WriteAllBytes($sample, [byte[]]@(0,1,3,255))
    $output = Join-Path $fixture 'tampered.json'
    Reject { & $verifier -ManifestPath @($manifest) -OutputPath $output }
    $r = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    Require ($r.status -eq 'evidence-mismatch' -and $r.manifests[0].files[0].status -eq 'mismatch')
}
Case 'Missing file fails' {
    $m = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    $m.files[0].file='absent.bin'
    $m | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding UTF8
    Reject { & $verifier -ManifestPath @($manifest) }
}
Case 'Traversal is rejected before creating a receipt' {
    $m = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    $m.files[0].file='../outside.bin'
    $m | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding UTF8
    $output = Join-Path $fixture 'invalid.json'
    Reject { & $verifier -ManifestPath @($manifest) -OutputPath $output }
    Require (-not (Test-Path -LiteralPath $output))
}
Case 'Empty manifest and duplicate names are rejected' {
    '{"files":[]}' | Set-Content -LiteralPath $manifest -Encoding UTF8
    Reject { & $verifier -ManifestPath @($manifest) }
    Reset-Fixture
    $m = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    $m.files=@($m.files[0],$m.files[0])
    $m | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding UTF8
    Reject { & $verifier -ManifestPath @($manifest) }
}
Case 'Existing output remains byte-identical' {
    $before=(Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash
    Reject { & $verifier -ManifestPath @($manifest) -OutputPath $sample }
    Require ((Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash -eq $before)
}
$json = [pscustomobject]@{fixtureDirectory=$fixture;results=@($results);passed=@($results | Where-Object passed).Count;total=$results.Count} | ConvertTo-Json -Depth 5
if ($ResultsPath) {
    $stream = [IO.File]::Open($ResultsPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json); $stream.Write($bytes,0,$bytes.Length) }
    finally { $stream.Dispose() }
}
$json
if (@($results | Where-Object { -not $_.passed }).Count) { throw 'Evidence verifier contracts failed.' }
# Fixtures are intentionally retained for inspection; no recursive cleanup.
