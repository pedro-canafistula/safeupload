<# Verifies the agent publish folder on the debuggee against the pinned package and, only if it differs, replaces it
   with a fresh extraction of that package. The damaged folder is renamed (kept on the guest), never deleted.
   Every extracted file is flushed to disk and read back, and the volume cache is written, so a later disk-only
   checkpoint cannot capture metadata without data. Run only from the experiment wrapper. #>
param([string] $ExpectedPackageSha256 = 'D887E0D7F38AD64AD40CEE18B841C6D38AD2BED4D6F760B1BDE4464927381997')
$ErrorActionPreference = 'Stop'
$documents = Join-Path $env:USERPROFILE 'Documents'
$zipPath = Join-Path $documents 'stage-service-publish.zip'
$target = Join-Path $documents 'stage-service-publish'
$staging = Join-Path $documents 'stage-service-publish.repair-new'
$damaged = Join-Path $documents ('stage-service-publish.damaged-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Get-StreamHash([IO.Stream] $Stream) { [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($Stream)) }
function Compare-Publish([string] $Directory) {
    $bad = 0; $total = 0
    $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName.EndsWith('/')) { continue }
            $total++
            $path = Join-Path $Directory ($entry.FullName -replace '/', '\')
            if (-not (Test-Path -LiteralPath $path)) { $bad++; continue }
            $s = $entry.Open(); $expected = Get-StreamHash $s; $s.Dispose()
            $f = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read); $actual = Get-StreamHash $f; $f.Dispose()
            if ($expected -ne $actual) { $bad++ }
        }
    }
    finally { $zip.Dispose() }
    [pscustomobject]@{ Total = $total; Bad = $bad }
}
if ((Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash -ne $ExpectedPackageSha256.ToUpperInvariant()) { throw 'Package hash mismatch.' }
'PackageSHA256=' + $ExpectedPackageSha256.ToUpperInvariant()
$before = Compare-Publish $target
"PublishBefore: entries=$($before.Total) differing=$($before.Bad)"
if ($before.Bad -eq 0) { 'Repair=not needed' }
else {
    if (Test-Path -LiteralPath $staging) { throw 'Staging folder already exists.' }
    [IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $staging)
    foreach ($file in Get-ChildItem -LiteralPath $staging -Recurse -File) {
        $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $stream.Flush($true); $stream.Dispose()
    }
    $stagingCheck = Compare-Publish $staging
    "StagingVerified: entries=$($stagingCheck.Total) differing=$($stagingCheck.Bad)"
    if ($stagingCheck.Bad -ne 0) { throw 'Fresh extraction does not match the package.' }
    Move-Item -LiteralPath $target -Destination $damaged
    Move-Item -LiteralPath $staging -Destination $target
    'DamagedFolderKeptAs=' + $damaged
}
try { Write-VolumeCache -DriveLetter C; 'VolumeCacheWritten=True' } catch { 'VolumeCacheWritten=False ' + $_.Exception.Message }
Start-Sleep -Seconds 3
$after = Compare-Publish $target
"PublishAfter: entries=$($after.Total) differing=$($after.Bad)"
$head = [IO.File]::ReadAllBytes((Join-Path $target 'SafeUpload.Agent.Service.exe'))[0..1]
'AgentExeHeader=' + [char]$head[0] + [char]$head[1]
'ServicePublishIntact=' + ($after.Bad -eq 0)
