#Requires -Version 5.1
<#
.SYNOPSIS
Checks preserved files against flat resumo.json manifests without running them.
.DESCRIPTION
Reads only manifest-listed regular files. A matching manifest is not proof of
authenticity, collection completeness, a new test result or driver qualification.
No VM, service, pipe or network access. OutputPath must be a new file.
#>
[CmdletBinding()]
param(
    [string[]]$ManifestPath,
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('ManifestPath')) {
    # PS5.1 may not initialize PSScriptRoot while evaluating parameter defaults.
    $ManifestPath = @(
        (Join-Path $PSScriptRoot '../evidencias/homologacao-win10-0114-20261024/resumo.json'),
        (Join-Path $PSScriptRoot '../evidencias/preparacao-par-m2-20261024/resumo.json')
    )
}
if ($OutputPath -and (Test-Path -LiteralPath $OutputPath)) { throw 'Output already exists.' }
if (-not $ManifestPath -or $ManifestPath.Count -eq 0) { throw 'At least one manifest is required.' }
$sets = @(
    foreach ($path in $ManifestPath) {
        $manifest = Get-Item -LiteralPath $path
        if ($manifest.PSIsContainer -or ($manifest.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Manifest must be a regular file.'
        }
        if ($manifest.Directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Manifest directory must not be a reparse point.'
        }
        $manifestHashBefore = (Get-FileHash -LiteralPath $manifest.FullName -Algorithm SHA256).Hash
        $data = Get-Content -LiteralPath $manifest.FullName -Raw | ConvertFrom-Json
        if ($null -eq $data.files -or $data.files -isnot [array] -or $data.files.Count -eq 0) {
            throw 'Manifest requires a nonempty files array.'
        }
        $seen = @{}
        $checks = @(
            foreach ($entry in $data.files) {
                # This format deliberately supports leaf names only, no traversal/ADS/globs.
                if ($entry.file -isnot [string] -or $entry.file -notmatch '^(?!\.{1,2}$)[^<>:"/\\|?*\x00-\x1f]+$' -or
                    $entry.file.EndsWith('.') -or $entry.file.EndsWith(' ') -or $seen.ContainsKey($entry.file)) {
                    throw 'Manifest has an invalid or duplicate leaf name.'
                }
                $seen[$entry.file] = $true
                if ($entry.sha256 -isnot [string] -or $entry.sha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
                    ($entry.bytes -isnot [int] -and $entry.bytes -isnot [long]) -or $entry.bytes -lt 0) {
                    throw 'Manifest requires a SHA-256 and nonnegative integer byte length.'
                }
                $file = Join-Path $manifest.DirectoryName $entry.file
                $status = 'missing'; $actualBytes = $null; $actualHash = $null
                if (Test-Path -LiteralPath $file) {
                    $item = Get-Item -LiteralPath $file -Force
                    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                        $status = 'not-regular-file'
                    } else {
                        $actualBytes = $item.Length
                        $actualHash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
                        $status = 'mismatch'
                        if ($actualBytes -eq $entry.bytes -and $actualHash -eq $entry.sha256) { $status = 'matched' }
                    }
                }
                [pscustomobject]@{file=$entry.file;status=$status;bytes=$actualBytes;sha256=$actualHash}
            }
        )
        $manifestHashAfter = (Get-FileHash -LiteralPath $manifest.FullName -Algorithm SHA256).Hash
        if ($manifestHashBefore -ne $manifestHashAfter) { throw 'Manifest changed during verification.' }
        [pscustomobject]@{
            evidenceSet=$manifest.Directory.Name
            manifestSha256=$manifestHashBefore
            checked=$checks.Count
            matched=@($checks | Where-Object status -eq 'matched').Count
            files=$checks
        }
    }
)
$failed = @($sets | Where-Object { $_.checked -ne $_.matched }).Count -gt 0
$receipt = [pscustomobject]@{
    schemaVersion=1
    collectedUtc=[DateTime]::UtcNow.ToString('o')
    status=$(if ($failed) { 'evidence-mismatch' } else { 'preserved-evidence-matched' })
    qualificationGranted=$false
    verifierSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    powerShellVersion=$PSVersionTable.PSVersion.ToString()
    manifests=$sets
}
$json = $receipt | ConvertTo-Json -Depth 10
if ($OutputPath) {
    $stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
    } finally { $stream.Dispose() }
}
$json
if ($failed) { throw 'Preserved evidence mismatch; see receipt. No qualification granted.' }
