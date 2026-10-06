<# Frozen native-host compile only. Never executes the host or extracted SDK programs. #>
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{3,60}$')][string] $Label,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ArchiveSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ManifestSha256,
    [Parameter(Mandatory)][string] $SdkRoot,
    [Parameter(Mandatory)][string] $SdkManifest,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $SdkManifestSha256
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69') {
    throw 'Wrong builder.'
}
$run = Join-Path 'C:\Users\vika\Documents' ('exact-owned-host-' + $Label)
$archive = $run + '.zip'
$manifest = $run + '.manifest'
if (Test-Path -LiteralPath $run) { throw 'Build directory already exists.' }
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $ArchiveSha256.ToUpperInvariant() -or
    (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ne $ManifestSha256.ToUpperInvariant() -or
    (Get-FileHash -LiteralPath $SdkManifest -Algorithm SHA256).Hash -ne $SdkManifestSha256.ToUpperInvariant()) {
    throw 'Pinned input hash mismatch.'
}
$sdkExpected = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
foreach ($line in [IO.File]::ReadAllLines($SdkManifest)) {
    if ($line -notmatch '^([0-9a-f]{64})  (inc/winfsp/[A-Za-z0-9._-]+\.h|lib/winfsp-x64\.lib)$') {
        throw 'Unexpected SDK compile input.'
    }
    $sdkExpected.Add($Matches[2], $Matches[1].ToUpperInvariant())
}
foreach ($required in @('inc/winfsp/winfsp.h', 'inc/winfsp/fsctl.h', 'lib/winfsp-x64.lib')) {
    if (-not $sdkExpected.ContainsKey($required)) { throw 'Missing SDK compile input.' }
}
function Confirm-SdkInputs {
    foreach ($relative in $sdkExpected.Keys) {
        $path = Join-Path $SdkRoot $relative
        if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $sdkExpected[$relative]) {
            throw 'SDK compile input changed.'
        }
    }
}
Confirm-SdkInputs
$expected = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$foldedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($line in [IO.File]::ReadAllLines($manifest)) {
    if ($line -notmatch '^([0-9a-f]{64})  (driver/SafeUpload\.OwnedFspHost/.+)$') { throw 'Malformed source manifest.' }
    $hash = $Matches[1].ToUpperInvariant()
    $relative = $Matches[2]
    foreach ($part in $relative.Split('/')) {
        if ($part -in @('', '.', '..') -or $part -match '[\x00-\x1f\\:*?<>|"]' -or
            $part -match '[ .]$' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
            throw 'Unsafe source manifest path.'
        }
    }
    if (-not $foldedPaths.Add($relative)) { throw 'Duplicate or case-colliding source manifest path.' }
    $expected.Add($relative, $hash)
}
if ($expected.Count -eq 0) { throw 'Empty source manifest.' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archive)
try {
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $zip.Entries) {
        if (-not $expected.ContainsKey($entry.FullName) -or -not $seen.Add($entry.FullName)) {
            throw 'Archive path is missing, duplicated or unexpected.'
        }
        if (($entry.ExternalAttributes -shr 16 -band 0xf000) -ne 0x8000) {
            throw 'Archive entry is not a regular file.'
        }
    }
    if ($seen.Count -ne $expected.Count) { throw 'Archive input count mismatch.' }
} finally { $zip.Dispose() }
$out = Join-Path $run 'out'
$src = Join-Path $run 'src'
[void][IO.Directory]::CreateDirectory($out)
[IO.Compression.ZipFile]::ExtractToDirectory($archive, $src)
$seenFiles = @(Get-ChildItem -LiteralPath $src -Recurse -File)
if ($seenFiles.Count -ne $expected.Count) { throw 'Extracted input count mismatch.' }
foreach ($file in $seenFiles) {
    $relative = $file.FullName.Substring($src.Length + 1).Replace('\', '/')
    if (-not $expected.ContainsKey($relative) -or
        (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $expected[$relative]) {
        throw 'Extracted input hash mismatch.'
    }
}
$summary = @("LABEL=$Label", "BUILDER=$env:COMPUTERNAME", "SOURCE_MANIFEST_VERIFIED=$($expected.Count)",
    "ARCHIVE_SHA256=$($ArchiveSha256.ToUpperInvariant())", "MANIFEST_SHA256=$($ManifestSha256.ToUpperInvariant())", "SDK_MANIFEST_SHA256=$($SdkManifestSha256.ToUpperInvariant())")
$gatePassed = $false
$compileFailed = $false
$msbuild = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
function Invoke-NativeToLog([string] $Executable, [string[]] $Arguments, [string] $Log) {
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) { throw 'Native build tool missing.' }
    $previousErrorPreference = $ErrorActionPreference
    try {
        # PS 5.1 converts redirected native stderr to ErrorRecords. Complete
        # the process and retain its actual stderr before evaluating its exit.
        $ErrorActionPreference = 'Continue'
        & $Executable @Arguments > $Log 2>&1
        $nativeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousErrorPreference }
    return $nativeExit
}
Push-Location $src
try {
    foreach ($configuration in @('Debug', 'Release')) {
        Confirm-SdkInputs
        $name = $configuration.ToLowerInvariant()
        $profileOut = Join-Path $out $name
        $profileObj = Join-Path $out ($name + '-obj')
        $log = Join-Path $out ($name + '-build.txt')
        $exit = Invoke-NativeToLog $msbuild @('driver\SafeUpload.OwnedFspHost\SafeUpload.OwnedFspHost.vcxproj',
            '/t:Rebuild', "/p:Configuration=$configuration", '/p:Platform=x64', '/warnaserror',
            '/p:SafeUploadOwnedWinFspPrototype=true', "/p:WinFspSdkRoot=$SdkRoot",
            "/p:OutDir=$profileOut\", "/p:IntDir=$profileObj\") $log
        $text = [IO.File]::ReadAllText($log)
        $warningCounts = @([regex]::Matches($text, '(?m)^\s*(\d+) Warning\(s\)') | ForEach-Object { [int]$_.Groups[1].Value })
        $errorCounts = @([regex]::Matches($text, '(?m)^\s*(\d+) Error\(s\)') | ForEach-Object { [int]$_.Groups[1].Value })
        $artifact = Join-Path $profileOut 'SafeUpload.OwnedFspHost.exe'
        $success = $exit -eq 0 -and $warningCounts.Count -eq 1 -and $errorCounts.Count -eq 1 -and
            $warningCounts[0] -eq 0 -and $errorCounts[0] -eq 0 -and (Test-Path -LiteralPath $artifact -PathType Leaf)
        $hash = if ($success) { (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash } else { 'NONE' }
        $summary += "$name`: exit=$exit succeeded=$success warnings=$($warningCounts -join ',') errors=$($errorCounts -join ',') artifact_sha256=$hash"
        if (-not $success) { $compileFailed = $true }
        Confirm-SdkInputs
    }
    foreach ($relative in $expected.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $src $relative) -Algorithm SHA256).Hash -ne $expected[$relative]) {
            throw 'Source changed during host build.'
        }
    }
    $gatePassed = -not $compileFailed
} finally {
    Pop-Location
    $summary += "NativeHostCompileGate=$gatePassed"
    $summary += 'HostExecuted=False'
    $summary += 'RuntimeInstalled=False'
    $summary += 'RuntimeQualified=False'
    $summary += 'BUILD_END_UTC=' + [DateTime]::UtcNow.ToString('o')
    $summary | Set-Content -LiteralPath (Join-Path $out 'summary.txt') -Encoding UTF8
    $summary | Write-Output
}
if (-not $gatePassed) { throw 'Native host compile gate incomplete.' }
