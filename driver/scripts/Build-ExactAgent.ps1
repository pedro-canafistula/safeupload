<# Builds/tests/publishes an exact agent archive in a fresh builder directory. Never installs it. #>
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{3,60}$')][string] $Label,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ArchiveSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ManifestSha256
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69') {
    throw 'Wrong builder.'
}
$documents = 'C:\Users\vika\Documents'
$run = Join-Path $documents ('exact-agent-' + $Label)
$archive = $run + '.zip'
$manifest = $run + '.manifest'
if (Test-Path $run) { throw 'Exact agent child directory already exists.' }
if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne $ArchiveSha256.ToUpperInvariant() -or
    (Get-FileHash $manifest -Algorithm SHA256).Hash -ne $ManifestSha256.ToUpperInvariant()) { throw 'Agent source hash mismatch.' }
$out = Join-Path $run 'out'
$src = Join-Path $run 'src'
[void][IO.Directory]::CreateDirectory($out)
Expand-Archive -LiteralPath $archive -DestinationPath $src
$expected = @{}
foreach ($line in [IO.File]::ReadAllLines($manifest)) {
    $expected[$line.Substring(66).Replace('/', '\')] = $line.Substring(0,64).ToUpperInvariant()
}
$seen = 0
foreach ($file in Get-ChildItem $src -Recurse -File) {
    $relative = $file.FullName.Substring($src.Length + 1)
    if (-not $expected.ContainsKey($relative) -or
        (Get-FileHash $file.FullName -Algorithm SHA256).Hash -ne $expected[$relative]) { throw ('Agent manifest mismatch: ' + $relative) }
    ++$seen
}
if ($seen -ne $expected.Count) { throw 'Agent manifest file count mismatch.' }
$summary = @("LABEL=$Label", "BUILDER=$env:COMPUTERNAME",
    "ARCHIVE_SHA256=$($ArchiveSha256.ToUpperInvariant())", "MANIFEST_SHA256=$($ManifestSha256.ToUpperInvariant())",
    "SOURCE_MANIFEST_VERIFIED=$seen")
Push-Location $src
try {
    & dotnet.exe --info > (Join-Path $out 'dotnet-info.txt') 2>&1
    & dotnet.exe test agente\SafeUpload.Agent.Tests\SafeUpload.Agent.Tests.csproj -c Release -warnaserror `
        --logger 'trx;LogFileName=agent-tests.trx' --results-directory $out > (Join-Path $out 'tests.txt') 2>&1
    $testExit = $LASTEXITCODE
    $testText = [IO.File]::ReadAllText((Join-Path $out 'tests.txt'))
    $testWarnings = [regex]::Matches($testText, '(?im)\bwarning\s+[A-Z]+\d+\b').Count
    $summary += "tests: exit=$testExit warnings=$testWarnings"
    if ($testExit -eq 0 -and $testWarnings -eq 0) {
        $publish = Join-Path $out 'publish'
        & dotnet.exe publish agente\SafeUpload.Agent.Service\SafeUpload.Agent.Service.csproj -c Release -r win-x64 `
            --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
            -warnaserror -o $publish > (Join-Path $out 'publish.txt') 2>&1
        $publishExit = $LASTEXITCODE
        $publishText = [IO.File]::ReadAllText((Join-Path $out 'publish.txt'))
        $publishWarnings = [regex]::Matches($publishText, '(?im)\bwarning\s+[A-Z]+\d+\b').Count
        $summary += "publish: exit=$publishExit warnings=$publishWarnings"
        if ($publishExit -eq 0 -and $publishWarnings -eq 0) {
            $files = @(Get-ChildItem $publish -Recurse -File | Sort-Object FullName | ForEach-Object {
                (Get-FileHash $_.FullName -Algorithm SHA256).Hash + '  ' + $_.FullName.Substring($publish.Length + 1)
            })
            $files | Set-Content (Join-Path $out 'package-manifest.txt') -Encoding UTF8
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $package = Join-Path $out 'stage-service-publish.zip'
            [IO.Compression.ZipFile]::CreateFromDirectory($publish, $package)
            $summary += 'package_sha256=' + (Get-FileHash $package -Algorithm SHA256).Hash
            $summary += 'exe_sha256=' + (Get-FileHash (Join-Path $publish 'SafeUpload.Agent.Service.exe') -Algorithm SHA256).Hash
        }
    }
} finally {
    Pop-Location
    $summary += 'BUILD_END_UTC=' + [DateTime]::UtcNow.ToString('o')
    $summary | Set-Content (Join-Path $out 'summary.txt') -Encoding UTF8
    $summary | Write-Output
}
