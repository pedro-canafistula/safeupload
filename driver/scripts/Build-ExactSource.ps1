<#
Runs on the isolated Windows builder. Builds a git-archive of one exact commit in a fresh child directory:
verifies every extracted file against the host-produced manifest, builds the four driver configurations
(normal/feature x Debug/Release) with /warnaserror, PREfast (DriverRecommendedRules) and ApiValidator, builds the
Inspector with and without the feature define, test-signs the feature Debug SYS, and writes a summary.
Never installs or loads anything. Refuses to reuse an existing child directory.
#>
param(
    [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z0-9._-]{3,60}$')] [string] $Label,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F]{64}$')] [string] $ArchiveSha256,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-fA-F]{64}$')] [string] $ManifestSha256,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9A-Fa-f]{40}$')] [string] $CertificateThumbprint
)
$ErrorActionPreference = 'Stop'
$documents = 'C:\Users\vika\Documents'
$run = Join-Path $documents ('exact-' + $Label)
$archive = Join-Path $documents ('exact-' + $Label + '.zip')
$manifestFile = Join-Path $documents ('exact-' + $Label + '.manifest')
$msbuild = 'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe'
$rules = 'C:\Program Files (x86)\Windows Kits\10\CodeAnalysis\DriverRecommendedRules.ruleset'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe'

if (Test-Path -LiteralPath $run) { throw "Child directory already exists: $run" }
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $ArchiveSha256.ToUpperInvariant()) { throw 'Archive hash mismatch.' }
if ((Get-FileHash -LiteralPath $manifestFile -Algorithm SHA256).Hash -ne $ManifestSha256.ToUpperInvariant()) { throw 'Manifest hash mismatch.' }
$out = Join-Path $run 'out'
$src = Join-Path $run 'src'
[void][IO.Directory]::CreateDirectory($out)
Expand-Archive -LiteralPath $archive -DestinationPath $src -Force

# Every extracted file must match the manifest, and nothing else may exist.
$expected = @{}
foreach ($line in [IO.File]::ReadAllLines($manifestFile)) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $hash = $line.Substring(0, 64).ToUpperInvariant()
    $path = $line.Substring(66).Replace('/', '\')
    $expected[$path] = $hash
}
$seen = 0
foreach ($file in Get-ChildItem -LiteralPath $src -Recurse -File) {
    $relative = $file.FullName.Substring($src.Length + 1)
    if (-not $expected.ContainsKey($relative)) { throw "Unexpected extracted file: $relative" }
    if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $expected[$relative]) { throw "Hash mismatch: $relative" }
    $seen++
}
if ($seen -ne $expected.Count) { throw "Manifest lists $($expected.Count) files but $seen were extracted." }
'SOURCE_MANIFEST_VERIFIED=' + $seen + ' files'

$summary = New-Object System.Collections.ArrayList
Push-Location $src
try {
    foreach ($configuration in @('Debug', 'Release')) {
        foreach ($feature in @('false', 'true')) {
            $name = if ($feature -eq 'true') { 'owned-feature' } else { 'normal' }
            if ($configuration -eq 'Release') { $name += '-release' }
            $log = Join-Path $out ($name + '-wdk.txt')
            & $msbuild driver\SafeUpload.Minifilter\SafeUpload.Minifilter.vcxproj /t:Rebuild `
                "/p:Configuration=$configuration" /p:Platform=x64 /warnaserror "/p:SafeUploadStagingPrototype=$feature" `
                /p:RunCodeAnalysis=true /p:EnablePREfast=true "/p:CodeAnalysisRuleSet=$rules" > $log 2>&1
            $exit = $LASTEXITCODE
            $text = [IO.File]::ReadAllText($log)
            $w = ([regex]::Matches($text, '(?m)^\s*(\d+) Warning\(s\)') | ForEach-Object { $_.Groups[1].Value }) -join ','
            $e = ([regex]::Matches($text, '(?m)^\s*(\d+) Error\(s\)') | ForEach-Object { $_.Groups[1].Value }) -join ','
            $sys = "driver\SafeUpload.Minifilter\x64\$configuration\SafeUpload.sys"
            $artifactHash = 'NONE'
            if ($exit -eq 0 -and (Test-Path -LiteralPath $sys)) {
                Copy-Item -LiteralPath $sys -Destination (Join-Path $out ($name + '.sys')) -Force
                $artifactHash = (Get-FileHash -LiteralPath $sys -Algorithm SHA256).Hash
            }
            [void]$summary.Add("driver:$name : configuration=$configuration feature=$feature exit=$exit succeeded=$($text -match 'Build succeeded') warnings=$w errors=$e apivalidator=$($text -match 'ApiValidator') prefast=$($text -match 'DriverRecommendedRules') artifact_sha256=$artifactHash")
        }
    }
    foreach ($feature in @('false', 'true')) {
        $name = if ($feature -eq 'true') { 'inspector-feature-release' } else { 'inspector-normal-release' }
        $log = Join-Path $out ($name + '.txt')
        & $msbuild driver\SafeUpload.Inspector\SafeUpload.Inspector.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64 `
            /warnaserror "/p:SafeUploadStagingPrototype=$feature" > $log 2>&1
        $exit = $LASTEXITCODE
        $text = [IO.File]::ReadAllText($log)
        $w = ([regex]::Matches($text, '(?m)^\s*(\d+) Warning\(s\)') | ForEach-Object { $_.Groups[1].Value }) -join ','
        $e = ([regex]::Matches($text, '(?m)^\s*(\d+) Error\(s\)') | ForEach-Object { $_.Groups[1].Value }) -join ','
        $exe = 'driver\SafeUpload.Inspector\x64\Release\SafeUpload.Inspector.exe'
        $artifactHash = 'NONE'
        if ($exit -eq 0 -and (Test-Path -LiteralPath $exe)) {
            Copy-Item -LiteralPath $exe -Destination (Join-Path $out ($name + '.exe')) -Force
            $artifactHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        }
        [void]$summary.Add("$name : exit=$exit succeeded=$($text -match 'Build succeeded') warnings=$w errors=$e artifact_sha256=$artifactHash")
    }
    $fixture = Join-Path $src 'driver\SafeUpload.WriterFixture\WriterFixture.cs'
    if (Test-Path -LiteralPath $fixture) {
        $log = Join-Path $out 'writer-fixture.txt'
        $exe = Join-Path $out 'writer-fixture.exe'
        $csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        & $csc /nologo /target:exe /platform:x64 /warn:4 /warnaserror+ "/out:$exe" $fixture > $log 2>&1
        $exit=$LASTEXITCODE; $text=[IO.File]::ReadAllText($log)
        $warnings=[regex]::Matches($text,'(?im)warning CS[0-9]+').Count
        $errors=[regex]::Matches($text,'(?im)error CS[0-9]+').Count
        $hash=if($exit -eq 0){(Get-FileHash $exe -Algorithm SHA256).Hash}else{'NONE'}
        [void]$summary.Add("writer-fixture : exit=$exit succeeded=$($exit -eq 0) warnings=$warnings errors=$errors artifact_sha256=$hash")
    }

}
finally { Pop-Location }

$unsigned = Join-Path $out 'owned-feature.sys'
if (Test-Path -LiteralPath $unsigned) {
    $signed = Join-Path $out 'SafeUpload-stage-prototype.sys'
    Copy-Item -LiteralPath $unsigned -Destination $signed -Force
    & $signtool sign /fd sha256 /sha1 $CertificateThumbprint $signed > (Join-Path $out 'sign.txt') 2>&1
    $signExit = $LASTEXITCODE
    [void]$summary.Add("sign : exit=$signExit unsigned_sha256=$((Get-FileHash -LiteralPath $unsigned -Algorithm SHA256).Hash) signed_sha256=$((Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash) signer=$CertificateThumbprint")
}
else { [void]$summary.Add('sign : SKIPPED (no feature Debug SYS)') }

$header = @("LABEL=$Label", "ARCHIVE_SHA256=$($ArchiveSha256.ToUpperInvariant())", "MANIFEST_SHA256=$($ManifestSha256.ToUpperInvariant())",
    "BUILDER=$env:COMPUTERNAME", "BUILD_END_UTC=$([DateTime]::UtcNow.ToString('o'))")
($header + $summary.ToArray()) | Set-Content -LiteralPath (Join-Path $out 'summary.txt') -Encoding UTF8
Get-Content -LiteralPath (Join-Path $out 'summary.txt')
'EXACT_BUILD_DONE'
