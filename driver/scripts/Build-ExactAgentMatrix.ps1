<# Build-only validation of frozen agent sources. Never installs or starts the service. #>
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{3,60}$')][string] $Label,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ArchiveSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ManifestSha256,
    [switch] $DiagnosticCompileOnly
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69') {
    throw 'Wrong builder.'
}
$documents = 'C:\Users\vika\Documents'
$run = Join-Path $documents ('exact-agent-matrix-' + $Label)
$archive = $run + '.zip'
$manifest = $run + '.manifest'
if (Test-Path -LiteralPath $run) { throw 'Build directory already exists.' }
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $ArchiveSha256.ToUpperInvariant() -or
    (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ne $ManifestSha256.ToUpperInvariant()) {
    throw 'Frozen source hash mismatch.'
}
$expected = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$foldedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($line in [IO.File]::ReadAllLines($manifest)) {
    if ($line -notmatch '^([0-9a-f]{64})  (agente/.+)$') { throw 'Malformed source manifest.' }
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
    "ARCHIVE_SHA256=$($ArchiveSha256.ToUpperInvariant())", "MANIFEST_SHA256=$($ManifestSha256.ToUpperInvariant())")
$gatePassed = $false
$diagnosticFailed = $false
function Invoke-DotnetGate([string] $Name, [string[]] $Arguments) {
    $log = Join-Path $out ($Name + '.txt')
    # PS 5.1 turns redirected native stderr into ErrorRecords. Let the native
    # process finish so a failed test still writes its complete log and TRX.
    $previousErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & dotnet.exe @Arguments > $log 2>&1
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousErrorPreference }
    $text = [IO.File]::ReadAllText($log)
    $warnings = [regex]::Matches($text, '(?im)\bwarning\s+[A-Z]+\d+\b').Count
    $errors = [regex]::Matches($text, '(?im)\berror\s+[A-Z]+\d+\b').Count
    $script:summary += "$Name`: exit=$code warnings=$warnings errors=$errors"
    if ($code -ne 0 -or $warnings -ne 0 -or $errors -ne 0) {
        if ($DiagnosticCompileOnly) { $script:diagnosticFailed = $true }
        else { throw ('Build gate failed: ' + $Name) }
    }
}
Push-Location $src
try {
    & dotnet.exe --info > (Join-Path $out 'dotnet-info.txt') 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'SDK identity query failed.' }
    foreach ($mode in @('normal', 'feature')) {
        $feature = if ($mode -eq 'feature') { 'true' } else { 'false' }
        foreach ($configuration in @('Debug', 'Release')) {
            $name = $mode + '-' + $configuration.ToLowerInvariant()
            # Existing source-contract tests locate agente/scripts by walking
            # upward from their assembly. Keep that layout in a fresh verified
            # full source copy per profile, never mixing feature/normal outputs.
            $profileSource = Join-Path $out ('profile-src-' + $name)
            if (Test-Path -LiteralPath $profileSource) { throw 'Profile source already exists.' }
            [void][IO.Directory]::CreateDirectory($profileSource)
            Copy-Item -LiteralPath (Join-Path $src 'agente') -Destination $profileSource -Recurse
            foreach ($relative in $expected.Keys) {
                if ((Get-FileHash -LiteralPath (Join-Path $profileSource $relative) -Algorithm SHA256).Hash -ne $expected[$relative]) {
                    throw 'Profile source copy hash mismatch.'
                }
            }
            $common = @('-c', $configuration, '-warnaserror',
                ('-p:SafeUploadAdmissionEvidence=' + $feature),
                ('-p:SafeUploadOwnedWinFspPrototype=' + $feature))
            $serviceProject = Join-Path $profileSource 'agente\SafeUpload.Agent.Service\SafeUpload.Agent.Service.csproj'
            $testProject = Join-Path $profileSource 'agente\SafeUpload.Agent.Tests\SafeUpload.Agent.Tests.csproj'
            Invoke-DotnetGate ($name + '-build') (@('build', $serviceProject) + $common)
            if ($DiagnosticCompileOnly) {
                Invoke-DotnetGate ($name + '-test-build') (@('build', $testProject) + $common)
                foreach ($relative in $expected.Keys) {
                    if ((Get-FileHash -LiteralPath (Join-Path $profileSource $relative) -Algorithm SHA256).Hash -ne $expected[$relative]) {
                        throw 'Diagnostic profile source changed during compilation.'
                    }
                }
                continue
            }
            $results = Join-Path $out ($name + '-results')
            Invoke-DotnetGate ($name + '-tests') (@('test', $testProject,
                '--logger', 'trx;LogFileName=agent-tests.trx', '--results-directory', $results) + $common)
            [xml] $trx = [IO.File]::ReadAllText((Join-Path $results 'agent-tests.trx'))
            $counters = $trx.TestRun.ResultSummary.Counters
            if ([int]$counters.total -le 0 -or $counters.passed -ne $counters.total -or
                $counters.executed -ne $counters.total) { throw ('Incomplete test run: ' + $name) }
            foreach ($field in @('failed', 'error', 'timeout', 'aborted', 'notExecuted', 'inconclusive')) {
                if ([int]$counters.$field -ne 0) { throw ('Unsuccessful test run: ' + $name + '/' + $field) }
            }
            $summary += "$name`: tests_passed=$($counters.passed)"
            if ($configuration -eq 'Release') {
                $publish = Join-Path $out ($name + '-publish')
                Invoke-DotnetGate ($name + '-publish') (@('publish', $serviceProject,
                    '-r', 'win-x64', '--self-contained', 'true', '-p:PublishSingleFile=true',
                    '-p:IncludeNativeLibrariesForSelfExtract=true', '-o', $publish) + $common)
                Get-ChildItem -LiteralPath $publish -Recurse -File | Sort-Object FullName | ForEach-Object {
                    (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash + '  ' + $_.FullName.Substring($publish.Length + 1)
                } | Set-Content (Join-Path $out ($name + '-package-manifest.txt')) -Encoding UTF8
                $package = Join-Path $out ($name + '-service-publish.zip')
                [IO.Compression.ZipFile]::CreateFromDirectory($publish, $package)
                $summary += "$name`: package_sha256=$((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash)"
            }
            foreach ($relative in $expected.Keys) {
                if ((Get-FileHash -LiteralPath (Join-Path $profileSource $relative) -Algorithm SHA256).Hash -ne $expected[$relative]) {
                    throw 'Profile source changed during build.'
                }
            }
        }
    }
    # The build outputs live outside src; recheck all captured inputs after execution.
    foreach ($file in $seenFiles) {
        $relative = $file.FullName.Substring($src.Length + 1).Replace('\', '/')
        if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne $expected[$relative]) {
            throw 'Source changed during build.'
        }
    }
    $gatePassed = -not $diagnosticFailed
} finally {
    Pop-Location
    if ($DiagnosticCompileOnly) {
        $summary += "DiagnosticCompileGate=$gatePassed"
        $summary += 'TestsExecuted=False'
        $summary += 'AgentMatrixGate=False'
    } else { $summary += "AgentMatrixGate=$gatePassed" }
    $summary += 'BUILD_END_UTC=' + [DateTime]::UtcNow.ToString('o')
    $summary | Set-Content (Join-Path $out 'summary.txt') -Encoding UTF8
    $summary | Write-Output
}
if (-not $gatePassed) { throw 'Agent matrix gate incomplete.' }
