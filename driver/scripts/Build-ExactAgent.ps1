<# Builds/tests/publishes an exact agent archive in a fresh builder directory. Never installs it. #>
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9._-]{3,60}$')][string] $Label,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ArchiveSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ManifestSha256,
    [switch] $AdmissionEvidence
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69') {
    throw 'Wrong builder.'
}
# Two groups of agent unit tests need different accounts. The certificate-authority and TLS-inspection tests create
# current-user CNG keys, which fails with "Access denied" in the builder's SSH logon (an S4U logon has no DPAPI user
# secret) and works as SYSTEM. The hand-back tests model an unprivileged host and the product refuses to route a
# hand-back to SYSTEM, so they must run as the normal user. Every test runs exactly once, in the account it needs; the two
# trx files are merged into the single agent-tests.trx that the pair qualification reads.
function Merge-TrxFiles {
    param([Parameter(Mandatory)][string[]] $Paths, [Parameter(Mandatory)][string] $Destination)
    $ns = 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010'
    $documents = @()
    foreach ($path in $Paths) { $document = New-Object System.Xml.XmlDocument; $document.Load($path); $documents += $document }
    $first = $documents[0]
    $firstManager = New-Object System.Xml.XmlNamespaceManager($first.NameTable); $firstManager.AddNamespace('t', $ns)
    foreach ($section in 'Results', 'TestDefinitions', 'TestEntries') {
        $target = $first.SelectSingleNode('//t:' + $section, $firstManager)
        if ($null -eq $target) { throw ('TRX has no ' + $section + ' section.') }
        for ($index = 1; $index -lt $documents.Count; $index++) {
            $manager = New-Object System.Xml.XmlNamespaceManager($documents[$index].NameTable); $manager.AddNamespace('t', $ns)
            $source = $documents[$index].SelectSingleNode('//t:' + $section, $manager)
            if ($null -eq $source) { continue }
            foreach ($node in @($source.ChildNodes)) { [void]$target.AppendChild($first.ImportNode($node, $true)) }
        }
    }
    $summary = $first.SelectSingleNode('//t:ResultSummary', $firstManager)
    $counters = $first.SelectSingleNode('//t:ResultSummary/t:Counters', $firstManager)
    foreach ($name in 'total', 'executed', 'passed', 'failed', 'error', 'timeout', 'aborted', 'inconclusive', 'passedButRunAborted',
        'notRunnable', 'notExecuted', 'disconnected', 'warning', 'completed', 'inProgress', 'pending') {
        $sum = 0
        foreach ($document in $documents) {
            $manager = New-Object System.Xml.XmlNamespaceManager($document.NameTable); $manager.AddNamespace('t', $ns)
            $counter = $document.SelectSingleNode('//t:ResultSummary/t:Counters', $manager)
            if ($counter.HasAttribute($name)) { $sum += [int]$counter.GetAttribute($name) }
        }
        $counters.SetAttribute($name, [string]$sum)
    }
    if ([int]$counters.GetAttribute('failed') -gt 0 -or [int]$counters.GetAttribute('error') -gt 0) { $summary.SetAttribute('outcome', 'Failed') }
    $first.Save($Destination)
}
function Invoke-SystemProcess {
    param([Parameter(Mandatory)][string] $FilePath, [Parameter(Mandatory)][string] $ArgumentLine,
        [Parameter(Mandatory)][string] $WorkingDirectory, [Parameter(Mandatory)][string] $StdoutPath,
        [hashtable] $Environment = @{}, [int] $TimeoutMinutes = 30)
    $directory = [IO.Path]::GetDirectoryName($StdoutPath)
    $stamp = [guid]::NewGuid().ToString('N')
    $wrapper = Join-Path $directory ('system-run-' + $stamp + '.ps1')
    $exitFile = $wrapper + '.exit'
    $stderrPath = $StdoutPath + '.stderr'
    $environmentLines = @($Environment.GetEnumerator() | ForEach-Object { '$env:' + $_.Key + ' = ''' + ([string]$_.Value).Replace("'", "''") + '''' })
    # One statement per line: in PowerShell the comma binds tighter than +, so joining string pieces and list items in
    # one expression fuses neighbouring lines.
    $startLine = '$p = Start-Process -FilePath ''' + $FilePath + ''' -ArgumentList ''' + $ArgumentLine.Replace("'", "''") +
        ''' -WorkingDirectory ''' + $WorkingDirectory + ''' -RedirectStandardOutput ''' + $StdoutPath +
        ''' -RedirectStandardError ''' + $stderrPath + ''' -Wait -PassThru -WindowStyle Hidden'
    $exitLine = 'Set-Content -LiteralPath ''' + $exitFile + ''' -Value $p.ExitCode -Encoding ASCII'
    $body = @('$env:DOTNET_NOLOGO = ''1''; $env:DOTNET_CLI_TELEMETRY_OPTOUT = ''1''')
    $body += $environmentLines
    $body += $startLine
    $body += $exitLine
    Set-Content -LiteralPath $wrapper -Value $body -Encoding UTF8
    $taskName = 'SafeUpload-ExactAgentSystem-' + $stamp
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $wrapper + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes($TimeoutMinutes + 5))
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        $began = [DateTime]::UtcNow
        $deadline = $began.AddMinutes($TimeoutMinutes)
        # A wrapper that ends without writing its exit code (the task is back to Ready) fails fast, not after the timeout.
        do {
            Start-Sleep -Seconds 2
            $ended = ([DateTime]::UtcNow - $began).TotalSeconds -gt 15 -and (Get-ScheduledTask -TaskName $taskName).State -eq 'Ready'
        } while (-not (Test-Path -LiteralPath $exitFile) -and -not $ended -and [DateTime]::UtcNow -lt $deadline)
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path -LiteralPath $exitFile)) { throw 'The SYSTEM test run ended without an exit code or did not finish in time.' }
    $code = [int]([IO.File]::ReadAllText($exitFile).Trim())
    if (Test-Path -LiteralPath $stderrPath) { Get-Content -LiteralPath $stderrPath | Add-Content -LiteralPath $StdoutPath }
    Remove-Item -LiteralPath $wrapper, $exitFile, $stderrPath -ErrorAction SilentlyContinue
    return $code
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
    $featureArgs=@();if($AdmissionEvidence){$featureArgs=@("-p:SafeUploadAdmissionEvidence=true")}
    $summary += "admission_evidence=$($AdmissionEvidence.IsPresent)"
    $nativePreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
    # Build with warnings as errors in this session, then run the built test assembly in two groups (see above).
    & dotnet.exe build agente\SafeUpload.Agent.Tests\SafeUpload.Agent.Tests.csproj -c Release -warnaserror @featureArgs `
        > (Join-Path $out 'tests.txt') 2>&1
    $testExit = $LASTEXITCODE;$ErrorActionPreference=$nativePreference
    if ($testExit -eq 0) {
        $testDll = Get-ChildItem (Join-Path $src 'agente\SafeUpload.Agent.Tests\bin\Release') -Recurse -Filter 'SafeUpload.Agent.Tests.dll' | Select-Object -First 1
        if ($null -eq $testDll) { throw 'The built test assembly was not found.' }
        $systemGroup = 'FullyQualifiedName~CertificateAuthorityTests|FullyQualifiedName~TlsInspectionProxyTests'
        $userGroup = 'FullyQualifiedName!~CertificateAuthorityTests&FullyQualifiedName!~TlsInspectionProxyTests'
        $testsLog = Join-Path $out 'tests.txt'

        $nativePreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
        & dotnet.exe vstest $testDll.FullName "/TestCaseFilter:$userGroup" '/Logger:trx;LogFileName=agent-tests-user.trx' "/ResultsDirectory:$out" >> $testsLog 2>&1
        $userExit = $LASTEXITCODE;$ErrorActionPreference=$nativePreference

        $systemLog = Join-Path $out 'tests-system.txt'
        $systemExit = Invoke-SystemProcess -FilePath (Get-Command dotnet.exe).Source `
            -ArgumentLine ('vstest "' + $testDll.FullName + '" /TestCaseFilter:"' + $systemGroup + '" /Logger:"trx;LogFileName=agent-tests-system.trx" /ResultsDirectory:"' + $out + '"') `
            -WorkingDirectory $testDll.DirectoryName -StdoutPath $systemLog `
            -Environment @{ SAFEUPLOAD_MACHINE_TESTS = '1' }   # MachineFact tests (they add and remove a uniquely named test CA) are meant for this disposable VM
        Get-Content -LiteralPath $systemLog | Add-Content -LiteralPath $testsLog

        Merge-TrxFiles -Paths @((Join-Path $out 'agent-tests-user.trx'), (Join-Path $out 'agent-tests-system.trx')) -Destination (Join-Path $out 'agent-tests.trx')
        $testExit = if ($userExit -ne 0) { $userExit } else { $systemExit }
    }
    $testText = [IO.File]::ReadAllText((Join-Path $out 'tests.txt'))
    $testWarnings = [regex]::Matches($testText, '(?im)\bwarning\s+[A-Z]+\d+\b').Count
    $summary += "tests: exit=$testExit warnings=$testWarnings"
    if ($testExit -eq 0 -and $testWarnings -eq 0) {
        $publish = Join-Path $out 'publish'
        $nativePreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
        & dotnet.exe publish agente\SafeUpload.Agent.Service\SafeUpload.Agent.Service.csproj -c Release -r win-x64 `
            --self-contained true @featureArgs -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
            -warnaserror -o $publish > (Join-Path $out 'publish.txt') 2>&1
        $publishExit = $LASTEXITCODE;$ErrorActionPreference=$nativePreference
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
if ($testExit -ne 0 -or $testWarnings -ne 0 -or $publishExit -ne 0 -or $publishWarnings -ne 0 -or
    -not (Test-Path (Join-Path $out 'stage-service-publish.zip'))) { throw 'Exact agent build/test gate failed; inspect retained logs.' }
