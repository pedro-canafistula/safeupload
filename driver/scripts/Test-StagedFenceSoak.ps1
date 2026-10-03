<# Load/unload soak for the mapped-writable stream fence, normally under the volatile Verifier (-Verifier).
   Each iteration: a fixture in the bootstrap scope is mapped writable with its handle closed, the feature
   driver loads (the pre-start scan registers it), fence status is read through the Inspector as SYSTEM,
   one protected open and one old-view write are attempted (both refused), the view is disposed and the
   driver is unloaded (the unload guard rescans, finds nothing mapped and allows it). Run only on the
   recorded isolated debuggee from the experiment wrapper. #>
param(
    [Parameter(Mandatory)] [string] $ExpectedFeatureSha256,
    [Parameter(Mandatory)] [string] $ExpectedInspectorSha256,
    [int] $Iterations = 5,
    [switch] $Verifier
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$documents = Join-Path $env:USERPROFILE 'Documents'
. (Join-Path $documents 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginal = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$expectedPolicy = '29DC8A341BD7C549996596D2477A0CCCAF19602C362A2167FB4FDD5C66663731'
$feature = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$inspector = Join-Path $documents 'SafeUpload.Inspector.input.exe'
$policy = 'C:\ProgramData\SafeUpload\policy.json'
$id = [guid]::NewGuid().ToString('N')
$scopeDirectory = Join-Path 'C:\SafeUpload\Escopo Monitorado' ('fence-soak-' + $id)
$backup = Join-Path $documents ('SafeUpload-original-before-fence-soak-' + $id + '.sys')
$changed = [Text.Encoding]::UTF8.GetBytes('SOAK WRITE ' + $id)
$loaded = $false; $replaced = $false; $verifierEnabled = $false; $scopeCreated = $false
$view = $null; $mapping = $null; $iterationsCompleted = 0

function Get-FenceStatus([string] $Label) {
    $cmdFile = Join-Path $documents ('fence-soak-' + $id + '.cmd')
    $cmdOut = Join-Path $documents ('fence-soak-' + $id + '.out')
    Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @('@echo off', ('"' + $inspector + '" --admission-fence-status'))
    $taskName = 'SafeUpload-StagedTest-FenceSoak-' + [guid]::NewGuid().ToString('N')
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c ""' + $cmdFile + '" > "' + $cmdOut + '" 2>&1"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(60))) | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 120; $i++) { Start-Sleep -Milliseconds 500; if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { break } }
        $text = if (Test-Path -LiteralPath $cmdOut) { (Get-Content -LiteralPath $cmdOut -Raw) -replace '\s+', ' ' } else { '(no output)' }
        "FenceStatus_$Label=" + $text.Trim()
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $cmdFile, $cmdOut -Force -ErrorAction SilentlyContinue
    }
}

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature driver hash mismatch.' }
if ((Get-FileHash -LiteralPath $inspector -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256.ToUpperInvariant()) { throw 'Inspector hash mismatch.' }
'Variant=fence-soak'
'Iterations=' + $Iterations
'FeatureSHA256=' + $ExpectedFeatureSha256.ToUpperInvariant()
try {
    [void][IO.Directory]::CreateDirectory($scopeDirectory); $scopeCreated = $true
    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Durable restoration backup mismatch.' }
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
        'VerifierEnabled=volatile flags 0x13B (special pool, IRQL, pool tracking, I/O, deadlock, DDI)'
    }
    for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
        $path = Join-Path $scopeDirectory ('soak-' + $iteration + '.maptest')
        [IO.File]::WriteAllBytes($path, (New-Object byte[] 4096))
        $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($stream, ('Local\SafeUpload-FenceSoak-' + $iteration + '-' + $id),
            [long]4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite, [IO.HandleInheritability]::None, $true)
        $view = $mapping.CreateViewAccessor(0, 4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
        $stream.Dispose()
        $watch = [Diagnostics.Stopwatch]::StartNew()
        & fltmc.exe load SafeUpload | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Feature filter load failed in iteration $iteration." }
        $loaded = $true
        "Iteration_$iteration" + "_LoadSeconds=" + [math]::Round($watch.Elapsed.TotalSeconds, 2)
        Get-FenceStatus ("Iteration$iteration")
        $open = try { $s = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite); $s.Dispose(); 'OPENED' } catch { 'REFUSED' }
        $write = try { $view.WriteArray(0, $changed, 0, $changed.Length); $view.Flush(); 'SUCCESS' } catch { 'REFUSED' }
        "Iteration_$iteration" + "_ProtectedOpen=$open"
        "Iteration_$iteration" + "_OldViewWrite=$write"
        try { $view.Dispose() } catch { }
        try { $mapping.Dispose() } catch { }
        $view = $null; $mapping = $null
        $unloaded = $false
        for ($attempt = 0; $attempt -lt 40 -and -not $unloaded; $attempt++) {
            & fltmc.exe unload SafeUpload 2>&1 | Out-Null
            $unloaded = ($LASTEXITCODE -eq 0)
            if (-not $unloaded) { Start-Sleep -Milliseconds 500 }
        }
        "Iteration_$iteration" + "_Unloaded=$unloaded"
        if (-not $unloaded) { throw "Unload refused in iteration $iteration." }
        $loaded = $false
        $iterationsCompleted = $iteration
    }
    'SoakComplete=' + $iterationsCompleted + '/' + $Iterations
}
finally {
    if ($null -ne $view) { try { $view.Dispose() } catch { } }
    if ($null -ne $mapping) { try { $mapping.Dispose() } catch { } }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    if ($scopeCreated -and (Test-Path -LiteralPath $scopeDirectory)) { Remove-Item -LiteralPath $scopeDirectory -Recurse -Force }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver was not restored.' }
    if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload filter remained loaded.' }
    'SoakRestoration=OriginalDriverRestored; FilterUnloaded; Verifier=' + $(if ($verifierEnabled) { 'removed' } else { 'not used' })
    'VariantComplete=fence-soak'
}
