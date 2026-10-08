<# Late attachment. Run only on the recorded isolated WIN10-DEBUGGED VM from the experiment wrapper. With the feature driver
   loaded, the filter is detached from C:, a writable mapping of a file in the bootstrap scope is created while NO filter is
   attached (nothing can see it), the filter is attached again, and after a short settle time a write+flush through the old
   view must be refused (the InstanceSetup-triggered fence refresh registered the stream). A driver without the trigger lets
   the write through. The fence counters are read through the Inspector as SYSTEM. #>
param(
    [Parameter(Mandatory)] [string] $ExpectedFeatureSha256,
    [Parameter(Mandatory)] [string] $ExpectedInspectorSha256,
    [int] $SettleMs = 2500,
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
$scopeDirectory = Join-Path 'C:\SafeUpload\Escopo Monitorado' ('fence-late-' + $id)
$backup = Join-Path $documents ('SafeUpload-original-before-fence-late-' + $id + '.sys')
$marker = [Text.Encoding]::UTF8.GetBytes('LATE ATTACH WRITE ' + $id)
$loaded = $false; $replaced = $false; $verifierEnabled = $false; $scopeCreated = $false
$stream = $null; $mapping = $null; $view = $null

function Invoke-Inspector([string] $Argument) {
    $cmdFile = Join-Path $documents ('fence-late-' + $id + '.cmd'); $cmdOut = Join-Path $documents ('fence-late-' + $id + '.out')
    Set-Content -LiteralPath $cmdFile -Encoding ASCII -Value @('@echo off', ('"' + $inspector + '" ' + $Argument))
    $taskName = 'SafeUpload-StagedTest-FenceLate-' + [guid]::NewGuid().ToString('N')
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c ""' + $cmdFile + '" > "' + $cmdOut + '" 2>&1"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromSeconds(60))) | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 120; $i++) { Start-Sleep -Milliseconds 500; if ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') { break } }
        if (Test-Path -LiteralPath $cmdOut) { return ((Get-Content -LiteralPath $cmdOut -Raw) -replace '\s+', ' ').Trim() } else { return '(no output)' }
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $cmdFile, $cmdOut -Force -ErrorAction SilentlyContinue
    }
}
function Get-Counter-Value([string] $Json, [string] $Name) { if ($Json -match ('"' + $Name + '":(\d+)')) { [int64]$Matches[1] } else { -1 } }

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') { throw 'Wrong debuggee.' }
if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Original driver hash mismatch.' }
if ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s') { throw 'SafeUpload must be unloaded at baseline.' }
if ((Get-FileHash -LiteralPath $policy -Algorithm SHA256).Hash -ne $expectedPolicy) { throw 'Original policy hash mismatch.' }
if ((Get-FileHash -LiteralPath $feature -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) { throw 'Feature driver hash mismatch.' }
if ((Get-FileHash -LiteralPath $inspector -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256.ToUpperInvariant()) { throw 'Inspector hash mismatch.' }
'Variant=late-attach'
'FeatureSHA256=' + $ExpectedFeatureSha256.ToUpperInvariant()
try {
    [void][IO.Directory]::CreateDirectory($scopeDirectory); $scopeCreated = $true
    $path = Join-Path $scopeDirectory 'late.maptest'
    $bytes = New-Object byte[] 4096; [Text.Encoding]::UTF8.GetBytes('BASELINE ' + $id).CopyTo($bytes, 0); [IO.File]::WriteAllBytes($path, $bytes)
    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginal) { throw 'Durable restoration backup mismatch.' }
    $replaced = $true
    Copy-Item -LiteralPath $feature -Destination $installed -Force
    if ($Verifier) {
        & verifier.exe /volatile /flags 0x13B /adddriver SafeUpload.sys | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Verifier enable failed.' }
        $verifierEnabled = $true
        'VerifierEnabled=volatile flags 0x13B'
    }
    & fltmc.exe load SafeUpload | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Feature filter load failed.' }
    $loaded = $true
    'InstancesAfterLoad=' + (@(& fltmc.exe instances -f SafeUpload 2>&1 | Where-Object { $_ -match 'C:' }).Count)
    $detach = (& fltmc.exe detach SafeUpload C: 2>&1 | Out-String) -replace '\s+', ' '
    'DetachExit=' + $LASTEXITCODE + ' output=' + $detach.Trim()
    $stillAttached = @(& fltmc.exe instances -f SafeUpload 2>&1 | Where-Object { $_ -match 'C:' }).Count
    'InstancesOnCAfterDetach=' + $stillAttached
    if ($stillAttached -ne 0) { throw 'The filter could not be detached from C:, the late-attach scenario cannot be built.' }
    # No filter is attached to C: now: this mapping is invisible to every scan.
    $stream = [IO.FileStream]::new($path, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    $mapping = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($stream, ('Local\SafeUpload-Late-' + $id), [long]4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite, [IO.HandleInheritability]::None, $true)
    $view = $mapping.CreateViewAccessor(0, 4096, [IO.MemoryMappedFiles.MemoryMappedFileAccess]::ReadWrite)
    $stream.Dispose(); $stream = $null
    $attach = (& fltmc.exe attach SafeUpload C: 2>&1 | Out-String) -replace '\s+', ' '
    'AttachExit=' + $LASTEXITCODE + ' output=' + $attach.Trim()
    Start-Sleep -Milliseconds $SettleMs
    $json = Invoke-Inspector '--admission-fence-status'
    'Status_AfterAttach=' + $json
    'LateRefreshesQueued=' + (Get-Counter-Value $json 'lateRefreshesQueued') + ' entries=' + (Get-Counter-Value $json 'entries')
    $write = try { $view.WriteArray(0, $marker, 0, $marker.Length); $view.Flush(); 'SUCCESS' } catch { 'REFUSED: ' + $_.Exception.Message }
    'LateAttachWriteAndFlush=' + $write
    'LateAttach=' + $(if ($write -eq 'SUCCESS') { 'REPRODUCED' } else { 'BLOCKED' })
}
catch { 'ScriptError=' + $_.Exception.Message + ' (line ' + $_.InvocationInfo.ScriptLineNumber + ')' }
finally {
    if ($null -ne $view) { try { $view.Dispose() } catch { } }
    if ($null -ne $mapping) { try { $mapping.Dispose() } catch { } }
    if ($null -ne $stream) { $stream.Dispose() }
    if ($loaded) {
        if (-not (@(& fltmc.exe instances -f SafeUpload 2>&1 | Where-Object { $_ -match 'C:' }).Count)) { & fltmc.exe attach SafeUpload C: 2>&1 | Out-Null }
        $unloaded = $false
        for ($attempt = 0; $attempt -lt 40 -and -not $unloaded; $attempt++) { & fltmc.exe unload SafeUpload 2>&1 | Out-Null; $unloaded = ($LASTEXITCODE -eq 0); if (-not $unloaded) { Start-Sleep -Milliseconds 500 } }
        $loaded = -not $unloaded
    }
    if ($replaced) { Restore-StagedTestDriver $backup $loaded $verifierEnabled }
    if ($scopeCreated -and (Test-Path -LiteralPath $scopeDirectory)) { try { Remove-Item -LiteralPath $scopeDirectory -Recurse -Force } catch { 'FixtureRemovalError=' + $_.Exception.Message } }
    if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
    'LateRestoration=OriginalDriverRestored; FilterUnloaded=' + (-not ((& fltmc.exe filters | Out-String) -match '(?m)^SafeUpload\s'))
    'VariantComplete=late-attach'
}
