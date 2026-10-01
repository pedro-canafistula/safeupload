<# A writer exits while its writable file object remains alive in another app. #>
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StagedTestAgent.ps1')
$installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
$backup = 'C:\Users\vika\Documents\SafeUpload-original-before-duplicate.sys'
$expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$serviceDir = 'C:\Users\vika\Documents\stage-service-publish'
$root = 'C:\SafeUpload\Escopo Monitorado'
$journal = 'C:\ProgramData\SafeUpload\staging-journal'
$id = [guid]::NewGuid().ToString('N')
$target = Join-Path $root ('duplicate-' + $id + '.txt')
$control = Join-Path $env:TEMP ('safeupload-duplicate-' + $id)
$agent = $null
$receiver = $null
$owner = $null
$loaded = $false
$replaced = $false
$cleanup = @($target)
if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) { throw 'Unexpected original driver.' }
try {
    New-Item -ItemType Directory -Force -Path $root,$serviceDir | Out-Null
    & tar.exe -xf 'C:\Users\vika\Documents\stage-service-publish.zip' -C $serviceDir
    if ($LASTEXITCODE -ne 0) { throw 'Service extraction failed.' }
    Copy-Item $installed $backup -Force
    Copy-Item 'C:\Users\vika\Documents\SafeUpload-stage-prototype.sys' $installed -Force
    $replaced = $true
    & fltmc.exe load SafeUpload | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Driver load failed.' }
    $loaded = $true
    $agent = Start-StagedTestAgent $serviceDir 'C:\Users\vika\Documents\stage-duplicate-service'
    Start-Sleep -Seconds 2
    $receiveScript = @'
$ErrorActionPreference = 'Stop'
$control = '__CONTROL__'
for ($i = 0; $i -lt 200 -and -not (Test-Path ($control + '.handle')); $i++) { Start-Sleep -Milliseconds 100 }
$raw = [long](Get-Content -LiteralPath ($control + '.handle'))
$handle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle ([IntPtr]$raw),$true
$file = New-Object System.IO.FileStream $handle,([IO.FileAccess]::ReadWrite)
try {
    [IO.File]::WriteAllText($control + '.ready', 'ready')
    for ($i = 0; $i -lt 200 -and -not (Test-Path ($control + '.finish')); $i++) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path ($control + '.finish'))) { throw 'Receiver timed out.' }
    $bytes = [Text.Encoding]::UTF8.GetBytes('tail')
    $file.Write($bytes, 0, $bytes.Length)
    $file.Flush()
}
finally { $file.Dispose() }
[IO.File]::WriteAllText($control + '.done', 'done')
'@
    $receivePath = $control + '.receiver.ps1'
    Set-Content -LiteralPath $receivePath -Value ($receiveScript.Replace('__CONTROL__', $control)) -Encoding UTF8
    $receiver = Start-Process powershell.exe -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$receivePath) `
        -RedirectStandardError ($control + '.receiver.err') -RedirectStandardOutput ($control + '.receiver.out')
    $null = $receiver.Handle # Cache the process handle before Windows PowerShell loses ExitCode.
    $ownerScript = @'
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class StageDuplicate {
    [DllImport("kernel32.dll", SetLastError=true)] static extern SafeFileHandle OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,
        SafeFileHandle source, SafeFileHandle targetProcess, out IntPtr target, uint access, bool inherit, uint options);
    public static long Send(SafeFileHandle file, uint targetPid) {
        using (var process = OpenProcess(0x40, false, targetPid)) {
            if (process.IsInvalid) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            IntPtr target;
            if (!DuplicateHandle(GetCurrentProcess(), file, process, out target, 0, false, 2))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            return target.ToInt64();
        }
    }
}
"@
$file = [IO.File]::Open('__TARGET__', [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
try {
    $bytes = [Text.Encoding]::UTF8.GetBytes('base')
    $file.Write($bytes, 0, $bytes.Length)
    $file.Flush()
    $handle = [StageDuplicate]::Send($file.SafeFileHandle, __RECEIVER__)
    [IO.File]::WriteAllText('__CONTROL__.handle', $handle.ToString())
}
finally { $file.Dispose() }
'@
    $ownerPath = $control + '.owner.ps1'
    Set-Content -LiteralPath $ownerPath -Value ($ownerScript.Replace('__TARGET__',$target).Replace('__CONTROL__',$control).Replace('__RECEIVER__',$receiver.Id)) -Encoding UTF8
    $owner = Start-Process powershell.exe -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$ownerPath) `
        -RedirectStandardError ($control + '.owner.err') -RedirectStandardOutput ($control + '.owner.out')
    $null = $owner.Handle
    if (-not $owner.WaitForExit(30000) -or $owner.ExitCode -ne 0) {
        Get-Content -LiteralPath ($control + '.owner.err') | Out-Host
        throw 'The original writer did not exit successfully.'
    }
    for ($i = 0; $i -lt 100 -and -not (Test-Path ($control + '.ready')); $i++) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path ($control + '.ready'))) {
        Get-Content -LiteralPath ($control + '.receiver.err') | Out-Host
        throw 'The second app did not receive the staged handle.'
    }
    $entries = @(Get-ChildItem -LiteralPath $journal -Filter '*.json' |
        ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw | ConvertFrom-Json } |
        Where-Object { $_.Transfer.DestinationPath -eq $target })
    if ($entries.Count -ne 1) { throw 'Expected one duplicated-handle version.' }
    $manifest = Join-Path $journal (([guid]$entries[0].Transfer.TransferId).ToString('N') + '.json')
    $cleanup += @($manifest, $entries[0].Transfer.StagePath)
    Start-Sleep -Seconds 1
    $current = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    if ($current.State -ne 0 -or [IO.File]::Exists($target)) { throw 'Owner exit sealed a live duplicated writer.' }
    Write-Output 'OwnerExitedWithDuplicatedWriterUnsealed=True'
    [IO.File]::WriteAllText($control + '.finish', 'finish')
    if (-not $receiver.WaitForExit(10000) -or $receiver.ExitCode -ne 0) {
        Get-Content -LiteralPath ($control + '.receiver.err') | Out-Host
        throw 'The duplicate writer did not close successfully.'
    }
    $released = $false
    for ($i = 0; $i -lt 40 -and -not $released; $i++) {
        Start-Sleep -Milliseconds 250
        $released = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).State -eq 5
    }
    if (-not $released -or [IO.File]::ReadAllText($target) -ne 'basetail') { throw 'Final duplicate cleanup did not publish the exact complete version.' }
    Write-Output 'PublishedOnlyAfterDuplicateFinalClose=basetail'
}
finally {
    foreach ($process in @($owner,$receiver)) {
        if ($null -ne $process -and -not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            [void]$process.WaitForExit(10000)
        }
    }
    Stop-StagedTestAgent $agent
    if ($replaced) { Restore-StagedTestDriver $backup $loaded }
    if ((Get-FileHash $installed -Algorithm SHA256).Hash -ne $expected) { throw 'Original driver restoration failed.' }
    Remove-StagedTestFiles $cleanup
    $evidence = 'C:\Users\vika\Documents\stage-duplicate-evidence'
    New-Item -ItemType Directory -Path $evidence -Force | Out-Null
    Get-ChildItem -LiteralPath (Split-Path $control) -Filter ((Split-Path $control -Leaf) + '.*') |
        Copy-Item -Destination $evidence -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath (Split-Path $control) -Filter ((Split-Path $control -Leaf) + '.*') |
        Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Output 'OriginalDriverRestored=True'
}
