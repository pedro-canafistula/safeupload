#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Runs the three minimum preventive checks on an already configured disposable Windows VM.
.DESCRIPTION
Requires the real gate, WinFsp, a LocalSystem agent in Drive mode and a local blocking policy.
Does not install components, edit policy, grant overrides or remove retained files. Leaves unique test files
and a JSON result for review. Run in an interactive administrator session, separately from the service.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Destination,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z]:\\$')][string] $DriveRoot,
    [Parameter(Mandatory = $true)][string] $ResultPath,
    [string] $PolicyPath = "$env:ProgramData\SafeUpload\policy.json",
    [ValidateRange(5, 60)][int] $TimeoutSeconds = 30
)
$ErrorActionPreference = 'Stop'
$ResultPath = [IO.Path]::GetFullPath($ResultPath)
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ResultPath))
$runId = [Guid]::NewGuid().ToString('N')
$result = [ordered]@{ passed = $false; runId = $runId; atUtc = [DateTime]::UtcNow.ToString('o'); checks = @() }
$client = $null
$reader = $null

function Check([string] $Name, [bool] $Passed) {
    $result.checks += [ordered]@{ name = $Name; passed = $Passed }
    if (-not $Passed) { throw "Check failed: $Name" }
}
function Read-Notification {
    $task = $reader.ReadLineAsync()
    if (-not $task.Wait($TimeoutSeconds * 1000)) { throw 'Notification timed out.' }
    $line = $task.GetAwaiter().GetResult()
    if ($null -eq $line) { throw 'Notification channel closed.' }
    return ($line | ConvertFrom-Json)
}
function Read-Events {
    $queue = Join-Path $env:ProgramData 'SafeUpload\queue.jsonl'
    if (-not (Test-Path -LiteralPath $queue)) { return }
    $stream = [IO.FileStream]::new($queue, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $events = [IO.StreamReader]::new($stream)
    try {
        if ($stream.Length -gt 16MB) { throw 'Use a disposable VM with a small audit queue for this test.' }
        while ($null -ne ($line = $events.ReadLine())) {
            try { $item = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
            if ($item.fileName -like "*-$runId.txt") { $item }
        }
    }
    finally { $events.Dispose() }
}
try {
    $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'"
    Check 'LocalSystem service running' ($service.State -eq 'Running' -and $service.StartName -eq 'LocalSystem')
    $result.serviceCommand = $service.PathName
    $process = Get-Process -Id $service.ProcessId
    $result.serviceSha256 = (Get-FileHash -LiteralPath $process.Path -Algorithm SHA256).Hash
    $serviceDirectory = [IO.Path]::GetDirectoryName($process.Path)
    $serviceDll = Join-Path $serviceDirectory 'SafeUpload.Agent.Service.dll'
    $result.serviceVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($serviceDll).ProductVersion
    $result.driveDllSha256 = (Get-FileHash -LiteralPath (Join-Path $serviceDirectory 'SafeUpload.Agent.Drive.dll') -Algorithm SHA256).Hash
    Check 'Local policy mode explicitly selected' ($service.PathName -match '(?:"--CentroAdministracao:BaseUrl="|--CentroAdministracao:BaseUrl=(?:""|(?=\s|$)))')
    $policyHash = (Get-FileHash -LiteralPath $PolicyPath -Algorithm SHA256).Hash
    $policy = Get-Content -LiteralPath $PolicyPath -Raw | ConvertFrom-Json
    $result.policySha256 = $policyHash
    $result.policyVersion = $policy.version
    $destinationPath = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
    Check 'Local CPF blocking policy without override' ($policy.activeCategories -contains 'Cpf' -and
        -not $policy.auditOnly -and -not $policy.overrideAllowed -and $policy.monitoredScopes.extensions -contains '.txt' -and
        @($policy.monitoredScopes.destinationPaths | Where-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') -eq $destinationPath }).Count -eq 1)
    $actor = (Get-Process -Id $PID).ProcessName
    Check 'Test process is inspected' ($policy.excludedProcesses -notcontains $actor -and $policy.excludedProcesses -notcontains "$actor.exe")
    Check 'Protected destination and drive exist' ((Test-Path -LiteralPath $destinationPath -PathType Container) -and (Test-Path -LiteralPath $DriveRoot))

    $client = [IO.Pipes.NamedPipeClientStream]::new('.', 'SafeUpload.Agent', [IO.Pipes.PipeDirection]::In, [IO.Pipes.PipeOptions]::Asynchronous)
    $client.Connect(5000)
    $reader = [IO.StreamReader]::new($client, [Text.UTF8Encoding]::new($false, $true))
    $status = Read-Notification
    Check 'Drive scope accepted by gate and mounts available' ($status.type -eq 'status' -and $status.protectionActive -and
        -not $status.auditOnly -and $status.policyVersion -eq $policy.version -and $status.driveProtection.gatePolicyApplied -and
        $status.driveProtection.requiredDrives -gt 0 -and $status.driveProtection.mountedDrives -eq $status.driveProtection.requiredDrives)
    $result.protection = $status.driveProtection
    $before = & "$PSScriptRoot\Get-SafeUploadDiagnostics.ps1" -Query counters
    $result.gateBefore = $before

    $cleanName = "safe-$runId.txt"
    $blockedName = "cpf-$runId.txt"
    $directName = "direct-$runId.txt"
    $clean = 'Synthetic report without sensitive data.'
    $utf8 = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $DriveRoot $cleanName), $clean, $utf8)
    $cleanTarget = Join-Path $destinationPath $cleanName
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $cleanTarget) -and $clock.Elapsed.TotalSeconds -lt $TimeoutSeconds) { Start-Sleep -Milliseconds 100 }
    Check 'Safe file published with exact bytes' ((Test-Path -LiteralPath $cleanTarget) -and [IO.File]::ReadAllText($cleanTarget) -ceq $clean)

    $blockedTarget = Join-Path $destinationPath $blockedName
    [IO.File]::WriteAllText((Join-Path $DriveRoot $blockedName), 'Synthetic CPF: 529.982.247-25', $utf8)
    $clock.Restart()
    $blocked = $null
    while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds -and $null -eq $blocked) {
        Check 'Sensitive version absent from destination while awaiting decision' (-not (Test-Path -LiteralPath $blockedTarget))
        $message = Read-Notification
        if ($message.type -eq 'transfer' -and $message.fileName -eq (Join-Path $DriveRoot $blockedName) -and $message.phase -eq 'Blocked') { $blocked = $message }
    }
    Check 'CPF block notification received with no override' ($null -ne $blocked -and -not $blocked.overrideAllowed -and
        @($blocked.findings | Where-Object { $_.category -eq 'Cpf' }).Count -gt 0)
    $result.blockEventId = $blocked.transferId
    Check 'Blocked bytes retained on protected drive' ((Test-Path -LiteralPath (Join-Path $DriveRoot $blockedName)) -and -not (Test-Path -LiteralPath $blockedTarget))

    $denied = $false
    try { [IO.File]::WriteAllText((Join-Path $destinationPath $directName), 'Direct write probe', $utf8) }
    catch { if ($_.Exception.GetBaseException() -is [UnauthorizedAccessException]) { $denied = $true } else { throw } }
    $after = & "$PSScriptRoot\Get-SafeUploadDiagnostics.ps1" -Query counters
    $result.gateAfter = $after
    Check 'Administrator direct write refused by real gate' ($denied -and $after.refused -gt $before.refused -and
        -not (Test-Path -LiteralPath (Join-Path $destinationPath $directName)))
    $clock.Restart()
    do {
        $audit = @(Read-Events)
        $safeEvent = @($audit | Where-Object { $_.fileName -eq $cleanName -and $_.verdict -eq 'Approved' -and $_.policyVersion -eq $policy.version })
        $blockEvent = @($audit | Where-Object { $_.eventId -eq $blocked.transferId -and $_.verdict -eq 'Blocked' -and $_.categories -contains 'Cpf' -and $_.policyVersion -eq $policy.version })
        if ($safeEvent.Count -gt 0 -and $blockEvent.Count -gt 0) { break }
        Start-Sleep -Milliseconds 100
    } while ($clock.Elapsed.TotalSeconds -lt $TimeoutSeconds)
    Check 'Publication and CPF decision audited under applied policy' ($safeEvent.Count -gt 0 -and $blockEvent.Count -gt 0)
    $result.safeEventId = $safeEvent[0].eventId
    Check 'Local policy bytes unchanged' ((Get-FileHash -LiteralPath $PolicyPath -Algorithm SHA256).Hash -eq $policyHash)
    Check 'Sensitive version still absent at end' (-not (Test-Path -LiteralPath $blockedTarget))
    $result.passed = $true
}
catch { $result.error = $_.Exception.Message; throw }
finally {
    if ($reader) { $reader.Dispose() }
    if ($client) { $client.Dispose() }
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($ResultPath), ($result | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
