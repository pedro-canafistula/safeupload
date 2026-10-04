# Shared test helpers. The agent runs as LocalSystem so its private backing
# files never grant the writing user's SID independent access.
function Save-StagedVerifierEvidence {
    if ([string]::IsNullOrEmpty($env:SAFEUPLOAD_STAGED_VERIFIER_LOG)) { return }
    $result = & verifier.exe /query 2>&1
    $result | Set-Content -LiteralPath $env:SAFEUPLOAD_STAGED_VERIFIER_LOG -Encoding UTF8
}

function Start-StagedTestAgent([string] $ServiceDir, [string] $LogPrefix,
    [string] $ExecutableName = 'SafeUpload.Agent.Service.exe', [string] $Arguments = '') {
    if ($ExecutableName -eq 'SafeUpload.Agent.Service.exe') {
        $serviceName = 'SafeUploadAgent'
        $serviceKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
        $serviceRegistryPath = 'SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
        $serviceExists = Test-Path -LiteralPath $serviceKeyPath
        $original = $null
        if ($serviceExists) {
            $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
            if ($service.State -ne 'Stopped') { throw 'SafeUploadAgent service must be stopped before a test launch.' }
            $key = Get-Item -LiteralPath $serviceKeyPath
            $values = Get-ItemProperty -LiteralPath $serviceKeyPath
            $original = [ordered]@{
                ImagePath = $values.ImagePath
                ImagePathKind = $key.GetValueKind('ImagePath').ToString()
                Start = [int]$values.Start
                ObjectName = [string]$values.ObjectName
                ServiceSidType = if ($null -eq $values.PSObject.Properties['ServiceSidType']) { 0 } else { [int]$values.ServiceSidType }
            }
        }

        if ([IO.Path]::GetFileName($ExecutableName) -ne $ExecutableName) { throw 'Test executable must be inside its publish folder.' }
        $exe = Join-Path $ServiceDir $ExecutableName
        $header = [byte[]]::new(2)
        $headerStream = [IO.File]::Open($exe, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try { [void]$headerStream.Read($header, 0, 2) } finally { $headerStream.Dispose() }
        if ($header[0] -ne 0x4D -or $header[1] -ne 0x5A) { throw 'Agent executable has no PE header (zero-filled or damaged publish folder); repair it from the pinned package.' }

        $binaryPath = '"' + $exe + '" --Interception:Mode=Minifilter --Interception:StagingPrototype=true'
        if (-not [string]::IsNullOrWhiteSpace($Arguments)) { $binaryPath += ' ' + $Arguments }
        $created = $false
        try {
            if ($serviceExists) {
                & sc.exe config $serviceName binPath= $binaryPath start= demand obj= LocalSystem | Out-Host
            }
            else {
                & sc.exe create $serviceName binPath= $binaryPath start= demand obj= LocalSystem | Out-Host
                $created = $true
            }
            if ($LASTEXITCODE -ne 0) { throw "Could not register test SafeUploadAgent service (sc.exe $LASTEXITCODE)." }
            & sc.exe sidtype $serviceName unrestricted | Out-Host
            if ($LASTEXITCODE -ne 0) { throw 'Could not enable the SafeUploadAgent service SID.' }
            $sidType = (& sc.exe qsidtype $serviceName 2>&1 | Out-String)
            if ($LASTEXITCODE -ne 0 -or $sidType -notmatch 'SERVICE_SID_TYPE_UNRESTRICTED') {
                throw "SafeUploadAgent does not have an unrestricted service SID: $sidType"
            }
            & sc.exe start $serviceName | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "Could not start SafeUploadAgent (sc.exe $LASTEXITCODE)." }

            $service = $null
            for ($attempt = 0; $attempt -lt 120; $attempt++) {
                $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
                if ($null -ne $service -and $service.State -eq 'Running' -and $service.ProcessId -ne 0) { break }
                Start-Sleep -Milliseconds 250
            }
            if ($null -eq $service -or $service.State -ne 'Running' -or $service.ProcessId -eq 0) {
                throw 'SafeUploadAgent did not reach Running state.'
            }
            $process = Get-Process -Id ([int]$service.ProcessId) -ErrorAction Stop
            return [pscustomobject]@{
                IsService = $true
                ServiceName = $serviceName
                ServiceCreated = $created
                OriginalService = $original
                Process = $process
                LogPrefix = $LogPrefix
            }
        }
        catch {
            try {
                & sc.exe stop $serviceName | Out-Null
                Start-Sleep -Milliseconds 500
                if ($created) { & sc.exe delete $serviceName | Out-Null }
                elseif ($serviceExists) { Restore-StagedAgentService $serviceName $serviceKeyPath $original }
            } catch { }
            throw
        }
    }

    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-StagedTest-' + $id
    $launcher = Join-Path $env:TEMP ('SafeUpload-agent-' + $id + '.ps1')
    $pidFile = $launcher + '.pid'
    if ([IO.Path]::GetFileName($ExecutableName) -ne $ExecutableName) { throw 'Test executable must be inside its publish folder.' }
    $exe = Join-Path $ServiceDir $ExecutableName
    $header = [byte[]]::new(2)
    $headerStream = [IO.File]::Open($exe, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try { [void]$headerStream.Read($header, 0, 2) } finally { $headerStream.Dispose() }
    if ($header[0] -ne 0x4D -or $header[1] -ne 0x5A) { throw 'Agent executable has no PE header (zero-filled or damaged publish folder); repair it from the pinned package.' }
    $script = @'
$ErrorActionPreference = 'Stop'
$env:Interception__Mode = 'Minifilter'
$env:Interception__StagingPrototype = 'true'
$start = @{ FilePath = '__EXE__'; PassThru = $true; WindowStyle = 'Hidden';
    RedirectStandardOutput = '__LOG__-out.log'; RedirectStandardError = '__LOG__-err.log' }
if ('__ARGUMENTS__'.Length -ne 0) { $start.ArgumentList = '__ARGUMENTS__' }
$process = Start-Process @start
Set-Content -LiteralPath '__PID__' -Value $process.Id
$process.WaitForExit()
'@
    $script = $script.Replace('__EXE__', $exe).Replace('__LOG__', $LogPrefix).Replace('__PID__', $pidFile)
    $script = $script.Replace('__ARGUMENTS__', $Arguments.Replace("'", "''"))
    Set-Content -LiteralPath $launcher -Value $script -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($attempt = 0; $attempt -lt 240 -and -not (Test-Path $pidFile); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path $pidFile)) { throw 'LocalSystem test agent did not launch.' }
        $process = Get-Process -Id ([int](Get-Content -LiteralPath $pidFile)) -ErrorAction Stop
        return [pscustomobject]@{ TaskName = $taskName; Launcher = $launcher; PidFile = $pidFile; Process = $process }
    }
    catch {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $launcher,$pidFile -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Stop-StagedTestAgent($Agent) {
    if ($null -eq $Agent) { return }
    if ($Agent.IsService) {
        if (-not $Agent.Process.HasExited) {
            & sc.exe stop $Agent.ServiceName | Out-Host
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1062) { throw "Could not stop test service (sc.exe $LASTEXITCODE)." }
            for ($attempt = 0; $attempt -lt 80; $attempt++) {
                $service = Get-CimInstance Win32_Service -Filter "Name='$($Agent.ServiceName)'" -ErrorAction SilentlyContinue
                if ($null -eq $service -or $service.State -eq 'Stopped') { break }
                Start-Sleep -Milliseconds 250
            }
            if ($null -ne $service -and $service.State -ne 'Stopped') {
                Stop-Process -Id $Agent.Process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        if ($Agent.ServiceCreated) {
            & sc.exe delete $Agent.ServiceName | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "Could not remove test SafeUploadAgent service (sc.exe $LASTEXITCODE)." }
        }
        else {
            $serviceKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
            Restore-StagedAgentService $Agent.ServiceName $serviceKeyPath $Agent.OriginalService
        }
        return
    }
    Stop-ScheduledTask -TaskName $Agent.TaskName -ErrorAction SilentlyContinue
    if (-not $Agent.Process.HasExited) {
        Stop-Process -Id $Agent.Process.Id -Force -ErrorAction SilentlyContinue
        [void]$Agent.Process.WaitForExit(10000)
    }
    Unregister-ScheduledTask -TaskName $Agent.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Agent.Launcher,$Agent.PidFile -Force -ErrorAction SilentlyContinue
}

function Restore-StagedAgentService([string] $ServiceName, [string] $ServiceKeyPath, $Original) {
    if ($null -eq $Original) { return }
    $startName = switch ([int]$Original.Start) {
        2 { 'auto' }
        4 { 'disabled' }
        default { 'demand' }
    }
    $objectName = if ([string]::IsNullOrWhiteSpace([string]$Original.ObjectName)) { 'LocalSystem' } else { [string]$Original.ObjectName }
    & sc.exe config $ServiceName binPath= $Original.ImagePath start= $startName obj= $objectName | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not restore the prior SafeUploadAgent configuration (sc.exe $LASTEXITCODE)." }
    $sidTypeName = switch ([int]$Original.ServiceSidType) {
        1 { 'unrestricted' }
        3 { 'restricted' }
        default { 'none' }
    }
    & sc.exe sidtype $ServiceName $sidTypeName | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not restore the prior service SID type (sc.exe $LASTEXITCODE)." }
    $key = Get-Item -LiteralPath $ServiceKeyPath
    $valueKind = [Enum]::Parse([Microsoft.Win32.RegistryValueKind], [string]$Original.ImagePathKind)
    $key.SetValue('ImagePath', [string]$Original.ImagePath, $valueKind)
    $key.SetValue('Start', [int]$Original.Start, [Microsoft.Win32.RegistryValueKind]::DWord)
    $key.SetValue('ObjectName', $objectName, [Microsoft.Win32.RegistryValueKind]::String)
}

function Remove-StagedTestFiles([string[]] $Paths) {
    $pathsToDelete = @($Paths | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)
    if ($pathsToDelete.Count -eq 0) { return }
    $id = [guid]::NewGuid().ToString('N')
    $taskName = 'SafeUpload-StagedCleanup-' + $id
    $launcher = Join-Path $env:TEMP ('SafeUpload-cleanup-' + $id + '.ps1')
    $manifest = $launcher + '.json'
    $done = $launcher + '.done'
    ConvertTo-Json -InputObject $pathsToDelete | Set-Content -LiteralPath $manifest -Encoding UTF8
    $script = @'
$ErrorActionPreference = 'Stop'
$cleanupDoneFile = '__DONE__'
try {
    $paths = Get-Content -LiteralPath '__MANIFEST__' -Raw | ConvertFrom-Json
    foreach ($path in $paths) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
    }
    [IO.File]::WriteAllText($cleanupDoneFile, 'removed')
}
catch {
    [IO.File]::WriteAllText($cleanupDoneFile, 'failed: ' + $_.Exception.Message)
    exit 1
}
'@
    Set-Content -LiteralPath $launcher -Value ($script.Replace('__MANIFEST__', $manifest).Replace('__DONE__', $done)) -Encoding UTF8
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $launcher + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        for ($attempt = 0; $attempt -lt 120 -and -not (Test-Path $done); $attempt++) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path $done)) {
            $info = Get-ScheduledTaskInfo -TaskName $taskName
            throw "LocalSystem test cleanup did not complete; task result $($info.LastTaskResult)."
        }
        $result = Get-Content -LiteralPath $done -Raw
        if ($result -ne 'removed') { throw $result }
    }
    finally {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $launcher,$manifest,$done -Force -ErrorAction SilentlyContinue
    }
}

function Copy-StagedOriginalDriver([string] $Source, [string] $Destination) {
    $expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
    if ((Get-FileHash -LiteralPath $Source).Hash -ne $expected) { throw 'Original driver source mismatch.' }
    $sourceStream = [IO.FileStream]::new($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $output = [IO.FileStream]::new($Destination,[IO.FileMode]::Create,[IO.FileAccess]::Write,
            [IO.FileShare]::Read,65536,[IO.FileOptions]::WriteThrough)
        try { $sourceStream.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
    } finally { $sourceStream.Dispose() }
    if ((Get-FileHash -LiteralPath $Destination).Hash -ne $expected) { throw 'Durable original copy mismatch.' }
}

function Backup-StagedTestDriver([string] $Backup) {
    Copy-StagedOriginalDriver 'C:\Windows\System32\drivers\SafeUpload.sys' $Backup
}

# Unload refusal must never leave experimental installed bytes behind. If a
# live kernel object prevents unloading, preserve fixtures and require reboot.
function Restore-StagedTestDriver([string] $Backup, [bool] $Loaded, [bool] $VerifierEnabled = $false) {
    $installed = 'C:\Windows\System32\drivers\SafeUpload.sys'
    $expected = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
    if ((Get-FileHash -LiteralPath $Backup).Hash -ne $expected) {
        throw 'Restoration backup is not the recorded original. Recover the preserved VM snapshot.'
    }
    $unloaded = -not $Loaded
    if ($Loaded) {
        for ($attempt = 0; $attempt -lt 80 -and -not $unloaded; $attempt++) {
            $result = & fltmc.exe unload SafeUpload 2>&1
            $unloaded = $LASTEXITCODE -eq 0
            if (-not $unloaded) { Start-Sleep -Milliseconds 250 }
        }
        $result | Out-Host
    }
    if ($VerifierEnabled) {
        & verifier.exe /volatile /removedriver SafeUpload.sys | Out-Host
        & verifier.exe /reset | Out-Host
    }
    if (-not $unloaded) {
        Move-Item -LiteralPath $installed -Destination ($installed + '.owned-' + [guid]::NewGuid().ToString('N') + '.loaded')
    }
    Copy-StagedOriginalDriver $Backup $installed
    $hash = (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash
    if ($hash -ne $expected) { throw "Original driver restoration failed: $hash" }
    Write-Output "OriginalDriverRestored=$hash"
    if (-not $unloaded) { throw 'Driver refused unload. Original installed bytes restored; reboot before cleaning retained fixtures.' }
    $filters = & fltmc.exe filters
    if ($filters -match '^SafeUpload\s') { throw 'SafeUpload remained loaded after restoration.' }
    Write-Output 'ExperimentalDriverUnloaded=True'
}
