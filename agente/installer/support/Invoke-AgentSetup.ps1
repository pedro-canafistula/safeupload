#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Preflight', 'Install', 'CheckUninstall', 'Uninstall')][string]$Action,
    [Parameter(Mandatory)][string]$InstallRoot,
    [string]$AnswersPath,
    [Parameter(Mandatory)][string]$ResultPath
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'SafeUpload.Setup.psm1') -Force
$serviceName = 'SafeUploadAgent'
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent'
$driverKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload'
$expectedRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'SafeUpload\Agent'
$createdByThisRun = $false
$startupCreatedByThisRun = $false
$startupKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$startupValue = '"' + (Join-Path $InstallRoot 'ui\SafeUpload.Agent.App.exe') + '"'

function Remove-OwnedStartup {
    $startup = Get-ItemProperty -LiteralPath $startupKey -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue
    if ($startup) {
        if ($startup.SafeUploadAgentConsole -ne $startupValue) { throw 'The startup entry belongs to another installation.' }
        Remove-ItemProperty -LiteralPath $startupKey -Name SafeUploadAgentConsole
    }
}

function Get-MachineState {
    $driverInstalled = Test-Path -LiteralPath $driverKey
    $driverState = 'Absent'; $driverStart = -1
    if ($driverInstalled) {
        $driverStart = [int](Get-ItemProperty -LiteralPath $driverKey -Name Start).Start
        $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'" -ErrorAction Stop
        $driverState = if ($null -eq $driver) { 'Unknown' } else { [string]$driver.State }
    }
    [pscustomobject]@{ AgentInstalled = (Test-Path -LiteralPath $serviceKey); DriverInstalled = $driverInstalled;
        DriverState = $driverState; DriverStart = $driverStart }
}

function Invoke-Sc([string[]]$ScArguments) {
    $output = & "$env:SystemRoot\System32\sc.exe" @ScArguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Service manager command failed ($LASTEXITCODE): $($output -join ' ')" }
}

function Assert-OwnedService {
    if (-not (Test-Path -LiteralPath $serviceKey)) { return }
    $properties = Get-ItemProperty -LiteralPath $serviceKey
    $prefix = '"' + (Join-Path $InstallRoot 'service\SafeUpload.Agent.Service.exe') + '"'
    $image = [string]$properties.ImagePath
    if (($image -ne $prefix -and -not $image.StartsWith($prefix + ' ', [StringComparison]::OrdinalIgnoreCase)) -or
        $properties.ObjectName -ne 'LocalSystem') { throw 'Refusing to change a service not owned by this installation.' }
}

function Remove-OwnedService {
    Assert-OwnedService
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        try {
            if ($service.Status -ne 'Stopped') {
                Stop-Service -InputObject $service -ErrorAction Stop
                $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
            }
        } finally { $service.Dispose() }
        Invoke-Sc @('delete', $serviceName)
        for ($attempt = 0; $attempt -lt 50 -and (Test-Path -LiteralPath $serviceKey); $attempt++) { Start-Sleep -Milliseconds 100 }
        if (Test-Path -LiteralPath $serviceKey) { throw 'Service deletion is pending. Close service consoles and restart Windows before retrying.' }
    }
}

try {
    $InstallRoot = Assert-SafeUploadDirectory -Path $InstallRoot -ExpectedPath $expectedRoot
    # Check the protected boundary, not C:\ (which normally permits users to create top-level folders).
    $boundary = [Environment]::GetFolderPath('ProgramFiles').TrimEnd('\')
    $directory = $InstallRoot
    while ($directory.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase)) {
        if (Test-Path -LiteralPath $directory) { Assert-SafeUploadInstallAcl -Acl (Get-Acl -LiteralPath $directory) }
        if ($directory.Equals($boundary, [StringComparison]::OrdinalIgnoreCase)) { break }
        $directory = Split-Path -Parent $directory
    }
    $state = Get-MachineState
    if ($Action -in @('Preflight', 'Install')) {
        $answers = Get-Content -LiteralPath $AnswersPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $plan = New-SafeUploadInstallPlan -InstallRoot $InstallRoot -Mode $answers.mode -AdminBaseUrl $answers.adminBaseUrl
        Assert-SafeUploadMachineState -State $state -Mode $plan.Mode -Operation Install
        if ($Action -eq 'Preflight') {
            if ((Test-Path -LiteralPath $InstallRoot) -and (Get-ChildItem -LiteralPath $InstallRoot -Force | Select-Object -First 1)) {
                throw 'The installation directory is not empty. Existing installations require a maintenance review.'
            }
            if (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadAgentConsole -ErrorAction SilentlyContinue) {
                throw 'An existing SafeUpload startup entry must be reviewed before installing.'
            }
        } else {
            $manifest = Test-SafeUploadPayload -Root $InstallRoot
            if (-not (Test-Path -LiteralPath $plan.Executable -PathType Leaf)) { throw 'Service executable is absent.' }
            if ($plan.Mode -eq 'Minifilter') {
                # The existing script may create the service before a later step fails.
                $createdByThisRun = $true
                & (Join-Path $PSScriptRoot 'Install-SafeUploadAgent.ps1') -ServiceExecutablePath $plan.Executable `
                    -AdminBaseUrl $plan.AdminBaseUrl -ServiceArguments @('--Interception:Mode=Minifilter',
                    '--Interception:StagingPrototype=true', ('--CentroAdministracao:BaseUrl=' + $plan.AdminBaseUrl),
                    '--InspecaoTls:Habilitada=false') | Out-Null
            } else {
                $newService = New-Service -Name $serviceName -DisplayName 'SafeUpload Agent' -BinaryPathName $plan.CommandLine `
                    -Description 'SafeUpload endpoint agent' -StartupType Automatic
                # A failed New-Service must never claim an existing service for rollback.
                $createdByThisRun = $true
                $newService.Dispose()
                Invoke-Sc @('sidtype', $serviceName, 'unrestricted')
            }
            Assert-OwnedService
            $registered = Get-ItemProperty -LiteralPath $serviceKey
            if ($registered.ImagePath -ne $plan.CommandLine -or [int]$registered.ServiceSidType -ne 1) {
                throw 'Service configuration read-back failed.'
            }
            if ($plan.Mode -eq 'FileSystemWatcher') {
                Start-Service $serviceName
                $service = Get-Service $serviceName
                try { $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30)) }
                finally { $service.Dispose() }
                Start-Sleep -Seconds 3
                $service = Get-Service $serviceName
                try { if ($service.Status -ne 'Running') { throw 'The service stopped during its initial startup.' } }
                finally { $service.Dispose() }
            }
            [ordered]@{ schemaVersion = 1; version = $manifest.version; commit = $manifest.commit; mode = $plan.Mode;
                adminBaseUrl = $plan.AdminBaseUrl; installedAtUtc = [DateTime]::UtcNow.ToString('o'); restartRequired = $plan.RestartRequired
            } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'installation.json') -Encoding UTF8
            New-ItemProperty -LiteralPath $startupKey -Name SafeUploadAgentConsole -Value $startupValue -PropertyType String | Out-Null
            $startupCreatedByThisRun = $true
        }
    } else {
        Assert-SafeUploadMachineState -State $state -Mode Minifilter -Operation Uninstall
        Assert-OwnedService
        if ($Action -eq 'Uninstall') { Remove-OwnedService; Remove-OwnedStartup }
    }
    [IO.File]::WriteAllText($ResultPath, 'OK', [Text.UTF8Encoding]::new($false))
    exit 0
} catch {
    $message = $_.Exception.Message
    if ($startupCreatedByThisRun) {
        try { Remove-OwnedStartup } catch { $message += ' Startup entry cleanup requires review.' }
    }
    if ($createdByThisRun) {
        try { Remove-OwnedService } catch { $message += ' Service cleanup requires review: ' + $_.Exception.Message }
        if (Test-Path -LiteralPath $driverKey) {
            try { Invoke-Sc @('config', 'SafeUpload', 'start=', 'demand') }
            catch { $message += ' Driver startup state requires review: ' + $_.Exception.Message }
        }
    }
    [IO.File]::WriteAllText($ResultPath, $message, [Text.UTF8Encoding]::new($false))
    Write-Error $message -ErrorAction Continue
    exit 1
}
