#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
Installs SafeUpload on this machine: WinFsp (if needed), the gate driver, the agent service and the tray app.

.EXAMPLE
.\Install-SafeUploadAgent.ps1 -PackagePath C:\pkg\agent -DriverPath C:\pkg\driver -WinFspMsi C:\pkg\winfsp-2.1.25156.msi

PackagePath holds SafeUpload.Agent.Service.exe and the tray app under App\. DriverPath holds SafeUpload.sys and
SafeUpload.inf (signed with the test certificate; the machine needs test signing on). AdminBaseUrl points the agent at
the web console (http://host:8080/agent/); leave it empty to use C:\ProgramData\SafeUpload\policy.json.

-PrerequisitesOnly installs only WinFsp and the gate driver; the .exe installer (agente/installer) uses it.
#>
[CmdletBinding()]
param(
    [string] $PackagePath = '',
    [string] $DriverPath = '',
    [string] $WinFspMsi = '',
    [string] $AdminBaseUrl = '',
    [switch] $PrerequisitesOnly
)
$ErrorActionPreference = 'Stop'
$programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { [Environment]::GetFolderPath('ProgramFiles') }
$installRoot = Join-Path $programFiles 'SafeUpload'
$agentDirectory = Join-Path $installRoot 'Agent'
$appDirectory = Join-Path $installRoot 'App'
if (-not $PrerequisitesOnly) {
    if (-not $PackagePath) { throw 'Pass -PackagePath (or -PrerequisitesOnly).' }
    $package = (Resolve-Path -LiteralPath $PackagePath).Path
    if (-not (Test-Path -LiteralPath (Join-Path $package 'SafeUpload.Agent.Service.exe'))) { throw 'PackagePath has no SafeUpload.Agent.Service.exe.' }
}

# 1. WinFsp provides the SafeUpload drives.
if (-not (Test-Path -LiteralPath "${env:ProgramFiles(x86)}\WinFsp\bin\winfsp-x64.dll")) {
    if (-not $WinFspMsi) { throw 'WinFsp is not installed; pass -WinFspMsi <winfsp.msi>.' }
    $msi = Start-Process msiexec.exe -ArgumentList '/i', ('"' + (Resolve-Path -LiteralPath $WinFspMsi).Path + '"'), '/qn', '/norestart' -Wait -PassThru
    if ($msi.ExitCode -ne 0) { throw "WinFsp installation failed ($($msi.ExitCode))." }
    Write-Output 'WinFspInstalled=True'
}

# 2. The gate driver (demand-start; the agent loads it).
if ($DriverPath) {
    $driverSource = (Resolve-Path -LiteralPath $DriverPath).Path
    $inf = Join-Path $driverSource 'SafeUpload.inf'
    & fltmc.exe unload SafeUpload 2>$null | Out-Null
    & rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.NTamd64 132 $inf
    Start-Sleep -Seconds 2
    # The INF copy skips a target that is not older; copy explicitly so an upgrade always replaces the driver.
    $target = Join-Path $env:SystemRoot 'System32\drivers\SafeUpload.sys'
    Copy-Item -LiteralPath (Join-Path $driverSource 'SafeUpload.sys') -Destination $target -Force
    if ((Get-FileHash $target).Hash -ne (Get-FileHash (Join-Path $driverSource 'SafeUpload.sys')).Hash) { throw 'Gate driver file was not replaced.' }
    if (-not (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload')) { throw 'Gate driver installation failed.' }
    Write-Output 'GateDriverInstalled=True'
}

if ($PrerequisitesOnly) { return }

# 3. The agent service.
$existing = Get-Service -Name SafeUploadAgent -ErrorAction SilentlyContinue
if ($existing) { Stop-Service -Name SafeUploadAgent -Force -ErrorAction SilentlyContinue }
Get-Process -Name 'SafeUpload.Agent.App' -ErrorAction SilentlyContinue | Stop-Process -Force
New-Item -ItemType Directory -Force -Path $agentDirectory | Out-Null
Get-ChildItem -LiteralPath $package -Force | Where-Object { $_.Name -ne 'App' } | Copy-Item -Destination $agentDirectory -Recurse -Force
$binaryPath = '"' + (Join-Path $agentDirectory 'SafeUpload.Agent.Service.exe') + '" "--CentroAdministracao:BaseUrl=' + $AdminBaseUrl + '"'
if (-not $existing) {
    New-Service -Name SafeUploadAgent -BinaryPathName $binaryPath -StartupType Automatic -DisplayName 'SafeUpload Agent' | Out-Null
} else {
    Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUploadAgent' -Name ImagePath -Value $binaryPath
}
& sc.exe description SafeUploadAgent 'Inspects files saved to SafeUpload drives before they reach protected folders.' | Out-Null
& sc.exe failure SafeUploadAgent reset= 86400 actions= restart/5000/restart/5000/restart/30000 | Out-Null
Write-Output "ServiceCommandLine=$binaryPath"

# 4. The tray app, started at every user's sign-in.
$appSource = Join-Path $package 'App'
if (Test-Path -LiteralPath (Join-Path $appSource 'SafeUpload.Agent.App.exe')) {
    New-Item -ItemType Directory -Force -Path $appDirectory | Out-Null
    Get-ChildItem -LiteralPath $appSource -Force | Copy-Item -Destination $appDirectory -Recurse -Force
    Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadApp `
        -Value ('"' + (Join-Path $appDirectory 'SafeUpload.Agent.App.exe') + '"')
    Write-Output 'AppInstalled=True'
}

Start-Service -Name SafeUploadAgent
Write-Output 'AgentStarted=True'
