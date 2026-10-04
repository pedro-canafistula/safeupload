#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string] $ServiceExecutablePath
)

$ErrorActionPreference = 'Stop'
$serviceName = 'SafeUploadAgent'
$binaryPath = '"' + (Resolve-Path -LiteralPath $ServiceExecutablePath).Path + '"'

function Invoke-ScChecked([string[]] $Arguments, [string] $Description) {
    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed (sc.exe $LASTEXITCODE): $($output -join ' ')"
    }
    $output | Out-Host
}

$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -eq $existing) {
    Invoke-ScChecked @('create', $serviceName, 'binPath=', $binaryPath,
        'start=', 'auto', 'obj=', 'LocalSystem') 'Creating SafeUploadAgent'
}
else {
    if ($existing.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw 'Stop SafeUploadAgent before changing its image path.'
    }
    Invoke-ScChecked @('config', $serviceName, 'binPath=', $binaryPath,
        'start=', 'auto', 'obj=', 'LocalSystem') 'Configuring SafeUploadAgent'
}

# SCM adds this service SID to the service process token. Unrestricted mode
# retains the LocalSystem token while including NT SERVICE\SafeUploadAgent.
Invoke-ScChecked @('sidtype', $serviceName, 'unrestricted') 'Configuring the service SID'
$sidType = (& sc.exe qsidtype $serviceName 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $sidType -notmatch 'SERVICE_SID_TYPE_UNRESTRICTED') {
    throw "SafeUploadAgent does not have an unrestricted service SID: $sidType"
}

Write-Output "ServiceName=$serviceName"
Write-Output 'ServiceSidType=UNRESTRICTED'
Write-Output 'ServiceConfigured=True'
Write-Output 'ServiceStarted=False'
Write-Output 'RestartWindowsAfterStagingTheBootStartDriver=True'
