#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
# Stop must succeed before removing the UI. The service/driver may veto stop
# while recovery obligations are outstanding; retain their actionable notices.
$service = Get-Service -Name 'SafeUploadAgent' -ErrorAction SilentlyContinue
if ($null -ne $service) {
    Stop-Service -Name 'SafeUploadAgent' -ErrorAction Stop
    & sc.exe delete SafeUploadAgent
    if ($LASTEXITCODE -ne 0) { throw ('Removing SafeUploadAgent failed: sc.exe ' + $LASTEXITCODE) }
}
$programFiles = [Environment]::GetFolderPath('ProgramFiles')
if ($env:ProgramW6432) { $programFiles = $env:ProgramW6432 }
$appDirectory = Join-Path $programFiles 'SafeUpload\App'
$appExecutable = Join-Path $appDirectory 'SafeUpload.Agent.App.exe'
$machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
try {
    $run = $machine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', $true)
    if ($null -ne $run) {
        try { $run.DeleteValue('SafeUploadApp', $false) }
        finally { $run.Dispose() }
    }
} finally { $machine.Dispose() }
Get-Process -Name 'SafeUpload.Agent.App' -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -eq $appExecutable
} | Stop-Process -Force -ErrorAction Stop
if (Test-Path -LiteralPath $appDirectory) { Remove-Item -LiteralPath $appDirectory -Recurse -Force }
Write-Output 'AgentServiceRemoved=True'
Write-Output 'AppRemoved=True'
Write-Output 'Driver, policy and recovery data retained.'
