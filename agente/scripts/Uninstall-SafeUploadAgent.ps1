#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
Removes the SafeUpload agent service, the tray app and the gate driver. WinFsp, policy and audit data are kept.
Files waiting for inspection stay in C:\ProgramData\SafeUpload\drive; the protected folders keep their content.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { [Environment]::GetFolderPath('ProgramFiles') }

if (Get-Service -Name SafeUploadAgent -ErrorAction SilentlyContinue) {
    Stop-Service -Name SafeUploadAgent -Force
    & sc.exe delete SafeUploadAgent | Out-Null
}
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name SafeUploadApp -ErrorAction SilentlyContinue
Get-Process -Name 'SafeUpload.Agent.App' -ErrorAction SilentlyContinue | Stop-Process -Force
& fltmc.exe unload SafeUpload 2>$null | Out-Null
if (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SafeUpload') { & sc.exe delete SafeUpload | Out-Null }
foreach ($directory in 'Agent', 'App') {
    $path = Join-Path $programFiles "SafeUpload\$directory"
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
}
Write-Output 'SafeUploadRemoved=True'
