#requires -Version 5.1
# SYSTEM task after the one initial lab login: remove setup credentials before enabling seeded SSH.
$ErrorActionPreference = 'Stop'
$state = 'C:\ProgramData\SafeUploadLab'
$timer = [Diagnostics.Stopwatch]::StartNew()
do {
    $setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
    if (-not $setup.SystemSetupInProgress -and -not $setup.OOBEInProgress) { break }
    Start-Sleep -Seconds 2
} while ($timer.Elapsed.TotalSeconds -lt 300)
if ($setup.SystemSetupInProgress -or $setup.OOBEInProgress) { throw 'OOBE did not complete; seed remains held.' }
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($name in 'DefaultPassword','DefaultUserName','DefaultDomainName','AutoLogonCount','AutoAdminLogon') {
    if (Get-ItemProperty $winlogon -Name $name -ErrorAction SilentlyContinue) { Remove-ItemProperty $winlogon -Name $name }
}
if ((Get-ItemProperty 'HKLM:\SYSTEM\Setup' -Name UnattendFile -ErrorAction SilentlyContinue).UnattendFile -eq (Join-Path $state 'instance-oobe.xml')) {
    Remove-ItemProperty 'HKLM:\SYSTEM\Setup' -Name UnattendFile
}
foreach ($path in @((Join-Path $state 'instance-oobe.xml'),'C:\Windows\Panther\unattend.xml','C:\Windows\Panther\Unattend\unattend.xml')) {
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}
Remove-Item -LiteralPath (Join-Path $state 'oobe-pending') -Force
Unregister-ScheduledTask -TaskName SafeUploadLabFinishOobe -Confirm:$false
$timer.Restart()
while ((Get-ScheduledTask -TaskName SafeUploadLabSeed).State -eq 'Running' -and $timer.Elapsed.TotalSeconds -lt 30) { Start-Sleep -Seconds 1 }
if ((Get-ScheduledTask -TaskName SafeUploadLabSeed).State -eq 'Running') { throw 'Startup seed task did not exit.' }
Start-ScheduledTask -TaskName SafeUploadLabSeed
