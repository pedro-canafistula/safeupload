# Packer's shutdown command (the last SSH session of the build). Removes the build's SSH key and this machine's host
# keys, then generalizes and powers off. First boot generates new host keys and authorizes only the seed's keys.
$ErrorActionPreference = 'Stop'
$bootstrap = 'C:\ProgramData\SafeUploadLabBootstrap'
$state = Get-Content -LiteralPath (Join-Path $bootstrap 'state.json') -Raw | ConvertFrom-Json
# OpenSSH kills ordinary children when the final session exits. A no-trigger SYSTEM task owns the waiting worker;
# the worker removes its own registration before launching Sysprep, so no generalization task survives in the image.
$taskName = 'SafeUploadLabGeneralize'
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Generalization task already exists.' }
$worker = {
    $ErrorActionPreference = 'Stop'
    try {
        Unregister-ScheduledTask -TaskName SafeUploadLabGeneralize -Confirm:$false
        $process = Start-Process -FilePath "$env:WINDIR\System32\Sysprep\sysprep.exe" -Wait -PassThru `
            -ArgumentList '/generalize', '/oobe', '/shutdown', '/quiet', '/unattend:C:\Windows\Temp\safeupload-firstboot.xml'
        if ($process.ExitCode -ne 0) { throw ('Sysprep failed: ' + $process.ExitCode) }
    } catch {
        $_ | Out-String | Set-Content -LiteralPath 'C:\Windows\Temp\safeupload-generalize-error.txt'
        throw
    }
}.ToString()
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($worker))
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
$principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 45)
$null = Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings
# NLA can return the build adapter to Public after a restart. Reapply the recorded temporary setting for local WSMan
# cleanup, then restore Public below; never leave the image dependent on the boot's current network classification.
foreach ($index in @($state.public_interfaces)) { Set-NetConnectionProfile -InterfaceIndex ([int]$index) -NetworkCategory Private }
# Recreate local management access for cleanup; remove HTTPS first and the local HTTP listener last.
Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null
Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' } | Remove-Item -Recurse -Force
Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTP' } | Remove-Item -Recurse -Force
Stop-Service WinRM -Force
Set-Service WinRM -StartupType Disabled
Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
Remove-NetFirewallRule -Name SafeUploadLabWinRM
$policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if ($state.had_uac) {
    Set-ItemProperty -Path $policy -Name LocalAccountTokenFilterPolicy -Value ([int]$state.uac_value)
} else { Remove-ItemProperty -Path $policy -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue }
$certPath = 'Cert:\LocalMachine\My\' + $state.thumbprint
Remove-Item -LiteralPath $certPath -DeleteKey -Force
if (Test-Path -LiteralPath $certPath) { throw 'Bootstrap TLS certificate remains.' }
foreach ($index in @($state.public_interfaces)) { Set-NetConnectionProfile -InterfaceIndex ([int]$index) -NetworkCategory Public }
Remove-Item -LiteralPath $bootstrap -Recurse -Force
Add-Type -AssemblyName System.Web
$random = [System.Web.Security.Membership]::GeneratePassword(40, 8)
Set-LocalUser -Name 'vika' -Password (ConvertTo-SecureString $random -AsPlainText -Force)
Remove-Item -LiteralPath 'C:\ProgramData\ssh\administrators_authorized_keys' -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath 'C:\ProgramData\ssh' -Filter 'ssh_host_*' -Force -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item -LiteralPath 'C:\ProgramData\ssh\logs' -Recurse -Force -ErrorAction SilentlyContinue
if ((Test-Path -LiteralPath 'C:\ProgramData\ssh\administrators_authorized_keys') -or
    @(Get-ChildItem -LiteralPath 'C:\ProgramData\ssh' -Filter 'ssh_host_*' -Force).Count -gt 0) {
    throw 'Build SSH keys remain; refusing to generalize the image.'
}
Set-Service -Name sshd -StartupType Manual
Start-ScheduledTask -TaskName $taskName
'GENERALIZE_WORKER_QUEUED=True'
