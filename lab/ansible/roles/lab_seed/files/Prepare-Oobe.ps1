#requires -Version 5.1
# Runs only during specialize. The shared image contains no autologon password.
$ErrorActionPreference = 'Stop'
$setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
$uuid = (Get-CimInstance Win32_ComputerSystemProduct).UUID
$protected = @('9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D','9D6E3F02-B40A-49F0-A77F-439714F8F308',
    'FFCB9530-146B-43B1-8AF7-2B5CC8EDE2E3','C6440689-D11C-4C63-A463-F3722B7DDB69','9A20C45F-7C79-4742-887F-5B279309FAB9')
if (-not $setup.SystemSetupInProgress -or $uuid -in $protected) { throw 'OOBE preparation is allowed only during setup on a new lab VM.' }
$v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if ("$($v.CurrentBuild).$($v.UBR)" -ne '19045.2965') { throw 'Unexpected Windows build.' }
$state = 'C:\ProgramData\SafeUploadLab'
$seedPath = $null
$timer = [Diagnostics.Stopwatch]::StartNew()
do {
    foreach ($volume in @(Get-Volume | Where-Object { $_.DriveLetter -and $_.FileSystemLabel -in @('cidata','CIDATA') })) {
        $candidate = $volume.DriveLetter + ':\user-data'
        if (Test-Path -LiteralPath $candidate) { $seedPath = $candidate; break }
    }
    if ($seedPath) { break }
    Start-Sleep -Seconds 2
} while ($timer.Elapsed.TotalSeconds -lt 90)
if (-not $seedPath) { throw 'A private CIDATA seed is required to complete lab setup.' }
$seed = [IO.File]::ReadAllText($seedPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
if ($seed.admin_user -ne 'vika' -or ([string]$seed.admin_password).Length -lt 12 -or
    $seed.hostname -notmatch '^[A-Za-z][A-Za-z0-9-]{0,14}$' -or $seed.hostname -ieq 'WIN10-DEBUGGED') { throw 'Invalid lab seed identity.' }
if (@($seed.authorized_keys).Count -eq 0) { throw 'Seed requires SSH public keys.' }
foreach ($key in @($seed.authorized_keys)) {
    if ($key -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( [^\r\n]*)?$') { throw 'Invalid seed public key.' }
}
$user = Get-LocalUser -Name vika
if (-not $user.Enabled) { throw 'The existing lab administrator is disabled.' }
Set-LocalUser -Name vika -Password (ConvertTo-SecureString ([string]$seed.admin_password) -AsPlainText -Force)
$xml = & (Join-Path $state 'New-OobeAnswer.ps1') -TemplatePath 'C:\Windows\Temp\safeupload-firstboot.xml' -Password ([string]$seed.admin_password)
$path = Join-Path $state 'instance-oobe.xml'
[IO.File]::WriteAllText($path, $xml, (New-Object Text.UTF8Encoding $false))
New-ItemProperty 'HKLM:\SYSTEM\Setup' -Name UnattendFile -Value $path -PropertyType String -Force | Out-Null
Set-Content -LiteralPath (Join-Path $state 'oobe-pending') -Value 'Pending'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\SafeUploadLab\Complete-Oobe.ps1'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User vika
$principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable
Register-ScheduledTask -TaskName SafeUploadLabFinishOobe -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
'Private per-instance OOBE answer prepared.'
