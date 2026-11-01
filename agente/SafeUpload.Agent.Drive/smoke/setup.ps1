$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force C:\T5 | Out-Null
$p = Start-Process msiexec.exe -ArgumentList '/i', 'C:\Users\vika\Documents\winfsp-2.1.25156.msi', '/qn', '/norestart' -Wait -PassThru
'WINFSP_MSI_EXIT=' + $p.ExitCode
Expand-Archive -LiteralPath C:\Users\vika\Documents\drive.zip -DestinationPath C:\SafeUploadSpike\bin -Force
$exe = 'C:\SafeUploadSpike\bin\drive\SafeUpload.Agent.Drive.exe'
$arguments = '--backing C:\SafeUploadSpike\Envios --private C:\ProgramData\SafeUploadSpike --mount S: --protect-backing'
$action = New-ScheduledTaskAction -Execute $exe -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName SafeUploadDrive -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
'TASK_REGISTERED=True'
Get-ChildItem 'C:\Program Files (x86)\WinFsp\bin' -Filter 'winfsp-x64.*' | ForEach-Object { 'WINFSP_FILE=' + $_.Name }
