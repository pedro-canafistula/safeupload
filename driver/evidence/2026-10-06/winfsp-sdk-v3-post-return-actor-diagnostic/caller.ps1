$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$processes=@(Get-CimInstance Win32_Process -Filter "Name='msiexec.exe'" | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate)
$services=@(Get-CimInstance Win32_Service -Filter "Name='msiserver'" | Select-Object Name,State,StartMode,ProcessId,PathName)
$log='C:\Users\vika\Documents\SafeUploadWinFspSdk-20261006-ef9bea72fc3545d985354fa5a939179b.msi.log'
$tail=@(Select-String -LiteralPath $log -Pattern 'MainEngineThread|Return value|Action ended|Installation completed|Verbose logging stopped' | Select-Object -Last 25 | ForEach-Object {$_.Line})
@{UTC=[DateTime]::UtcNow.ToString('o');Processes=$processes;WindowsInstallerService=$services;ReviewedLogPath=$log;ReviewedLogSHA256=(Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash;CompletionLines=$tail;ProcessStoppedByUs=$false;ServiceConfigurationChanged=$false}|ConvertTo-Json -Depth 6
