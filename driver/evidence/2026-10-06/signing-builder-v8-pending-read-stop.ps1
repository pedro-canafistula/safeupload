$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$p='C:\Users\vika\AppData\Local\Temp\remote_ps_8a621ad16c9f4b42b6b62fd53da226e8.ps1'
$process=Get-CimInstance Win32_Process -Filter 'ProcessId=584'
if($null -eq $process -or $process.Name -ine 'powershell.exe' -or $process.ParentProcessId -ne 484 -or $process.CommandLine -notmatch [regex]::Escape('-File '+$p)){throw 'Pending read identity changed'}
if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ine 'd525d8631daeb65777dff7e359bd575b0d9e3f29e068c8908bce64dd6f746c11'){throw 'Read probe source changed'}
Stop-Process -Id 584 -Force -ErrorAction Stop
'ExactPendingPublicReadProbeStopped=True'
