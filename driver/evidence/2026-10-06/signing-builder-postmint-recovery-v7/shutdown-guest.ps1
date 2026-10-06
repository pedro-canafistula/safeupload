$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
if(@(Get-Process -Name MSBuild,dotnet,csc,vbcsc,VBCSCompiler -ErrorAction SilentlyContinue).Count){throw 'Build processes active'}
& shutdown.exe /s /t 0
if($LASTEXITCODE -ne 0){throw 'Graceful shutdown failed'}
'GracefulGuestShutdownRequested=True'
