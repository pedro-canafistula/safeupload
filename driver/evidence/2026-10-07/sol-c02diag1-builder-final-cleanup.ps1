$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder UUID'}
if(@(Get-CimInstance Win32_Process -Filter "Name='cdb.exe'" | Where-Object {$_.CommandLine -like '*sol-c02diag1-memory*'}).Count){throw 'Owned debugger still running'}
$disk=Get-Disk -Number 1
if($disk.SerialNumber.Trim() -cne 'sol-c02diag1-2026100' -or $disk.UniqueId.Trim() -cne 'sol-c02diag1-2026100' -or $disk.Size -ne 21474836480 -or $disk.IsBoot -or $disk.IsSystem -or (Get-Volume -DriveLetter E).FileSystemLabel -cne 'SolC02Diagnostic'){throw 'Diagnostic volume guard mismatch'}
$d='E:\sol-c02diag1-memory'
$p=Join-Path $d 'guest.dmp'
if((Get-Item -LiteralPath $p).Length -ne 8723972096){throw 'Derived dump length guard failed'}
Remove-Item -LiteralPath $p -Force
Remove-Item -LiteralPath (Join-Path $d 'guest.dmp.zip') -Force
'DerivedBuilderDumpAndTransportRemoved=True;OriginalHostELFAndDMPUnchanged'
Get-Volume -DriveLetter C,E | Select-Object DriveLetter,SizeRemaining | Format-List
$disk | Set-Disk -IsOffline $true
'OwnedDiagnosticDiskOffline=True'
