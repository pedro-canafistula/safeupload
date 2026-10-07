$ErrorActionPreference='Stop'
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder UUID'}
$disk=Get-Disk -Number 1
if($disk.SerialNumber.Trim() -cne 'sol-c02diag1-2026100' -or $disk.UniqueId.Trim() -cne 'sol-c02diag1-2026100' -or $disk.Size -ne 21474836480 -or $disk.PartitionStyle -ne 'RAW' -or $disk.IsBoot -or $disk.IsSystem){throw 'New diagnostic disk identity mismatch'}
$boot=Get-Disk -Number 0
if($boot.UniqueId.Trim() -cne '0000000400000000' -or $boot.Size -ne 128849018880 -or -not $boot.IsBoot -or -not $boot.IsSystem){throw 'Original builder disk identity changed'}
if(Get-Volume -DriveLetter E -ErrorAction SilentlyContinue){throw 'Drive E already exists'}
$disk | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -UseMaximumSize -DriveLetter E | Format-Volume -FileSystem NTFS -NewFileSystemLabel SolC02Diagnostic -Confirm:$false
$d='E:\sol-c02diag1-memory'
New-Item -ItemType Directory -Path $d | Out-Null
& icacls.exe $d /inheritance:r /grant:r 'BUILTIN\Administrators:(OI)(CI)F' 'NT AUTHORITY\SYSTEM:(OI)(CI)F' 'vika:(OI)(CI)F'
if($LASTEXITCODE -ne 0){throw 'Private diagnostic ACL failed'}
Get-Disk -Number 1 | Format-List Number,SerialNumber,UniqueId,Size,PartitionStyle,IsBoot,IsSystem
Get-Volume -DriveLetter E | Format-List DriveLetter,FileSystemLabel,FileSystem,Size,SizeRemaining
