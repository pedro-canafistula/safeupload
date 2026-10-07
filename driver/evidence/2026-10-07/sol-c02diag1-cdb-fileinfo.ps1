$ErrorActionPreference='Stop'
$d='E:\sol-c02diag1-memory'
$p=Join-Path $d 'guest.dmp'
$commands=@'
.reload /f fileinfo.sys
!irp ffffb985795aca20 1
!fltkd.irpctrl ffffb985783a7010
!stacks 1 fileinfo
lmvm fileinfo
q
'@
$cf=Join-Path $d 'fileinfo.commands.txt'
[IO.File]::WriteAllText($cf,$commands,[Text.Encoding]::ASCII)
$sym='srv*E:\sol-c02diag1-memory\symbols*https://msdl.microsoft.com/download/symbols;C:\Users\vika\Documents\exact-mvp4-sol-b13\src\driver\SafeUpload.Minifilter\x64\Debug'
$cdb='C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
$old=$ErrorActionPreference
try{$ErrorActionPreference='Continue';& $cdb -sins -y $sym -z $p -cf $cf > (Join-Path $d 'cdb-fileinfo.txt') 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
'CdbExit='+$code
