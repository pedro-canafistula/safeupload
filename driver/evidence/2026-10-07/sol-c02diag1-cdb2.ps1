$ErrorActionPreference='Stop'
$d='E:\sol-c02diag1-memory'
$p=Join-Path $d 'guest.dmp'
$commands=@'
.reload /f nt
.reload /f SafeUpload.sys
.reload /f fltmgr.sys
.reload /f Ntfs.sys
dq nt!KiBugCheckData L5
!process 14c8 7
!locks
!running -it
lmvm SafeUpload
q
'@
$cf=Join-Path $d 'initial.commands.txt'
[IO.File]::WriteAllText($cf,$commands,[Text.Encoding]::ASCII)
$sym='srv*E:\sol-c02diag1-memory\symbols*https://msdl.microsoft.com/download/symbols;C:\Users\vika\Documents\exact-mvp4-sol-b13\src\driver\SafeUpload.Minifilter\x64\Debug'
$cdb='C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
$old=$ErrorActionPreference
try{$ErrorActionPreference='Continue';& $cdb -sins -y $sym -z $p -cf $cf > (Join-Path $d 'cdb-initial2.txt') 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
'CdbExit='+$code
if($code -ne 0){throw 'CDB analysis failed'}
