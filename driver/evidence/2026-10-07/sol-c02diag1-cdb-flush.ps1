$ErrorActionPreference='Stop'
$d='E:\sol-c02diag1-memory'
$p=Join-Path $d 'guest.dmp'
$commands=@'
!fltkd.cbd ffffb985783a70f8
dt nt!_ETHREAD ffffb98579569080 TopLevelIrp
!fileobj ffffb985793767c0
dt SafeUpload!_STAGE_STREAM ffffb98579622010 Header
!stacks 1 Ntfs
q
'@
$cf=Join-Path $d 'flush.commands.txt'
[IO.File]::WriteAllText($cf,$commands,[Text.Encoding]::ASCII)
$sym='srv*E:\sol-c02diag1-memory\symbols;C:\Users\vika\Documents\exact-mvp4-sol-b13\src\driver\SafeUpload.Minifilter\x64\Debug'
$cdb='C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
$old=$ErrorActionPreference
try{$ErrorActionPreference='Continue';& $cdb -sins -y $sym -z $p -cf $cf > (Join-Path $d 'cdb-flush.txt') 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
'CdbExit='+$code
