$ErrorActionPreference='Stop'
$d='E:\sol-c02diag1-memory'
$p=Join-Path $d 'guest.dmp'
if(-not(Test-Path -LiteralPath $p)){throw 'Dump missing'}
'DumpBytes='+(Get-Item -LiteralPath $p).Length
$digest=(Get-FileHash -LiteralPath $p).Hash
'DumpSHA256='+$digest
if($digest -cne '5DEC25174741239830B67C67FE3B7466CAD20C416566E931DF091F14ACD3E054'){throw 'Dump transport hash mismatch'}
'DumpAttributes='+(Get-Item -LiteralPath $p).Attributes
$cdb='C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
$commands='.symfix E:\sol-c02diag1-memory\symbols; .sympath+ C:\Users\vika\Documents\exact-mvp4-sol-b13\src\driver\SafeUpload.Minifilter\x64\Debug; .reload /f nt; .reload /f SafeUpload.sys; .reload /f fltmgr.sys; .reload /f Ntfs.sys; dq nt!KiBugCheckData L5; !process 14c8 7; !locks; !running -it; lmvm SafeUpload; q'
$old=$ErrorActionPreference
try{$ErrorActionPreference='Continue';& $cdb -z $p -c $commands > (Join-Path $d 'cdb-initial.txt') 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
'CdbExit='+$code
if($code -ne 0){throw 'CDB analysis failed'}
