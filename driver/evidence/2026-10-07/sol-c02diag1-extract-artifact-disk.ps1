$ErrorActionPreference='Stop'
$d='E:\sol-c02diag1-memory'
if((Get-Volume -DriveLetter E).FileSystemLabel -cne 'SolC02Diagnostic'){throw 'Wrong artifact volume'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[IO.Compression.ZipFile]::OpenRead((Join-Path $d 'guest.dmp.zip'))
try{
 if($zip.Entries.Count -ne 1 -or $zip.Entries[0].FullName -cne 'guest.dmp' -or $zip.Entries[0].Length -ne 8723972096){throw 'Archive identity mismatch'}
 $inputStream=$zip.Entries[0].Open()
 try{
  $outputStream=New-Object IO.FileStream((Join-Path $d 'guest.dmp'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$inputStream.CopyTo($outputStream,65536);$outputStream.Flush($true)}finally{$outputStream.Dispose()}
 }finally{$inputStream.Dispose()}
}finally{$zip.Dispose()}
$p=Join-Path $d 'guest.dmp'
'DumpBytes='+(Get-Item -LiteralPath $p).Length
$hash=(Get-FileHash -LiteralPath $p).Hash
'DumpSHA256='+$hash
if($hash -cne '5DEC25174741239830B67C67FE3B7466CAD20C416566E931DF091F14ACD3E054'){throw 'Dump transport hash mismatch'}
