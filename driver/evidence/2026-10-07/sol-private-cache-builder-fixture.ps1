$ErrorActionPreference='Stop'
Import-Module 'C:\Users\vika\Documents\sol-harness-20261007a\StagedInvariantObserver.psm1' -Force
if((Get-CimInstance Win32_SystemDriver -Filter "Name='SafeUpload'").State -eq 'Running'){throw 'Builder fixture requires SafeUpload unloaded'}
$d=Join-Path $env:TEMP ('SolPrivateCache-'+[guid]::NewGuid().ToString('N'))
$v=$null;$h=$null
try {
 $null=New-Item -ItemType Directory -Path $d
 foreach($size in @(37,12288)){
  $leaf=([guid]::NewGuid().ToString('N')+'.txt');$p=Join-Path $d $leaf
  $b=New-Object byte[] $size
  for($i=0;$i -lt $size;$i++){$b[$i]=[byte](65+($i%23))}
  $s=New-Object IO.FileStream($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite,4096,[IO.FileOptions]::WriteThrough)
  try{$s.Write($b,0,$b.Length);$s.Flush($true)}finally{$s.Dispose()}
  if($null -eq $v){$v=[StagedInvariant.Native]::OpenVolume([StagedInvariant.Native]::ResolveGuid($d),$d);$h=[StagedInvariant.Native]::Open($d,$false,$true)}
  $image=[StagedInvariant.Native]::CaptureNamedTrusted($v,$h,$leaf)
  if($image.Logical.Length -ne $size -or $image.Digest -cne [StagedInvariant.Native]::Hash($b)){throw 'Full fixture bytes differ'}
  if($image.Identity.Links -ne 1 -or $image.Records.Count -ne 1){throw 'Invalid fixture identity/record count'}
  $kinds=@($image.Containers|ForEach-Object{$_.Kind}|Select-Object -Unique)
  if('FSCTL_CACHED_FILE_RECORD' -notin $kinds -or 'KERNEL_DIRECTORY_QUERY' -notin $kinds){throw 'Cache source containers missing'}
  Write-Output ('PrivateCacheFixture=PASS;Length='+$size+';Resident='+$image.Resident+';SHA256='+$image.Digest+';FileId='+$image.Identity.FileId+';Containers='+($kinds -join ','))
 }
 # Additional hard links and ADS must never be accepted as a private allocator snapshot.
 $extra=Join-Path $d 'another-name.txt'
 $null=New-Item -ItemType HardLink -Path $extra -Value $p
 $rejected=$false
 try{$null=[StagedInvariant.Native]::CaptureNamedTrusted($v,$h,$leaf)}catch{
  if($_.Exception.Message -notmatch 'name/hard-link|parent/hard-link|FILE_NAME/header'){throw};$rejected=$true
 }
 if(-not $rejected){throw 'Additional hard link accepted'}
 Remove-Item -LiteralPath $extra -Force
 Write-Output 'PrivateCacheAdditionalHardLink=REJECTED;PASS'
 Set-Content -LiteralPath $p -Stream extra -Value 'Private ADS adversarial fixture' -Encoding ASCII
 $rejected=$false
 try{$null=[StagedInvariant.Native]::CaptureNamedTrusted($v,$h,$leaf)}catch{
  if($_.Exception.Message -notmatch 'ADS ambiguity'){throw};$rejected=$true
 }
 if(-not $rejected){throw 'ADS accepted'}
 Write-Output 'PrivateCacheAds=REJECTED;PASS'
 Write-Output 'PrivateCacheFixtureGate=PASS' 
}finally{if($null -ne $h){$h.Dispose()};if($null -ne $v){$v.Dispose()};if(Test-Path $d){Remove-Item -LiteralPath $d -Recurse -Force}}
