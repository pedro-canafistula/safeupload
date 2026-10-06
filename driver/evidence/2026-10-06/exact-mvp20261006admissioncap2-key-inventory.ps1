$ErrorActionPreference='Stop'
$thumb='220DD82C37FCF36048D59E4F10113185D81D5DC7';$root='C:\Users\vika\Documents\exact-mvp20261006admissioncap2'
$r=[ordered]@{Status='Started';UTC=[DateTime]::UtcNow.ToString('o')}
try{
 $product=Get-CimInstance Win32_ComputerSystemProduct
 if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or $product.UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Builder identity mismatch.'}
 $cert=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$thumb)
 $guid=[Guid]::NewGuid().ToString('N');$out=Join-Path $env:TEMP ('safeupload-key-list-'+$guid+'.stdout.bin');$err=Join-Path $env:TEMP ('safeupload-key-list-'+$guid+'.stderr.bin')
 $p=Start-Process -FilePath (Join-Path $env:windir 'System32\certutil.exe') -ArgumentList '-user -key' -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
 $ob=[IO.File]::ReadAllBytes($out);$eb=[IO.File]::ReadAllBytes($err)
 $roots=@($root,'C:\Users\vika\Documents\SafeUpload','C:\Users\vika\Documents\safeupload')
 $backups=@();foreach($d in $roots){if(Test-Path -LiteralPath $d){foreach($f in Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {$_.Extension -match '^\.(pfx|p12|pvk|key)$'}){$backups += [ordered]@{Path=$f.FullName;Length=$f.Length;LastWriteUtc=$f.LastWriteTimeUtc.ToString('o')}}}}
 $keyMetadata=@();$keyDirs=@((Join-Path $env:APPDATA 'Microsoft\Crypto\Keys'),(Join-Path $env:APPDATA 'Microsoft\Crypto\RSA'))
 foreach($d in $keyDirs){if(Test-Path -LiteralPath $d){foreach($f in Get-ChildItem -LiteralPath $d -Recurse -File -Force -ErrorAction SilentlyContinue){$keyMetadata += [ordered]@{Store=$d;Name=$f.Name;Length=$f.Length;LastWriteUtc=$f.LastWriteTimeUtc.ToString('o')}}}}
 $r=[ordered]@{Status='Completed';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;Thumbprint=$cert.Thumbprint;CertutilExit=$p.ExitCode;CertutilStdoutBase64=[Convert]::ToBase64String($ob);CertutilStderrBase64=[Convert]::ToBase64String($eb);TaskBackupMetadata=$backups;UserKeyStoreFileMetadata=$keyMetadata}
}catch{$r.Status='Failed';$r.Error=$_.Exception.ToString()}
$r|ConvertTo-Json -Depth 10 -Compress
if($r.Status -ne 'Completed'){exit 2}
