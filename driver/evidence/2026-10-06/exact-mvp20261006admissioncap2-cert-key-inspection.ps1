$ErrorActionPreference = 'Stop'
$thumb='220DD82C37FCF36048D59E4F10113185D81D5DC7'
$result=[ordered]@{Status='Started';UTC=[DateTime]::UtcNow.ToString('o')}
try {
  $product=Get-CimInstance Win32_ComputerSystemProduct
  if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or $product.UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Builder identity mismatch.'}
  $cert=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$thumb)
  $key=[ordered]@{HasPrivateKey=[bool]$cert.HasPrivateKey;LegacyPrivateKeyType=$null;ModernRsaType=$null;Provider=$null;Accessible=$null;KeySize=$null;Error=$null}
  try {
    $legacy=$cert.PrivateKey
    if($null -ne $legacy){$key.LegacyPrivateKeyType=$legacy.GetType().FullName}else{$key.LegacyPrivateKeyType='NULL'}
  }catch{$key.LegacyPrivateKeyType='ERROR';$key.Error='Legacy PrivateKey: '+$_.Exception.ToString()}
  try {
    $rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if($null -eq $rsa){$key.ModernRsaType='NULL'}else{
      $key.ModernRsaType=$rsa.GetType().FullName;$key.KeySize=$rsa.KeySize
      if($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]){$ci=$rsa.CspKeyContainerInfo;$key.Provider=$ci.ProviderName;$key.Accessible=[bool]$ci.Accessible}
      elseif($rsa -is [System.Security.Cryptography.RSACng]){$ck=$rsa.Key;$key.Provider=$ck.Provider.Provider;$key.Accessible=$true}
      else{$key.Provider='Opened by modern RSA API; provider type unclassified.';$key.Accessible=$true}
    }
  }catch{$key.ModernRsaType='ERROR';$key.Error+=' Modern RSA API: '+$_.Exception.ToString()}
  $guid=[Guid]::NewGuid().ToString('N');$out=Join-Path $env:TEMP ('safeupload-certutil-'+$guid+'.stdout.bin');$err=Join-Path $env:TEMP ('safeupload-certutil-'+$guid+'.stderr.bin')
  $p=Start-Process -FilePath (Join-Path $env:windir 'System32\certutil.exe') -ArgumentList ('-user -store My '+$thumb) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  $ob=[IO.File]::ReadAllBytes($out);$eb=[IO.File]::ReadAllBytes($err)
  $result=[ordered]@{Status='Completed';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;Thumbprint=$cert.Thumbprint;Subject=$cert.Subject;KeyInspection=$key;CertutilExit=$p.ExitCode;CertutilStdoutPath=$out;CertutilStdoutBase64=[Convert]::ToBase64String($ob);CertutilStderrPath=$err;CertutilStderrBase64=[Convert]::ToBase64String($eb)}
}catch{$result.Status='Failed';$result.Error=$_.Exception.ToString()}
$result|ConvertTo-Json -Depth 12 -Compress
if($result.Status -ne 'Completed'){exit 2}
