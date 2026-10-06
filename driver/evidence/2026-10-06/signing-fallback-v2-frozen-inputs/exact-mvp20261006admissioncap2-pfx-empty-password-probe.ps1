$ErrorActionPreference='Stop'
$expectedComputer='DESKTOP-O1LP5DG';$expectedUuid='C6440689-D11C-4C63-A463-F3722B7DDB69';$thumb='220DD82C37FCF36048D59E4F10113185D81D5DC7'
$pfx='C:\safeupload-cert\SafeUploadTest.pfx';$cer='C:\safeupload-cert\SafeUploadTest.cer';$pfxHash='DE1CD348314292C3F391015C9B2790FBE8956D886994BF5C4AE7C67AC51B2F03';$cerHash='46E4E8082155E2EE9E3602C613224322F863ADB85EC02C542FF2F4C8700BA0A1'
$product=Get-CimInstance Win32_ComputerSystemProduct;if($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid){throw 'Builder identity mismatch.'}
$result=[ordered]@{Status='Started';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;PfxPath=$pfx;PfxSHA256Before=$null;PfxSHA256After=$null;PfxUnchanged=$null;PublicCerSHA256Before=$null;PublicCerSHA256After=$null;PfxCandidate='EmptyStringOnly';EphemeralKeySetRequested=$true;PersistedStoreTouched=$false;ThumbprintExact=$false;PublicRsaExactMatch=$false;ChallengeSignatureVerified=$false;PfxPrivateMaterialExported=$false;ErrorType=$null;ErrorHResult=$null;ErrorChain=@()}
$loaded=$null;$privateRsa=$null;$publicRsa=$null;$signature=$null;$challenge=$null
try{
  if((Get-FileHash -LiteralPath $pfx -Algorithm SHA256).Hash -cne $pfxHash -or (Get-FileHash -LiteralPath $cer -Algorithm SHA256).Hash -cne $cerHash){throw 'Pinned backup file hash mismatch.'}
  $result.PfxSHA256Before=(Get-FileHash -LiteralPath $pfx -Algorithm SHA256).Hash;$result.PublicCerSHA256Before=(Get-FileHash -LiteralPath $cer -Algorithm SHA256).Hash
  $loaded=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfx,[string]::Empty,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
  $public=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cer)
  $result.ThumbprintExact=($loaded.Thumbprint -ceq $thumb -and $public.Thumbprint -ceq $thumb)
  $a=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($loaded).ExportParameters($false);$b=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($public).ExportParameters($false)
  $result.PublicRsaExactMatch=([Convert]::ToBase64String($a.Modulus) -ceq [Convert]::ToBase64String($b.Modulus) -and [Convert]::ToBase64String($a.Exponent) -ceq [Convert]::ToBase64String($b.Exponent))
  $privateRsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($loaded);$publicRsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($public)
  $challenge=New-Object byte[] 32;[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($challenge)
  if($privateRsa -is [System.Security.Cryptography.RSACng]){$signature=$privateRsa.SignData($challenge,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1);$result.ChallengeSignatureVerified=$publicRsa.VerifyData($challenge,$signature,[System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)}elseif($privateRsa -is [System.Security.Cryptography.RSACryptoServiceProvider]){$oid=[System.Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256');$signature=$privateRsa.SignData($challenge,$oid);$result.ChallengeSignatureVerified=$publicRsa.VerifyData($challenge,$oid,$signature)}else{throw 'Unsupported in-memory RSA implementation.'}
  $result.ChallengeSHA256=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($challenge)).Replace('-','')
  $result.Status='Completed'
}catch{$result.Status='ProbeFailed';$ex=$_.Exception;while($null -ne $ex){$result.ErrorChain+=@([ordered]@{Type=$ex.GetType().FullName;HResult=('0x{0:X8}' -f $ex.HResult)});$ex=$ex.InnerException};if($result.ErrorChain.Count -gt 0){$result.ErrorType=$result.ErrorChain[0].Type;$result.ErrorHResult=$result.ErrorChain[0].HResult}}finally{
  if($null -ne $signature){[Array]::Clear($signature,0,$signature.Length)};if($null -ne $challenge){[Array]::Clear($challenge,0,$challenge.Length)}
  if($null -ne $privateRsa){$privateRsa.Dispose()};if($null -ne $publicRsa){$publicRsa.Dispose()};if($null -ne $loaded){$loaded.Dispose()};if($null -ne $public){$public.Dispose()}
  $result.PfxSHA256After=(Get-FileHash -LiteralPath $pfx -Algorithm SHA256).Hash;$result.PublicCerSHA256After=(Get-FileHash -LiteralPath $cer -Algorithm SHA256).Hash;$result.PfxUnchanged=($result.PfxSHA256Before -ceq $result.PfxSHA256After);$result.CerUnchanged=($result.PublicCerSHA256Before -ceq $result.PublicCerSHA256After)
}
$result|ConvertTo-Json -Depth 6 -Compress
