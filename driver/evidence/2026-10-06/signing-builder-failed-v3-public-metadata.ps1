$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$c=Get-Item -LiteralPath 'Cert:\LocalMachine\My\CD10B2C8AD4F578759350CA8C03EA5064C692192' -ErrorAction Stop
$eku=@($c.EnhancedKeyUsageList|ForEach-Object {[ordered]@{Type=$_.GetType().FullName;ObjectId=$_.ObjectId;ObjectIdType=$_.ObjectId.GetType().FullName;NestedValue=$_.ObjectId.Value}})
$ext=@($c.Extensions|ForEach-Object {[ordered]@{Oid=$_.Oid.Value;Type=$_.GetType().FullName;Formatted=$_.Format($false)}})
[ordered]@{UTC=[DateTime]::UtcNow.ToString('o');Thumbprint=$c.Thumbprint;Subject=$c.Subject;Issuer=$c.Issuer;HasPrivateKey=$c.HasPrivateKey;PublicKeyOid=$c.PublicKey.Oid.Value;SignatureOid=$c.SignatureAlgorithm.Value;NotBeforeUtc=$c.NotBefore.ToUniversalTime().ToString('o');NotAfterUtc=$c.NotAfter.ToUniversalTime().ToString('o');EnhancedKeyUsageView=$eku;Extensions=$ext;KeyUsedOrExported=$false;StateMutated=$false}|ConvertTo-Json -Depth 6 -Compress
