$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69'){throw 'Wrong builder'}
$c=Get-Item -LiteralPath 'Cert:\LocalMachine\My\DF864DD743809E379FAEE81EFD8D35F7D9BE75EA' -ErrorAction Stop
$eku=@($c.EnhancedKeyUsageList|ForEach-Object {[ordered]@{Type=$_.GetType().FullName;ObjectId=$_.ObjectId;ObjectIdType=$_.ObjectId.GetType().FullName;NestedValue=$_.ObjectId.Value}})
$ext=@($c.Extensions|ForEach-Object {[ordered]@{Oid=$_.Oid.Value;Type=$_.GetType().FullName;Formatted=$_.Format($false)}})
$keyFiles=@(Get-ChildItem -LiteralPath "$env:ProgramData\Microsoft\Crypto\Keys" -File -ErrorAction Stop | Where-Object {$_.CreationTimeUtc -ge [DateTime]::Parse('2026-10-06T17:21:00Z').ToUniversalTime()} | ForEach-Object {
 $acl=Get-Acl -LiteralPath $_.FullName
 $orderedAces=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {[ordered]@{SID=$_.IdentityReference.Value;Type=$_.AccessControlType.ToString();Rights=[int]$_.FileSystemRights;InheritanceFlags=$_.InheritanceFlags.ToString();PropagationFlags=$_.PropagationFlags.ToString();Inherited=$_.IsInherited}})
 [ordered]@{Path=$_.FullName;Bytes=$_.Length;CreationTimeUtc=$_.CreationTimeUtc.ToString('o');LastWriteTimeUtc=$_.LastWriteTimeUtc.ToString('o');SDDL=$acl.Sddl;Owner=$acl.Owner;Group=$acl.Group;Protected=$acl.AreAccessRulesProtected;OrderedAces=$orderedAces}
})
[ordered]@{UTC=[DateTime]::UtcNow.ToString('o');Thumbprint=$c.Thumbprint;Subject=$c.Subject;HasPrivateKey=$c.HasPrivateKey;Extensions=$ext;RecentMachineKeyFileMetadata=$keyFiles;KeyFileBytesRead=$false;PrivateKeyOpened=$false;KeyUsedOrExported=$false;StateMutated=$false}|ConvertTo-Json -Depth 8 -Compress
