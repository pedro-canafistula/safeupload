$ErrorActionPreference='Stop'
$expectedComputer='DESKTOP-O1LP5DG'
$expectedUuid='C6440689-D11C-4C63-A463-F3722B7DDB69'
$expectedSid='S-1-5-21-316478115-1595729549-2803163825-1001'
$oldThumb='220DD82C37FCF36048D59E4F10113185D81D5DC7'
$oldPfxHash='DE1CD348314292C3F391015C9B2790FBE8956D886994BF5C4AE7C67AC51B2F03'
$oldCerHash='46E4E8082155E2EE9E3602C613224322F863ADB85EC02C542FF2F4C8700BA0A1'
$newSubject='CN=SafeUpload Test Signing Recovery 20261006 V8'
$creationMetadataPath='C:\Users\vika\Documents\exact-mvp20261006admissioncap2\replacement-machine-key-v8-metadata.json'
$publicCerPath='C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v8.cer'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$product=Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
$os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid -or $identity.User.Value -cne $expectedSid){throw 'Builder identity mismatch'}
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Pinned vika token lacks enabled Administrators membership'}
$metadataHash=(Get-FileHash -LiteralPath $creationMetadataPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
if($metadataHash -cne '51701037AF41FCC19101E26DD2D632934D20B94190D42782474F68F05ABDFC1E'){throw 'Pinned V8 creation metadata hash mismatch'}
$metadata=Get-Content -LiteralPath $creationMetadataPath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
if($metadata.Status -cne 'CreatedAndProbed' -or $metadata.Thumbprint -cne 'A6D6CE1AA28835D509160A80ADB7894869AADF38' -or
   $metadata.PublicCerSHA256 -cne '47E7069980A60CBCF4DFF61F0F2D3F02EDCF97C2976708790B49D03A09243B2A' -or $metadata.Subject -cne $newSubject -or
   $metadata.NoAclWrite -ne $true -or $metadata.KeyAclUnchanged -ne $true -or $metadata.PrivateKeyMaterialExported -ne $false -or
   $metadata.ChallengeSignatureVerified -ne $true -or $metadata.PersistentTrustChanged -ne $false -or
   $metadata.ChallengeSignaturePersistedOrExported -ne $false){throw 'V8 mint evidence does not match the pinned no-trust/no-export creation result'}
if((Get-FileHash -LiteralPath $publicCerPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant() -cne '47E7069980A60CBCF4DFF61F0F2D3F02EDCF97C2976708790B49D03A09243B2A'){throw 'V8 public CER SHA-256 mismatch'}
$publicCer=[Security.Cryptography.X509Certificates.X509Certificate2]::new($publicCerPath)
if($publicCer.Thumbprint -cne 'A6D6CE1AA28835D509160A80ADB7894869AADF38' -or $publicCer.Subject -cne $newSubject){throw 'V8 public CER identity mismatch'}
$stores=[ordered]@{}
foreach($scope in @('CurrentUser','LocalMachine')){
  foreach($name in @('My','Root','TrustedPublisher')){
    $path='Cert:\'+$scope+'\'+$name
    $property=$metadata.PostMintAllStoreThumbprints.PSObject.Properties[$path]
    if($null -eq $property){throw "Pinned mint evidence lacks store inventory $path"}
    $actual=@((Get-ChildItem -LiteralPath $path -ErrorAction Stop)|ForEach-Object{$_.Thumbprint.ToUpperInvariant()}|Sort-Object)
    $expected=@($property.Value|ForEach-Object{$_.ToUpperInvariant()}|Sort-Object)
    if($path -ceq 'Cert:\CurrentUser\Root' -or $path -ceq 'Cert:\LocalMachine\Root'){$expected=@($expected + 'A6D6CE1AA28835D509160A80ADB7894869AADF38'|Sort-Object)}
    if(($actual -join ',') -cne ($expected -join ',')){throw "Six-store inventory differs from mint evidence: $path"}
    $stores[$scope+'\'+$name]=$actual
  }
}
if(-not ($stores['LocalMachine\My'] -ccontains 'A6D6CE1AA28835D509160A80ADB7894869AADF38')){throw 'V8 thumbprint absent from LocalMachine My'}
foreach($storeName in @('CurrentUser\My','CurrentUser\TrustedPublisher','LocalMachine\TrustedPublisher')){
  if($stores[$storeName] -ccontains 'A6D6CE1AA28835D509160A80ADB7894869AADF38'){throw "V8 thumbprint unexpectedly present in $storeName"}
}
$machineCert=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+'A6D6CE1AA28835D509160A80ADB7894869AADF38') -ErrorAction Stop
if($machineCert.Subject -cne $newSubject -or -not $machineCert.HasPrivateKey){throw 'V8 LocalMachine My public cert/private-key association is missing'}
$files=@()
foreach($path in @('C:\safeupload-cert\SafeUploadTest.pfx','C:\safeupload-cert\SafeUploadTest.cer')){
  $item=Get-Item -LiteralPath $path -ErrorAction Stop
  $files+=@([ordered]@{Path=$path;Length=$item.Length;SHA256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()})
}
if($files[0].SHA256 -cne $oldPfxHash -or $files[1].SHA256 -cne $oldCerHash){throw 'Original PFX/CER hash changed'}
$old=Get-Item -LiteralPath ('Cert:\CurrentUser\My\'+$oldThumb) -ErrorAction Stop
if($old.Subject -cne 'CN=SafeUpload Test Signing' -or -not $old.HasPrivateKey){throw 'Original CurrentUser signing certificate was not retained'}
$bcd=& bcdedit.exe /enum '{current}' 2>&1|Out-String
if($LASTEXITCODE -ne 0){throw 'Boot configuration read failed'}
$testSigning=if($bcd -match '(?im)^testsigning\s+No\s*$'){'No'}elseif($bcd -match '(?im)^testsigning\s+Yes\s*$'){'Yes'}else{'NotPresent'}
if($testSigning -cne 'No'){throw 'Builder testsigning state is not the original No baseline'}
$actors=@(Get-Process -Name MSBuild,dotnet,csc,vbcsc,VBCSCompiler -ErrorAction SilentlyContinue|ForEach-Object{[ordered]@{Name=$_.ProcessName;Id=$_.Id;StartTimeUtc=$_.StartTime.ToUniversalTime().ToString('o')}})
if($actors.Count -ne 0){throw 'Unexpected build process present during cold checkpoint verification'}
$keyAcl=Get-Acl -LiteralPath $metadata.KeyFilePath -ErrorAction Stop
$keyRules=@($keyAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object{[ordered]@{SID=$_.IdentityReference.Value;Rights=[int]$_.FileSystemRights;Type=[string]$_.AccessControlType;Inherited=$_.IsInherited;Inheritance=[int]$_.InheritanceFlags;Propagation=[int]$_.PropagationFlags}})
[ordered]@{
  KeyAclSddl=$keyAcl.Sddl;KeyAclOwner=$keyAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value;KeyAclGroup=$keyAcl.GetGroup([Security.Principal.SecurityIdentifier]).Value;KeyAclProtected=$keyAcl.AreAccessRulesProtected;KeyAclCanonical=$keyAcl.AreAccessRulesCanonical;KeyAclRules=$keyRules
  UTC=[DateTime]::UtcNow.ToString('o');BootTimeUtc=$os.LastBootUpTime.ToUniversalTime().ToString('o');Verdict='V10_BUILDER_TRUST_INDEPENDENT_BASELINE_PASS';ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;SID=$identity.User.Value;EffectiveAdministratorsMembership=$true
  Stores=$stores;AllSixStoresMatchMintPlusExactMachineRootAndMergedUserRoot=$true;NewThumbprint='A6D6CE1AA28835D509160A80ADB7894869AADF38';NewCertificateInLocalMachineMy=$true
  NewCertificateAbsentFromOtherThreeStores=$true;NewCertificateHasPrivateKeyAssociation=$true;NewCertificatePublicCerSha256='47E7069980A60CBCF4DFF61F0F2D3F02EDCF97C2976708790B49D03A09243B2A'
  CreationMetadataSha256=$metadataHash;OriginalFiles=$files;OriginalCertificate=[ordered]@{Thumbprint=$old.Thumbprint;Subject=$old.Subject;HasPrivateKey=$old.HasPrivateKey}
  TestSigning='No';BuildProcesses=$actors;OnlyApprovedMachineRootAndMergedUserRootAddedSinceMintEvidence=$true;StateMutated=$false
}|ConvertTo-Json -Depth 8 -Compress
