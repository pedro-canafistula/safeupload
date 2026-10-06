[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string] $ExpectedThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCerSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCreationMetadataSha256
)
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
if($metadataHash -cne $ExpectedCreationMetadataSha256.ToUpperInvariant()){throw 'Pinned V8 creation metadata hash mismatch'}
$metadata=Get-Content -LiteralPath $creationMetadataPath -Raw -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop
if($metadata.Status -cne 'CreatedAndProbed' -or $metadata.Thumbprint -cne $ExpectedThumbprint.ToUpperInvariant() -or
   $metadata.PublicCerSHA256 -cne $ExpectedCerSha256.ToUpperInvariant() -or $metadata.Subject -cne $newSubject -or
   $metadata.NoAclWrite -ne $true -or $metadata.KeyAclUnchanged -ne $true -or $metadata.PrivateKeyMaterialExported -ne $false -or
   $metadata.ChallengeSignatureVerified -ne $true -or $metadata.PersistentTrustChanged -ne $false -or
   $metadata.ChallengeSignaturePersistedOrExported -ne $false){throw 'V8 mint evidence does not match the pinned no-trust/no-export creation result'}
if((Get-FileHash -LiteralPath $publicCerPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant() -cne $ExpectedCerSha256.ToUpperInvariant()){throw 'V8 public CER SHA-256 mismatch'}
$publicCer=[Security.Cryptography.X509Certificates.X509Certificate2]::new($publicCerPath)
if($publicCer.Thumbprint -cne $ExpectedThumbprint.ToUpperInvariant() -or $publicCer.Subject -cne $newSubject){throw 'V8 public CER identity mismatch'}
$stores=[ordered]@{}
foreach($scope in @('CurrentUser','LocalMachine')){
  foreach($name in @('My','Root','TrustedPublisher')){
    $path='Cert:\'+$scope+'\'+$name
    $property=$metadata.PostMintAllStoreThumbprints.PSObject.Properties[$path]
    if($null -eq $property){throw "Pinned mint evidence lacks store inventory $path"}
    $actual=@((Get-ChildItem -LiteralPath $path -ErrorAction Stop)|ForEach-Object{$_.Thumbprint.ToUpperInvariant()}|Sort-Object)
    $expected=@($property.Value|ForEach-Object{$_.ToUpperInvariant()}|Sort-Object)
    if(($actual -join ',') -cne ($expected -join ',')){throw "Six-store inventory differs from mint evidence: $path"}
    $stores[$scope+'\'+$name]=$actual
  }
}
if(-not ($stores['LocalMachine\My'] -ccontains $ExpectedThumbprint.ToUpperInvariant())){throw 'V8 thumbprint absent from LocalMachine My'}
foreach($storeName in @('CurrentUser\My','CurrentUser\Root','CurrentUser\TrustedPublisher','LocalMachine\Root','LocalMachine\TrustedPublisher')){
  if($stores[$storeName] -ccontains $ExpectedThumbprint.ToUpperInvariant()){throw "V8 thumbprint unexpectedly present in $storeName"}
}
$machineCert=Get-Item -LiteralPath ('Cert:\LocalMachine\My\'+$ExpectedThumbprint.ToUpperInvariant()) -ErrorAction Stop
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
[ordered]@{
  UTC=[DateTime]::UtcNow.ToString('o');BootTimeUtc=$os.LastBootUpTime.ToUniversalTime().ToString('o');Verdict='V8_KEY_BEARING_COLD_BASELINE_PASS';ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;SID=$identity.User.Value;EffectiveAdministratorsMembership=$true
  Stores=$stores;AllSixStoresMatchMintEvidence=$true;NewThumbprint=$ExpectedThumbprint.ToUpperInvariant();NewCertificateInLocalMachineMy=$true
  NewCertificateAbsentFromOtherFiveStores=$true;NewCertificateHasPrivateKeyAssociation=$true;NewCertificatePublicCerSha256=$ExpectedCerSha256.ToUpperInvariant()
  CreationMetadataSha256=$metadataHash;OriginalFiles=$files;OriginalCertificate=[ordered]@{Thumbprint=$old.Thumbprint;Subject=$old.Subject;HasPrivateKey=$old.HasPrivateKey}
  TestSigning='No';BuildProcesses=$actors;TrustChangedSinceMintEvidence=$false;StateMutated=$false
}|ConvertTo-Json -Depth 8 -Compress
