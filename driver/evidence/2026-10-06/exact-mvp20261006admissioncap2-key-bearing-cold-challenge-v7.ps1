# REVIEW ONLY: run after the restricted key-bearing builder disk checkpoint is
# created, verified, and cold-booted. It signs only an in-memory random
# challenge; it does not export private material, import trust, or build/sign
# artifacts.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch] $RootApprovedForColdChallenge,
    [Parameter(Mandatory)][switch] $KeyBearingCheckpointVerified,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string] $ExpectedThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCerSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCreationMetadataSha256
)
$ErrorActionPreference = 'Stop'
$guardHelpersPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v7.ps1'
$guardHelpersExpectedSha256 = 'f71d8fedfc9a87a07487c693823a2f71cd4803d993e63b5759021d0431f1c0ab'
if (-not (Test-Path -LiteralPath $guardHelpersPath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $guardHelpersPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $guardHelpersExpectedSha256) {
    throw 'Pinned V7 signing guard helper is missing or changed.'
}
. $guardHelpersPath
$expectedComputer = 'DESKTOP-O1LP5DG'
$expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$oldThumb = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$oldPfxHash = 'DE1CD348314292C3F391015C9B2790FBE8956D886994BF5C4AE7C67AC51B2F03'
$oldCerHash = '46E4E8082155E2EE9E3602C613224322F863ADB85EC02C542FF2F4C8700BA0A1'
$subject = 'CN=SafeUpload Test Signing Recovery 20261006 V7'
$evidenceDirectory = 'C:\Users\vika\Documents\exact-mvp20261006admissioncap2'
$creationMetadataPath = Join-Path $evidenceDirectory 'replacement-machine-key-v7-metadata.json'
$publicCerPath = 'C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v7.cer'
$storePaths = @('Cert:\CurrentUser\My','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher','Cert:\LocalMachine\My','Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')

function Get-StoreThumbInventory {
    $snapshot = [ordered]@{}
    foreach ($store in $storePaths) {
        $certificates = @(Get-ChildItem -LiteralPath $store -ErrorAction Stop)
        $snapshot[$store] = @($certificates | ForEach-Object { $_.Thumbprint.ToUpperInvariant() } | Sort-Object)
    }
    return $snapshot
}
function Get-TestSigningState {
    $raw = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Could not read builder testsigning state.' }
    if ($raw -match '(?im)^\s*testsigning\s+Yes\s*$') { return 'Yes' }
    if ($raw -match '(?im)^\s*testsigning\s+No\s*$') { return 'No' }
    return 'NotPresent'
}

if (-not $RootApprovedForColdChallenge -or -not $KeyBearingCheckpointVerified) { throw 'Root approval and verified key-bearing checkpoint switches are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$product = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid -or $identity.User.Value -cne $expectedSid) { throw 'Exact builder identity guard failed.' }
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Cold challenge requires the pinned vika token with enabled Administrators membership.' }
if ((Get-TestSigningState) -cne 'No') { throw 'Builder testsigning state is not the recorded No baseline.' }
if ((Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.pfx' -Algorithm SHA256).Hash -cne $oldPfxHash -or
    (Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.cer' -Algorithm SHA256).Hash -cne $oldCerHash) { throw 'Original PFX/CER hash changed since the mint baseline.' }
$oldCert = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $oldThumb) -ErrorAction Stop
if ($oldCert.Subject -cne 'CN=SafeUpload Test Signing' -or -not $oldCert.HasPrivateKey) { throw 'Original CurrentUser certificate was not retained.' }
if ((Get-FileHash -LiteralPath $creationMetadataPath -Algorithm SHA256).Hash -cne $ExpectedCreationMetadataSha256.ToUpperInvariant()) { throw 'V7 creation metadata SHA-256 guard failed.' }
if ((Get-FileHash -LiteralPath $publicCerPath -Algorithm SHA256).Hash -cne $ExpectedCerSha256.ToUpperInvariant()) { throw 'V7 public CER SHA-256 guard failed.' }
$metadata = Get-Content -LiteralPath $creationMetadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ($metadata.Status -cne 'CreatedAndProbed' -or $metadata.ComputerName -cne $expectedComputer -or $metadata.UUID -cne $expectedUuid -or
        $metadata.SID -cne $expectedSid -or $metadata.Thumbprint -cne $ExpectedThumbprint.ToUpperInvariant() -or
    $metadata.Subject -cne $subject -or $metadata.NoAclWrite -ne $true -or
    $metadata.EffectiveAdministratorsMembership -ne $true -or $metadata.KeyAclUnchanged -ne $true -or
    $metadata.ChallengeSignatureVerified -ne $true -or $metadata.PrivateKeyMaterialExported -ne $false -or
    $metadata.ChallengeSignaturePersistedOrExported -ne $false -or $metadata.PersistentTrustChanged -ne $false -or
    $metadata.TestSigningBefore -cne 'No' -or $metadata.TestSigningAfter -cne 'No' -or
    $metadata.PublicCerPath -cne $publicCerPath -or $metadata.PublicCerSHA256 -cne $ExpectedCerSha256.ToUpperInvariant()) {
    throw 'V7 creation metadata identity/ACL/use evidence is incomplete or inconsistent.'
}
$certFile = [Security.Cryptography.X509Certificates.X509Certificate2]::new($publicCerPath)
if ($certFile.Thumbprint -cne $ExpectedThumbprint.ToUpperInvariant() -or $certFile.Subject -cne $subject) { throw 'V7 public CER identity mismatch.' }
$eku = @(Get-SafeUploadCodeSigningEkuOids -Extensions @($certFile.Extensions) -Context 'Cold-challenge public CER')
$machineCert = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $ExpectedThumbprint.ToUpperInvariant()) -ErrorAction Stop
if ($machineCert.Subject -cne $subject -or -not $machineCert.HasPrivateKey) { throw 'Exact V7 LocalMachine certificate with private-key association is missing.' }
$rsa = $null
$publicRsa = $null
$challenge = $null
$signature = $null
$rng = $null
try {
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($machineCert)
    if ($rsa -isnot [Security.Cryptography.RSACng] -or $rsa.KeySize -ne 3072 -or
        $rsa.Key.Provider.Provider -cne 'Microsoft Software Key Storage Provider' -or
        $rsa.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None -or
        -not $rsa.Key.IsMachineKey -or $rsa.Key.IsEphemeral -or
        $rsa.Key.UniqueName -cne $metadata.KeyContainerUniqueName) {
        throw 'V7 cold-boot key provider, size, export, or container metadata changed.'
    }
    $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $rsa.Key.UniqueName
    if ($keyPath -cne $metadata.KeyFilePath -or -not (Test-Path -LiteralPath $keyPath -PathType Leaf)) { throw 'V7 machine key path does not match the pinned creation metadata.' }
    $aclBeforeChallenge = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $keyPath -ErrorAction Stop)
    Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $aclBeforeChallenge
    Assert-SafeUploadKeyAclUnchanged -Before $metadata.KeyAclSnapshotBefore -After $aclBeforeChallenge
    Assert-SafeUploadKeyAclUnchanged -Before $metadata.KeyAclSnapshotAfter -After $aclBeforeChallenge

    $storeBefore = Get-StoreThumbInventory
    foreach ($store in $storePaths) {
        $metadataStoreProperty = $metadata.PostMintAllStoreThumbprints.PSObject.Properties[$store]
        if ($null -eq $metadataStoreProperty) { throw "V7 creation metadata is missing store inventory $store." }
        $expectedThumbs = @($metadataStoreProperty.Value)
        if (($storeBefore[$store] -join ',') -cne ($expectedThumbs -join ',')) { throw "Six-store inventory differs from mint evidence in $store." }
    }
    $challenge = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($challenge)
    $signature = $rsa.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $publicRsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certFile)
    if (-not $publicRsa.VerifyData($challenge,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) { throw 'Cold-boot in-memory private/public challenge verification failed.' }
    $aclAfterChallenge = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $keyPath -ErrorAction Stop)
    Assert-SafeUploadKeyAclUnchanged -Before $aclBeforeChallenge -After $aclAfterChallenge
    Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $aclAfterChallenge
    $storeAfter = Get-StoreThumbInventory
    foreach ($store in $storePaths) {
        if (($storeAfter[$store] -join ',') -cne ($storeBefore[$store] -join ',')) { throw "Certificate-store inventory changed during cold challenge in $store." }
    }
    $testSigningAfter = Get-TestSigningState
    if ($testSigningAfter -cne 'No') { throw 'Builder testsigning state changed during cold challenge.' }
    [ordered]@{
        Status='V7_COLD_KEY_CHALLENGE_PASS'; UTC=[DateTime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME; UUID=$product.UUID; User=$identity.Name; SID=$identity.User.Value
        Thumbprint=$machineCert.Thumbprint; Subject=$machineCert.Subject; Provider=$rsa.Key.Provider.Provider; KeySize=$rsa.KeySize; ExportPolicy=$rsa.Key.ExportPolicy.ToString(); IsMachineKey=$rsa.Key.IsMachineKey; IsEphemeral=$rsa.Key.IsEphemeral
        EffectiveAdministratorsMembership=$true; DefaultAclPrincipals=@('S-1-5-18','S-1-5-32-544'); KeyAclUnchangedFromMint=$true; NoAclWrite=$true
        PrivateKeyMaterialExported=$false; TrustChanged=$false; BuildOrArtifactSignAttempted=$false; ChallengeSignaturePersistedOrExported=$false
        CreationMetadataSha256=$ExpectedCreationMetadataSha256.ToUpperInvariant(); PublicCerSha256=$ExpectedCerSha256.ToUpperInvariant(); EnhancedKeyUsageOids=$eku
        TestSigningBefore='No'; TestSigningAfter=$testSigningAfter; PreChallengeAllStoreThumbprints=$storeBefore; PostChallengeAllStoreThumbprints=$storeAfter
    } | ConvertTo-Json -Depth 10 -Compress
} finally {
    if ($challenge) { [Array]::Clear($challenge,0,$challenge.Length) }
    if ($signature) { [Array]::Clear($signature,0,$signature.Length) }
    if ($rng) { $rng.Dispose() }
    if ($publicRsa) { $publicRsa.Dispose() }
    if ($rsa) { $rsa.Dispose() }
}
