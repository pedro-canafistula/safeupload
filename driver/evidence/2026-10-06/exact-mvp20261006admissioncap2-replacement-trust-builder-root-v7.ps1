# REVIEW ONLY: V7 adds the exact new public certificate to vika CurrentUser Root.
# Required because Build-ExactSource.ps1 gates on Authenticode Status=Valid.
# Not executed. Never adds TrustedPublisher or changes machine trust.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch] $RootApprovedForBuilderTrust,
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
$expectedComputer = 'DESKTOP-O1LP5DG'; $expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'; $expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$oldThumb = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$oldPfxHash = 'DE1CD348314292C3F391015C9B2790FBE8956D886994BF5C4AE7C67AC51B2F03'
$oldCerHash = '46E4E8082155E2EE9E3602C613224322F863ADB85EC02C542FF2F4C8700BA0A1'
$subject = 'CN=SafeUpload Test Signing Recovery 20261006 V7'
$cerPath = 'C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v7.cer'
$creationMetadataPath = 'C:\Users\vika\Documents\exact-mvp20261006admissioncap2\replacement-machine-key-v7-metadata.json'
if (-not $RootApprovedForBuilderTrust -or -not $KeyBearingCheckpointVerified) { throw 'Root approval and verified key-bearing builder checkpoint switches are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $product = Get-CimInstance Win32_ComputerSystemProduct
if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid -or $identity.User.Value -cne $expectedSid) { throw 'Exact builder identity guard failed.' }
if ((Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.pfx' -Algorithm SHA256).Hash -cne $oldPfxHash -or
    (Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.cer' -Algorithm SHA256).Hash -cne $oldCerHash) { throw 'Original PFX/CER hash guard failed before builder trust.' }
$oldCert = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $oldThumb) -ErrorAction Stop
if ($oldCert.Subject -cne 'CN=SafeUpload Test Signing' -or -not $oldCert.HasPrivateKey) { throw 'Original CurrentUser certificate was not retained.' }
if ((Get-FileHash -LiteralPath $cerPath -Algorithm SHA256).Hash -cne $ExpectedCerSha256.ToUpperInvariant()) { throw 'Public CER SHA-256 guard failed.' }
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)
if ($cert.Thumbprint -cne $ExpectedThumbprint.ToUpperInvariant() -or $cert.Subject -cne $subject) { throw 'Public CER identity guard failed.' }
$machineCert = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $cert.Thumbprint) -ErrorAction Stop
if (-not $machineCert.HasPrivateKey -or $machineCert.Subject -cne $subject) { throw 'Matching LocalMachine private certificate is missing.' }
$eku = @(Get-SafeUploadCodeSigningEkuOids -Extensions @($cert.Extensions) -Context 'Builder public CER')
if ((Get-FileHash -LiteralPath $creationMetadataPath -Algorithm SHA256).Hash -cne $ExpectedCreationMetadataSha256.ToUpperInvariant()) { throw 'V7 creation metadata SHA-256 guard failed.' }
$creationMetadata = Get-Content -LiteralPath $creationMetadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ($creationMetadata.Status -cne 'CreatedAndProbed' -or $creationMetadata.Thumbprint -cne $cert.Thumbprint -or
    $creationMetadata.Subject -cne $subject -or $creationMetadata.PublicCerSHA256 -cne $ExpectedCerSha256.ToUpperInvariant() -or
    $creationMetadata.PublicCerPath -cne $cerPath -or $creationMetadata.NoAclWrite -ne $true -or
    $creationMetadata.EffectiveAdministratorsMembership -ne $true -or $creationMetadata.KeyAclUnchanged -ne $true -or
    $creationMetadata.PrivateKeyMaterialExported -ne $false) { throw 'Pinned V7 creation metadata does not attest the expected no-ACL-write key.' }
$metadataKeyPath = [string]$creationMetadata.KeyFilePath
$keyUniqueName = [string]$creationMetadata.KeyContainerUniqueName
if ([string]::IsNullOrWhiteSpace($keyUniqueName) -or $keyUniqueName -notmatch '^[A-Za-z0-9{}._-]{1,256}$') { throw 'V7 CNG unique-name metadata is malformed.' }
$expectedMetadataKeyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $keyUniqueName
if ($metadataKeyPath -cne $expectedMetadataKeyPath -or -not (Test-Path -LiteralPath $metadataKeyPath -PathType Leaf)) { throw 'V7 KSP key path does not exactly match the pinned unique-name file in the machine key directory.' }
$currentAcl = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $metadataKeyPath -ErrorAction Stop)
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $currentAcl
Assert-SafeUploadKeyAclUnchanged -Before $creationMetadata.KeyAclSnapshotBefore -After $currentAcl
Assert-SafeUploadKeyAclUnchanged -Before $creationMetadata.KeyAclSnapshotAfter -After $currentAcl
$newThumb = $cert.Thumbprint
$stores = @('Cert:\CurrentUser\My','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher','Cert:\LocalMachine\My','Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')
function Get-StoreInventory {
    $snapshot = [ordered]@{}
    foreach ($store in $stores) {
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
$testSigningBefore = Get-TestSigningState
if ($testSigningBefore -cne 'No') { throw 'Builder testsigning state must remain No before builder trust.' }
$before = Get-StoreInventory
foreach ($store in $stores) {
    $newThumbCount = @($before[$store] | Where-Object { $_ -ceq $newThumb }).Count
    if ($store -ceq 'Cert:\LocalMachine\My') {
        if ($newThumbCount -ne 1) { throw 'New thumb must be present exactly once in LocalMachine My before builder trust.' }
    } elseif ($newThumbCount -ne 0) {
        throw "New thumbprint is already present outside its expected LocalMachine My key store: $store."
    }
}
try {
    Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    $after = Get-StoreInventory
    foreach ($store in $stores) {
        $expectedThumbs = @($before[$store])
        if ($store -ceq 'Cert:\CurrentUser\Root') { $expectedThumbs = @($expectedThumbs + $newThumb | Sort-Object) }
        if (($after[$store] -join ',') -cne ($expectedThumbs -join ',')) { throw "Builder trust inventory changed unexpectedly in $store." }
    }
    $aclAfterTrust = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $metadataKeyPath -ErrorAction Stop)
    Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $aclAfterTrust
    Assert-SafeUploadKeyAclUnchanged -Before $creationMetadata.KeyAclSnapshotBefore -After $aclAfterTrust
    Assert-SafeUploadKeyAclUnchanged -Before $creationMetadata.KeyAclSnapshotAfter -After $aclAfterTrust
    $testSigningAfter = Get-TestSigningState
    if ($testSigningAfter -cne $testSigningBefore) { throw 'Builder testsigning changed during trust operation.' }
    [ordered]@{Status='ExactBuilderRootAdded';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;User=$identity.Name;Thumbprint=$newThumb;Subject=$cert.Subject;CerSha256=$ExpectedCerSha256.ToUpperInvariant();CreationMetadataSha256=$ExpectedCreationMetadataSha256.ToUpperInvariant();Store='CurrentUser\Root';BeforeAllStoreThumbprints=$before;AfterAllStoreThumbprints=$after;TestSigningBefore=$testSigningBefore;TestSigningAfter=$testSigningAfter;OnlyApprovedCurrentUserRootDelta=$true;TrustedPublisherChanged=$false;LocalMachineTrustChanged=$false;KeyAclCheckedUnchanged=$true;NoAclWrite=$true;CreationMetadataStatus=$creationMetadata.Status}|ConvertTo-Json -Depth 8 -Compress
} catch {
    Get-ChildItem -LiteralPath 'Cert:\CurrentUser\Root' -ErrorAction Stop | Where-Object { $_.Thumbprint -ceq $newThumb } | Remove-Item -Force
    throw 'Builder-root verification failed; the exact new thumb was removed from CurrentUser Root. Restore checkpoint and re-inventory before retry.'
}
