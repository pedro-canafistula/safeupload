# REVIEW-ONLY, READ-ONLY baseline verifier for a cold-booted V10 trusted signer checkpoint.
# Derived from /tmp/safeupload-v10-independent-baseline.ps1; this candidate has not been executed.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $PublicProofDirectory,
    [Parameter(Mandatory)][string] $TrustRootReadoutPath,
    [Parameter(Mandatory)][string] $ColdRootReadoutPath,
    [Parameter(Mandatory)][string] $PostSignIndependentReadoutPath,
    [Parameter(Mandatory)][string] $PostSignStderrPath,
    [Parameter(Mandatory)][string] $PostSignRootReadoutPath
)
$ErrorActionPreference = 'Stop'

$expectedComputer = 'DESKTOP-O1LP5DG'
$expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$oldThumb = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$newThumb = 'A6D6CE1AA28835D509160A80ADB7894869AADF38'
$newSubject = 'CN=SafeUpload Test Signing Recovery 20261006 V8'
$metadataSha = '51701037AF41FCC19101E26DD2D632934D20B94190D42782474F68F05ABDFC1E'
$cerSha = '47E7069980A60CBCF4DFF61F0F2D3F02EDCF97C2976708790B49D03A09243B2A'
$trustReceiptSha = 'ac22de20b6845a524de4fbb157514171eef02ef5678384c5c36225aea8306daa'
$trustReadoutSha = '546e4af933179b58781f4c928c74740077083e40012306247653b51fc4116901'
$coldReceiptSha = '3ec14f6af6883fae2fa51e4945da12a8390d12e599e384231c1c061bdc4ba93e'
$coldReadoutSha = 'f940d145b5e8126c0666cf06413969cb548fb67c8620f7ff7b0510615e1ba61c'
$proofJsonSha = 'f007f1bb9522ec38c7ea043b62546409aaa9ab6731fd331724a2ab396d7e710a'
$proofManifestSha = '8e51d83991a97fe274ba30b1fe1138984a6a6e3b6cd1fa452a704c3aa35fb028'
$signedArtifactSha = '30ae04a0033fe80577f608d1fe8e10a06cf2faa2ca034f88d1b848c3630cb14d'
$postSignIndependentReadoutSha = 'abbd29d85a527798722bf7c48432fff6165825651bf5510a32dc9e34b26a0282'
$postSignStderrSha = 'a3639af5e23464fc391dae127fd5493f02c8178068a35866d9c7fdd35dcd623f'
$postSignRootReadoutSha = '155ce22a721fb17b2200bc788c60d63fb06fcda5786720550cda1fc75f7820e5'
$proofRootRunSha = '7652a3b1a0b2158b48e8a5e66b024f816864bc204a0fba92ea0cea4de0cd1d94'
$signerProofScriptSha = 'de29f2e9770e8c478770af33b04f194b0d810185bafac64b6c91652a5e0a7d8d'
$trustScriptSha = '235f1c14cfcbd402c4fb7f464a7c2af2c54bcc67ac78ecb57f0b815903ca749a'
$helperPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v8.ps1'
$helperSha = '9585e1acd512f9532de032c6ce2df251fa774acc83d27cfc6afceb437ce64c42'
$metadataPath = 'C:\Users\vika\Documents\exact-mvp20261006admissioncap2\replacement-machine-key-v8-metadata.json'
$publicCerPath = 'C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v8.cer'
$oldPfxPath = 'C:\safeupload-cert\SafeUploadTest.pfx'
$oldCerPath = 'C:\safeupload-cert\SafeUploadTest.cer'
$storePaths = @(
    'Cert:\CurrentUser\My', 'Cert:\CurrentUser\Root', 'Cert:\CurrentUser\TrustedPublisher',
    'Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher'
)

function Get-FileSha256([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ("Missing pinned file: {0}" -f $Path) }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}
function Assert-FileSha256([string] $Path, [string] $Expected, [string] $Name) {
    if ((Get-FileSha256 $Path) -cne $Expected.ToLowerInvariant()) { throw ("{0} SHA-256 mismatch." -f $Name) }
}
function Read-PinnedJson([string] $Path, [string] $Expected, [string] $Name) {
    Assert-FileSha256 $Path $Expected $Name
    try { return (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw ("{0} is not valid JSON." -f $Name) }
}
function Read-PinnedJsonLines([string] $Path, [string] $Expected, [string] $Name, [int] $ExpectedCount) {
    Assert-FileSha256 $Path $Expected $Name
    $lines = @(Get-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop)
    if ($lines.Count -ne $ExpectedCount) { throw ("{0} line count mismatch." -f $Name) }
    $records = @()
    foreach ($line in $lines) {
        try { $records += ($line | ConvertFrom-Json -ErrorAction Stop) }
        catch { throw ("{0} contains invalid JSON Lines." -f $Name) }
    }
    return $records
}
function Get-Thumbs([object] $Inventory, [string] $Store) {
    $property = $Inventory.PSObject.Properties[$Store]
    if ($null -eq $property) { throw ("Store inventory missing {0}." -f $Store) }
    return @($property.Value | ForEach-Object { ([string]$_).ToUpperInvariant() } | Sort-Object)
}
function Assert-InventoryEqual([object] $Left, [object] $Right, [string] $Context) {
    foreach ($store in $storePaths) {
        $a = @(Get-Thumbs $Left $store); $b = @(Get-Thumbs $Right $store)
        if (($a -join ',') -cne ($b -join ',')) { throw ("{0}: inventory mismatch at {1}." -f $Context, $store) }
    }
}
function Get-StoreInventory {
    $result = [ordered]@{}
    foreach ($store in $storePaths) {
        $result[$store] = @(Get-ChildItem -LiteralPath $store -ErrorAction Stop |
            ForEach-Object { $_.Thumbprint.ToUpperInvariant() } | Sort-Object)
    }
    return $result
}
function Get-TestSigningState {
    $raw = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Could not read builder testsigning state.' }
    if ($raw -match '(?im)^\s*testsigning\s+Yes\s*$') { return 'Yes' }
    if ($raw -match '(?im)^\s*testsigning\s+No\s*$') { return 'No' }
    return 'NotPresent'
}
function Assert-ExactProofManifest([string] $Path) {
    Assert-FileSha256 $Path $proofManifestSha 'Artifact proof package manifest'
    $expected = @{
        'owned-feature.signed.sys' = $signedArtifactSha
        'artifact-signature-proof.json' = $proofJsonSha
        'cold-challenge-receipt.json' = $coldReceiptSha
        'builder-trust-receipt.json' = $trustReceiptSha
    }
    $observed = @{}
    foreach ($line in (Get-Content -LiteralPath $Path -Encoding ASCII -ErrorAction Stop)) {
        if ($line -notmatch '^([0-9A-Fa-f]{64})  ([^/\\]+)$') { throw 'Malformed artifact proof package manifest line.' }
        $name = $matches[2]
        if ($observed.ContainsKey($name)) { throw ("Duplicate proof manifest entry: {0}" -f $name) }
        $observed[$name] = $matches[1].ToLowerInvariant()
    }
    if ((($observed.Keys | Sort-Object) -join ',') -cne (($expected.Keys | Sort-Object) -join ',')) {
        throw 'Artifact proof package contains missing or extra manifest entries.'
    }
    foreach ($name in $expected.Keys) {
        if ($observed[$name] -cne $expected[$name]) { throw ("Unexpected proof manifest hash for {0}." -f $name) }
        Assert-FileSha256 (Join-Path (Split-Path -Parent $Path) $name) $expected[$name] $name
    }
}

Assert-FileSha256 $helperPath $helperSha 'V8 ordered ACL helper'
. $helperPath

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$product = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid -or $identity.User.Value -cne $expectedSid) {
    throw 'Exact builder identity mismatch.'
}
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Pinned builder token lacks enabled Administrators membership.'
}

$metadataHash = Get-FileSha256 $metadataPath
if ($metadataHash -cne $metadataSha) { throw 'V8 creation metadata SHA-256 mismatch.' }
$metadata = Get-Content -LiteralPath $metadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ($metadata.Status -cne 'CreatedAndProbed' -or $metadata.ComputerName -cne $expectedComputer -or
    $metadata.UUID -cne $expectedUuid -or $metadata.SID -cne $expectedSid -or
    $metadata.Thumbprint -cne $newThumb -or $metadata.PublicCerSHA256 -cne $cerSha -or $metadata.Subject -cne $newSubject -or
    $metadata.PublicCerPath -cne $publicCerPath -or
    $metadata.NoAclWrite -ne $true -or $metadata.KeyAclUnchanged -ne $true -or
    $metadata.PrivateKeyMaterialExported -ne $false -or $metadata.PersistentTrustChanged -ne $false -or
    $metadata.ChallengeSignatureVerified -ne $true -or $metadata.ChallengeSignaturePersistedOrExported -ne $false) {
    throw 'V8 mint metadata does not match the pinned no-trust/no-export creation result.'
}
if (@($metadata.PostMintAllStoreThumbprints.PSObject.Properties).Count -ne 6) { throw 'Mint-time six-store inventory is missing.' }
if ($metadata.KeyContainerUniqueName -notmatch '^[A-Za-z0-9{}._-]{1,256}$') { throw 'Malformed V8 machine-key container name.' }
$keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $metadata.KeyContainerUniqueName
if ($metadata.KeyFilePath -cne $keyPath -or -not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
    throw 'Machine key path is not the pinned V8 KSP key file.'
}
Assert-FileSha256 $publicCerPath $cerSha 'V8 public CER'
$publicCer = [Security.Cryptography.X509Certificates.X509Certificate2]::new($publicCerPath)
if ($publicCer.Thumbprint -cne $newThumb -or $publicCer.Subject -cne $newSubject) { throw 'V8 public CER identity mismatch.' }

$trustReceiptPath = Join-Path $PublicProofDirectory 'builder-trust-receipt.json'
$coldReceiptPath = Join-Path $PublicProofDirectory 'cold-challenge-receipt.json'
$proofJsonPath = Join-Path $PublicProofDirectory 'artifact-signature-proof.json'
$proofManifestPath = Join-Path $PublicProofDirectory 'artifact-signature-proof.sha256'
$signedArtifactPath = Join-Path $PublicProofDirectory 'owned-feature.signed.sys'
$trust = Read-PinnedJson $trustReceiptPath $trustReceiptSha 'V10 builder trust receipt'
$cold = Read-PinnedJson $coldReceiptPath $coldReceiptSha 'V8 cold-key challenge receipt C'
$proof = Read-PinnedJson $proofJsonPath $proofJsonSha 'V10 artifact signature proof'
$trustReadout = Read-PinnedJson $TrustRootReadoutPath $trustReadoutSha 'Independent V10 trust readout'
$coldReadout = Read-PinnedJson $ColdRootReadoutPath $coldReadoutSha 'Independent V8 cold-key challenge readout C'
$postSignRecords = @(Read-PinnedJsonLines $PostSignIndependentReadoutPath $postSignIndependentReadoutSha 'Independent post-sign readout JSONL' 2)
Assert-FileSha256 $PostSignStderrPath $postSignStderrSha 'Independent post-sign stderr capture'
$postSignRoot = Read-PinnedJson $PostSignRootReadoutPath $postSignRootReadoutSha 'Independent post-sign root readout'
if ($postSignRecords[0].Verdict -cne 'V10_BUILDER_TRUST_INDEPENDENT_BASELINE_PASS' -or
    $postSignRecords[0].ComputerName -cne $expectedComputer -or $postSignRecords[0].UUID -cne $expectedUuid -or
    $postSignRecords[0].SID -cne $expectedSid -or $postSignRecords[0].Thumbprint -cne $newThumb -or
    $postSignRecords[0].AllSixStoresMatchMintPlusExactMachineRootAndMergedUserRoot -ne $true -or
    $postSignRecords[0].KeyAclUnchanged -ne $true -or $postSignRecords[0].TestSigning -cne 'No' -or
    @($postSignRecords[0].BuildProcesses).Count -ne 0 -or $postSignRecords[0].StateMutated -ne $false) {
    throw 'Independent post-sign builder/trust JSONL record is not the pinned no-mutation baseline.'
}
if ($postSignRecords[1].Status -cne 'INDEPENDENT_SIGNED_ARTIFACT_READ' -or
    $postSignRecords[1].SignedSHA256 -cne $signedArtifactSha -or
    $postSignRecords[1].AuthenticodeStatus -cne 'Valid' -or
    $postSignRecords[1].SignerThumbprint -cne $newThumb -or
    $postSignRecords[1].UnsignedSHA256 -cne '8C19FE05135E10AABACABC433F0DC5CB68A53CCBD7A3CC82052D0D9804586FC9' -or
    $postSignRecords[1].UnsignedAuthenticodeStatus -cne 'NotSigned' -or
    $postSignRecords[1].NoSigningAttempted -ne $true) {
    throw 'Independent post-sign artifact JSONL record does not verify the exact public signed/unsigned pair.'
}
if ($postSignRoot.Verdict -cne 'READY4_SIGNED_COPY_AND_INDEPENDENT_SIGNATURE_VERIFIED' -or
    $postSignRoot.ArtifactWorkflowExitCode -ne 0 -or $postSignRoot.IndependentRemoteExitCode -ne 0 -or
    $postSignRoot.SignedArtifactSHA256 -cne $signedArtifactSha -or
    $postSignRoot.UnsignedSHA256 -cne '8C19FE05135E10AABACABC433F0DC5CB68A53CCBD7A3CC82052D0D9804586FC9' -or
    $postSignRoot.AuthenticodeStatus -cne 'Valid' -or $postSignRoot.SignerThumbprint -cne $newThumb -or
    $postSignRoot.UnsignedUnchanged -ne $true -or $postSignRoot.StoresMatchReviewedTrustBaseline -ne $true -or
    $postSignRoot.KeyAclMatchesMint -ne $true -or $postSignRoot.TestSigningNo -ne $true -or
    $postSignRoot.PrivateKeyExported -ne $false -or $postSignRoot.DriverInstalledOrLoaded -ne $false) {
    throw 'Independent post-sign root readout does not bind the zero-exit no-mutation signature verification.'
}
$postSignExpectedPins = @{
    'driver/evidence/2026-10-06/signing-artifact-proof-v10-post-sign-independent.stdout.json' = $postSignIndependentReadoutSha
    'driver/evidence/2026-10-06/signing-artifact-proof-v10-post-sign-independent.stderr.txt' = $postSignStderrSha
    'output/signing-artifact-proof-v10-20261006a/root-run.json' = $proofRootRunSha
}
foreach ($pinPath in $postSignExpectedPins.Keys) {
    $pin = $postSignRoot.EvidencePins.PSObject.Properties[$pinPath]
    if ($null -eq $pin -or $pin.Value -cne $postSignExpectedPins[$pinPath]) {
        throw ("Independent post-sign root readout does not pin the exact input: {0}." -f $pinPath)
    }
}
Assert-ExactProofManifest $proofManifestPath
$expectedPackageNames = @('artifact-signature-proof.json','artifact-signature-proof.sha256','builder-trust-receipt.json',
    'cold-challenge-receipt.json','owned-feature.signed.sys') | Sort-Object
$actualPackageNames = @(Get-ChildItem -LiteralPath $PublicProofDirectory -Force -ErrorAction Stop |
    ForEach-Object { $_.Name } | Sort-Object)
if (($actualPackageNames -join ',') -cne ($expectedPackageNames -join ',')) {
    throw 'Public artifact proof directory contains unexpected files.'
}

if ($trust.Status -cne 'ExactBuilderLocalMachineRootAddedV10Candidate' -or
    $trust.ComputerName -cne $expectedComputer -or $trust.UUID -cne $expectedUuid -or $trust.User -cne $identity.Name -or
    $trust.Thumbprint -cne $newThumb -or $trust.Subject -cne $newSubject -or
    $trust.Store -cne 'LocalMachine\Root' -or $trust.AddStoreMethod -cne 'certutil -addstore Root (no -user; LocalMachine target)' -or
    $trust.CertutilExitCode -ne 0 -or $trust.TestSigningBefore -cne 'No' -or $trust.TestSigningAfter -cne 'No' -or
    $trust.OnlyApprovedLocalMachineRootDelta -ne $true -or $trust.CurrentUserRootIsExpectedMergedView -ne $true -or
    $trust.TrustedPublisherChanged -ne $false -or $trust.LocalMachineMyUnchanged -ne $true -or
    $trust.KeyAclCheckedUnchanged -ne $true -or $trust.NoAclWrite -ne $true -or
    $trust.CreationMetadataSha256 -cne $metadataSha -or $trust.CerSha256 -cne $cerSha) {
    throw 'V10 trust receipt does not prove the exact approved machine-root trust delta.'
}
if ($trustReadout.Verdict -cne 'V10_BUILDER_MACHINE_ROOT_ONLY_TRUST_INDEPENDENTLY_VERIFIED' -or
    $trustReadout.TrustRemoteExitCode -ne 0 -or $trustReadout.IndependentRemoteExitCode -ne 0 -or
    $trustReadout.Thumbprint -cne $newThumb -or $trustReadout.OnlyMachineRootAndMergedCurrentUserRootChanged -ne $true -or
    $trustReadout.AllOtherStoresExactlyMint -ne $true -or $trustReadout.KeyAclOrderedAndSddlExactlyMint -ne $true -or
    $trustReadout.OriginalFilesAndCertificateRetained -ne $true -or $trustReadout.TestSigningNo -ne $true -or
    $trustReadout.ArtifactSigningAttempted -ne $false -or $trustReadout.PrivateKeyExported -ne $false) {
    throw 'Independent V10 trust readout is not the pinned no-sign/no-export trust verification.'
}
$trustPinProperty = $trustReadout.EvidencePins.PSObject.Properties['driver/evidence/2026-10-06/signing-builder-trust-v10-public-receipt.json']
if ($null -eq $trustPinProperty -or $trustPinProperty.Value -cne $trustReceiptSha) { throw 'Independent trust readout does not pin the exact public receipt.' }
if ($cold.Status -cne 'V8_COLD_KEY_CHALLENGE_PASS' -or $cold.Thumbprint -cne $newThumb -or
    $cold.Subject -cne $newSubject -or $cold.Provider -cne 'Microsoft Software Key Storage Provider' -or
    $cold.KeySize -ne 3072 -or $cold.ExportPolicy -cne 'None' -or $cold.IsMachineKey -ne $true -or
    $cold.IsEphemeral -ne $false -or $cold.EffectiveAdministratorsMembership -ne $true -or
    $cold.CreationMetadataSha256 -cne $metadataSha -or $cold.PublicCerSha256 -cne $cerSha -or
    $cold.TrustChanged -ne $false -or $cold.PrivateKeyMaterialExported -ne $false -or
    $cold.BuildOrArtifactSignAttempted -ne $false -or $cold.ChallengeSignaturePersistedOrExported -ne $false -or
    $cold.TestSigningBefore -cne 'No' -or $cold.TestSigningAfter -cne 'No' -or
    @($cold.EnhancedKeyUsageOids).Count -ne 1 -or @($cold.EnhancedKeyUsageOids)[0] -cne '1.3.6.1.5.5.7.3.3') {
    throw 'Pinned pre-trust V8 cold key challenge receipt is inconsistent.'
}
if ($coldReadout.Verdict -cne 'V8_RETRY2_COLD_KEY_CHALLENGE_VERIFIED' -or
    $coldReadout.RemoteExitCode -ne 0 -or $coldReadout.ReceiptSHA256 -cne $coldReceiptSha -or
    $coldReadout.StoresUnchanged -ne $true -or $coldReadout.KeyAclUnchanged -ne $true -or
    $coldReadout.NoPrivateExport -ne $true -or $coldReadout.NoTrust -ne $true -or
    $coldReadout.NoArtifactSign -ne $true) {
    throw 'Independent V8 cold key challenge readout C is not the pinned no-trust/no-export verification.'
}

Assert-InventoryEqual $trust.BeforeAllStoreThumbprints $metadata.PostMintAllStoreThumbprints 'V10 trust pre-inventory vs V8 mint inventory'
foreach ($store in $storePaths) {
    $before = @(Get-Thumbs $trust.BeforeAllStoreThumbprints $store)
    $after = @(Get-Thumbs $trust.AfterAllStoreThumbprints $store)
    if ($store -ceq 'Cert:\CurrentUser\Root' -or $store -ceq 'Cert:\LocalMachine\Root') {
        if ($before -contains $newThumb) { throw ("V10 thumb was present before approved trust at {0}." -f $store) }
        $expectedAfter = @($before + $newThumb | Sort-Object)
    } else { $expectedAfter = $before }
    if (($after -join ',') -cne ($expectedAfter -join ',')) { throw ("Unexpected trust delta at {0}." -f $store) }
}
$stores = Get-StoreInventory
Assert-InventoryEqual $stores $trust.AfterAllStoreThumbprints 'Current six-store inventory vs V10 trust receipt'

if ($proof.Status -cne 'READY4_ARTIFACT_SIGNED_COPY_VALID' -or
    $proof.BuilderComputerName -cne $expectedComputer -or $proof.BuilderUUID -cne $expectedUuid -or
    $proof.SigningUser -cne $identity.Name -or $proof.SigningUserSid -cne $expectedSid -or
    $proof.EnabledAdministratorsInSigningPowerShell -ne $true -or
    $proof.SignToolExitCode -ne 0 -or $proof.AuthenticodeStatus -cne 'Valid' -or
    $proof.AuthenticodeSignerThumbprint -cne $newThumb -or $proof.SignedArtifactSHA256 -cne $signedArtifactSha -or
    $proof.UnsignedArtifactSHA256 -cne '8C19FE05135E10AABACABC433F0DC5CB68A53CCBD7A3CC82052D0D9804586FC9' -or
    $proof.UnsignedArtifactUnchangedAfterSign -ne $true -or
    $proof.BuilderTrustReceiptSHA256 -cne $trustReceiptSha -or
    $proof.BuilderTrustReceiptStatus -cne $trust.Status -or
    $proof.BuilderTrustMethod -cne $trust.AddStoreMethod -or $proof.BuilderTrustNativeExitCode -ne 0 -or
    $proof.V10BuilderTrustScriptSHA256 -cne $trustScriptSha.ToUpperInvariant() -or
    $proof.SignerScriptSHA256 -cne $signerProofScriptSha.ToUpperInvariant() -or
    $proof.KeyAclMatchesMintBeforeAndAfterSnapshots -ne $true -or $proof.KeyAclChanged -ne $false -or
    $proof.TrustChangedBySigner -ne $false -or $proof.CurrentSixStoreInventoryStillMatchesReviewedTrustReceipt -ne $true) {
    throw 'V10 artifact signature proof does not match the exact post-trust signer result.'
}
if ((Get-FileSha256 $signedArtifactPath) -cne $signedArtifactSha) { throw 'Signed artifact SHA-256 mismatch.' }
$signature = Get-AuthenticodeSignature -LiteralPath $signedArtifactPath -ErrorAction Stop
$signatureThumb = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { 'NONE' }
if ($signature.Status.ToString() -cne 'Valid' -or $signatureThumb -cne $newThumb) { throw 'Public signed artifact is not valid under the exact V8 thumbprint.' }

$machineCerts = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -ErrorAction Stop |
    Where-Object { $_.Thumbprint.ToUpperInvariant() -ceq $newThumb })
if ($machineCerts.Count -ne 1 -or -not $machineCerts[0].HasPrivateKey -or $machineCerts[0].Subject -cne $newSubject) {
    throw 'Exact V8 private certificate is not unique in LocalMachine My.'
}
$oldMachineCert = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -ErrorAction Stop |
    Where-Object { $_.Thumbprint.ToUpperInvariant() -ceq $oldThumb })
if ($oldMachineCert.Count -ne 0) { throw 'Old fallback signer remains in LocalMachine My.' }
$oldUserCert = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $oldThumb) -ErrorAction Stop
if ($oldUserCert.Subject -cne 'CN=SafeUpload Test Signing' -or -not $oldUserCert.HasPrivateKey) {
    throw 'Original CurrentUser signing certificate was not retained.'
}

$files = @()
foreach ($path in @($oldPfxPath, $oldCerPath)) {
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    $files += @([ordered]@{ Path = $path; Length = $item.Length; SHA256 = (Get-FileSha256 $path).ToUpperInvariant() })
}
if ($files[0].SHA256 -cne 'DE1CD348314292C3F391015C9B2790FBE8956D886994BF5C4AE7C67AC51B2F03' -or
    $files[1].SHA256 -cne '46E4E8082155E2EE9E3602C613224322F863ADB85EC02C542FF2F4C8700BA0A1') {
    throw 'Original PFX/CER files changed.'
}
if ((Get-TestSigningState) -cne 'No') { throw 'Builder testsigning state is not No.' }
$actors = @(Get-Process -Name MSBuild,dotnet,csc,vbcsc,VBCSCompiler -ErrorAction SilentlyContinue |
    ForEach-Object { [ordered]@{ Name = $_.ProcessName; Id = $_.Id; StartTimeUtc = $_.StartTime.ToUniversalTime().ToString('o') } })
if ($actors.Count -ne 0) { throw 'Unexpected build process present during trusted checkpoint baseline.' }

$keyAcl = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $keyPath -ErrorAction Stop)
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $keyAcl
Assert-SafeUploadKeyAclUnchanged -Before $metadata.KeyAclSnapshotBefore -After $keyAcl
Assert-SafeUploadKeyAclUnchanged -Before $metadata.KeyAclSnapshotAfter -After $keyAcl
Assert-SafeUploadKeyAclUnchanged -Before $trust.KeyAclBeforeTrust -After $keyAcl
Assert-SafeUploadKeyAclUnchanged -Before $trust.KeyAclAfterTrust -After $keyAcl

[ordered]@{
    UTC = [DateTime]::UtcNow.ToString('o'); BootTimeUtc = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    Verdict = 'V10_TRUSTED_SIGNER_CHECKPOINT_BASELINE_PASS'; ComputerName = $env:COMPUTERNAME; UUID = $product.UUID
    SID = $identity.User.Value; EffectiveAdministratorsMembership = $true
    TrustReceiptSHA256 = $trustReceiptSha; TrustIndependentReadoutSHA256 = $trustReadoutSha
    ColdReceiptSHA256 = $coldReceiptSha; ColdIndependentReadoutSHA256 = $coldReadoutSha
    ArtifactProofJsonSHA256 = $proofJsonSha; ArtifactProofManifestSHA256 = $proofManifestSha
    IndependentPostSignJsonLSHA256 = $postSignIndependentReadoutSha
    IndependentPostSignStderrSHA256 = $postSignStderrSha
    IndependentPostSignRootReadoutSHA256 = $postSignRootReadoutSha
    SignedArtifactSHA256 = $signedArtifactSha
    SignerProofScriptSHA256 = $signerProofScriptSha; V10BuilderTrustScriptSHA256 = $trustScriptSha
    Stores = $stores; CurrentSixStoreInventoryMatchesV10TrustReceipt = $true
    OnlyApprovedMachineRootAndMergedUserRootPresentSinceMintEvidence = $true
    NewThumbprint = $newThumb; NewCertificateInLocalMachineMy = $true; NewCertificateAbsentFromOtherThreeStores = $true
    NewCertificateHasPrivateKeyAssociation = $true; NewCertificatePublicCerSha256 = $cerSha
    KeyAcl = $keyAcl; KeyAclMatchesMintAndTrustSnapshots = $true; KeyAclChanged = $false
    OriginalFiles = $files; OriginalCertificateRetained = $true; TestSigning = 'No'; BuildProcesses = $actors
    ArtifactSigningProofVerified = $true; TrustChangedDuringBaseline = $false; PrivateKeyMaterialExported = $false
    StateMutated = $false
} | ConvertTo-Json -Depth 10 -Compress
