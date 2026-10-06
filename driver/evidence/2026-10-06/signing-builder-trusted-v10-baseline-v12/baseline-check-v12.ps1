# V12 amendment: audit the pinned evidence schemas and bind the real post-sign ACL fields.
# REVIEW-ONLY, READ-ONLY baseline verifier for a cold-booted V10 trusted signer checkpoint.
# Frozen V10 and V11 sources remain immutable; this candidate has not been executed.
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
function Test-Sha256Equal([AllowNull()][object] $Actual, [AllowNull()][object] $Expected) {
    $actualText = [string]$Actual
    $expectedText = [string]$Expected
    if ($actualText -notmatch '\A[0-9A-Fa-f]{64}\z' -or $expectedText -notmatch '\A[0-9A-Fa-f]{64}\z') {
        return $false
    }
    return [string]::Equals($actualText.ToLowerInvariant(), $expectedText.ToLowerInvariant(),
        [StringComparison]::Ordinal)
}
function Assert-FileSha256([string] $Path, [string] $Expected, [string] $Name) {
    if (-not (Test-Sha256Equal (Get-FileSha256 $Path) $Expected)) { throw ("{0} SHA-256 mismatch." -f $Name) }
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
function Assert-ExactObjectSchema([object] $Value, [string] $Context, [string[]] $ExpectedKeys) {
    if ($null -eq $Value) { throw ("{0} is null." -f $Context) }
    $actualKeys = @($Value.PSObject.Properties | ForEach-Object { [string]$_.Name })
    $missing = @()
    foreach ($key in $ExpectedKeys) { if ($actualKeys -cnotcontains $key) { $missing += $key } }
    $extra = @()
    foreach ($key in $actualKeys) { if ($ExpectedKeys -cnotcontains $key) { $extra += $key } }
    if ($missing.Count -gt 0 -or $extra.Count -gt 0) {
        $missingText = if ($missing.Count -gt 0) { $missing -join ',' } else { '<none>' }
        $extraText = if ($extra.Count -gt 0) { $extra -join ',' } else { '<none>' }
        throw ("{0} schema mismatch; missing=[{1}], extra=[{2}]." -f $Context, $missingText, $extraText)
    }
}
function Assert-FieldValue([AllowNull()][object] $Actual, [AllowNull()][object] $Expected, [string] $Context) {
    if ($null -eq $Expected) {
        if ($null -ne $Actual) { throw ("{0} expected null." -f $Context) }
        return
    }
    if ($null -eq $Actual) { throw ("{0} is missing or null." -f $Context) }
    if ($Expected -is [string]) {
        if ($Actual -isnot [string] -or -not [string]::Equals($Actual, $Expected, [StringComparison]::Ordinal)) {
            throw ("{0} mismatch." -f $Context)
        }
        return
    }
    if ($Expected -is [bool]) {
        if ($Actual -isnot [bool] -or $Actual -ne $Expected) { throw ("{0} mismatch or has a non-Boolean type." -f $Context) }
        return
    }
    if ($Expected -is [System.ValueType]) {
        if ($Actual -isnot [System.ValueType] -or $Actual -is [bool]) { throw ("{0} mismatch or has a non-numeric type." -f $Context) }
        try { $actualNumber = [decimal]$Actual }
        catch { throw ("{0} has an invalid numeric type." -f $Context) }
        if ($actualNumber -ne [decimal]$Expected) { throw ("{0} mismatch." -f $Context) }
        return
    }
    if ($Actual -ne $Expected) { throw ("{0} mismatch." -f $Context) }
}
function Assert-Sha256Field([AllowNull()][object] $Actual, [string] $Expected, [string] $Context) {
    if (-not (Test-Sha256Equal $Actual $Expected)) { throw ("{0} mismatch or is not a 64-character SHA-256 digest." -f $Context) }
}
function Assert-StoreInventorySchema([object] $Inventory, [string] $Context, [string[]] $ExpectedStores) {
    Assert-ExactObjectSchema $Inventory $Context $ExpectedStores
    foreach ($store in $ExpectedStores) {
        $property = $Inventory.PSObject.Properties[$store]
        if ($null -eq $property -or $null -eq $property.Value) { throw ("{0}.{1} is missing." -f $Context, $store) }
        foreach ($thumb in @($property.Value)) {
            if ($thumb -isnot [string] -or $thumb -notmatch '\A[0-9A-Fa-f]{40}\z') {
                throw ("{0}.{1} contains a non-thumbprint value." -f $Context, $store)
            }
        }
    }
}
function Assert-KeyAclSnapshotSchema([object] $Snapshot, [string] $Context) {
    Assert-ExactObjectSchema $Snapshot $Context @('Sddl','Owner','Group','OwnerSid','GroupSid',
        'AreAccessRulesProtected','AreAccessRulesCanonical','OrderedAceRows')
    foreach ($field in @('Sddl','Owner','Group','OwnerSid','GroupSid')) {
        $value = $Snapshot.PSObject.Properties[$field].Value
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
            throw ("{0}.{1} must be a non-empty string." -f $Context, $field)
        }
    }
    foreach ($field in @('AreAccessRulesProtected','AreAccessRulesCanonical')) {
        if ($Snapshot.PSObject.Properties[$field].Value -isnot [bool]) {
            throw ("{0}.{1} must be Boolean." -f $Context, $field)
        }
    }
    $rows = @($Snapshot.OrderedAceRows)
    if ($rows.Count -ne 3) { throw ("{0}.OrderedAceRows must contain exactly three rows." -f $Context) }
    foreach ($row in $rows) { if ($row -isnot [string]) { throw ("{0}.OrderedAceRows contains a non-string row." -f $Context) } }
}
function Assert-PostSignAclMatchesSnapshot([object] $Record, [object] $Snapshot, [string] $Context) {
    Assert-FieldValue $Record.KeyAclSddl $Snapshot.Sddl ("{0}.KeyAclSddl" -f $Context)
    Assert-FieldValue $Record.KeyAclOwner $Snapshot.OwnerSid ("{0}.KeyAclOwner vs snapshot OwnerSid" -f $Context)
    Assert-FieldValue $Record.KeyAclGroup $Snapshot.GroupSid ("{0}.KeyAclGroup vs snapshot GroupSid" -f $Context)
    Assert-FieldValue $Record.KeyAclProtected $Snapshot.AreAccessRulesProtected ("{0}.KeyAclProtected" -f $Context)
    Assert-FieldValue $Record.KeyAclCanonical $Snapshot.AreAccessRulesCanonical ("{0}.KeyAclCanonical" -f $Context)
    $expectedRows = @($Snapshot.OrderedAceRows)
    $rules = @($Record.KeyAclRules)
    if ($rules.Count -ne $expectedRows.Count) { throw ("{0}.KeyAclRules count differs from pinned ACL snapshot." -f $Context) }
    $actualRows = @()
    for ($index = 0; $index -lt $rules.Count; $index++) {
        $ruleContext = ("{0}.KeyAclRules[{1}]" -f $Context, $index)
        $rule = $rules[$index]
        Assert-ExactObjectSchema $rule $ruleContext @('SID','Rights','Type','Inherited','Inheritance','Propagation')
        $parts = [string]$expectedRows[$index] -split '\|',6
        if ($parts.Count -ne 6) { throw ("{0} snapshot ACE row is malformed." -f $ruleContext) }
        Assert-FieldValue $rule.SID $parts[0] ("{0}.SID" -f $ruleContext)
        Assert-FieldValue $rule.Type $parts[1] ("{0}.Type" -f $ruleContext)
        Assert-FieldValue $rule.Rights ([int]$parts[2]) ("{0}.Rights" -f $ruleContext)
        Assert-FieldValue $rule.Inherited ([bool]::Parse($parts[5])) ("{0}.Inherited" -f $ruleContext)
        if ($rule.Inheritance -isnot [System.ValueType] -or [int]$rule.Inheritance -ne 0) {
            throw ("{0}.Inheritance must be the pinned non-inheriting zero value." -f $ruleContext)
        }
        if ($rule.Propagation -isnot [System.ValueType] -or [int]$rule.Propagation -ne 0) {
            throw ("{0}.Propagation must be the pinned zero value." -f $ruleContext)
        }
        $actualRows += ('{0}|{1}|{2}|None|None|{3}' -f $rule.SID,$rule.Type,[int]$rule.Rights,[string]([bool]$rule.Inherited))
    }
    if (($actualRows -join "`n") -cne ($expectedRows -join "`n")) {
        throw ("{0}.KeyAclRules ordered values differ from the mint/trust ACL snapshot." -f $Context)
    }
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
        if (-not (Test-Sha256Equal $observed[$name] $expected[$name])) { throw ("Unexpected proof manifest hash for {0}." -f $name) }
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
Assert-Sha256Field $metadataHash $metadataSha 'V8 creation metadata file'
$metadata = Get-Content -LiteralPath $metadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
Assert-ExactObjectSchema $metadata 'V8 mint metadata' @('Status','UTC','ComputerName','UUID','User','SID','Thumbprint','Subject','Issuer','NotBeforeUtc','NotAfterUtc','Store','Provider','Algorithm','KeySize','PublicKeyOid','SignatureAlgorithmOid','IssuerEqualsSubject','BasicConstraintsCount','BasicConstraintsCA','IsMachineKey','IsEphemeral','ExportPolicy','PrivateKeyMaterialExported','KeyContainerUniqueName','KeyFilePath','KeyAclSnapshotBefore','KeyAclSnapshotAfter','KeyAclUnchanged','DefaultAclPrincipals','CreatorOwnerKeptAsLiteralProviderAce','EffectiveAdministratorsMembership','NoAclWrite','EnhancedKeyUsageOids','KeyUsage','PublicCerPath','PublicCerSHA256','PreMintAllStoreThumbprints','PostMintAllStoreThumbprints','TestSigningBefore','TestSigningAfter','ChallengeSignatureVerified','ChallengeSignaturePersistedOrExported','PersistentTrustChanged')
Assert-KeyAclSnapshotSchema $metadata.KeyAclSnapshotBefore 'V8 mint metadata.KeyAclSnapshotBefore'
Assert-KeyAclSnapshotSchema $metadata.KeyAclSnapshotAfter 'V8 mint metadata.KeyAclSnapshotAfter'
$certStoreKeys = @('Cert:\CurrentUser\My','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher','Cert:\LocalMachine\My','Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')
Assert-StoreInventorySchema $metadata.PreMintAllStoreThumbprints 'V8 mint metadata.PreMintAllStoreThumbprints' $certStoreKeys
Assert-StoreInventorySchema $metadata.PostMintAllStoreThumbprints 'V8 mint metadata.PostMintAllStoreThumbprints' $certStoreKeys
Assert-FieldValue $metadata.Status 'CreatedAndProbed' 'V8 mint metadata.Status'
Assert-FieldValue $metadata.ComputerName $expectedComputer 'V8 mint metadata.ComputerName'
Assert-FieldValue $metadata.UUID $expectedUuid 'V8 mint metadata.UUID'
Assert-FieldValue $metadata.SID $expectedSid 'V8 mint metadata.SID'
Assert-FieldValue $metadata.Thumbprint $newThumb 'V8 mint metadata.Thumbprint'
Assert-Sha256Field $metadata.PublicCerSHA256 $cerSha 'V8 mint metadata.PublicCerSHA256'
Assert-FieldValue $metadata.Subject $newSubject 'V8 mint metadata.Subject'
Assert-FieldValue $metadata.PublicCerPath $publicCerPath 'V8 mint metadata.PublicCerPath'
Assert-FieldValue $metadata.NoAclWrite $true 'V8 mint metadata.NoAclWrite'
Assert-FieldValue $metadata.KeyAclUnchanged $true 'V8 mint metadata.KeyAclUnchanged'
Assert-FieldValue $metadata.PrivateKeyMaterialExported $false 'V8 mint metadata.PrivateKeyMaterialExported'
Assert-FieldValue $metadata.PersistentTrustChanged $false 'V8 mint metadata.PersistentTrustChanged'
Assert-FieldValue $metadata.ChallengeSignatureVerified $true 'V8 mint metadata.ChallengeSignatureVerified'
Assert-FieldValue $metadata.ChallengeSignaturePersistedOrExported $false 'V8 mint metadata.ChallengeSignaturePersistedOrExported'
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

# Schema checks below were derived from the exact SHA-pinned JSON/JSONL inputs,
# not from presumed property names. Keep the full observed object shapes exact.
$trustStoreKeys = @('Cert:\CurrentUser\My','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher','Cert:\LocalMachine\My','Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')
$postSignStoreKeys = @('CurrentUser\My','CurrentUser\Root','CurrentUser\TrustedPublisher','LocalMachine\My','LocalMachine\Root','LocalMachine\TrustedPublisher')
Assert-ExactObjectSchema $trust 'V10 trust receipt' @('Status','UTC','ComputerName','UUID','User','Thumbprint','Subject','Issuer','CertificateAuthority','CerSha256','CreationMetadataSha256','Store','AddStoreMethod','CertutilExitCode','CertutilStdout','CertutilStderr','BeforeAllStoreThumbprints','AfterAllStoreThumbprints','KeyAclBeforeTrust','KeyAclAfterTrust','TestSigningBefore','TestSigningAfter','OnlyApprovedLocalMachineRootDelta','CurrentUserRootIsExpectedMergedView','TrustedPublisherChanged','LocalMachineMyUnchanged','KeyAclCheckedUnchanged','NoAclWrite','CreationMetadataStatus')
Assert-StoreInventorySchema $trust.BeforeAllStoreThumbprints 'V10 trust receipt.BeforeAllStoreThumbprints' $trustStoreKeys
Assert-StoreInventorySchema $trust.AfterAllStoreThumbprints 'V10 trust receipt.AfterAllStoreThumbprints' $trustStoreKeys
Assert-KeyAclSnapshotSchema $trust.KeyAclBeforeTrust 'V10 trust receipt.KeyAclBeforeTrust'
Assert-KeyAclSnapshotSchema $trust.KeyAclAfterTrust 'V10 trust receipt.KeyAclAfterTrust'
Assert-ExactObjectSchema $trustReadout 'V10 independent trust readout' @('UTC','Verdict','TrustRemoteExitCode','IndependentRemoteExitCode','Thumbprint','OnlyMachineRootAndMergedCurrentUserRootChanged','AllOtherStoresExactlyMint','KeyAclOrderedAndSddlExactlyMint','OriginalFilesAndCertificateRetained','TestSigningNo','ArtifactSigningAttempted','PrivateKeyExported','EvidencePins')
Assert-ExactObjectSchema $trustReadout.EvidencePins 'V10 independent trust readout.EvidencePins' @('driver/evidence/2026-10-06/signing-builder-trust-v10-20261006a.stdout.txt','driver/evidence/2026-10-06/signing-builder-trust-v10-20261006a.stderr.txt','driver/evidence/2026-10-06/signing-builder-v10-post-trust-independent.stdout.json','driver/evidence/2026-10-06/signing-builder-v10-post-trust-independent.stderr.txt','output/signing-builder-trust-v10-20261006a/root-run.json','driver/evidence/2026-10-06/signing-builder-trust-v10-public-receipt.json','driver/evidence/2026-10-06/signing-builder-trust-v10-source-and-evidence-sha256.txt')
Assert-ExactObjectSchema $cold 'V8 cold challenge receipt C' @('Status','UTC','ComputerName','UUID','User','SID','Thumbprint','Subject','Provider','KeySize','ExportPolicy','IsMachineKey','IsEphemeral','EffectiveAdministratorsMembership','DefaultAclPrincipals','CreatorOwnerKeptAsLiteralProviderAce','KeyAclUnchangedFromMint','NoAclWrite','PrivateKeyMaterialExported','TrustChanged','BuildOrArtifactSignAttempted','ChallengeSignaturePersistedOrExported','CreationMetadataSha256','PublicCerSha256','EnhancedKeyUsageOids','TestSigningBefore','TestSigningAfter','PreChallengeAllStoreThumbprints','PostChallengeAllStoreThumbprints')
Assert-StoreInventorySchema $cold.PreChallengeAllStoreThumbprints 'V8 cold challenge receipt C.PreChallengeAllStoreThumbprints' $trustStoreKeys
Assert-StoreInventorySchema $cold.PostChallengeAllStoreThumbprints 'V8 cold challenge receipt C.PostChallengeAllStoreThumbprints' $trustStoreKeys
Assert-ExactObjectSchema $coldReadout 'V8 cold challenge independent readout C' @('UTC','Verdict','Thumbprint','CerSha256','MetadataSha256','ReceiptSHA256','RemoteExitCode','StoresUnchanged','KeyAclUnchanged','NoPrivateExport','NoTrust','NoArtifactSign','StderrAssessment','EvidencePins')
Assert-ExactObjectSchema $coldReadout.EvidencePins 'V8 cold challenge independent readout C.EvidencePins' @('driver/evidence/2026-10-06/signing-cold-challenge-v8-20261006c.stdout.txt','driver/evidence/2026-10-06/signing-cold-challenge-v8-20261006c.stderr.txt','driver/evidence/2026-10-06/signing-cold-challenge-v8-public-receipt-c.json','driver/evidence/2026-10-06/signing-builder-key-bearing-recovery-v8-retry2/host-readout.json','driver/evidence/2026-10-06/signing-builder-key-bearing-recovery-v8-retry2/guest-baseline-root-readout.json','output/signing-cold-challenge-v8-20261006c/root-run.json')
$postSignBase = $postSignRecords[0]
$postSignArtifact = $postSignRecords[1]
Assert-ExactObjectSchema $postSignBase 'Independent post-sign JSONL record 0' @('KeyAclSddl','KeyAclOwner','KeyAclGroup','KeyAclProtected','KeyAclCanonical','KeyAclRules','UTC','BootTimeUtc','Verdict','ComputerName','UUID','SID','EffectiveAdministratorsMembership','Stores','AllSixStoresMatchMintPlusExactMachineRootAndMergedUserRoot','NewThumbprint','NewCertificateInLocalMachineMy','NewCertificateAbsentFromOtherThreeStores','NewCertificateHasPrivateKeyAssociation','NewCertificatePublicCerSha256','CreationMetadataSha256','OriginalFiles','OriginalCertificate','TestSigning','BuildProcesses','OnlyApprovedMachineRootAndMergedUserRootAddedSinceMintEvidence','StateMutated')
Assert-StoreInventorySchema $postSignBase.Stores 'Independent post-sign JSONL record 0.Stores' $postSignStoreKeys
if (@($postSignBase.KeyAclRules).Count -ne 3) { throw 'Independent post-sign JSONL record 0.KeyAclRules must contain exactly three rules.' }
foreach ($rule in @($postSignBase.KeyAclRules)) { Assert-ExactObjectSchema $rule 'Independent post-sign JSONL record 0.KeyAclRules item' @('SID','Rights','Type','Inherited','Inheritance','Propagation') }
if (@($postSignBase.OriginalFiles).Count -ne 2) { throw 'Independent post-sign JSONL record 0.OriginalFiles must contain two file records.' }
foreach ($file in @($postSignBase.OriginalFiles)) { Assert-ExactObjectSchema $file 'Independent post-sign JSONL record 0.OriginalFiles item' @('Path','Length','SHA256') }
Assert-ExactObjectSchema $postSignBase.OriginalCertificate 'Independent post-sign JSONL record 0.OriginalCertificate' @('Thumbprint','Subject','HasPrivateKey')
Assert-ExactObjectSchema $postSignArtifact 'Independent post-sign JSONL record 1' @('Status','SignedPath','SignedSHA256','AuthenticodeStatus','SignerThumbprint','UnsignedSHA256','UnsignedAuthenticodeStatus','NoSigningAttempted')
Assert-ExactObjectSchema $postSignRoot 'Independent post-sign root readout' @('UTC','Verdict','ArtifactWorkflowExitCode','IndependentRemoteExitCode','SignedArtifactSHA256','UnsignedSHA256','AuthenticodeStatus','SignerThumbprint','UnsignedUnchanged','StoresMatchReviewedTrustBaseline','KeyAclMatchesMint','TestSigningNo','PrivateKeyExported','DriverInstalledOrLoaded','EvidencePins')
Assert-ExactObjectSchema $postSignRoot.EvidencePins 'Independent post-sign root readout.EvidencePins' @('driver/evidence/2026-10-06/signing-artifact-proof-v10-20261006a.stdout.txt','driver/evidence/2026-10-06/signing-artifact-proof-v10-20261006a.stderr.txt','driver/evidence/2026-10-06/signing-artifact-proof-v10-post-sign-independent.stdout.json','driver/evidence/2026-10-06/signing-artifact-proof-v10-post-sign-independent.stderr.txt','output/signing-artifact-proof-v10-20261006a/root-run.json','output/signing-artifact-proof-v10-20261006a/public-proof/owned-feature.signed.sys','output/signing-artifact-proof-v10-20261006a/public-proof/artifact-signature-proof.json','output/signing-artifact-proof-v10-20261006a/public-proof/artifact-signature-proof.sha256','output/signing-artifact-proof-v10-20261006a/public-proof/cold-challenge-receipt.json','output/signing-artifact-proof-v10-20261006a/public-proof/builder-trust-receipt.json','driver/evidence/2026-10-06/exact-mvp20261006ready4-artifact-sign-proof-v10-source-manifest.sha256')
Assert-ExactObjectSchema $proof 'V10 artifact signature proof' @('Status','UTC','ProofGuid','BuilderComputerName','BuilderUUID','SigningUser','SigningUserSid','EnabledAdministratorsInSigningPowerShell','SigningPowerShellProcessId','SignToolProcessId','SamePowerShellCheckedIdentityAndStartedSignTool','SignToolExitCode','SignToolPath','SignToolStore','SignToolSelection','BuildExactSourceSha256','SignToolThumbprint','AuthenticodeStatus','AuthenticodeSignerThumbprint','UnsignedArtifactSHA256','UnsignedArtifactUnchangedAfterSign','SignedArtifactSHA256','ColdReceiptSHA256','ColdReceiptStatus','BuilderTrustReceiptSHA256','BuilderTrustReceiptStatus','BuilderTrustStore','BuilderTrustMethod','BuilderTrustLocalMachineRootOnly','BuilderTrustCurrentUserRootExpectedMergedView','BuilderTrustNativeExitCode','SignerScriptSHA256','V8AclHelperSHA256','V8ColdChallengeScriptSHA256','V10BuilderTrustScriptSHA256','V8MetadataSHA256','V8PublicCerSHA256','KeyAclMatchesMintBeforeAndAfterSnapshots','KeyAclChanged','TrustChangedBySigner','CurrentSixStoreInventoryStillMatchesReviewedTrustReceipt')

Assert-FieldValue $postSignBase.Verdict 'V10_BUILDER_TRUST_INDEPENDENT_BASELINE_PASS' 'Post-sign record 0.Verdict'
Assert-FieldValue $postSignBase.ComputerName $expectedComputer 'Post-sign record 0.ComputerName'
Assert-FieldValue $postSignBase.UUID $expectedUuid 'Post-sign record 0.UUID'
Assert-FieldValue $postSignBase.SID $expectedSid 'Post-sign record 0.SID'
Assert-FieldValue $postSignBase.NewThumbprint $newThumb 'Post-sign record 0.NewThumbprint'
Assert-FieldValue $postSignBase.AllSixStoresMatchMintPlusExactMachineRootAndMergedUserRoot $true 'Post-sign record 0.AllSixStoresMatchMintPlusExactMachineRootAndMergedUserRoot'
Assert-FieldValue $postSignBase.TestSigning 'No' 'Post-sign record 0.TestSigning'
if (@($postSignBase.BuildProcesses).Count -ne 0) { throw 'Post-sign record 0.BuildProcesses is not empty.' }
Assert-FieldValue $postSignBase.StateMutated $false 'Post-sign record 0.StateMutated'
Assert-PostSignAclMatchesSnapshot $postSignBase $metadata.KeyAclSnapshotBefore 'Post-sign JSONL ACL vs mint-before snapshot'
Assert-PostSignAclMatchesSnapshot $postSignBase $metadata.KeyAclSnapshotAfter 'Post-sign JSONL ACL vs mint-after snapshot'
Assert-PostSignAclMatchesSnapshot $postSignBase $trust.KeyAclBeforeTrust 'Post-sign JSONL ACL vs trust-before snapshot'
Assert-PostSignAclMatchesSnapshot $postSignBase $trust.KeyAclAfterTrust 'Post-sign JSONL ACL vs trust-after snapshot'

Assert-FieldValue $postSignArtifact.Status 'INDEPENDENT_SIGNED_ARTIFACT_READ' 'Post-sign record 1.Status'
Assert-Sha256Field $postSignArtifact.SignedSHA256 $signedArtifactSha 'Post-sign record 1.SignedSHA256'
Assert-FieldValue $postSignArtifact.AuthenticodeStatus 'Valid' 'Post-sign record 1.AuthenticodeStatus'
Assert-FieldValue $postSignArtifact.SignerThumbprint $newThumb 'Post-sign record 1.SignerThumbprint'
Assert-Sha256Field $postSignArtifact.UnsignedSHA256 '8C19FE05135E10AABACABC433F0DC5CB68A53CCBD7A3CC82052D0D9804586FC9' 'Post-sign record 1.UnsignedSHA256'
Assert-FieldValue $postSignArtifact.UnsignedAuthenticodeStatus 'NotSigned' 'Post-sign record 1.UnsignedAuthenticodeStatus'
Assert-FieldValue $postSignArtifact.NoSigningAttempted $true 'Post-sign record 1.NoSigningAttempted'

Assert-FieldValue $postSignRoot.Verdict 'READY4_SIGNED_COPY_AND_INDEPENDENT_SIGNATURE_VERIFIED' 'Post-sign root readout.Verdict'
Assert-FieldValue $postSignRoot.ArtifactWorkflowExitCode 0 'Post-sign root readout.ArtifactWorkflowExitCode'
Assert-FieldValue $postSignRoot.IndependentRemoteExitCode 0 'Post-sign root readout.IndependentRemoteExitCode'
Assert-Sha256Field $postSignRoot.SignedArtifactSHA256 $signedArtifactSha 'Post-sign root readout.SignedArtifactSHA256'
Assert-Sha256Field $postSignRoot.UnsignedSHA256 '8C19FE05135E10AABACABC433F0DC5CB68A53CCBD7A3CC82052D0D9804586FC9' 'Post-sign root readout.UnsignedSHA256'
Assert-FieldValue $postSignRoot.AuthenticodeStatus 'Valid' 'Post-sign root readout.AuthenticodeStatus'
Assert-FieldValue $postSignRoot.SignerThumbprint $newThumb 'Post-sign root readout.SignerThumbprint'
Assert-FieldValue $postSignRoot.UnsignedUnchanged $true 'Post-sign root readout.UnsignedUnchanged'
Assert-FieldValue $postSignRoot.StoresMatchReviewedTrustBaseline $true 'Post-sign root readout.StoresMatchReviewedTrustBaseline'
Assert-FieldValue $postSignRoot.KeyAclMatchesMint $true 'Post-sign root readout.KeyAclMatchesMint'
Assert-FieldValue $postSignRoot.TestSigningNo $true 'Post-sign root readout.TestSigningNo'
Assert-FieldValue $postSignRoot.PrivateKeyExported $false 'Post-sign root readout.PrivateKeyExported'
Assert-FieldValue $postSignRoot.DriverInstalledOrLoaded $false 'Post-sign root readout.DriverInstalledOrLoaded'
$postSignExpectedPins = @{
    'driver/evidence/2026-10-06/signing-artifact-proof-v10-post-sign-independent.stdout.json' = $postSignIndependentReadoutSha
    'driver/evidence/2026-10-06/signing-artifact-proof-v10-post-sign-independent.stderr.txt' = $postSignStderrSha
    'output/signing-artifact-proof-v10-20261006a/root-run.json' = $proofRootRunSha
}
foreach ($pinPath in $postSignExpectedPins.Keys) {
    $pin = $postSignRoot.EvidencePins.PSObject.Properties[$pinPath]
    if ($null -eq $pin) { throw ("Post-sign root readout.EvidencePins is missing {0}." -f $pinPath) }
    Assert-Sha256Field $pin.Value $postSignExpectedPins[$pinPath] ("Post-sign root readout.EvidencePins[{0}]" -f $pinPath)
}
Assert-ExactProofManifest $proofManifestPath
$expectedPackageNames = @('artifact-signature-proof.json','artifact-signature-proof.sha256','builder-trust-receipt.json',
    'cold-challenge-receipt.json','owned-feature.signed.sys') | Sort-Object
$actualPackageNames = @(Get-ChildItem -LiteralPath $PublicProofDirectory -Force -ErrorAction Stop |
    ForEach-Object { $_.Name } | Sort-Object)
if (($actualPackageNames -join ',') -cne ($expectedPackageNames -join ',')) {
    throw 'Public artifact proof directory contains unexpected files.'
}

Assert-FieldValue $trust.Status 'ExactBuilderLocalMachineRootAddedV10Candidate' 'V10 trust receipt.Status'
Assert-FieldValue $trust.ComputerName $expectedComputer 'V10 trust receipt.ComputerName'
Assert-FieldValue $trust.UUID $expectedUuid 'V10 trust receipt.UUID'
Assert-FieldValue $trust.User $identity.Name 'V10 trust receipt.User'
Assert-FieldValue $trust.Thumbprint $newThumb 'V10 trust receipt.Thumbprint'
Assert-FieldValue $trust.Subject $newSubject 'V10 trust receipt.Subject'
Assert-FieldValue $trust.Store 'LocalMachine\Root' 'V10 trust receipt.Store'
Assert-FieldValue $trust.AddStoreMethod 'certutil -addstore Root (no -user; LocalMachine target)' 'V10 trust receipt.AddStoreMethod'
Assert-FieldValue $trust.CertutilExitCode 0 'V10 trust receipt.CertutilExitCode'
Assert-FieldValue $trust.TestSigningBefore 'No' 'V10 trust receipt.TestSigningBefore'
Assert-FieldValue $trust.TestSigningAfter 'No' 'V10 trust receipt.TestSigningAfter'
Assert-FieldValue $trust.OnlyApprovedLocalMachineRootDelta $true 'V10 trust receipt.OnlyApprovedLocalMachineRootDelta'
Assert-FieldValue $trust.CurrentUserRootIsExpectedMergedView $true 'V10 trust receipt.CurrentUserRootIsExpectedMergedView'
Assert-FieldValue $trust.TrustedPublisherChanged $false 'V10 trust receipt.TrustedPublisherChanged'
Assert-FieldValue $trust.LocalMachineMyUnchanged $true 'V10 trust receipt.LocalMachineMyUnchanged'
Assert-FieldValue $trust.KeyAclCheckedUnchanged $true 'V10 trust receipt.KeyAclCheckedUnchanged'
Assert-FieldValue $trust.NoAclWrite $true 'V10 trust receipt.NoAclWrite'
Assert-Sha256Field $trust.CreationMetadataSha256 $metadataSha 'V10 trust receipt.CreationMetadataSha256'
Assert-Sha256Field $trust.CerSha256 $cerSha 'V10 trust receipt.CerSha256'

Assert-FieldValue $trustReadout.Verdict 'V10_BUILDER_MACHINE_ROOT_ONLY_TRUST_INDEPENDENTLY_VERIFIED' 'V10 independent trust readout.Verdict'
Assert-FieldValue $trustReadout.TrustRemoteExitCode 0 'V10 independent trust readout.TrustRemoteExitCode'
Assert-FieldValue $trustReadout.IndependentRemoteExitCode 0 'V10 independent trust readout.IndependentRemoteExitCode'
Assert-FieldValue $trustReadout.Thumbprint $newThumb 'V10 independent trust readout.Thumbprint'
Assert-FieldValue $trustReadout.OnlyMachineRootAndMergedCurrentUserRootChanged $true 'V10 independent trust readout.OnlyMachineRootAndMergedCurrentUserRootChanged'
Assert-FieldValue $trustReadout.AllOtherStoresExactlyMint $true 'V10 independent trust readout.AllOtherStoresExactlyMint'
Assert-FieldValue $trustReadout.KeyAclOrderedAndSddlExactlyMint $true 'V10 independent trust readout.KeyAclOrderedAndSddlExactlyMint'
Assert-FieldValue $trustReadout.OriginalFilesAndCertificateRetained $true 'V10 independent trust readout.OriginalFilesAndCertificateRetained'
Assert-FieldValue $trustReadout.TestSigningNo $true 'V10 independent trust readout.TestSigningNo'
Assert-FieldValue $trustReadout.ArtifactSigningAttempted $false 'V10 independent trust readout.ArtifactSigningAttempted'
Assert-FieldValue $trustReadout.PrivateKeyExported $false 'V10 independent trust readout.PrivateKeyExported'
$trustPinProperty = $trustReadout.EvidencePins.PSObject.Properties['driver/evidence/2026-10-06/signing-builder-trust-v10-public-receipt.json']
if ($null -eq $trustPinProperty) { throw 'V10 independent trust readout.EvidencePins is missing the public receipt pin.' }
Assert-Sha256Field $trustPinProperty.Value $trustReceiptSha 'V10 independent trust readout public receipt pin'

Assert-FieldValue $cold.Status 'V8_COLD_KEY_CHALLENGE_PASS' 'V8 cold receipt C.Status'
Assert-FieldValue $cold.Thumbprint $newThumb 'V8 cold receipt C.Thumbprint'
Assert-FieldValue $cold.Subject $newSubject 'V8 cold receipt C.Subject'
Assert-FieldValue $cold.Provider 'Microsoft Software Key Storage Provider' 'V8 cold receipt C.Provider'
Assert-FieldValue $cold.KeySize 3072 'V8 cold receipt C.KeySize'
Assert-FieldValue $cold.ExportPolicy 'None' 'V8 cold receipt C.ExportPolicy'
Assert-FieldValue $cold.IsMachineKey $true 'V8 cold receipt C.IsMachineKey'
Assert-FieldValue $cold.IsEphemeral $false 'V8 cold receipt C.IsEphemeral'
Assert-FieldValue $cold.EffectiveAdministratorsMembership $true 'V8 cold receipt C.EffectiveAdministratorsMembership'
Assert-Sha256Field $cold.CreationMetadataSha256 $metadataSha 'V8 cold receipt C.CreationMetadataSha256'
Assert-Sha256Field $cold.PublicCerSha256 $cerSha 'V8 cold receipt C.PublicCerSha256'
Assert-FieldValue $cold.TrustChanged $false 'V8 cold receipt C.TrustChanged'
Assert-FieldValue $cold.PrivateKeyMaterialExported $false 'V8 cold receipt C.PrivateKeyMaterialExported'
Assert-FieldValue $cold.BuildOrArtifactSignAttempted $false 'V8 cold receipt C.BuildOrArtifactSignAttempted'
Assert-FieldValue $cold.ChallengeSignaturePersistedOrExported $false 'V8 cold receipt C.ChallengeSignaturePersistedOrExported'
Assert-FieldValue $cold.TestSigningBefore 'No' 'V8 cold receipt C.TestSigningBefore'
Assert-FieldValue $cold.TestSigningAfter 'No' 'V8 cold receipt C.TestSigningAfter'
if (@($cold.EnhancedKeyUsageOids).Count -ne 1 -or @($cold.EnhancedKeyUsageOids)[0] -cne '1.3.6.1.5.5.7.3.3') { throw 'V8 cold receipt C.EnhancedKeyUsageOids must contain only the code-signing OID.' }

Assert-FieldValue $coldReadout.Verdict 'V8_RETRY2_COLD_KEY_CHALLENGE_VERIFIED' 'V8 cold independent readout C.Verdict'
Assert-FieldValue $coldReadout.RemoteExitCode 0 'V8 cold independent readout C.RemoteExitCode'
Assert-Sha256Field $coldReadout.ReceiptSHA256 $coldReceiptSha 'V8 cold independent readout C.ReceiptSHA256'
Assert-FieldValue $coldReadout.StoresUnchanged $true 'V8 cold independent readout C.StoresUnchanged'
Assert-FieldValue $coldReadout.KeyAclUnchanged $true 'V8 cold independent readout C.KeyAclUnchanged'
Assert-FieldValue $coldReadout.NoPrivateExport $true 'V8 cold independent readout C.NoPrivateExport'
Assert-FieldValue $coldReadout.NoTrust $true 'V8 cold independent readout C.NoTrust'
Assert-FieldValue $coldReadout.NoArtifactSign $true 'V8 cold independent readout C.NoArtifactSign'

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

Assert-FieldValue $proof.Status 'READY4_ARTIFACT_SIGNED_COPY_VALID' 'V10 artifact proof.Status'
Assert-FieldValue $proof.BuilderComputerName $expectedComputer 'V10 artifact proof.BuilderComputerName'
Assert-FieldValue $proof.BuilderUUID $expectedUuid 'V10 artifact proof.BuilderUUID'
Assert-FieldValue $proof.SigningUser $identity.Name 'V10 artifact proof.SigningUser'
Assert-FieldValue $proof.SigningUserSid $expectedSid 'V10 artifact proof.SigningUserSid'
Assert-FieldValue $proof.EnabledAdministratorsInSigningPowerShell $true 'V10 artifact proof.EnabledAdministratorsInSigningPowerShell'
Assert-FieldValue $proof.SignToolExitCode 0 'V10 artifact proof.SignToolExitCode'
Assert-FieldValue $proof.AuthenticodeStatus 'Valid' 'V10 artifact proof.AuthenticodeStatus'
Assert-FieldValue $proof.AuthenticodeSignerThumbprint $newThumb 'V10 artifact proof.AuthenticodeSignerThumbprint'
Assert-Sha256Field $proof.SignedArtifactSHA256 $signedArtifactSha 'V10 artifact proof.SignedArtifactSHA256'
Assert-Sha256Field $proof.UnsignedArtifactSHA256 '8C19FE05135E10AABACABC433F0DC5CB68A53CCBD7A3CC82052D0D9804586FC9' 'V10 artifact proof.UnsignedArtifactSHA256'
Assert-FieldValue $proof.UnsignedArtifactUnchangedAfterSign $true 'V10 artifact proof.UnsignedArtifactUnchangedAfterSign'
Assert-Sha256Field $proof.BuilderTrustReceiptSHA256 $trustReceiptSha 'V10 artifact proof.BuilderTrustReceiptSHA256'
Assert-FieldValue $proof.BuilderTrustReceiptStatus $trust.Status 'V10 artifact proof.BuilderTrustReceiptStatus'
Assert-FieldValue $proof.BuilderTrustMethod $trust.AddStoreMethod 'V10 artifact proof.BuilderTrustMethod'
Assert-FieldValue $proof.BuilderTrustNativeExitCode 0 'V10 artifact proof.BuilderTrustNativeExitCode'
Assert-Sha256Field $proof.V10BuilderTrustScriptSHA256 $trustScriptSha 'V10 artifact proof.V10BuilderTrustScriptSHA256'
Assert-Sha256Field $proof.SignerScriptSHA256 $signerProofScriptSha 'V10 artifact proof.SignerScriptSHA256'
Assert-FieldValue $proof.KeyAclMatchesMintBeforeAndAfterSnapshots $true 'V10 artifact proof.KeyAclMatchesMintBeforeAndAfterSnapshots'
Assert-FieldValue $proof.KeyAclChanged $false 'V10 artifact proof.KeyAclChanged'
Assert-FieldValue $proof.TrustChangedBySigner $false 'V10 artifact proof.TrustChangedBySigner'
Assert-FieldValue $proof.CurrentSixStoreInventoryStillMatchesReviewedTrustReceipt $true 'V10 artifact proof.CurrentSixStoreInventoryStillMatchesReviewedTrustReceipt'
if (-not (Test-Sha256Equal (Get-FileSha256 $signedArtifactPath) $signedArtifactSha)) { throw 'Signed artifact SHA-256 mismatch.' }
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
if (-not (Test-Sha256Equal $files[0].SHA256 'DE1CD348314292C3F391015C9B2790FBE8956D886994BF5C4AE7C67AC51B2F03') -or
    -not (Test-Sha256Equal $files[1].SHA256 '46E4E8082155E2EE9E3602C613224322F863ADB85EC02C542FF2F4C8700BA0A1')) {
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
