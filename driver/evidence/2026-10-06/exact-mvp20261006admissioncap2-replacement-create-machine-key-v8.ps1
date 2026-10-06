# REVIEW ONLY: V8 creates one isolated, nonexportable test key using the
# provider's untouched default SYSTEM/Administrators DACL. Not executed.
# This lifecycle has no Set-Acl call and never exports private-key material.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch] $RootApprovedForKeyCreation,
    [Parameter(Mandatory)][switch] $PreFallbackCheckpointVerified
)
$ErrorActionPreference = 'Stop'
$guardHelpersPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v8.ps1'
$guardHelpersExpectedSha256 = '9585e1acd512f9532de032c6ce2df251fa774acc83d27cfc6afceb437ce64c42'
if (-not (Test-Path -LiteralPath $guardHelpersPath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $guardHelpersPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $guardHelpersExpectedSha256) {
    throw 'Pinned V8 signing guard helper is missing or changed.'
}
. $guardHelpersPath
$expectedComputer = 'DESKTOP-O1LP5DG'
$expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$oldThumb = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$oldPfxHash = 'DE1CD348314292C3F391015C9B2790FBE8956D886994BF5C4AE7C67AC51B2F03'
$oldCerHash = '46E4E8082155E2EE9E3602C613224322F863ADB85EC02C542FF2F4C8700BA0A1'
$subject = 'CN=SafeUpload Test Signing Recovery 20261006 V8'
$provider = 'Microsoft Software Key Storage Provider'
$publicCerPath = 'C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v8.cer'
$evidenceDirectory = 'C:\Users\vika\Documents\exact-mvp20261006admissioncap2'
$evidencePath = Join-Path $evidenceDirectory 'replacement-machine-key-v8-metadata.json'
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

if (-not $RootApprovedForKeyCreation -or -not $PreFallbackCheckpointVerified) { throw 'Root approval and verified pre-fallback checkpoint switches are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
$product = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$effectiveAdministratorMembership = [bool]$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid -or $sid -cne $expectedSid) { throw 'Exact builder identity guard failed.' }
if (-not $effectiveAdministratorMembership) { throw 'Elevated vika token with enabled Administrators membership is required for the default machine-key ACL.' }
$testSigningBefore = Get-TestSigningState
if ($testSigningBefore -cne 'No') { throw 'Builder testsigning baseline must remain No for V8 signer recovery.' }
if (-not (Test-Path -LiteralPath $evidenceDirectory -PathType Container)) { throw 'Expected evidence directory is missing.' }
if ((Test-Path -LiteralPath $publicCerPath -PathType Leaf) -or (Test-Path -LiteralPath $evidencePath -PathType Leaf)) { throw 'V8 replacement output already exists; refusing to overwrite.' }

$old = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $oldThumb) -ErrorAction Stop
if ($old.Subject -cne 'CN=SafeUpload Test Signing' -or -not $old.HasPrivateKey) { throw 'Original CurrentUser certificate guard failed.' }
if ((Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.pfx' -Algorithm SHA256).Hash -cne $oldPfxHash -or
    (Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.cer' -Algorithm SHA256).Hash -cne $oldCerHash) { throw 'Original PFX/CER hash guard failed.' }
foreach ($store in $storePaths) {
    if (@(Get-ChildItem -LiteralPath $store -ErrorAction Stop | Where-Object { $_.Subject -ceq $subject }).Count -ne 0) { throw "V8 replacement subject already exists in $store." }
}
if (-not (Test-Path -LiteralPath 'C:\safeupload-pkg' -PathType Container)) { throw 'Existing package directory is missing.' }
$preMintStoreThumbprints = Get-StoreThumbInventory

$created = $null
$rsa = $null
$publicRsa = $null
$challenge = $null
$signature = $null
$rng = $null
$keyPath = $null
$aclBeforeSnapshot = $null
$aclAfterSnapshot = $null
try {
    $created = New-SelfSignedCertificate -Type Custom -Subject $subject `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3','2.5.29.19={text}') `
        -KeyUsage DigitalSignature -KeyUsageProperty Sign `
        -Provider $provider -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable -CertStoreLocation 'Cert:\LocalMachine\My' `
        -NotBefore (Get-Date).AddMinutes(-5) -NotAfter (Get-Date).AddDays(90)
    if ($created.Subject -cne $subject -or -not $created.HasPrivateKey -or $created.Thumbprint -ceq $oldThumb) { throw 'Created certificate identity guard failed.' }
    if ($created.Issuer -cne $created.Subject) { throw 'Certificate is not self-issued with the exact expected subject.' }
    if ($created.PublicKey.Oid.Value -cne '1.2.840.113549.1.1.1') { throw 'Certificate public-key OID is not RSA.' }
    if ($created.SignatureAlgorithm.Value -cne '1.2.840.113549.1.1.11') { throw 'Certificate signature-algorithm OID is not SHA-256 with RSA.' }
    $basicExtensions = @($created.Extensions | Where-Object { $_.Oid.Value -ceq '2.5.29.19' })
    if ($basicExtensions.Count -ne 1) { throw 'Certificate must have exactly one Basic Constraints extension.' }
    $basicConstraints = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$basicExtensions[0]
    if ($basicConstraints.CertificateAuthority) { throw 'Basic Constraints must assert CA=false.' }
    $eku = @(Get-SafeUploadCodeSigningEkuOids -Extensions @($created.Extensions) -Context 'Created certificate')
    $kuExtensions = @($created.Extensions | Where-Object { $_.Oid.Value -ceq '2.5.29.15' })
    if ($kuExtensions.Count -ne 1) { throw 'Certificate must have exactly one Key Usage extension.' }
    try { $ku = [Security.Cryptography.X509Certificates.X509KeyUsageExtension]$kuExtensions[0] }
    catch { throw 'Key Usage extension has an unexpected or malformed representation.' }
    if ($ku.KeyUsages -ne [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) { throw 'Key Usage must permit only DigitalSignature.' }
    if ($created.NotAfter -gt (Get-Date).AddDays(91) -or $created.NotAfter -lt (Get-Date).AddDays(89)) { throw '90-day validity guard failed.' }

    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($created)
    if ($rsa -isnot [Security.Cryptography.RSACng] -or $rsa.KeySize -ne 3072 -or
        $rsa.Key.Provider.Provider -cne $provider -or
        $rsa.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None -or
        -not $rsa.Key.IsMachineKey -or $rsa.Key.IsEphemeral) {
        throw 'RSA-3072 nonexportable machine Microsoft Software KSP guard failed.'
    }
    $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $rsa.Key.UniqueName
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) { throw 'Expected machine KSP key file is missing.' }

    # Preserve the provider's untouched captured default ACL: explicit
    # CREATOR OWNER, SYSTEM, then BUILTIN\Administrators full-control ACEs.
    $aclBeforeSnapshot = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $keyPath -ErrorAction Stop)
    Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $aclBeforeSnapshot
    $aclAfterSnapshot = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $keyPath -ErrorAction Stop)
    Assert-SafeUploadKeyAclUnchanged -Before $aclBeforeSnapshot -After $aclAfterSnapshot
    Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $aclAfterSnapshot

    $postMintStoreThumbprints = Get-StoreThumbInventory
    foreach ($store in $storePaths) {
        $expectedThumbprints = @($preMintStoreThumbprints[$store])
        if ($store -ceq 'Cert:\LocalMachine\My') { $expectedThumbprints = @($expectedThumbprints + $created.Thumbprint | Sort-Object) }
        if (($postMintStoreThumbprints[$store] -join ',') -cne ($expectedThumbprints -join ',')) { throw "Certificate-store inventory changed unexpectedly after mint in $store." }
    }
    $testSigningAfterMint = Get-TestSigningState
    if ($testSigningAfterMint -cne $testSigningBefore) { throw 'Builder testsigning state changed during mint.' }

    # Prove private-key access in the elevated pinned vika context before any
    # public CER export or trust action. Keep only generated bytes in memory.
    $challenge = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($challenge)
    $signature = $rsa.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $publicRsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($created)
    if (-not $publicRsa.VerifyData($challenge,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) { throw 'In-memory private/public challenge verification failed.' }
    $aclAfterSnapshot = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $keyPath -ErrorAction Stop)
    Assert-SafeUploadKeyAclUnchanged -Before $aclBeforeSnapshot -After $aclAfterSnapshot
    Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $aclAfterSnapshot

    $oldAfter = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $oldThumb) -ErrorAction Stop
    if ($oldAfter.Subject -cne 'CN=SafeUpload Test Signing' -or -not $oldAfter.HasPrivateKey -or
        (Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.pfx' -Algorithm SHA256).Hash -cne $oldPfxHash -or
        (Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.cer' -Algorithm SHA256).Hash -cne $oldCerHash) {
        throw 'Original CurrentUser certificate or PFX/CER hash changed during mint/challenge.'
    }

    Export-Certificate -Cert $created -FilePath $publicCerPath -Type CERT -NoClobber | Out-Null
    $publicCert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($publicCerPath)
    if ($publicCert.Thumbprint -cne $created.Thumbprint -or $publicCert.Subject -cne $subject) { throw 'Public CER identity mismatch.' }
    $aclAfterSnapshot = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $keyPath -ErrorAction Stop)
    Assert-SafeUploadKeyAclUnchanged -Before $aclBeforeSnapshot -After $aclAfterSnapshot

    $metadata = [ordered]@{
        Status='CreatedAndProbed'; UTC=[DateTime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME; UUID=$product.UUID; User=$identity.Name; SID=$sid
        Thumbprint=$created.Thumbprint; Subject=$created.Subject; Issuer=$created.Issuer; NotBeforeUtc=$created.NotBefore.ToUniversalTime().ToString('o'); NotAfterUtc=$created.NotAfter.ToUniversalTime().ToString('o')
        Store='LocalMachine\My'; Provider=$rsa.Key.Provider.Provider; Algorithm='RSA'; KeySize=$rsa.KeySize; PublicKeyOid=$created.PublicKey.Oid.Value; SignatureAlgorithmOid=$created.SignatureAlgorithm.Value; IssuerEqualsSubject=($created.Issuer -ceq $created.Subject); BasicConstraintsCount=$basicExtensions.Count; BasicConstraintsCA=$basicConstraints.CertificateAuthority; IsMachineKey=$rsa.Key.IsMachineKey; IsEphemeral=$rsa.Key.IsEphemeral; ExportPolicy=$rsa.Key.ExportPolicy.ToString(); PrivateKeyMaterialExported=$false
        KeyContainerUniqueName=$rsa.Key.UniqueName; KeyFilePath=$keyPath; KeyAclSnapshotBefore=$aclBeforeSnapshot; KeyAclSnapshotAfter=$aclAfterSnapshot; KeyAclUnchanged=$true; DefaultAclPrincipals=@('S-1-3-0','S-1-5-18','S-1-5-32-544'); CreatorOwnerKeptAsLiteralProviderAce=$true; EffectiveAdministratorsMembership=$effectiveAdministratorMembership; NoAclWrite=$true
        EnhancedKeyUsageOids=$eku; KeyUsage=$ku.KeyUsages.ToString(); PublicCerPath=$publicCerPath; PublicCerSHA256=(Get-FileHash -LiteralPath $publicCerPath -Algorithm SHA256).Hash
        PreMintAllStoreThumbprints=$preMintStoreThumbprints; PostMintAllStoreThumbprints=$postMintStoreThumbprints; TestSigningBefore=$testSigningBefore; TestSigningAfter=$testSigningAfterMint; ChallengeSignatureVerified=$true; ChallengeSignaturePersistedOrExported=$false; PersistentTrustChanged=$false
    }
    $metadata | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
    $metadata | ConvertTo-Json -Depth 8 -Compress
} catch {
    $caughtError = $_
    $originalErrorMessage = [string]$caughtError.Exception.Message
    if ($originalErrorMessage.Length -gt 2048) { $originalErrorMessage = $originalErrorMessage.Substring(0,2048) }
    $originalErrorType = [string]$caughtError.Exception.GetType().FullName
    $originalErrorHResult = '0x{0:X8}' -f $caughtError.Exception.HResult
    $originalErrorFullyQualifiedId = [string]$caughtError.FullyQualifiedErrorId
    $failureStores = $null
    $failureInventoryError = $null
    try { $failureStores = Get-StoreThumbInventory }
    catch { $failureInventoryError = [string]$_.Exception.Message }
    $partialCertificates = @()
    $partialCertificateInventoryError = $null
    try {
        foreach ($store in $storePaths) {
            $partialCertificates += @(Get-ChildItem -LiteralPath $store -ErrorAction Stop | Where-Object { $_.Subject -ceq $subject } | ForEach-Object { [ordered]@{Store=$store;Thumbprint=$_.Thumbprint;Subject=$_.Subject;HasPrivateKey=[bool]$_.HasPrivateKey} })
        }
    } catch { $partialCertificateInventoryError = [string]$_.Exception.Message }
    $failureAclSnapshot = $null
    $failureAclSnapshotError = $null
    if ($keyPath -and (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
        try { $failureAclSnapshot = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $keyPath -ErrorAction Stop) }
        catch { $failureAclSnapshotError = [string]$_.Exception.Message }
    }
    $testSigningAtFailure = 'ReadError'
    try { $testSigningAtFailure = Get-TestSigningState } catch { }
    $createdThumbprint = if ($created) { $created.Thumbprint } else { $null }
    $failure = [ordered]@{
        Status='PostMintGuardFailed'; UTC=[DateTime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME; UUID=$product.UUID; User=$identity.Name; SID=$sid
        ExpectedSubject=$subject; CreatedThumbprint=$createdThumbprint; OriginalThumbprint=$oldThumb
        OriginalErrorMessage=$originalErrorMessage; OriginalErrorType=$originalErrorType; OriginalErrorHResult=$originalErrorHResult; OriginalErrorFullyQualifiedId=$originalErrorFullyQualifiedId
        PreMintAllStoreThumbprints=$preMintStoreThumbprints; FailureAllStoreThumbprints=$failureStores; MatchingSubjectCertificates=$partialCertificates
        FailureInventoryError=$failureInventoryError; PartialCertificateInventoryError=$partialCertificateInventoryError
        KeyFilePath=$keyPath; KeyAclSnapshotBefore=$aclBeforeSnapshot; KeyAclSnapshotAtFailure=$failureAclSnapshot; KeyAclSnapshotError=$failureAclSnapshotError
        EffectiveAdministratorsMembership=$effectiveAdministratorMembership; TestSigningBefore=$testSigningBefore; TestSigningAtFailure=$testSigningAtFailure; NoAclWrite=$true; PrivateKeyMaterialExported=$false; PersistentTrustChanged=$false; SourcePinsChanged=$false; BuildOrSigningAttempted=$false
        PublicCerExists=[bool](Test-Path -LiteralPath $publicCerPath -PathType Leaf)
        RequiredNextStep='Preserve this failure and failed branch evidence; do not use the key or CER. Restore the independently verified pre-fallback builder checkpoint, then verify complete store inventories, original certificate thumbprint, and pinned PFX/CER hashes before another attempt.'
    }
    try { if (-not (Test-Path -LiteralPath $evidencePath -PathType Leaf)) { $failure | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $evidencePath -Encoding UTF8 } } catch { }
    $failure | ConvertTo-Json -Depth 10 -Compress
    throw ("Post-mint guard failed; preserve failed branch/evidence, perform no trust/source/build/sign action, and restore the verified pre-fallback checkpoint. Original guard error: {0}" -f $originalErrorMessage)
} finally {
    if ($challenge) { [Array]::Clear($challenge,0,$challenge.Length) }
    if ($signature) { [Array]::Clear($signature,0,$signature.Length) }
    if ($rng) { $rng.Dispose() }
    if ($publicRsa) { $publicRsa.Dispose() }
    if ($rsa) { $rsa.Dispose() }
}
