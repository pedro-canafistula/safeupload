# REVIEW ONLY: creates one isolated, nonexportable test key. Not executed.
# Run only after the exact pre-fallback builder checkpoint is verified and
# root has separately approved this fallback.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch] $RootApprovedForKeyCreation,
    [Parameter(Mandatory)][switch] $PreFallbackCheckpointVerified
)
$ErrorActionPreference = 'Stop'
$expectedComputer = 'DESKTOP-O1LP5DG'
$expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$oldThumb = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$oldPfxHash = 'DE1CD348314292C3F391015C9B2790FBE8956D886994BF5C4AE7C67AC51B2F03'
$oldCerHash = '46E4E8082155E2EE9E3602C613224322F863ADB85EC02C542FF2F4C8700BA0A1'
$subject = 'CN=SafeUpload Test Signing Recovery 20261006'
$provider = 'Microsoft Software Key Storage Provider'
$publicCerPath = 'C:\safeupload-pkg\SafeUploadTest-Recovery-20261006.cer'
$evidenceDirectory = 'C:\Users\vika\Documents\exact-mvp20261006admissioncap2'
$evidencePath = Join-Path $evidenceDirectory 'replacement-machine-key-metadata.json'
$storePaths = @('Cert:\CurrentUser\My','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher','Cert:\LocalMachine\My','Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')

function Get-StoreThumbInventory {
    $snapshot = [ordered]@{}
    foreach ($store in $storePaths) { $snapshot[$store] = @((Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | ForEach-Object { $_.Thumbprint.ToUpperInvariant() } | Sort-Object)) }
    return $snapshot
}

if (-not $RootApprovedForKeyCreation -or -not $PreFallbackCheckpointVerified) { throw 'Root approval and verified pre-fallback checkpoint switches are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
$product = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid -or $sid -cne $expectedSid) { throw 'Exact builder identity guard failed.' }
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated vika token required to create a LocalMachine key.' }
if (-not (Test-Path -LiteralPath $evidenceDirectory -PathType Container)) { throw 'Expected evidence directory is missing.' }
if ((Test-Path -LiteralPath $publicCerPath -PathType Leaf) -or (Test-Path -LiteralPath $evidencePath -PathType Leaf)) { throw 'Replacement output already exists; refusing to overwrite.' }

$old = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $oldThumb) -ErrorAction Stop
if ($old.Subject -cne 'CN=SafeUpload Test Signing' -or -not $old.HasPrivateKey) { throw 'Original CurrentUser certificate guard failed.' }
if ((Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.pfx' -Algorithm SHA256).Hash -cne $oldPfxHash -or
    (Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.cer' -Algorithm SHA256).Hash -cne $oldCerHash) { throw 'Original PFX/CER hash guard failed.' }
foreach ($store in $storePaths) {
    if (Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Subject -ceq $subject }) { throw "Replacement subject already exists in $store." }
}
if (-not (Test-Path -LiteralPath 'C:\safeupload-pkg' -PathType Container)) { throw 'Existing package directory is missing.' }
$preMintStoreThumbprints = Get-StoreThumbInventory

$created = $null
$rsa = $null
$publicRsa = $null
$challenge = $null
$signature = $null
$rng = $null
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
    $basicExtensions = @($created.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
    if ($basicExtensions.Count -ne 1) { throw 'Certificate must have exactly one Basic Constraints extension.' }
    $basicConstraints = [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$basicExtensions[0]
    if ($basicConstraints.CertificateAuthority) { throw 'Basic Constraints must assert CA=false.' }

    $eku = @($created.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value })
    $kuExtension = $created.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' } | Select-Object -First 1
    $ku = if ($kuExtension) { [Security.Cryptography.X509Certificates.X509KeyUsageExtension]$kuExtension } else { $null }
    if ($eku.Count -ne 1 -or $eku[0] -cne '1.3.6.1.5.5.7.3.3' -or -not $ku -or $ku.KeyUsages -ne [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature) { throw 'Code-sign-only EKU/key-usage guard failed.' }
    if ($created.NotAfter -gt (Get-Date).AddDays(91) -or $created.NotAfter -lt (Get-Date).AddDays(89)) { throw '90-day validity guard failed.' }

    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($created)
    if ($rsa -isnot [Security.Cryptography.RSACng] -or $rsa.KeySize -ne 3072 -or $rsa.Key.Provider.Provider -cne $provider -or $rsa.Key.ExportPolicy -ne [Security.Cryptography.CngExportPolicies]::None -or -not $rsa.Key.IsMachineKey -or $rsa.Key.IsEphemeral) { throw 'RSA-3072 nonexportable machine Microsoft Software KSP guard failed.' }
    $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $rsa.Key.UniqueName
    if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) { throw 'Expected machine KSP key file is missing.' }

    $aclBefore = Get-Acl -LiteralPath $keyPath
    $aclBeforeSddl = $aclBefore.Sddl
    $aclBeforeOwner = $aclBefore.Owner
    $aclBeforeGroup = $aclBefore.Group
    $aclBeforeProtected = $aclBefore.AreAccessRulesProtected
    $vikaSid = [Security.Principal.SecurityIdentifier]::new($expectedSid)
    function Get-SidValue($IdentityReference) {
        try { return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { return $IdentityReference.Value }
    }
    function Get-AceRows($AclObject) {
        @($AclObject.Access | ForEach-Object {
            $aceSid = Get-SidValue $_.IdentityReference
            '{0}|{1}|{2}|{3}|{4}|{5}' -f $aceSid,$_.AccessControlType.ToString(),[int]$_.FileSystemRights,$_.InheritanceFlags.ToString(),$_.PropagationFlags.ToString(),$_.IsInherited
        } | Sort-Object)
    }
    $beforeAceRows = @(Get-AceRows $aclBefore)
    $vikaRulesBefore = @($aclBefore.Access | Where-Object { (Get-SidValue $_.IdentityReference) -ceq $expectedSid })
    if ($vikaRulesBefore.Count -gt 1) { throw 'More than one vika ACE exists; manual ACL review required.' }
    if ($vikaRulesBefore.Count -eq 1) {
        $rule = $vikaRulesBefore[0]
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or [int]$rule.FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::Read -or $rule.IsInherited) { throw 'Existing vika ACE is not exactly one explicit Read rule; manual ACL review required.' }
    } else {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($vikaSid,[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow)
        [void]$aclBefore.AddAccessRule($rule)
        Set-Acl -LiteralPath $keyPath -AclObject $aclBefore
    }
    $aclAfter = Get-Acl -LiteralPath $keyPath
    $afterAceRows = @(Get-AceRows $aclAfter)
    $vikaRulesAfter = @($aclAfter.Access | Where-Object { (Get-SidValue $_.IdentityReference) -ceq $expectedSid })
    if ($vikaRulesAfter.Count -ne 1 -or $vikaRulesAfter[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or [int]$vikaRulesAfter[0].FileSystemRights -ne [int][Security.AccessControl.FileSystemRights]::Read -or $vikaRulesAfter[0].IsInherited) { throw 'Final ACL lacks exactly one explicit vika Read ACE.' }
    if ($aclAfter.Owner -cne $aclBeforeOwner -or $aclAfter.Group -cne $aclBeforeGroup -or $aclAfter.AreAccessRulesProtected -ne $aclBeforeProtected) { throw 'Key ACL owner, group, or protection state changed.' }
    $expectedVikaAce = '{0}|Allow|{1}|None|None|False' -f $expectedSid,[int][Security.AccessControl.FileSystemRights]::Read
    $beforeCounts = @{}; foreach ($row in $beforeAceRows) { if (-not $beforeCounts.ContainsKey($row)) { $beforeCounts[$row]=0 }; $beforeCounts[$row]++ }
    $afterCounts = @{}; foreach ($row in $afterAceRows) { if (-not $afterCounts.ContainsKey($row)) { $afterCounts[$row]=0 }; $afterCounts[$row]++ }
    $removedAceRows = @(); $addedAceRows = @()
    foreach ($row in @($beforeCounts.Keys + $afterCounts.Keys | Sort-Object -Unique)) {
        $beforeCount = if ($beforeCounts.ContainsKey($row)) { $beforeCounts[$row] } else { 0 }
        $afterCount = if ($afterCounts.ContainsKey($row)) { $afterCounts[$row] } else { 0 }
        for ($n=0; $n -lt ($beforeCount - $afterCount); $n++) { $removedAceRows += $row }
        for ($n=0; $n -lt ($afterCount - $beforeCount); $n++) { $addedAceRows += $row }
    }
    if ($removedAceRows.Count -ne 0 -or ($beforeAceRows -notcontains $expectedVikaAce -and ($addedAceRows.Count -ne 1 -or $addedAceRows[0] -cne $expectedVikaAce)) -or ($beforeAceRows -contains $expectedVikaAce -and $addedAceRows.Count -ne 0)) { throw 'Final key ACL is not exactly the original ACE set plus the one exact vika Read ACE.' }
    $broadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545')
    foreach ($ace in $aclAfter.Access) {
        $aceSid = Get-SidValue $ace.IdentityReference
        if ($broadSids -contains $aceSid -and $ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) { throw 'Broad Everyone/Authenticated Users/Users key ACL is present; stop for review.' }
    }
    foreach ($requiredSid in @('S-1-5-18','S-1-5-32-544')) {
        $protectedPrincipals = @($aclBefore.Access | Where-Object { (Get-SidValue $_.IdentityReference) -ceq $requiredSid -and $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow })
        $protectedAfter = @($aclAfter.Access | Where-Object { (Get-SidValue $_.IdentityReference) -ceq $requiredSid -and $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow })
        if ($protectedPrincipals.Count -eq 0 -or $protectedPrincipals.Count -ne $protectedAfter.Count) { throw 'SYSTEM/Administrators key ACL entry missing or changed.' }
    }

    $postMintStoreThumbprints = Get-StoreThumbInventory
    foreach ($store in $storePaths) {
        $expectedThumbprints = @($preMintStoreThumbprints[$store])
        if ($store -ceq 'Cert:\LocalMachine\My') { $expectedThumbprints = @($expectedThumbprints + $created.Thumbprint | Sort-Object) }
        if (($postMintStoreThumbprints[$store] -join ',') -cne ($expectedThumbprints -join ',')) { throw "Certificate-store inventory changed unexpectedly after mint in $store." }
    }

    $challenge = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($challenge)
    $signature = $rsa.SignData($challenge,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $publicRsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($created)
    if (-not $publicRsa.VerifyData($challenge,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)) { throw 'In-memory private/public challenge verification failed.' }

    Export-Certificate -Cert $created -FilePath $publicCerPath -Type CERT -NoClobber | Out-Null
    $publicCert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($publicCerPath)
    if ($publicCert.Thumbprint -cne $created.Thumbprint) { throw 'Public CER thumbprint mismatch.' }
    $metadata = [ordered]@{
        Status='CreatedAndProbed'; UTC=[DateTime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME; UUID=$product.UUID; User=$identity.Name; SID=$sid
        Thumbprint=$created.Thumbprint; Subject=$created.Subject; Issuer=$created.Issuer; NotBeforeUtc=$created.NotBefore.ToUniversalTime().ToString('o'); NotAfterUtc=$created.NotAfter.ToUniversalTime().ToString('o')
        Store='LocalMachine\My'; Provider=$rsa.Key.Provider.Provider; Algorithm='RSA'; KeySize=$rsa.KeySize; PublicKeyOid=$created.PublicKey.Oid.Value; SignatureAlgorithmOid=$created.SignatureAlgorithm.Value; IssuerEqualsSubject=($created.Issuer -ceq $created.Subject); BasicConstraintsCount=$basicExtensions.Count; BasicConstraintsCA=$basicConstraints.CertificateAuthority; IsMachineKey=$rsa.Key.IsMachineKey; IsEphemeral=$rsa.Key.IsEphemeral; ExportPolicy=$rsa.Key.ExportPolicy.ToString(); PrivateKeyMaterialExported=$false
        KeyContainerUniqueName=$rsa.Key.UniqueName; KeyFilePath=$keyPath; KeyAclSddlBefore=$aclBeforeSddl; KeyAclSddlAfter=$aclAfter.Sddl; KeyAclOwnerBefore=$aclBeforeOwner; KeyAclOwnerAfter=$aclAfter.Owner; KeyAclGroupBefore=$aclBeforeGroup; KeyAclGroupAfter=$aclAfter.Group; KeyAclProtectedBefore=$aclBeforeProtected; KeyAclProtectedAfter=$aclAfter.AreAccessRulesProtected; KeyAclAceRowsBefore=$beforeAceRows; KeyAclAceRowsAfter=$afterAceRows; KeyAclAddedAceRows=$addedAceRows; KeyAclRemovedAceRows=$removedAceRows; VikaSidHasExactRead=$true
        EnhancedKeyUsageOids=$eku; KeyUsage=$ku.KeyUsages.ToString(); PublicCerPath=$publicCerPath; PublicCerSHA256=(Get-FileHash -LiteralPath $publicCerPath -Algorithm SHA256).Hash
        PreMintAllStoreThumbprints=$preMintStoreThumbprints; PostMintAllStoreThumbprints=$postMintStoreThumbprints; ChallengeSignatureVerified=$true; SignatureBytesEmitted=$false; PersistentTrustChanged=$false
    }
    $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $evidencePath -Encoding UTF8
    $metadata | ConvertTo-Json -Depth 5 -Compress
} catch {
    $failureStores = Get-StoreThumbInventory
    $partialCertificates = @()
    foreach ($store in $storePaths) {
        $partialCertificates += @(Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Subject -ceq $subject } | ForEach-Object { [ordered]@{Store=$store;Thumbprint=$_.Thumbprint;Subject=$_.Subject;HasPrivateKey=[bool]$_.HasPrivateKey} })
    }
    $createdThumbprint = if ($created) { $created.Thumbprint } else { $null }
    $failure = [ordered]@{
        Status='PostMintGuardFailed'; UTC=[DateTime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME; UUID=$product.UUID; User=$identity.Name; SID=$sid
        ExpectedSubject=$subject; CreatedThumbprint=$createdThumbprint; OriginalThumbprint=$oldThumb
        ErrorType=$_.Exception.GetType().FullName; ErrorHResult=('0x{0:X8}' -f $_.Exception.HResult)
        PreMintAllStoreThumbprints=$preMintStoreThumbprints; FailureAllStoreThumbprints=$failureStores; MatchingSubjectCertificates=$partialCertificates
        PrivateKeyMaterialExported=$false; PersistentTrustChanged=$false; SourcePinsChanged=$false; BuildOrSigningAttempted=$false
        RequiredNextStep='Preserve this metadata and failed branch evidence; do not use this key. Restore the independently verified pre-fallback builder checkpoint, then verify complete store inventories, original certificate thumbprint, and pinned PFX/CER hashes before another attempt.'
    }
    try { if (-not (Test-Path -LiteralPath $evidencePath -PathType Leaf)) { $failure | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $evidencePath -Encoding UTF8 } } catch { }
    $failure | ConvertTo-Json -Depth 8 -Compress
    throw 'Post-mint guard failed. Preserve the failed branch/evidence, perform no trust/source/build/sign action, and restore the verified pre-fallback checkpoint.'
} finally {
    if ($challenge) { [Array]::Clear($challenge,0,$challenge.Length) }
    if ($signature) { [Array]::Clear($signature,0,$signature.Length) }
    if ($rng) { $rng.Dispose() }
    if ($publicRsa) { $publicRsa.Dispose() }
    if ($rsa) { $rsa.Dispose() }
}
