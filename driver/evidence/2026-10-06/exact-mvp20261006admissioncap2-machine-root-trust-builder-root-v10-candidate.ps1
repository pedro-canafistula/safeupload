# REVIEW ONLY / CANDIDATE: one diagnostic LM\Root trust attempt for the exact frozen V8 CER.
# V8/V9 files remain frozen and unchanged. This exact candidate passed a Windows PowerShell 5.1 parse; it has not been executed.
# It does not assume that a CA:FALSE self-issued signing certificate is accepted as a Root trust anchor.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch] $RootApprovedForBuilderTrust,
    [Parameter(Mandatory)][switch] $KeyBearingCheckpointVerified,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string] $ExpectedThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCerSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCreationMetadataSha256
)
$ErrorActionPreference = 'Stop'
$guardHelpersPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v8.ps1'
$guardHelpersExpectedSha256 = '9585e1acd512f9532de032c6ce2df251fa774acc83d27cfc6afceb437ce64c42'
if (-not (Test-Path -LiteralPath $guardHelpersPath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $guardHelpersPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $guardHelpersExpectedSha256) {
    throw 'Pinned V8 signing guard helper is missing or changed.'
}
. $guardHelpersPath
$processCapturePath = Join-Path $PSScriptRoot 'signing-process-capture-v9.ps1'
$processCaptureExpectedSha256 = '6cac6f59c640c6fb045f61b87be1bb4deeeea451c80cd067ae022180a0a01a9f'
if (-not (Test-Path -LiteralPath $processCapturePath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $processCapturePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $processCaptureExpectedSha256) {
    throw 'Pinned V9 process-capture helper is missing or changed.'
}
. $processCapturePath
$expectedComputer = 'DESKTOP-O1LP5DG'; $expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'; $expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$oldThumb = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$oldPfxHash = 'DE1CD348314292C3F391015C9B2790FBE8956D886994BF5C4AE7C67AC51B2F03'
$oldCerHash = '46E4E8082155E2EE9E3602C613224322F863ADB85EC02C542FF2F4C8700BA0A1'
$subject = 'CN=SafeUpload Test Signing Recovery 20261006 V8'
$cerPath = 'C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v8.cer'
$creationMetadataPath = 'C:\Users\vika\Documents\exact-mvp20261006admissioncap2\replacement-machine-key-v8-metadata.json'
if (-not $RootApprovedForBuilderTrust -or -not $KeyBearingCheckpointVerified) { throw 'Root approval and verified key-bearing builder checkpoint switches are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $product = Get-CimInstance Win32_ComputerSystemProduct
if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid -or $identity.User.Value -cne $expectedSid) { throw 'Exact builder identity guard failed.' }
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Current builder token must have enabled Administrators membership for LocalMachine Root.' }
if ((Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.pfx' -Algorithm SHA256).Hash -cne $oldPfxHash -or
    (Get-FileHash -LiteralPath 'C:\safeupload-cert\SafeUploadTest.cer' -Algorithm SHA256).Hash -cne $oldCerHash) { throw 'Original PFX/CER hash guard failed before builder trust.' }
$oldCert = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $oldThumb) -ErrorAction Stop
if ($oldCert.Subject -cne 'CN=SafeUpload Test Signing' -or -not $oldCert.HasPrivateKey) { throw 'Original CurrentUser certificate was not retained.' }
if ((Get-FileHash -LiteralPath $cerPath -Algorithm SHA256).Hash -cne $ExpectedCerSha256.ToUpperInvariant()) { throw 'Public CER SHA-256 guard failed.' }
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)
if ($cert.Thumbprint -cne $ExpectedThumbprint.ToUpperInvariant() -or $cert.Subject -cne $subject -or -not $cert.Issuer.Equals($cert.Subject, [StringComparison]::Ordinal)) { throw 'Public CER identity/self-issued guard failed.' }
$basicConstraints = @($cert.Extensions | Where-Object { $_.Oid.Value -ceq '2.5.29.19' })
if ($basicConstraints.Count -ne 1 -or -not ($basicConstraints[0] -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) -or $basicConstraints[0].CertificateAuthority) { throw 'V8 candidate requires the exact pinned CA:FALSE certificate profile.' }
$machineCert = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $cert.Thumbprint) -ErrorAction Stop
if (-not $machineCert.HasPrivateKey -or $machineCert.Subject -cne $subject) { throw 'Matching LocalMachine private certificate is missing.' }
$eku = @(Get-SafeUploadCodeSigningEkuOids -Extensions @($cert.Extensions) -Context 'Builder public CER')
if ((Get-FileHash -LiteralPath $creationMetadataPath -Algorithm SHA256).Hash -cne $ExpectedCreationMetadataSha256.ToUpperInvariant()) { throw 'V8 creation metadata SHA-256 guard failed.' }
$creationMetadata = Get-Content -LiteralPath $creationMetadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ($creationMetadata.Status -cne 'CreatedAndProbed' -or $creationMetadata.Thumbprint -cne $cert.Thumbprint -or
    $creationMetadata.Subject -cne $subject -or $creationMetadata.PublicCerSHA256 -cne $ExpectedCerSha256.ToUpperInvariant() -or
    $creationMetadata.PublicCerPath -cne $cerPath -or $creationMetadata.NoAclWrite -ne $true -or
    $creationMetadata.EffectiveAdministratorsMembership -ne $true -or $creationMetadata.KeyAclUnchanged -ne $true -or
    $creationMetadata.CreatorOwnerKeptAsLiteralProviderAce -ne $true -or
    $creationMetadata.PrivateKeyMaterialExported -ne $false) { throw 'Pinned V8 creation metadata does not attest the expected no-ACL-write key.' }
$expectedDefaultAclPrincipals = @('S-1-3-0','S-1-5-18','S-1-5-32-544')
if ((@($creationMetadata.DefaultAclPrincipals) -join ',') -cne ($expectedDefaultAclPrincipals -join ',')) { throw 'V8 metadata does not pin the exact captured default ACL trustees.' }
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $creationMetadata.KeyAclSnapshotBefore
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $creationMetadata.KeyAclSnapshotAfter
$metadataKeyPath = [string]$creationMetadata.KeyFilePath
$keyUniqueName = [string]$creationMetadata.KeyContainerUniqueName
if ([string]::IsNullOrWhiteSpace($keyUniqueName) -or $keyUniqueName -notmatch '^[A-Za-z0-9{}._-]{1,256}$') { throw 'V8 CNG unique-name metadata is malformed.' }
$expectedMetadataKeyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $keyUniqueName
if ($metadataKeyPath -cne $expectedMetadataKeyPath -or -not (Test-Path -LiteralPath $metadataKeyPath -PathType Leaf)) { throw 'V8 KSP key path does not exactly match the pinned unique-name file in the machine key directory.' }
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
$aclBeforeTrust = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $metadataKeyPath -ErrorAction Stop)
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $aclBeforeTrust
Assert-SafeUploadKeyAclUnchanged -Before $creationMetadata.KeyAclSnapshotBefore -After $aclBeforeTrust
Assert-SafeUploadKeyAclUnchanged -Before $creationMetadata.KeyAclSnapshotAfter -After $aclBeforeTrust
function Test-StoreSnapshotEqual {
    param([Parameter(Mandatory)][object] $Left, [Parameter(Mandatory)][object] $Right)
    foreach ($store in $stores) {
        if ($null -eq $Left[$store] -or $null -eq $Right[$store] -or
            (($Left[$store] -join ',') -cne ($Right[$store] -join ','))) { return $false }
    }
    return $true
}
foreach ($store in $stores) {
    $newThumbCount = @($before[$store] | Where-Object { $_ -ceq $newThumb }).Count
    if ($store -ceq 'Cert:\LocalMachine\My') {
        if ($newThumbCount -ne 1) { throw 'New thumb must be present exactly once in LocalMachine My before builder trust.' }
    } elseif ($newThumbCount -ne 0) {
        throw "New thumbprint is already present outside its expected LocalMachine My key store: $store."
    }
}
$certutilExitCode = $null
$certutilStdout = ''
$certutilStderr = ''
$machineRootAddAttempted = $false
try {
    $certutilPath = Join-Path $env:SystemRoot 'System32\certutil.exe'
    if (-not (Test-Path -LiteralPath $certutilPath -PathType Leaf)) { throw 'Pinned Windows certutil.exe is unavailable.' }
    # With no -user option certutil targets the LocalMachine store. Do not use -f: the exact thumb
    # must be absent at baseline, so this attempt must never overwrite a pre-existing certificate.
    $machineRootAddAttempted = $true
    $processResult = Invoke-SafeUploadCapturedProcess -FilePath $certutilPath -Arguments ('-addstore Root "' + $cerPath + '"')
    $certutilExitCode = $processResult.ExitCode
    $certutilStdout = $processResult.Stdout
    $certutilStderr = $processResult.Stderr
    if ($certutilExitCode -ne 0) { throw ('certutil -addstore Root (LocalMachine) failed with exit ' + $certutilExitCode + '; stdout: ' + $certutilStdout + '; stderr: ' + $certutilStderr) }
    $after = Get-StoreInventory
    foreach ($store in $stores) {
        $expectedThumbs = @($before[$store])
        if ($store -ceq 'Cert:\CurrentUser\Root' -or $store -ceq 'Cert:\LocalMachine\Root') { $expectedThumbs = @($expectedThumbs + $newThumb | Sort-Object) }
        if (($after[$store] -join ',') -cne ($expectedThumbs -join ',')) { throw "Builder trust inventory changed unexpectedly in $store." }
    }
    $aclAfterTrust = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $metadataKeyPath -ErrorAction Stop)
    Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $aclAfterTrust
    Assert-SafeUploadKeyAclUnchanged -Before $creationMetadata.KeyAclSnapshotBefore -After $aclAfterTrust
    Assert-SafeUploadKeyAclUnchanged -Before $creationMetadata.KeyAclSnapshotAfter -After $aclAfterTrust
    $testSigningAfter = Get-TestSigningState
    if ($testSigningAfter -cne $testSigningBefore) { throw 'Builder testsigning changed during trust operation.' }
    [ordered]@{Status='ExactBuilderLocalMachineRootAddedV10Candidate';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;User=$identity.Name;Thumbprint=$newThumb;Subject=$cert.Subject;Issuer=$cert.Issuer;CertificateAuthority=$basicConstraints[0].CertificateAuthority;CerSha256=$ExpectedCerSha256.ToUpperInvariant();CreationMetadataSha256=$ExpectedCreationMetadataSha256.ToUpperInvariant();Store='LocalMachine\Root';AddStoreMethod='certutil -addstore Root (no -user; LocalMachine target)';CertutilExitCode=$certutilExitCode;CertutilStdout=$certutilStdout;CertutilStderr=$certutilStderr;BeforeAllStoreThumbprints=$before;AfterAllStoreThumbprints=$after;KeyAclBeforeTrust=$aclBeforeTrust;KeyAclAfterTrust=$aclAfterTrust;TestSigningBefore=$testSigningBefore;TestSigningAfter=$testSigningAfter;OnlyApprovedLocalMachineRootDelta=$true;CurrentUserRootIsExpectedMergedView=$true;TrustedPublisherChanged=$false;LocalMachineMyUnchanged=$true;KeyAclCheckedUnchanged=$true;NoAclWrite=$true;CreationMetadataStatus=$creationMetadata.Status}|ConvertTo-Json -Depth 12 -Compress
} catch {
    $originalError = $_
    $failureStores = $null
    $failureAcl = $null
    $failureTestSigning = $null
    $failureCaptureErrors = @()
    try { $failureStores = Get-StoreInventory } catch { $failureCaptureErrors += ('StoreSnapshot=' + $_.Exception.ToString()) }
    try { $failureAcl = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $metadataKeyPath -ErrorAction Stop) } catch { $failureCaptureErrors += ('KeyAclSnapshot=' + $_.Exception.ToString()) }
    try { $failureTestSigning = Get-TestSigningState } catch { $failureCaptureErrors += ('TestSigningSnapshot=' + $_.Exception.ToString()) }
    $rollbackAttempted = $false
    $rollbackError = $null
    try {
        # Only the exact LM\Root thumb may be removed, and only after an attempt made from a
        # baseline where that thumb was absent from both projected Root views and all other stores.
        $newMachineRootCerts = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\Root' -ErrorAction Stop | Where-Object { $_.Thumbprint -ceq $newThumb })
        if ($machineRootAddAttempted -and $newMachineRootCerts.Count -gt 0) {
            $rollbackAttempted = $true
            Remove-Item -LiteralPath ('Cert:\LocalMachine\Root\' + $newThumb) -Force -ErrorAction Stop
        }
    } catch { $rollbackError = $_.Exception.ToString() }
    $rollbackStores = $null
    $rollbackAcl = $null
    try { $rollbackStores = Get-StoreInventory } catch { $failureCaptureErrors += ('PostRollbackStoreSnapshot=' + $_.Exception.ToString()) }
    try { $rollbackAcl = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $metadataKeyPath -ErrorAction Stop) } catch { $failureCaptureErrors += ('PostRollbackKeyAclSnapshot=' + $_.Exception.ToString()) }
    $rollbackStoresRestored = $false
    if ($null -ne $rollbackStores) { $rollbackStoresRestored = Test-StoreSnapshotEqual -Left $before -Right $rollbackStores }
    $rollbackAclUnchanged = $false
    if ($null -ne $rollbackAcl) {
        try {
            Assert-SafeUploadKeyAclUnchanged -Before $aclBeforeTrust -After $rollbackAcl
            $rollbackAclUnchanged = $true
        } catch { $failureCaptureErrors += ('PostRollbackKeyAclComparison=' + $_.Exception.ToString()) }
    }
    $failureAclUnchanged = $false
    if ($null -ne $failureAcl) {
        try {
            Assert-SafeUploadKeyAclUnchanged -Before $aclBeforeTrust -After $failureAcl
            $failureAclUnchanged = $true
        } catch { $failureCaptureErrors += ('FailureKeyAclComparison=' + $_.Exception.ToString()) }
    }
    [ordered]@{
        Status='BuilderLocalMachineRootTrustFailedV10Candidate'; UTC=[DateTime]::UtcNow.ToString('o'); ComputerName=$env:COMPUTERNAME; UUID=$product.UUID; User=$identity.Name; Thumbprint=$newThumb
        OriginalErrorType=$originalError.Exception.GetType().FullName; OriginalErrorMessage=$originalError.Exception.Message; OriginalErrorHResult=('0x{0:X8}' -f $originalError.Exception.HResult); OriginalExceptionToString=$originalError.Exception.ToString()
        OriginalFullyQualifiedErrorId=$originalError.FullyQualifiedErrorId; OriginalCategory=([string]$originalError.CategoryInfo)
        OriginalScriptStackTrace=$originalError.ScriptStackTrace; OriginalPositionMessage=$originalError.InvocationInfo.PositionMessage
        BeforeAllStoreThumbprints=$before; AfterFailureAllStoreThumbprints=$failureStores; AfterRollbackAllStoreThumbprints=$rollbackStores
        KeyAclBeforeTrust=$aclBeforeTrust; KeyAclAtFailure=$failureAcl; KeyAclAfterRollback=$rollbackAcl
        KeyAclUnchangedAtFailure=$failureAclUnchanged; KeyAclUnchangedAfterRollback=$rollbackAclUnchanged
        RollbackAttempted=$rollbackAttempted; RollbackError=$rollbackError; StoreInventoryRestoredAfterRollback=$rollbackStoresRestored
        TestSigningBefore=$testSigningBefore; TestSigningAtFailure=$failureTestSigning; CertutilExitCode=$certutilExitCode; CertutilStdout=$certutilStdout; CertutilStderr=$certutilStderr; FailureCaptureErrors=$failureCaptureErrors
        TrustScope='LocalMachine\Root only; CurrentUser\Root expected merged view'; MachineRootAddAttempted=$machineRootAddAttempted; PrivateKeyExported=$false; NoAclWrite=$true
    } | ConvertTo-Json -Depth 16 -Compress | Write-Output
    $PSCmdlet.ThrowTerminatingError($originalError)
}
