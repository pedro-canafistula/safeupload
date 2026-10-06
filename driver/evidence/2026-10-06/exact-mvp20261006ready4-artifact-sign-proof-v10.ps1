# V10 ONE-SHOT SIGNING PROOF CANDIDATE. Static review is pending; this script has
# not been executed. Do not run until both receipts pass independent review and
# root supplies their exact hashes and approval.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $UnsignedArtifactPath,
    [Parameter(Mandatory)][string] $ColdReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ColdReceiptSha256,
    [Parameter(Mandatory)][string] $TrustReceiptPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $TrustReceiptSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedScriptSha256,
    [Parameter(Mandatory)][string] $PrivateRoot,
    [Parameter(Mandatory)][string] $PublicRoot,
    [Parameter(Mandatory)][switch] $RootApprovedForArtifactSigning,
    [Parameter(Mandatory)][switch] $ColdReceiptIndependentlyReviewed,
    [Parameter(Mandatory)][switch] $TrustReceiptIndependentlyReviewed
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Requires Windows PowerShell 5.1.' }
if (-not $RootApprovedForArtifactSigning -or -not $ColdReceiptIndependentlyReviewed -or -not $TrustReceiptIndependentlyReviewed) {
    throw 'Root approval and independent review of both receipts are required.'
}

$computer = 'DESKTOP-O1LP5DG'
$uuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$user = 'DESKTOP-O1LP5DG\vika'
$sid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$thumb = 'A6D6CE1AA28835D509160A80ADB7894869AADF38'
$subject = 'CN=SafeUpload Test Signing Recovery 20261006 V8'
$oldFallbackThumb = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$cerSha = '47E7069980A60CBCF4DFF61F0F2D3F02EDCF97C2976708790B49D03A09243B2A'
$metadataSha = '51701037AF41FCC19101E26DD2D632934D20B94190D42782474F68F05ABDFC1E'
$unsignedSha = '8C19FE05135E10AABACABC433F0DC5CB68A53CCBD7A3CC82052D0D9804586FC9'
$helperSha = '9585e1acd512f9532de032c6ce2df251fa774acc83d27cfc6afceb437ce64c42'
$buildScriptSha = 'ccd8996a91de8b7663e0d2dfe5c78629c346513dbc72909014339538f8865773'
$coldScriptSha = 'cfa6dff0ba96f3bbc346bb1dc03eec6a47153c2cd4011b913deae0c3634896a3'
$trustScriptSha = '235f1c14cfcbd402c4fb7f464a7c2af2c54bcc67ac78ecb57f0b815903ca749a'
$helperPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v8.ps1'
$coldScriptPath = Join-Path $PSScriptRoot 'exact-mvp20261006admissioncap2-key-bearing-cold-challenge-v8.ps1'
$trustScriptPath = Join-Path $PSScriptRoot 'exact-mvp20261006admissioncap2-machine-root-trust-builder-root-v10-candidate.ps1'
$metadataPath = 'C:\Users\vika\Documents\exact-mvp20261006admissioncap2\replacement-machine-key-v8-metadata.json'
$cerPath = 'C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v8.cer'
$signTool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.28000.0\x64\signtool.exe'
$stores = @(
    'Cert:\CurrentUser\My', 'Cert:\CurrentUser\Root', 'Cert:\CurrentUser\TrustedPublisher',
    'Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher'
)

function Get-Hash([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ("Missing file: {0}" -f $Path) }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToUpperInvariant()
}
function Assert-Hash([string] $Path, [string] $Expected, [string] $Name) {
    if ((Get-Hash $Path) -cne $Expected.ToUpperInvariant()) { throw ("{0} SHA-256 mismatch." -f $Name) }
}
function Read-Receipt([string] $Path, [string] $ExpectedHash, [string] $Name) {
    Assert-Hash $Path $ExpectedHash $Name
    try { return (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw ("{0} is not valid JSON." -f $Name) }
}
function Get-Thumbs([object] $Inventory, [string] $Store) {
    if ($Inventory -is [System.Collections.IDictionary]) {
        if (-not $Inventory.Contains($Store)) { throw ("Store inventory missing {0}." -f $Store) }
        $items = $Inventory[$Store]
    } else {
        $property = $Inventory.PSObject.Properties[$Store]
        if ($null -eq $property) { throw ("Store inventory missing {0}." -f $Store) }
        $items = $property.Value
    }
    return @($items | ForEach-Object { ([string]$_).ToUpperInvariant() } | Sort-Object)
}
function Assert-InventoryEqual([object] $Left, [object] $Right, [string] $Context) {
    foreach ($store in $stores) {
        $a = @(Get-Thumbs $Left $store); $b = @(Get-Thumbs $Right $store)
        if (($a -join ',') -cne ($b -join ',')) { throw ("{0}: store inventory mismatch at {1}." -f $Context, $store) }
    }
}
function Get-StoreInventory {
    $result = [ordered]@{}
    foreach ($store in $stores) {
        $result[$store] = @(Get-ChildItem -LiteralPath $store -ErrorAction Stop |
            ForEach-Object { $_.Thumbprint.ToUpperInvariant() } | Sort-Object)
    }
    return $result
}
function Get-Identity {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = [Security.Principal.WindowsPrincipal]::new($wi)
    $product = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
    return [pscustomobject]@{
        ComputerName = [string]$env:COMPUTERNAME; UUID = [string]$product.UUID
        User = [string]$wi.Name; SID = [string]$wi.User.Value
        EnabledAdministrators = [bool]$wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        PowerShellProcessId = [int]$PID
    }
}
function Assert-Identity([object] $Identity) {
    if ($Identity.ComputerName -cne $computer -or $Identity.UUID -cne $uuid -or $Identity.User -cne $user -or
        $Identity.SID -cne $sid -or -not $Identity.EnabledAdministrators) { throw 'Exact builder identity or enabled Administrators token check failed.' }
}
function Assert-ReceiptBase([object] $Receipt, [string] $Name, [string] $CerField, [switch] $RequireSid) {
    if ($Receipt.ComputerName -cne $computer -or $Receipt.UUID -cne $uuid -or $Receipt.User -cne $user -or
        $Receipt.Thumbprint -cne $thumb -or $Receipt.CreationMetadataSha256 -cne $metadataSha -or
        $Receipt.$CerField -cne $cerSha -or ($RequireSid -and $Receipt.SID -cne $sid)) {
        throw ("{0} is not bound to the pinned builder and V8 certificate." -f $Name)
    }
}
function Assert-KeyAcl([object] $Metadata) {
    $name = [string]$Metadata.KeyContainerUniqueName
    if ([string]::IsNullOrWhiteSpace($name) -or $name -notmatch '^[A-Za-z0-9{}._-]{1,256}$') { throw 'Malformed V8 key container name.' }
    $path = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $name
    if ($Metadata.KeyFilePath -cne $path) { throw 'V8 key file path differs from the pinned machine KSP location.' }
    $current = Get-SafeUploadOrderedKeyAclSnapshot -AclObject (Get-Acl -LiteralPath $path -ErrorAction Stop)
    Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $current
    Assert-SafeUploadKeyAclUnchanged -Before $Metadata.KeyAclSnapshotBefore -After $current
    Assert-SafeUploadKeyAclUnchanged -Before $Metadata.KeyAclSnapshotAfter -After $current
}
function New-PrivateDirectory([string] $Path) {
    [void][IO.Directory]::CreateDirectory($Path)
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($allowedSid in @('S-1-5-18', 'S-1-5-32-544', $sid)) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($allowedSid),
            [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop
    $actual = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    $actualSids = @($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object)
    $expectedSids = @('S-1-5-18', 'S-1-5-32-544', $sid) | Sort-Object
    if ($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544' -or
        -not $actual.AreAccessRulesProtected -or -not $actual.AreAccessRulesCanonical -or
        $rules.Count -ne 3 -or ($actualSids -join ',') -cne ($expectedSids -join ',')) { throw 'Private run directory ACL is not the protected three-principal allowlist.' }
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.InheritanceFlags -ne $inherit -or $rule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None -or
            $rule.IsInherited) { throw 'Private run directory contains an unexpected ACE.' }
    }
    return [string]$actual.Sddl
}

if ((Get-Hash $PSCommandPath) -cne $ExpectedScriptSha256.ToUpperInvariant()) { throw 'Signer script hash differs from the reviewed pin.' }
Assert-Hash $helperPath $helperSha 'V8 ACL/EKU helper'
Assert-Hash $coldScriptPath $coldScriptSha 'V8 cold-challenge script'
Assert-Hash $trustScriptPath $trustScriptSha 'V10 builder-trust script'
. $helperPath
$identityBefore = Get-Identity; Assert-Identity $identityBefore
Assert-Hash $metadataPath $metadataSha 'V8 creation metadata'
Assert-Hash $cerPath $cerSha 'V8 public certificate'
$metadata = Get-Content -LiteralPath $metadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
if ($metadata.Status -cne 'CreatedAndProbed' -or $metadata.ComputerName -cne $computer -or $metadata.UUID -cne $uuid -or
    $metadata.SID -cne $sid -or $metadata.Thumbprint -cne $thumb -or $metadata.Subject -cne $subject -or
    $metadata.NoAclWrite -ne $true -or $metadata.KeyAclUnchanged -ne $true -or
    $metadata.PrivateKeyMaterialExported -ne $false -or $metadata.PersistentTrustChanged -ne $false -or
    $metadata.TestSigningBefore -cne 'No' -or $metadata.TestSigningAfter -cne 'No') { throw 'V8 mint metadata failed its pinned no-key-change checks.' }
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $metadata.KeyAclSnapshotBefore
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $metadata.KeyAclSnapshotAfter
Assert-KeyAcl $metadata

$cold = Read-Receipt $ColdReceiptPath $ColdReceiptSha256 'Cold challenge receipt'
Assert-ReceiptBase $cold 'Cold challenge receipt' 'PublicCerSha256' -RequireSid
if ($cold.Status -cne 'V8_COLD_KEY_CHALLENGE_PASS' -or $cold.Subject -cne $subject -or
    $cold.Provider -cne 'Microsoft Software Key Storage Provider' -or $cold.KeySize -ne 3072 -or $cold.ExportPolicy -cne 'None' -or
    $cold.IsMachineKey -ne $true -or $cold.IsEphemeral -ne $false -or $cold.EffectiveAdministratorsMembership -ne $true -or
    $cold.KeyAclUnchangedFromMint -ne $true -or $cold.NoAclWrite -ne $true -or $cold.PrivateKeyMaterialExported -ne $false -or
    $cold.TrustChanged -ne $false -or $cold.BuildOrArtifactSignAttempted -ne $false -or
    $cold.ChallengeSignaturePersistedOrExported -ne $false -or $cold.TestSigningBefore -cne 'No' -or $cold.TestSigningAfter -cne 'No' -or
    @($cold.EnhancedKeyUsageOids).Count -ne 1 -or @($cold.EnhancedKeyUsageOids)[0] -cne '1.3.6.1.5.5.7.3.3') {
    throw 'Cold challenge receipt failed the exact V8 key proof checks.'
}
Assert-InventoryEqual $cold.PreChallengeAllStoreThumbprints $cold.PostChallengeAllStoreThumbprints 'Cold challenge'
Assert-InventoryEqual $cold.PostChallengeAllStoreThumbprints $metadata.PostMintAllStoreThumbprints 'Cold challenge vs mint inventory'

$trust = Read-Receipt $TrustReceiptPath $TrustReceiptSha256 'Builder trust receipt'
Assert-ReceiptBase $trust 'Builder trust receipt' 'CerSha256'
if ($trust.Status -cne 'ExactBuilderLocalMachineRootAddedV10Candidate' -or $trust.Subject -cne $subject -or
    $trust.Store -cne 'LocalMachine\Root' -or $trust.TestSigningBefore -cne 'No' -or $trust.TestSigningAfter -cne 'No' -or
    $trust.AddStoreMethod -cne 'certutil -addstore Root (no -user; LocalMachine target)' -or $trust.CertutilExitCode -ne 0 -or
    $trust.OnlyApprovedLocalMachineRootDelta -ne $true -or $trust.CurrentUserRootIsExpectedMergedView -ne $true -or
    $trust.TrustedPublisherChanged -ne $false -or $trust.LocalMachineMyUnchanged -ne $true -or
    $trust.KeyAclCheckedUnchanged -ne $true -or $trust.NoAclWrite -ne $true -or
    $trust.CreationMetadataStatus -cne 'CreatedAndProbed') { throw 'Builder trust receipt failed the exact LocalMachine Root plus merged CurrentUser Root checks.' }
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $trust.KeyAclBeforeTrust
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $trust.KeyAclAfterTrust
Assert-SafeUploadKeyAclUnchanged -Before $metadata.KeyAclSnapshotBefore -After $trust.KeyAclBeforeTrust
Assert-SafeUploadKeyAclUnchanged -Before $metadata.KeyAclSnapshotAfter -After $trust.KeyAclBeforeTrust
Assert-SafeUploadKeyAclUnchanged -Before $metadata.KeyAclSnapshotBefore -After $trust.KeyAclAfterTrust
Assert-SafeUploadKeyAclUnchanged -Before $metadata.KeyAclSnapshotAfter -After $trust.KeyAclAfterTrust
Assert-InventoryEqual $trust.BeforeAllStoreThumbprints $metadata.PostMintAllStoreThumbprints 'Trust before vs mint inventory'
foreach ($store in $stores) {
    $before = @(Get-Thumbs $trust.BeforeAllStoreThumbprints $store)
    $after = @(Get-Thumbs $trust.AfterAllStoreThumbprints $store)
    if ($store -ceq 'Cert:\CurrentUser\Root' -or $store -ceq 'Cert:\LocalMachine\Root') {
        if ($before -contains $thumb) { throw 'V8 root thumb already existed before the approved LocalMachine Root trust delta.' }
        $expected = @($before + $thumb | Sort-Object)
    } else { $expected = $before }
    if (($after -join ',') -cne ($expected -join ',')) { throw ("Trust receipt contains an unapproved store change at {0}." -f $store) }
}

$inventoryAfterTrust = Get-StoreInventory
Assert-InventoryEqual $inventoryAfterTrust $trust.AfterAllStoreThumbprints 'Current builder stores vs trust receipt'
$machineCerts = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Thumbprint.ToUpperInvariant() -ceq $thumb })
if ($machineCerts.Count -ne 1 -or -not $machineCerts[0].HasPrivateKey -or $machineCerts[0].Subject -cne $subject) { throw 'Exact V8 private certificate is not unique in LocalMachine My.' }
$eku = @(Get-SafeUploadCodeSigningEkuOids -Extensions @($machineCerts[0].Extensions) -Context 'V8 machine certificate')
if ($eku.Count -ne 1 -or $eku[0] -cne '1.3.6.1.5.5.7.3.3') { throw 'V8 machine certificate lacks the exact code-signing EKU.' }
$oldFallbackCerts = @(Get-ChildItem -LiteralPath 'Cert:\LocalMachine\My' -ErrorAction Stop | Where-Object { $_.Thumbprint.ToUpperInvariant() -ceq $oldFallbackThumb })
if ($oldFallbackCerts.Count -ne 0) {
    throw 'Old fallback signer exists in LocalMachine My; refusing ambiguous signer selection.'
}
Assert-KeyAcl $metadata

Assert-Hash $UnsignedArtifactPath $unsignedSha 'READY4 unsigned feature artifact'
$unsignedSignature = Get-AuthenticodeSignature -LiteralPath $UnsignedArtifactPath -ErrorAction Stop
if ($unsignedSignature.Status.ToString() -cne 'NotSigned' -or $null -ne $unsignedSignature.SignerCertificate) { throw 'Pinned READY4 source is not unsigned.' }
if (-not (Test-Path -LiteralPath $signTool -PathType Leaf)) { throw 'Pinned Windows SDK SignTool is missing.' }
foreach ($root in @($PrivateRoot, $PublicRoot)) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw ("Output parent is missing: {0}" -f $root) }
    $full = [IO.Path]::GetFullPath($root).TrimEnd('\')
    if ($full.StartsWith('\\') -or $full -notmatch '^[A-Za-z]:\\.+') { throw 'Output parents must be non-root local drive directories.' }
}
$privateRootFull = [IO.Path]::GetFullPath($PrivateRoot).TrimEnd('\')
$publicRootFull = [IO.Path]::GetFullPath($PublicRoot).TrimEnd('\')
if ($privateRootFull -ieq $publicRootFull -or $privateRootFull.StartsWith($publicRootFull + '\',[StringComparison]::OrdinalIgnoreCase) -or
    $publicRootFull.StartsWith($privateRootFull + '\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Private and public roots must be separate.' }

$guid = [Guid]::NewGuid().ToString('D').ToUpperInvariant()
$privateDir = Join-Path $privateRootFull $guid
$publicDir = Join-Path $publicRootFull $guid
if ((Test-Path -LiteralPath $privateDir) -or (Test-Path -LiteralPath $publicDir)) { throw 'Fresh proof GUID already exists.' }
$privateDirectorySddl = New-PrivateDirectory $privateDir
$privateUnsigned = Join-Path $privateDir 'owned-feature.unsigned.sys'
$signedCopy = Join-Path $privateDir 'owned-feature.signed.sys'
$signOut = Join-Path $privateDir 'signtool.stdout.txt'
$signErr = Join-Path $privateDir 'signtool.stderr.txt'
Copy-Item -LiteralPath $UnsignedArtifactPath -Destination $privateUnsigned -ErrorAction Stop
Copy-Item -LiteralPath $privateUnsigned -Destination $signedCopy -ErrorAction Stop
Assert-Hash $privateUnsigned $unsignedSha 'Private unsigned copy'
Assert-Hash $signedCopy $unsignedSha 'Fresh signing copy before signing'

$identityAtSign = Get-Identity; Assert-Identity $identityAtSign
if ($identityAtSign.PowerShellProcessId -ne $identityBefore.PowerShellProcessId) { throw 'PowerShell process identity changed before SignTool.' }
Assert-KeyAcl $metadata
$signArguments = @('sign','/fd','sha256','/sha1',$thumb,'/s','My','/sm',('"' + $signedCopy + '"'))
$process = Start-Process -FilePath $signTool -ArgumentList ($signArguments -join ' ') -Wait -PassThru -NoNewWindow `
    -RedirectStandardOutput $signOut -RedirectStandardError $signErr -ErrorAction Stop
if ([int]$process.ExitCode -ne 0) { throw ("SignTool failed ({0}); no public proof was emitted." -f $process.ExitCode) }

Assert-Hash $UnsignedArtifactPath $unsignedSha 'Original unsigned artifact after signing'
Assert-Hash $privateUnsigned $unsignedSha 'Private unsigned copy after signing'
$signedSha = Get-Hash $signedCopy
if ($signedSha -ceq $unsignedSha) { throw 'SignTool did not change the fresh signing copy.' }
$signature = Get-AuthenticodeSignature -LiteralPath $signedCopy -ErrorAction Stop
$signer = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { 'NONE' }
if ($signature.Status.ToString() -cne 'Valid' -or $signer -cne $thumb) { throw 'Signed artifact is not Valid under the exact V8 thumbprint.' }
Assert-InventoryEqual (Get-StoreInventory) $trust.AfterAllStoreThumbprints 'Stores after signing'
Assert-KeyAcl $metadata
$identityAfter = Get-Identity; Assert-Identity $identityAfter
if ($identityAfter.PowerShellProcessId -ne $identityAtSign.PowerShellProcessId) { throw 'PowerShell process identity changed during signing.' }
Assert-Hash $metadataPath $metadataSha 'V8 creation metadata after signing'
Assert-Hash $cerPath $cerSha 'V8 public certificate after signing'
Assert-Hash $PSCommandPath $ExpectedScriptSha256 'Signer script after signing'
if ((Get-Acl -LiteralPath $privateDir -ErrorAction Stop).Sddl -cne $privateDirectorySddl) { throw 'Private work directory ACL changed during signing.' }

$proof = [ordered]@{
    Status = 'READY4_ARTIFACT_SIGNED_COPY_VALID'; UTC = [DateTime]::UtcNow.ToString('o'); ProofGuid = $guid
    BuilderComputerName = $identityAfter.ComputerName; BuilderUUID = $identityAfter.UUID
    SigningUser = $identityAfter.User; SigningUserSid = $identityAfter.SID
    EnabledAdministratorsInSigningPowerShell = $identityAtSign.EnabledAdministrators
    SigningPowerShellProcessId = $identityAtSign.PowerShellProcessId; SignToolProcessId = [int]$process.Id
    SamePowerShellCheckedIdentityAndStartedSignTool = $true; SignToolExitCode = [int]$process.ExitCode
    SignToolPath = $signTool; SignToolStore = 'LocalMachine\My'; SignToolSelection = '/sha1 exact V8 thumbprint + /s My + /sm'
    BuildExactSourceSha256 = $buildScriptSha
    SignToolThumbprint = $thumb; AuthenticodeStatus = $signature.Status.ToString(); AuthenticodeSignerThumbprint = $signer
    UnsignedArtifactSHA256 = $unsignedSha; UnsignedArtifactUnchangedAfterSign = $true; SignedArtifactSHA256 = $signedSha
    ColdReceiptSHA256 = $ColdReceiptSha256.ToUpperInvariant(); ColdReceiptStatus = $cold.Status
    BuilderTrustReceiptSHA256 = $TrustReceiptSha256.ToUpperInvariant(); BuilderTrustReceiptStatus = $trust.Status
    BuilderTrustStore = $trust.Store; BuilderTrustMethod = $trust.AddStoreMethod
    BuilderTrustLocalMachineRootOnly = [bool]$trust.OnlyApprovedLocalMachineRootDelta
    BuilderTrustCurrentUserRootExpectedMergedView = [bool]$trust.CurrentUserRootIsExpectedMergedView
    BuilderTrustNativeExitCode = [int]$trust.CertutilExitCode
    SignerScriptSHA256 = $ExpectedScriptSha256.ToUpperInvariant(); V8AclHelperSHA256 = $helperSha.ToUpperInvariant()
    V8ColdChallengeScriptSHA256 = $coldScriptSha.ToUpperInvariant(); V10BuilderTrustScriptSHA256 = $trustScriptSha.ToUpperInvariant()
    V8MetadataSHA256 = $metadataSha; V8PublicCerSHA256 = $cerSha
    KeyAclMatchesMintBeforeAndAfterSnapshots = $true; KeyAclChanged = $false
    TrustChangedBySigner = $false; CurrentSixStoreInventoryStillMatchesReviewedTrustReceipt = $true
}
$proofJsonPath = Join-Path $privateDir 'artifact-signature-proof.json'
Set-Content -LiteralPath $proofJsonPath -Value ($proof | ConvertTo-Json -Depth 8) -Encoding UTF8 -ErrorAction Stop
$proofSha = Get-Hash $proofJsonPath
$receiptColdName = 'cold-challenge-receipt.json'
$receiptTrustName = 'builder-trust-receipt.json'
New-Item -ItemType Directory -Path $publicDir -ErrorAction Stop | Out-Null
Copy-Item -LiteralPath $signedCopy -Destination (Join-Path $publicDir 'owned-feature.signed.sys') -ErrorAction Stop
Copy-Item -LiteralPath $ColdReceiptPath -Destination (Join-Path $publicDir $receiptColdName) -ErrorAction Stop
Copy-Item -LiteralPath $TrustReceiptPath -Destination (Join-Path $publicDir $receiptTrustName) -ErrorAction Stop
Copy-Item -LiteralPath $proofJsonPath -Destination (Join-Path $publicDir 'artifact-signature-proof.json') -ErrorAction Stop
$manifestLines = @(
    ('{0}  owned-feature.signed.sys' -f $signedSha),
    ('{0}  artifact-signature-proof.json' -f $proofSha),
    ('{0}  {1}' -f $ColdReceiptSha256.ToUpperInvariant(), $receiptColdName),
    ('{0}  {1}' -f $TrustReceiptSha256.ToUpperInvariant(), $receiptTrustName)
)
Set-Content -LiteralPath (Join-Path $publicDir 'artifact-signature-proof.sha256') -Value ($manifestLines -join "`r`n") -Encoding ASCII -ErrorAction Stop
$manifestSha = Get-Hash (Join-Path $publicDir 'artifact-signature-proof.sha256')
$expectedNames = @('artifact-signature-proof.json','artifact-signature-proof.sha256','builder-trust-receipt.json',
    'cold-challenge-receipt.json','owned-feature.signed.sys') | Sort-Object
$actualNames = @(Get-ChildItem -LiteralPath $publicDir -Force -ErrorAction Stop | ForEach-Object { $_.Name } | Sort-Object)
if (($actualNames -join ',') -cne ($expectedNames -join ',')) { throw 'Public proof package contains unexpected files.' }
Assert-Hash (Join-Path $publicDir 'owned-feature.signed.sys') $signedSha 'Published signed artifact'
Assert-Hash (Join-Path $publicDir 'artifact-signature-proof.json') $proofSha 'Published proof JSON'
Assert-Hash (Join-Path $publicDir $receiptColdName) $ColdReceiptSha256 'Published cold receipt'
Assert-Hash (Join-Path $publicDir $receiptTrustName) $TrustReceiptSha256 'Published trust receipt'
[ordered]@{
    Status = 'READY4_ARTIFACT_SIGNED_COPY_VALID'; ProofGuid = $guid; PublicProofDirectory = $publicDir
    SignedArtifactSHA256 = $signedSha; ProofJsonSHA256 = $proofSha; ProofManifestSHA256 = $manifestSha
    UnsignedArtifactSHA256 = $unsignedSha
    SignToolExitCode = [int]$process.ExitCode; AuthenticodeStatus = $signature.Status.ToString()
    AuthenticodeSignerThumbprint = $signer
} | ConvertTo-Json -Compress
