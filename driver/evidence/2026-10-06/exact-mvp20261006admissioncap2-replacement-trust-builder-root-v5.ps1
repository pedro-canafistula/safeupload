# REVIEW ONLY: V5 adds the exact new public certificate to vika CurrentUser Root.
# Required because Build-ExactSource.ps1 gates on Authenticode Status=Valid.
# Not executed. Never adds TrustedPublisher or changes machine trust.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch] $RootApprovedForBuilderTrust,
    [Parameter(Mandatory)][switch] $KeyBearingCheckpointVerified,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string] $ExpectedThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCerSha256
)
$ErrorActionPreference = 'Stop'
$guardHelpersPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v5.ps1'
$guardHelpersExpectedSha256 = 'c833ebca338f366fb41fbb274b4a0dcab6cd47f4e7863f61774a5fb83e22f03e'
if (-not (Test-Path -LiteralPath $guardHelpersPath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $guardHelpersPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $guardHelpersExpectedSha256) {
    throw 'Pinned V5 signing guard helper is missing or changed.'
}
. $guardHelpersPath
$expectedComputer = 'DESKTOP-O1LP5DG'; $expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'; $expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$subject = 'CN=SafeUpload Test Signing Recovery 20261006'
$cerPath = 'C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v5.cer'
if (-not $RootApprovedForBuilderTrust -or -not $KeyBearingCheckpointVerified) { throw 'Root approval and verified key-bearing builder checkpoint switches are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $product = Get-CimInstance Win32_ComputerSystemProduct
if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid -or $identity.User.Value -cne $expectedSid) { throw 'Exact builder identity guard failed.' }
if ((Get-FileHash -LiteralPath $cerPath -Algorithm SHA256).Hash -cne $ExpectedCerSha256.ToUpperInvariant()) { throw 'Public CER SHA-256 guard failed.' }
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)
if ($cert.Thumbprint -cne $ExpectedThumbprint.ToUpperInvariant() -or $cert.Subject -cne $subject) { throw 'Public CER identity guard failed.' }
$machineCert = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $cert.Thumbprint) -ErrorAction Stop
if (-not $machineCert.HasPrivateKey -or $machineCert.Subject -cne $subject) { throw 'Matching LocalMachine private certificate is missing.' }
$eku = @(Get-SafeUploadCodeSigningEkuOids -Extensions @($cert.Extensions) -Context 'Builder public CER')
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
$before = Get-StoreInventory
foreach ($store in $stores) { if (@($before[$store] | Where-Object { $_ -ceq $newThumb }).Count -ne 0) { throw "New thumbprint already present in $store." } }
try {
    Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
    $after = Get-StoreInventory
    foreach ($store in $stores) {
        $expectedThumbs = @($before[$store])
        if ($store -ceq 'Cert:\CurrentUser\Root') { $expectedThumbs = @($expectedThumbs + $newThumb | Sort-Object) }
        if (($after[$store] -join ',') -cne ($expectedThumbs -join ',')) { throw "Builder trust inventory changed unexpectedly in $store." }
    }
    [ordered]@{Status='ExactBuilderRootAdded';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;User=$identity.Name;Thumbprint=$newThumb;Subject=$cert.Subject;CerSha256=$ExpectedCerSha256.ToUpperInvariant();Store='CurrentUser\Root';BeforeAllStoreThumbprints=$before;AfterAllStoreThumbprints=$after;OnlyApprovedCurrentUserRootDelta=$true;TrustedPublisherChanged=$false;LocalMachineTrustChanged=$false}|ConvertTo-Json -Depth 8 -Compress
} catch {
    Get-ChildItem -LiteralPath 'Cert:\CurrentUser\Root' -ErrorAction Stop | Where-Object { $_.Thumbprint -ceq $newThumb } | Remove-Item -Force
    throw 'Builder-root verification failed; the exact new thumb was removed from CurrentUser Root. Restore checkpoint and re-inventory before retry.'
}
