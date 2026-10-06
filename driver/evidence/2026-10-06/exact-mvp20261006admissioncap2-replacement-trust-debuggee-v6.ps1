# REVIEW ONLY: V6 imports one exact public CER into the disposable debuggee's two
# code-signing trust stores. Not executed. Never touches test-signing/firmware.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch] $RootApprovedForDebuggeeTrust,
    [Parameter(Mandatory)][switch] $DebuggeeCheckpointVerified,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string] $ExpectedThumbprint,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{64}$')][string] $ExpectedCerSha256
)
$ErrorActionPreference = 'Stop'
$guardHelpersPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v6.ps1'
$guardHelpersExpectedSha256 = 'b149f6b59d992783565194a9c3826eb3dcdf236751ac5154f35128cc27bb7ef8'
if (-not (Test-Path -LiteralPath $guardHelpersPath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $guardHelpersPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $guardHelpersExpectedSha256) {
    throw 'Pinned V6 signing guard helper is missing or changed.'
}
. $guardHelpersPath
$expectedComputer = 'WIN10-DEBUGGED'; $expectedUuid = '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D'
$oldThumb = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$subject = 'CN=SafeUpload Test Signing Recovery 20261006 V6'
$cerPath = 'C:\safeupload-pkg\SafeUploadTest-Recovery-20261006-v6.cer'
if (-not $RootApprovedForDebuggeeTrust -or -not $DebuggeeCheckpointVerified) { throw 'Root approval and verified debuggee checkpoint switches are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $product = Get-CimInstance Win32_ComputerSystemProduct
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid) { throw 'Exact debuggee identity guard failed.' }
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated administrator token required for machine trust-store changes.' }
if ((Get-FileHash -LiteralPath $cerPath -Algorithm SHA256).Hash -cne $ExpectedCerSha256.ToUpperInvariant()) { throw 'Public CER SHA-256 guard failed.' }
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($cerPath)
if ($cert.Thumbprint -cne $ExpectedThumbprint.ToUpperInvariant() -or $cert.Subject -cne $subject) { throw 'Public CER identity guard failed.' }
$eku = @(Get-SafeUploadCodeSigningEkuOids -Extensions @($cert.Extensions) -Context 'Debuggee public CER')
$bcd = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $bcd -notmatch '(?im)^\s*testsigning\s+Yes\s*$') { throw 'Debuggee testsigning baseline is not Yes; no trust change attempted.' }
$signingBefore = 'Yes'
$stores = @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher','Cert:\LocalMachine\My','Cert:\CurrentUser\My','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher')
function Get-TargetInventory {
    $snapshot = [ordered]@{}
    foreach ($store in $stores) {
        $certificates = @(Get-ChildItem -LiteralPath $store -ErrorAction Stop)
        $snapshot[$store] = @($certificates | ForEach-Object { $_.Thumbprint.ToUpperInvariant() } | Sort-Object)
    }
    return $snapshot
}
$before = Get-TargetInventory
foreach ($store in $stores) { if (@($before[$store] | Where-Object { $_ -ceq $cert.Thumbprint }).Count -ne 0) { throw "New thumbprint already exists in $store." } }
foreach ($store in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')) { if (@($before[$store] | Where-Object { $_ -ceq $oldThumb }).Count -ne 1) { throw "Original signer baseline missing or duplicated in $store." } }
try {
    Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Import-Certificate -FilePath $cerPath -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
    $after = Get-TargetInventory
    foreach ($store in $stores) {
        $expectedThumbs = @($before[$store])
        if ($store -in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher')) { $expectedThumbs = @($expectedThumbs + $cert.Thumbprint | Sort-Object) }
        if (($after[$store] -join ',') -cne ($expectedThumbs -join ',')) { throw "Full certificate-store inventory changed unexpectedly in $store." }
    }
    foreach ($store in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')) { if (@($after[$store] | Where-Object { $_ -ceq $oldThumb }).Count -ne 1) { throw "Original signer changed in $store." } }
    $bcdAfter = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $bcdAfter -notmatch '(?im)^\s*testsigning\s+Yes\s*$') { throw 'testsigning changed during trust operation.' }
    [ordered]@{Status='ExactDebuggeeTrustAdded';UTC=[DateTime]::UtcNow.ToString('o');ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;User=$identity.Name;NewThumbprint=$cert.Thumbprint;OldThumbprintRetained=$oldThumb;Subject=$cert.Subject;CerSha256=$ExpectedCerSha256.ToUpperInvariant();BeforeAllStoreThumbprints=$before;AfterAllStoreThumbprints=$after;TestSigningBefore=$signingBefore;TestSigningAfter='Yes';OnlyNewThumbAddedToLocalMachineRootAndTrustedPublisher=$true;Rebooted=$false}|ConvertTo-Json -Depth 8 -Compress
} catch {
    foreach ($store in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')) {
        Get-ChildItem -LiteralPath $store -ErrorAction Stop | Where-Object { $_.Thumbprint -ceq $cert.Thumbprint } | Remove-Item -Force
    }
    throw 'Trust verification failed; the exact new thumb was removed from both target stores. Restore checkpoint and re-inventory before retry.'
}
