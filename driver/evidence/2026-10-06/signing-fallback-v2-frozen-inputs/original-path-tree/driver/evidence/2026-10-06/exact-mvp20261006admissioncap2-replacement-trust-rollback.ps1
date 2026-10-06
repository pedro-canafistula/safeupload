# REVIEW ONLY: removes only the replacement public cert trust entries. Not executed.
# Hypervisor baseline restoration is a separate host action and still required.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Builder','Debuggee')][string] $Target,
    [Parameter(Mandatory)][switch] $RootApprovedForTrustRollback,
    [Parameter(Mandatory)][switch] $BaselineCheckpointVerified,
    [Parameter(Mandatory)][ValidatePattern('^[0-9A-Fa-f]{40}$')][string] $ExpectedThumbprint
)
$ErrorActionPreference = 'Stop'
$oldThumb = '220DD82C37FCF36048D59E4F10113185D81D5DC7'
$newThumb = $ExpectedThumbprint.ToUpperInvariant()
$subject = 'CN=SafeUpload Test Signing Recovery 20261006'
if (-not $RootApprovedForTrustRollback -or -not $BaselineCheckpointVerified) { throw 'Root approval and verified baseline checkpoint switches are required.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $product = Get-CimInstance Win32_ComputerSystemProduct
if ($Target -eq 'Builder') {
    if ($env:COMPUTERNAME -cne 'DESKTOP-O1LP5DG' -or $product.UUID -cne 'C6440689-D11C-4C63-A463-F3722B7DDB69' -or $identity.User.Value -cne 'S-1-5-21-316478115-1595729549-2803163825-1001') { throw 'Exact builder identity guard failed.' }
    $targetStores = @('Cert:\CurrentUser\Root')
    $allStores = @('Cert:\CurrentUser\My','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher','Cert:\LocalMachine\My','Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')
} else {
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($env:COMPUTERNAME -cne 'WIN10-DEBUGGED' -or $product.UUID -cne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D' -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Exact debuggee identity/admin guard failed.' }
    $targetStores = @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')
    $allStores = @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher','Cert:\LocalMachine\My','Cert:\CurrentUser\My','Cert:\CurrentUser\Root','Cert:\CurrentUser\TrustedPublisher')
}
function Get-TestSigningState {
    $raw = (& bcdedit.exe /enum '{current}' 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Could not read testsigning state.' }
    if ($raw -match '(?im)^\s*testsigning\s+Yes\s*$') { return 'Yes' }
    if ($raw -match '(?im)^\s*testsigning\s+No\s*$') { return 'No' }
    return 'NotPresent'
}
$testSigningBefore = Get-TestSigningState
if ($Target -eq 'Debuggee' -and $testSigningBefore -cne 'Yes') { throw 'Debuggee testsigning baseline is not Yes.' }
$testSigningBuilderOrGuestBefore = $testSigningBefore
$before = [ordered]@{}
foreach ($store in $allStores) { $before[$store] = @((Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | ForEach-Object { $_.Thumbprint.ToUpperInvariant() } | Sort-Object)) }
foreach ($store in $targetStores) {
    $newCerts = @(Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -ceq $newThumb -and $_.Subject -ceq $subject })
    if ($newCerts.Count -ne 1) { throw "Expected exactly one matching replacement cert in $store." }
}
if ($Target -eq 'Debuggee') {
    foreach ($store in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')) {
        if (@($before[$store] | Where-Object { $_ -ceq $oldThumb }).Count -ne 1) { throw "Original signer missing or duplicated in $store." }
    }
}
foreach ($store in $targetStores) {
    Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -ceq $newThumb -and $_.Subject -ceq $subject } | Remove-Item -Force
}
$after = [ordered]@{}
foreach ($store in $allStores) {
    $after[$store] = @((Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue | ForEach-Object { $_.Thumbprint.ToUpperInvariant() } | Sort-Object))
    $expectedThumbs = @($before[$store] | Where-Object { -not ($store -in $targetStores -and $_ -ceq $newThumb) } | Sort-Object)
    if (($after[$store] -join ',') -cne ($expectedThumbs -join ',')) { throw "Full certificate-store inventory did not return to the recorded baseline in $store." }
}
if ($Target -eq 'Debuggee') {
    foreach ($store in @('Cert:\LocalMachine\Root','Cert:\LocalMachine\TrustedPublisher')) { if (@($after[$store] | Where-Object { $_ -ceq $oldThumb }).Count -ne 1) { throw "Original signer changed during rollback in $store." } }
}
$testSigningAfter = Get-TestSigningState
if ($testSigningAfter -cne $testSigningBuilderOrGuestBefore) { throw 'testsigning state changed during trust rollback.' }
[ordered]@{Status='ReplacementTrustRemovedByExactThumb';UTC=[DateTime]::UtcNow.ToString('o');Target=$Target;ComputerName=$env:COMPUTERNAME;UUID=$product.UUID;User=$identity.Name;RemovedThumbprint=$newThumb;TargetStores=$targetStores;BeforeAllStoreThumbprints=$before;AfterAllStoreThumbprints=$after;TestSigningBefore=$testSigningBefore;TestSigningAfter=$testSigningAfter;PrivateKeyRemoved=$false;CheckpointRestorationStillRequired=$true}|ConvertTo-Json -Depth 8 -Compress
