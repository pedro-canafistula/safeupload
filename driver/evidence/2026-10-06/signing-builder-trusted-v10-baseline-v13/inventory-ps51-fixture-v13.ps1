[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $BaselinePath,
    [Parameter(Mandatory)][string] $MetadataPath,
    [Parameter(Mandatory)][string] $TrustReceiptPath,
    [Parameter(Mandatory)][string] $PostSignJsonlPath,
    [Parameter(Mandatory)][string] $ExpectedBaselineSha256
)
$ErrorActionPreference = 'Stop'

function Assert-FixtureSha256([string] $Path, [string] $Expected, [string] $Name) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ("Fixture input missing: {0}" -f $Name) }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($actual -notmatch '\A[0-9A-Fa-f]{64}\z' -or
        -not [string]::Equals($actual, $Expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw ("Fixture input hash mismatch: {0}." -f $Name)
    }
}
function Assert-FixtureExpectedFailure([scriptblock] $Action, [string] $MessagePattern, [string] $Name) {
    $caughtExpected = $false
    try { $null = & $Action }
    catch {
        $message = [string]$_.Exception.Message
        if ($message -notmatch $MessagePattern) { throw ("{0} failed with an unexpected diagnostic: {1}" -f $Name, $message) }
        $caughtExpected = $true
    }
    if (-not $caughtExpected) { throw ("{0} unexpectedly succeeded; rejection was required." -f $Name) }
}

Assert-FixtureSha256 $BaselinePath $ExpectedBaselineSha256 'V13 baseline source'
Assert-FixtureSha256 $MetadataPath '51701037af41fcc19101e26dd2d632934d20b94190d42782474f68f05abdfc1e' 'V8 public mint metadata'
Assert-FixtureSha256 $TrustReceiptPath 'ac22de20b6845a524de4fbb157514171eef02ef5678384c5c36225aea8306daa' 'V10 builder trust receipt'
Assert-FixtureSha256 $PostSignJsonlPath 'abbd29d85a527798722bf7c48432fff6165825651bf5510a32dc9e34b26a0282' 'V10 post-sign JSONL'

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($BaselinePath, [ref]$tokens, [ref]$parseErrors)
if ($null -ne $parseErrors -and $parseErrors.Count -ne 0) { throw 'V13 baseline source has PowerShell parser errors.' }
$requiredFunctions = @(
    'Get-InventoryStoreKeys', 'Get-InventoryStoreValue', 'Test-OrdinalStringContains',
    'Assert-ExactInventoryKeys', 'Assert-StoreInventorySchema', 'Get-Thumbs',
    'Assert-InventoryEqual', 'Convert-PostSignStoreInventory'
)
$functionNodes = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
foreach ($functionName in $requiredFunctions) {
    $found = @($functionNodes | Where-Object { [string]::Equals([string]$_.Name, $functionName, [StringComparison]::Ordinal) })
    if ($found.Count -ne 1) { throw ("Expected exactly one AST function definition for {0}." -f $functionName) }
    . ([scriptblock]::Create($found[0].Extent.Text))
}

$storePaths = @(
    'Cert:\CurrentUser\My', 'Cert:\CurrentUser\Root', 'Cert:\CurrentUser\TrustedPublisher',
    'Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher'
)
$metadata = Get-Content -LiteralPath $MetadataPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$trust = Get-Content -LiteralPath $TrustReceiptPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
$lines = @(Get-Content -LiteralPath $PostSignJsonlPath -Encoding UTF8 -ErrorAction Stop)
if ($lines.Count -ne 2) { throw 'Pinned post-sign JSONL must contain exactly two records.' }
$postSignRecord = $lines[0] | ConvertFrom-Json -ErrorAction Stop

Assert-StoreInventorySchema $metadata.PostMintAllStoreThumbprints 'Fixture mint inventory' $storePaths
Assert-StoreInventorySchema $trust.BeforeAllStoreThumbprints 'Fixture trust-before inventory' $storePaths
Assert-StoreInventorySchema $trust.AfterAllStoreThumbprints 'Fixture trust-after inventory' $storePaths
Assert-InventoryEqual $metadata.PostMintAllStoreThumbprints $trust.BeforeAllStoreThumbprints 'Fixture mint vs trust-before PSCustomObject comparison'

$postSignShortKeys = @('CurrentUser\My','CurrentUser\Root','CurrentUser\TrustedPublisher',
    'LocalMachine\My','LocalMachine\Root','LocalMachine\TrustedPublisher')
$normalizedPostSign = Convert-PostSignStoreInventory $postSignRecord.Stores 'Fixture pinned post-sign stores'
if ($normalizedPostSign -isnot [System.Collections.IDictionary]) { throw 'Normalized post-sign inventory is not a dictionary.' }
Assert-StoreInventorySchema $normalizedPostSign 'Fixture normalized post-sign inventory' $storePaths
Assert-InventoryEqual $normalizedPostSign $trust.AfterAllStoreThumbprints 'Fixture post-sign vs trust-after comparison'

# Reproduce the live return type from Get-StoreInventory without querying a certificate store.
$liveInventory = [ordered]@{}
foreach ($store in $storePaths) {
    $liveInventory[$store] = Get-InventoryStoreValue $trust.AfterAllStoreThumbprints $store
}
if ($liveInventory.GetType().FullName -cne 'System.Collections.Specialized.OrderedDictionary') {
    throw 'Fixture live-shaped inventory is not the expected OrderedDictionary type.'
}
Assert-StoreInventorySchema $liveInventory 'Fixture live OrderedDictionary inventory' $storePaths
Assert-InventoryEqual $liveInventory $trust.AfterAllStoreThumbprints 'Fixture live OrderedDictionary vs trust-after comparison'
Assert-InventoryEqual $trust.AfterAllStoreThumbprints $liveInventory 'Fixture reverse OrderedDictionary comparison'

$missingStore = [ordered]@{}
foreach ($store in $storePaths) {
    if (-not [string]::Equals($store, $storePaths[0], [StringComparison]::Ordinal)) {
        $missingStore[$store] = Get-InventoryStoreValue $liveInventory $store
    }
}
Assert-FixtureExpectedFailure {
    Assert-StoreInventorySchema $missingStore 'Fixture missing-store rejection' $storePaths
} 'exact-key schema mismatch' 'Missing-key schema rejection'

$extraStore = [ordered]@{}
foreach ($store in $storePaths) { $extraStore[$store] = Get-InventoryStoreValue $liveInventory $store }
$extraStore['Cert:\Fixture\Unexpected'] = @()
Assert-FixtureExpectedFailure {
    Assert-StoreInventorySchema $extraStore 'Fixture extra-store rejection' $storePaths
} 'exact-key schema mismatch' 'Extra-key schema rejection'

$caseMismatch = [ordered]@{}
$caseMismatch['cert:\CurrentUser\My'] = Get-InventoryStoreValue $liveInventory $storePaths[0]
foreach ($store in $storePaths | Select-Object -Skip 1) {
    $caseMismatch[$store] = Get-InventoryStoreValue $liveInventory $store
}
Assert-FixtureExpectedFailure {
    Assert-StoreInventorySchema $caseMismatch 'Fixture ordinal-key rejection' $storePaths
} 'exact-key schema mismatch' 'Case-sensitive exact-key rejection'

$wrongPostSignKeys = [ordered]@{}
$wrongPostSignKeys['Cert:\CurrentUser\My'] = Get-InventoryStoreValue $postSignRecord.Stores 'CurrentUser\My'
foreach ($key in $postSignShortKeys | Select-Object -Skip 1) {
    $wrongPostSignKeys[$key] = Get-InventoryStoreValue $postSignRecord.Stores $key
}
Assert-FixtureExpectedFailure {
    Convert-PostSignStoreInventory $wrongPostSignKeys 'Fixture wrong-prefix post-sign rejection'
} 'exact-key schema mismatch' 'Post-sign exact source-key rejection'

$changedInventory = [ordered]@{}
foreach ($store in $storePaths) { $changedInventory[$store] = Get-InventoryStoreValue $liveInventory $store }
$changedInventory[$storePaths[0]] = @('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
Assert-FixtureExpectedFailure {
    Assert-InventoryEqual $changedInventory $trust.AfterAllStoreThumbprints 'Fixture changed-thumbprint rejection'
} 'inventory mismatch at' 'Changed-thumbprint comparison rejection'

$scalarInventory = [ordered]@{}
foreach ($store in $storePaths) { $scalarInventory[$store] = Get-InventoryStoreValue $liveInventory $store }
$scalarInventory[$storePaths[0]] = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
Assert-FixtureExpectedFailure {
    Assert-StoreInventorySchema $scalarInventory 'Fixture scalar-value rejection' $storePaths
} 'must be an array' 'Scalar-store-value rejection'

Write-Output 'V13_INVENTORY_ADAPTER_FIXTURE_PASS'
