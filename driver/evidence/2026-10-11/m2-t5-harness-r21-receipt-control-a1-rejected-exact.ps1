#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$ExpectedModuleSha256 = 'f9dba8569c7bf2fafef648c5b6d49211ee299b6adc4651733dfb5acbbd6f251a'
$ExpectedModuleLength = 102549
$ModulePath = Join-Path $PSScriptRoot 'HarnessWindowsGateProtocol.psm1'
$ControlPath = $PSCommandPath
$ModuleSha256Before = $null
$ModuleSha256After = $null
$ControlSha256Before = $null
$ControlSha256After = $null
$FixtureRoot = $null
$FixtureCreated = $false
$FixtureRemoved = $false
$FixtureMarkerPath = $null
$FixtureMarkerBytes = $null
$OwnedFixtureFiles = New-Object 'System.Collections.Generic.List[string]'
$PassedChecks = New-Object 'System.Collections.Generic.List[string]'
$ProcessId = [uint32]$PID
$ProcessStartFiletime = [long]0
$FailureMessage = $null

function Get-R21Sha256Hex([byte[]]$Bytes) {
    if ($null -eq $Bytes) { throw 'Cannot hash a null byte array.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Test-R21ByteArraysEqual([byte[]]$Left, [byte[]]$Right) {
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
    for ($i = 0; $i -lt $Left.Length; $i++) {
        if ($Left[$i] -ne $Right[$i]) { return $false }
    }
    return $true
}

function Assert-R21([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-R21FixtureEntries([string]$Root, [string[]]$ExpectedPaths) {
    $actualPaths = @([IO.Directory]::GetFileSystemEntries($Root))
    Assert-R21 ($actualPaths.Count -eq $ExpectedPaths.Count) 'Fixture contains an unexpected entry count; preserve the fixture for review.'
    foreach ($actualPath in $actualPaths) {
        $actualFull = [IO.Path]::GetFullPath($actualPath)
        $matched = $false
        foreach ($expectedPath in $ExpectedPaths) {
            if ([string]::Equals($actualFull, [IO.Path]::GetFullPath($expectedPath), [StringComparison]::OrdinalIgnoreCase)) {
                $matched = $true
                break
            }
        }
        Assert-R21 $matched 'Fixture contains an unowned entry; preserve the fixture for review.'
        $attributes = [IO.File]::GetAttributes($actualFull)
        Assert-R21 (($attributes -band [IO.FileAttributes]::Directory) -eq 0) 'Fixture contains an unexpected directory; preserve the fixture for review.'
        Assert-R21 (($attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Fixture contains a reparse point; preserve the fixture for review.'
    }
}

function Get-R21ModuleFunctionAst($ModuleAst, [string]$FunctionName) {
    $allFunctions = @($ModuleAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    $functionMatches = @($allFunctions | Where-Object { $_.Name -ceq $FunctionName })
    Assert-R21 ($functionMatches.Count -eq 1) ('Expected exactly one AST definition for ' + $FunctionName + '.')
    $topLevel = @($ModuleAst.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -ceq $FunctionName
    })
    Assert-R21 ($topLevel.Count -eq 1) ('Expected the reviewed definition to be top-level: ' + $FunctionName + '.')
    $nested = @($functionMatches[0].Body.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    Assert-R21 ($nested.Count -eq 0) ('Nested function definitions are outside the extraction allowlist: ' + $FunctionName + '.')
    return $functionMatches[0]
}

function New-R21ReviewedFunctionBlock($Definition, [string]$ExpectedName) {
    $fragment = [string]$Definition.Extent.Text
    $fragmentTokens = $null
    $fragmentErrors = $null
    $fragmentAst = [System.Management.Automation.Language.Parser]::ParseInput($fragment, [ref]$fragmentTokens, [ref]$fragmentErrors)
    Assert-R21 (@($fragmentErrors).Count -eq 0) ('Extracted function does not parse: ' + $ExpectedName + '.')
    $statements = @($fragmentAst.EndBlock.Statements)
    Assert-R21 ($statements.Count -eq 1) ('Extracted text contains content beyond one function: ' + $ExpectedName + '.')
    Assert-R21 ($statements[0] -is [System.Management.Automation.Language.FunctionDefinitionAst]) ('Extracted text is not one function: ' + $ExpectedName + '.')
    Assert-R21 ($statements[0].Name -ceq $ExpectedName) ('Extracted function name changed: ' + $ExpectedName + '.')
    return [ScriptBlock]::Create($fragment)
}

try {
    Assert-R21 ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'This control requires Windows PowerShell 5.1.'
    Assert-R21 ($PSVersionTable.PSEdition -ceq 'Desktop') 'This control requires the Desktop PowerShell edition.'
    Assert-R21 ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) 'This control requires Windows.'
    Assert-R21 ([Environment]::Is64BitProcess) 'This control requires a 64-bit PowerShell process.'

    $currentProcess = [Diagnostics.Process]::GetCurrentProcess()
    try {
        Assert-R21 ($currentProcess.Id -eq $PID) 'PowerShell process identity could not be pinned.'
        $ProcessStartFiletime = [long]$currentProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
    } finally {
        $currentProcess.Dispose()
    }
    Assert-R21 ($ProcessStartFiletime -gt 0) 'PowerShell process start FILETIME is invalid.'

    $controlItem = Get-Item -LiteralPath $ControlPath -ErrorAction Stop
    Assert-R21 (-not $controlItem.PSIsContainer) 'Control input is not a plain file.'
    Assert-R21 (($controlItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Control input is a reparse point.'
    $ControlSha256Before = Get-R21Sha256Hex ([IO.File]::ReadAllBytes($ControlPath))

    $moduleItem = Get-Item -LiteralPath $ModulePath -ErrorAction Stop
    Assert-R21 (-not $moduleItem.PSIsContainer) 'Pinned module input is not a plain file.'
    Assert-R21 (($moduleItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Pinned module input is a reparse point.'
    $moduleBytes = [IO.File]::ReadAllBytes($ModulePath)
    Assert-R21 ($moduleBytes.Length -eq $ExpectedModuleLength) 'Pinned module length does not match the frozen source.'
    $ModuleSha256Before = Get-R21Sha256Hex $moduleBytes
    Assert-R21 ($ModuleSha256Before -ceq $ExpectedModuleSha256) 'Pinned module hash does not match the frozen R21 source.'

    $utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)
    $textOffset = 0
    if ($moduleBytes.Length -ge 3 -and $moduleBytes[0] -eq 239 -and $moduleBytes[1] -eq 187 -and $moduleBytes[2] -eq 191) { $textOffset = 3 }
    $moduleText = $utf8Strict.GetString($moduleBytes, $textOffset, $moduleBytes.Length - $textOffset)
    $moduleTokens = $null
    $moduleParseErrors = $null
    $moduleAst = [System.Management.Automation.Language.Parser]::ParseInput($moduleText, [ref]$moduleTokens, [ref]$moduleParseErrors)
    Assert-R21 (@($moduleParseErrors).Count -eq 0) 'Pinned module data did not parse cleanly.'

    $allowedFunctions = @(
        'Get-HarnessGateJobName',
        'Get-HarnessGateKeeperJobName',
        'Get-HarnessGateKeeperReadyPath',
        'Write-HarnessGateKeeperReadyReceipt'
    )
    foreach ($functionName in $allowedFunctions) {
        $definition = Get-R21ModuleFunctionAst $moduleAst $functionName
        $extractedBlock = New-R21ReviewedFunctionBlock $definition $functionName
        . $extractedBlock
    }
    $PassedChecks.Add('Pinned module parsed as data; only the four exact allowlisted function ASTs were defined.')

    $script:FixtureRoot = $null
    function Get-HarnessGateStateRoot {
        if ([string]::IsNullOrWhiteSpace([string]$script:FixtureRoot)) { throw 'Fixture state-root adapter is not initialized.' }
        return [string]$script:FixtureRoot
    }

    $tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $tempParentInfo = Get-Item -LiteralPath $tempParent -ErrorAction Stop
    Assert-R21 ($tempParentInfo.PSIsContainer) 'TEMP is not a directory.'
    Assert-R21 (($tempParentInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'TEMP is a reparse point.'
    $fixtureLeaf = 'SafeUpload-HarnessGate-ReceiptControl-' + [guid]::NewGuid().ToString('N')
    $FixtureRoot = Join-Path $tempParent $fixtureLeaf
    Assert-R21 (-not [IO.Directory]::Exists($FixtureRoot) -and -not [IO.File]::Exists($FixtureRoot)) 'Fresh fixture path unexpectedly exists.'
    $null = [IO.Directory]::CreateDirectory($FixtureRoot)
    $FixtureCreated = $true
    $script:FixtureRoot = [IO.Path]::GetFullPath($FixtureRoot)
    $fixtureItem = Get-Item -LiteralPath $FixtureRoot -ErrorAction Stop
    Assert-R21 ($fixtureItem.PSIsContainer) 'Created fixture is not a directory.'
    Assert-R21 (($fixtureItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Created fixture is a reparse point.'

    $FixtureMarkerPath = Join-Path $FixtureRoot 'control-owner.marker'
    $FixtureMarkerBytes = $utf8Strict.GetBytes('safeupload-r21-receipt-writer-control-v1:' + [guid]::NewGuid().ToString('D'))
    $markerStream = New-Object IO.FileStream($FixtureMarkerPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $markerStream.Write($FixtureMarkerBytes, 0, $FixtureMarkerBytes.Length)
        $markerStream.Flush($true)
    } finally {
        $markerStream.Dispose()
    }
    $OwnedFixtureFiles.Add($FixtureMarkerPath)
    Assert-R21FixtureEntries $FixtureRoot $OwnedFixtureFiles.ToArray()

    $runToken = [guid]::NewGuid().ToString('D')
    $keeperPid = [uint32]$ProcessId
    $keeperStartFiletime = [long]$ProcessStartFiletime
    $mainJobName = Get-HarnessGateJobName $runToken
    $keeperJobName = Get-HarnessGateKeeperJobName $runToken
    $readyPath = Get-HarnessGateKeeperReadyPath $runToken
    $expectedReadyPath = [IO.Path]::GetFullPath((Join-Path $FixtureRoot ($runToken + '.keeper-ready.json')))
    Assert-R21 ([string]::Equals([IO.Path]::GetFullPath($readyPath), $expectedReadyPath, [StringComparison]::OrdinalIgnoreCase)) 'Fixture adapter did not confine the writer path to the fresh TEMP directory.'
    Assert-R21 ([string]::Equals([IO.Path]::GetDirectoryName($readyPath), $FixtureRoot, [StringComparison]::OrdinalIgnoreCase)) 'Writer target parent escaped the fixture directory.'
    $PassedChecks.Add('Fixture adapter maps the receipt target exclusively into the fresh TEMP directory.')

    $emptyBefore = @([IO.Directory]::GetFileSystemEntries($FixtureRoot))
    $badTupleMessage = $null
    try {
        $null = Write-HarnessGateKeeperReadyReceipt $runToken $keeperPid $keeperStartFiletime ($mainJobName + '.wrong') $keeperJobName $readyPath
    } catch {
        $badTupleMessage = [string]$_.Exception.Message
    }
    Assert-R21 ($badTupleMessage -ceq 'Keeper readiness receipt identity is incomplete or not bound to the deterministic run objects.') 'Wrong main-job tuple did not fail at the exact identity guard.'
    Assert-R21 ((@([IO.Directory]::GetFileSystemEntries($FixtureRoot))).Count -eq $emptyBefore.Count) 'Wrong main-job tuple changed fixture contents.'
    Assert-R21FixtureEntries $FixtureRoot $OwnedFixtureFiles.ToArray()
    $PassedChecks.Add('Wrong tuple rejected before any receipt or staging write.')

    $badPathMessage = $null
    $wrongPath = Join-Path $FixtureRoot ($runToken + '.wrong-ready.json')
    try {
        $null = Write-HarnessGateKeeperReadyReceipt $runToken $keeperPid $keeperStartFiletime $mainJobName $keeperJobName $wrongPath
    } catch {
        $badPathMessage = [string]$_.Exception.Message
    }
    Assert-R21 ($badPathMessage -ceq 'Keeper readiness receipt identity is incomplete or not bound to the deterministic run objects.') 'Wrong path did not fail at the exact identity guard.'
    Assert-R21 ((@([IO.Directory]::GetFileSystemEntries($FixtureRoot))).Count -eq $emptyBefore.Count) 'Wrong target path changed fixture contents.'
    Assert-R21FixtureEntries $FixtureRoot $OwnedFixtureFiles.ToArray()
    $PassedChecks.Add('Noncanonical target path rejected before any receipt or staging write.')

    $collisionBytes = $utf8Strict.GetBytes('preexisting-r21-receipt-collision-sentinel')
    $collisionStream = New-Object IO.FileStream($readyPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $collisionStream.Write($collisionBytes, 0, $collisionBytes.Length)
        $collisionStream.Flush($true)
    } finally {
        $collisionStream.Dispose()
    }
    $OwnedFixtureFiles.Add($readyPath)
    Assert-R21FixtureEntries $FixtureRoot $OwnedFixtureFiles.ToArray()
    $collisionException = $null
    try {
        $null = Write-HarnessGateKeeperReadyReceipt $runToken $keeperPid $keeperStartFiletime $mainJobName $keeperJobName $readyPath
    } catch {
        $collisionException = $_.Exception.GetBaseException()
    }
    Assert-R21 ($null -ne $collisionException) 'Writer unexpectedly replaced the existing final target.'
    Assert-R21 ($collisionException -is [IO.IOException]) 'Existing-target failure was not an IOException from the no-overwrite publish.'
    $collisionAfterBytes = [IO.File]::ReadAllBytes($readyPath)
    Assert-R21 (Test-R21ByteArraysEqual $collisionBytes $collisionAfterBytes) 'Existing final target bytes changed after a rejected publish.'
    Assert-R21FixtureEntries $FixtureRoot $OwnedFixtureFiles.ToArray()
    $PassedChecks.Add('Final-target collision fails closed, preserves exact preexisting bytes, and leaves no staging artifact.')
    [IO.File]::Delete($readyPath)
    $null = $OwnedFixtureFiles.Remove($readyPath)
    Assert-R21FixtureEntries $FixtureRoot $OwnedFixtureFiles.ToArray()

    $writerHash = Write-HarnessGateKeeperReadyReceipt $runToken $keeperPid $keeperStartFiletime $mainJobName $keeperJobName $readyPath
    Assert-R21 ($writerHash -is [string] -and $writerHash.Length -eq 64 -and $writerHash -cmatch '^[0-9a-f]{64}$') 'Writer did not return exactly one lowercase SHA-256 string.'
    $OwnedFixtureFiles.Add($readyPath)
    $actualBytes = [IO.File]::ReadAllBytes($readyPath)

    $keeperPidText = $keeperPid.ToString([Globalization.CultureInfo]::InvariantCulture)
    $keeperStartText = $keeperStartFiletime.ToString([Globalization.CultureInfo]::InvariantCulture)
    $mainJobJson = $mainJobName.Replace('\', '\\')
    $keeperJobJson = $keeperJobName.Replace('\', '\\')
    $expectedText = '{"schema":"safeupload-harness-gate-keeper-ready-v1","runToken":"' + $runToken + '","keeperPid":' + $keeperPidText + ',"keeperStartFiletime":' + $keeperStartText + ',"mainJobName":"' + $mainJobJson + '","keeperJobName":"' + $keeperJobJson + '","mainJobQuery":"EXACT_HANDLE_QUERY_SUCCEEDED","keeperJobMembership":"CURRENT_PROCESS_MEMBER"}'
    $expectedBytes = $utf8Strict.GetBytes($expectedText)
    Assert-R21 (Test-R21ByteArraysEqual $actualBytes $expectedBytes) 'Successful receipt bytes differ from the exact closed UTF-8 schema and tuple.'
    $actualHash = Get-R21Sha256Hex $actualBytes
    $expectedHash = Get-R21Sha256Hex $expectedBytes
    Assert-R21 ($writerHash -ceq $actualHash -and $actualHash -ceq $expectedHash) 'Returned, on-disk, and expected receipt hashes are not identical.'
    $receiptObject = ConvertFrom-Json -InputObject ([string]$utf8Strict.GetString($actualBytes)) -ErrorAction Stop
    $expectedPropertyNames = @('schema', 'runToken', 'keeperPid', 'keeperStartFiletime', 'mainJobName', 'keeperJobName', 'mainJobQuery', 'keeperJobMembership')
    $actualPropertyNames = @($receiptObject.PSObject.Properties | ForEach-Object { $_.Name })
    Assert-R21 ($actualPropertyNames.Count -eq $expectedPropertyNames.Count) 'Receipt property set is not closed.'
    for ($i = 0; $i -lt $expectedPropertyNames.Count; $i++) {
        Assert-R21 ($actualPropertyNames[$i] -ceq $expectedPropertyNames[$i]) 'Receipt property order or name changed.'
    }
    Assert-R21 ($receiptObject.schema -ceq 'safeupload-harness-gate-keeper-ready-v1') 'Receipt schema value changed.'
    Assert-R21 ($receiptObject.runToken -ceq $runToken) 'Receipt run token changed.'
    Assert-R21 ([long]$receiptObject.keeperPid -eq [long]$keeperPid) 'Receipt keeper PID changed.'
    Assert-R21 ([long]$receiptObject.keeperStartFiletime -eq $keeperStartFiletime) 'Receipt keeper FILETIME changed.'
    Assert-R21 ($receiptObject.mainJobName -ceq $mainJobName) 'Receipt main-job identity changed.'
    Assert-R21 ($receiptObject.keeperJobName -ceq $keeperJobName) 'Receipt keeper-job identity changed.'
    Assert-R21 ($receiptObject.mainJobQuery -ceq 'EXACT_HANDLE_QUERY_SUCCEEDED') 'Receipt exact-handle query field changed.'
    Assert-R21 ($receiptObject.keeperJobMembership -ceq 'CURRENT_PROCESS_MEMBER') 'Receipt keeper membership field changed.'
    Assert-R21FixtureEntries $FixtureRoot $OwnedFixtureFiles.ToArray()
    $PassedChecks.Add('Successful writer returned the exact closed receipt bytes and matching SHA-256.')

    $moduleBytesAtEnd = [IO.File]::ReadAllBytes($ModulePath)
    $ModuleSha256After = Get-R21Sha256Hex $moduleBytesAtEnd
    Assert-R21 ($moduleBytesAtEnd.Length -eq $ExpectedModuleLength -and $ModuleSha256After -ceq $ExpectedModuleSha256 -and $ModuleSha256After -ceq $ModuleSha256Before) 'Pinned module changed during the control.'
    $ControlSha256After = Get-R21Sha256Hex ([IO.File]::ReadAllBytes($ControlPath))
    Assert-R21 ($ControlSha256After -ceq $ControlSha256Before) 'Control script changed during the control.'

    Assert-R21FixtureEntries $FixtureRoot $OwnedFixtureFiles.ToArray()
    $markerAttributes = [IO.File]::GetAttributes($FixtureMarkerPath)
    Assert-R21 (($markerAttributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'Ownership marker became a reparse point.'
    Assert-R21 (Test-R21ByteArraysEqual $FixtureMarkerBytes ([IO.File]::ReadAllBytes($FixtureMarkerPath))) 'Ownership marker changed; preserve the fixture.'
    foreach ($ownedPath in $OwnedFixtureFiles.ToArray()) {
        [IO.File]::Delete($ownedPath)
        $null = $OwnedFixtureFiles.Remove($ownedPath)
    }
    Assert-R21 ((@([IO.Directory]::GetFileSystemEntries($FixtureRoot))).Count -eq 0) 'Fixture contains entries after owned-file cleanup; preserve it.'
    [IO.Directory]::Delete($FixtureRoot, $false)
    $FixtureRemoved = $true
    $FixtureCreated = $false

    $ModuleSha256After = Get-R21Sha256Hex ([IO.File]::ReadAllBytes($ModulePath))
    $ControlSha256After = Get-R21Sha256Hex ([IO.File]::ReadAllBytes($ControlPath))
    Assert-R21 ($ModuleSha256After -ceq $ExpectedModuleSha256 -and $ModuleSha256After -ceq $ModuleSha256Before) 'Pinned module changed before final reporting.'
    Assert-R21 ($ControlSha256After -ceq $ControlSha256Before) 'Control script changed before final reporting.'

    $result = [ordered]@{
        schema = 'safeupload-harness-gate-r21-receipt-writer-control-v1'
        status = 'PASS'
        process = [ordered]@{ pid = $ProcessId; startFiletime = $ProcessStartFiletime }
        module = [ordered]@{ path = $ModulePath; sha256Before = $ModuleSha256Before; sha256After = $ModuleSha256After; length = $ExpectedModuleLength }
        control = [ordered]@{ path = $ControlPath; sha256Before = $ControlSha256Before; sha256After = $ControlSha256After }
        fixture = [ordered]@{ path = $FixtureRoot; createdFresh = $true; removedAfterOwnedCleanup = $FixtureRemoved }
        receipt = [ordered]@{ runToken = $runToken; keeperPid = $keeperPid; keeperStartFiletime = $keeperStartFiletime; sha256 = $actualHash; exactClosedBytes = $true }
        checks = $PassedChecks.ToArray()
        boundaries = @('Standalone receipt-writer control only; no full-module import or coordinator/harness execution.', 'No Windows run has occurred yet; this script is a prepared plan for independent review.', 'The synchronous source-writer check does not observe the temporary file during an in-progress partial write.')
    }
    [Console]::Out.WriteLine('R21_RECEIPT_WRITER_CONTROL_PASS ' + (ConvertTo-Json -InputObject $result -Depth 8 -Compress))
} catch {
    $FailureMessage = [string]$_.Exception.Message
    if ([string]::IsNullOrEmpty($FailureMessage)) { $FailureMessage = 'Unspecified control failure.' }
    $fixtureRetained = $false
    if (-not [string]::IsNullOrEmpty([string]$FixtureRoot)) { $fixtureRetained = [IO.Directory]::Exists($FixtureRoot) }
    $failureResult = [ordered]@{
        schema = 'safeupload-harness-gate-r21-receipt-writer-control-v1'
        status = 'FAIL'
        process = [ordered]@{ pid = $ProcessId; startFiletime = $ProcessStartFiletime }
        module = [ordered]@{ path = $ModulePath; sha256Before = $ModuleSha256Before; sha256After = $ModuleSha256After; expectedSha256 = $ExpectedModuleSha256 }
        control = [ordered]@{ path = $ControlPath; sha256Before = $ControlSha256Before; sha256After = $ControlSha256After }
        fixture = [ordered]@{ path = $FixtureRoot; created = $FixtureCreated; retainedForReview = $fixtureRetained; removedAfterOwnedCleanup = $FixtureRemoved }
        completedChecks = $PassedChecks.ToArray()
        failure = $FailureMessage
    }
    [Console]::Error.WriteLine('R21_RECEIPT_WRITER_CONTROL_FAIL ' + (ConvertTo-Json -InputObject $failureResult -Depth 8 -Compress))
    exit 1
}
