# REVIEW ONLY: memory-only Windows PowerShell 5.1 semantic fixture.
# Constructs certificate-extension and ACL-rule objects only. It reads this
# pinned helper source, but does not open artifact/key files, inspect stores,
# call Get-Acl/Set-Acl, import trust, contact a VM, or write output files.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'This semantic fixture is scoped to Windows PowerShell 5.1.' }

$helperPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v5.ps1'
$helperSha256 = 'c833ebca338f366fb41fbb274b4a0dcab6cd47f4e7863f61774a5fb83e22f03e'
if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $helperSha256) {
    throw 'V5 pure-helper file is missing or changed.'
}
. $helperPath

function Assert-ExpectedRejection {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][scriptblock] $Action)
    try {
        & $Action | Out-Null
    } catch {
        return
    }
    throw ("Fixture expected guard rejection: {0}" -f $Name)
}

# Typed EKU positive case, duplicate-extension rejection, duplicate-purpose
# rejection, and malformed-DER rejection.
$codeSigningOid = [Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')
$ekuOids = [Security.Cryptography.OidCollection]::new()
[void]$ekuOids.Add($codeSigningOid)
$goodEku = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids,$false)
$goodResult = @(Get-SafeUploadCodeSigningEkuOids -Extensions @($goodEku) -Context 'fixture positive certificate')
if ($goodResult.Count -ne 1 -or $goodResult[0] -cne '1.3.6.1.5.5.7.3.3') { throw 'Typed EKU positive case did not return the sole code-signing OID.' }
Assert-ExpectedRejection 'duplicate EKU extension' {
    Get-SafeUploadCodeSigningEkuOids -Extensions @($goodEku,$goodEku) -Context 'fixture duplicate extension'
}
$duplicateOids = [Security.Cryptography.OidCollection]::new()
[void]$duplicateOids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
[void]$duplicateOids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
$duplicatePurposeEku = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($duplicateOids,$false)
Assert-ExpectedRejection 'duplicate code-signing purpose OID' {
    Get-SafeUploadCodeSigningEkuOids -Extensions @($duplicatePurposeEku) -Context 'fixture duplicate purpose'
}
$malformedEku = [Security.Cryptography.X509Certificates.X509Extension]::new(
    [Security.Cryptography.Oid]::new('2.5.29.37'),[byte[]]@(0xFF),$false
)
Assert-ExpectedRejection 'malformed EKU DER' {
    Get-SafeUploadCodeSigningEkuOids -Extensions @($malformedEku) -Context 'fixture malformed extension'
}

# ACL rows are synthesized from in-memory FileSystemAccessRule objects. The
# rule constructor is the source of the allowed mask (Read plus its implicit
# Synchronize bit on Windows); no filesystem ACL is created or modified.
$targetSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-21-316478115-1595729549-2803163825-1001')
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$adminSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$usersSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
$allow = [Security.AccessControl.AccessControlType]::Allow
$readRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $targetSid,[Security.AccessControl.FileSystemRights]::Read,$allow
)
$expectedMask = [int]$readRule.FileSystemRights
$requestedReadWithSynchronize = [int]([int][Security.AccessControl.FileSystemRights]::Read -bor [int][Security.AccessControl.FileSystemRights]::Synchronize)
if ($expectedMask -ne $requestedReadWithSynchronize) { throw 'Constructed Read rule has an unexpected mask on this PowerShell/.NET runtime.' }
$expectedReadRow = Get-SafeUploadFileSystemRuleAceRow -Sid $targetSid -Rule $readRule
$baseRows = @(
    Get-SafeUploadFileSystemRuleAceRow -Sid $systemSid -Rule ([Security.AccessControl.FileSystemAccessRule]::new($systemSid,[Security.AccessControl.FileSystemRights]::FullControl,$allow))
    Get-SafeUploadFileSystemRuleAceRow -Sid $adminSid -Rule ([Security.AccessControl.FileSystemAccessRule]::new($adminSid,[Security.AccessControl.FileSystemRights]::FullControl,$allow))
)
$owner = 'S-1-5-18'; $group = 'S-1-5-32-544'; $protected = $false
$afterGrant = @($baseRows + $expectedReadRow)
$grantCheck = Assert-SafeUploadExactReadAclChange -BeforeAceRows $baseRows -AfterAceRows $afterGrant `
    -TargetSid $targetSid.Value -ExpectedReadAceRow $expectedReadRow -ExpectedReadMask $expectedMask `
    -OwnerBefore $owner -OwnerAfter $owner -GroupBefore $group -GroupAfter $group -ProtectedBefore $protected -ProtectedAfter $protected
if (@($grantCheck.AddedAceRows).Count -ne 1 -or @($grantCheck.RemovedAceRows).Count -ne 0) { throw 'Exact one-ACE ACL delta was not accepted.' }

$fullControlRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $targetSid,[Security.AccessControl.FileSystemRights]::FullControl,$allow
)
$fullControlRow = Get-SafeUploadFileSystemRuleAceRow -Sid $targetSid -Rule $fullControlRule
Assert-ExpectedRejection 'existing FullControl ACE' {
    Assert-SafeUploadExactReadAclChange -BeforeAceRows @($baseRows + $fullControlRow) -AfterAceRows @($baseRows + $fullControlRow) `
        -TargetSid $targetSid.Value -ExpectedReadAceRow $expectedReadRow -ExpectedReadMask $expectedMask `
        -OwnerBefore $owner -OwnerAfter $owner -GroupBefore $group -GroupAfter $group -ProtectedBefore $protected -ProtectedAfter $protected
}

$readWriteRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $targetSid,[Security.AccessControl.FileSystemRights]([int][Security.AccessControl.FileSystemRights]::Read -bor [int][Security.AccessControl.FileSystemRights]::WriteData),$allow
)
$readWriteRow = Get-SafeUploadFileSystemRuleAceRow -Sid $targetSid -Rule $readWriteRule
Assert-ExpectedRejection 'extra write rights' {
    Assert-SafeUploadExactReadAclChange -BeforeAceRows $baseRows -AfterAceRows @($baseRows + $readWriteRow) `
        -TargetSid $targetSid.Value -ExpectedReadAceRow $expectedReadRow -ExpectedReadMask $expectedMask `
        -OwnerBefore $owner -OwnerAfter $owner -GroupBefore $group -GroupAfter $group -ProtectedBefore $protected -ProtectedAfter $protected
}

$extraUsersRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $usersSid,[Security.AccessControl.FileSystemRights]::Read,$allow
)
$extraUsersRow = Get-SafeUploadFileSystemRuleAceRow -Sid $usersSid -Rule $extraUsersRule
Assert-ExpectedRejection 'unexpected extra ACE in delta' {
    Assert-SafeUploadExactReadAclChange -BeforeAceRows $baseRows -AfterAceRows @($baseRows + $expectedReadRow + $extraUsersRow) `
        -TargetSid $targetSid.Value -ExpectedReadAceRow $expectedReadRow -ExpectedReadMask $expectedMask `
        -OwnerBefore $owner -OwnerAfter $owner -GroupBefore $group -GroupAfter $group -ProtectedBefore $protected -ProtectedAfter $protected
}
Assert-ExpectedRejection 'missing original administrator ACE' {
    Assert-SafeUploadExactReadAclChange -BeforeAceRows $baseRows -AfterAceRows @($baseRows[0] + $expectedReadRow) `
        -TargetSid $targetSid.Value -ExpectedReadAceRow $expectedReadRow -ExpectedReadMask $expectedMask `
        -OwnerBefore $owner -OwnerAfter $owner -GroupBefore $group -GroupAfter $group -ProtectedBefore $protected -ProtectedAfter $protected
}
Assert-ExpectedRejection 'owner drift' {
    Assert-SafeUploadExactReadAclChange -BeforeAceRows $baseRows -AfterAceRows $afterGrant `
        -TargetSid $targetSid.Value -ExpectedReadAceRow $expectedReadRow -ExpectedReadMask $expectedMask `
        -OwnerBefore $owner -OwnerAfter 'S-1-5-32-544' -GroupBefore $group -GroupAfter $group -ProtectedBefore $protected -ProtectedAfter $protected
}
Assert-ExpectedRejection 'group drift' {
    Assert-SafeUploadExactReadAclChange -BeforeAceRows $baseRows -AfterAceRows $afterGrant `
        -TargetSid $targetSid.Value -ExpectedReadAceRow $expectedReadRow -ExpectedReadMask $expectedMask `
        -OwnerBefore $owner -OwnerAfter $owner -GroupBefore $group -GroupAfter 'S-1-5-18' -ProtectedBefore $protected -ProtectedAfter $protected
}
Assert-ExpectedRejection 'ACL protection drift' {
    Assert-SafeUploadExactReadAclChange -BeforeAceRows $baseRows -AfterAceRows $afterGrant `
        -TargetSid $targetSid.Value -ExpectedReadAceRow $expectedReadRow -ExpectedReadMask $expectedMask `
        -OwnerBefore $owner -OwnerAfter $owner -GroupBefore $group -GroupAfter $group -ProtectedBefore $protected -ProtectedAfter $true
}
Assert-SafeUploadNoBroadAllowAces -AceRows $baseRows
Assert-ExpectedRejection 'existing broad Users allow ACE' {
    Assert-SafeUploadNoBroadAllowAces -AceRows @($baseRows + $extraUsersRow)
}

[ordered]@{
    Status = 'V5_MEMORY_ONLY_FIXTURE_PASS'
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    FileOrKeyOpened = $false
    CertificateStoreRead = $false
    FilesystemAclReadOrWritten = $false
    TrustChanged = $false
    VmContacted = $false
    ConstructedReadMask = $expectedMask
    ConstructedReadRights = $readRule.FileSystemRights.ToString()
    ExactOneAceDeltaAccepted = $true
    ExistingFullControlRejected = $true
    ExtraRightsAndUnexpectedAceRejected = $true
    OwnerGroupProtectionDriftRejected = $true
    TypedEkuPositiveAccepted = $true
    DuplicateExtensionsAndPurposesRejected = $true
    MalformedEkuRejected = $true
} | ConvertTo-Json -Depth 3 -Compress
