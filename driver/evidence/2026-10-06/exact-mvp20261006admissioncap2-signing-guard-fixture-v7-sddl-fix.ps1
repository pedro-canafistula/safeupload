# REVIEW ONLY: memory-only Windows PowerShell 5.1 semantic fixture.
# Reads only the pinned helper source. It does not inspect stores, call ACL
# cmdlets, create files, open keys, import trust, contact a VM, or write output.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'This semantic fixture is scoped to Windows PowerShell 5.1.' }
$helperPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v7.ps1'
$helperSha256 = 'f71d8fedfc9a87a07487c693823a2f71cd4803d993e63b5759021d0431f1c0ab'
if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $helperSha256) {
    throw 'V7 pure-helper file is missing or changed.'
}
. $helperPath

function Assert-ExpectedRejection {
    param([Parameter(Mandatory)][string] $Name, [Parameter(Mandatory)][scriptblock] $Action)
    try { & $Action | Out-Null } catch { return }
    throw ("Fixture expected guard rejection: {0}" -f $Name)
}

function New-FixtureSnapshot {
    param(
        [Parameter(Mandatory)][string] $Sddl,
        [Parameter(Mandatory)][string[]] $Rows,
        [string] $Owner='BUILTIN\Administrators',
        [string] $OwnerSid='S-1-5-32-544',
        [string] $Group='DESKTOP-O1LP5DG\None',
        [string] $GroupSid='S-1-5-21-316478115-1595729549-2803163825-513',
        [bool] $Protected=$true,
        [bool] $Canonical=$true
    )
    return [pscustomobject][ordered]@{
        Sddl=$Sddl; Owner=$Owner; Group=$Group; OwnerSid=$OwnerSid; GroupSid=$GroupSid; AreAccessRulesProtected=$Protected
        AreAccessRulesCanonical=$Canonical; OrderedAceRows=@($Rows)
    }
}

# Typed code-signing EKU positive case and malformed/duplicate rejection.
$codeSigningOid = [Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')
$ekuOids = [Security.Cryptography.OidCollection]::new()
[void]$ekuOids.Add($codeSigningOid)
$goodEku = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids,$false)
$goodResult = @(Get-SafeUploadCodeSigningEkuOids -Extensions @($goodEku) -Context 'fixture positive')
if ($goodResult.Count -ne 1 -or $goodResult[0] -cne '1.3.6.1.5.5.7.3.3') { throw 'Typed EKU positive case did not return the sole code-signing OID.' }
Assert-ExpectedRejection 'duplicate EKU extension' {
    Get-SafeUploadCodeSigningEkuOids -Extensions @($goodEku,$goodEku) -Context 'fixture duplicate extension'
}
$duplicateOids = [Security.Cryptography.OidCollection]::new()
[void]$duplicateOids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
[void]$duplicateOids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
$duplicateEku = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($duplicateOids,$false)
Assert-ExpectedRejection 'duplicate purpose OID' {
    Get-SafeUploadCodeSigningEkuOids -Extensions @($duplicateEku) -Context 'fixture duplicate purpose'
}
$malformedEku = [Security.Cryptography.X509Certificates.X509Extension]::new(
    [Security.Cryptography.Oid]::new('2.5.29.37'),[byte[]]@(0xFF),$false
)
Assert-ExpectedRejection 'malformed EKU DER' {
    Get-SafeUploadCodeSigningEkuOids -Extensions @($malformedEku) -Context 'fixture malformed EKU'
}

# Exact default key ACL allowlist. The two accepted provider spellings remain
# distinct in the metadata; tests never normalize or rewrite either spelling.
$system = 'S-1-5-18'; $admins = 'S-1-5-32-544'; $vika = 'S-1-5-21-316478115-1595729549-2803163825-1001'; $users = 'S-1-5-32-545'
$fullMask = [int][Security.AccessControl.FileSystemRights]::FullControl
$genericAllMask = [int]0x10000000
$systemFull = '{0}|Allow|{1}|None|None|False' -f $system,$fullMask
$adminFull = '{0}|Allow|{1}|None|None|False' -f $admins,$fullMask
$systemGeneric = '{0}|Allow|{1}|None|None|False' -f $system,$genericAllMask
$adminGeneric = '{0}|Allow|{1}|None|None|False' -f $admins,$genericAllMask
$goodSddlFull = 'O:BAG:S-1-5-21-316478115-1595729549-2803163825-513D:P(A;;FA;;;SY)(A;;FA;;;BA)'
$goodSddlGeneric = 'O:BAG:S-1-5-21-316478115-1595729549-2803163825-513D:P(A;;GA;;;SY)(A;;GA;;;BA)'
$goodFull = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($systemFull,$adminFull)
$goodGeneric = New-FixtureSnapshot -Sddl $goodSddlGeneric -Rows @($systemGeneric,$adminGeneric)
$unapprovedOwnerExactDacl = New-FixtureSnapshot -Sddl 'O:SYG:S-1-5-21-316478115-1595729549-2803163825-513D:P(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($systemFull,$adminFull) -Owner 'SYSTEM' -OwnerSid 'S-1-5-18'
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $goodFull
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $goodGeneric
Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $goodFull
Assert-SafeUploadKeyAclUnchanged -Before $goodGeneric -After $goodGeneric

# Exercise the typed owner/group SID extraction on an in-memory descriptor;
# this does not associate the descriptor with a file or call Get-Acl/Set-Acl.
$memoryAcl = [Security.AccessControl.FileSecurity]::new()
$memoryAcl.SetSecurityDescriptorSddlForm($goodSddlFull,[Security.AccessControl.AccessControlSections]::All)
$memorySnapshot = Get-SafeUploadOrderedKeyAclSnapshot -AclObject $memoryAcl
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $memorySnapshot
if ($memorySnapshot.OwnerSid -cne $admins -or $memorySnapshot.GroupSid -cne 'S-1-5-21-316478115-1595729549-2803163825-513') { throw 'Typed owner/group SID extraction did not preserve the in-memory descriptor identities.' }
$memoryUnapprovedOwner = [Security.AccessControl.FileSecurity]::new()
$memoryUnapprovedOwner.SetSecurityDescriptorSddlForm('O:SYG:S-1-5-21-316478115-1595729549-2803163825-513D:P(A;;FA;;;SY)(A;;FA;;;BA)',[Security.AccessControl.AccessControlSections]::All)
$memoryUnapprovedSnapshot = Get-SafeUploadOrderedKeyAclSnapshot -AclObject $memoryUnapprovedOwner
Assert-ExpectedRejection 'unapproved real descriptor owner SID with exact approved DACL' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $memoryUnapprovedSnapshot }

$vikaReadSync = '{0}|Allow|1179785|None|None|False' -f $vika
$usersReadSync = '{0}|Allow|1179785|None|None|False' -f $users
$adminDeny = '{0}|Deny|{1}|None|None|False' -f $admins,$fullMask
$adminInherited = '{0}|Allow|{1}|None|None|True' -f $admins,$fullMask
$adminInheritable = '{0}|Allow|{1}|ContainerInherit, ObjectInherit|None|False' -f $admins,$fullMask
$adminRead = '{0}|Allow|131209|None|None|False' -f $admins
$adminDuplicate = $adminFull
Assert-ExpectedRejection 'vika added as a third principal' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;vika)' -Rows @($systemFull,$adminFull,$vikaReadSync)) }
Assert-ExpectedRejection 'unexpected Users principal' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)' -Rows @($systemFull,$adminFull,$usersReadSync)) }
Assert-ExpectedRejection 'duplicate Administrators ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($systemFull,$adminFull,$adminDuplicate)) }
Assert-ExpectedRejection 'missing SYSTEM ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;BA)' -Rows @($adminFull)) }
Assert-ExpectedRejection 'deny ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;SY)(D;;FA;;;BA)' -Rows @($systemFull,$adminDeny)) }
Assert-ExpectedRejection 'inherited ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;SY)(A;ID;FA;;;BA)' -Rows @($systemFull,$adminInherited)) }
Assert-ExpectedRejection 'inheritable ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($systemFull,$adminInheritable)) }
Assert-ExpectedRejection 'unexpected mask' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FR;;;BA)' -Rows @($systemFull,$adminRead)) }
Assert-ExpectedRejection 'unprotected DACL' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($systemFull,$adminFull) -Protected $false) }
Assert-ExpectedRejection 'unapproved owner SID with otherwise exact default DACL' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $unapprovedOwnerExactDacl }
Assert-ExpectedRejection 'noncanonical ACL' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($systemFull,$adminFull) -Canonical $false) }

# The equality guard rejects every relevant descriptor or ordered-ACE drift.
$changedSddl = New-FixtureSnapshot -Sddl ($goodSddlFull + 'S:') -Rows @($systemFull,$adminFull)
$changedOwner = New-FixtureSnapshot -Sddl 'O:SYG:S-1-5-21-316478115-1595729549-2803163825-513D:P(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($systemFull,$adminFull) -Owner 'SYSTEM' -OwnerSid 'S-1-5-18'
$changedOwnerSidOnly = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($systemFull,$adminFull) -Owner $goodFull.Owner -OwnerSid 'S-1-5-18'
$changedGroup = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($systemFull,$adminFull) -Group 'S-1-5-18'
$changedGroupSid = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($systemFull,$adminFull) -GroupSid 'S-1-5-18'
$changedProtection = New-FixtureSnapshot -Sddl 'O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($systemFull,$adminFull) -Protected $false
$changedCanonicality = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($systemFull,$adminFull) -Canonical $false
$changedOrder = New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)' -Rows @($adminFull,$systemFull)
$changedRows = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($systemFull,$adminFull,$usersReadSync)
Assert-ExpectedRejection 'SDDL drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedSddl }
Assert-ExpectedRejection 'owner drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedOwner }
Assert-ExpectedRejection 'typed owner SID drift with unchanged SDDL/display owner' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedOwnerSidOnly }
Assert-ExpectedRejection 'group drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedGroup }
Assert-ExpectedRejection 'typed group SID drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedGroupSid }
Assert-ExpectedRejection 'protection drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedProtection }
Assert-ExpectedRejection 'canonicality drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedCanonicality }
Assert-ExpectedRejection 'ACE order drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedOrder }
Assert-ExpectedRejection 'ACE-row delta' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedRows }

[ordered]@{
    Status='V7_MEMORY_ONLY_FIXTURE_PASS'; PowerShellVersion=$PSVersionTable.PSVersion.ToString()
    FileOrKeyOpened=$false; CertificateStoreRead=$false; FilesystemAclReadOrWritten=$false; TrustChanged=$false; VmContacted=$false
    ExactAdministratorsOwnerAndSystemAdministratorsOnlyAclAccepted=$true; FullControlAndGenericAllSpellingsAcceptedWithoutNormalization=$true
    UnapprovedOwnerSidRejectedEvenWithOtherwiseExactDacl=$true
    TypedOwnerAndGroupSidsReadFromInMemoryDescriptor=$true
    VikaOrUnexpectedPrincipalAndExtraAceRejected=$true; MissingDuplicateDenyInheritedOrInheritableAceRejected=$true
    UnprotectedOrNoncanonicalAclRejected=$true; SddlTypedOwnerAndGroupSidOwnerGroupProtectionCanonicalityAndOrderedAceDriftRejected=$true
    TypedEkuPositiveAccepted=$true; DuplicateExtensionsAndPurposesRejected=$true; MalformedEkuRejected=$true
} | ConvertTo-Json -Depth 4 -Compress
