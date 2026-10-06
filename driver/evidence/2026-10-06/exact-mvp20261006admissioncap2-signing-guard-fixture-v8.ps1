# REVIEW ONLY: memory-only Windows PowerShell 5.1 semantic fixture.
# Reads only the pinned helper source. It does not inspect stores, call ACL
# cmdlets, create files, open keys, import trust, contact a VM, or write output.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'This semantic fixture is scoped to Windows PowerShell 5.1.' }
$helperPath = Join-Path $PSScriptRoot 'signing-guard-helpers-v8.ps1'
$helperSha256 = '9585e1acd512f9532de032c6ce2df251fa774acc83d27cfc6afceb437ce64c42'
if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $helperSha256) {
    throw 'V8 pure-helper file is missing or changed.'
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

# Exact captured default key ACL allowlist. The provider's pristine descriptor
# is protected and canonical, with exactly these ordered explicit Allow ACEs:
# CREATOR OWNER, SYSTEM, BUILTIN\Administrators. Each row remains as observed;
# this fixture does not normalize or write a DACL.
$creatorOwner = 'S-1-3-0'; $system = 'S-1-5-18'; $admins = 'S-1-5-32-544'
$vika = 'S-1-5-21-316478115-1595729549-2803163825-1001'; $users = 'S-1-5-32-545'
$fullMask = [int][Security.AccessControl.FileSystemRights]::FullControl
$genericAllMask = [int]0x10000000
$creatorFull = '{0}|Allow|{1}|None|None|False' -f $creatorOwner,$fullMask
$creatorGeneric = '{0}|Allow|{1}|None|None|False' -f $creatorOwner,$genericAllMask
$systemFull = '{0}|Allow|{1}|None|None|False' -f $system,$fullMask
$adminFull = '{0}|Allow|{1}|None|None|False' -f $admins,$fullMask
$goodSddlFull = 'O:BAG:S-1-5-21-316478115-1595729549-2803163825-513D:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)'
$goodFull = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($creatorFull,$systemFull,$adminFull)
$unapprovedOwnerExactDacl = New-FixtureSnapshot -Sddl 'O:SYG:S-1-5-21-316478115-1595729549-2803163825-513D:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($creatorFull,$systemFull,$adminFull) -Owner 'SYSTEM' -OwnerSid 'S-1-5-18'
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $goodFull
Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $goodFull

# Exercise typed owner/group extraction on an in-memory descriptor. It is not
# associated with a file and no filesystem ACL cmdlet is called.
$memoryAcl = [Security.AccessControl.FileSecurity]::new()
$memoryAcl.SetSecurityDescriptorSddlForm($goodSddlFull,[Security.AccessControl.AccessControlSections]::All)
$memorySnapshot = Get-SafeUploadOrderedKeyAclSnapshot -AclObject $memoryAcl
Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $memorySnapshot
if ($memorySnapshot.OwnerSid -cne $admins -or $memorySnapshot.GroupSid -cne 'S-1-5-21-316478115-1595729549-2803163825-513') { throw 'Typed owner/group SID extraction did not preserve the in-memory descriptor identities.' }
$memoryUnapprovedOwner = [Security.AccessControl.FileSecurity]::new()
$memoryUnapprovedOwner.SetSecurityDescriptorSddlForm('O:SYG:S-1-5-21-316478115-1595729549-2803163825-513D:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)',[Security.AccessControl.AccessControlSections]::All)
$memoryUnapprovedSnapshot = Get-SafeUploadOrderedKeyAclSnapshot -AclObject $memoryUnapprovedOwner
Assert-ExpectedRejection 'unapproved real descriptor owner SID with exact approved DACL' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $memoryUnapprovedSnapshot }

$vikaReadSync = '{0}|Allow|1179785|None|None|False' -f $vika
$usersReadSync = '{0}|Allow|1179785|None|None|False' -f $users
$adminDeny = '{0}|Deny|{1}|None|None|False' -f $admins,$fullMask
$adminInherited = '{0}|Allow|{1}|None|None|True' -f $admins,$fullMask
$adminInheritable = '{0}|Allow|{1}|ContainerInherit, ObjectInherit|None|False' -f $admins,$fullMask
$creatorInheritable = '{0}|Allow|{1}|ObjectInherit|None|False' -f $creatorOwner,$fullMask
$adminRead = '{0}|Allow|131209|None|None|False' -f $admins
Assert-ExpectedRejection 'unexpected Vika ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;vika)' -Rows @($creatorFull,$systemFull,$adminFull,$vikaReadSync)) }
Assert-ExpectedRejection 'unexpected Users principal' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)' -Rows @($creatorFull,$systemFull,$adminFull,$usersReadSync)) }
Assert-ExpectedRejection 'duplicate Creator Owner ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;CO)(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($creatorFull,$creatorFull,$systemFull,$adminFull)) }
Assert-ExpectedRejection 'duplicate Administrators ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl ($goodSddlFull + '(A;;FA;;;BA)') -Rows @($creatorFull,$systemFull,$adminFull,$adminFull)) }
Assert-ExpectedRejection 'missing Creator Owner ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($systemFull,$adminFull)) }
Assert-ExpectedRejection 'missing SYSTEM ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;CO)(A;;FA;;;BA)' -Rows @($creatorFull,$adminFull)) }
Assert-ExpectedRejection 'deny ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;CO)(A;;FA;;;SY)(D;;FA;;;BA)' -Rows @($creatorFull,$systemFull,$adminDeny)) }
Assert-ExpectedRejection 'inherited ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;CO)(A;;FA;;;SY)(A;ID;FA;;;BA)' -Rows @($creatorFull,$systemFull,$adminInherited)) }
Assert-ExpectedRejection 'inheritable Administrators ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;CO)(A;;FA;;;SY)(A;OI;FA;;;BA)' -Rows @($creatorFull,$systemFull,$adminInheritable)) }
Assert-ExpectedRejection 'inheritable Creator Owner ACE' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;OI;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($creatorInheritable,$systemFull,$adminFull)) }
Assert-ExpectedRejection 'unexpected mask' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FR;;;BA)' -Rows @($creatorFull,$systemFull,$adminRead)) }
Assert-ExpectedRejection 'unobserved generic-all spelling' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;GA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($creatorGeneric,$systemFull,$adminFull)) }
Assert-ExpectedRejection 'unprotected DACL' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl 'O:BAG:BAD(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($creatorFull,$systemFull,$adminFull) -Protected $false) }
Assert-ExpectedRejection 'unapproved owner SID with exact captured DACL' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot $unapprovedOwnerExactDacl }
Assert-ExpectedRejection 'noncanonical ACL' { Assert-SafeUploadDefaultMachineKeyAcl -Snapshot (New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($creatorFull,$systemFull,$adminFull) -Canonical $false) }

# The equality guard rejects relevant descriptor and ordered-ACE drift.
$changedSddl = New-FixtureSnapshot -Sddl ($goodSddlFull + 'S:') -Rows @($creatorFull,$systemFull,$adminFull)
$changedOwner = New-FixtureSnapshot -Sddl 'O:SYG:S-1-5-21-316478115-1595729549-2803163825-513D:P(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($creatorFull,$systemFull,$adminFull) -Owner 'SYSTEM' -OwnerSid 'S-1-5-18'
$changedOwnerSidOnly = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($creatorFull,$systemFull,$adminFull) -Owner $goodFull.Owner -OwnerSid 'S-1-5-18'
$changedGroup = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($creatorFull,$systemFull,$adminFull) -Group 'S-1-5-18'
$changedGroupSid = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($creatorFull,$systemFull,$adminFull) -GroupSid 'S-1-5-18'
$changedProtection = New-FixtureSnapshot -Sddl 'O:BAG:BAD(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)' -Rows @($creatorFull,$systemFull,$adminFull) -Protected $false
$changedCanonicality = New-FixtureSnapshot -Sddl $goodSddlFull -Rows @($creatorFull,$systemFull,$adminFull) -Canonical $false
$changedOrder = New-FixtureSnapshot -Sddl 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;CO)(A;;FA;;;BA)' -Rows @($systemFull,$creatorFull,$adminFull)
$changedRows = New-FixtureSnapshot -Sddl ($goodSddlFull + '(A;;FR;;;BU)') -Rows @($creatorFull,$systemFull,$adminFull,$usersReadSync)
Assert-ExpectedRejection 'SDDL drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedSddl }
Assert-ExpectedRejection 'owner drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedOwner }
Assert-ExpectedRejection 'typed owner SID drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedOwnerSidOnly }
Assert-ExpectedRejection 'group drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedGroup }
Assert-ExpectedRejection 'typed group SID drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedGroupSid }
Assert-ExpectedRejection 'protection drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedProtection }
Assert-ExpectedRejection 'canonicality drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedCanonicality }
Assert-ExpectedRejection 'ACE order drift' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedOrder }
Assert-ExpectedRejection 'ACE-row delta' { Assert-SafeUploadKeyAclUnchanged -Before $goodFull -After $changedRows }

[ordered]@{
    Status='V8_MEMORY_ONLY_FIXTURE_PASS'; PowerShellVersion=$PSVersionTable.PSVersion.ToString()
    FileOrKeyOpened=$false; CertificateStoreRead=$false; FilesystemAclReadOrWritten=$false; TrustChanged=$false; VmContacted=$false
    ExactAdministratorsOwnerAndCapturedCreatorOwnerSystemAdministratorsAclAccepted=$true; CapturedFullControlMaskOnlyAccepted=$true
    UnapprovedOwnerSidRejectedEvenWithOtherwiseExactDacl=$true
    TypedOwnerAndGroupSidsReadFromInMemoryDescriptor=$true
    CreatorOwnerKeptAsLiteralProviderAce=$true; VikaOrUnexpectedPrincipalAndExtraAceRejected=$true; MissingDuplicateDenyInheritedOrInheritableAceRejected=$true
    UnprotectedOrNoncanonicalAclRejected=$true; SddlTypedOwnerAndGroupSidOwnerGroupProtectionCanonicalityAndOrderedAceDriftRejected=$true
    TypedEkuPositiveAccepted=$true; DuplicateExtensionsAndPurposesRejected=$true; MalformedEkuRejected=$true
} | ConvertTo-Json -Depth 4 -Compress
