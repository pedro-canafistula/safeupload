# Diagnostic only: test whether Windows PowerShell/.NET and the file system
# rewrite GENERIC_ALL ACE masks when one exact Read ACE is added to an ordinary
# zero-byte temporary file. This script must never target a CNG/key file.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) {
    throw 'This probe requires Windows PowerShell 5.1.'
}
$expectedComputer = 'DESKTOP-O1LP5DG'
$expectedUuid = 'C6440689-D11C-4C63-A463-F3722B7DDB69'
$expectedSid = 'S-1-5-21-316478115-1595729549-2803163825-1001'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$product = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($env:COMPUTERNAME -cne $expectedComputer -or $product.UUID -cne $expectedUuid -or
    $identity.User.Value -cne $expectedSid -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Exact elevated builder identity guard failed.'
}

$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$vikaSid = [Security.Principal.SecurityIdentifier]::new($expectedSid)
$genericAllMask = [int]0x10000000
$fileFullControlMask = [int][Security.AccessControl.FileSystemRights]::FullControl
$readRule = [Security.AccessControl.FileSystemAccessRule]::new(
    $vikaSid,
    [Security.AccessControl.FileSystemRights]::Read,
    [Security.AccessControl.AccessControlType]::Allow
)
$expectedReadMask = [int]$readRule.FileSystemRights
$seedSddl = 'D:PAI(A;;GA;;;SY)(A;;GA;;;BA)'

function Get-OrderedAceRows {
    param([Parameter(Mandatory)][object] $AclObject)
    return @($AclObject.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.IdentityReference.Value,$_.AccessControlType.ToString(),
            [int]$_.FileSystemRights,$_.InheritanceFlags.ToString(),$_.PropagationFlags.ToString(),[bool]$_.IsInherited
    })
}

$memory = [Security.AccessControl.FileSecurity]::new()
$memory.SetSecurityDescriptorSddlForm($seedSddl,[Security.AccessControl.AccessControlSections]::Access)
$memoryBeforeSddl = $memory.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
$memoryBeforeRows = @(Get-OrderedAceRows -AclObject $memory)
$memory.AddAccessRule($readRule)
$memoryAfterAddSddl = $memory.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
$memoryAfterAddRows = @(Get-OrderedAceRows -AclObject $memory)

$tempPath = Join-Path $env:TEMP ('SafeUpload-AclGenericAllProbe-' + [Guid]::NewGuid().ToString('N') + '.tmp')
if (Test-Path -LiteralPath $tempPath) { throw 'Unexpected throwaway-file collision.' }
$createdFile = $false
$result = $null
try {
    $stream = [IO.File]::Open($tempPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $createdFile = $true
    $stream.Dispose()

    # Only the new empty temporary file is changed. Persist the generic-all
    # seed DACL, then execute the same Get-Acl/AddAccessRule/Set-Acl sequence as
    # the creator. The file is removed in finally; no key/certificate APIs run.
    $seed = [Security.AccessControl.FileSecurity]::new()
    $seed.SetSecurityDescriptorSddlForm($seedSddl,[Security.AccessControl.AccessControlSections]::Access)
    Set-Acl -LiteralPath $tempPath -AclObject $seed
    $fileBefore = Get-Acl -LiteralPath $tempPath
    $fileBeforeSddl = $fileBefore.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
    $fileBeforeRows = @(Get-OrderedAceRows -AclObject $fileBefore)

    $fileUpdate = Get-Acl -LiteralPath $tempPath
    $fileUpdate.AddAccessRule($readRule)
    $fileAfterAddSddl = $fileUpdate.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
    $fileAfterAddRows = @(Get-OrderedAceRows -AclObject $fileUpdate)
    Set-Acl -LiteralPath $tempPath -AclObject $fileUpdate
    $fileAfter = Get-Acl -LiteralPath $tempPath
    $fileAfterSddl = $fileAfter.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
    $fileAfterRows = @(Get-OrderedAceRows -AclObject $fileAfter)

    $allowedSids = @($systemSid.Value,$administratorsSid.Value,$vikaSid.Value)
    $unexpectedAfterSids = @($fileAfterRows | ForEach-Object { ($_ -split '\|',2)[0] } |
        Where-Object { $_ -notin $allowedSids } | Sort-Object -Unique)
    $result = [ordered]@{
        Status='ACL_GENERIC_ALL_FILE_PROBE_COMPLETE'
        UTC=[DateTime]::UtcNow.ToString('o')
        ComputerName=$env:COMPUTERNAME
        UUID=$product.UUID
        User=$identity.Name
        SID=$identity.User.Value
        PowerShellVersion=$PSVersionTable.PSVersion.ToString()
        SeedSddl=$seedSddl
        GenericAllMask=$genericAllMask
        FileSystemFullControlMask=$fileFullControlMask
        ConstructedReadMask=$expectedReadMask
        ExpectedReadMaskIsReadAndSynchronize=($expectedReadMask -eq [int]([int][Security.AccessControl.FileSystemRights]::Read -bor [int][Security.AccessControl.FileSystemRights]::Synchronize))
        MemoryOnlyBeforeSddl=$memoryBeforeSddl
        MemoryOnlyBeforeOrderedAces=$memoryBeforeRows
        MemoryOnlyAfterAddSddl=$memoryAfterAddSddl
        MemoryOnlyAfterAddOrderedAces=$memoryAfterAddRows
        ThrowawayFile=$tempPath
        ThrowawayFileIsZeroBytes=([IO.FileInfo]::new($tempPath).Length -eq 0)
        FileBeforeSddl=$fileBeforeSddl
        FileBeforeOrderedAces=$fileBeforeRows
        FileObjectAfterAddSddl=$fileAfterAddSddl
        FileObjectAfterAddOrderedAces=$fileAfterAddRows
        FileAfterSetAclSddl=$fileAfterSddl
        FileAfterSetAclOrderedAces=$fileAfterRows
        FileOwnerBefore=$fileBefore.Owner
        FileOwnerAfter=$fileAfter.Owner
        FileGroupBefore=$fileBefore.Group
        FileGroupAfter=$fileAfter.Group
        FileProtectionBefore=$fileBefore.AreAccessRulesProtected
        FileProtectionAfter=$fileAfter.AreAccessRulesProtected
        UnexpectedAllowPrincipalsAfter=$unexpectedAfterSids
        KeyOrCertificateOpened=$false
        CertificateStoreReadOrChanged=$false
        PrivateKeyUsedOrExported=$false
        TrustChanged=$false
        SourceOrBuildChanged=$false
    }
} finally {
    if ($createdFile -and (Test-Path -LiteralPath $tempPath)) {
        Remove-Item -LiteralPath $tempPath -Force
    }
}
if ($null -eq $result) { throw 'Probe did not produce its metadata result.' }
$result['ThrowawayFileAbsentAfterCleanup'] = -not (Test-Path -LiteralPath $tempPath)
if (-not $result['ThrowawayFileAbsentAfterCleanup']) { throw 'Throwaway file cleanup was not verified.' }
$result | ConvertTo-Json -Depth 8 -Compress
