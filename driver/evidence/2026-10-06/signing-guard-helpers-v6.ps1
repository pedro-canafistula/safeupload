# Pure V6 helpers for the exact-source signer fallback.
# The ACL snapshot helper reads only the supplied ACL metadata object. This
# file calls no ACL cmdlet, accesses no external store/file/VM/key, and contains
# no ACL-write helper.

function Get-SafeUploadCodeSigningEkuOids {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Extensions,
        [Parameter(Mandatory)][string] $Context
    )

    $ekuExtensions = @()
    foreach ($extension in $Extensions) {
        if ($null -eq $extension) { continue }
        try {
            if ($null -ne $extension.Oid -and $extension.Oid.Value -ceq '2.5.29.37') {
                $ekuExtensions += $extension
            }
        } catch {
            throw ("{0} has an unreadable certificate-extension OID." -f $Context)
        }
    }
    if ($ekuExtensions.Count -ne 1) {
        throw ("{0} must have exactly one Enhanced Key Usage extension." -f $Context)
    }

    try {
        $encodedEku = [Security.Cryptography.AsnEncodedData]::new(
            $ekuExtensions[0].Oid,
            [byte[]]$ekuExtensions[0].RawData
        )
        $typedExtension = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
            $encodedEku,
            [bool]$ekuExtensions[0].Critical
        )
        $usageOids = @()
        foreach ($oid in $typedExtension.EnhancedKeyUsages) {
            if ($null -eq $oid -or [string]::IsNullOrWhiteSpace([string]$oid.Value)) {
                throw 'An EKU OID is missing or malformed.'
            }
            $usageOids += [string]$oid.Value
        }
    } catch {
        throw ("{0} Enhanced Key Usage extension is malformed or has an unexpected representation." -f $Context)
    }

    if ($usageOids.Count -ne 1 -or $usageOids[0] -cne '1.3.6.1.5.5.7.3.3') {
        throw ("{0} must contain exactly one code-signing OID." -f $Context)
    }
    return $usageOids
}

function Get-SafeUploadSidValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object] $IdentityReference)
    try {
        return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return [string]$IdentityReference.Value
    }
}

function Get-SafeUploadOrderedKeyAclSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object] $AclObject)

    $rows = @($AclObject.Access | ForEach-Object {
        $aceSid = Get-SafeUploadSidValue -IdentityReference $_.IdentityReference
        '{0}|{1}|{2}|{3}|{4}|{5}' -f $aceSid,$_.AccessControlType.ToString(),
            [int]$_.FileSystemRights,$_.InheritanceFlags.ToString(),$_.PropagationFlags.ToString(),[bool]$_.IsInherited
    })
    return [pscustomobject][ordered]@{
        Sddl = [string]$AclObject.Sddl
        Owner = [string]$AclObject.Owner
        Group = [string]$AclObject.Group
        AreAccessRulesProtected = [bool]$AclObject.AreAccessRulesProtected
        AreAccessRulesCanonical = [bool]$AclObject.AreAccessRulesCanonical
        OrderedAceRows = @($rows)
    }
}

function Assert-SafeUploadDefaultMachineKeyAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object] $Snapshot)

    if ([string]::IsNullOrWhiteSpace([string]$Snapshot.Sddl) -or
        [string]::IsNullOrWhiteSpace([string]$Snapshot.Owner) -or
        [string]::IsNullOrWhiteSpace([string]$Snapshot.Group)) {
        throw 'Machine-key ACL snapshot is incomplete.'
    }
    if (-not [bool]$Snapshot.AreAccessRulesProtected -or -not [bool]$Snapshot.AreAccessRulesCanonical) {
        throw 'Default machine-key DACL must be protected and canonical; no ACL rewrite is permitted.'
    }
    $rows = @($Snapshot.OrderedAceRows)
    if ($rows.Count -ne 2) { throw 'Default machine-key DACL must contain exactly the SYSTEM and Administrators ACEs.' }
    $expectedSids = @('S-1-5-18','S-1-5-32-544')
    $observedSids = @()
    # Preserve either spelling emitted by the provider. This validator never
    # normalizes GENERIC_ALL to a file-rights mask or writes a DACL.
    $allowedFullMasks = @([int][Security.AccessControl.FileSystemRights]::FullControl,[int]0x10000000)
    foreach ($row in $rows) {
        $parts = [string]$row -split '\|',6
        if ($parts.Count -ne 6) { throw 'Default machine-key DACL contains a malformed ACE row.' }
        $sid = $parts[0]
        $observedSids += $sid
        if ($expectedSids -notcontains $sid -or $parts[1] -cne 'Allow' -or
            [int]$parts[2] -notin $allowedFullMasks -or $parts[3] -cne 'None' -or
            $parts[4] -cne 'None' -or $parts[5] -cne 'False') {
            throw 'Default machine-key DACL contains an unapproved principal or ACE shape.'
        }
    }
    foreach ($sid in $expectedSids) {
        if (@($observedSids | Where-Object { $_ -ceq $sid }).Count -ne 1) {
            throw 'Default machine-key DACL must contain one exact ACE for each of SYSTEM and Administrators.'
        }
    }
}

function Assert-SafeUploadKeyAclUnchanged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object] $Before,
        [Parameter(Mandatory)][object] $After
    )
    if ($Before.Sddl -cne $After.Sddl -or $Before.Owner -cne $After.Owner -or
        $Before.Group -cne $After.Group -or
        $Before.AreAccessRulesProtected -ne $After.AreAccessRulesProtected -or
        $Before.AreAccessRulesCanonical -ne $After.AreAccessRulesCanonical -or
        (@($Before.OrderedAceRows) -join "`n") -cne (@($After.OrderedAceRows) -join "`n")) {
        throw 'Machine-key ACL SDDL, owner/group, protection, canonicality, or ordered ACE rows changed; no trust/sign/build action is permitted.'
    }
}
