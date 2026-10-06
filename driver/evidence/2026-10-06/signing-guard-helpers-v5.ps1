# Pure in-memory helpers shared by the V5 signing guard scripts.
# This file deliberately does not inspect stores, files, ACLs, VMs, or keys.

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

function Get-SafeUploadFileSystemRuleAceRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier] $Sid,
        [Parameter(Mandatory)][Security.AccessControl.FileSystemAccessRule] $Rule
    )
    return ('{0}|{1}|{2}|{3}|{4}|{5}' -f $Sid.Value,$Rule.AccessControlType.ToString(),[int]$Rule.FileSystemRights,$Rule.InheritanceFlags.ToString(),$Rule.PropagationFlags.ToString(),[bool]$Rule.IsInherited)
}

function Get-SafeUploadAclAceRows {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object] $AclObject)
    $rows = @($AclObject.Access | ForEach-Object {
        $aceSid = Get-SafeUploadSidValue -IdentityReference $_.IdentityReference
        '{0}|{1}|{2}|{3}|{4}|{5}' -f $aceSid,$_.AccessControlType.ToString(),[int]$_.FileSystemRights,$_.InheritanceFlags.ToString(),$_.PropagationFlags.ToString(),[bool]$_.IsInherited
    } | Sort-Object)
    return $rows
}

function Assert-SafeUploadNoBroadAllowAces {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]] $AceRows)
    $broadSids = @('S-1-1-0','S-1-5-11','S-1-5-32-545')
    foreach ($row in $AceRows) {
        $parts = $row -split '\|',6
        if ($parts.Count -eq 6 -and $broadSids -contains $parts[0] -and $parts[1] -ceq 'Allow') {
            throw 'Broad Everyone, Authenticated Users, or Users allow ACE is present; refusing ACL change.'
        }
    }
}

function Assert-SafeUploadSystemAndAdministratorsAllowAces {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]] $AceRows)
    foreach ($requiredSid in @('S-1-5-18','S-1-5-32-544')) {
        $requiredRows = @($AceRows | Where-Object {
            $parts = $_ -split '\|',6
            $parts.Count -eq 6 -and $parts[0] -ceq $requiredSid -and $parts[1] -ceq 'Allow'
        })
        if ($requiredRows.Count -eq 0) {
            throw 'Original SYSTEM or Administrators allow ACE is missing; refusing ACL change.'
        }
    }
}

function Assert-SafeUploadExactReadAclChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $BeforeAceRows,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $AfterAceRows,
        [Parameter(Mandatory)][string] $TargetSid,
        [Parameter(Mandatory)][string] $ExpectedReadAceRow,
        [Parameter(Mandatory)][int] $ExpectedReadMask,
        [Parameter(Mandatory)][string] $OwnerBefore,
        [Parameter(Mandatory)][string] $OwnerAfter,
        [Parameter(Mandatory)][string] $GroupBefore,
        [Parameter(Mandatory)][string] $GroupAfter,
        [Parameter(Mandatory)][bool] $ProtectedBefore,
        [Parameter(Mandatory)][bool] $ProtectedAfter
    )

    if ($OwnerBefore -cne $OwnerAfter -or $GroupBefore -cne $GroupAfter -or $ProtectedBefore -ne $ProtectedAfter) {
        throw 'Key ACL owner, group, or protection state changed.'
    }

    $expectedParts = $ExpectedReadAceRow -split '\|',6
    if ($expectedParts.Count -ne 6 -or $expectedParts[0] -cne $TargetSid -or $expectedParts[1] -cne 'Allow' -or
        [int]$expectedParts[2] -ne $ExpectedReadMask -or $expectedParts[3] -cne 'None' -or
        $expectedParts[4] -cne 'None' -or $expectedParts[5] -cne 'False') {
        throw 'Constructed minimum-read ACE does not match the expected explicit allow rule.'
    }

    $beforeTargetRows = @($BeforeAceRows | Where-Object { ($_ -split '\|',2)[0] -ceq $TargetSid })
    $afterTargetRows = @($AfterAceRows | Where-Object { ($_ -split '\|',2)[0] -ceq $TargetSid })
    if ($beforeTargetRows.Count -gt 1 -or $afterTargetRows.Count -ne 1 -or $afterTargetRows[0] -cne $ExpectedReadAceRow) {
        throw 'Target SID does not have exactly one explicit ACE with the constructed minimum-read mask.'
    }
    if ($beforeTargetRows.Count -eq 1 -and $beforeTargetRows[0] -cne $ExpectedReadAceRow) {
        throw 'Existing target SID ACE is broader or otherwise differs from the exact constructed minimum-read ACE.'
    }

    Assert-SafeUploadSystemAndAdministratorsAllowAces -AceRows $BeforeAceRows

    $beforeCounts = @{}
    foreach ($row in $BeforeAceRows) {
        if (-not $beforeCounts.ContainsKey($row)) { $beforeCounts[$row] = 0 }
        $beforeCounts[$row]++
    }
    $afterCounts = @{}
    foreach ($row in $AfterAceRows) {
        if (-not $afterCounts.ContainsKey($row)) { $afterCounts[$row] = 0 }
        $afterCounts[$row]++
    }
    $addedRows = @()
    $removedRows = @()
    foreach ($row in @($beforeCounts.Keys + $afterCounts.Keys | Sort-Object -Unique)) {
        $beforeCount = if ($beforeCounts.ContainsKey($row)) { $beforeCounts[$row] } else { 0 }
        $afterCount = if ($afterCounts.ContainsKey($row)) { $afterCounts[$row] } else { 0 }
        for ($n = 0; $n -lt ($beforeCount - $afterCount); $n++) { $removedRows += $row }
        for ($n = 0; $n -lt ($afterCount - $beforeCount); $n++) { $addedRows += $row }
    }

    if ($removedRows.Count -ne 0) { throw 'ACL verification found a removed or rewritten ACE.' }
    if ($beforeTargetRows.Count -eq 0) {
        if ($addedRows.Count -ne 1 -or $addedRows[0] -cne $ExpectedReadAceRow) {
            throw 'ACL delta is not exactly the original ACE multiset plus the constructed minimum-read ACE.'
        }
    } elseif ($addedRows.Count -ne 0) {
        throw 'ACL changed even though the exact minimum-read target ACE already existed.'
    }

    return [pscustomobject][ordered]@{
        AddedAceRows = @($addedRows)
        RemovedAceRows = @($removedRows)
        ExpectedReadMask = $ExpectedReadMask
        ExpectedReadAceRow = $ExpectedReadAceRow
    }
}
