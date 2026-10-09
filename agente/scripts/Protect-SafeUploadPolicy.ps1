#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
Gives C:\ProgramData\SafeUpload and policy.json the exact protected ACL the agent insists on.

.DESCRIPTION
The agent refuses to read a policy file whose owner or access list differs from this, instead of repairing it: a file a standard
user could write may already hold a weakened policy. Owner SYSTEM; inheritance removed; full control for SYSTEM and Administrators
only (container/object inherit on the directory, no inheritance flags on the file); no entry for any standard user.
Run it after writing or replacing policy.json and before installing the agent or rebooting. Editing icacls flags by hand does not
produce this: `(OI)(CI)` on the file adds inheritance flags the verifier rejects.
#>
[CmdletBinding()]
param(
    [string] $PolicyPath = 'C:\ProgramData\SafeUpload\policy.json'
)

$ErrorActionPreference = 'Stop'
$systemSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administratorsSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$directory = Split-Path -Parent $PolicyPath

if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory) }

$directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
$directoryAcl.SetAccessRuleProtection($true, $false)
$directoryAcl.SetOwner($systemSid)
$childFlags = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
foreach ($sid in $systemSid, $administratorsSid) {
    $directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl, $childFlags,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
}
Set-Acl -LiteralPath $directory -AclObject $directoryAcl

if (-not (Test-Path -LiteralPath $PolicyPath)) { throw "No policy file at $PolicyPath; write it first." }
$fileAcl = [Security.AccessControl.FileSecurity]::new()
$fileAcl.SetAccessRuleProtection($true, $false)
$fileAcl.SetOwner($systemSid)
foreach ($sid in $systemSid, $administratorsSid) {
    $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]::None,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow))
}
Set-Acl -LiteralPath $PolicyPath -AclObject $fileAcl

Write-Output "PolicyAclApplied=True"
Write-Output ("Directory=" + $directory)
Write-Output ("File=" + $PolicyPath)
