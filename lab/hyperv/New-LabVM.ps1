#requires -Version 5.1
<#
.SYNOPSIS
Create a private local Hyper-V development VM from the generalized lab image.
.DESCRIPTION
Run in elevated Windows PowerShell 5.1 on a Windows 10/11 Pro/Enterprise Hyper-V host.
Uses an existing switch; never enables Hyper-V, changes networking, or touches another VM.
The seed VHDX contains the administrator password. Keep the VM directory private.
Use -ValidateOnly for read-only preflight. The VM is left off unless -Start is supplied.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $ImagePath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string] $ImageSha256,
    [Parameter(Mandatory)][string] $VMRoot,
    [Parameter(Mandatory)][string] $SwitchName,
    [Parameter(Mandatory)][string[]] $SshPublicKeyFiles,
    [ValidatePattern('^su-lab-[a-z0-9-]{1,40}$')][string] $Name = 'su-lab-debuggee',
    [ValidatePattern('^[A-Za-z][A-Za-z0-9-]{0,14}$')][string] $Hostname = 'SU-LAB-DEBUG',
    [Security.SecureString] $AdminPassword,
    [string[]] $TrustedCertificateFiles = @(),
    [string] $TimeZone = 'UTC',
    [ValidateRange(2,32)][int] $MemoryGiB = 4,
    [ValidateRange(1,32)][int] $Processors = 4,
    [switch] $ValidateOnly,
    [switch] $Start
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this script on a Windows Hyper-V host.' }
if ($Hostname -ieq 'WIN10-DEBUGGED') { throw 'Do not reuse the qualified target hostname.' }
foreach ($command in 'Get-VM','Get-VMSwitch','Get-VHD','New-VHD','Mount-VHD','Dismount-VHD','New-VM',
        'Set-VM','Set-VMProcessor','Set-VMFirmware','Add-VMHardDiskDrive','Get-VMHardDiskDrive',
        'Get-Disk','Initialize-Disk','New-Partition','Format-Volume','Get-Volume','Start-VM') {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "Missing $command; install/enable Hyper-V separately." }
}
$image = (Resolve-Path -LiteralPath $ImagePath).ProviderPath
if ([IO.Path]::GetExtension($image) -ine '.vhdx') { throw 'Use the VHDX from export-hyperv.sh.' }
if ((Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash -ine $ImageSha256) { throw 'Image SHA-256 mismatch.' }
$vhd = Get-VHD -Path $image
if ($vhd.VhdType -eq 'Differencing' -or $vhd.Attached) { throw 'Use an unattached standalone generalized VHDX.' }
if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "VM $Name already exists; choose a fresh name." }
$null = Get-VMSwitch -Name $SwitchName
$root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($VMRoot)
$directory = Join-Path $root $Name
if (Test-Path -LiteralPath $directory) { throw 'VM directory exists; choose a fresh location/name.' }
$null = Get-TimeZone -Id $TimeZone
$keys = @($SshPublicKeyFiles | ForEach-Object {
    $key = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $_).ProviderPath).Trim()
    if ($key -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( [^\r\n]*)?$') {
        throw 'Expected a single-line OpenSSH public key.'
    }
    $key
})
if ($keys.Count -eq 0) { throw 'Supply at least one SSH public key.' }
$certificates = @($TrustedCertificateFiles | ForEach-Object {
    $file = (Resolve-Path -LiteralPath $_).ProviderPath
    if ([IO.Path]::GetExtension($file) -notin '.cer','.crt') { throw 'Only public .cer/.crt certificates are allowed.' }
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $file
    try {
        if ($cert.HasPrivateKey) { throw 'Never put a private signing key in the seed.' }
        [Convert]::ToBase64String($cert.RawData)
    } finally { $cert.Dispose() }
})
if ($ValidateOnly) { 'HyperVPreflight=PASS'; return }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated Windows PowerShell.' }
if ($null -eq $AdminPassword) { $AdminPassword = Read-Host 'New lab administrator password (vika)' -AsSecureString }
if ($AdminPassword.Length -lt 12) { throw 'Use an administrator password of at least 12 characters.' }

# Only this fresh directory belongs to this invocation. Preserve partial failures for diagnosis.
$null = New-Item -ItemType Directory -Path $directory
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
foreach ($sid in 'S-1-5-18','S-1-5-32-544') {
    $identity = New-Object Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $directory -AclObject $acl
$disk = Join-Path $directory 'system.vhdx'
$seedDisk = Join-Path $directory 'seed.vhdx'
Copy-Item -LiteralPath $image -Destination $disk
if ((Get-FileHash -LiteralPath $disk -Algorithm SHA256).Hash -ine $ImageSha256) { throw 'Copied image SHA-256 mismatch.' }
$null = New-VHD -Path $seedDisk -Dynamic -SizeBytes 64MB
$mounted = $false
try {
    $mountedVhd = Mount-VHD -Path $seedDisk -Passthru
    $mounted = $true
    $seedDevice = $mountedVhd | Get-Disk
    if (@($seedDevice).Count -ne 1 -or $seedDevice.PartitionStyle -ne 'RAW') { throw 'Seed disk is not one fresh RAW disk.' }
    $partition = $seedDevice | Initialize-Disk -PartitionStyle GPT -PassThru |
        New-Partition -UseMaximumSize -AssignDriveLetter
    $null = $partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel cidata -Confirm:$false -Force
    $volume = $partition | Get-Volume
    if (-not $volume.DriveLetter) { throw 'Seed disk has no drive letter.' }
    # A new protected ACL removes the default volume-root grants before any password is written.
    Set-Acl -LiteralPath ($volume.DriveLetter + ':\') -AclObject $acl
    $credential = New-Object Management.Automation.PSCredential('vika', $AdminPassword)
    $seed = @{
        hostname = $Hostname; admin_user = 'vika'; admin_password = $credential.GetNetworkCredential().Password
        authorized_keys = $keys; time_zone = $TimeZone; trusted_certificates = $certificates
    }
    $json = $seed | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText(($volume.DriveLetter + ':\user-data'), $json, (New-Object Text.UTF8Encoding $false))
} finally {
    $json = $null; $seed = $null; $credential = $null
    if ($mounted) { Dismount-VHD -Path $seedDisk }
}
$vm = New-VM -Name $Name -Path $directory -Generation 2 -MemoryStartupBytes ([long]$MemoryGiB * 1GB) -VHDPath $disk -SwitchName $SwitchName
Set-VMProcessor -VM $vm -Count $Processors
Set-VM -VM $vm -AutomaticCheckpointsEnabled $false -CheckpointType Disabled -AutomaticStopAction ShutDown
Set-VMFirmware -VM $vm -EnableSecureBoot Off -FirstBootDevice (Get-VMHardDiskDrive -VM $vm | Select-Object -First 1)
# A new Generation 2 VM has no enabled virtual TPM. Do not import a VM configuration or key protector.
Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $seedDisk
if ($Start) { Start-VM -VM $vm }
[pscustomobject]@{ Name = $Name; Directory = $directory; AdminUser = 'vika'; Started = [bool]$Start; ProductQualification = $false }
