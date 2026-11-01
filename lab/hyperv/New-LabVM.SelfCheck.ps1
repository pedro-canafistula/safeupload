#requires -Version 5.1
# Contract controls with simulated Hyper-V cmdlets. No VM or native disk is created.
# Run on Windows PowerShell 5.1, including a Windows host without the Hyper-V role.
$ErrorActionPreference = 'Stop'
$temp = Join-Path $env:TEMP ('lab-hyperv-check-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temp
$script:mutations = 0
function Get-VM { param($Name, $ErrorAction) return $null }
function Get-VMSwitch { param($Name) [pscustomobject]@{ Name = $Name } }
function Get-VHD { param($Path) [pscustomobject]@{ VhdType = 'Dynamic'; Attached = $false } }
# Preflight must never call these. Throw even if native Hyper-V is installed on the test machine.
foreach ($command in 'New-VHD','Mount-VHD','Dismount-VHD','New-VM','Set-VM','Set-VMProcessor','Set-VMFirmware',
        'Add-VMHardDiskDrive','Get-VMHardDiskDrive','Initialize-Disk','New-Partition','Format-Volume','Start-VM') {
    Set-Item -Path ('Function:' + $command) -Value { $script:mutations++; throw 'Unexpected mutation in preflight.' }
}
function Assert-Refused([hashtable] $ArgsOverride, [string] $Message) {
    $testArgs = $script:valid.Clone()
    foreach ($key in $ArgsOverride.Keys) { $testArgs[$key] = $ArgsOverride[$key] }
    $refused = $false
    try { & "$PSScriptRoot\New-LabVM.ps1" @testArgs | Out-Null } catch { $refused = $true }
    if (-not $refused) { throw "Accepted $Message" }
}
try {
    $image = Join-Path $temp 'generalized.vhdx'
    [IO.File]::WriteAllText($image, 'preflight fixture; no virtual disk is mounted')
    $key = Join-Path $temp 'id.pub'
    [IO.File]::WriteAllText($key, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestFixture colleague@test')
    $script:valid = @{
        ImagePath = $image; ImageSha256 = (Get-FileHash $image -Algorithm SHA256).Hash
        VMRoot = (Join-Path $temp 'VMs'); SwitchName = 'existing-switch'
        SshPublicKeyFiles = @($key); ValidateOnly = $true
    }
    $result = & "$PSScriptRoot\New-LabVM.ps1" @valid
    if ($result -ne 'HyperVPreflight=PASS') { throw 'Valid preflight did not pass.' }
    Assert-Refused @{ ImageSha256 = ('0' * 64) } 'wrong image digest'
    Assert-Refused @{ Name = 'win10-debug3' } 'qualified domain name'
    Assert-Refused @{ Hostname = 'WIN10-DEBUGGED' } 'qualified hostname'
    Assert-Refused @{ SshPublicKeyFiles = @() } 'empty SSH keys'
    [IO.File]::WriteAllText($key, "ssh-ed25519 AAAA first`nssh-ed25519 AAAA second")
    Assert-Refused @{} 'multiline SSH key'
    [IO.File]::WriteAllText($key, '-----BEGIN OPENSSH PRIVATE KEY-----')
    Assert-Refused @{} 'private key'
    if ($script:mutations -ne 0) { throw 'Preflight attempted a mutation.' }
    if (Test-Path -LiteralPath $valid.VMRoot) { throw 'Preflight created a VM directory.' }
    'HyperVContractChecks=PASS; NativeHyperVRun=NOT_RUN'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
