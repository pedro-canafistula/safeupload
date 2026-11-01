#requires -Version 5.1
# Read-only candidate acceptance, inside the VM after seed/restart. This is not a product qualification gate.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $ExpectedHostname,
    [Parameter(Mandatory)][string[]] $ExpectedSshPublicKeyFiles,
    [ValidateRange(1,32)][int] $ExpectedProcessors = 4
)
$ErrorActionPreference = 'Stop'
$v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
if ("$($v.CurrentBuild).$($v.UBR)" -ne '19045.2965') { throw 'Unexpected Windows build.' }
if ($env:COMPUTERNAME -ine $ExpectedHostname) { throw 'First-boot hostname was not applied.' }
try { $secureBoot = Confirm-SecureBootUEFI } catch {
    # OVMF built without Secure Boot defines no SecureBoot variable (STATUS_VARIABLE_NOT_FOUND): it cannot be on.
    if ($_.Exception.Message -notmatch '0xC0000100') { throw }
    $secureBoot = $false
}
if ($secureBoot) { throw 'Secure Boot must be off.' }
if ((Get-Tpm).TpmPresent) { throw 'The development candidate must have no TPM.' }
$bcd = & bcdedit.exe /enum '{current}'
if ($LASTEXITCODE -ne 0 -or -not ($bcd -match '^testsigning\s+Yes\s*$')) { throw 'Test signing must be on.' }
if ((Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors -ne $ExpectedProcessors) { throw 'Unexpected CPU count/topology.' }
if ((Get-Service sshd).Status -ne 'Running') { throw 'SSH is not running.' }
$setup = Get-ItemProperty 'HKLM:\SYSTEM\Setup'
if ($setup.SystemSetupInProgress -or $setup.OOBEInProgress) { throw 'Windows setup/OOBE is incomplete.' }
if ((Get-Service WinRM).StartType -ne 'Disabled') { throw 'Build-only WinRM was not disabled.' }
if (Test-Path -LiteralPath 'C:\ProgramData\SafeUploadLabBootstrap') { throw 'Build bootstrap state remains.' }
if (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -eq 'SafeUploadLabBootstrap' }) { throw 'Build TLS certificate remains.' }
if (Get-ScheduledTask -TaskName SafeUploadLabGeneralize -ErrorAction SilentlyContinue) { throw 'One-off generalization task remains.' }
if (Get-ScheduledTask -TaskName SafeUploadLabFinishOobe -ErrorAction SilentlyContinue) { throw 'One-off OOBE task remains.' }
foreach ($file in 'oobe-pending','instance-oobe.xml') {
    if (Test-Path -LiteralPath (Join-Path 'C:\ProgramData\SafeUploadLab' $file)) { throw 'Temporary OOBE credentials/state remain.' }
}
$autologon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($autologon.DefaultPassword -or $autologon.AutoAdminLogon -eq '1') { throw 'Temporary autologon credentials remain.' }
$users = @(Get-LocalUser)
# sshd is the privilege-separation account that the Windows OpenSSH Server feature creates.
$allowedUsers = @('vika','Administrator','DefaultAccount','Guest','WDAGUtilityAccount','sshd')
if ($users | Where-Object { $_.Name -notin $allowedUsers }) { throw 'Unexpected local user accounts in the candidate.' }
$expected = @($ExpectedSshPublicKeyFiles | ForEach-Object { ([IO.File]::ReadAllText((Resolve-Path -LiteralPath $_).ProviderPath)).Trim() })
$actual = @(Get-Content -LiteralPath 'C:\ProgramData\ssh\administrators_authorized_keys' | Where-Object { $_.Trim() })
if (@(Compare-Object $expected $actual).Count -ne 0) { throw 'Authorized keys differ from the seed.' }
if (-not (Test-Path -LiteralPath 'C:\ProgramData\SafeUploadLab\seed-applied.txt')) { throw 'Seed completion receipt missing.' }
if (Get-Service SafeUploadAgent -ErrorAction SilentlyContinue) { throw 'Generalized development image unexpectedly contains SafeUpload.' }
if (Test-Path -LiteralPath 'C:\Windows\System32\drivers\SafeUpload.sys') { throw 'Development image unexpectedly contains the product driver.' }
[pscustomobject]@{
    CandidateAcceptance = 'PASS'; ProductQualification = $false
    WindowsBuild = "$($v.CurrentBuild).$($v.UBR)"; Hostname = $env:COMPUTERNAME
    UUID = (Get-CimInstance Win32_ComputerSystemProduct).UUID
    SshHostKeySha256 = (Get-FileHash 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub' -Algorithm SHA256).Hash
}
