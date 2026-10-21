# Build-only HTTPS WinRM. Its public certificate is downloaded over Packer's authenticated SSH connection and used
# as an explicit trust anchor by Ansible. The finalize script removes the listener, certificate/key and UAC exception.
$ErrorActionPreference = 'Stop'
$directory = 'C:\ProgramData\SafeUploadLabBootstrap'
$null = New-Item -ItemType Directory -Path $directory -Force
& icacls.exe $directory /inheritance:r /grant '*S-1-5-18:(OI)(CI)F' /grant '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the bootstrap directory.' }
$policy = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$statePath = Join-Path $directory 'state.json'
if (Test-Path -LiteralPath $statePath) {
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $certificate = Get-Item ('Cert:\LocalMachine\My\' + $state.thumbprint)
    if ($certificate.FriendlyName -ne 'SafeUploadLabBootstrap') { throw 'Unexpected bootstrap certificate.' }
} else {
    $existing = Get-ItemProperty -Path $policy
    $hadUac = $null -ne $existing.PSObject.Properties['LocalAccountTokenFilterPolicy']
    $uac = if ($hadUac) { [int]$existing.LocalAccountTokenFilterPolicy } else { 0 }
    $certificate = New-SelfSignedCertificate -Type SSLServerAuthentication -DnsName localhost -CertStoreLocation Cert:\LocalMachine\My `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddDays(2) -FriendlyName SafeUploadLabBootstrap
    @{ thumbprint = $certificate.Thumbprint; had_uac = $hadUac; uac_value = $uac;
       public_interfaces = @(Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' } | Select-Object -ExpandProperty InterfaceIndex) } |
        ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
}
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
if ($null -eq $state.PSObject.Properties['public_interfaces']) {
    $state | Add-Member -NotePropertyName public_interfaces -NotePropertyValue @(Get-NetConnectionProfile | Where-Object { $_.NetworkCategory -eq 'Public' } | Select-Object -ExpandProperty InterfaceIndex)
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
}
# Win10's local WSMan provider invokes quickconfig even for HTTPS settings. Its Public-profile check does not honor
# Enable-PSRemoting's skip flag here. This is the build VM's isolated QEMU NAT adapter; finalize restores these profiles.
foreach ($index in @($state.public_interfaces)) { Set-NetConnectionProfile -InterfaceIndex ([int]$index) -NetworkCategory Private }
$pem = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($certificate.RawData, [Base64FormattingOptions]::InsertLineBreaks) + "`n-----END CERTIFICATE-----`n"
[IO.File]::WriteAllText((Join-Path $directory 'winrm.pem'), $pem, [Text.Encoding]::ASCII)
Set-Service WinRM -StartupType Automatic
Start-Service WinRM
Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null
# The local WSMan provider needs its HTTP management listener while changing service configuration.
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' } | Remove-Item -Recurse -Force
$null = New-Item WSMan:\localhost\Listener -Transport HTTPS -Address '*' -CertificateThumbprint $certificate.Thumbprint -Force
# Remove HTTP last, then use only local SCM/firewall APIs. No HTTP port is forwarded by QEMU.
Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTP' } | Remove-Item -Recurse -Force
Start-Service WinRM
New-ItemProperty -Path $policy -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force | Out-Null
Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue | Disable-NetFirewallRule
# Packer uses QEMU user networking: forwarded connections originate at its gateway, 10.0.2.2.
Get-NetFirewallRule -Name SafeUploadLabWinRM -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$null = New-NetFirewallRule -Name SafeUploadLabWinRM -DisplayName 'SafeUpload lab build HTTPS WinRM' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986 -RemoteAddress 10.0.2.2 -Profile Any
'WINRM_HTTPS_READY=True;CertificateThumbprint=' + $certificate.Thumbprint
