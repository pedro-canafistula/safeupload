# Build-time only (run once by FirstLogonCommands from the Packer config CD). Installs the Windows-shipped OpenSSH
# server (Feature on Demand, required by Ansible's Windows SSH support), authorizes the build's throwaway public key and
# starts sshd for Packer. Ansible uses HTTPS WinRM because the pinned OS ships OpenSSH 7.7 (unsupported by Ansible SSH).
# The finalize script removes all bootstrap credentials/listeners before sysprep.
param([Parameter(Mandatory)][string] $ConfigRoot)
$ErrorActionPreference = 'Stop'
$log = 'C:\Windows\Temp\safeupload-lab-openssh.log'
Start-Transcript -Path $log -Append | Out-Null
try {
    $capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    if ($capability.State -ne 'Installed') { Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null }
    $keys = 'C:\ProgramData\ssh\administrators_authorized_keys'
    New-Item -ItemType Directory -Force -Path 'C:\ProgramData\ssh' | Out-Null
    Copy-Item -LiteralPath (Join-Path $ConfigRoot 'build_key.pub') -Destination $keys -Force
    # OpenSSH ignores administrators_authorized_keys unless only SYSTEM and Administrators can access it.
    & icacls.exe $keys /inheritance:r /grant 'SYSTEM:F' /grant '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not secure the build SSH key.' }
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -PropertyType String `
        -Value "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Force | Out-Null
    & (Join-Path $ConfigRoot 'enable-winrm.ps1')
    Set-Service -Name sshd -StartupType Automatic
    if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow | Out-Null
    }
    if ((Get-CimInstance Win32_ComputerSystem).Name -ine 'SU-LAB-BUILD') {
        Rename-Computer -NewName SU-LAB-BUILD -Force
        Restart-Computer -Force
    } else { Start-Service -Name sshd }
    'BOOTSTRAP_READY=True'
} finally { Stop-Transcript | Out-Null }
