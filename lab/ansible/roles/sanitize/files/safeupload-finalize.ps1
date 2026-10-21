# Packer's shutdown command (the last SSH session of the build). Removes the build's SSH key and this machine's host
# keys, then generalizes and powers off. First boot generates new host keys and authorizes only the seed's keys.
$ErrorActionPreference = 'Continue'
Remove-Item -LiteralPath 'C:\ProgramData\ssh\administrators_authorized_keys' -Force -ErrorAction SilentlyContinue
Get-ChildItem -LiteralPath 'C:\ProgramData\ssh' -Filter 'ssh_host_*' -Force -ErrorAction SilentlyContinue | Remove-Item -Force
Remove-Item -LiteralPath 'C:\ProgramData\ssh\logs' -Recurse -Force -ErrorAction SilentlyContinue
Set-Service -Name sshd -StartupType Manual
Start-Process -FilePath "$env:WINDIR\System32\Sysprep\sysprep.exe" `
    -ArgumentList '/generalize', '/oobe', '/shutdown', '/quiet', '/unattend:C:\Windows\Temp\safeupload-firstboot.xml'
