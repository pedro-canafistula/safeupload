# An MSI with a few hundred files: PowerShell 7 (the package is large enough to exercise the installer's temp files, the
# Windows Installer service's rollback script and many small writers).
$url = 'https://github.com/PowerShell/PowerShell/releases/download/v7.4.5/PowerShell-7.4.5-win-x64.msi'
& curl.exe -sS -L -o C:\T3\pwsh.msi $url
if (-not (Test-Path C:\T3\pwsh.msi) -or (Get-Item C:\T3\pwsh.msi).Length -lt 50MB) { throw 'download failed' }
$t = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process msiexec.exe -ArgumentList '/i C:\T3\pwsh.msi /qn /norestart /l*v C:\T3\msi.log' -Wait -PassThru
$r.duration = [math]::Round($t.Elapsed.TotalSeconds, 1)
$r.exit = $p.ExitCode
$version = ''
if (Test-Path 'C:\Program Files\PowerShell\7\pwsh.exe') { $version = (& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -Command '$PSVersionTable.PSVersion.ToString()') }
$r.version = $version
$r.ok = ($p.ExitCode -in 0, 3010) -and ($version -match '^7\.4')
