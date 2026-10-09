# Microsoft Defender signature update. The debuggee baseline disables Defender by policy (DisableAntiSpyware=1); inside the
# checkpoint the policy is removed and the services are enabled so the update runs against a live engine.
Remove-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Recurse -Force -ErrorAction SilentlyContinue
foreach ($s in 'WinDefend', 'WdNisSvc', 'WdFilter', 'WdBoot', 'WdNisDrv') { & sc.exe config $s start= auto 2>&1 | Out-Null }
& sc.exe start WinDefend 2>&1 | Out-Null
Start-Sleep -Seconds 10
$platform = Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform' -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
$exe = if ($platform) { Join-Path $platform.FullName 'MpCmdRun.exe' } else { 'C:\Program Files\Windows Defender\MpCmdRun.exe' }
$r.mpcmdrun = $exe
$r.platformBefore = (Get-Item $exe -ErrorAction SilentlyContinue).VersionInfo.FileVersion
$t = [Diagnostics.Stopwatch]::StartNew()
# 0x80070652 is ERROR_INSTALL_ALREADY_RUNNING: another installation (servicing after the boot) holds the installer. Wait it out; it is
# the same with and without the driver, so it says nothing about the driver.
for ($attempt = 1; $attempt -le 15; $attempt++) {
    $out = & $exe -SignatureUpdate 2>&1 | Out-String
    $r.exit = $LASTEXITCODE
    if ($LASTEXITCODE -eq 0 -or $out -notmatch '80070652') { break }
    Start-Sleep -Seconds 60
}
$r.attempts = $attempt
$r.duration = [math]::Round($t.Elapsed.TotalSeconds, 1)
$r.output = ($out -replace '\s+', ' ').Trim()
$r.ok = ($r.exit -eq 0)
