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
$out = & $exe -SignatureUpdate 2>&1 | Out-String
$r.duration = [math]::Round($t.Elapsed.TotalSeconds, 1)
$r.exit = $LASTEXITCODE
$r.output = ($out -replace '\s+', ' ').Trim()
$r.ok = ($LASTEXITCODE -eq 0)
