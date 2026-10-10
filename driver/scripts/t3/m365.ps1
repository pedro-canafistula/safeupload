# Microsoft 365 Apps through the Office Deployment Tool: the workload that was very slow and then failed ("couldn't use a
# required file") with the driver loaded.
New-Item -ItemType Directory -Force -Path C:\T3\o365 | Out-Null
& curl.exe -sS -L -o C:\T3\o365\setup.exe https://officecdn.microsoft.com/pr/wsus/setup.exe
if (-not (Test-Path C:\T3\o365\setup.exe) -or (Get-Item C:\T3\o365\setup.exe).Length -lt 1MB) { throw 'ODT download failed' }
$xml = '<Configuration><Add OfficeClientEdition="64" Channel="Current"><Product ID="O365ProPlusRetail"><Language ID="en-us"/></Product></Add>' +
       '<Display Level="None" AcceptEULA="TRUE"/><Property Name="FORCEAPPSHUTDOWN" Value="TRUE"/></Configuration>'
Set-Content -LiteralPath C:\T3\o365\configuration.xml -Value $xml -Encoding UTF8
$t = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process C:\T3\o365\setup.exe -ArgumentList '/configure C:\T3\o365\configuration.xml' -Wait -PassThru
$r.duration = [math]::Round($t.Elapsed.TotalSeconds, 1)
$r.exit = $p.ExitCode
$r.ok = ($p.ExitCode -eq 0) -and (Test-Path 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE')
