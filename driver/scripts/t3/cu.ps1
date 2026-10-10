# The monthly cumulative update through the Windows Update Agent API (what Windows Update itself uses). The runner reboots
# afterwards and checks that the driver loaded again and coverage is Ready on the new build.
$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$found = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0").Updates
$r.candidates = @($found | ForEach-Object { $_.Title })
$cu = @($found | Where-Object { $_.Title -match 'Cumulative Update' -and $_.Title -notmatch '\.NET|Preview' }) | Select-Object -First 1
if (-not $cu) { $r.ok = $false; $r.note = 'no cumulative update offered'; return }
$r.update = $cu.Title
$coll = New-Object -ComObject Microsoft.Update.UpdateColl
[void]$coll.Add($cu)
$cu.AcceptEula()
$t = [Diagnostics.Stopwatch]::StartNew()
$downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $coll; $dl = $downloader.Download()
$r.downloadResult = $dl.ResultCode
$installer = $session.CreateUpdateInstaller(); $installer.Updates = $coll; $ir = $installer.Install()
$r.duration = [math]::Round($t.Elapsed.TotalSeconds, 1)
$r.installResult = $ir.ResultCode
$r.rebootRequired = $ir.RebootRequired
$r.ok = ($dl.ResultCode -eq 2) -and ($ir.ResultCode -eq 2)
