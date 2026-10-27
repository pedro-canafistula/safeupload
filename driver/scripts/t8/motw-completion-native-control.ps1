#requires -Version 5.1
<#
  Run as interactive standard user t5actor, on unprotected fixed NTFS fixtures.
  Usage: -Label <fresh-label> [-RootParent C:\T8] or -SelfCheck.
  Does not install/change a product pair or implement a completion witness.
  CDP events are observations from a fresh Edge profile, not product authority.
  Evidence and the fresh profile remain for host collection and exact-run cleanup.
#>
[CmdletBinding()]
param([string]$Label, [string]$RootParent = 'C:\T8', [switch]$SelfCheck)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1 -or -not [Environment]::Is64BitProcess) {
    throw 'Windows PowerShell 5.1 Desktop x64 required'
}
Add-Type -Path (Join-Path $PSScriptRoot 'motw-completion-native-control.cs') -ReferencedAssemblies @(
    'System.dll', 'System.Core.dll', 'System.Net.Http.dll', 'System.Web.Extensions.dll')
[SafeUpload.T8.MotwObserver]::SelfCheck()
if ($SelfCheck) { 'T8MotwCompletionSignatureSelfCheck=PASS NativeCalls=False'; return }
if ($Label -notmatch '^[A-Za-z0-9_-]{3,40}$') { throw 'A fresh bounded label is required' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($identity.IsSystem -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Standard user required' }
$root = Join-Path $RootParent ('motw-' + $Label)
if (Test-Path -LiteralPath $root) { throw 'Fixture already exists; use a fresh label' }
[void](New-Item -ItemType Directory -Path $root)
$files = Join-Path $root 'files'; $downloads = Join-Path $files 'downloads'
[void](New-Item -ItemType Directory -Path $downloads -Force)
$edgeProfile = Join-Path $root 'edge-profile'
$edge = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
$report = [ordered]@{ Label = $Label; Qualification = $false; ProductImplementation = $false;
    Identity = $identity.Name; Sid = $identity.User.Value; Root = $root;
    OS = [Environment]::OSVersion.Version.ToString(); Edge = [Diagnostics.FileVersionInfo]::GetVersionInfo($edge).FileVersion;
    Mechanism = 'installed headed Edge; fresh profile; loopback HTTP attachment; CDP instrumentation';
    WholeVersionWitnessEstablished = $false; Cases = @(); Failures = @() }
$observer = $null; $server = $null; $cdp = $null; $browser = $null
try {
    $observer = [SafeUpload.T8.MotwObserver]::new($files)
    $server = [SafeUpload.T8.MotwDownload]::new()
    $browser = Start-Process -FilePath $edge -ArgumentList @(
        ('--user-data-dir="' + $edgeProfile + '"'), '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check', 'about:blank') -PassThru
    $report.BrowserPid = $browser.Id
    $report.BrowserStartTicks = $browser.StartTime.ToUniversalTime().Ticks
    $active = Join-Path $edgeProfile 'DevToolsActivePort'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while (-not (Test-Path -LiteralPath $active)) {
        if ($clock.Elapsed.TotalSeconds -ge 30) { throw 'Edge CDP did not become ready' }
        Start-Sleep -Milliseconds 100
    }
    $port = @(Get-Content -LiteralPath $active)
    if ($port.Count -ne 2 -or $port[0] -notmatch '^\d+$' -or $port[1] -notmatch '^/devtools/browser/') { throw 'Malformed Edge CDP endpoint' }
    $cdp = [SafeUpload.T8.MotwCdp]::new(('ws://127.0.0.1:' + $port[0] + $port[1]))
    $cdp.Send((@{ id = 1; method = 'Browser.setDownloadBehavior'; params = @{
        behavior = 'allow'; downloadPath = $downloads; eventsEnabled = $true } } | ConvertTo-Json -Compress -Depth 5))
    $reply = $cdp.Receive(10000) | ConvertFrom-Json
    if ($reply.id -ne 1 -or $null -ne $reply.PSObject.Properties['error']) { throw 'Edge rejected download instrumentation' }
    $observer.Mark('BeforeEdgeNavigation', $server.Url)
    $cdp.Send((@{ id = 2; method = 'Target.createTarget'; params = @{ url = $server.Url } } | ConvertTo-Json -Compress))
    $complete = $false
    $clock.Restart()
    while (-not $complete -and $clock.Elapsed.TotalSeconds -lt 120) {
        $remaining = [Math]::Max(1, [int](120000 - $clock.Elapsed.TotalMilliseconds))
        $message = $cdp.Receive($remaining)
        $observer.Mark('CdpReceipt', $message)
        $event = $message | ConvertFrom-Json
        if ($null -ne $event.PSObject.Properties['error']) { throw ('CDP error: ' + $message) }
        if ($null -ne $event.PSObject.Properties['method'] -and $event.method -eq 'Browser.downloadProgress') {
            if ($event.params.state -eq 'canceled') { throw 'Edge canceled the fixture download' }
            $complete = $event.params.state -eq 'completed'
        }
    }
    if (-not $complete) { throw 'Edge download completion not observed' }
    $download = Join-Path $downloads 'edge-clean.txt'
    $report.Cases += @{ Name = 'EdgeDownload'; State = [SafeUpload.T8.MotwObserver]::State($download) }
    $observer.Mark('EdgeCompletedObserved', $report.Cases[-1])
    if ((Get-Item -LiteralPath $download).Length -ne 8 * 1024 * 1024) { throw 'Incomplete Edge download' }

    # A known tagged source isolates copy semantics even if loopback Edge gives no tag.
    $source = Join-Path $files 'copy-source.txt'
    [IO.File]::Copy($download, $source)
    $zone = "[ZoneTransfer]`r`nZoneId=3`r`nHostUrl=https://example.invalid/safeupload-fixture`r`n"
    [SafeUpload.T8.MotwObserver]::SetZone($source, $zone, $false)
    foreach ($kind in @('ShellCopyHere', 'CopyItem', 'Robocopy')) {
        $targetDir = Join-Path $files $kind
        [void](New-Item -ItemType Directory -Path $targetDir)
        $target = Join-Path $targetDir 'copy-source.txt'
        $observer.Mark(('Before' + $kind), $target)
        if ($kind -eq 'ShellCopyHere') {
            $shell = New-Object -ComObject Shell.Application
            try { $shell.NameSpace($targetDir).CopyHere($source, 4 + 16 + 1024) }
            finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) }
        } elseif ($kind -eq 'CopyItem') { Copy-Item -LiteralPath $source -Destination $target }
        else {
            & robocopy.exe $files $targetDir 'copy-source.txt' /COPY:DAT /R:0 /W:0 /NFL /NDL /NJH /NJS /NP | Out-Null
            if ($LASTEXITCODE -gt 7) { throw ('Robocopy failed: ' + $LASTEXITCODE) }
        }
        $observer.Mark(($kind + 'Returned'), $target)
        $clock.Restart()
        while ($true) {
            if (Test-Path -LiteralPath $target) {
                $candidate = [SafeUpload.T8.MotwObserver]::State($target)
                $tagProperty = $candidate.PSObject.Properties['Zone']
                $lengthProperty = $candidate.PSObject.Properties['Length']
                if ($null -ne $tagProperty -and $null -ne $lengthProperty -and
                    $tagProperty.Value -ceq $zone -and $lengthProperty.Value -eq 8 * 1024 * 1024) { break }
            }
            if ($clock.Elapsed.TotalSeconds -ge 30) { throw ($kind + ' did not finish with the tagged fixture') }
            Start-Sleep -Milliseconds 10
        }
        $state = [SafeUpload.T8.MotwObserver]::State($target)
        if ($state.Zone -cne $zone -or -not $state.SameObjectAfter -or -not $state.ZoneSameObject) { throw ($kind + ' tag/identity mismatch') }
        $report.Cases += @{ Name = $kind; State = $state; Sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash }
        $observer.Mark(($kind + 'CompleteStateObserved'), $state)
    }

    # Receiving a completion notification is not a future-write cutoff.
    foreach ($path in @($download, (Join-Path $files 'ShellCopyHere\copy-source.txt'))) {
        $before = [SafeUpload.T8.MotwObserver]::State($path)
        [SafeUpload.T8.MotwObserver]::SetZone($path, 'ProbeLateField=owned-fixture', $true)
        $after = [SafeUpload.T8.MotwObserver]::State($path)
        if ($before.Identity -ne $after.Identity -or $after.Zone -notmatch 'ProbeLateField=owned-fixture') { throw 'Late-tag fixture check failed' }
        $report.Cases += @{ Name = 'PostCompletionZoneWrite'; Path = $path; SameObject = $true; Succeeded = $true }
        $observer.Mark('PostCompletionZoneWrite', $path)
    }
    $report.ServedBytes = $server.ServedBytes
    $report.ServerFailures = $server.Failures
    if ($server.Failures.Count) { throw 'Loopback fixture server reported an error' }
    $report.NativeProbeCompleted = $true
} catch {
    $report.NativeProbeCompleted = $false
    $report.Failures += $_.ToString()
} finally {
    if ($null -ne $cdp) {
        try { $cdp.Send('{"id":99,"method":"Browser.close"}') } catch { $report.Failures += ('BrowserClose: ' + $_.Exception.Message) }
        $cdp.Dispose()
    }
    if ($null -ne $server) { $server.Dispose() }
    if ($null -ne $browser) {
        if (-not $browser.WaitForExit(10000)) { $report.Failures += 'Owned Edge browser did not exit; preserve fixture' }
        $report.BrowserExited = $browser.HasExited
    }
    if ($null -ne $observer) {
        $observer.Dispose()
        [IO.File]::WriteAllText((Join-Path $root 'observations.json'), $observer.Results(), [Text.Encoding]::UTF8)
    }
    [IO.File]::WriteAllText((Join-Path $root 'result.json'), ($report | ConvertTo-Json -Depth 12), [Text.Encoding]::UTF8)
}
$report | ConvertTo-Json -Compress -Depth 12
if (-not $report.NativeProbeCompleted -or $report.Failures.Count) { throw ('Native probe incomplete; evidence=' + $root) }
'T8MotwNativeProbe=COMPLETE WholeVersionWitnessEstablished=False Qualification=False'
