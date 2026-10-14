#requires -Version 5.1
# Real Kernel-File capture/parser and actual pool timeline; no product service, driver or purge is invoked.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'T4 purge attribution self-check requires elevation; Kernel-File capture cannot be skipped'
}
. (Join-Path $PSScriptRoot 't4\purge-attribution.ps1')
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 't4\cycles-coordinator.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Coordinator does not parse' }
$declarations = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -ceq 'Add-Type' -and
        $node.Extent.Text.Contains('public static class T4Pool')
}, $true))
if ($declarations.Count -ne 1) { throw 'Actual T4Pool declarations unavailable' }
Invoke-Expression $declarations[0].Extent.Text
$count = 0
function Assert-PurgeAttribution([bool]$Good, [string]$Label) {
    if (-not $Good) { throw ('T4 purge attribution control failed: ' + $Label) }
    $script:count++
}
$root = Join-Path $env:TEMP ('T4PurgeAttributionSelfCheck-' + [guid]::NewGuid().ToString('N'))
$diagnostic = New-T4PurgeAttribution $root
$window = $null
try {
    $window = Start-T4PurgeWindow $diagnostic 'selfcheck'
    Assert-PurgeAttribution $window.Started 'real elevated Kernel-File session start'
    $leaf = 'T4PurgeAttributionProbe-' + [guid]::NewGuid().ToString('N')
    $path = Join-Path $root ($leaf + '.txt')
    $renamed = Join-Path $root ($leaf + '-renamed.txt')
    [IO.File]::WriteAllText($path, 'Kernel-File create probe', [Text.Encoding]::ASCII)
    [IO.File]::Move($path, $renamed)
    [IO.File]::Delete($renamed)
    # A real two-second pool window flushes ETW buffers too. All deadlines are monotonic.
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Wait-T4PurgeTimeline $diagnostic 'selfcheck' 2 $window
    Assert-PurgeAttribution ($watch.ElapsedMilliseconds -ge 2000 -and $watch.ElapsedMilliseconds -lt 10000) 'two-second deadline'
    Stop-T4PurgeWindow $diagnostic $window
    Assert-PurgeAttribution ($window.Stopped -and $window.NativeReceipts.Count -eq 3 -and
        @($window.NativeReceipts | Where-Object { $_.ExitCode -ne 0 -or $_.Error }).Count -eq 0) 'start/query/stop native receipts'
    Complete-T4PurgeParse $diagnostic ($leaf + '.txt')
    $summary = $window.Summary
    Assert-PurgeAttribution ($diagnostic.Errors.Count -eq 0 -and $null -ne $summary -and -not $summary.Error) 'same ETL parser has no errors'
    Assert-PurgeAttribution ($summary.TotalCreates -gt 0 -and $summary.EventsById['12'] -gt 0 -and $summary.DistinctPaths -gt 0) 'create event 12 and paths'
    $ownCreates = @($summary.TopProcesses | Where-Object { $_.ProcessId -eq $PID -and $_.CreateCount -gt 0 })
    Assert-PurgeAttribution ($ownCreates.Count -gt 0) 'event header attributes creates to self-check PID'
    # ETW may use a device path. Compare the unique temp-directory suffix without resolving it by opening files.
    $suffix = '\' + [IO.Path]::GetFileName($root) + '\'
    $ownDirectories = @($summary.TopProcessDirectories | Where-Object {
        $_.ProcessId -eq $PID -and $_.Directory.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase) -and $_.CreateCount -gt 0
    })
    Assert-PurgeAttribution ($ownDirectories.Count -gt 0) 'temp directory under own PID has create events'
    $probeCreates = @($summary.ProbeCreates | Where-Object {
        $_.ProcessId -eq $PID -and $_.Path.EndsWith(($suffix + $leaf + '.txt'), [StringComparison]::OrdinalIgnoreCase) -and $_.CreateCount -gt 0
    })
    Assert-PurgeAttribution ($probeCreates.Count -gt 0) 'exact unique probe file under own PID has event 12'
    foreach ($name in 'Label','TotalEvents','EventsById','TotalCreates','DistinctPaths','TopProcesses',
        'TopProcessDirectories','TopDirectories','LostEvents','LostBuffers','Truncated','MaxEvents','EtlBytes','Error') {
        Assert-PurgeAttribution ($summary.PSObject.Properties.Name -contains $name) ('summary field ' + $name)
    }
    Assert-PurgeAttribution ($summary.TopProcesses.Count -le 15 -and $summary.TopProcessDirectories.Count -le 30 -and
        $summary.TopDirectories.Count -le 30 -and -not $summary.Truncated -and $summary.EtlBytes -gt 0) 'summary bounds and raw ETL'
    $saved = @(Get-Content -LiteralPath (Join-Path $root 'summary.json') -Raw | ConvertFrom-Json)
    Assert-PurgeAttribution ($saved.Count -eq 1 -and $saved[0].Label -ceq 'selfcheck') 'summary JSON receipt'
    $timeline = @(Get-Content -LiteralPath (Join-Path $root 'sufl-timeline.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-PurgeAttribution ($timeline.Count -eq 2) 'one timeline line per second'
    foreach ($line in $timeline) {
        Assert-PurgeAttribution ($line.Label -ceq 'selfcheck' -and $line.ElapsedMs -ge 0 -and $line.Qpc -gt 0) 'timeline window identity'
        foreach ($tag in 'SUfl','SUwH') {
            Assert-PurgeAttribution ($null -ne $line.$tag.NonPagedAllocs -and $null -ne $line.$tag.NonPagedFrees) ('actual pool counters ' + $tag)
        }
    }
    Assert-PurgeAttribution ($timeline[1].Qpc -gt $timeline[0].Qpc -and
        $timeline[1].ElapsedMs - $timeline[0].ElapsedMs -ge 900) 'monotonic timeline'
} catch {
    # Print the native receipts before the temporary folder is removed, so the gate receipt keeps the cause.
    if ($null -ne $window) {
        foreach ($receipt in $window.NativeReceipts) {
            'logman ' + $receipt.Label + ' exit=' + $receipt.ExitCode + ' error=' + $receipt.Error + ' text=' + (([string]$receipt.Text) -replace '\s+', ' ')
        }
    }
    foreach ($failure in $diagnostic.Errors) { 'diagnostic error: ' + $failure }
    throw
} finally {
    if ($null -ne $window -and -not $window.Stopped) { Stop-T4PurgeWindow $diagnostic $window }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
'T4PurgeAttributionSelfCheck=PASS;Controls=' + $count + ';Qualification=False'
