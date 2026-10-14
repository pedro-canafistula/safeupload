#requires -Version 5.1
# Opt-in, non-qualifying helpers. Every diagnostic failure is retained, never propagated.
function Add-T4PurgeError($Diagnostic, [string]$Where, $Failure) {
    $Diagnostic.Errors += ($Where + ': ' + [string]$Failure)
}
function Invoke-T4PurgeAction($Diagnostic, [string]$Label, [scriptblock]$Action) {
    try { & $Action } catch { Add-T4PurgeError $Diagnostic $Label $_.Exception.Message }
}
function Write-T4PurgeJson([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
function New-T4PurgeAttribution([string]$Directory = 'C:\T4\purge-attribution') {
    $diagnostic = [ordered]@{ NonQualifying=$true; Directory=$Directory; Windows=@(); Controls=[ordered]@{}; Errors=@() }
    try { [void][IO.Directory]::CreateDirectory($Directory) }
    catch { Add-T4PurgeError $diagnostic 'directory' $_.Exception.Message }
    return $diagnostic
}
function Invoke-T4PurgeLogman($Diagnostic, $Window, [string]$Label, [string[]]$Arguments) {
    $fileLabel = $Label + '-' + $Window.NativeReceipts.Count
    $receipt = [ordered]@{ Label=$Label; Arguments=$Arguments; ExitCode=$null; Error=$null; Text=$null;
        Qpc=[Diagnostics.Stopwatch]::GetTimestamp() }
    try {
        $logman = Get-Command logman.exe -CommandType Application -ErrorAction Stop
        # Native stderr must be captured without PowerShell's Stop preference terminating the receipt.
        $savedPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            # Native calls set the global variable; a local assignment would shadow it and hide the exit code.
            $global:LASTEXITCODE = $null
            $receipt.Text = (& $logman.Source @Arguments 2>&1 | Out-String)
            $receipt.ExitCode = $global:LASTEXITCODE
        } finally { $ErrorActionPreference = $savedPreference }
        if ($receipt.ExitCode -ne 0) { throw ('logman exit ' + $receipt.ExitCode) }
    } catch {
        $receipt.Error = $_.Exception.Message
        Add-T4PurgeError $Diagnostic ($Window.Label + '-' + $Label) $receipt.Error
    }
    $Window.NativeReceipts += [pscustomobject]$receipt
    try {
        [IO.File]::WriteAllText((Join-Path $Diagnostic.Directory ($Window.Label + '-' + $fileLabel + '.txt')),
            [string]$receipt.Text, [Text.UTF8Encoding]::new($false))
        Write-T4PurgeJson (Join-Path $Diagnostic.Directory ($Window.Label + '-' + $fileLabel + '.receipt.json')) $receipt
    } catch { Add-T4PurgeError $Diagnostic 'native receipt write' $_.Exception.Message }
    return [pscustomobject]$receipt
}
function Save-T4PurgeProcesses($Diagnostic, $Window, [string]$Boundary) {
    try {
        $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId, Name, ParentProcessId,
            @{Name='CreationDate';Expression={ if ($_.CreationDate) { $_.CreationDate.ToString('o') } else { $null } }})
        $Window[$Boundary + 'Processes'] = $processes
        Write-T4PurgeJson (Join-Path $Diagnostic.Directory ($Window.Label + '-processes-' + $Boundary + '-' + $Window.NativeReceipts.Count + '.json')) $processes
    } catch { Add-T4PurgeError $Diagnostic ($Window.Label + ' processes ' + $Boundary) $_.Exception.Message }
}
function Start-T4PurgeWindow($Diagnostic, [string]$Label) {
    $window = [ordered]@{ Label=$Label; Session=('T4Purge-' + $Label + '-' + [guid]::NewGuid().ToString('N'));
        Etl=(Join-Path $Diagnostic.Directory ($Label + '.etl')); StartQpc=$null; EndQpc=$null;
        StartProcesses=@(); EndProcesses=@(); NativeReceipts=@(); Started=$false; Stopped=$false;
        LostEvents=$null; LostBuffers=$null; Summary=$null }
    $Diagnostic.Windows += $window
    Save-T4PurgeProcesses $Diagnostic $window 'Start'
    $window.StartQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    $receipt = Invoke-T4PurgeLogman $Diagnostic $window 'start' @('create','trace',$window.Session,
        '-o',$window.Etl,'-p','Microsoft-Windows-Kernel-File','0xC80','5','-bs','1024','-nb','64','512','-ets')
    $window.Started = $receipt.ExitCode -eq 0 -and -not $receipt.Error
    return $window
}
function Stop-T4PurgeWindow($Diagnostic, $Window) {
    if ($null -eq $Window -or $Window.Stopped) { return }
    # Query before stop, even on a failed start; raw text retains localized/unknown loss fields.
    $query = Invoke-T4PurgeLogman $Diagnostic $Window 'query' @('query',$Window.Session,'-ets')
    foreach ($field in @(@('LostEvents','(?:Events\s+Lost|Lost\s+Events)'), @('LostBuffers','(?:Buffers\s+Lost|Lost\s+Buffers)'))) {
        $match = [regex]::Match([string]$query.Text, '(?im)^\s*' + $field[1] + '\s*:\s*(\d+)\s*$')
        if ($match.Success) { $Window[$field[0]] = [long]$match.Groups[1].Value }
    }
    $receipt = Invoke-T4PurgeLogman $Diagnostic $Window 'stop' @('stop',$Window.Session,'-ets')
    $Window.Stopped = $receipt.ExitCode -eq 0 -and -not $receipt.Error
    $Window.EndQpc = [Diagnostics.Stopwatch]::GetTimestamp()
    Save-T4PurgeProcesses $Diagnostic $Window 'End'
}
function Wait-T4PurgeTimeline($Diagnostic, [string]$Label, [int]$Seconds, $Window = $null) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $origin = [Diagnostics.Stopwatch]::GetTimestamp()
    if ($null -ne $Window) { $origin = $Window.StartQpc }
    $next = 0L
    while ($watch.ElapsedMilliseconds -lt (1000L * $Seconds)) {
        if ($watch.ElapsedMilliseconds -ge $next) {
            try {
                $qpc = [Diagnostics.Stopwatch]::GetTimestamp()
                $line = [ordered]@{ Label=$Label; ElapsedMs=[long](1000.0 * ($qpc - $origin) / [Diagnostics.Stopwatch]::Frequency); Qpc=$qpc }
                foreach ($tag in 'SUfl','SUwH') {
                    $line[$tag] = [ordered]@{ NonPagedAllocs=$null; NonPagedFrees=$null }
                    try {
                        $values = [T4Pool]::Tag($tag)
                        $line[$tag].NonPagedAllocs = $values[0]; $line[$tag].NonPagedFrees = $values[1]
                    } catch { Add-T4PurgeError $Diagnostic ($Label + ' timeline ' + $tag) $_.Exception.Message }
                }
                # Shared append semantics match the coordinator; no dependency on its top-level execution.
                $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($line | ConvertTo-Json -Depth 4 -Compress) + "`r`n")
                $stream = [IO.FileStream]::new((Join-Path $Diagnostic.Directory 'sufl-timeline.jsonl'),
                    [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]'ReadWrite, Delete')
                try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
            } catch { Add-T4PurgeError $Diagnostic ($Label + ' timeline') $_.Exception.Message }
            $next += 1000L
        }
        $remaining = (1000L * $Seconds) - $watch.ElapsedMilliseconds
        if ($remaining -gt 0) { Start-Sleep -Milliseconds ([int][Math]::Min(100, $remaining)) }
    }
}
function Read-T4PurgeEtl($Diagnostic, $Window, [int]$MaxEvents = 400000, [string]$ProbeLeaf = '') {
    $summary = [ordered]@{ Label=$Window.Label; TotalEvents=0L; EventsById=@{}; TotalCreates=0L; DistinctPaths=0;
        TopProcesses=@(); TopProcessDirectories=@(); TopDirectories=@(); LostEvents=$Window.LostEvents;
        LostBuffers=$Window.LostBuffers; ProbeCreates=@(); Truncated=$false; MaxEvents=$MaxEvents; EtlBytes=$null; Error=$null }
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $processes = @{}; $pairs = @{}; $directories = @{}; $identities = @{}; $probes = @{}
    foreach ($process in @($Window.StartProcesses) + @($Window.EndProcesses)) {
        $key = [string]$process.ProcessId
        if (-not $identities.ContainsKey($key)) { $identities[$key] = @() }
        $created = [DateTime]::MinValue
        if ($process.CreationDate) { $created = [DateTime]$process.CreationDate }
        $identities[$key] += [pscustomobject]@{ Name=$process.Name; Created=$created }
    }
    try {
        $summary.EtlBytes = (Get-Item -LiteralPath $Window.Etl -ErrorAction Stop).Length
        # Stream records through bounded aggregation; do not materialize 400k EventLogRecord objects.
        Get-WinEvent -Path $Window.Etl -Oldest -MaxEvents $MaxEvents -ErrorAction Stop | ForEach-Object {
            $event = $_
            try {
                $summary.TotalEvents++
                $id = [string]$event.Id
                if (-not $summary.EventsById.ContainsKey($id)) { $summary.EventsById[$id] = 0L }
                $summary.EventsById[$id]++
                $path = $null
                foreach ($property in $event.Properties) {
                    if ($property.Value -is [string] -and $property.Value.Contains('\')) { $path = $property.Value; break }
                }
                if ($null -ne $path) {
                    [void]$paths.Add($path)
                    # Include delete/rename paths in the distinct-file directory view too.
                    $directory = $path.Substring(0,$path.LastIndexOf('\') + 1)
                    if (-not $directories.ContainsKey($directory)) {
                        $directories[$directory] = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                    }
                    [void]$directories[$directory].Add($path)
                }
                if ($event.Id -eq 12) {
                    $summary.TotalCreates++
                    $processId = [long]$event.ProcessId
                    $key = [string]$processId
                    $name = 'pid-' + $key
                    # If a PID was reused across the boundary, use the latest creation preceding this event.
                    $latestCreation = [DateTime]::MinValue
                    foreach ($identity in $identities[$key]) {
                        if ($identity.Created -le $event.TimeCreated -and $identity.Created -ge $latestCreation) {
                            $name = $identity.Name; $latestCreation = $identity.Created
                        }
                    }
                    $processKey = $key + '|' + $name
                    if (-not $processes.ContainsKey($processKey)) {
                        $processes[$processKey] = [pscustomobject]@{ ProcessId=$processId; Name=$name; CreateCount=0L }
                    }
                    $processes[$processKey].CreateCount++
                    if ($null -ne $path) {
                        # Device paths need only a separator split; no filesystem lookup or path resolution.
                        if ($ProbeLeaf -and $path.EndsWith(('\' + $ProbeLeaf), [StringComparison]::OrdinalIgnoreCase)) {
                            $probeKey = $processKey + '|' + $path
                            if (-not $probes.ContainsKey($probeKey)) {
                                $probes[$probeKey] = [pscustomobject]@{ ProcessId=$processId; Name=$name; Path=$path; CreateCount=0L }
                            }
                            $probes[$probeKey].CreateCount++
                        }
                        $pairKey = $processKey + '|' + $directory
                        if (-not $pairs.ContainsKey($pairKey)) {
                            $pairs[$pairKey] = [pscustomobject]@{ ProcessId=$processId; Name=$name; Directory=$directory; CreateCount=0L }
                        }
                        $pairs[$pairKey].CreateCount++
                    }
                }
            } finally { $event.Dispose() }
        }
    } catch {
        $summary.Error = $_.Exception.Message
        Add-T4PurgeError $Diagnostic ($Window.Label + ' ETL parse') $summary.Error
    }
    # Hitting the bound is conservatively reported as truncated (the exact-bound case is uncertain).
    $summary.Truncated = $summary.TotalEvents -ge $MaxEvents
    $summary.ProbeCreates = @($probes.Values)
    $summary.DistinctPaths = $paths.Count
    $summary.TopProcesses = @($processes.Values | Sort-Object -Property @{Expression='CreateCount';Descending=$true},ProcessId,Name | Select-Object -First 15)
    $summary.TopProcessDirectories = @($pairs.Values | Sort-Object -Property @{Expression='CreateCount';Descending=$true},ProcessId,Directory | Select-Object -First 30)
    $summary.TopDirectories = @($directories.Keys | ForEach-Object {
        [pscustomobject]@{ Directory=$_; DistinctFiles=$directories[$_].Count }
    } | Sort-Object -Property @{Expression='DistinctFiles';Descending=$true},Directory | Select-Object -First 30)
    return [pscustomobject]$summary
}
function Complete-T4PurgeParse($Diagnostic, [string]$ProbeLeaf = '') {
    foreach ($window in $Diagnostic.Windows) {
        try { $window.Summary = Read-T4PurgeEtl $Diagnostic $window -ProbeLeaf $ProbeLeaf }
        catch { Add-T4PurgeError $Diagnostic ($window.Label + ' summary') $_.Exception.Message }
    }
    try { Write-T4PurgeJson (Join-Path $Diagnostic.Directory 'summary.json') @($Diagnostic.Windows | ForEach-Object { $_.Summary }) }
    catch { Add-T4PurgeError $Diagnostic 'summary write' $_.Exception.Message }
}
function Wait-T4PurgeService([string]$State, [int]$Seconds, $OldProcess) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $outcome = [ordered]@{ Reached=$false; State=$null; ProcessId=$null; OldProcessExited=$null; ElapsedMs=0; Error=$null }
    try {
        do {
            $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction Stop
            if ($null -eq $service) { throw 'SafeUploadAgent service missing' }
            $outcome.State = $service.State; $outcome.ProcessId = $service.ProcessId
            $outcome.OldProcessExited = $null -eq $OldProcess -or $OldProcess.HasExited
            $outcome.Reached = $service.State -eq $State
            if ($State -eq 'Stopped') { $outcome.Reached = $outcome.Reached -and $service.ProcessId -eq 0 -and $outcome.OldProcessExited }
            if ($outcome.Reached) { break }
            Start-Sleep -Milliseconds 200
        } while ($watch.Elapsed.TotalSeconds -lt $Seconds)
        if (-not $outcome.Reached) { $outcome.Error = 'SCM/process deadline expired' }
    } catch { $outcome.Error = $_.Exception.Message }
    $outcome.ElapsedMs = $watch.ElapsedMilliseconds
    return [pscustomobject]$outcome
}
function Invoke-T4PurgeControls($Diagnostic, [int]$Cycle, [string]$ReadinessPath) {
    $controls = $Diagnostic.Controls
    $oldProcess = $null
    try {
        try {
            $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction Stop
            $controls.RepeatService = [pscustomobject]@{ State=$service.State; ProcessId=$service.ProcessId }
            if ($service.State -ne 'Running') { throw 'Agent is not Running for the repeat time control' }
        } catch { Add-T4PurgeError $Diagnostic 'repeat service' $_.Exception.Message }
        try { $controls.RepeatPurge = @(Invoke-T4MemoryPurge) }
        catch { Add-T4PurgeError $Diagnostic 'repeat purge' $_.Exception.Message }
        Wait-T4PurgeTimeline $Diagnostic 'purged-repeat' 30
        try { $controls.PurgedRepeat = Get-Sample $Cycle 'purged-repeat' }
        catch { Add-T4PurgeError $Diagnostic 'repeat sample' $_.Exception.Message }
        try {
            $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction Stop
            $controls.OldProcessId = $service.ProcessId
            if ($service.ProcessId -gt 0) {
                $oldProcess = Get-Process -Id $service.ProcessId -ErrorAction Stop
                # Cache a real process handle before stop to distinguish exit from PID reuse.
                $null = $oldProcess.Handle
            }
            # Submit the request without Stop-Service's unbounded SCM wait.
            $request = Invoke-CimMethod -InputObject $service -MethodName StopService -ErrorAction Stop
            $controls.StopReturnValue = $request.ReturnValue
            if ($request.ReturnValue -ne 0) { throw ('StopService return ' + $request.ReturnValue) }
        } catch { Add-T4PurgeError $Diagnostic 'agent stop request' $_.Exception.Message }
        $controls.AgentStop = Wait-T4PurgeService 'Stopped' 60 $oldProcess
        if ($controls.OldProcessId -gt 0 -and $null -eq $oldProcess) {
            $controls.AgentStop.Reached = $false
            $controls.AgentStop.OldProcessExited = $null
            $controls.AgentStop.Error = 'Old process exit could not be observed'
        }
        if (-not $controls.AgentStop.Reached) { Add-T4PurgeError $Diagnostic 'agent stop' $controls.AgentStop.Error }
        try { $controls.StoppedPurge = @(Invoke-T4MemoryPurge) }
        catch { Add-T4PurgeError $Diagnostic 'stopped purge' $_.Exception.Message }
        Wait-T4PurgeTimeline $Diagnostic 'purged-agent-stopped' 30
        try { $controls.PurgedAgentStopped = Get-Sample $Cycle 'purged-agent-stopped' }
        catch { Add-T4PurgeError $Diagnostic 'stopped sample' $_.Exception.Message }
    } catch { Add-T4PurgeError $Diagnostic 'controls' $_.Exception.Message }
    finally {
        # Always attempt restoration, including when stop or a control failed.
        try {
            $service = Get-CimInstance Win32_Service -Filter "Name='SafeUploadAgent'" -ErrorAction Stop
            if ($service.State -ne 'Running') {
                $request = Invoke-CimMethod -InputObject $service -MethodName StartService -ErrorAction Stop
                $controls.StartReturnValue = $request.ReturnValue
                if ($request.ReturnValue -ne 0) { throw ('StartService return ' + $request.ReturnValue) }
            }
        } catch { Add-T4PurgeError $Diagnostic 'agent start request' $_.Exception.Message }
        $controls.AgentRestart = Wait-T4PurgeService 'Running' 120 $null
        if (-not $controls.AgentRestart.Reached) { Add-T4PurgeError $Diagnostic 'agent restart' $controls.AgentRestart.Error }
        try {
            $controls.ReadinessOutput = @(& $ReadinessPath)
            $controls.AgentReady = [bool]($controls.ReadinessOutput -contains 'READY=True')
            if (-not $controls.AgentReady) { throw 'Agent readiness helper did not report READY=True' }
        } catch { Add-T4PurgeError $Diagnostic 'agent readiness' $_.Exception.Message }
        if ($null -ne $oldProcess) { $oldProcess.Dispose() }
        try { Write-T4PurgeJson (Join-Path $Diagnostic.Directory 'controls.json') $controls }
        catch { Add-T4PurgeError $Diagnostic 'controls write' $_.Exception.Message }
    }
}
