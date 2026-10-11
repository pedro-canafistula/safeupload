<#
Source-pinned runtime fixture for the SafeUpload v20 minifilter unload lifecycle.
Run only on the explicitly isolated WIN10-DEBUGGED qualification VM. This fixture
uses real Filter Manager/service/file APIs. It does not simulate FltStartFiltering
failure or force callback ordering; those require a separately approved diagnostic
hook. A missing target boundary is INCONCLUSIVE, never PASS by timeout or by a
successful generic unload alone.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('voluntary-precommit', 'mandatory-held-owner')]
    [string] $Case,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedFeatureSha256,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedInspectorSha256,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ExpectedServicePackageSha256,
    [ValidateRange(2, 60)]
    [int] $MandatoryHoldSeconds = 8
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$helperPath = Join-Path $PSScriptRoot 'StagedTestAgent.ps1'
$expectedHelperSha256 = 'abd9c67925a4a18b4635bb4b1d21b35cd033453d6ca0c03acf46246472aa6dd7'
if ((Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash -ne $expectedHelperSha256) {
    throw 'Pinned StagedTestAgent helper hash mismatch.'
}
. $helperPath

$documents = Join-Path $env:USERPROFILE 'Documents'
$installedDriver = 'C:\Windows\System32\drivers\SafeUpload.sys'
$expectedOriginalDriver = 'ADA9D05AB6AECDD2B6C521B0CE529FC06C732154ACB3EE85439FBDC8AA80DFCE'
$featureDriver = Join-Path $documents 'SafeUpload-stage-prototype.sys'
$inspector = Join-Path $documents 'SafeUpload.Inspector.input.exe'
$servicePackage = Join-Path $documents 'stage-service-publish.zip'
$serviceDirectory = Join-Path $documents ('SafeUpload-v20-unload-service-' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $documents ('SafeUpload-original-before-unload-lifecycle-' + [guid]::NewGuid().ToString('N') + '.sys')
$diskImage = Join-Path $documents ('SafeUpload-v20-unload-' + [guid]::NewGuid().ToString('N') + '.vhdx')
$diskpart = $diskImage + '.diskpart.txt'
$scope = 'S:\SafeUpload\Escopo Monitorado'
$journal = 'C:\ProgramData\SafeUpload\staging-journal'
$id = [guid]::NewGuid().ToString('N')
$evidenceDir = Join-Path $documents ('SafeUpload-v20-unload-evidence-' + $id)
$eventLog = Join-Path $evidenceDir 'events.log'
$firstPath = Join-Path $scope ($id + '-first.txt')
$secondPath = Join-Path $scope ($id + '-second.txt')
$holdPath = Join-Path $scope ($id + '-mandatory.txt')
$observerScript = Join-Path $evidenceDir 'destination-observer.ps1'
$observerRules = Join-Path $evidenceDir 'destination-observer-rules.json'
$observerLog = Join-Path $evidenceDir 'destination-observer.log'
$observerOut = $observerLog + '.out'
$observerErr = $observerLog + '.err'
$observerStop = Join-Path $evidenceDir 'destination-observer.stop'
$inspectorTaskName = 'SafeUpload-v20-unload-inspector-' + $id
$mandatoryOut = Join-Path $evidenceDir 'sc-stop.stdout'
$mandatoryErr = Join-Path $evidenceDir 'sc-stop.stderr'
$mandatoryExitPath = Join-Path $evidenceDir 'sc-stop.exit'
$agent = $null
$observer = $null
$heldFile = $null
$secondFile = $null
$mandatoryFile = $null
$mandatoryProcess = $null
$replaced = $false
$filterLoaded = $false
$mounted = $false
$verifierEnabled = $false
$observerRulesMap = @{}
$cleanupPaths = New-Object System.Collections.Generic.List[string]
$statusTaskNames = New-Object System.Collections.Generic.List[string]
$scenarioResult = 'INCONCLUSIVE'
$scenarioReason = 'Target runtime boundary was not observed.'
$restoreComplete = $false
$serviceEpochBefore = $null
$driverServiceConfigBefore = $null
$expectedObserverFinal = @{}
$finalizationIssues = New-Object System.Collections.Generic.List[string]
$observerRequired = $false
$captureSequence = 0
$stopResponseRecorded = $false
$agentServiceBaseline = $null
$agentServiceRestored = $false
$observerStoppedAndValidated = $false
$originalDriverRestored = $false
$verifierRestored = $false
$driverServiceRestored = $false
$statusTasksRemoved = $false
$privateStageCleaned = $false
$disposableVolumeDetached = $false

function Write-Event([string] $Name, [string] $Value) {
    $line = 'UTC=' + [DateTime]::UtcNow.ToString('o') + ' ' + $Name + '=' + $Value
    Write-Host $line
    if (Test-Path -LiteralPath $evidenceDir) { Add-Content -LiteralPath $eventLog -Value $line -Encoding UTF8 -ErrorAction Stop }
}

function Add-FinalizationIssue([string] $Message) {
    [void]$finalizationIssues.Add($Message)
    Write-Event 'FinalizationIssue' ($Message -replace '\s+', ' ')
}

function Invoke-Diskpart([string[]] $Commands) {
    Set-Content -LiteralPath $diskpart -Value $Commands -Encoding ASCII
    $result = & diskpart.exe /s $diskpart 2>&1
    $result | Out-Host
    if ($LASTEXITCODE -ne 0 -or $result -match 'DiskPart has encountered an error') {
        throw 'Disposable volume operation failed.'
    }
}

function Invoke-CapturedCommand([string] $Name, [string] $FilePath, [string[]] $Arguments) {
    ++$script:captureSequence
    $stem = '{0:D3}-{1}' -f $script:captureSequence, ([regex]::Replace($Name, '[^A-Za-z0-9_-]', '_'))
    $stdoutPath = Join-Path $evidenceDir ($stem + '.stdout')
    $stderrPath = Join-Path $evidenceDir ($stem + '.stderr')
    $exitPath = Join-Path $evidenceDir ($stem + '.exit')
    $startedUtc = [DateTime]::UtcNow.ToString('o')
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -Wait -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
    $completedUtc = [DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText($exitPath, [string]$process.ExitCode)
    $stdout = if (Test-Path -LiteralPath $stdoutPath) { [IO.File]::ReadAllText($stdoutPath) } else { '' }
    $stderr = if (Test-Path -LiteralPath $stderrPath) { [IO.File]::ReadAllText($stderrPath) } else { '' }
    $argumentRecord = ConvertTo-Json -InputObject @($Arguments) -Compress
    Write-Event 'RawCommand' ('name=' + $Name + ';command=' + $FilePath + ';arguments=' + $argumentRecord +
        ';startedUtc=' + $startedUtc + ';completedUtc=' + $completedUtc + ';exit=' + $process.ExitCode + ';stdout=' + $stdoutPath +
        ';stderr=' + $stderrPath + ';exitFile=' + $exitPath)
    $result = [pscustomobject]@{ ExitCode=[int]$process.ExitCode; Stdout=$stdout; Stderr=$stderr;
        StdoutPath=$stdoutPath; StderrPath=$stderrPath; ExitPath=$exitPath }
    if ($result -isnot [pscustomobject] -or $result.PSObject.Properties.Name -notcontains 'Stdout') {
        throw 'Captured command did not produce one structured result object.'
    }
    return $result
}

function Get-FilterStateFromCapture($Capture, [string] $Context) {
    if ($null -eq $Capture -or [int]$Capture.ExitCode -ne 0) {
        $exit = if ($null -eq $Capture) { 'missing' } else { [string]$Capture.ExitCode }
        throw ('Filter state is UNKNOWN because fltmc filters failed during ' + $Context + ';exit=' + $exit)
    }
    $text = [string]$Capture.Stdout + "`n" + [string]$Capture.Stderr
    if ($text -notmatch '(?mi)^\s*Filter\s+Name\b') {
        throw ('Filter state is UNKNOWN because the successful fltmc filters output was not recognizable during ' + $Context)
    }
    if ($text -match '(?mi)^\s*SafeUpload\s') { return 'PRESENT' }
    return 'ABSENT'
}

function Get-FilterState([string] $Context = 'filter-state-query') {
    $capture = Invoke-CapturedCommand $Context 'fltmc.exe' @('filters')
    $state = Get-FilterStateFromCapture $capture $Context
    Write-Event 'FilterStateQuery' ($Context + ';state=' + $state + ';exit=' + $capture.ExitCode +
        ';stdout=' + $capture.StdoutPath + ';stderr=' + $capture.StderrPath + ';exitFile=' + $capture.ExitPath)
    return $state
}

function Test-FilterLoaded {
    return ((Get-FilterState 'fltmc-filters-state') -eq 'PRESENT')
}

function Write-FilterSnapshot([string] $Phase) {
    $filters = Invoke-CapturedCommand ($Phase + '-fltmc-filters') 'fltmc.exe' @('filters')
    $filterState = Get-FilterStateFromCapture $filters $Phase
    $instanceSummary = 'skipped;filter-confirmed-absent'
    if ($filterState -eq 'PRESENT') {
        $instances = Invoke-CapturedCommand ($Phase + '-fltmc-instances') 'fltmc.exe' @('instances','-f','SafeUpload')
        if ($instances.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace([string]$instances.Stdout + [string]$instances.Stderr)) {
            throw ('Filter instance state is UNKNOWN during ' + $Phase + ';exit=' + $instances.ExitCode)
        }
        $instanceSummary = 'exit=' + $instances.ExitCode + ';stdout=' + $instances.StdoutPath +
            ';stderr=' + $instances.StderrPath + ';exitFile=' + $instances.ExitPath
    }
    Write-Event 'FilterSnapshot' ($Phase + ';filterState=' + $filterState + ';filtersExit=' + $filters.ExitCode +
        ';filtersStdout=' + $filters.StdoutPath + ';filtersStderr=' + $filters.StderrPath +
        ';filtersExitFile=' + $filters.ExitPath + ';instances=' + $instanceSummary)
    return ($filterState -eq 'PRESENT')
}

function Get-DriverServiceConfig([string] $Phase) {
    $capture = Invoke-CapturedCommand ('sc-qc-' + $Phase) 'sc.exe' @('qc','SafeUpload')
    if ($capture.ExitCode -ne 0) { throw ('Could not query SafeUpload service configuration during ' + $Phase) }
    Write-Event 'DriverServiceConfig' ($Phase + ';scExit=' + $capture.ExitCode + ';stdout=' + $capture.StdoutPath +
        ';stderr=' + $capture.StderrPath)
    return (($capture.Stdout + "`n" + $capture.Stderr) -replace '\s+', ' ').Trim()
}

function Get-DriverServiceSnapshot([string] $Phase) {
    $capture = Invoke-CapturedCommand ('sc-query-' + $Phase) 'sc.exe' @('query','SafeUpload')
    $text = ($capture.Stdout + "`n" + $capture.Stderr) -replace '\s+', ' '
    $stateMatch = [regex]::Match($text, 'STATE\s*:\s*(\d+)')
    $querySucceeded = ($capture.ExitCode -eq 0 -and $stateMatch.Success)
    $state = if ($querySucceeded) { $stateMatch.Groups[1].Value } else { 'UNKNOWN' }
    Write-Event 'DriverServiceStatus' ($Phase + ';scExit=' + $capture.ExitCode + ';stdout=' + $capture.StdoutPath +
        ';stderr=' + $capture.StderrPath + ';exitFile=' + $capture.ExitPath + ';querySucceeded=' + $querySucceeded + ';state=' + $state)
    return [pscustomobject]@{ ExitCode=$capture.ExitCode; QuerySucceeded=$querySucceeded; State=$state; Text=$text;
        StdoutPath=$capture.StdoutPath; StderrPath=$capture.StderrPath; ExitPath=$capture.ExitPath }
}

function Record-ScStopProcessExit([System.Diagnostics.Process] $Process) {
    $Process.Refresh()
    if (-not $Process.HasExited -or $script:stopResponseRecorded) { return }
    [IO.File]::WriteAllText($mandatoryExitPath, [string]$Process.ExitCode)
    Write-Event 'ScStopProcessExitObserved' ('exit=' + $Process.ExitCode + ';commandAccepted=' + ($Process.ExitCode -eq 0) +
        ';exitObservedUtc=' + [DateTime]::UtcNow.ToString('o') + ';stdout=' + $mandatoryOut +
        ';stderr=' + $mandatoryErr + ';exitFile=' + $mandatoryExitPath)
    $script:stopResponseRecorded = $true
}

function Test-FilterAttached([string] $Drive) {
    $capture = Invoke-CapturedCommand 'fltmc-instance-attach-state' 'fltmc.exe' @('instances','-f','SafeUpload')
    if ($capture.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace([string]$capture.Stdout + [string]$capture.Stderr)) {
        throw ('Filter attachment state is UNKNOWN because fltmc instances failed during attach check;exit=' + $capture.ExitCode)
    }
    return (([string]$capture.Stdout + "`n" + [string]$capture.Stderr) -match ('(?mi)^.*' + [regex]::Escape($Drive)))
}

function Wait-FilterAttached([string] $Drive, [int] $Seconds = 30) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (Test-FilterAttached $Drive) { return $true }
        Start-Sleep -Milliseconds 250
    } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
    return $false
}

function Assert-AgentServiceRestored($AgentRecord) {
    if ($null -eq $AgentRecord -or -not $AgentRecord.IsService) { return }
    $keyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $AgentRecord.ServiceName
    if ($AgentRecord.ServiceCreated) {
        if (Test-Path -LiteralPath $keyPath) { throw 'Test-created agent service remains registered after cleanup.' }
        return
    }
    $original = $AgentRecord.OriginalService
    if ($null -eq $original -or -not (Test-Path -LiteralPath $keyPath)) {
        throw 'Preexisting agent service configuration could not be verified after restoration.'
    }
    $key = Get-Item -LiteralPath $keyPath
    $values = Get-ItemProperty -LiteralPath $keyPath
    $expectedObjectName = if ([string]::IsNullOrWhiteSpace([string]$original.ObjectName)) { 'LocalSystem' } else { [string]$original.ObjectName }
    if ([string]$values.ImagePath -cne [string]$original.ImagePath -or
        $key.GetValueKind('ImagePath').ToString() -cne [string]$original.ImagePathKind -or
        [int]$values.Start -ne [int]$original.Start -or
        [string]$values.ObjectName -cne $expectedObjectName) {
        throw 'Preexisting agent service registry configuration differs from the saved original.'
    }
    $sidCapture = Invoke-CapturedCommand 'agent-service-sid-type-restored' 'sc.exe' @('qsidtype',$AgentRecord.ServiceName)
    $sidOutput = $sidCapture.Stdout + "`n" + $sidCapture.Stderr
    if ($sidCapture.ExitCode -ne 0) { throw 'Could not query restored agent service SID type.' }
    $expectedSid = switch ([int]$original.ServiceSidType) {
        1 { 'UNRESTRICTED' }
        3 { 'RESTRICTED' }
        default { 'NONE' }
    }
    if ($sidOutput -notmatch ('SERVICE_SID_TYPE:\s+' + $expectedSid)) {
        throw 'Preexisting agent service SID type differs from the saved original.'
    }
    $service = Get-CimInstance Win32_Service -Filter ("Name='" + $AgentRecord.ServiceName + "'") -ErrorAction Stop
    if ($null -eq $service -or $service.State -ne 'Stopped') { throw 'Preexisting agent service did not return to its stopped baseline.' }
}

function Get-AgentServiceBaseline {
    $serviceName = 'SafeUploadAgent'
    $keyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $serviceName
    if (-not (Test-Path -LiteralPath $keyPath)) { return [pscustomobject]@{ Exists=$false; ServiceName=$serviceName } }
    $service = Get-CimInstance Win32_Service -Filter ("Name='" + $serviceName + "'") -ErrorAction Stop
    if ($null -eq $service -or $service.State -ne 'Stopped') {
        throw 'SafeUploadAgent must be stopped while its restoration baseline is captured.'
    }
    $key = Get-Item -LiteralPath $keyPath
    $values = Get-ItemProperty -LiteralPath $keyPath
    $sidType = if ($null -eq $values.PSObject.Properties['ServiceSidType']) { 0 } else { [int]$values.ServiceSidType }
    $objectName = if ([string]::IsNullOrWhiteSpace([string]$values.ObjectName)) { 'LocalSystem' } else { [string]$values.ObjectName }
    return [pscustomobject]@{
        Exists=$true; ServiceName=$serviceName; ImagePath=[string]$values.ImagePath
        ImagePathKind=$key.GetValueKind('ImagePath').ToString(); Start=[int]$values.Start
        ObjectName=$objectName; ServiceSidType=$sidType
    }
}

function Assert-AgentServiceBaseline($Baseline) {
    if ($null -eq $Baseline) { throw 'SafeUploadAgent restoration baseline was not captured.' }
    $keyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $Baseline.ServiceName
    if (-not $Baseline.Exists) {
        if (Test-Path -LiteralPath $keyPath) { throw 'Test-created agent service remains registered after restoration.' }
    } else {
        if (-not (Test-Path -LiteralPath $keyPath)) { throw 'Preexisting agent service registration is missing after restoration.' }
        $key = Get-Item -LiteralPath $keyPath
        $values = Get-ItemProperty -LiteralPath $keyPath
        $sidType = if ($null -eq $values.PSObject.Properties['ServiceSidType']) { 0 } else { [int]$values.ServiceSidType }
        $objectName = if ([string]::IsNullOrWhiteSpace([string]$values.ObjectName)) { 'LocalSystem' } else { [string]$values.ObjectName }
        if ([string]$values.ImagePath -cne [string]$Baseline.ImagePath -or
            $key.GetValueKind('ImagePath').ToString() -cne [string]$Baseline.ImagePathKind -or
            [int]$values.Start -ne [int]$Baseline.Start -or $objectName -cne [string]$Baseline.ObjectName -or
            $sidType -ne [int]$Baseline.ServiceSidType) {
            throw 'SafeUploadAgent service registry configuration differs from the recorded baseline.'
        }
        $service = Get-CimInstance Win32_Service -Filter ("Name='" + $Baseline.ServiceName + "'") -ErrorAction Stop
        if ($null -eq $service -or $service.State -ne 'Stopped') {
            throw 'SafeUploadAgent did not return to the recorded stopped state.'
        }
    }
    if (@(Get-Process -Name 'SafeUpload.Agent.Service' -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'SafeUploadAgent process remains active after restoration.'
    }
}

function Confirm-StatusTasksRemoved {
    $tasks = @(Get-ScheduledTask -ErrorAction Stop)
    foreach ($taskName in $script:statusTaskNames) {
        if (@($tasks | Where-Object { $_.TaskName -eq $taskName }).Count -ne 0) {
            throw ('Inspector status task remains registered: ' + $taskName)
        }
    }
    return $true
}

function Read-Manifest([string] $Path) {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
            try {
                $reader = [IO.StreamReader]::new($stream)
                try { return ($reader.ReadToEnd() | ConvertFrom-Json) }
                finally { $reader.Dispose() }
            } finally { $stream.Dispose() }
        } catch [IO.IOException] { Start-Sleep -Milliseconds 20 }
    }
    throw ('Journal manifest remained unavailable: ' + $Path)
}

function Find-Entry([string] $Destination) {
    if (-not (Test-Path -LiteralPath $journal)) { return @() }
    return @((Get-ChildItem -LiteralPath $journal -Filter '*.json' -File -ErrorAction Stop |
        Where-Object { $_.Name -ne 'driver-epoch.state' } | ForEach-Object {
            try { Read-Manifest $_.FullName } catch { $null }
        } | Where-Object { $null -ne $_ -and $_.Transfer.DestinationPath -ieq $Destination }))
}

function Wait-Entry([string] $Destination, [int] $State, [int] $Seconds = 120) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $entries = Find-Entry $Destination
        if ($entries.Count -eq 1 -and [int]$entries[0].State -eq $State) { return $entries[0] }
        if ($entries.Count -gt 1) { throw ('Multiple journal entries name the exact destination: ' + $Destination) }
        Start-Sleep -Milliseconds 200
    } while ($clock.Elapsed.TotalSeconds -lt $Seconds)
    if ($entries.Count -eq 1) { throw ('Journal state did not reach ' + $State + '; observed ' + $entries[0].State) }
    throw ('No exact journal entry appeared for ' + $Destination)
}

function Get-EpochRecord {
    $path = Join-Path $journal 'driver-epoch.state'
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    return (Read-Manifest $path)
}

function Save-EpochEvidence([string] $Name) {
    $source = Join-Path $journal 'driver-epoch.state'
    if (-not (Test-Path -LiteralPath $source)) { throw 'Durable service epoch record is missing.' }
    $destination = Join-Path $evidenceDir ($Name + '.epoch.json')
    [IO.File]::Copy($source, $destination, $true)
    $sourceBytes = [IO.File]::ReadAllBytes($source)
    $copyBytes = [IO.File]::ReadAllBytes($destination)
    if ([Convert]::ToBase64String($sourceBytes) -cne [Convert]::ToBase64String($copyBytes)) {
        throw 'Copied durable service epoch evidence differs from the journal bytes.'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = [BitConverter]::ToString($sha.ComputeHash($copyBytes)).Replace('-', '') }
    finally { $sha.Dispose() }
    Write-Event 'EpochEvidenceCopy' ('name=' + $Name + ';sha256=' + $digest + ';path=' + $destination)
}

function Get-ContentSha256([string] $Text) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ('SHA256:' + [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '')) }
    finally { $sha.Dispose() }
}

function Save-ObserverRules {
    $temp = $observerRules + '.next'
    [IO.File]::WriteAllText($temp, ($observerRulesMap | ConvertTo-Json -Depth 4))
    if (Test-Path -LiteralPath $observerRules) {
        [IO.File]::Replace($temp, $observerRules, $null)
    } else {
        [IO.File]::Move($temp, $observerRules)
    }
}

function Set-ObserverAllowance([string] $Path, [string] $AllowedToken) {
    # Keep ABSENT permitted while a staged publication atomically replaces it.
    # The final independent sample below separately requires the exact payload.
    $allowed = @($observerRulesMap[$Path])
    if ($allowed -notcontains 'ABSENT') { $allowed += 'ABSENT' }
    if ($allowed -notcontains $AllowedToken) { $allowed += $AllowedToken }
    $observerRulesMap[$Path] = $allowed
    Save-ObserverRules
    Write-Event 'ObserverAllowance' ($Path + ':ABSENT|' + $AllowedToken)
}

function Start-ByteObserver {
    $watch = @'
$ErrorActionPreference = 'Stop'
$rulesPath = '__RULES__'
$logPath = '__LOG__'
$stopPath = '__STOP__'
$samples = 0; $gaps = 0; $leaks = 0; $lastError = ''
$lastSeen = [ordered]@{}
$ready = $false
do {
    try {
        $rules = Get-Content -LiteralPath $rulesPath -Raw | ConvertFrom-Json
        $sampledThisPass = 0
        foreach ($rule in $rules.PSObject.Properties) {
            $actual = 'ABSENT'
            if ([IO.File]::Exists($rule.Name)) {
                try {
                    $stream = [IO.FileStream]::new($rule.Name,[IO.FileMode]::Open,[IO.FileAccess]::Read,
                        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
                    try {
                        $sha = [Security.Cryptography.SHA256]::Create()
                        try { $actual = 'SHA256:' + [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') }
                        finally { $sha.Dispose() }
                    } finally { $stream.Dispose() }
                } catch [IO.IOException] {
                    $gaps++; $lastError = 'IO:' + $_.Exception.HResult
                    continue
                } catch [UnauthorizedAccessException] {
                    $gaps++; $lastError = 'ACCESS:' + $_.Exception.HResult
                    continue
                }
            }
            if (@($rule.Value) -notcontains $actual) {
                $leaks++
                Add-Content -LiteralPath $logPath -Value ('LEAK utc=' + [DateTime]::UtcNow.ToString('o') +
                    ' path=' + $rule.Name + ' observed=' + $actual)
                exit 2
            }
            $lastSeen[[string]$rule.Name] = $actual
            $samples++
            $sampledThisPass++
        }
        if (-not $ready -and $sampledThisPass -eq $rules.PSObject.Properties.Count) {
            Add-Content -LiteralPath $logPath -Value ('ObserverReady samples=' + $sampledThisPass)
            $ready = $true
        }
    } catch {
        $gaps++; $lastError = $_.Exception.Message
    }
    if (-not (Test-Path -LiteralPath $stopPath)) { Start-Sleep -Milliseconds 40 }
} while (-not (Test-Path -LiteralPath $stopPath))
Add-Content -LiteralPath $logPath -Value ('ObserverSummary samples=' + $samples + ' gaps=' + $gaps +
    ' leaks=' + $leaks + ' lastError=' + $lastError)
foreach ($path in $lastSeen.Keys) {
    Add-Content -LiteralPath $logPath -Value ('ObserverFinal path=' + $path + ' value=' + $lastSeen[$path])
}
if ($leaks -ne 0) { exit 2 }
if ($samples -eq 0 -or $gaps -ne 0) { exit 3 }
exit 0
'@
    $watch = $watch.Replace('__RULES__', $observerRules).Replace('__LOG__', $observerLog).Replace('__STOP__', $observerStop)
    Set-Content -LiteralPath $observerScript -Value $watch -Encoding UTF8
    $script:observer = Start-Process -FilePath 'powershell.exe' -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $observerOut -RedirectStandardError $observerErr `
        -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',('"' + $observerScript + '"'))
    [void]$script:observer.Handle
    $clock = [Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Milliseconds 100
        $script:observer.Refresh()
        if ($script:observer.HasExited) { throw 'Independent destination byte observer exited before its initial sample.' }
        if (Test-Path -LiteralPath $observerLog) {
            $initialLog = [IO.File]::ReadAllText($observerLog)
            if ($initialLog -match 'ObserverReady samples=[1-9][0-9]*') { break }
        }
    } while ($clock.Elapsed.TotalSeconds -lt 30)
    if (-not (Test-Path -LiteralPath $observerLog) -or
        [IO.File]::ReadAllText($observerLog) -notmatch 'ObserverReady samples=[1-9][0-9]*') {
        throw 'Independent byte observer did not complete a gap-free initial-path sample.'
    }
    Write-Event 'ObserverStarted' ('pid=' + $script:observer.Id + ';log=' + $observerLog)
}

function Stop-ByteObserver([hashtable] $RequiredFinal) {
    $process = $script:observer
    if ($null -eq $process) { throw 'Independent destination byte observer never started.' }
    Set-Content -LiteralPath $observerStop -Value 'stop' -Encoding ASCII
    $process.WaitForExit()
    Write-Event 'ObserverExit' ('code=' + $process.ExitCode + ';log=' + $observerLog)
    if (Test-Path -LiteralPath $observerLog) { Get-Content -LiteralPath $observerLog | ForEach-Object { Write-Host $_ } }
    if (Test-Path -LiteralPath $observerErr) { Get-Content -LiteralPath $observerErr | ForEach-Object { Write-Host ('ObserverStderr=' + $_) } }
    if ($process.ExitCode -ne 0) { throw ('Independent observer failed with exit ' + $process.ExitCode) }
    $summary = if (Test-Path -LiteralPath $observerLog) { Get-Content -LiteralPath $observerLog -Raw } else { '' }
    if ($summary -notmatch 'ObserverSummary samples=[1-9][0-9]* gaps=0 leaks=0') {
        throw 'Observer did not provide gap-free, leak-free independent byte samples.'
    }
    foreach ($path in $RequiredFinal.Keys) {
        $expectedLine = 'ObserverFinal path=' + $path + ' value=' + $RequiredFinal[$path]
        if (@($summary -split "`r?`n") -notcontains $expectedLine) {
            throw ('Observer final independent sample did not match the exact required payload for ' + $path)
        }
    }
}

function Invoke-WriterStatus {
    ++$script:captureSequence
    $stem = '{0:D3}-writer-state-status' -f $script:captureSequence
    $outputPath = Join-Path $evidenceDir ($stem + '.stdout')
    $errorPath = Join-Path $evidenceDir ($stem + '.stderr')
    $exitPath = Join-Path $evidenceDir ($stem + '.exit')
    $commandPath = Join-Path $evidenceDir ($stem + '.cmd')
    $taskName = $inspectorTaskName + '-' + $script:captureSequence
    $commandText = '@echo off' + "`r`n" + '"' + $inspector + '" --writer-state-status 1> "' + $outputPath +
        '" 2> "' + $errorPath + '"' + "`r`n" + 'echo %errorlevel%>"' + $exitPath + '"' + "`r`n"
    Set-Content -LiteralPath $commandPath -Value $commandText -Encoding ASCII
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c ""' + $commandPath + '"')
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # This is a read-only status query. Do not cancel a client that might be
    # inside a Filter Manager callback; wait for its own completion instead.
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    [void]$script:statusTaskNames.Add($taskName)
    $taskCompleted = $false
    try {
        Start-ScheduledTask -TaskName $taskName
        $dispatchClock = [Diagnostics.Stopwatch]::StartNew()
        do {
            Start-Sleep -Milliseconds 250
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            if ($task.State -ne 'Running' -and (Test-Path -LiteralPath $exitPath)) { $taskCompleted = $true; break }
            if ($task.State -ne 'Running' -and $dispatchClock.Elapsed.TotalSeconds -ge 30) {
                throw 'Read-only writer-status task was not dispatched; it was not cancelled.'
            }
        } while ($true)
        if (-not (Test-Path -LiteralPath $outputPath) -or -not (Test-Path -LiteralPath $errorPath) -or
            -not (Test-Path -LiteralPath $exitPath)) { throw 'Writer-status command did not retain all raw output and exit files.' }
        $commandExit = [int](Get-Content -LiteralPath $exitPath -Raw).Trim()
        $raw = [IO.File]::ReadAllText($outputPath)
        $errRaw = [IO.File]::ReadAllText($errorPath)
        $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
        Write-Event 'WriterStatusCapture' ('commandExit=' + $commandExit + ';taskResult=' + $taskInfo.LastTaskResult +
            ';stdout=' + $outputPath + ';stderr=' + $errorPath + ';exitFile=' + $exitPath + ';command=' + $commandPath)
        if ($commandExit -ne 0 -or [int]$taskInfo.LastTaskResult -ne 0) {
            throw ('Read-only writer-status command failed; exit=' + $commandExit + ';taskResult=' + $taskInfo.LastTaskResult +
                ';stderr=' + ($errRaw -replace '\s+', ' '))
        }
        $jsonLine = @($raw -split "`r?`n" | Where-Object { $_ -match '^\{"writerState"' }) | Select-Object -First 1
        if (-not $jsonLine) { Write-Event 'WriterStatusRaw' ($raw -replace '\s+', ' '); return $null }
        $status = $jsonLine | ConvertFrom-Json
        if ($status -isnot [pscustomobject] -or $null -eq $status.PSObject.Properties['writerState']) {
            throw 'Writer-status capture did not produce one structured status object.'
        }
        return $status
    } finally {
        if ($taskCompleted) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
        } else {
            $latest = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($null -eq $latest -or $latest.State -in @('Ready','Disabled')) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            } else {
                Write-Event 'WriterStatusTaskRetained' ('task=' + $taskName + ';state=' + $latest.State + ';reason=not-complete-or-still-running;not-cancelled')
            }
        }
    }
}

function Write-StageFile([string] $Path, [string] $Text) {
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $file = $null
    try {
        $file = [IO.FileStream]::new($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, $share)
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        $file.Write($bytes, 0, $bytes.Length)
        $file.Flush()
        $entry = Wait-Entry $Path 0
        if ($entry.Transfer.StagePath) { $cleanupPaths.Add([string]$entry.Transfer.StagePath) }
        $cleanupPaths.Add((Join-Path $journal (([guid]$entry.Transfer.TransferId).ToString('N') + '.json')))
        Write-Event 'StagedOwnerCreated' ('destination=' + $Path + ';transfer=' + $entry.Transfer.TransferId + ';state=' + $entry.State +
            ';contentLength=' + $bytes.Length + ';contentSha256=' + (Get-ContentSha256 $Text))
        $result = [pscustomobject]@{ File=$file; Entry=$entry; Text=$Text }
        # Transfer ownership only after every operation that can fail has
        # completed. The caller's finally then owns this exact live FILE_OBJECT.
        $file = $null
        return $result
    } catch {
        # If the write or journal wait failed after the minifilter created an
        # entry, retain its exact private cleanup paths even though no owner
        # object will be returned to the caller.
        try {
            foreach ($entry in @(Find-Entry $Path)) {
                if ($entry.Transfer.StagePath) { $cleanupPaths.Add([string]$entry.Transfer.StagePath) }
                if ($entry.Transfer.TransferId) {
                    $cleanupPaths.Add((Join-Path $journal (([guid]$entry.Transfer.TransferId).ToString('N') + '.json')))
                }
            }
        } catch { }
        throw
    } finally {
        if ($null -ne $file) { $file.Dispose() }
    }
}

function Wait-FilterAbsent {
    while (Test-FilterLoaded) { Start-Sleep -Milliseconds 250 }
}

if ($env:COMPUTERNAME -ne 'WIN10-DEBUGGED' -or
    (Get-CimInstance Win32_ComputerSystemProduct).UUID -ne '9D44EEE8-81CF-4CC1-9FBA-7670F11DEF4D') {
    throw 'This fixture is permitted only on the pinned isolated WIN10-DEBUGGED VM.'
}
New-Item -ItemType Directory -Path $evidenceDir -ErrorAction Stop | Out-Null
if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
    throw 'Original installed driver bytes differ from the pinned baseline.'
}
if ((Get-FileHash -LiteralPath $featureDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
    throw 'R18 feature driver hash mismatch.'
}
if ((Get-FileHash -LiteralPath $inspector -Algorithm SHA256).Hash -ne $ExpectedInspectorSha256.ToUpperInvariant()) {
    throw 'Inspector hash mismatch.'
}
if ((Get-FileHash -LiteralPath $servicePackage -Algorithm SHA256).Hash -ne $ExpectedServicePackageSha256.ToUpperInvariant()) {
    throw 'Service package hash mismatch.'
}
if (Test-FilterLoaded) { throw 'SafeUpload must be unloaded at baseline.' }
$driverServiceConfigBefore = Get-DriverServiceConfig 'baseline'
if ((Test-Path -LiteralPath 'S:\') -or (Test-Path -LiteralPath $diskImage)) { throw 'Disposable S: volume is already present.' }
if (@(Get-Process -Name 'SafeUpload.Agent.Service' -ErrorAction SilentlyContinue).Count -ne 0) {
    throw 'SafeUploadAgent must be stopped at baseline.'
}
$agentServiceBaseline = Get-AgentServiceBaseline
$verifierBaseline = Invoke-CapturedCommand 'verifier-query-baseline' 'verifier.exe' @('/query')
$verifierBefore = $verifierBaseline.Stdout + "`n" + $verifierBaseline.Stderr
if ($verifierBaseline.ExitCode -ne 0 -or $verifierBefore -notmatch 'No drivers are currently verified') {
    throw 'Driver Verifier must be queryable and idle at baseline.'
}
if ((Test-Path -LiteralPath (Join-Path $journal 'driver-epoch.state'))) {
    $serviceEpochBefore = Get-EpochRecord
    if ($serviceEpochBefore.DrainNonce -eq $null) {
        throw 'The service journal has an undrained prior driver epoch; recover it before this test.'
    }
}
Write-Event 'Fixture' ('case=' + $Case + ';fixtureSha256=' + (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash +
    ';driver=' + $ExpectedFeatureSha256.ToUpperInvariant() + ';inspector=' + $ExpectedInspectorSha256.ToUpperInvariant() +
    ';servicePackage=' + $ExpectedServicePackageSha256.ToUpperInvariant() + ';helper=' + $expectedHelperSha256)

try {
    Invoke-Diskpart @("create vdisk file=`"$diskImage`" maximum=128 type=expandable", "select vdisk file=`"$diskImage`"",
        'attach vdisk','create partition primary','format fs=ntfs quick label=SafeUploadUnload','assign letter=S')
    $mounted = $true
    New-Item -ItemType Directory -Force -Path $scope,$serviceDirectory | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($servicePackage)
    $fileCount = 0
    try {
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName.EndsWith('/')) { continue }
            if ([IO.Path]::IsPathRooted($entry.FullName) -or $entry.FullName -match '(^|[\\/])\.\.([\\/]|$)|:') {
                throw 'Service package has an unsafe path.'
            }
            $destination = [IO.Path]::GetFullPath((Join-Path $serviceDirectory ($entry.FullName.Replace('/', '\'))))
            $rootPrefix = [IO.Path]::GetFullPath($serviceDirectory) + [IO.Path]::DirectorySeparatorChar
            if (-not $destination.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Service package entry escaped its extraction directory.'
            }
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
            $hashInput = $entry.Open()
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $sourceHash = [BitConverter]::ToString($sha.ComputeHash($hashInput)).Replace('-', '') }
            finally { $sha.Dispose(); $hashInput.Dispose() }
            $input = $entry.Open()
            try {
                $output = [IO.FileStream]::new($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
                try { $input.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
            } finally { $input.Dispose() }
            $fileStream = [IO.File]::OpenRead($destination)
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $actualHash = [BitConverter]::ToString($sha.ComputeHash($fileStream)).Replace('-', '') }
            finally { $sha.Dispose(); $fileStream.Dispose() }
            if ($actualHash -ne $sourceHash -or (Get-Item -LiteralPath $destination).Length -ne $entry.Length) {
                throw 'Extracted service member differs from its pinned archive entry.'
            }
            ++$fileCount
        }
    } finally { $archive.Dispose() }
    if ($fileCount -eq 0 -or -not (Test-Path -LiteralPath (Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe'))) {
        throw 'Pinned service package did not contain the expected service executable.'
    }
    Write-Event 'ServicePackageExtracted' ('files=' + $fileCount + ';exeSha256=' +
        (Get-FileHash -LiteralPath (Join-Path $serviceDirectory 'SafeUpload.Agent.Service.exe') -Algorithm SHA256).Hash)

    $observerRulesMap[$firstPath] = @('ABSENT')
    $observerRulesMap[$secondPath] = @('ABSENT')
    $observerRulesMap[$holdPath] = @('ABSENT')
    Save-ObserverRules
    $observerRequired = $true
    Start-ByteObserver

    Backup-StagedTestDriver $backup
    if ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
        throw 'Durable original-driver restoration backup mismatch.'
    }
    $replaced = $true
    Copy-Item -LiteralPath $featureDriver -Destination $installedDriver -Force
    if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $ExpectedFeatureSha256.ToUpperInvariant()) {
        throw 'Installed R18 driver bytes differ from the exact input.'
    }
    $verifierAdd = Invoke-CapturedCommand 'verifier-enable' 'verifier.exe' @('/volatile','/flags','0x13B','/adddriver','SafeUpload.sys')
    if ($verifierAdd.ExitCode -ne 0) { throw 'Volatile Driver Verifier could not be enabled.' }
    $verifierEnabled = $true
    $verifierActiveCapture = Invoke-CapturedCommand 'verifier-query-active' 'verifier.exe' @('/query')
    $verifierActive = $verifierActiveCapture.Stdout + "`n" + $verifierActiveCapture.Stderr
    if ($verifierActive -notmatch 'SafeUpload\.sys') { throw 'Verifier query did not show SafeUpload.sys active.' }
    Write-Event 'VerifierActive' (($verifierActive -replace '\s+', ' ').Trim())

    $filterLoad = Invoke-CapturedCommand 'fltmc-load' 'fltmc.exe' @('load','SafeUpload')
    if ($filterLoad.ExitCode -ne 0 -or -not (Test-FilterLoaded)) { throw 'R18 filter load failed.' }
    $filterLoaded = $true
    Write-Event 'FilterLoaded' $ExpectedFeatureSha256.ToUpperInvariant()
    [void](Write-FilterSnapshot 'loaded-before-agent')
    if (-not (Wait-FilterAttached 'S:' 30)) { throw 'SafeUpload did not attach to the disposable S: volume.' }
    Write-Event 'FilterInstanceAttached' 'volume=S:'
    $agent = Start-StagedTestAgent $serviceDirectory (Join-Path $documents ('v20-unload-agent-' + $id))
    $epochClock = [Diagnostics.Stopwatch]::StartNew()
    do {
        $serviceEpochBefore = Get-EpochRecord
        if ($null -ne $serviceEpochBefore -and $serviceEpochBefore.DrainNonce -eq $null) { break }
        Start-Sleep -Milliseconds 250
    } while ($epochClock.Elapsed.TotalSeconds -lt 60)
    if ($null -eq $serviceEpochBefore -or $serviceEpochBefore.DrainNonce -ne $null) {
        throw 'Service did not publish one active v20 epoch before unload testing.'
    }
    Save-EpochEvidence 'epoch-active-before-unload'
    Write-Event 'ActiveServiceEpoch' ('driverInstance=' + $serviceEpochBefore.DriverInstanceId +
        ';acceptedAtUtc=' + $serviceEpochBefore.AcceptedAtUtc)

    if ($Case -eq 'voluntary-precommit') {
        $firstText = 'R18-VOLUNTARY-PRIVATE-' + $id
        $held = Write-StageFile $firstPath $firstText
        $heldFile = $held.File
        $before = Invoke-WriterStatus
        if ($null -eq $before -or [int]$before.stageFileObjects -lt 1) {
            $scenarioReason = 'Could not observe the held real stage FILE_OBJECT before voluntary unload.'
            throw [OperationCanceledException]::new($scenarioReason)
        }
        Write-Event 'WriterBeforeVoluntaryUnload' ($before | ConvertTo-Json -Compress)
        $unloadCapture = Invoke-CapturedCommand 'fltmc-voluntary-precommit-unload' 'fltmc.exe' @('unload','SafeUpload')
        $unloadExit = $unloadCapture.ExitCode
        $unloadText = ($unloadCapture.Stdout + "`n" + $unloadCapture.Stderr).Trim()
        $stillLoaded = Test-FilterLoaded
        [void](Write-FilterSnapshot 'after-voluntary-precommit-unload')
        Write-Event 'VoluntaryUnloadResult' ('exit=' + $unloadExit + ';filterStillLoaded=' + $stillLoaded + ';output=' + ($unloadText -replace '\s+', ' '))
        if (-not $stillLoaded) { throw 'Voluntary unload removed the filter while a staged FILE_OBJECT remained live.' }
        $after = Invoke-WriterStatus
        if ($null -eq $after) {
            $scenarioReason = 'The target unload-veto state was not observable after voluntary refusal.'
            throw [OperationCanceledException]::new($scenarioReason)
        }
        Write-Event 'WriterAfterVoluntaryUnload' ($after | ConvertTo-Json -Compress)
        if ([int]$after.stageFileObjects -lt 1 -or [int]$after.lastUnloadVeto -ne 4 -or $unloadExit -eq 0) {
            throw 'Voluntary unload did not expose the expected stage-object precommit veto.'
        }
        Write-Event 'VoluntaryPrecommitVeto' 'observed=stageFileObjects>0;lastUnloadVeto=4;filterResident=true'

        $secondText = 'R18-ROLLBACK-CHANNEL-' + $id
        $second = Write-StageFile $secondPath $secondText
        $secondFile = $second.File
        $secondHash = Get-ContentSha256 $secondText
        Set-ObserverAllowance $secondPath $secondHash
        $secondFile.Dispose(); $secondFile = $null
        $secondEntry = Wait-Entry $secondPath 5
        if (-not $secondEntry.SealedOnce) { throw 'Post-rollback service work reached state 5 without sealed publication evidence.' }
        Write-Event 'PostRollbackServiceWork' ('state=' + $secondEntry.State + ';transfer=' + $secondEntry.Transfer.TransferId)

        $firstHash = Get-ContentSha256 $firstText
        Set-ObserverAllowance $firstPath $firstHash
        $heldFile.Dispose(); $heldFile = $null
        $firstEntry = Wait-Entry $firstPath 5
        if (-not $firstEntry.SealedOnce) { throw 'Released original owner reached state 5 without sealed publication evidence.' }
        Write-Event 'ReleasedOriginalOwnerAndServiceCleanup' ('state=' + $firstEntry.State + ';transfer=' + $firstEntry.Transfer.TransferId)
        if ((Get-FileHash -LiteralPath $secondPath -Algorithm SHA256).Hash -ne $secondHash.Substring(7) -or
            (Get-FileHash -LiteralPath $firstPath -Algorithm SHA256).Hash -ne $firstHash.Substring(7)) {
            throw 'Independent post-publication file bytes did not match the exact allowlisted payloads.'
        }
        $statusAfterCleanup = Invoke-WriterStatus
        if ($null -eq $statusAfterCleanup) { throw 'Writer status unavailable after rollback cleanup.' }
        Write-Event 'WriterAfterRollbackCleanup' ($statusAfterCleanup | ConvertTo-Json -Compress)
        $expectedObserverFinal[$secondPath] = $secondHash
        $expectedObserverFinal[$firstPath] = $firstHash

        $drainBefore = Get-EpochRecord
        if ($null -eq $drainBefore -or $drainBefore.DriverInstanceId -ne $serviceEpochBefore.DriverInstanceId -or
            $null -ne $drainBefore.DrainNonce) { throw 'Active service epoch changed unexpectedly before final unload.' }
        Save-EpochEvidence 'epoch-active-immediately-before-commit'
        $finalCapture = Invoke-CapturedCommand 'fltmc-committed-voluntary-unload' 'fltmc.exe' @('unload','SafeUpload')
        $finalExit = $finalCapture.ExitCode
        $finalText = ($finalCapture.Stdout + "`n" + $finalCapture.Stderr).Trim()
        $filterLoaded = Test-FilterLoaded
        Write-Event 'CommittedVoluntaryUnloadResult' ('exit=' + $finalExit + ';filterStillLoaded=' + $filterLoaded + ';output=' + ($finalText -replace '\s+', ' '))
        if ($finalExit -ne 0 -or $filterLoaded) { throw 'Final voluntary unload did not complete after the owners and service work drained.' }
        $drainAfter = Get-EpochRecord
        if ($null -eq $drainAfter -or $drainAfter.DriverInstanceId -ne $serviceEpochBefore.DriverInstanceId -or
            [UInt64]$drainAfter.DrainRequestId -eq 0 -or [UInt64]$drainAfter.DrainNonce -eq 0 -or
            $null -eq $drainAfter.DrainedAtUtc) {
            throw 'Successful unload did not leave the exact durable epoch-drain tuple.'
        }
        Save-EpochEvidence 'epoch-drained-after-voluntary-unload'
        Write-Event 'ServiceDurableEpochDrain' ('driverInstance=' + $drainAfter.DriverInstanceId +
            ';requestId=' + $drainAfter.DrainRequestId + ';nonce=' + $drainAfter.DrainNonce +
            ';drainedAtUtc=' + $drainAfter.DrainedAtUtc + ';rawWireReplyCaptured=false')
        Write-Event 'VoluntaryPrecommitRollbackApiSubcase' 'OBSERVED;held-stage-owner-vetoed;post-rollback-service-work-completed;final-filter-removal-observed'
        Write-Event 'ServiceEpochReceiptSubcase' 'OBSERVED;durable-driver-instance-request-nonce-receipt-present'
        Write-Event 'ExactOp17WireAckObservation' 'INCONCLUSIVE;raw-request-and-ack-frame-are-not-exposed-by-current-service-logging;no-claim-made'
        $scenarioResult = 'INCONCLUSIVE'
        $scenarioReason = 'Voluntary precommit veto, rollback service work, owner cleanup and final filter removal were observed. The durable receipt is correlated evidence; raw op17 ACK observation remains unqualified and no ACK claim is made.'
    }
    else {
        $heldText = 'R18-MANDATORY-PRIVATE-' + $id
        $mandatory = Write-StageFile $holdPath $heldText
        $mandatoryFile = $mandatory.File
        $heldStatus = Invoke-WriterStatus
        if ($null -eq $heldStatus -or [int]$heldStatus.stageFileObjects -lt 1) {
            $scenarioReason = 'Could not observe the retained real stage FILE_OBJECT before mandatory unload.'
            throw [OperationCanceledException]::new($scenarioReason)
        }
        Write-Event 'WriterBeforeMandatoryUnload' ($heldStatus | ConvertTo-Json -Compress)
        $mandatoryProcess = Start-Process -FilePath 'sc.exe' -ArgumentList @('stop','SafeUpload') `
            -PassThru -WindowStyle Hidden -RedirectStandardOutput $mandatoryOut -RedirectStandardError $mandatoryErr
        [void]$mandatoryProcess.Handle
        Write-Event 'MandatoryStopStarted' ('pid=' + $mandatoryProcess.Id + ';service=SafeUpload')
        $ownerHeldFilterResident = $false
        $mandatoryStopProgressObserved = $false
        for ($sample = 1; $sample -le $MandatoryHoldSeconds; $sample++) {
            Start-Sleep -Seconds 1
            $serviceSnapshot = Get-DriverServiceSnapshot ('mandatory-hold-' + $sample)
            $present = Write-FilterSnapshot ('mandatory-hold-' + $sample)
            $ownerStillOpen = -not $mandatoryFile.SafeFileHandle.IsClosed
            if ($ownerStillOpen -and $present) { $ownerHeldFilterResident = $true }
            $serviceState = $serviceSnapshot.State
            Record-ScStopProcessExit $mandatoryProcess
            $mandatoryProcess.Refresh()
            if ($ownerStillOpen -and $present -and (($serviceSnapshot.QuerySucceeded -and $serviceState -eq '3') -or
                ($mandatoryProcess.HasExited -and $mandatoryProcess.ExitCode -eq 0))) {
                $mandatoryStopProgressObserved = $true
            }
            Write-Event 'MandatoryHoldState' ('sample=' + $sample + ';scProcessExited=' + $mandatoryProcess.HasExited +
                ';filterResident=' + $present + ';realStageFileStreamOpen=' + $ownerStillOpen +
                ';serviceQuerySucceeded=' + $serviceSnapshot.QuerySucceeded + ';serviceState=' + $serviceState +
                ';stateAndOwnerAreSequentialObservations=true')
            if (-not $present) { throw 'Filter disappeared while the real stage FILE_OBJECT remained held.' }
        }
        if (-not $ownerHeldFilterResident) {
            $scenarioReason = 'The real external owner and a resident filter were not simultaneously observed during the mandatory request.'
        } elseif (-not $mandatoryStopProgressObserved) {
            $scenarioReason = 'The real owner remained open and the filter remained loaded, but STOP_PENDING or a successful SCM response was not observed before owner release.'
        }
        if (-not $stopResponseRecorded) {
            Write-Event 'ScStopProcessExitObservation' 'PENDING_AT_END_OF_OWNER_HOLD;process-lifetime-is-not-used-as-the-unload-signal'
        }
        Write-Event 'MandatoryOwnerWaitObserved' ('ownerHandleAndFilterResident=' + $ownerHeldFilterResident +
            ';stopProgressCorrelatedWithHoldSample=' + $mandatoryStopProgressObserved + ';holdSeconds=' + $MandatoryHoldSeconds)

        $heldHash = Get-ContentSha256 $heldText
        Set-ObserverAllowance $holdPath $heldHash
        $expectedObserverFinal[$holdPath] = $heldHash
        $mandatoryFile.Dispose(); $mandatoryFile = $null
        $releasedEntry = Wait-Entry $holdPath 5
        if (-not $releasedEntry.SealedOnce) { throw 'Mandatory owner release reached state 5 without sealed publication evidence.' }
        Write-Event 'MandatoryOwnerReleased' ('state=' + $releasedEntry.State + ';transfer=' + $releasedEntry.Transfer.TransferId)
        # Intentionally wait without killing the SCM process or imposing a
        # teardown deadline. The private owner was released; any remaining wait
        # belongs to service/worker/filter quiescence and must finish safely.
        while (Test-FilterLoaded) {
            if (-not $stopResponseRecorded) {
                $mandatoryProcess.Refresh()
                if ($mandatoryProcess.HasExited) {
                    Record-ScStopProcessExit $mandatoryProcess
                }
            }
            Start-Sleep -Milliseconds 250
        }
        Write-Event 'FilterAbsentAfterMandatoryRequest' 'true'
        # The API model distinguishes the accepted control request from actual
        # filter disappearance. Wait for sc.exe itself without killing it, but
        # do not use its process lifetime as the kernel unload signal.
        $mandatoryProcess.WaitForExit()
        $mandatoryProcess.Refresh()
        Record-ScStopProcessExit $mandatoryProcess
        $filterLoaded = Test-FilterLoaded
        [void](Write-FilterSnapshot 'after-mandatory-owner-release')
        $postServiceSnapshot = Get-DriverServiceSnapshot 'mandatory-complete'
        Write-Event 'MandatoryStopCompleted' ('scExit=' + $mandatoryProcess.ExitCode + ';accepted=' + ($mandatoryProcess.ExitCode -eq 0) +
            ';filterStillLoaded=' + $filterLoaded + ';serviceQueryExit=' + $postServiceSnapshot.ExitCode +
            ';serviceQuerySucceeded=' + $postServiceSnapshot.QuerySucceeded + ';serviceState=' + $postServiceSnapshot.State +
            ';stdout=' + $mandatoryOut + ';stderr=' + $mandatoryErr + ';exitFile=' + $mandatoryExitPath)
        if ($mandatoryProcess.ExitCode -ne 0 -or $filterLoaded) { throw 'Mandatory stop did not complete after owner release.' }
        $mandatoryStoppedObserved = ($postServiceSnapshot.QuerySucceeded -and $postServiceSnapshot.State -eq '1')
        Write-Event 'MandatoryFinalServiceStoppedSubcase' $(if ($mandatoryStoppedObserved) { 'OBSERVED;successful-query-state=STOPPED' } else { 'INCONCLUSIVE;final-service-query-did-not-confirm-STOPPED' })
        if (-not $ownerHeldFilterResident) {
            $scenarioReason = 'Filter removal completed after owner release, but the live external owner plus resident-filter boundary was not observed.'
        } elseif (-not $mandatoryStopProgressObserved) {
            $scenarioReason = 'Filter removal completed after owner release, but SCM stop progress was not correlated with an owner-held sample.'
        } elseif (-not $mandatoryStoppedObserved) {
            $scenarioReason = 'Filter removal completed, but a successful final SCM query confirming STOPPED was not observed.'
        }
        $drainAfter = Get-EpochRecord
        if ($null -eq $drainAfter -or $drainAfter.DriverInstanceId -ne $serviceEpochBefore.DriverInstanceId -or
            [UInt64]$drainAfter.DrainRequestId -eq 0 -or [UInt64]$drainAfter.DrainNonce -eq 0 -or
            $null -eq $drainAfter.DrainedAtUtc) {
            throw 'Mandatory unload completed without the exact durable epoch-drain tuple.'
        }
        Save-EpochEvidence 'epoch-drained-after-mandatory-unload'
        Write-Event 'ServiceDurableEpochDrain' ('driverInstance=' + $drainAfter.DriverInstanceId +
            ';requestId=' + $drainAfter.DrainRequestId + ';nonce=' + $drainAfter.DrainNonce +
            ';drainedAtUtc=' + $drainAfter.DrainedAtUtc + ';rawWireReplyCaptured=false')
        Write-Event 'MandatoryHeldOwnerFilterResidentSubcase' $(if ($ownerHeldFilterResident) { 'OBSERVED' } else { 'INCONCLUSIVE' })
        Write-Event 'MandatoryStopProgressCorrelatedWithOwnerHoldSampleSubcase' $(if ($mandatoryStopProgressObserved) { 'OBSERVED;sequential-sample-correlation' } else { 'INCONCLUSIVE' })
        Write-Event 'MandatoryOwnerReleaseFilterRemovalAndServiceStoppedSubcase' $(if ($ownerHeldFilterResident -and -not $filterLoaded -and $mandatoryStoppedObserved) { 'OBSERVED' } else { 'INCONCLUSIVE' })
        Write-Event 'ServiceEpochReceiptSubcase' 'OBSERVED;durable-driver-instance-request-nonce-receipt-present'
        Write-Event 'ExactOp17WireAckObservation' 'INCONCLUSIVE;raw-request-and-ack-frame-are-not-exposed-by-current-service-logging;no-claim-made'
        $scenarioResult = 'INCONCLUSIVE'
        if ($ownerHeldFilterResident -and $mandatoryStopProgressObserved -and $mandatoryStoppedObserved) {
            $scenarioReason = 'SCM response or STOP_PENDING, held external owner, filter presence, owner release and final filter disappearance were recorded separately. The durable receipt is correlated evidence; raw op17 ACK observation remains unqualified and no ACK claim is made.'
        }
    }
}
catch [OperationCanceledException] {
    $scenarioResult = 'INCONCLUSIVE'
    $scenarioReason = $_.Exception.Message
    Write-Event 'ScenarioInconclusive' $scenarioReason
}
catch {
    $scenarioResult = 'FAIL'
    $scenarioReason = $_.Exception.ToString()
    Write-Event 'ScenarioFailure' ($scenarioReason -replace '\s+', ' ')
}
finally {
    if ($null -ne $secondFile) { try { $secondFile.Dispose() } catch { } }
    if ($null -ne $heldFile) { try { $heldFile.Dispose() } catch { } }
    if ($null -ne $mandatoryFile) { try { $mandatoryFile.Dispose() } catch { } }

    # UNKNOWN is treated like PRESENT for every destructive restoration step.
    # A failed fltmc query cannot authorize overwriting an image that may be live.
    $finalFilterState = 'UNKNOWN'
    try {
        $finalFilterState = Get-FilterState 'fltmc-finalizer-state'
        $filterLoaded = ($finalFilterState -eq 'PRESENT')
    } catch {
        $filterLoaded = $true
        Add-FinalizationIssue ('Could not establish current filter state: ' + $_.Exception.Message)
    }
    if ($finalFilterState -ne 'ABSENT') {
        Write-Event 'RestorationPending' ('filterState=' + $finalFilterState + ';original-driver-not-overwritten;temporary-and-private-fixture-preserved;external-recovery-gate-required')
        Add-FinalizationIssue ('Filter state is ' + $finalFilterState + '; driver bytes, backup and mounted fixture were preserved for the independent recovery gate.')
        if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
    }

    if ($observerRequired) {
        try {
            Stop-ByteObserver $expectedObserverFinal
            $observerStoppedAndValidated = $true
        } catch {
            Add-FinalizationIssue ('Observer stop/verification failed: ' + $_.Exception.Message)
            if ($_.Exception.Message -match 'failed with exit 2|leak') { $scenarioResult = 'FAIL' }
            elseif ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
        }
    } else {
        $observerStoppedAndValidated = $true
    }

    if ($finalFilterState -eq 'ABSENT') {
        try {
            if ($null -ne $agent) {
                $agentRecordForAudit = $agent
                Stop-StagedTestAgent $agent
                $agent = $null
                Assert-AgentServiceRestored $agentRecordForAudit
                Write-Event 'TestAgentStopped' 'true;service-config-and-stopped-state-verified'
            }
            Assert-AgentServiceBaseline $agentServiceBaseline
            $agentServiceRestored = $true
            Write-Event 'AgentServiceBaselineRestoration' 'verified'
        } catch {
            Add-FinalizationIssue ('Test agent stop/service restoration failed: ' + $_.Exception.Message)
            if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
        }

        if ($replaced) {
            try {
                $preRestoreFilterState = Get-FilterState 'fltmc-pre-driver-restore-state'
                if ($preRestoreFilterState -ne 'ABSENT') {
                    throw ('Driver restore refused because filter state is ' + $preRestoreFilterState)
                }
                Restore-StagedTestDriver $backup $false $verifierEnabled
                $replaced = $false
                $verifierEnabled = $false
                $restoreComplete = $true
                Write-Event 'DriverRestoreOperation' 'completed'
            } catch {
                Add-FinalizationIssue ('Driver restore failed: ' + $_.Exception.Message)
                if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
            }
        } else {
            $restoreComplete = $true
        }

        if ($restoreComplete) {
            try {
                if ((Get-FileHash -LiteralPath $installedDriver -Algorithm SHA256).Hash -ne $expectedOriginalDriver) {
                    throw 'Installed driver hash does not match the pinned original after restoration.'
                }
                $restoredFilterState = Get-FilterState 'fltmc-post-driver-restore-state'
                if ($restoredFilterState -ne 'ABSENT') {
                    throw ('Filter state after driver restoration is ' + $restoredFilterState)
                }
                $originalDriverRestored = $true
                Write-Event 'OriginalDriverRestoration' 'verified;filterState=ABSENT'
            } catch {
                Add-FinalizationIssue ('Original driver restoration verification failed: ' + $_.Exception.Message)
                if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
            }
            try {
                $verifierAfterCapture = Invoke-CapturedCommand 'verifier-query-restored' 'verifier.exe' @('/query')
                $verifierAfter = $verifierAfterCapture.Stdout + "`n" + $verifierAfterCapture.Stderr
                if ($verifierAfterCapture.ExitCode -ne 0 -or $verifierAfter -notmatch 'No drivers are currently verified') {
                    throw 'Driver Verifier did not return to the pinned idle baseline.'
                }
                $verifierRestored = $true
                Write-Event 'VerifierRestoration' 'verified;idle-baseline'
            } catch {
                Add-FinalizationIssue ('Driver Verifier restoration verification failed: ' + $_.Exception.Message)
                if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
            }
            try {
                $driverServiceConfigAfter = Get-DriverServiceConfig 'restored'
                if ($driverServiceConfigAfter -cne $driverServiceConfigBefore) {
                    throw 'SafeUpload service configuration changed during the fixture.'
                }
                $driverServiceRestored = $true
                Write-Event 'DriverServiceRestoration' 'verified;configuration-matches-baseline'
            } catch {
                Add-FinalizationIssue ('Driver service restoration verification failed: ' + $_.Exception.Message)
                if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
            }
            try {
                [void](Confirm-StatusTasksRemoved)
                $statusTasksRemoved = $true
                Write-Event 'InspectorStatusTasksRestoration' 'verified;all-fixture-tasks-removed'
            } catch {
                Add-FinalizationIssue ('Inspector status task restoration verification failed: ' + $_.Exception.Message)
                if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
            }
        }

        $prePrivateCleanupChecks = $agentServiceRestored -and $observerStoppedAndValidated -and
            $originalDriverRestored -and $verifierRestored -and $driverServiceRestored -and $statusTasksRemoved
        if ($prePrivateCleanupChecks -and $mounted) {
            try {
                if ($cleanupPaths.Count -gt 0) { Remove-StagedTestFiles @($cleanupPaths.ToArray()) }
                $remainingPrivate = @($cleanupPaths | Where-Object { Test-Path -LiteralPath $_ })
                if ($remainingPrivate.Count -gt 0) { throw ('Private stage/journal artifacts remain: ' + ($remainingPrivate -join ',')) }
                Invoke-Diskpart @(('select vdisk file="' + $diskImage + '"'),'detach vdisk')
                if (Test-Path -LiteralPath 'S:\') { throw 'Disposable volume S: remains mounted after detach.' }
                $mounted = $false
                $privateStageCleaned = $true
                $disposableVolumeDetached = $true
                Write-Event 'PrivateStageCleanupAndVolumeDetach' 'verified'
            } catch {
                Add-FinalizationIssue ('Private stage cleanup or volume detach failed: ' + $_.Exception.Message)
                if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
            }
        }

        if ($prePrivateCleanupChecks -and -not $mounted -and -not (Test-Path -LiteralPath 'S:\')) {
            $privateStageCleaned = $true
            $disposableVolumeDetached = $true
            Write-Event 'PrivateStageCleanupAndVolumeDetach' 'verified;fixture-volume-was-never-mounted'
        } elseif ($prePrivateCleanupChecks -and -not $mounted -and (Test-Path -LiteralPath 'S:\')) {
            Add-FinalizationIssue 'Fixture volume S: remains present while mount state was not recorded; recovery material was preserved.'
            if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
        }

        $allRestorationChecksPassed = ($finalFilterState -eq 'ABSENT' -and $agentServiceRestored -and
            $observerStoppedAndValidated -and $originalDriverRestored -and $verifierRestored -and
            $driverServiceRestored -and $statusTasksRemoved -and $privateStageCleaned -and $disposableVolumeDetached)
        if ($allRestorationChecksPassed) {
            try {
                $temporaryPaths = @($serviceDirectory,$backup,$diskImage,$diskpart) | Where-Object { Test-Path -LiteralPath $_ }
                if ($temporaryPaths.Count -gt 0) { Remove-Item -LiteralPath $temporaryPaths -Force -Recurse -ErrorAction Stop }
                if ((Test-Path -LiteralPath $backup) -or (Test-Path -LiteralPath $diskImage) -or (Test-Path -LiteralPath $serviceDirectory)) {
                    throw 'Temporary service package, restoration backup or disposable image remains after cleanup.'
                }
                Write-Event 'LocalFixtureCleanup' ('verified;observer-and-command-raw-evidence-retained=' + $evidenceDir)
            } catch {
                Add-FinalizationIssue ('Local fixture cleanup failed: ' + $_.Exception.Message)
                if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
            }
        } else {
            Write-Event 'LocalFixtureCleanupDeferred' 'one-or-more-independent-restoration-checks-failed;backup-package-volume-and-private-owner-recovery-material-retained'
        }
    }
    if ($null -ne $script:observer) {
        Write-Event 'RetainedObserverEvidence' ('log=' + $observerLog + ';stdout=' + $observerOut + ';stderr=' + $observerErr)
    } elseif ($observerRequired) {
        Add-FinalizationIssue 'Independent byte observer was required but no process handle was retained.'
        if ($scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
    }
    Write-Event 'IndependentVMRestorationGate' 'REQUIRED_EXTERNAL;script-cleanup-is-not-independent-qualification'
}

if ($finalizationIssues.Count -gt 0 -and $scenarioResult -ne 'FAIL') { $scenarioResult = 'INCONCLUSIVE' }
if ($finalizationIssues.Count -gt 0) {
    $scenarioReason += ' FinalizationIssues=' + ($finalizationIssues -join '|')
}
Write-Event 'ScenarioResult' ($scenarioResult + ';reason=' + ($scenarioReason -replace '\s+', ' '))
if ($scenarioResult -eq 'FAIL') { exit 1 }
if ($scenarioResult -eq 'INCONCLUSIVE') { exit 3 }
exit 0
