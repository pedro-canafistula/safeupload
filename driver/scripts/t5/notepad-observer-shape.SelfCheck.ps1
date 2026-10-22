[CmdletBinding()]
param([string]$CoordinatorPath, [string]$ObserverPath)
# Windows PowerShell 5.1 leaves $PSScriptRoot empty in an advanced script's param() defaults under -File.
if (-not $CoordinatorPath) { $CoordinatorPath = Join-Path $PSScriptRoot 'notepad-coordinator.ps1' }
if (-not $ObserverPath) { $ObserverPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'StagedInvariantObserver.psm1' }
$ErrorActionPreference = 'Stop'
$script:assertions = 0
function Assert-T5([bool]$Condition, [string]$Message) {
    $script:assertions++
    if (-not $Condition) { throw ('T5 observer-shape self-check failed: ' + $Message) }
}

# m2t5ord10: Windows PowerShell runs a ForEach-Object stage once with $_ = $null for a $null input, so an image with no names
# produced one all-null name and the raw-sample schema rejected every sample. The projection must iterate with a null guard.
Assert-T5 (@($null | ForEach-Object { 1 }).Count -eq 1) 'precondition: a null pipeline input runs ForEach-Object once'
function Project-Names($Names) {
    return @(foreach ($name in @($Names)) { if ($null -ne $name) { [pscustomobject]@{ Name = $name.Name; Parent = $name.Parent } } })
}
Assert-T5 (@(Project-Names $null).Count -eq 0) 'no names project to an empty array'
Assert-T5 (@(Project-Names @()).Count -eq 0) 'an empty name list projects to an empty array'
Assert-T5 (@(Project-Names ([pscustomobject]@{ Name = 'a'; Parent = 'p' })).Count -eq 1) 'a single name stays one entry'
Assert-T5 (@(Project-Names @([pscustomobject]@{ Name = 'a'; Parent = 'p' }, [pscustomobject]@{ Name = 'b'; Parent = 'p' })).Count -eq 2) 'two names stay two entries'
Assert-T5 ((@(Project-Names $null) | ConvertTo-Json -Compress) -ne '[{"Name":null,"Parent":null}]') 'an absent image serializes without a null name'

$coordinator = [IO.File]::ReadAllText($CoordinatorPath)
Assert-T5 ($coordinator.Contains('FileNames = @(foreach ($imageFileName in @($image.FileNames)) { if ($null -ne $imageFileName)')) 'the coordinator projects image names with a null guard'
Assert-T5 (-not $coordinator.Contains('FileNames = @($image.FileNames | ForEach-Object')) 'the coordinator no longer pipes a possibly null name list'
Assert-T5 ($coordinator.Contains("Probe=`$(if(`$guarded){'PrivateNamespaceGuard'}")) 'a guarded stage lookup is recorded as such'
Assert-T5 ($coordinator.Contains('[Management.Automation.ErrorCategory]::PermissionDenied')) 'the stage lookup tolerates the private-namespace guard only by its permission-denied category'

# Owner 2026-10-22: a raw sample that failed an observation race is superseded by the next valid sample of the same case and phase.
Assert-T5 ($coordinator.Contains("function Test-T5TransientObservationError(`$Sample)")) 'the coordinator classifies transient observation errors'
Assert-T5 ($coordinator.Contains("`$previous.Sequence -eq (`$object.Sequence - 1)") -and -not $coordinator.Contains("`$previous.Phase -ceq `$Phase")) 'supersession needs the very next sequence of the same case, in any phase'
Assert-T5 ($coordinator.Contains("`$previous | Add-Member -NotePropertyName SupersededBySequence")) 'a superseded sample is marked, never removed'
Assert-T5 ($coordinator.Contains("`$result.RawObserver.Samples += `$object") -and $coordinator.Contains("`$Case.RawSamples += `$object")) 'both sample lists hold the same object so a mark is seen by both'
Assert-T5 ($coordinator.Contains('if (-not (Test-T5TransientObservationError $sample)){throw') -or $coordinator.Contains('if(-not (Test-T5TransientObservationError $sample)){throw')) 'the settlement wait retries only transient errors'
Assert-T5 ($coordinator.Contains('$entry.ModuleSequence = $sample.Sequence }')) 'an ERROR sample keeps its module sequence'

$actor = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent $CoordinatorPath) 'notepad-actor.ps1'))
Assert-T5 ($actor.Contains('function Read-ActorControlText') -and -not $actor.Contains('[IO.File]::ReadAllText($command.FullName)')) 'the actor reads its command with a bounded sharing-violation retry'
Assert-T5 ($actor.Contains('-notin @(32,33)')) 'the actor retries only ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION'

$observer = [IO.File]::ReadAllText($ObserverPath)
Assert-T5 ($observer.Contains('Requested record=\d+; Bad signature') -and $observer.Contains('Target metadata probe failed, yet the named lookup succeeded')) 'the in-sample stale-metadata retry covers a lagging MFT record and a name that appeared mid-capture'
Assert-T5 ($coordinator.Contains("Completed bytes changed during hot collection*") -and $coordinator.Contains('Start-Sleep -Milliseconds 100; continue }')) 'the forced-order gate retries a hot-journal collection race and keeps every other journal error fatal'
$head = $observer.IndexOf('function Get-IOCapture(')
Assert-T5 ($head -ge 0) 'Get-IOCapture exists'
$body = $observer.Substring($head, 600)
Assert-T5 ($body.Contains('$key=$null; $entry=$null')) 'Get-IOCapture initializes $key and $entry before its catch block reads them under strict mode'

Write-Output ('T5 observer-shape self-check PASS (' + $script:assertions + ' assertions).')
