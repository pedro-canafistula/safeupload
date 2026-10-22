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

$observer = [IO.File]::ReadAllText($ObserverPath)
$head = $observer.IndexOf('function Get-IOCapture(')
Assert-T5 ($head -ge 0) 'Get-IOCapture exists'
$body = $observer.Substring($head, 600)
Assert-T5 ($body.Contains('$key=$null; $entry=$null')) 'Get-IOCapture initializes $key and $entry before its catch block reads them under strict mode'

Write-Output ('T5 observer-shape self-check PASS (' + $script:assertions + ' assertions).')
